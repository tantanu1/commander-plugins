//! Signed S3 HTTP requests (ureq, blocking): URL style, region redirects, retries, error mapping.
use crate::config::Config;
use crate::sign::{self, Canonical};
use commander_plugin_abi::{self as abi, Status};
use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use ureq::http::Request;

pub type Resp = ureq::http::Response<ureq::Body>;

/// Plugin error: ABI status + detail text (never contains secrets).
#[derive(Debug, Clone)]
pub struct Error {
    pub status: Status,
    pub msg: String,
    /// HTTP status when it came from S3, else 0.
    pub http: u16,
}

impl Error {
    pub fn new(status: Status, msg: impl Into<String>) -> Self {
        Self {
            status,
            msg: msg.into(),
            http: 0,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// One request. Headers: lowercase; `x-amz-*` are signed, the rest (range) sent as is.
pub struct Req<'a> {
    pub method: &'static str,
    pub bucket: Option<&'a str>,
    pub key: &'a str,
    pub query: Vec<(&'static str, String)>,
    pub headers: Vec<(&'static str, String)>,
    pub body: &'a [u8],
    /// Retry 5xx / network errors (off for non-idempotent CreateMultipartUpload).
    pub retry: bool,
}

impl<'a> Req<'a> {
    pub fn new(method: &'static str, bucket: Option<&'a str>, key: &'a str) -> Self {
        Self {
            method,
            bucket,
            key,
            query: Vec::new(),
            headers: Vec::new(),
            body: &[],
            retry: true,
        }
    }

    pub fn no_retry(mut self) -> Self {
        self.retry = false;
        self
    }

    pub fn q(mut self, k: &'static str, v: impl Into<String>) -> Self {
        self.query.push((k, v.into()));
        self
    }

    pub fn h(mut self, k: &'static str, v: impl Into<String>) -> Self {
        self.headers.push((k, v.into()));
        self
    }

    pub fn body(mut self, b: &'a [u8]) -> Self {
        self.body = b;
        self
    }

    fn what(&self) -> String {
        match self.bucket {
            Some(b) => format!("s3: {} {b}/{}", self.method, self.key),
            None => format!("s3: {} (bucket list)", self.method),
        }
    }
}

/// S3 error code + HTTP status -> ABI status. `temp`: the request used temporary credentials
/// (a session token), so a rejected token means they expired.
fn status_of(http: u16, code: &str, temp: bool) -> Status {
    match (http, code) {
        (_, "ExpiredToken" | "ExpiredTokenException" | "TokenRefreshRequired") => abi::AUTH_EXPIRED,
        (_, "InvalidClientTokenId" | "InvalidToken" | "InvalidAccessKeyId") if temp => {
            abi::AUTH_EXPIRED
        }
        (_, "NoSuchKey" | "NoSuchBucket" | "NoSuchUpload") | (404, _) => abi::NOT_FOUND,
        (
            _,
            "InvalidAccessKeyId"
            | "SignatureDoesNotMatch"
            | "InvalidToken"
            | "InvalidClientTokenId"
            | "AuthorizationHeaderMalformed"
            | "RequestTimeTooSkewed",
        ) => abi::AUTH,
        (403, _) => abi::DENIED,
        (412, _) => abi::EXISTS,
        (_, "BucketNotEmpty") => abi::NOT_EMPTY,
        (400, _) => abi::INVALID,
        _ => abi::IO,
    }
}

/// DNS-safe bucket => virtual-hosted style is possible (dots break TLS wildcard certs).
fn dns_bucket(b: &str) -> bool {
    b.bytes()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

pub struct Client {
    agent: ureq::Agent,
    cfg: Config,
    /// Bucket -> region learnt from `x-amz-bucket-region`.
    regions: Mutex<HashMap<String, String>>,
}

impl Client {
    pub fn new(cfg: Config) -> Self {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_connect(Some(Duration::from_secs(15)))
            .timeout_recv_response(Some(Duration::from_secs(120)))
            // parallel downloads: keep their connections (default 3 per host)
            .max_idle_connections(64)
            .max_idle_connections_per_host(32)
            .build()
            .new_agent();
        Self {
            agent,
            cfg,
            regions: Mutex::default(),
        }
    }

    fn regions(&self) -> std::sync::MutexGuard<'_, HashMap<String, String>> {
        self.regions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn region(&self, bucket: Option<&str>) -> String {
        bucket
            .and_then(|b| self.regions().get(b).cloned())
            .unwrap_or_else(|| self.cfg.region.clone())
    }

    /// (scheme, host, encoded path).
    #[cfg(test)]
    pub fn profile(&self) -> &str {
        &self.cfg.profile
    }

    fn target(&self, region: &str, bucket: Option<&str>, key: &str) -> (String, String, String) {
        let (scheme, base) = match &self.cfg.endpoint {
            Some(e) => {
                let (s, rest) = e.split_once("://").unwrap_or(("https", e));
                (
                    s.to_owned(),
                    rest.split('/').next().unwrap_or(rest).to_owned(),
                )
            }
            None => ("https".to_owned(), format!("s3.{region}.amazonaws.com")),
        };
        let key = sign::uri_encode(key, false);
        match bucket {
            None => (scheme, base, "/".to_owned()),
            Some(b) if !self.cfg.path_style && dns_bucket(b) => {
                (scheme, format!("{b}.{base}"), format!("/{key}"))
            }
            Some(b) => (scheme, base, format!("/{b}/{key}")),
        }
    }

    fn send_once(&self, r: &Req, region: &str) -> std::result::Result<Resp, ureq::Error> {
        let (scheme, host, path) = self.target(region, r.bucket, r.key);
        let query = sign::canonical_query(&r.query);
        let payload_sha = sign::sha256_hex(r.body);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        let amz_date = sign::amz_date(now);
        let mut signed: Vec<(String, String)> = vec![
            ("host".into(), host.clone()),
            ("x-amz-content-sha256".into(), payload_sha.clone()),
            ("x-amz-date".into(), amz_date.clone()),
        ];
        if let Some(t) = &self.cfg.creds.token {
            signed.push(("x-amz-security-token".into(), t.clone()));
        }
        let (amz, plain): (Vec<_>, Vec<_>) =
            r.headers.iter().partition(|(k, _)| k.starts_with("x-amz-"));
        signed.extend(amz.iter().map(|(k, v)| ((*k).to_owned(), v.clone())));
        signed.sort();
        let auth = sign::authorization(
            &self.cfg.creds,
            &Canonical {
                method: r.method,
                path: &path,
                query: &query,
                headers: &signed,
                payload_sha: &payload_sha,
                amz_date: &amz_date,
                region,
            },
        );
        let url = match query.is_empty() {
            true => format!("{scheme}://{host}{path}"),
            false => format!("{scheme}://{host}{path}?{query}"),
        };
        let mut b = Request::builder().method(r.method).uri(url);
        let all = signed.iter().map(|(k, v)| (k.as_str(), v));
        for (k, v) in all.chain(plain.iter().map(|(k, v)| (*k, v))) {
            b = b.header(k, v.as_str());
        }
        b = b.header("authorization", auth);
        match (r.method, r.body.is_empty()) {
            ("GET" | "HEAD" | "DELETE", true) => self.agent.run(b.body(())?),
            _ => self.agent.run(b.body(r.body)?),
        }
    }

    /// 2xx response or a mapped error. Retries 5xx / transport errors twice; follows one
    /// wrong-region answer (`x-amz-bucket-region`).
    pub fn send(&self, r: &Req) -> Result<Resp> {
        let mut retries = if r.retry { 0u32 } else { 2 };
        let mut redirected = false;
        loop {
            let region = self.region(r.bucket);
            match self.send_once(r, &region) {
                Ok(resp) if resp.status().is_success() => return Ok(resp),
                Ok(resp) => {
                    let st = resp.status().as_u16();
                    let other = resp
                        .headers()
                        .get("x-amz-bucket-region")
                        .and_then(|v| v.to_str().ok())
                        .filter(|reg| *reg != region);
                    if let (Some(b), Some(reg), false, 301 | 307 | 400) =
                        (r.bucket, other, redirected, st)
                    {
                        self.regions().insert(b.to_owned(), reg.to_owned());
                        redirected = true;
                        continue;
                    }
                    if st < 500 || retries == 2 {
                        return Err(self.http_error(r, resp));
                    }
                }
                Err(e)
                    if retries == 2
                        || matches!(
                            e,
                            ureq::Error::BadUri(_)
                                | ureq::Error::Http(_)
                                | ureq::Error::HostNotFound
                        ) =>
                {
                    return Err(Error::new(abi::IO, format!("{}: {e}", r.what())));
                }
                Err(_) => {}
            }
            retries += 1;
            std::thread::sleep(Duration::from_millis(300 << (2 * retries)));
        }
    }

    /// `send` + the body as text; a 200 carrying `<Error>` (CopyObject/Complete) is an error.
    pub fn send_text(&self, r: &Req) -> Result<String> {
        let mut resp = self.send(r)?;
        let text = resp
            .body_mut()
            .read_to_string()
            .map_err(|e| Error::new(abi::IO, format!("{}: {e}", r.what())))?;
        match crate::xml::error(&text) {
            Some((code, msg)) => {
                Err(self.error(200, &code, format!("{}: {code}: {msg}", r.what())))
            }
            None => Ok(text),
        }
    }

    /// Mapped S3 error; expired credentials get the profile's login hint.
    fn error(&self, http: u16, code: &str, msg: String) -> Error {
        let status = status_of(http, code, self.cfg.creds.token.is_some());
        let msg = match status {
            abi::AUTH_EXPIRED => {
                crate::config::expired_error(&self.cfg.profile, self.cfg.login.clone(), &msg).msg
            }
            _ => msg,
        };
        Error { status, msg, http }
    }

    fn http_error(&self, r: &Req, mut resp: Resp) -> Error {
        let http = resp.status().as_u16();
        let body = match r.method {
            "HEAD" => String::new(),
            _ => resp.body_mut().read_to_string().unwrap_or_default(),
        };
        let (code, msg) = crate::xml::error(&body).unwrap_or_default();
        let mut detail = match code.is_empty() {
            true => format!("HTTP {http}"),
            false => format!("{code}: {msg} (HTTP {http})"),
        };
        if code == "RequestTimeTooSkewed" {
            detail.push_str(" - check the system clock");
        }
        self.error(http, &code, format!("{}: {detail}", r.what()))
    }
}

/// Test HTTP server on 127.0.0.1: every request gets `reply(method, path)` (then the
/// connection closes). Returns `http://127.0.0.1:<port>`.
#[cfg(test)]
pub(crate) fn mock(reply: fn(&str, &str) -> (u16, String)) -> String {
    use std::io::{BufRead, BufReader, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut r = BufReader::new(&s);
            let mut first = String::new();
            let _ = r.read_line(&mut first);
            let mut len = 0usize;
            loop {
                let mut h = String::new();
                if r.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                    break;
                }
                if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
            }
            let _ = std::io::Read::read_exact(&mut r, &mut vec![0; len]);
            let mut parts = first.split(' ');
            let (m, p) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
            let (code, body) = reply(m, p);
            let body = if m == "HEAD" { String::new() } else { body };
            let _ = write!(
                &s,
                "HTTP/1.1 {code} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    url
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Creds;

    #[test]
    fn http_errors_from_a_server() {
        let url = mock(|m, p| match (m, p) {
            ("GET", "/b/skew") => (
                403,
                "<Error><Code>RequestTimeTooSkewed</Code><Message>late</Message></Error>".into(),
            ),
            ("GET", "/b/ok") => (200, "hi".into()),
            _ => (404, String::new()),
        });
        let c = client(Some(&url), true);
        let e = c.send(&Req::new("GET", Some("b"), "skew")).unwrap_err();
        assert_eq!((e.status, e.http), (abi::AUTH, 403));
        assert!(e.msg.contains("RequestTimeTooSkewed: late") && e.msg.ends_with("system clock"));
        let e = c.send(&Req::new("HEAD", Some("b"), "gone")).unwrap_err();
        assert_eq!(
            (e.status, e.msg.as_str()),
            (abi::NOT_FOUND, "s3: HEAD b/gone: HTTP 404")
        );
        assert_eq!(
            c.send_text(&Req::new("GET", Some("b"), "ok")).unwrap(),
            "hi"
        );
    }

    fn client(endpoint: Option<&str>, path_style: bool) -> Client {
        Client::new(Config {
            creds: Creds {
                access_key: "a".into(),
                secret_key: "s".into(),
                token: None,
            },
            region: "eu-west-1".into(),
            endpoint: endpoint.map(str::to_owned),
            path_style,
            profile: "p".into(),
            login: Vec::new(),
        })
    }

    #[test]
    fn url_styles() {
        let t = |c: &Client, b, k| c.target("eu-west-1", b, k);
        let aws = client(None, false);
        assert_eq!(
            t(&aws, Some("bkt"), "a b/c"),
            (
                "https".into(),
                "bkt.s3.eu-west-1.amazonaws.com".into(),
                "/a%20b/c".into()
            )
        );
        assert_eq!(
            t(&aws, Some("my.bkt"), "k"),
            (
                "https".into(),
                "s3.eu-west-1.amazonaws.com".into(),
                "/my.bkt/k".into()
            )
        );
        assert_eq!(t(&aws, None, "").2, "/");
        let minio = client(Some("http://localhost:9000"), true);
        assert_eq!(
            t(&minio, Some("bkt"), ""),
            ("http".into(), "localhost:9000".into(), "/bkt/".into())
        );
    }

    #[test]
    fn error_status_mapping() {
        let st = |h, c| status_of(h, c, false);
        assert_eq!(st(404, ""), abi::NOT_FOUND);
        assert_eq!(st(200, "NoSuchKey"), abi::NOT_FOUND);
        assert_eq!(st(403, "SignatureDoesNotMatch"), abi::AUTH);
        assert_eq!(st(403, "AccessDenied"), abi::DENIED);
        assert_eq!(st(403, "RequestTimeTooSkewed"), abi::AUTH);
        assert_eq!(st(409, "BucketNotEmpty"), abi::NOT_EMPTY);
        assert_eq!(st(503, "SlowDown"), abi::IO);
    }

    #[test]
    fn expired_token_classification() {
        for code in [
            "ExpiredToken",
            "ExpiredTokenException",
            "TokenRefreshRequired",
        ] {
            assert_eq!(status_of(400, code, false), abi::AUTH_EXPIRED, "{code}");
        }
        for code in ["InvalidClientTokenId", "InvalidToken", "InvalidAccessKeyId"] {
            assert_eq!(status_of(403, code, true), abi::AUTH_EXPIRED, "temp {code}");
            assert_eq!(status_of(403, code, false), abi::AUTH, "long-term {code}");
        }
        // The error text carries the profile and its login argv.
        let mut c = client(None, false);
        c.cfg.creds.token = Some("t".into());
        c.cfg.login = vec!["aws".into(), "login".into()];
        let e = c.error(403, "InvalidToken", "s3: GET b/k: InvalidToken: x".into());
        assert_eq!(e.status, abi::AUTH_EXPIRED);
        let x = abi::auth::Expired::parse(&e.msg);
        assert!(
            x.msg.contains("profile p") && x.msg.contains("InvalidToken"),
            "{}",
            x.msg
        );
        assert_eq!(x.login, ["aws", "login"]);
        let e = c.error(403, "AccessDenied", "denied".into());
        assert_eq!(
            (e.status, e.msg.as_str(), e.http),
            (abi::DENIED, "denied", 403)
        );
    }
}

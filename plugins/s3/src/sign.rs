//! AWS SigV4 (header auth) + the URI encoding and date helpers it needs. No secrets in errors.
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fmt::Write;

/// Static credentials. No `Debug`: never printable.
pub struct Creds {
    pub access_key: String,
    pub secret_key: String,
    pub token: Option<String>,
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

fn hex(b: &[u8]) -> String {
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

fn hmac(key: &[u8], msg: &str) -> Vec<u8> {
    // HMAC accepts any key length: new_from_slice never fails.
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("hmac takes any key length");
    m.update(msg.as_bytes());
    m.finalize().into_bytes().to_vec()
}

/// S3 URI encoding: everything but `A-Za-z0-9-_.~` as `%XX`; `/` kept unless `slash`.
pub fn uri_encode(s: &str, slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if !slash => out.push('/'),
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Canonical (sorted, encoded) query string; also used verbatim in the URL.
pub fn canonical_query(q: &[(&str, String)]) -> String {
    let mut v: Vec<(String, String)> = q
        .iter()
        .map(|(k, v)| (uri_encode(k, true), uri_encode(v, true)))
        .collect();
    v.sort();
    v.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// One request to sign. `headers`: lowercase names, sorted, must include `host`,
/// `x-amz-date` and `x-amz-content-sha256`. `path` already URI-encoded.
pub struct Canonical<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub headers: &'a [(String, String)],
    pub payload_sha: &'a str,
    pub amz_date: &'a str,
    pub region: &'a str,
}

/// `Authorization` header value.
pub fn authorization(c: &Creds, r: &Canonical) -> String {
    let date = &r.amz_date[..8];
    let canon_headers: String = r
        .headers
        .iter()
        .map(|(k, v)| format!("{k}:{}\n", v.trim()))
        .collect();
    let signed = r
        .headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let creq = format!(
        "{}\n{}\n{}\n{canon_headers}\n{signed}\n{}",
        r.method, r.path, r.query, r.payload_sha
    );
    let scope = format!("{date}/{}/s3/aws4_request", r.region);
    let sts = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        r.amz_date,
        sha256_hex(creq.as_bytes())
    );
    let k = hmac(format!("AWS4{}", c.secret_key).as_bytes(), date);
    let k = hmac(&k, r.region);
    let k = hmac(&k, "s3");
    let k = hmac(&k, "aws4_request");
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={}",
        c.access_key,
        hex(&hmac(&k, &sts))
    )
}

/// Days since 1970-01-01 -> (y, m, d). Howard Hinnant's civil_from_days.
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

use commander_plugin_abi::glue::days_from_civil;

/// `YYYYMMDDTHHMMSSZ` for unix seconds.
pub fn amz_date(unix: i64) -> String {
    let (y, m, d) = civil(unix.div_euclid(86_400));
    let s = unix.rem_euclid(86_400);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        s / 3600,
        s / 60 % 60,
        s % 60
    )
}

fn to_ns(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> i64 {
    (days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s) * 1_000_000_000
}

fn hms(t: &str) -> Option<(i64, i64, i64)> {
    let mut it = t.splitn(3, ':').map(|x| x.parse::<i64>().ok());
    Some((it.next()??, it.next()??, it.next()??))
}

/// ISO-8601 `2009-10-12T17:50:30.000Z` -> unix ns.
pub fn parse_iso(s: &str) -> Option<i64> {
    let (date, time) = s.split_once('T')?;
    let mut d = date.splitn(3, '-').map(|x| x.parse::<i64>().ok());
    let (y, mo, da) = (d.next()??, d.next()??, d.next()??);
    let time = time.trim_end_matches('Z');
    let (h, mi, sec) = hms(time.split('.').next()?)?;
    Some(to_ns(y, mo, da, h, mi, sec))
}

/// HTTP date `Wed, 21 Oct 2015 07:28:00 GMT` -> unix ns.
pub fn parse_http_date(s: &str) -> Option<i64> {
    let mut p = s.split_whitespace().skip(1);
    let d = p.next()?.parse().ok()?;
    let mon = p.next()?;
    let mo = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|m| *m == mon)? as i64
        + 1;
    let y = p.next()?.parse().ok()?;
    let (h, mi, sec) = hms(p.next()?)?;
    Some(to_ns(y, mo, d, h, mi, sec))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_creds() -> Creds {
        // AWS documentation example keys (public, not real).
        Creds {
            access_key: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            token: None,
        }
    }

    fn h(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    #[test]
    fn sigv4_matches_aws_docs_get_object() {
        let empty = sha256_hex(b"");
        let headers = h(&[
            ("host", "examplebucket.s3.amazonaws.com"),
            ("range", "bytes=0-9"),
            ("x-amz-content-sha256", &empty),
            ("x-amz-date", "20130524T000000Z"),
        ]);
        let auth = authorization(
            &example_creds(),
            &Canonical {
                method: "GET",
                path: "/test.txt",
                query: "",
                headers: &headers,
                payload_sha: &empty,
                amz_date: "20130524T000000Z",
                region: "us-east-1",
            },
        );
        assert!(
            auth.ends_with(
                "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
            ),
            "{auth}"
        );
        assert!(auth.contains("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date"));
    }

    #[test]
    fn sigv4_matches_aws_docs_list_objects() {
        let empty = sha256_hex(b"");
        let headers = h(&[
            ("host", "examplebucket.s3.amazonaws.com"),
            ("x-amz-content-sha256", &empty),
            ("x-amz-date", "20130524T000000Z"),
        ]);
        let q = canonical_query(&[("prefix", "J".into()), ("max-keys", "2".into())]);
        assert_eq!(q, "max-keys=2&prefix=J");
        let auth = authorization(
            &example_creds(),
            &Canonical {
                method: "GET",
                path: "/",
                query: &q,
                headers: &headers,
                payload_sha: &empty,
                amz_date: "20130524T000000Z",
                region: "us-east-1",
            },
        );
        assert!(
            auth.ends_with(
                "Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
            ),
            "{auth}"
        );
    }

    #[test]
    fn encoding() {
        assert_eq!(uri_encode("a b/ż~.txt", false), "a%20b/%C5%BC~.txt");
        assert_eq!(uri_encode("a/b+c=", true), "a%2Fb%2Bc%3D");
        assert_eq!(uri_encode("a+b c~", false), "a%2Bb%20c~");
        assert_eq!(
            canonical_query(&[("prefix", "d/x y".into()), ("delimiter", "/".into())]),
            "delimiter=%2F&prefix=d%2Fx%20y"
        );
    }

    #[test]
    fn dates() {
        assert_eq!(amz_date(1_369_353_600), "20130524T000000Z");
        assert_eq!(amz_date(951_825_599), "20000229T115959Z");
        let ns = 1_255_369_830 * 1_000_000_000;
        assert_eq!(parse_iso("2009-10-12T17:50:30.000Z"), Some(ns));
        assert_eq!(parse_iso("2009-10-12T17:50:30Z"), Some(ns));
        assert_eq!(parse_http_date("Mon, 12 Oct 2009 17:50:30 GMT"), Some(ns));
        assert_eq!(parse_iso("garbage"), None);
        assert_eq!(parse_http_date("Mon, 12 Foo 2009 17:50:30 GMT"), None);
    }
}

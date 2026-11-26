//! AWS profiles from `~/.aws/config` + `~/.aws/credentials` (paths: `AWS_CONFIG_FILE` /
//! `AWS_SHARED_CREDENTIALS_FILE`, home: `HOME`, then `USERPROFILE`). Static keys are read
//! directly; SSO / `aws login` / credential_process / assume-role profiles get temporary keys
//! from `aws configure export-credentials` (argv, no shell). Env keys apply to the env profile
//! (`AWS_PROFILE`, else `default`). Not supported: IMDS/ECS. Secrets never leave `Creds`.
use crate::client::Error;
use crate::sign::Creds;
use commander_plugin_abi::{self as abi, auth::Expired};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct Config {
    pub creds: Creds,
    pub region: String,
    /// `scheme://host[:port]` of an S3-compatible server; `None` = AWS.
    pub endpoint: Option<String>,
    pub path_style: bool,
    /// Profile name (error text) and the login argv for an expired-credentials error.
    pub profile: String,
    pub login: Vec<String>,
}

/// section -> key -> value. Nested keys (`s3 =` + indented lines) flatten to `s3.key`.
type Ini = HashMap<String, HashMap<String, String>>;

fn parse_ini(text: &str) -> Ini {
    let mut ini = Ini::new();
    let mut section = String::new();
    let mut parent: Option<String> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = s.trim().to_owned();
            parent = None;
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        let nested = raw.starts_with([' ', '\t']);
        let key = match (&parent, nested) {
            (Some(p), true) => format!("{p}.{k}"),
            _ => {
                parent = v.is_empty().then(|| k.to_owned());
                k.to_owned()
            }
        };
        ini.entry(section.clone())
            .or_default()
            .insert(key, v.to_owned());
    }
    ini
}

/// Profile name of a config-file section: `[profile x]` -> x, `[default]` -> default. Other
/// sections (`[sso-session x]`, `[services x]`, a bare `[x]`) are not profiles (AWS CLI rule).
fn config_profile(section: &str) -> Option<&str> {
    match section.strip_prefix("profile ") {
        Some(p) => Some(p.trim()),
        None => (section == "default").then_some(section),
    }
}

/// A name the host can show as a dir and the CLI takes as `--profile` (never an option).
fn usable_name(p: &str) -> bool {
    crate::fs::valid_name(p) && !p.starts_with('-')
}

/// How a profile gets its credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` (the env profile only).
    Env,
    /// `aws_access_key_id` + `aws_secret_access_key` in the files.
    Static,
    /// IAM Identity Center (`sso_session` / `sso_start_url`): `aws sso login`.
    Sso,
    /// `aws login` console session (`login_session`).
    Login,
    /// credential_process / role_arn / web identity: the CLI resolves it.
    Cli,
    None,
}

/// Env vars read (once, at mount open).
const VARS: [&str; 13] = [
    "HOME",
    "USERPROFILE",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_PROFILE",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_ENDPOINT_URL_S3",
    "AWS_ENDPOINT_URL",
    "COMMANDER_S3_PATH_STYLE",
];

pub const INSTALL_HINT: &str = "Install the AWS CLI v2: \
    https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html";

/// The AWS config files + env, read once.
pub struct Aws {
    env: HashMap<&'static str, String>,
    creds: Ini,
    /// Config file sections keyed by profile name (non-profile sections dropped).
    config: Ini,
}

/// Runs `aws configure export-credentials --profile <p> --format process`: stdout or stderr.
pub type CliFn = dyn Fn(&str) -> Result<String, String>;

impl Aws {
    /// The real environment and files.
    pub fn load() -> Self {
        Self::from(&|k| std::env::var(k).ok().filter(|v| !v.is_empty()), &|p| {
            std::fs::read_to_string(p).ok()
        })
    }

    fn from(env: &dyn Fn(&str) -> Option<String>, read: &dyn Fn(&Path) -> Option<String>) -> Self {
        let env: HashMap<_, _> = VARS.iter().filter_map(|&k| Some((k, env(k)?))).collect();
        let home = env
            .get("HOME")
            .or_else(|| env.get("USERPROFILE"))
            .map(PathBuf::from);
        let file = |var: &str, name: &str| {
            env.get(var)
                .map(PathBuf::from)
                .or_else(|| home.as_ref().map(|h| h.join(".aws").join(name)))
                .and_then(|p| read(&p))
                .map(|t| parse_ini(&t))
                .unwrap_or_default()
        };
        let creds = file("AWS_SHARED_CREDENTIALS_FILE", "credentials");
        // Keyed by profile name: `[profile  x]` and `[profile x]` are the same profile.
        let config = file("AWS_CONFIG_FILE", "config")
            .into_iter()
            .filter_map(|(s, kv)| Some((config_profile(&s)?.to_owned(), kv)))
            .collect();
        Self { env, creds, config }
    }

    /// Test fixture: these file texts, no env.
    #[cfg(test)]
    pub fn fixture(creds: &str, config: &str) -> Self {
        let read = |p: &Path| match p.file_name()?.to_str()? {
            "credentials" => Some(creds.to_owned()),
            _ => Some(config.to_owned()),
        };
        Self::from(&|k| (k == "HOME").then(|| "/h".to_owned()), &read)
    }

    fn env(&self, k: &str) -> Option<String> {
        self.env.get(k).cloned()
    }

    /// Profile env keys belong to: `AWS_PROFILE`, else `default`.
    fn env_profile(&self) -> &str {
        self.env
            .get("AWS_PROFILE")
            .map_or("default", String::as_str)
    }

    fn env_keys(&self) -> bool {
        self.env.contains_key("AWS_ACCESS_KEY_ID") && self.env.contains_key("AWS_SECRET_ACCESS_KEY")
    }

    /// Profiles in fallback order: the env profile, `default`, then the rest by name.
    pub fn profiles(&self) -> Vec<String> {
        let mut rest: Vec<&str> = self
            .creds
            .keys()
            .map(String::as_str)
            .chain(self.config.keys().map(String::as_str))
            .collect();
        if self.env_keys() {
            rest.push(self.env_profile());
        }
        rest.sort_unstable();
        rest.dedup();
        let first = [self.env_profile(), "default"];
        let mut out: Vec<String> = Vec::new();
        for p in first.into_iter().chain(rest) {
            if usable_name(p) && !out.iter().any(|o| o == p) && self.known(p) {
                out.push(p.to_owned());
            }
        }
        out
    }

    fn known(&self, p: &str) -> bool {
        self.creds.contains_key(p)
            || self.conf_sec(p).is_some()
            || (p == self.env_profile() && self.env_keys())
    }

    fn conf_sec(&self, p: &str) -> Option<&HashMap<String, String>> {
        self.config.get(p)
    }

    /// Profile value: credentials file first, then config file.
    fn get(&self, p: &str, k: &str) -> Option<String> {
        let c = self.creds.get(p).and_then(|s| s.get(k));
        c.or_else(|| self.conf_sec(p)?.get(k)).cloned()
    }

    pub fn source(&self, p: &str) -> Source {
        let has = |k| self.get(p, k).is_some();
        if p == self.env_profile() && self.env_keys() {
            Source::Env
        } else if has("aws_access_key_id") && has("aws_secret_access_key") {
            Source::Static
        } else if has("sso_session") || has("sso_start_url") {
            Source::Sso
        } else if has("login_session") {
            Source::Login
        } else if has("credential_process") || has("role_arn") || has("web_identity_token_file") {
            Source::Cli
        } else {
            Source::None
        }
    }

    /// argv that renews `p`'s login (empty: none, e.g. static keys).
    pub fn login_argv(&self, p: &str) -> Vec<String> {
        let sub: &[&str] = match self.source(p) {
            Source::Sso => &["sso", "login"],
            Source::Login => &["login"],
            _ => return Vec::new(),
        };
        let mut v = vec!["aws".to_owned()];
        v.extend(sub.iter().map(|s| (*s).to_owned()));
        v.extend(["--profile".to_owned(), p.to_owned()]);
        v
    }

    /// The AUTH_EXPIRED error for profile `p` (`why`: what failed, no secrets).
    pub fn expired(&self, p: &str, why: &str) -> Error {
        expired_error(p, self.login_argv(p), why)
    }

    /// Credentials + endpoint settings of profile `p`. `cli` runs the AWS CLI export.
    pub fn config(&self, p: &str, cli: &CliFn) -> Result<Config, Error> {
        let creds = match self.source(p) {
            Source::Env => Creds {
                access_key: self.env("AWS_ACCESS_KEY_ID").unwrap_or_default(),
                secret_key: self.env("AWS_SECRET_ACCESS_KEY").unwrap_or_default(),
                token: self.env("AWS_SESSION_TOKEN"),
            },
            Source::Static => Creds {
                access_key: self.get(p, "aws_access_key_id").unwrap_or_default(),
                secret_key: self.get(p, "aws_secret_access_key").unwrap_or_default(),
                token: self.get(p, "aws_session_token"),
            },
            Source::None => {
                return Err(Error::new(
                    abi::AUTH,
                    format!("s3: profile {p} has no credentials (see aws configure)"),
                ));
            }
            src => match cli(p).map(|out| parse_process_creds(&out)) {
                Ok(Some(c)) => c,
                Ok(None) => {
                    return Err(Error::new(
                        abi::AUTH,
                        format!("s3: profile {p}: unreadable aws CLI credentials output"),
                    ));
                }
                Err(e) if matches!(src, Source::Sso | Source::Login) => {
                    return Err(self.expired(p, &e));
                }
                Err(e) => return Err(Error::new(abi::AUTH, format!("s3: profile {p}: {e}"))),
            },
        };
        let region = self
            .env("AWS_REGION")
            .or_else(|| self.env("AWS_DEFAULT_REGION"))
            .or_else(|| self.get(p, "region"))
            .unwrap_or_else(|| "us-east-1".into());
        let endpoint = self
            .env("AWS_ENDPOINT_URL_S3")
            .or_else(|| self.env("AWS_ENDPOINT_URL"))
            .or_else(|| self.get(p, "s3.endpoint_url"))
            .or_else(|| self.get(p, "endpoint_url"))
            .map(|e| e.trim_end_matches('/').to_owned());
        if let Some(e) = &endpoint {
            check_endpoint(e).map_err(|m| Error::new(abi::INVALID, m))?;
        }
        let path_style = match self.env("COMMANDER_S3_PATH_STYLE").as_deref() {
            Some("1" | "true") => true,
            Some("0" | "false") => false,
            _ => match self.get(p, "s3.addressing_style").as_deref() {
                Some("path") => true,
                Some("virtual") => false,
                // S3-compatible servers (MinIO, ...) usually want path style.
                _ => endpoint.is_some(),
            },
        };
        Ok(Config {
            creds,
            region,
            endpoint,
            path_style,
            profile: p.to_owned(),
            login: self.login_argv(p),
        })
    }
}

/// AUTH_EXPIRED for profile `p`: message, login argv (may be empty) and the CLI install hint.
pub fn expired_error(p: &str, login: Vec<String>, why: &str) -> Error {
    let todo = match login.is_empty() {
        true => "renew them in ~/.aws/credentials",
        false => "log in",
    };
    let first = why.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let why = match first.trim() {
        "" => String::new(),
        w => format!(" ({w})").replace("aws: [ERROR]: ", ""),
    };
    let x = Expired {
        msg: format!("Credentials for AWS profile {p} expired or need a login: {todo}.{why}"),
        install: (!login.is_empty()).then(|| INSTALL_HINT.to_owned()),
        login,
    };
    Error::new(abi::AUTH_EXPIRED, x.detail())
}

fn check_endpoint(e: &str) -> Result<(), String> {
    let host = e
        .strip_prefix("http://")
        .or_else(|| e.strip_prefix("https://"))
        .ok_or_else(|| format!("endpoint {e:?} must start with http:// or https://"))?;
    if host.is_empty() || host.contains(['/', '@', '?', '#']) {
        return Err(format!(
            "endpoint {e:?} must be scheme://host[:port] (no path, user or query)"
        ));
    }
    Ok(())
}

/// String value of `"key": "..."` in a flat JSON object (credential_process output).
fn json_str(text: &str, key: &str) -> Option<String> {
    let at = text.find(&format!("\"{key}\""))? + key.len() + 2;
    let rest = text[at..].trim_start().strip_prefix(':')?.trim_start();
    let body = rest.strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                c => out.push(c), // \" \\ \/
            },
            c => out.push(c),
        }
    }
    None
}

/// `credential_process` JSON (`aws configure export-credentials --format process`).
pub fn parse_process_creds(text: &str) -> Option<Creds> {
    Some(Creds {
        access_key: json_str(text, "AccessKeyId")?,
        secret_key: json_str(text, "SecretAccessKey")?,
        token: json_str(text, "SessionToken"),
    })
}

/// The real CLI export: `aws configure export-credentials --profile <p> --format process`.
/// No shell, no console window; a stuck CLI is killed after 60 s.
pub fn aws_cli(p: &str) -> Result<String, String> {
    let mut cmd = std::process::Command::new("aws");
    cmd.args(["configure", "export-credentials", "--profile", p])
        .args(["--format", "process"]);
    run(cmd, std::time::Duration::from_secs(60))
}

/// Run `cmd` (no stdin, no console window): stdout on success, else stderr. Both pipes are
/// drained on threads (a chatty child never blocks on a full pipe). After `timeout` the child
/// is killed and reaped.
fn run(mut cmd: std::process::Command, timeout: std::time::Duration) -> Result<String, String> {
    use std::io::Read;
    use std::process::Stdio;
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};
    fn drain<R: Read + Send + 'static>(r: Option<R>) -> JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut v = Vec::new();
            if let Some(mut r) = r {
                let _ = r.read_to_end(&mut v);
            }
            v
        })
    }
    let prog = cmd.get_program().to_string_lossy().into_owned();
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = cmd.spawn().map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => format!("{prog} CLI not found on PATH"),
        _ => format!("cannot run {prog}: {e}"),
    })?;
    let (out, err) = (drain(child.stdout.take()), drain(child.stderr.take()));
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if start.elapsed() < timeout => std::thread::sleep(Duration::from_millis(20)),
            r => {
                let _ = child.kill();
                let _ = child.wait();
                // Readers are left to finish on their own (a grandchild may hold the pipes).
                return Err(match r {
                    Err(e) => format!("{prog}: {e}"),
                    _ => format!("{prog} timed out"),
                });
            }
        }
    };
    let text = |h: JoinHandle<Vec<u8>>| {
        String::from_utf8_lossy(&h.join().unwrap_or_default()).into_owned()
    };
    match status.success() {
        true => Ok(text(out)),
        false => Err(text(err).trim().to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CREDS: &str = "[default]\naws_access_key_id = AK1\naws_secret_access_key = SK1\n\n\
                         [work]\naws_access_key_id=AK2\naws_secret_access_key=SK2\naws_session_token=T2\n";
    const CONF: &str = "[default]\nregion = eu-west-1\n\n# comment\n[profile work]\nregion = us-west-2\n\
                        endpoint_url = http://localhost:9000/\ns3 =\n  addressing_style = virtual\n\
                        [profile sso]\nsso_session = corp\nregion = eu-central-1\n\
                        [profile old-sso]\nsso_start_url = https://x.awsapps.com/start\n\
                        [profile console]\nlogin_session = arn:aws:iam::1:user/u\n\
                        [profile role]\nrole_arn = arn:aws:iam::1:role/r\nsource_profile = default\n\
                        [profile empty]\nregion = us-east-2\n\
                        [sso-session corp]\nsso_region = eu-west-1\n\
                        [services x]\ns3 =\n  endpoint_url = http://y\n\
                        [bare]\nregion = ap-south-1\n\
                        [profile -evil]\nregion = x\n[profile  wide ]\nregion = ap-east-1\n\
                        [profile .]\nregion = x\n";

    fn aws(vars: &[(&str, &str)]) -> Aws {
        let env = |k: &str| {
            vars.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        };
        let read = |p: &Path| match p.file_name()?.to_str()? {
            "credentials" => Some(CREDS.to_owned()),
            "config" => Some(CONF.to_owned()),
            _ => None,
        };
        Aws::from(&env, &read)
    }

    fn no_cli(_: &str) -> Result<String, String> {
        Err("Error when retrieving token from sso: Token has expired".into())
    }

    fn run(vars: &[(&str, &str)], p: &str) -> Result<Config, Error> {
        aws(vars).config(p, &no_cli)
    }

    #[test]
    fn profile_sections_and_order() {
        let a = aws(&[("HOME", "/h")]);
        assert_eq!(
            a.profiles(),
            [
                "default", "console", "empty", "old-sso", "role", "sso", "wide", "work"
            ],
            "[profile x] + credentials [x]; no sso-session/services/bare/-evil"
        );
        assert_eq!(
            a.get("wide", "region").as_deref(),
            Some("ap-east-1"),
            "[profile  x] = x"
        );
        let a = aws(&[("HOME", "/h"), ("AWS_PROFILE", "work")]);
        assert_eq!(a.profiles()[..2], ["work", "default"]);
        // Env keys alone make the env profile.
        let a = aws(&[
            ("AWS_ACCESS_KEY_ID", "E"),
            ("AWS_SECRET_ACCESS_KEY", "S"),
            ("AWS_PROFILE", "ci"),
        ]);
        assert_eq!(a.profiles(), ["ci"]);
        assert!(aws(&[]).profiles().is_empty(), "no HOME, no files");
        assert_eq!(config_profile("profile  x "), Some("x"));
        assert_eq!(config_profile("default"), Some("default"));
        assert_eq!(config_profile("sso-session corp"), None);
        assert!(!usable_name("a/b") && !usable_name("-x") && usable_name("dev.1"));
        assert!(!usable_name(".") && !usable_name(".."));
    }

    #[test]
    fn sources_and_login_argv() {
        let a = aws(&[("USERPROFILE", "C:/u")]);
        let s = |p| a.source(p);
        assert_eq!(s("default"), Source::Static);
        assert_eq!(s("sso"), Source::Sso);
        assert_eq!(s("old-sso"), Source::Sso);
        assert_eq!(s("console"), Source::Login);
        assert_eq!(s("role"), Source::Cli);
        assert_eq!(s("empty"), Source::None);
        assert_eq!(
            a.login_argv("sso"),
            ["aws", "sso", "login", "--profile", "sso"]
        );
        assert_eq!(
            a.login_argv("console"),
            ["aws", "login", "--profile", "console"]
        );
        assert!(a.login_argv("default").is_empty() && a.login_argv("role").is_empty());
    }

    #[test]
    fn default_profile_from_files() {
        let c = run(&[("HOME", "/h")], "default").unwrap();
        assert_eq!(
            (c.creds.access_key.as_str(), c.creds.secret_key.as_str()),
            ("AK1", "SK1")
        );
        assert!(c.creds.token.is_none());
        assert_eq!(c.region, "eu-west-1");
        assert!(c.endpoint.is_none() && !c.path_style);
        assert_eq!(c.profile, "default");
    }

    #[test]
    fn named_profile_nested_keys_and_endpoint() {
        let c = run(&[("USERPROFILE", "C:/u")], "work").unwrap();
        assert_eq!(c.creds.access_key, "AK2");
        assert_eq!(c.creds.token.as_deref(), Some("T2"));
        assert_eq!(c.region, "us-west-2");
        assert_eq!(c.endpoint.as_deref(), Some("http://localhost:9000"));
        assert!(
            !c.path_style,
            "addressing_style = virtual wins over the endpoint default"
        );
    }

    #[test]
    fn env_wins() {
        let v = [
            ("HOME", "/h"),
            ("AWS_ACCESS_KEY_ID", "EK"),
            ("AWS_SECRET_ACCESS_KEY", "ES"),
            ("AWS_SESSION_TOKEN", "ET"),
            ("AWS_REGION", "ap-south-1"),
            ("AWS_ENDPOINT_URL", "https://acct.r2.cloudflarestorage.com"),
        ];
        let c = run(&v, "default").unwrap();
        assert_eq!(c.creds.access_key, "EK");
        assert_eq!(c.creds.token.as_deref(), Some("ET"));
        assert_eq!(c.region, "ap-south-1");
        assert!(c.path_style);
        assert_eq!(
            run(&v, "work").unwrap().creds.access_key,
            "AK2",
            "env keys only for the env profile"
        );
        let c = run(
            &[("HOME", "/h"), ("COMMANDER_S3_PATH_STYLE", "1")],
            "default",
        )
        .unwrap();
        assert!(c.path_style);
    }

    #[test]
    fn cli_profiles_use_export_credentials() {
        let a = aws(&[("HOME", "/h")]);
        let ok = |p: &str| {
            assert_eq!(p, "sso");
            Ok(
                r#"{"Version": 1, "AccessKeyId": "ASIA1", "SecretAccessKey": "s\/k",
                 "SessionToken": "tok", "Expiration": "2026-01-01T00:00:00+00:00"}"#
                    .to_owned(),
            )
        };
        let c = a.config("sso", &ok).unwrap();
        assert_eq!(
            (c.creds.access_key.as_str(), c.creds.secret_key.as_str()),
            ("ASIA1", "s/k")
        );
        assert_eq!(c.creds.token.as_deref(), Some("tok"));
        assert_eq!((c.region.as_str(), c.login.len()), ("eu-central-1", 5));
        let garbage = |_: &str| Ok("not json".to_owned());
        assert_eq!(a.config("sso", &garbage).err().unwrap().status, abi::AUTH);
    }

    #[test]
    fn expired_and_missing_creds() {
        let e = run(&[("HOME", "/h")], "sso").err().unwrap();
        assert_eq!(e.status, abi::AUTH_EXPIRED);
        let x = Expired::parse(&e.msg);
        assert!(
            x.msg.contains("profile sso") && x.msg.contains("Token has expired"),
            "{}",
            x.msg
        );
        assert_eq!(x.login, ["aws", "sso", "login", "--profile", "sso"]);
        assert!(x.install.is_some());
        let e = run(&[("HOME", "/h")], "role").err().unwrap();
        assert_eq!(
            e.status,
            abi::AUTH,
            "non-login CLI profile: plain auth error"
        );
        let e = run(&[("HOME", "/h")], "empty").err().unwrap();
        assert!(
            e.status == abi::AUTH && e.msg.contains("no credentials"),
            "{}",
            e.msg
        );
        let x = Expired::parse(&expired_error("k", Vec::new(), "").msg);
        assert!(x.msg.ends_with("renew them in ~/.aws/credentials.") && x.install.is_none());
    }

    #[test]
    fn bad_endpoint() {
        let e = run(
            &[("HOME", "/h"), ("AWS_ENDPOINT_URL", "localhost:9000")],
            "default",
        )
        .err()
        .unwrap();
        assert!(e.msg.contains("http://"), "{}", e.msg);
        for bad in ["http://u:p@h:9000", "https://h/base", "http://?x"] {
            let e = run(&[("HOME", "/h"), ("AWS_ENDPOINT_URL", bad)], "default")
                .err()
                .unwrap();
            assert!(e.msg.contains("scheme://host"), "{bad}: {}", e.msg);
        }
    }

    #[test]
    fn json_values() {
        assert_eq!(
            json_str(r#"{"a" : "x\"y\\z\n"}"#, "a").as_deref(),
            Some("x\"y\\z\n")
        );
        assert_eq!(json_str(r#"{"a": 1}"#, "a"), None);
        assert_eq!(json_str(r#"{"a": "open"#, "a"), None);
        assert_eq!(json_str(r#"{"a" "x"}"#, "a"), None);
        assert_eq!(json_str("{}", "a"), None);
        assert!(parse_process_creds(r#"{"AccessKeyId":"a"}"#).is_none());
    }

    /// Needs the aws CLI and a configured profile: `COMMANDER_S3_TEST_PROFILE=p cargo test -p
    /// commander_s3 -- --ignored cli_export`.
    #[test]
    #[ignore = "needs the aws CLI"]
    fn cli_export_live() {
        let p = std::env::var("COMMANDER_S3_TEST_PROFILE").unwrap_or("default".into());
        let out = aws_cli(&p).expect("export-credentials");
        assert!(parse_process_creds(&out).is_some());
    }

    const FAKE: &str = "COMMANDER_S3_FAKE_CLI";

    /// This test binary re-run as a fake CLI (`FAKE` = chatty | sleep | fail).
    fn fake(mode: &str) -> std::process::Command {
        let mut c = std::process::Command::new(std::env::current_exe().unwrap());
        c.args(["config::tests::fake_cli_child", "--exact", "--ignored"])
            .args(["--nocapture", "--test-threads=1"])
            .env(FAKE, mode);
        c
    }

    #[test]
    #[ignore = "child of runner_drains_times_out_and_reports"]
    fn fake_cli_child() {
        match std::env::var(FAKE).as_deref() {
            // Far more than a pipe buffer, on both streams.
            Ok("chatty") => {
                let line = "x".repeat(1023);
                for _ in 0..256 {
                    println!("{line}");
                    eprintln!("{line}");
                }
                println!("END-MARK");
            }
            Ok("sleep") => std::thread::sleep(std::time::Duration::from_secs(60)),
            Ok("fail") => {
                eprintln!("boom from cli");
                std::process::exit(3);
            }
            _ => {}
        }
    }

    #[test]
    fn runner_drains_times_out_and_reports() {
        use std::time::Duration;
        let out = super::run(fake("chatty"), Duration::from_secs(120)).unwrap();
        assert!(
            out.len() > 256 * 1024 && out.contains("END-MARK"),
            "{}",
            out.len()
        );
        let e = super::run(fake("sleep"), Duration::from_millis(300)).unwrap_err();
        assert!(e.ends_with("timed out"), "{e}");
        let e = super::run(fake("fail"), Duration::from_secs(120)).unwrap_err();
        assert!(e.contains("boom from cli"), "{e}");
        let none = std::process::Command::new("commander-no-such-cli");
        let e = super::run(none, Duration::from_secs(5)).unwrap_err();
        assert_eq!(e, "commander-no-such-cli CLI not found on PATH");
    }
}

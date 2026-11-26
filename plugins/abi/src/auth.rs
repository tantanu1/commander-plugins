//! `AUTH_EXPIRED` detail text (header: CMDR_AUTH_EXPIRED). Line 1 = message for the user; then
//! optional `key=value` lines: `login=` a tab-separated argv the host may run (no shell,
//! detached) when the user presses "Log in", `install=` a hint shown when `argv[0]` is not on
//! PATH. Unknown keys are ignored. Never put a secret in it.
//! `NEED_PASSPHRASE` detail ([`Passphrase`]): line 1 = message; `key=<path>`; `wrong=1`;
//! `password=1` (the secret is an account password for `key` = `user@host`, not a key file's).
use alloc::string::String;
use alloc::vec::Vec;

/// Parsed `AUTH_EXPIRED` detail.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Expired {
    pub msg: String,
    /// Login argv (empty = no login command: the message says what to do).
    pub login: Vec<String>,
    pub install: Option<String>,
}

/// Tabs / line breaks would break the format: spaces instead.
fn clean(s: &str) -> String {
    s.replace(['\t', '\n', '\r'], " ")
}

impl Expired {
    /// Plugin side: the detail text.
    pub fn detail(&self) -> String {
        let mut out = clean(&self.msg);
        if !self.login.is_empty() {
            let argv: Vec<String> = self.login.iter().map(|a| clean(a)).collect();
            out.push_str("\nlogin=");
            out.push_str(&argv.join("\t"));
        }
        if let Some(i) = &self.install {
            out.push_str("\ninstall=");
            out.push_str(&clean(i));
        }
        out
    }

    /// Host side: parse a detail text (a plain message is just `msg`).
    pub fn parse(detail: &str) -> Self {
        let mut lines = detail.lines();
        let mut e = Self {
            msg: lines.next().unwrap_or("").into(),
            ..Self::default()
        };
        for l in lines {
            match l.split_once('=') {
                Some(("login", v)) => {
                    e.login = v
                        .split('\t')
                        .filter(|a| !a.is_empty())
                        .map(Into::into)
                        .collect()
                }
                Some(("install", v)) => e.install = Some(v.into()),
                _ => {}
            }
        }
        e
    }
}

impl core::fmt::Display for Expired {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl core::error::Error for Expired {}

/// Parsed `NEED_PASSPHRASE` detail: which key file needs its passphrase. Never the passphrase.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Passphrase {
    pub msg: String,
    /// The key file (as the plugin names it; shown to the user).
    pub key: String,
    /// The last passphrase given for it was refused.
    pub wrong: bool,
    /// An account password for `key` (`user@host`), not a key file passphrase.
    pub password: bool,
}

impl Passphrase {
    /// Plugin side: the detail text.
    pub fn detail(&self) -> String {
        let mut out = clean(&self.msg);
        out.push_str("\nkey=");
        out.push_str(&clean(&self.key));
        if self.wrong {
            out.push_str("\nwrong=1");
        }
        if self.password {
            out.push_str("\npassword=1");
        }
        out
    }

    /// Host side: parse a detail text.
    pub fn parse(detail: &str) -> Self {
        let mut lines = detail.lines();
        let mut p = Self {
            msg: lines.next().unwrap_or("").into(),
            ..Self::default()
        };
        for l in lines {
            match l.split_once('=') {
                Some(("key", v)) => p.key = v.into(),
                Some(("wrong", v)) => p.wrong = v == "1",
                Some(("password", v)) => p.password = v == "1",
                _ => {}
            }
        }
        p
    }
}

impl core::fmt::Display for Passphrase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl core::error::Error for Passphrase {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn round_trip_and_plain() {
        let e = Expired {
            msg: "creds for p\texpired".into(),
            login: vec!["aws".into(), "sso".into(), "login".into(), "a\nb".into()],
            install: Some("get it".into()),
        };
        let d = e.detail();
        assert_eq!(
            d,
            "creds for p expired\nlogin=aws\tsso\tlogin\ta b\ninstall=get it"
        );
        let back = Expired::parse(&d);
        assert_eq!(back.msg, "creds for p expired");
        assert_eq!(back.login, ["aws", "sso", "login", "a b"]);
        assert_eq!(back.install.as_deref(), Some("get it"));
        let plain = Expired::parse("just text\nother=1");
        assert_eq!((plain.msg.as_str(), plain.login.len()), ("just text", 0));
        assert_eq!(Expired::parse(""), Expired::default());
        let bare = Expired {
            msg: "m".into(),
            ..Default::default()
        };
        assert_eq!(bare.detail(), "m");
        assert_eq!(alloc::format!("{bare}"), "m");
    }

    #[test]
    fn passphrase_round_trip() {
        let p = Passphrase {
            msg: "key\tencrypted".into(),
            key: "C:\\k\nx".into(),
            wrong: true,
            password: false,
        };
        let d = p.detail();
        assert_eq!(d, "key encrypted\nkey=C:\\k x\nwrong=1");
        let back = Passphrase::parse(&d);
        assert_eq!((back.key.as_str(), back.wrong), ("C:\\k x", true));
        assert_eq!(alloc::format!("{back}"), "key encrypted");
        let first = Passphrase {
            wrong: false,
            ..back
        };
        assert_eq!(Passphrase::parse(&first.detail()), first);
        assert!(!Passphrase::parse("m\nwrong=0\nx=1").wrong);
        let login = Passphrase {
            password: true,
            ..first
        };
        assert!(login.detail().ends_with("\npassword=1"));
        assert_eq!(Passphrase::parse(&login.detail()), login);
    }
}

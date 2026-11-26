//! Where to connect: a mount's authority is a bookmark name from `sftp.toml` or
//! `[user@]host[:port]`, then completed from `~/.ssh/config` (what the bookmark or URL gives
//! wins). Passwords come only from bookmarks, key passphrases only from the host prompt; neither
//! reaches error text or `Debug`.
use crate::ssh_config::{self, Tokens};
use commander_plugin_abi::url;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// What a bookmark or URL asked for; `None` = not given (`~/.ssh/config`, then defaults).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Spec {
    /// Host or `~/.ssh/config` alias.
    pub host: String,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub pass: Option<String>,
    pub identity: Option<PathBuf>,
}

impl fmt::Debug for Spec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Spec")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub pass: Option<String>,
    /// Key files (bookmark `identity`, then `~/.ssh/config` `IdentityFile`s); empty = agent +
    /// `~/.ssh/id_*`.
    pub identities: Vec<PathBuf>,
    /// `IdentitiesOnly yes`: no agent.
    pub identities_only: bool,
    /// Passphrase the user just typed for the key file the last try asked about.
    pub passphrase: Option<Zeroizing<String>>,
}

impl fmt::Debug for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Target")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("identities", &self.identities)
            .field("identities_only", &self.identities_only)
            .finish_non_exhaustive()
    }
}

/// Also shown by the connect dialog.
pub const NO_URL_PASSWORD: &str = "sftp: no passwords in sftp:// addresses (they show in the path bar and history): \
     put it in a bookmark in sftp.toml, or use ssh-agent / a key file";

const PORT: u16 = 22;

/// The user's home (`USERPROFILE` on Windows, `HOME` elsewhere).
pub fn home() -> Option<PathBuf> {
    let k = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(k)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Login name when none is given (like ssh: the local user).
fn local_user() -> Option<String> {
    let k = if cfg!(windows) { "USERNAME" } else { "USER" };
    std::env::var(k).ok().filter(|u| !u.is_empty())
}

fn user_or_local(user: Option<String>) -> Result<String, String> {
    user.or_else(local_user)
        .ok_or_else(|| "sftp: no user name (sftp://user@host)".into())
}

/// `[user@]host[:port]`; a password is refused ([`NO_URL_PASSWORD`]).
pub fn parse_authority(auth: &str) -> Result<Spec, String> {
    let a = url::parse_authority(auth, "sftp", NO_URL_PASSWORD)?;
    Ok(Spec {
        user: a.user,
        host: a.host,
        port: a.port,
        ..Spec::default()
    })
}

/// `s` completed from `~/.ssh/config` text `ssh` (the `Host` alias = `s.host`) and defaults.
pub fn finish(s: Spec, ssh: &str) -> Result<Target, String> {
    let c = ssh_config::lookup(ssh, &s.host);
    let home = home();
    let home_s = home
        .as_deref()
        .map(Path::to_string_lossy)
        .unwrap_or_default();
    let local = local_user().unwrap_or_default();
    let mut tok = Tokens {
        home: &home_s,
        local_user: &local,
        host: &s.host,
        user: "",
    };
    let host = match &c.host_name {
        Some(h) => ssh_config::expand_tokens(h, &tok),
        None => s.host.clone(),
    };
    if !url::valid_host(&host) || host.contains(char::is_control) {
        return Err(format!("~/.ssh/config: bad HostName for {:?}", s.host));
    }
    let user = user_or_local(s.user.or(c.user))?;
    // Same rule as bookmarks; no path separators where `%r` puts it into an IdentityFile path
    // (elsewhere `DOMAIN\user` stays valid).
    let in_path = c.identity_files.iter().any(|f| f.contains("%r"));
    if user.contains(|ch: char| ch.is_control() || (in_path && matches!(ch, '/' | '\\'))) {
        return Err(format!("sftp: bad user name for {:?}", s.host));
    }
    tok.host = &host;
    tok.user = &user;
    let identities = s
        .identity
        .into_iter()
        .chain(
            c.identity_files
                .iter()
                .map(|f| expand(&ssh_config::expand_tokens(f, &tok), home.as_deref())),
        )
        .collect();
    Ok(Target {
        port: s.port.or(c.port).unwrap_or(PORT),
        pass: s.pass,
        identities,
        identities_only: c.identities_only.unwrap_or(false),
        passphrase: None,
        host,
        user,
    })
}

/// `~/x` -> home/x.
fn expand(p: &str, home: Option<&Path>) -> PathBuf {
    match (p.strip_prefix("~/").or(p.strip_prefix("~\\")), home) {
        (Some(rest), Some(h)) => h.join(rest),
        _ => PathBuf::from(p),
    }
}

/// One `[name]` table of `sftp.toml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bookmark {
    host: String,
    port: Option<u16>,
    user: Option<String>,
    password: Option<String>,
    identity: Option<String>,
}

/// Bookmarks by name (sorted).
pub type Bookmarks = BTreeMap<String, Spec>;

pub fn parse_bookmarks(text: &str) -> Result<Bookmarks, String> {
    let raw: BTreeMap<String, Bookmark> =
        toml::from_str(text).map_err(|e| format!("sftp.toml: {}", e.message()))?;
    let home = home();
    raw.into_iter()
        .map(|(name, b)| {
            let bad = |s: &str| s.contains(char::is_control);
            if !url::valid_host(&b.host) || bad(&b.host) || b.user.as_deref().is_some_and(bad) {
                return Err(format!(
                    "sftp.toml: [{name}]: bad host or user (control character)"
                ));
            }
            let t = Spec {
                user: b.user.filter(|u| !u.is_empty()),
                host: b.host,
                port: b.port,
                pass: b.password.filter(|p| !p.is_empty()),
                identity: b
                    .identity
                    .filter(|p| !p.is_empty())
                    .map(|p| expand(&p, home.as_deref())),
            };
            Ok((name, t))
        })
        .collect()
}

/// `COMMANDER_SFTP_CONFIG`, else `sftp.toml` next to Commander's config.toml.
pub fn path() -> Option<PathBuf> {
    url::config_file("COMMANDER_SFTP_CONFIG", "sftp.toml")
}

/// Bookmarks from [`path`]; a missing file = none.
pub fn bookmarks() -> Result<Bookmarks, String> {
    match path() {
        Some(p) => url::read_optional(&p)?.map_or(Ok(Bookmarks::new()), |t| parse_bookmarks(&t)),
        None => Ok(Bookmarks::new()),
    }
}

/// A mount authority: bookmark name first (from `marks`), else a literal address; then
/// [`finish`]ed with `~/.ssh/config` text `ssh`.
pub fn resolve_in(
    auth: &str,
    marks: impl FnOnce() -> Result<Bookmarks, String>,
    ssh: &str,
) -> Result<Target, String> {
    // A broken sftp.toml only matters when the authority isn't a valid address either.
    let marks = marks();
    let spec = match &marks {
        Ok(m) if m.contains_key(auth) => m[auth].clone(),
        _ => parse_authority(auth).map_err(|e| marks.err().unwrap_or(e))?,
    };
    finish(spec, ssh)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(host: &str, port: Option<u16>, user: Option<&str>) -> Spec {
        Spec {
            host: host.into(),
            port,
            user: user.map(Into::into),
            ..Spec::default()
        }
    }

    fn done(s: Spec) -> Target {
        finish(s, "").unwrap()
    }

    #[test]
    fn authority_forms() {
        let a = |s| parse_authority(s).unwrap();
        assert_eq!(a("me@h"), spec("h", None, Some("me")));
        assert_eq!(a("me@[::1]:2222"), spec("::1", Some(2222), Some("me")));
        let t = done(a("me@h"));
        assert_eq!((t.host.as_str(), t.port, t.user.as_str()), ("h", 22, "me"));
        if local_user().is_some() {
            assert_eq!(
                done(a("h")).user,
                local_user().unwrap(),
                "default = local user"
            );
        }
        assert_eq!(parse_authority("me:pw@h").unwrap_err(), NO_URL_PASSWORD);
        assert!(
            !parse_authority("me:hunter2@h:0")
                .unwrap_err()
                .contains("hunter2")
        );
        assert!(user_or_local(None).is_ok() == local_user().is_some());
    }

    #[test]
    fn bookmarks_parse() {
        let home = home();
        let b = parse_bookmarks(
            "[work]\nhost = \"example.com\"\nport = 2222\nuser = \"me\"\npassword = \"pw\"\n\
             identity = \"~/.ssh/work\"\n\n[box]\nhost = \"10.0.0.5\"\nuser = \"root\"\npassword = \"\"\n\
             identity = \"\"\n",
        )
        .unwrap();
        let w = done(b["work"].clone());
        assert_eq!(
            (w.host.as_str(), w.port, w.user.as_str()),
            ("example.com", 2222, "me")
        );
        assert_eq!(w.pass.as_deref(), Some("pw"));
        if let Some(h) = &home {
            assert_eq!(w.identities, [h.join(".ssh/work")]);
        }
        assert_eq!(
            b["box"],
            spec("10.0.0.5", None, Some("root")),
            "empty password / identity = none"
        );
        assert!(
            parse_bookmarks("[x]\nhots = \"h\"\n").is_err(),
            "typo'd key"
        );
        assert!(parse_bookmarks("[x]\nhost = \"\"\n").is_err());
        let bad_host = parse_bookmarks("[x]\nhost = \"a b/c\"\n");
        assert!(bad_host.is_err(), "same host rule as URLs");
        assert!(parse_bookmarks("[x]\nhost = \"h\"\nuser = \"a\\nb\"\n").is_err());
        assert!(
            parse_bookmarks("[x")
                .unwrap_err()
                .starts_with("sftp.toml: ")
        );
    }

    #[test]
    fn tilde_expansion() {
        let h = Path::new("/home/me");
        assert_eq!(expand("~/k", Some(h)), h.join("k"));
        assert_eq!(expand("~\\k", Some(h)), h.join("k"));
        assert_eq!(expand("/abs/k", Some(h)), PathBuf::from("/abs/k"));
        assert_eq!(expand("~/k", None), PathBuf::from("~/k"));
    }

    const SSH: &str = "Host web\n  HostName %h.example.com\n  User deploy\n  Port 2200\n\
                       IdentityFile ~/.ssh/web_%r\n  IdentitiesOnly yes\n\
                       Host evil\n  HostName \"a b\"\n";

    #[test]
    fn resolve_bookmark_then_address() {
        let marks = || parse_bookmarks("[box]\nhost = \"10.0.0.5\"\nuser = \"me\"\n");
        let t = resolve_in("box", marks, "").unwrap();
        assert_eq!((t.host.as_str(), t.user.as_str()), ("10.0.0.5", "me"));
        assert_eq!(resolve_in("u@other", marks, "").unwrap().host, "other");
        let broken = || Err("sftp.toml: broken".to_string());
        assert_eq!(resolve_in("u@h", broken, "").unwrap().host, "h");
        assert_eq!(
            resolve_in("bad host", broken, "").unwrap_err(),
            "sftp.toml: broken"
        );
    }

    #[test]
    fn ssh_config_fills_what_is_not_given() {
        let none = || Ok(Bookmarks::new());
        let t = resolve_in("web", none, SSH).unwrap();
        assert_eq!(
            (t.host.as_str(), t.port, t.user.as_str()),
            ("web.example.com", 2200, "deploy")
        );
        assert!(t.identities_only);
        let key = |user: &str| expand(&format!("~/.ssh/web_{user}"), home().as_deref());
        assert_eq!(t.identities, [key("deploy")], "%r = the remote user");
        // The URL's user and port win.
        let t = resolve_in("me@web:2", none, SSH).unwrap();
        assert_eq!((t.port, t.user.as_str()), (2, "me"));
        assert_eq!(t.identities, [key("me")]);
        // A bookmark's fields win; its identity comes first.
        let marks =
            || parse_bookmarks("[w]\nhost = \"web\"\nuser = \"bm\"\nport = 3\nidentity = \"/k\"\n");
        let t = resolve_in("w", marks, SSH).unwrap();
        assert_eq!(
            (t.host.as_str(), t.port, t.user.as_str()),
            ("web.example.com", 3, "bm")
        );
        assert_eq!(t.identities, [PathBuf::from("/k"), key("bm")]);
        let err = resolve_in("u@evil", none, SSH).unwrap_err();
        assert!(err.contains("bad HostName"), "{err}");
        let sneaky = "Host s\n  User ../../x\n  IdentityFile ~/.ssh/%r\n";
        let err = resolve_in("s", none, sneaky).unwrap_err();
        assert!(err.contains("bad user name"), "{err}");
        let err = resolve_in("a%5Cb@web", none, SSH).unwrap_err();
        assert!(
            err.contains("bad user name"),
            "URL user with a backslash: {err}"
        );
        assert!(
            resolve_in("DOM%5Cme@other", none, SSH).is_ok(),
            "no %r: allowed"
        );
        assert!(resolve_in("s", none, "Host s\n User \"a\u{1}b\"\n").is_err());
        let plain = resolve_in("u@other", none, SSH).unwrap();
        assert!(plain.identities.is_empty() && !plain.identities_only);
    }

    #[test]
    fn debug_hides_secrets() {
        let mut x = done(spec("h", None, Some("u")));
        x.pass = Some("hunter2".into());
        x.passphrase = Some(Zeroizing::new("sesame".into()));
        let s = format!("{x:?}");
        assert!(
            !s.contains("hunter2") && !s.contains("sesame") && s.contains("\"h\""),
            "{s}"
        );
        let mut sp = spec("h", None, None);
        sp.pass = Some("hunter2".into());
        assert!(!format!("{sp:?}").contains("hunter2"));
        assert!(path().is_none_or(|p| p.ends_with("sftp.toml") || p.is_absolute()));
    }
}

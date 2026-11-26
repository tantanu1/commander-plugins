//! Where to connect: a mount's authority is a bookmark name from `smb.toml` or
//! `[user@]host[:port]`. Passwords come only from bookmarks or the host's password prompt; they
//! never reach error text or `Debug`.
use commander_plugin_abi::glue::valid_name;
use commander_plugin_abi::url;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// One server (and, from a bookmark, maybe one share).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    /// Bookmark share: the mount root is that share, not the share list.
    pub share: Option<String>,
    /// "" = guest / anonymous.
    pub user: String,
    pub domain: String,
    pub pass: Option<Zeroizing<String>>,
    /// Refuse a session the server does not encrypt (bookmark `encrypt = true`).
    pub encrypt: bool,
}

impl fmt::Debug for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Target")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("share", &self.share)
            .field("user", &self.user)
            .field("domain", &self.domain)
            .field("encrypt", &self.encrypt)
            .finish_non_exhaustive()
    }
}

/// Also shown by the connect dialog.
pub const NO_URL_PASSWORD: &str = "smb: no passwords in smb:// addresses (they show in the path bar and history): \
     put it in a bookmark in smb.toml, or type it when asked";

pub const PORT: u16 = 445;

/// `DOMAIN\user` -> (`DOMAIN`, `user`); `user@domain` (a UPN) is kept whole, NTLM takes it so.
fn split_user(user: &str) -> (&str, &str) {
    user.split_once('\\').unwrap_or(("", user))
}

/// `t` with user / domain from `user` (a bookmark's own `domain` wins).
fn with_user(mut t: Target, user: &str, domain: &str) -> Target {
    let (d, u) = split_user(user);
    t.user = u.into();
    t.domain = if domain.is_empty() { d } else { domain }.into();
    t
}

/// `[user@]host[:port]`; a password is refused ([`NO_URL_PASSWORD`]).
pub fn parse_authority(auth: &str) -> Result<Target, String> {
    let a = url::parse_authority(auth, "smb", NO_URL_PASSWORD)?;
    let t = Target {
        host: a.host,
        port: a.port.unwrap_or(PORT),
        ..Target::default()
    };
    Ok(with_user(t, a.user.as_deref().unwrap_or(""), ""))
}

/// One `[name]` table of `smb.toml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bookmark {
    host: String,
    port: Option<u16>,
    share: Option<String>,
    user: Option<String>,
    domain: Option<String>,
    password: Option<String>,
    encrypt: Option<bool>,
}

/// Bookmarks by name (sorted).
pub type Bookmarks = BTreeMap<String, Target>;

pub fn parse_bookmarks(text: &str) -> Result<Bookmarks, String> {
    let raw: BTreeMap<String, Bookmark> =
        toml::from_str(text).map_err(|e| format!("smb.toml: {}", e.message()))?;
    raw.into_iter()
        .map(|(name, b)| {
            let bad =
                |s: &Option<String>| s.as_deref().is_some_and(|s| s.contains(char::is_control));
            if !url::valid_host(&b.host)
                || b.host.contains(char::is_control)
                || bad(&b.user)
                || bad(&b.domain)
            {
                return Err(format!(
                    "smb.toml: [{name}]: bad host, user or domain (control character)"
                ));
            }
            let share = b.share.filter(|s| !s.is_empty());
            if share.as_deref().is_some_and(|s| !valid_name(s)) {
                return Err(format!("smb.toml: [{name}]: bad share name"));
            }
            let t = Target {
                host: b.host,
                port: b.port.unwrap_or(PORT),
                share,
                pass: b.password.filter(|p| !p.is_empty()).map(Zeroizing::new),
                encrypt: b.encrypt.unwrap_or(false),
                ..Target::default()
            };
            let user = b.user.unwrap_or_default();
            Ok((name, with_user(t, &user, &b.domain.unwrap_or_default())))
        })
        .collect()
}

/// `COMMANDER_SMB_CONFIG`, else `smb.toml` next to Commander's config.toml.
pub fn path() -> Option<PathBuf> {
    url::config_file("COMMANDER_SMB_CONFIG", "smb.toml")
}

/// Bookmarks from [`path`]; a missing file = none.
pub fn bookmarks() -> Result<Bookmarks, String> {
    match path() {
        Some(p) => url::read_optional(&p)?.map_or(Ok(Bookmarks::new()), |t| parse_bookmarks(&t)),
        None => Ok(Bookmarks::new()),
    }
}

/// A mount authority: bookmark name first (from `marks`), else a literal address.
pub fn resolve_in(
    auth: &str,
    marks: impl FnOnce() -> Result<Bookmarks, String>,
) -> Result<Target, String> {
    // A broken smb.toml only matters when the authority isn't a valid address either.
    let marks = marks();
    match &marks {
        Ok(m) if m.contains_key(auth) => Ok(m[auth].clone()),
        _ => parse_authority(auth).map_err(|e| marks.err().unwrap_or(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(host: &str, port: u16, user: &str, domain: &str) -> Target {
        Target {
            host: host.into(),
            port,
            user: user.into(),
            domain: domain.into(),
            ..Target::default()
        }
    }

    #[test]
    fn authority_forms() {
        let a = |s| parse_authority(s).unwrap();
        assert_eq!(a("nas"), t("nas", 445, "", ""), "guest");
        assert_eq!(a("me@nas:1445"), t("nas", 1445, "me", ""));
        assert_eq!(a("CORP%5Cme@nas"), t("nas", 445, "me", "CORP"));
        assert_eq!(
            a("me%40corp.example@nas"),
            t("nas", 445, "me@corp.example", "")
        );
        assert_eq!(a("[::1]"), t("::1", 445, "", ""));
        assert_eq!(parse_authority("me:pw@h").unwrap_err(), NO_URL_PASSWORD);
        assert!(
            !parse_authority("me:hunter2@h:0")
                .unwrap_err()
                .contains("hunter2")
        );
        assert!(parse_authority("a b").is_err());
    }

    #[test]
    fn bookmarks_parse() {
        let b = parse_bookmarks(
            "[nas]\nhost = \"nas.local\"\nshare = \"media\"\nuser = \"me\"\npassword = \"pw\"\nencrypt = true\n\
             [work]\nhost = \"fs1\"\nport = 1445\nuser = \"CORP\\\\me\"\n\
             [dom]\nhost = \"fs1\"\nuser = \"OLD\\\\me\"\ndomain = \"NEW\"\nshare = \"\"\npassword = \"\"\n",
        )
        .unwrap();
        let n = &b["nas"];
        assert_eq!(n.share.as_deref(), Some("media"));
        assert_eq!(n.pass.as_ref().map(|p| p.as_str()), Some("pw"));
        assert_eq!((n.port, n.user.as_str(), n.encrypt), (445, "me", true));
        assert_eq!(b["work"], t("fs1", 1445, "me", "CORP"));
        assert_eq!(
            b["dom"],
            t("fs1", 445, "me", "NEW"),
            "domain field wins; empty = none"
        );
        assert!(
            parse_bookmarks("[x]\nhots = \"h\"\n").is_err(),
            "typo'd key"
        );
        assert!(parse_bookmarks("[x]\nhost = \"\"\n").is_err());
        assert!(parse_bookmarks("[x]\nhost = \"h\"\nuser = \"a\\nb\"\n").is_err());
        assert!(parse_bookmarks("[x]\nhost = \"h\"\ndomain = \"a\\nb\"\n").is_err());
        let e = parse_bookmarks("[x]\nhost = \"h\"\nshare = \"a/b\"\n").unwrap_err();
        assert!(e.contains("bad share"), "{e}");
        assert!(parse_bookmarks("[x").unwrap_err().starts_with("smb.toml: "));
    }

    #[test]
    fn resolve_bookmark_then_address() {
        let marks = || parse_bookmarks("[box]\nhost = \"10.0.0.5\"\nuser = \"me\"\n");
        assert_eq!(resolve_in("box", marks).unwrap().host, "10.0.0.5");
        assert_eq!(resolve_in("u@other", marks).unwrap().host, "other");
        let broken = || Err("smb.toml: broken".to_string());
        assert_eq!(resolve_in("u@h", broken).unwrap().host, "h");
        assert_eq!(
            resolve_in("bad host", broken).unwrap_err(),
            "smb.toml: broken"
        );
        assert!(resolve_in("bad host", || Ok(Bookmarks::new())).is_err());
    }

    #[test]
    fn debug_hides_secrets() {
        let mut x = t("h", 445, "u", "d");
        x.pass = Some(Zeroizing::new("hunter2".into()));
        let s = format!("{x:?}");
        assert!(!s.contains("hunter2") && s.contains("\"h\""), "{s}");
        assert!(path().is_none_or(|p| p.ends_with("smb.toml") || p.is_absolute()));
        assert!(bookmarks().is_ok() || path().is_some());
    }
}

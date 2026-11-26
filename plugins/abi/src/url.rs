//! Shared by the network plugins (feature `glue`): `[user@]host[:port]` authorities and the
//! per-plugin bookmark file next to Commander's config.toml. Errors never echo the input
//! (a mistyped `user:password` would land in it).
use std::path::{Path, PathBuf};

/// `%XX` decoding for user names (`@`, `:` and `/` must be escaped in a URL).
pub fn pct_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// A host name or address (no brackets): non-empty, no whitespace or `/ \ [ ] @`.
pub fn valid_host(host: &str) -> bool {
    !host.is_empty() && !host.contains(|c: char| c.is_whitespace() || "/\\[]@".contains(c))
}

/// A parsed `[user@]host[:port]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    /// `None` = absent or empty.
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
}

/// `[user@]host[:port]`, host may be `[ipv6]`. `user:password@` is refused with `no_password`;
/// other errors start with `scheme: `.
pub fn parse_authority(auth: &str, scheme: &str, no_password: &str) -> Result<Authority, String> {
    let (userinfo, hostport) = match auth.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, auth),
    };
    let user = match userinfo {
        None => None,
        Some(u) => {
            let (user, pass) = u.split_once(':').unwrap_or((u, ""));
            if !pass.is_empty() {
                // A URL is shown and stored (path bar, tabs, history, config.toml).
                return Err(no_password.into());
            }
            let user = pct_decode(user)
                .filter(|u| !u.contains(char::is_control))
                .ok_or_else(|| {
                    format!("{scheme}: bad user name (%-escape or control character)")
                })?;
            Some(user).filter(|u| !u.is_empty())
        }
    };
    let (host, port) = match hostport.strip_prefix('[') {
        Some(rest) => {
            let (h, after) = rest
                .split_once(']')
                .ok_or_else(|| format!("{scheme}: unclosed '[' in the host"))?;
            (h, after.strip_prefix(':'))
        }
        None => match hostport.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (hostport, None),
        },
    };
    if !valid_host(host) {
        return Err(format!("{scheme}: bad host {host:?}"));
    }
    let port = match port {
        None => None,
        Some(p) => Some(
            p.parse()
                .ok()
                .filter(|&p| p != 0)
                // Not echoed: `user:password` without `@host` would put the password here.
                .ok_or_else(|| format!("{scheme}: bad port (want 1-65535)"))?,
        ),
    };
    Ok(Authority {
        user,
        host: host.to_owned(),
        port,
    })
}

/// `$<env>`, else `<file>` next to Commander's config.toml
/// (keep in sync with `commander_core::config::config_path`; plugins can't depend on core)
/// (`%APPDATA%\commander`, `$XDG_CONFIG_HOME/commander`, `~/.config/commander`).
pub fn config_file(env: &str, file: &str) -> Option<PathBuf> {
    let var = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    if let Some(p) = var(env) {
        return Some(p);
    }
    let base = match cfg!(windows) {
        true => var("APPDATA"),
        false => var("XDG_CONFIG_HOME").or_else(|| var("HOME").map(|h| h.join(".config"))),
    };
    base.map(|b| b.join("commander").join(file))
}

/// File text; a missing file = `None`.
pub fn read_optional(p: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(p) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", p.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> Authority {
        parse_authority(s, "x", "NOPW").unwrap()
    }

    #[test]
    fn authority_forms() {
        let au = |user: Option<&str>, host: &str, port| Authority {
            user: user.map(Into::into),
            host: host.into(),
            port,
        };
        assert_eq!(a("h"), au(None, "h", None));
        assert_eq!(a("me@h:2121"), au(Some("me"), "h", Some(2121)));
        assert_eq!(a("a%40b.c@h"), au(Some("a@b.c"), "h", None));
        assert_eq!(
            a("me:@h"),
            au(Some("me"), "h", None),
            "empty password = none"
        );
        assert_eq!(a("[::1]:990"), au(None, "::1", Some(990)));
        assert_eq!(a("u@[fe80::1]"), au(Some("u"), "fe80::1", None));
        assert_eq!(a("@h"), au(None, "h", None));
    }

    #[test]
    fn bad_authority_never_echoes_password() {
        for bad in [
            "u:hunter2@",
            "u:hunter2@h:0",
            "u:hunter2@h:99999",
            "u:hunter2@[::1",
            "u:hunter2@h:x",
            "u:hunter2%zz@h",
            "u:hunter2@h",
            "",
        ] {
            let e = parse_authority(bad, "x", "NOPW").unwrap_err();
            assert!(!e.contains("hunter2"), "{bad}: {e}");
        }
        assert_eq!(parse_authority("u:pw@h", "x", "NOPW").unwrap_err(), "NOPW");
        for bad in ["u%0a@h", "u%00@h", "%zz@h", "a%7f@h", "[::1"] {
            let e = parse_authority(bad, "x", "NOPW").unwrap_err();
            assert!(e.starts_with("x: "), "{bad}: {e}");
        }
    }

    #[test]
    fn files() {
        let dir = std::env::temp_dir().join(format!("cmdr-abi-url-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("x.toml");
        assert_eq!(read_optional(&p).unwrap(), None, "missing = none");
        std::fs::write(&p, "t").unwrap();
        assert_eq!(read_optional(&p).unwrap().as_deref(), Some("t"));
        assert!(read_optional(&dir).is_err(), "a dir is not a file");
        std::fs::remove_file(&p).unwrap();
        std::fs::remove_dir(&dir).unwrap();
        let f = config_file("CMDR_ABI_TEST_UNSET_VAR", "x.toml");
        assert!(f.is_none_or(|p| p.ends_with("commander/x.toml")));
    }
}

//! Where to connect: a mount's authority is a bookmark name from `ftp.toml` or
//! `[user[:password]@]host[:port]`. Passwords never reach error text or `Debug`.
use commander_plugin_abi::url;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub pass: String,
    /// Explicit FTPS (AUTH TLS on the control port).
    pub tls: bool,
    pub mode: Mode,
}

/// Transfer type (TC cm_FtpSelectTransferMode; bookmark `mode`), shared with the host. Text =
/// `TYPE A`: line ends are CRLF on the wire and the OS's own locally; no resume.
pub use commander_plugin_abi::ftp_mode::TransferMode as Mode;

impl fmt::Debug for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Target")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("tls", &self.tls)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

const ANON_USER: &str = "anonymous";
const ANON_PASS: &str = "anonymous@";

/// Also shown by the connect dialog.
pub const NO_URL_PASSWORD: &str = "ftp: no passwords in ftp:// addresses (they show in the path bar and history): \
     put it in a bookmark in ftp.toml";

/// `[user@]host[:port]`, host may be `[ipv6]`. A password is refused ([`NO_URL_PASSWORD`]);
/// errors never echo the input.
pub fn parse_authority(auth: &str, tls: bool) -> Result<Target, String> {
    let a = url::parse_authority(auth, "ftp", NO_URL_PASSWORD)?;
    let (user, pass) = match a.user {
        None => (ANON_USER.to_owned(), ANON_PASS.to_owned()),
        Some(u) => (u, String::new()),
    };
    Ok(Target {
        host: a.host,
        port: a.port.unwrap_or(21),
        user,
        pass,
        tls,
        mode: Mode::Binary,
    })
}

/// One `[name]` table of `ftp.toml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bookmark {
    host: String,
    port: Option<u16>,
    user: Option<String>,
    password: Option<String>,
    #[serde(default)]
    tls: bool,
    mode: Option<String>,
}

/// Bookmarks by name (sorted).
pub type Bookmarks = BTreeMap<String, Target>;

pub fn parse_bookmarks(text: &str) -> Result<Bookmarks, String> {
    let raw: BTreeMap<String, Bookmark> =
        toml::from_str(text).map_err(|e| format!("ftp.toml: {}", e.message()))?;
    raw.into_iter()
        .map(|(name, b)| {
            // CR/LF in a host or user would inject FTP commands.
            let bad = |s: &str| s.contains(char::is_control);
            if !url::valid_host(&b.host) || bad(&b.host) || b.user.as_deref().is_some_and(bad) {
                return Err(format!(
                    "ftp.toml: [{name}]: bad host or user (control character)"
                ));
            }
            if b.password.as_deref().is_some_and(bad) {
                return Err(format!(
                    "ftp.toml: [{name}]: control character in the password"
                ));
            }
            let mode = match b.mode.as_deref() {
                None => Mode::Binary,
                Some(m) => Mode::parse(m).ok_or_else(|| {
                    format!("ftp.toml: [{name}]: mode must be binary, ascii or auto")
                })?,
            };
            let anon = b.user.as_deref().is_none_or(str::is_empty);
            let t = Target {
                host: b.host,
                port: b.port.unwrap_or(21),
                user: match anon {
                    true => ANON_USER.to_owned(),
                    false => b.user.unwrap_or_default(),
                },
                pass: match (anon, b.password) {
                    (true, None) => ANON_PASS.to_owned(),
                    (_, p) => p.unwrap_or_default(),
                },
                tls: b.tls,
                mode,
            };
            Ok((name, t))
        })
        .collect()
}

/// `COMMANDER_FTP_CONFIG`, else `ftp.toml` next to Commander's config.toml.
pub fn path() -> Option<PathBuf> {
    url::config_file("COMMANDER_FTP_CONFIG", "ftp.toml")
}

/// Bookmarks from [`path`]; a missing file = none.
pub fn bookmarks() -> Result<Bookmarks, String> {
    let Some(p) = path() else {
        return Ok(Bookmarks::new());
    };
    read(&p)
}

fn read(p: &Path) -> Result<Bookmarks, String> {
    url::read_optional(p)?.map_or(Ok(Bookmarks::new()), |t| parse_bookmarks(&t))
}

/// A mount authority: bookmark name first (from `marks`), else a literal address.
pub(crate) fn resolve_in(
    auth: &str,
    tls: bool,
    marks: impl FnOnce() -> Result<Bookmarks, String>,
) -> Result<Target, String> {
    // Bookmarks first, so any name (even with '@' or ':') opens; a broken ftp.toml only
    // matters when the authority isn't a valid address either.
    let marks = marks();
    if let Ok(m) = &marks
        && let Some(t) = m.get(auth)
    {
        return Ok(Target {
            tls: t.tls || tls,
            ..t.clone()
        });
    }
    parse_authority(auth, tls).map_err(|e| marks.err().unwrap_or(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(host: &str, port: u16, user: &str, pass: &str, tls: bool) -> Target {
        Target {
            host: host.into(),
            port,
            user: user.into(),
            pass: pass.into(),
            tls,
            mode: Mode::Binary,
        }
    }

    #[test]
    fn authority_forms() {
        let a = |s| parse_authority(s, false).unwrap();
        assert_eq!(a("h"), t("h", 21, "anonymous", "anonymous@", false));
        assert_eq!(a("me@h:2121"), t("h", 2121, "me", "", false));
        assert_eq!(a("a%40b.c@h"), t("h", 21, "a@b.c", "", false));
        assert_eq!(
            a("me:@h"),
            t("h", 21, "me", "", false),
            "empty password = none"
        );
        assert_eq!(
            a("[::1]:990"),
            t("::1", 990, "anonymous", "anonymous@", false)
        );
        assert_eq!(a("u@[fe80::1]"), t("fe80::1", 21, "u", "", false));
        assert_eq!(a("@h"), t("h", 21, "anonymous", "anonymous@", false));
        assert!(parse_authority("h", true).unwrap().tls);
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
            let e = parse_authority(bad, false).unwrap_err();
            assert!(!e.contains("hunter2"), "{bad}: {e}");
        }
        assert_eq!(
            parse_authority("u:pw@h", false).unwrap_err(),
            NO_URL_PASSWORD
        );
        for bad in ["u%0a@h", "u%00@h", "%zz@h", "a%7f@h"] {
            assert!(parse_authority(bad, false).is_err(), "{bad}");
        }
    }

    #[test]
    fn resolve_bookmark_then_address() {
        let marks = || parse_bookmarks("[box]\nhost = \"10.0.0.5\"\nuser = \"me\"\n");
        let b = resolve_in("box", true, marks).unwrap();
        assert_eq!(b, t("10.0.0.5", 21, "me", "", true), "ftps:// forces TLS");
        assert_eq!(resolve_in("other", false, marks).unwrap().host, "other");
        assert_eq!(resolve_in("u@box", false, marks).unwrap().host, "box");
        let at = || parse_bookmarks("[\"me@work\"]\nhost = \"w\"\n");
        assert_eq!(
            resolve_in("me@work", false, at).unwrap().host,
            "w",
            "bookmark wins"
        );
        let broken = || Err("ftp.toml: broken".to_string());
        assert_eq!(resolve_in("h", false, broken).unwrap().host, "h");
        assert_eq!(
            resolve_in("bad host", false, broken).unwrap_err(),
            "ftp.toml: broken"
        );
    }

    #[test]
    fn read_file_or_missing() {
        let dir = std::env::temp_dir().join(format!("cmdr-ftp-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("ftp.toml");
        assert!(read(&p).unwrap().is_empty(), "missing file = no bookmarks");
        std::fs::write(&p, "[a]\nhost = \"h\"\n").unwrap();
        assert_eq!(read(&p).unwrap()["a"].host, "h");
        assert!(read(&dir).is_err(), "a dir is not a file");
        std::fs::remove_file(&p).unwrap();
        std::fs::remove_dir(&dir).unwrap();
        assert!(path().is_some_and(|p| p.ends_with("ftp.toml") || p.is_absolute()));
    }

    #[test]
    fn debug_hides_password() {
        let s = format!("{:?}", t("h", 21, "u", "hunter2", true));
        assert!(!s.contains("hunter2") && s.contains("\"h\""), "{s}");
    }

    #[test]
    fn bookmarks_parse() {
        let b = parse_bookmarks(
            "[work]\nhost = \"ftp.example.com\"\nport = 2121\nuser = \"me\"\npassword = \"pw\"\ntls = true\n\n\
             [pub]\nhost = \"ftp.gnu.org\"\n",
        )
        .unwrap();
        assert_eq!(b["work"], t("ftp.example.com", 2121, "me", "pw", true));
        assert_eq!(
            b["pub"],
            t("ftp.gnu.org", 21, "anonymous", "anonymous@", false)
        );
        assert_eq!(b.keys().collect::<Vec<_>>(), ["pub", "work"]);
        assert!(
            parse_bookmarks("[x]\nhots = \"h\"\n").is_err(),
            "typo'd key"
        );
        assert!(
            parse_bookmarks("[x]\nport = 21\n").is_err(),
            "host required"
        );
        for bad in [
            "host = \"h\\r\\nDELE x\"",
            "host = \"h\"\nuser = \"u\\nPASS\"",
            "host = \"\"",
        ] {
            assert!(parse_bookmarks(&format!("[x]\n{bad}\n")).is_err(), "{bad}");
        }
        let e = parse_bookmarks("[x]\nhost = \"h\"\npassword = \"p\\u0007w\"\n").unwrap_err();
        assert!(!e.contains("p\u{7}w"), "{e}");
    }

    #[test]
    fn transfer_modes() {
        let b = parse_bookmarks(
            "[a]\nhost = \"h\"\nmode = \"ascii\"\n[t]\nhost = \"h\"\nmode = \"text\"\n\
             [u]\nhost = \"h\"\nmode = \"auto\"\n[n]\nhost = \"h\"\n",
        )
        .unwrap();
        let m: Vec<Mode> = b.values().map(|t| t.mode).collect();
        assert_eq!(m, [Mode::Ascii, Mode::Binary, Mode::Ascii, Mode::Auto]);
        let e = parse_bookmarks("[x]\nhost = \"h\"\nmode = \"ebcdic\"\n").unwrap_err();
        assert!(e.contains("mode must be"), "{e}");
        assert!(format!("{:?}", parse_authority("h", false).unwrap()).contains("Binary"));
    }
}

//! `~/.ssh/config`, the part a file manager needs: `Host` blocks (aliases, `*` `?` wildcards,
//! `!negation`, several patterns per line) with `HostName`, `User`, `Port`, `IdentityFile`
//! and `IdentitiesOnly`. OpenSSH rules: the first value found wins, `IdentityFile`s add up,
//! lines before the first `Host` apply to every host. Everything else is ignored, and nothing
//! is ever executed: `Match` blocks (incl. `Match exec`) never match, `Include`,
//! `ProxyCommand`, `ProxyJump`, `LocalCommand` etc. are skipped.
use std::path::PathBuf;

/// What `~/.ssh/config` says about one host alias.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HostConfig {
    pub host_name: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    /// Raw values, in file order (tokens and `~` not expanded yet: see [`expand_tokens`]).
    pub identity_files: Vec<String>,
    pub identities_only: Option<bool>,
}

/// `~/.ssh/config` (missing or unreadable = empty).
pub fn path() -> Option<PathBuf> {
    crate::config::home().map(|h| h.join(".ssh").join("config"))
}

/// The user's config text ("" when there is none).
pub fn user_text() -> String {
    path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default()
}

/// `*` = any run, `?` = one char; case-insensitive (like OpenSSH host matching).
/// Linear two-pointer match (backtracks only to the last `*`).
fn glob(pat: &[char], s: &[char]) -> bool {
    let (mut p, mut i) = (0, 0);
    let mut star: Option<(usize, usize)> = None; // (pattern after '*', s position)
    while i < s.len() {
        match pat.get(p) {
            Some('*') => {
                star = Some((p + 1, i));
                p += 1;
            }
            Some(&c) if c == '?' || c == s[i] => {
                p += 1;
                i += 1;
            }
            _ => match star {
                Some((sp, si)) => {
                    p = sp;
                    i = si + 1;
                    star = Some((sp, si + 1));
                }
                None => return false,
            },
        }
    }
    pat[p..].iter().all(|&c| c == '*')
}

/// A `Host` line's patterns match `host`: one positive match and no negated one.
fn host_matches(patterns: &[String], host: &str) -> bool {
    let h: Vec<char> = host.to_lowercase().chars().collect();
    let mut hit = false;
    for p in patterns {
        let (neg, p) = match p.strip_prefix('!') {
            Some(p) => (true, p),
            None => (false, p.as_str()),
        };
        let p: Vec<char> = p.to_lowercase().chars().collect();
        if glob(&p, &h) {
            if neg {
                return false;
            }
            hit = true;
        }
    }
    hit
}

/// `Keyword value...` / `Keyword=value`: lowercase keyword + arguments (`"..."` groups).
fn split_line(line: &str) -> Option<(String, Vec<String>)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let end = line.find(|c: char| c.is_whitespace() || c == '=')?;
    let (key, rest) = line.split_at(end);
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=').unwrap_or(rest);
    let (mut args, mut cur, mut quoted, mut any) = (Vec::new(), String::new(), false, false);
    for c in rest.chars() {
        match c {
            '"' => (quoted, any) = (!quoted, true),
            c if c.is_whitespace() && !quoted => {
                if any {
                    args.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => {
                cur.push(c);
                any = true;
            }
        }
    }
    if any {
        args.push(cur);
    }
    Some((key.to_ascii_lowercase(), args))
}

/// The settings for `alias` (the name typed in `sftp://alias`).
pub fn lookup(text: &str, alias: &str) -> HostConfig {
    let mut c = HostConfig::default();
    let mut active = true; // before the first Host/Match: every host
    for line in text.lines() {
        let Some((key, args)) = split_line(line) else {
            continue;
        };
        let first = args.first().cloned();
        match key.as_str() {
            "host" => active = host_matches(&args, alias),
            "match" => active = false, // conditions (incl. exec) are never evaluated
            _ if !active => {}
            "hostname" => _ = c.host_name.get_or_insert_with(|| first.unwrap_or_default()),
            "user" => _ = c.user.get_or_insert_with(|| first.unwrap_or_default()),
            "port" if c.port.is_none() => {
                c.port = first.and_then(|p| p.parse().ok()).filter(|&p| p != 0);
            }
            // `none` = no file (OpenSSH).
            "identityfile" => c
                .identity_files
                .extend(first.filter(|f| !f.eq_ignore_ascii_case("none"))),
            "identitiesonly" if c.identities_only.is_none() => {
                c.identities_only = first.map(|v| v.eq_ignore_ascii_case("yes"));
            }
            _ => {}
        }
    }
    // An empty value is no value.
    c.host_name = c.host_name.filter(|h| !h.is_empty());
    c.user = c.user.filter(|u| !u.is_empty());
    c
}

/// Values for the `%` tokens of `IdentityFile` / `HostName`.
pub struct Tokens<'a> {
    /// `%d` local home.
    pub home: &'a str,
    /// `%u` local user.
    pub local_user: &'a str,
    /// `%h` remote host name.
    pub host: &'a str,
    /// `%r` remote user.
    pub user: &'a str,
}

/// `%d %u %h %r %%` replaced; any other `%x` stays as written.
pub fn expand_tokens(s: &str, t: &Tokens) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('d') => out.push_str(t.home),
            Some('u') => out.push_str(t.local_user),
            Some('h') => out.push_str(t.host),
            Some('r') => out.push_str(t.user),
            Some('%') => out.push('%'),
            Some(x) => {
                out.push('%');
                out.push(x);
            }
            None => out.push('%'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = "# global\nIdentityFile ~/.ssh/global\n\n\
        Host web *.prod !bad.prod\n  HostName=%h.example.com\n  User deploy\n  Port 2222\n\
        \x20 IdentityFile \"~/.ssh/my key\"\n  IdentitiesOnly yes\n  ProxyCommand nc evil 22\n\n\
        Match exec \"rm -rf /\"\n  User matched\n\n\
        Host b?x\n  User boxer\n\n\
        Host *\n  User fallback\n  Port 22\n  IdentityFile %d/.ssh/%u-%r@%h\n  Unknown x\n";

    #[test]
    fn host_blocks_first_value_wins() {
        let web = lookup(CFG, "web");
        assert_eq!(web.host_name.as_deref(), Some("%h.example.com"));
        assert_eq!(
            (web.user.as_deref(), web.port),
            (Some("deploy"), Some(2222))
        );
        assert_eq!(
            web.identity_files,
            ["~/.ssh/global", "~/.ssh/my key", "%d/.ssh/%u-%r@%h"],
            "identity files add up, global first"
        );
        assert_eq!(web.identities_only, Some(true));
        let prod = lookup(CFG, "API.PROD");
        assert_eq!(prod.user.as_deref(), Some("deploy"), "wildcard, any case");
        let bad = lookup(CFG, "bad.prod");
        assert_eq!(bad.user.as_deref(), Some("fallback"), "negated pattern");
        assert_eq!(lookup(CFG, "box").user.as_deref(), Some("boxer"));
        assert_eq!(lookup(CFG, "boox").user.as_deref(), Some("fallback"));
        let other = lookup(CFG, "other");
        assert_eq!((other.port, other.host_name), (Some(22), None));
        assert_ne!(
            other.user.as_deref(),
            Some("matched"),
            "Match never applies"
        );
        assert_eq!(lookup("", "x"), HostConfig::default());
    }

    #[test]
    fn odd_lines() {
        let c = lookup(
            "Host x\nPort nope\nUser\nHostName \"\"\nIdentitiesOnly no\nPort 0\n=\nIdentityFile none\n",
            "x",
        );
        assert_eq!(
            c,
            HostConfig {
                identities_only: Some(false),
                ..HostConfig::default()
            }
        );
        assert_eq!(split_line("  # c"), None);
        assert_eq!(split_line("Bare"), None, "keyword without value");
        assert_eq!(
            split_line("Key = a \"b c\"  d"),
            Some(("key".into(), vec!["a".into(), "b c".into(), "d".into()]))
        );
        assert!(!host_matches(&[], "x"));
        assert!(glob(&['*'], &[]) && !glob(&['?'], &[]));
        let g = |p: &str, s: &str| {
            let v = |x: &str| x.chars().collect::<Vec<_>>();
            glob(&v(p), &v(s))
        };
        assert!(g("a*b*c", "axxbyyc") && g("*.prod", "x.y.prod") && g("a*", "a"));
        assert!(!g("a*b", "axxc") && !g("*.prod", "prod") && !g("ab", "abc"));
        // Many stars on a long miss: linear, not exponential.
        assert!(!g(&"*a".repeat(30), &"a".repeat(29)));
    }

    #[test]
    fn tokens() {
        let t = Tokens {
            home: "/home/me",
            local_user: "me",
            host: "h.example.com",
            user: "deploy",
        };
        assert_eq!(
            expand_tokens("%d/.ssh/%u-%r@%h %% %p %", &t),
            "/home/me/.ssh/me-deploy@h.example.com % %p %"
        );
        assert!(path().is_none_or(|p| p.ends_with("config")));
        let _ = user_text(); // whatever the developer has: never panics
    }
}

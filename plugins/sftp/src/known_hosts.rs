//! OpenSSH `known_hosts` check (pure): plain, wildcard (`*`, `?`), negated (`!`) and hashed
//! (`|1|salt|hmac-sha1`) host patterns, `[host]:port` for non-22 ports, `@revoked` lines.
//! Unknown or changed keys are refused; nothing is ever trusted automatically.
use data_encoding::BASE64;
use ring::hmac;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Known,
    Unknown,
    /// Another key of the same type is recorded (1-based line).
    Changed(usize),
    /// Only keys of another type (this one) are recorded for the host.
    OtherType(String),
    Revoked,
}

/// The name a server is recorded under: `host`, or `[host]:port` off port 22.
pub fn lookup_name(host: &str, port: u16) -> String {
    let h = host.to_ascii_lowercase();
    match port {
        22 => h,
        p => format!("[{h}]:{p}"),
    }
}

/// `*` / `?` wildcards, ASCII case-insensitive.
fn glob(pat: &[u8], s: &[u8]) -> bool {
    let (mut p, mut i) = (0, 0);
    let mut star = None; // (pattern pos after '*', input pos it matched up to)
    while i < s.len() {
        match pat.get(p) {
            Some(b'*') => {
                star = Some((p + 1, i));
                p += 1;
            }
            Some(&c) if c == b'?' || c.eq_ignore_ascii_case(&s[i]) => {
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
    pat[p..].iter().all(|&c| c == b'*')
}

/// `salt|hash` (base64) = HMAC-SHA1(salt, name)?
fn hashed(entry: &str, name: &str) -> bool {
    let Some((salt, hash)) = entry.split_once('|') else {
        return false;
    };
    let (Ok(salt), Ok(hash)) = (
        BASE64.decode(salt.as_bytes()),
        BASE64.decode(hash.as_bytes()),
    ) else {
        return false;
    };
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &salt);
    hmac::verify(&key, name.as_bytes(), &hash).is_ok()
}

/// Comma list of patterns; any negated match excludes the line.
fn host_matches(patterns: &str, name: &str) -> bool {
    let mut hit = false;
    for p in patterns.split(',') {
        let (neg, p) = match p.strip_prefix('!') {
            Some(p) => (true, p),
            None => (false, p),
        };
        let m = match p.strip_prefix("|1|") {
            Some(h) => hashed(h, name),
            None => glob(p.as_bytes(), name.as_bytes()),
        };
        if m && neg {
            return false;
        }
        hit |= m;
    }
    hit
}

/// One line recorded for a host.
struct Line<'a> {
    /// 1-based.
    no: usize,
    /// `@revoked` / `@cert-authority` without the `@`.
    marker: Option<&'a str>,
    ty: &'a str,
    b64: &'a str,
}

/// The lines of `text` whose host patterns match `name`.
fn lines_for<'a>(text: &'a str, name: &'a str) -> impl Iterator<Item = Line<'a>> {
    text.lines().enumerate().filter_map(move |(i, line)| {
        let mut f = line.split_whitespace();
        let mut hosts = f.next().filter(|h| !h.starts_with('#'))?;
        let marker = hosts.strip_prefix('@');
        if marker.is_some() {
            hosts = f.next()?;
        }
        let (ty, b64) = (f.next()?, f.next()?);
        host_matches(hosts, name).then_some(Line {
            no: i + 1,
            marker,
            ty,
            b64,
        })
    })
}

/// Key types with a plain entry for `name` (to ask the server for exactly those, like OpenSSH).
pub fn recorded_types(text: &str, name: &str) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for l in lines_for(text, name).filter(|l| l.marker.is_none()) {
        if !v.iter().any(|t| t == l.ty) {
            v.push(l.ty.to_owned());
        }
    }
    v
}

/// Is `key_type` + `blob` (SSH wire encoding) recorded for `name` ([`lookup_name`]) in `text`?
pub fn check(text: &str, name: &str, key_type: &str, blob: &[u8]) -> Verdict {
    let (mut known, mut changed, mut other) = (false, None, None);
    for l in lines_for(text, name) {
        let same = l.ty == key_type && BASE64.decode(l.b64.as_bytes()).is_ok_and(|k| k == blob);
        match l.marker {
            Some("revoked") if same => return Verdict::Revoked,
            Some(_) => {} // @cert-authority: host certificates are not used
            None if same => known = true,
            None if l.ty == key_type => {
                changed.get_or_insert(l.no);
            }
            None => {
                other.get_or_insert(l.ty);
            }
        }
    }
    match (known, changed, other) {
        (true, _, _) => Verdict::Known,
        (false, Some(n), _) => Verdict::Changed(n),
        (false, None, Some(ty)) => Verdict::OtherType(ty.to_owned()),
        (false, None, None) => Verdict::Unknown,
    }
}

/// Why a key is refused (`None` = accepted). `fp` = `SHA256:...`, `entry` = `type base64`.
pub fn refusal(v: Verdict, name: &str, fp: &str, entry: &str, file: &str) -> Option<String> {
    match v {
        Verdict::Known => None,
        Verdict::Unknown => Some(format!(
            "sftp: {name}: unknown host key {fp}. Check that fingerprint with the server's admin, \
             then trust it (connect once with ssh, or add this line to {file}): {name} {entry}"
        )),
        Verdict::Changed(line) => Some(format!(
            "sftp: {name}: HOST KEY CHANGED (now {fp}; {file} line {line} differs). Someone may \
             be intercepting the connection. If the change is expected, remove that line."
        )),
        Verdict::OtherType(ty) => Some(format!(
            "sftp: {name}: the server offered a {} key ({fp}), but the host has a {ty} key \
             recorded in {file}. Refused: check with the server's admin before changing it.",
            entry.split(' ').next().unwrap_or("different")
        )),
        Verdict::Revoked => Some(format!(
            "sftp: {name}: host key {fp} is marked @revoked in {file}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED: &str = "ssh-ed25519";
    // Any bytes work: entries are compared as decoded blobs.
    const K1: &[u8] = b"key-one";
    const K2: &[u8] = b"key-two";

    fn line(hosts: &str, ty: &str, k: &[u8]) -> String {
        format!("{hosts} {ty} {} comment\n", BASE64.encode(k))
    }

    #[test]
    fn names() {
        assert_eq!(lookup_name("Example.COM", 22), "example.com");
        assert_eq!(lookup_name("h", 2222), "[h]:2222");
        assert_eq!(lookup_name("::1", 2222), "[::1]:2222");
    }

    #[test]
    fn plain_entries() {
        let text = format!(
            "# comment\n\n{}{}{}",
            line("a.com,b.com", ED, K1),
            line("[c.com]:2222", ED, K1),
            line("x.com", "ssh-rsa", K2),
        );
        let c = |name: &str, ty, k| check(&text, name, ty, k);
        assert_eq!(c("b.com", ED, K1), Verdict::Known);
        assert_eq!(c("[c.com]:2222", ED, K1), Verdict::Known);
        assert_eq!(c("c.com", ED, K1), Verdict::Unknown, "port matters");
        assert_eq!(c("a.com", ED, K2), Verdict::Changed(3));
        assert_eq!(
            c("x.com", ED, K1),
            Verdict::OtherType("ssh-rsa".into()),
            "other key type only"
        );
        assert_eq!(recorded_types(&text, "x.com"), ["ssh-rsa"]);
        let two = format!(
            "{}{}{}",
            line("h", ED, K1),
            line("h", "ssh-rsa", K2),
            line("h", ED, K2)
        );
        assert_eq!(recorded_types(&two, "h"), [ED, "ssh-rsa"]);
        assert!(recorded_types(&two, "nope").is_empty());
        let m = refusal(
            Verdict::OtherType("ssh-rsa".into()),
            "h",
            "SHA256:x",
            "ssh-ed25519 AA",
            "kh",
        );
        assert!(m.unwrap().contains("has a ssh-rsa key recorded"));
        assert_eq!(c("nope.com", ED, K1), Verdict::Unknown);
        assert_eq!(check("", "a.com", ED, K1), Verdict::Unknown);
    }

    #[test]
    fn hashed_entries() {
        // Python: hmac.new(bytes(range(1,21)), b"example.com", sha1)
        let salt = "AQIDBAUGBwgJCgsMDQ4PEBESExQ=";
        let text = format!(
            "{}{}",
            line(&format!("|1|{salt}|qvtG0DaqrsqPDhV2Ni+wmYohchA="), ED, K1),
            line(&format!("|1|{salt}|uVLj+YL3GsbtNOcCoC7AMM/WVh0="), ED, K2),
        );
        assert_eq!(check(&text, "example.com", ED, K1), Verdict::Known);
        assert_eq!(check(&text, "[example.com]:2222", ED, K2), Verdict::Known);
        assert_eq!(check(&text, "example.org", ED, K1), Verdict::Unknown);
        assert_eq!(check(&text, "example.com", ED, K2), Verdict::Changed(1));
        for bad in ["|1|nobar", "|1|!!|AA==", "|1|AA==|!!"] {
            assert_eq!(
                check(&line(bad, ED, K1), "example.com", ED, K1),
                Verdict::Unknown
            );
        }
    }

    #[test]
    fn wildcards_and_negation() {
        let text = line("*.lan,!evil.lan,10.0.0.?", ED, K1);
        let c = |name: &str| check(&text, name, ED, K1);
        assert_eq!(c("box.lan"), Verdict::Known);
        assert_eq!(c("BOX.LAN"), Verdict::Known, "case-insensitive");
        assert_eq!(c("evil.lan"), Verdict::Unknown, "negated");
        assert_eq!(c("10.0.0.7"), Verdict::Known);
        assert_eq!(c("10.0.0.77"), Verdict::Unknown);
        assert!(glob(b"a*b*c", b"axxbyyc") && !glob(b"a*b", b"axxc") && glob(b"**", b""));
    }

    #[test]
    fn markers_and_junk() {
        let text = format!(
            "{}{}@cert-authority *.lan {ED} AAAA\n@revoked\nshort line\nh {ED} !!notbase64\n",
            line("h", ED, K1),
            line("@revoked h", ED, K1),
        );
        assert_eq!(check(&text, "h", ED, K1), Verdict::Revoked, "revoked wins");
        assert_eq!(check(&text, "h", ED, K2), Verdict::Changed(1));
        assert_eq!(
            check(&text, "x.lan", ED, K1),
            Verdict::Unknown,
            "CA lines ignored"
        );
    }

    #[test]
    fn refusal_messages() {
        let r = |v| refusal(v, "h", "SHA256:abc", "ssh-ed25519 AAAA", "kh");
        assert_eq!(r(Verdict::Known), None);
        let u = r(Verdict::Unknown).unwrap();
        assert!(
            u.contains("SHA256:abc") && u.contains("h ssh-ed25519 AAAA"),
            "{u}"
        );
        assert!(r(Verdict::Changed(7)).unwrap().contains("line 7"));
        assert!(r(Verdict::Revoked).unwrap().contains("@revoked"));
    }
}

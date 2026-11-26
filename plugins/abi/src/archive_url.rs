//! Archive-file mounts (`[vfs] extensions` plugins): the archive's fs path travels as ONE URL
//! authority segment, `<scheme>://<encoded path>/<inner>`. The native separator becomes `|`
//! (readable: `sevenzip://C:|x|a.rar/sub`); `%`, `|`, `@` (password masking), the other
//! slash and control chars are `%XX`. Shared by host and plugins so both agree.
//! An optional secret (archive password from a host prompt) follows the mount in the `open`
//! config after [`SECRET_SEP`]; it is never part of a path.
use alloc::string::String;
use alloc::vec::Vec;

/// `open(config)`: `<scheme>://<authority>` [`SECRET_SEP` `<secret>`].
pub const SECRET_SEP: char = '\n';

const NATIVE: char = if cfg!(windows) { '\\' } else { '/' };

/// fs path (UTF-8) -> authority segment. Windows accepts `/` too: both map to `|`.
pub fn encode(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        match c {
            c if c == NATIVE || (cfg!(windows) && c == '/') => out.push('|'),
            '%' | '|' | '@' | '/' | '\\' => push_hex(&mut out, c as u8),
            c if c.is_control() && c.is_ascii() => push_hex(&mut out, c as u8),
            c => out.push(c),
        }
    }
    out
}

fn push_hex(out: &mut String, b: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out.push('%');
    out.push(HEX[usize::from(b >> 4)] as char);
    out.push(HEX[usize::from(b & 15)] as char);
}

/// [`encode`] reversed; None on a bad escape or non-UTF-8 result.
pub fn decode(seg: &str) -> Option<String> {
    let mut out = Vec::with_capacity(seg.len());
    let mut it = seg.bytes();
    while let Some(b) = it.next() {
        match b {
            b'|' => out.push(NATIVE as u8),
            b'%' => {
                let hi = (it.next()? as char).to_digit(16)?;
                let lo = (it.next()? as char).to_digit(16)?;
                out.push((hi * 16 + lo) as u8);
            }
            b => out.push(b),
        }
    }
    String::from_utf8(out).ok()
}

/// Split an `open` config into (mount, secret).
pub fn split_secret(config: &str) -> (&str, Option<&str>) {
    match config.split_once(SECRET_SEP) {
        Some((m, s)) => (m, Some(s)),
        None => (config, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_shape() {
        for p in [
            "C:\\Users\\me@corp\\a 1%.rar",
            "/home/me/a|b.rar",
            "/x/back\\slash.7z",
            "\\\\srv\\share\\a.iso",
            "tab\there",
            "é/ü.7z",
        ] {
            let e = encode(p);
            assert!(
                !e.contains(['/', '\\', '@']) && !e.contains(char::is_control),
                "{e}"
            );
            let back = decode(&e).unwrap();
            let want = match cfg!(windows) {
                true => p.replace('/', "\\"),
                false => p.into(),
            };
            assert_eq!(back, want, "{p}");
        }
        let native = if cfg!(windows) {
            "C:\\x\\a.rar"
        } else {
            "/x/a.rar"
        };
        assert_eq!(encode(native).matches('|').count(), 2);
        assert_eq!(decode("%4"), None);
        assert_eq!(decode("%zz"), None);
        assert_eq!(decode("%FF"), None, "not UTF-8");
        assert_eq!(split_secret("s://a\npw\nx"), ("s://a", Some("pw\nx")));
        assert_eq!(split_secret("s://a"), ("s://a", None));
    }
}

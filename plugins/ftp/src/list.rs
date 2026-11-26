//! Directory listing lines -> items: MLSD facts, else `LIST` in unix or DOS format.
use commander_plugin_abi::{self as abi, glue::Item, glue::valid_name};
use std::time::UNIX_EPOCH;
use suppaftp::list::{File, ListParser};

/// MLSD line with only the facts we use (`type`, `size`, `modify`): suppaftp rejects the whole
/// line on a fact it can't parse (e.g. `UNIX.mode=100644`, `type=OS.unix=slink:/x`).
fn mlsx_clean(line: &str) -> Option<String> {
    let (facts, name) = line.split_once("; ")?;
    let mut out = String::new();
    for fact in facts.split(';') {
        let Some((k, v)) = fact.split_once('=') else {
            continue;
        };
        let k = k.to_ascii_lowercase();
        let v = match k.as_str() {
            // RFC 3659 OS-specific types: unix symlinks (`OS.unix=slink:...`) and the like.
            "type" if v.to_ascii_lowercase().starts_with("os.") => "link",
            "type" | "size" | "modify" => v,
            _ => continue,
        };
        out.push_str(&format!("{k}={v};"));
    }
    Some(format!("{out} {name}"))
}

fn to_item(f: &File, name: String) -> Item {
    let kind = match () {
        _ if f.is_directory() => abi::KIND_DIR,
        _ if f.is_symlink() => abi::KIND_SYMLINK,
        _ => abi::KIND_FILE,
    };
    let mtime = f
        .modified()
        .duration_since(UNIX_EPOCH)
        .ok()
        .filter(|d| !d.is_zero()) // parser default = unknown
        .and_then(|d| i64::try_from(d.as_nanos()).ok());
    Item {
        name,
        kind,
        size: if kind == abi::KIND_FILE {
            f.size() as u64
        } else {
            0
        },
        mtime,
        link: false,
    }
}

/// Listing entry; `None` for ".", "..", MLSD cdir/pdir and names the host can't hold.
fn item(f: &File) -> Option<Item> {
    valid_name(f.name()).then(|| to_item(f, f.name().to_owned()))
}

/// One MLSD line (`None` = skip).
pub fn mlsd(line: &str) -> Option<Item> {
    item(&ListParser::parse_mlsd(&mlsx_clean(line)?).ok()?)
}

/// MLST reply line, for `stat` (its full-path name is dropped).
pub fn mlst(line: &str) -> Option<Item> {
    let f = ListParser::parse_mlst(&mlsx_clean(line.trim_start())?).ok()?;
    Some(to_item(&f, String::new()))
}
/// One `LIST` line, unix (`ls -l`) or DOS/IIS format (`None` = skip, e.g. `total 12`).
pub fn list(line: &str) -> Option<Item> {
    let f = ListParser::parse_posix(line)
        .or_else(|_| ListParser::parse_dos(line))
        .ok()?;
    item(&f)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kn(i: &Item) -> (&str, u32, u64) {
        (i.name.as_str(), i.kind, i.size)
    }

    #[test]
    fn unix_lines() {
        let f = list("-rw-r--r--   1 ftp  ftp      1234 Nov  5 13:46 readme.txt").unwrap();
        assert_eq!(kn(&f), ("readme.txt", abi::KIND_FILE, 1234));
        assert!(f.mtime.is_some());
        let d = list("drwxr-xr-x   2 0  0      4096 Jan 01  2019 pub").unwrap();
        assert_eq!(kn(&d), ("pub", abi::KIND_DIR, 0));
        assert!(list("total 12").is_none());
        assert!(list("-rw-r--r--   1 u  g  1 Mar 10 09:15 ../etc/passwd").is_none());
        assert!(list("-rw-r--r--   1 u  g  1 Mar 10 09:15 a\\b.txt").is_none());
        assert!(list("04-08-14  03:09PM   403 c:\\x.txt").is_none());
        assert!(list("drwxr-xr-x   2 0  0      4096 Jan 01  2019 ..").is_none());
    }

    #[test]
    fn unix_symlink_and_spaces() {
        let l = list("lrwxrwxrwx   1 0  0         8 Mar 10 09:15 latest -> rel/v2.1").unwrap();
        assert_eq!(kn(&l), ("latest", abi::KIND_SYMLINK, 0));
        let s = list("-rw-r--r--   1 u  g        42 Mar 10 09:15 my  holiday pics.zip").unwrap();
        assert_eq!(kn(&s), ("my  holiday pics.zip", abi::KIND_FILE, 42));
        let u = list("-rw-r--r--   1 u  g         7 Mar 10 09:15 Grüße.txt").unwrap();
        assert_eq!(u.name, "Grüße.txt");
    }

    #[test]
    fn dos_lines() {
        let d = list("10-19-20  03:19PM       <DIR>          pub files").unwrap();
        assert_eq!(kn(&d), ("pub files", abi::KIND_DIR, 0));
        let f = list("04-08-14  03:09PM                  403 readme.txt").unwrap();
        assert_eq!(kn(&f), ("readme.txt", abi::KIND_FILE, 403));
        assert!(f.mtime.is_some());
    }

    #[test]
    fn mlsd_lines() {
        let f =
            mlsd("type=file;size=1024;modify=20201019151930;UNIX.mode=0644; a b;c.txt").unwrap();
        assert_eq!(kn(&f), ("a b;c.txt", abi::KIND_FILE, 1024));
        assert_eq!(f.mtime, Some(1_603_120_770_000_000_000));
        let d = mlsd("Type=dir;Modify=20201019151930;UNIX.mode=100755; pub").unwrap();
        assert_eq!(kn(&d), ("pub", abi::KIND_DIR, 0));
        let l = mlsd("type=OS.unix=slink:/srv/x;modify=20201019151930; link").unwrap();
        assert_eq!(kn(&l), ("link", abi::KIND_SYMLINK, 0));
        assert!(mlsd("type=cdir;modify=20201019151930; .").is_none());
        assert!(mlsd("type=pdir;modify=20201019151930; ..").is_none());
        assert!(mlsd("type=file;size=1; bad:name").is_none());
        assert!(mlsd("type=file;size=1; a/b").is_none(), "slash");
        assert!(mlsd("type=file;size=1; a\\b").is_none(), "backslash");
        assert!(mlsd("type=file;size=1;").is_none(), "no name");
        assert!(mlsd("type=file;size=1; a\rb").is_none(), "CR");
        assert!(mlsd("type=file;size=1; a\nb").is_none(), "LF");
        assert!(mlsd("type=weird;size=1; x").is_none(), "unknown type");
    }

    #[test]
    fn mlst_reply() {
        let f = mlst(" type=file;size=5;modify=20201019151930; /dir/f.txt").unwrap();
        assert_eq!(kn(&f), ("", abi::KIND_FILE, 5));
        let d = mlst("type=dir; /dir").unwrap();
        assert_eq!(kn(&d), ("", abi::KIND_DIR, 0));
    }
}

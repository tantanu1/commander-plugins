//! `7z l -slt` output -> flat records -> a dir tree with host-safe names only.
use commander_plugin_abi::glue::{self, Item};
use commander_plugin_abi::names::is_device_name;
use commander_plugin_abi::{KIND_DIR, KIND_FILE};
use std::collections::HashMap;

/// One listed archive item, as 7-Zip printed it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Raw {
    /// Exactly as listed (passed back to 7z verbatim).
    pub path: String,
    pub is_dir: bool,
    /// None: not listed (empty `Size =`).
    pub size: Option<u64>,
    /// Unix ns. 7-Zip prints local wall-clock time: taken as UTC so it shows unchanged
    /// (same rule as the built-in zip reader).
    pub mtime: Option<i64>,
    pub encrypted: bool,
    /// Symlink / hard link: never listed (no link is ever written out).
    pub link: bool,
}

/// Records after the `----------` line; blocks are blank-line separated `Key = Value` lines.
/// A name holding a newline could forge lines: forged records still pass `clean`, and a
/// forged name reads nothing (7z finds no such item), so they can't escape the rules.
pub fn parse(out: &str) -> Vec<Raw> {
    let mut lines = out.lines().map(|l| l.strip_suffix('\r').unwrap_or(l));
    if !lines.any(|l| l == "----------") {
        return Vec::new();
    }
    let (mut all, mut cur): (Vec<Raw>, Option<Raw>) = (Vec::new(), None);
    for l in lines {
        if l.is_empty() {
            all.extend(cur.take());
            continue;
        }
        let (k, v) = l
            .split_once(" = ")
            .unwrap_or((l.trim_end_matches(" ="), ""));
        if k == "Path" {
            all.extend(cur.take());
            cur = Some(Raw {
                path: v.to_owned(),
                ..Raw::default()
            });
            continue;
        }
        let Some(r) = cur.as_mut() else { continue };
        match k {
            "Folder" => r.is_dir |= v == "+",
            "Size" => r.size = v.parse().ok(),
            "Modified" => r.mtime = parse_time(v),
            "Encrypted" => r.encrypted = v == "+",
            "Attributes" => {
                let (win, unix) = v.split_once(' ').unwrap_or((v, ""));
                r.is_dir |= win.contains('D') || unix.starts_with('d');
                r.link |= unix.starts_with('l');
            }
            "Symbolic Link" | "Hard Link" | "Link" => r.link |= !v.is_empty(),
            _ => {}
        }
    }
    all.extend(cur);
    all
}

/// `YYYY-MM-DD HH:MM:SS[.fraction]` -> unix ns.
fn parse_time(v: &str) -> Option<i64> {
    let (date, time) = v.split_once(' ')?;
    let num = |s: &str| s.parse::<i64>().ok();
    let mut d = date.splitn(3, '-').map(num);
    let (y, mo, da) = (d.next()??, d.next()??, d.next()??);
    let (hms, frac) = time.split_once('.').unwrap_or((time, ""));
    let mut t = hms.splitn(3, ':').map(num);
    let (h, mi, s) = (t.next()??, t.next()??, t.next()??);
    let ok = (1..=12).contains(&mo) && (1..=31).contains(&da) && h < 24 && mi < 60 && s < 61;
    let ns: String = frac.chars().chain("000000000".chars()).take(9).collect();
    let secs = glue::days_from_civil(y, mo, da) * 86_400 + h * 3600 + mi * 60 + s;
    ok.then(|| Some(secs.checked_mul(1_000_000_000)? + ns.parse::<i64>().ok()?))
        .flatten()
}

/// Host-safe segments of an archive name (like core's `unpack::safe_rel`): both separators
/// split, empty and `.` segments dropped; absolute, `..`, drive (`:`) or control-char names
/// are refused (None), so they are never listed and never extracted.
pub fn clean(name: &str) -> Option<Vec<&str>> {
    if name.starts_with(['/', '\\']) {
        return None;
    }
    let segs: Vec<&str> = name
        .split(['/', '\\'])
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();
    segs.iter().all(|s| glue::valid_name(s)).then_some(segs)
}

/// Name shown (and copied out) for an archive segment. Windows: a device name (`aux.c`,
/// `CON`) gets a `_` prefix like 7-Zip's own extract, so a copy never opens the device; 7z
/// itself is always given the raw name.
fn listed_name(seg: &str) -> String {
    match cfg!(windows) && is_device_name(seg) {
        true => format!("_{seg}"),
        false => seg.to_owned(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ent {
    pub is_dir: bool,
    /// None: 7-Zip listed no size (reads are then not capped).
    pub size: Option<u64>,
    pub mtime: Option<i64>,
    /// The archive's own name for it ('/'-joined raw segments for an implied dir), handed
    /// to 7z verbatim (a listed device name may be shown with a `_` prefix).
    pub raw: String,
    /// No entry of its own: only implied by items below it.
    pub implied: bool,
    pub encrypted: bool,
}

/// Clean '/'-joined path -> entry ("" = root), and dir -> child names. Records that are not
/// listed (links, unsafe names, duplicates, a file in a dir's way) are kept as `hidden` raw
/// segments, so a delete never takes them along unseen.
#[derive(Debug, Default)]
pub struct Tree {
    ents: HashMap<String, Ent>,
    kids: HashMap<String, Vec<String>>,
    hidden: Vec<Vec<String>>,
}

fn implied(raw: String) -> Ent {
    Ent {
        is_dir: true,
        size: Some(0),
        mtime: None,
        raw,
        implied: true,
        encrypted: false,
    }
}

/// Raw name split like 7-Zip matches it (both separators; empty and `.` segments dropped).
fn raw_segs(raw: &str) -> Vec<String> {
    raw.split(['/', '\\'])
        .filter(|s| !s.is_empty() && *s != ".")
        .map(str::to_owned)
        .collect()
}

impl Tree {
    pub fn build(raws: Vec<Raw>) -> Self {
        let mut t = Tree::default();
        t.ents.insert(String::new(), implied(String::new()));
        for r in raws {
            let raw: Vec<String> = match clean(&r.path).filter(|s| !s.is_empty() && !r.link) {
                Some(s) => s.into_iter().map(str::to_owned).collect(),
                None => {
                    t.hidden.push(raw_segs(&r.path));
                    continue;
                }
            };
            if !t.insert(&raw, r) {
                t.hidden.push(raw);
            }
        }
        t
    }

    /// False: not listed (duplicate, or a file in the way).
    fn insert(&mut self, raw: &[String], r: Raw) -> bool {
        let segs: Vec<String> = raw.iter().map(|s| listed_name(s)).collect();
        // Parents first; a file in the way (a "x" file and "x/y") drops the entry.
        for i in 1..segs.len() {
            let dir = segs[..i].join("/");
            match self.ents.get(&dir) {
                Some(e) if !e.is_dir => return false,
                Some(_) => {}
                None => {
                    let e = implied(raw[..i].join("/"));
                    self.add(dir, &segs[i - 1], &segs[..i - 1], e);
                }
            }
        }
        let path = segs.join("/");
        let ent = Ent {
            is_dir: r.is_dir,
            size: if r.is_dir { Some(0) } else { r.size },
            mtime: r.mtime,
            raw: r.path,
            implied: false,
            encrypted: r.encrypted,
        };
        match self.ents.get_mut(&path) {
            // An explicit dir entry after its implied twin: keep its date and name.
            Some(e) if e.is_dir && ent.is_dir && e.implied => *e = ent,
            Some(_) => return false, // duplicate: first wins
            None => {
                let name = &segs[segs.len() - 1];
                self.add(path, name, &segs[..segs.len() - 1], ent);
            }
        }
        true
    }

    fn add(&mut self, path: String, name: &str, parent: &[String], e: Ent) {
        self.kids
            .entry(parent.join("/"))
            .or_default()
            .push(name.to_owned());
        self.ents.insert(path, e);
    }

    pub fn get(&self, path: &str) -> Option<&Ent> {
        self.ents.get(path)
    }

    /// Children of dir `dir` (None: not a dir here).
    pub fn list(&self, dir: &str) -> Option<Vec<Item>> {
        if !self.get(dir)?.is_dir {
            return None;
        }
        let kids = self.kids.get(dir).map_or(&[][..], Vec::as_slice);
        Some(
            kids.iter()
                .map(|n| {
                    let p = match dir {
                        "" => n.clone(),
                        d => format!("{d}/{n}"),
                    };
                    item(n, &self.ents[&p])
                })
                .collect(),
        )
    }

    /// An unlisted record is `raw` itself or sits below it (7z d / rn would touch it).
    pub fn hides_under(&self, raw: &str) -> bool {
        let base = raw_segs(raw);
        self.hidden.iter().any(|h| h.starts_with(&base))
    }

    /// Smallest encrypted file (cheapest password check), if any.
    pub fn smallest_encrypted(&self) -> Option<&Ent> {
        self.ents
            .values()
            .filter(|e| e.encrypted && !e.is_dir)
            .min_by_key(|e| e.size)
    }
}

pub fn item(name: &str, e: &Ent) -> Item {
    Item {
        name: name.to_owned(),
        kind: if e.is_dir { KIND_DIR } else { KIND_FILE },
        size: e.size.unwrap_or(0),
        mtime: e.mtime,
        link: false, // links are never listed
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    const OUT: &str = "\
7-Zip 26.00 (x64)\r\n\r\nListing archive: C:\\a.7z\r\n\r\n--\r\nPath = C:\\a.7z\r\nType = 7z\r\n\r\n\
----------\r\n\
Path = sub\r\nSize = 0\r\nModified = 2026-11-23 13:18:46.6711354\r\nAttributes = D\r\nEncrypted = -\r\n\r\n\
Path = sub\\b.txt\r\nSize = 7\r\nModified = 2026-11-23 13:18:46\r\nAttributes = A\r\nCRC = \r\nEncrypted = +\r\n\r\n\
Path = -x.txt\r\nSize = 6\r\nAttributes = A_ -rw-r--r--\r\nEncrypted = -\r\n\r\n\
Path = zipdir\r\nFolder = +\r\nSize = \r\n\r\n\
Path = deep/x/y.txt\r\nSize = 1\r\n\r\n\
Path = ln\r\nAttributes = A_ lrwxrwxrwx\r\nSize = 3\r\n\r\n\
Path = tarln\r\nSymbolic Link = /etc/passwd\r\n\r\n\
Path = ..\\evil.txt\r\nSize = 4\r\n\r\n\
Path = a\\..\\..\\b\r\nSize = 4\r\n\r\n\
Path = C:\\abs.txt\r\nSize = 4\r\n\r\n\
Path = /abs.txt\r\nSize = 4\r\n\r\n\
Path = bad\u{1b}name\r\nSize = 4\r\n\r\n\
Path = ./dot//x = y.txt\r\nSize = 2\r\n\r\n\
Path = sub\\b.txt\r\nSize = 99\r\n\r\n\
Path = -x.txt\\under-file\r\nSize = 1\r\n";

    #[test]
    fn parses_records() {
        let r = parse(OUT);
        assert_eq!(r.len(), 15, "{r:#?}");
        assert_eq!(
            r[0],
            Raw {
                path: "sub".into(),
                is_dir: true,
                size: Some(0),
                mtime: Some(1_795_439_926_671_135_400),
                encrypted: false,
                link: false,
            }
        );
        assert!(r[1].encrypted && !r[1].is_dir && r[1].size == Some(7));
        assert_eq!(r[1].mtime, Some(1_795_439_926_000_000_000));
        assert!(r[3].is_dir, "Folder = +");
        assert_eq!(r[3].size, None, "empty Size");
        assert!(r[5].link && r[6].link);
        assert_eq!(r[12].path, "./dot//x = y.txt");
        assert!(parse("no separator line\nPath = x").is_empty());
        assert_eq!(parse_time("2026-13-01 00:00:00"), None);
        assert_eq!(parse_time("garbage"), None);
        assert_eq!(parse_time("1970-01-01 00:00:01.5"), Some(1_500_000_000));
    }

    #[test]
    fn hostile_names_are_dropped() {
        for bad in [
            "..\\evil", "a/../b", "/abs", "\\abs", "C:\\x", "c:x", "a\u{0}b", "a\nb",
        ] {
            assert_eq!(clean(bad), None, "{bad:?}");
        }
        assert_eq!(clean("./a//b/"), Some(vec!["a", "b"]));
        let t = Tree::build(parse(OUT));
        let names = |d| {
            let mut v: Vec<_> = t.list(d).unwrap().into_iter().map(|i| i.name).collect();
            v.sort();
            v
        };
        assert_eq!(names(""), ["-x.txt", "deep", "dot", "sub", "zipdir"]);
        assert_eq!(names("dot"), ["x = y.txt"]);
        assert_eq!(names("deep/x"), ["y.txt"]);
        assert!(t.list("sub/b.txt").is_none() && t.list("nope").is_none());
        // Duplicate: first wins; a file in the way of a dir: dropped.
        assert_eq!(t.get("sub/b.txt").unwrap().size, Some(7));
        assert!(t.get("-x.txt/under-file").is_none());
        assert_eq!(t.get("sub").unwrap().raw, "sub");
        let deep = t.get("deep/x").unwrap();
        assert!(deep.implied && deep.raw == "deep/x", "implied: raw prefix");
        // Unlisted records (dup, file in the way, `a\..\..\b`) count for deletes below them.
        assert!(t.hides_under("sub") && t.hides_under("-x.txt") && t.hides_under("a"));
        assert!(!t.hides_under("deep") && !t.hides_under("zipdir"));
        assert_eq!(t.smallest_encrypted().unwrap().raw, "sub\\b.txt");
        let it = t.list("").unwrap();
        let sub = it.iter().find(|i| i.name == "sub").unwrap();
        assert_eq!((sub.kind, sub.size), (KIND_DIR, 0));
    }

    #[test]
    fn explicit_dir_after_implied_keeps_its_entry() {
        let raws = vec![
            Raw {
                path: "d/f".into(),
                size: Some(1),
                ..Raw::default()
            },
            Raw {
                path: "d".into(),
                is_dir: true,
                mtime: Some(5),
                ..Raw::default()
            },
        ];
        let t = Tree::build(raws);
        assert_eq!(t.get("d").unwrap().mtime, Some(5));
        assert!(!t.get("d").unwrap().implied);
        assert_eq!(t.list("").unwrap().len(), 1);
        assert!(t.smallest_encrypted().is_none());
    }

    #[test]
    fn device_names_get_a_prefix_on_windows() {
        let t = Tree::build(vec![Raw {
            path: "con\\aux.c".into(),
            size: Some(1),
            ..Raw::default()
        }]);
        let (dir, file) = match cfg!(windows) {
            true => ("_con", "_con/_aux.c"),
            false => ("con", "con/aux.c"),
        };
        assert_eq!(
            t.get(file).unwrap().raw,
            "con\\aux.c",
            "7z gets the raw name"
        );
        assert_eq!(t.get(dir).unwrap().raw, "con", "implied dir too");
        assert_eq!(listed_name("readme"), "readme");
    }
}

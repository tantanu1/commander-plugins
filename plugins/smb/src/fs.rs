//! SMB semantics over a [`Session`]. Mount `smb://` lists bookmarks; `smb://<authority>` is one
//! server whose root lists its shares (`share/path` below), or one share when a bookmark names
//! it. Uploads go to a temp name and are renamed on finish, so an aborted upload leaves nothing
//! at the target.
use crate::config::{self, Target};
use commander_plugin_abi::glue::{Error, Item, PART_TRIES, Result, part_name, valid_name};
use commander_plugin_abi::{self as abi, archive_url};
use std::io::Read;
use std::sync::Arc;
use zeroize::Zeroizing;

/// One signed-in server. Paths are share-relative, `/`-separated ("" = share root).
pub trait Session: Send + Sync {
    /// Disk shares (no `$` admin shares).
    fn shares(&self) -> Result<Vec<String>>;
    fn list(&self, share: &str, dir: &str) -> Result<Box<dyn Batches>>;
    fn stat(&self, share: &str, path: &str) -> Result<Item>;
    fn reader(&self, share: &str, path: &str, offset: u64) -> Result<Box<dyn Read + Send>>;
    /// Create a new file (an existing name fails with `EXISTS`, never opened).
    fn create(&self, share: &str, path: &str) -> Result<Box<dyn Upload>>;
    fn mkdir(&self, share: &str, path: &str) -> Result<()>;
    fn remove_file(&self, share: &str, path: &str) -> Result<()>;
    fn remove_dir(&self, share: &str, path: &str) -> Result<()>;
    /// `replace` = atomically over an existing `to`; else an existing `to` fails.
    fn rename(&self, share: &str, from: &str, to: &str, replace: bool) -> Result<()>;
}

/// An open new file. Dropped without `finish` = abandoned (the caller deletes it).
pub trait Upload: Send {
    fn write(&mut self, data: &[u8]) -> Result<()>;
    fn finish(self: Box<Self>) -> Result<()>;
}

/// A directory listing, one server batch at a time (`None` = done).
pub trait Batches: Send {
    fn next(&mut self) -> Result<Option<Vec<Item>>>;
}

impl Batches for std::vec::IntoIter<Vec<Item>> {
    fn next(&mut self) -> Result<Option<Vec<Item>>> {
        Ok(Iterator::next(self))
    }
}

/// Entries per listing before it fails (a huge or endless directory must not eat the memory).
const MAX_ENTRIES: usize = 1_000_000;

/// What `list` hands the host: batches fetched as it asks, cancel checked between them.
pub struct Listing {
    src: Option<Box<dyn Batches>>,
    buf: std::vec::IntoIter<Item>,
    seen: usize,
    max: usize,
}

impl Listing {
    fn ready(items: Vec<Item>) -> Self {
        Self {
            src: None,
            buf: items.into_iter(),
            seen: 0,
            max: MAX_ENTRIES,
        }
    }

    /// Everything (tests).
    #[cfg(test)]
    pub(crate) fn all(mut self) -> Result<Vec<Item>> {
        let mut out = Vec::new();
        loop {
            match self.next_batch(1000, &|| false)? {
                v if v.is_empty() => return Ok(out),
                v => out.extend(v),
            }
        }
    }

    /// Up to `cap` items; empty = done.
    pub fn next_batch(&mut self, cap: usize, cancelled: &dyn Fn() -> bool) -> Result<Vec<Item>> {
        loop {
            let out: Vec<Item> = self.buf.by_ref().take(cap).collect();
            let Some(src) = self.src.as_mut().filter(|_| out.is_empty()) else {
                return Ok(out);
            };
            if cancelled() {
                return Err(Error::new(abi::CANCELLED, "cancelled"));
            }
            let Some(mut v) = src.next()? else {
                self.src = None;
                continue;
            };
            self.seen += v.len();
            if self.seen > self.max {
                self.src = None;
                return Err(Error::new(
                    abi::IO,
                    format!("smb: more than {} entries in one folder", self.max),
                ));
            }
            v.retain(|i| valid_name(&i.name));
            self.buf = v.into_iter();
        }
    }
}

type Marks = fn() -> std::result::Result<config::Bookmarks, String>;

pub struct Smb {
    /// `None` = the `smb://` top (bookmark list).
    target: Option<Target>,
    sess: Option<Box<dyn Session>>,
    /// Bookmark source (`smb.toml`; injected by tests).
    marks: Marks,
}

fn unsupported(what: &str) -> Error {
    Error::new(abi::UNSUPPORTED, format!("smb: {what}"))
}

impl Smb {
    /// `config` = `smb://<authority>` (empty = bookmark list). A secret after
    /// `archive_url::SECRET_SEP` = the password the user typed after a `NEED_PASSPHRASE`.
    pub fn open(config: &str) -> Result<Self> {
        Self::open_with(config, config::bookmarks, &crate::client::dial)
    }

    pub(crate) fn open_with(
        config: &str,
        marks: Marks,
        dial: &dyn Fn(&Target) -> Result<Box<dyn Session>>,
    ) -> Result<Self> {
        let (config, secret) = archive_url::split_secret(config);
        let auth = config
            .strip_prefix("smb://")
            .ok_or_else(|| Error::new(abi::INVALID, "smb: mount must be smb://..."))?;
        let mut fs = Self {
            target: None,
            sess: None,
            marks,
        };
        if !auth.is_empty() {
            let mut t = config::resolve_in(auth, marks).map_err(|m| Error::new(abi::INVALID, m))?;
            if let Some(s) = secret {
                t.pass = Some(Zeroizing::new(s.to_owned()));
            }
            // Sign in now: a wrong host/password fails the mount (and asks), not a listing.
            fs.sess = Some(dial(&t)?);
            t.pass = None; // the client keeps the copy it reconnects with; ours goes now
            fs.target = Some(t);
        }
        Ok(fs)
    }

    fn sess(&self) -> Result<&dyn Session> {
        self.sess.as_deref().ok_or_else(|| {
            unsupported("not supported on the bookmark list (open a bookmark first)")
        })
    }

    /// `path` as (share, share-relative path); `None` = the share list (server root).
    fn split<'a>(&'a self, path: &'a str) -> Result<Option<(&'a str, &'a str)>> {
        self.sess()?;
        Ok(
            match self.target.as_ref().and_then(|t| t.share.as_deref()) {
                Some(share) => Some((share, path)),
                None if path.is_empty() => None,
                None => Some(path.split_once('/').unwrap_or((path, ""))),
            },
        )
    }

    /// Like [`Self::split`], for ops on an entry inside a share (not a share itself).
    fn inner<'a>(&'a self, path: &'a str, what: &str) -> Result<(&'a str, &'a str)> {
        match self.split(path)? {
            Some((share, p)) if !p.is_empty() => Ok((share, p)),
            _ => Err(unsupported(&format!("{what}: not on a share itself"))),
        }
    }

    pub fn list(&self, dir: &str) -> Result<Listing> {
        let dirs = |names: Vec<String>| {
            let items = names.into_iter().filter(|n| valid_name(n));
            Listing::ready(items.map(Item::dir).collect())
        };
        if self.sess.is_none() && dir.is_empty() {
            let marks = (self.marks)().map_err(|m| Error::new(abi::IO, m))?;
            return Ok(dirs(marks.into_keys().collect()));
        }
        let s = self.sess()?;
        match self.split(dir)? {
            None => Ok(dirs(s.shares()?)),
            Some((share, p)) => Ok(Listing {
                src: Some(s.list(share, p)?),
                ..Listing::ready(Vec::new())
            }),
        }
    }

    pub fn stat(&self, path: &str) -> Result<Item> {
        if self.sess.is_none() {
            let marks = (self.marks)().map_err(|m| Error::new(abi::IO, m))?;
            return match path.is_empty() || marks.contains_key(path) {
                true => Ok(Item::dir("")),
                false => Err(Error::new(
                    abi::NOT_FOUND,
                    format!("smb: no bookmark {path:?}"),
                )),
            };
        }
        match self.split(path)? {
            None => Ok(Item::dir("")),
            Some((share, p)) => self.sess()?.stat(share, p),
        }
    }

    /// Absent = `Ok(false)`; other errors pass through.
    fn exists(&self, share: &str, p: &str) -> Result<bool> {
        match self.sess()?.stat(share, p) {
            Ok(_) => Ok(true),
            Err(e) if e.status == abi::NOT_FOUND => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn exists_err(&self, share: &str, p: &str) -> Result<()> {
        match self.exists(share, p)? {
            true => Err(Error::new(abi::EXISTS, format!("smb: {share}/{p}: exists"))),
            false => Ok(()),
        }
    }

    pub fn reader(&self, path: &str, offset: u64) -> Result<Box<dyn Read + Send>> {
        let (share, p) = self.inner(path, "read")?;
        self.sess()?.reader(share, p, offset)
    }

    pub fn writer(self: &Arc<Self>, path: &str, overwrite: bool) -> Result<Writer> {
        let (share, p) = self.inner(path, "write")?;
        if !overwrite {
            self.exists_err(share, p)?;
        }
        let (dir, name) = p.rsplit_once('/').map_or(("", p), |(d, n)| (d, n));
        let mut last = None;
        for _ in 0..PART_TRIES {
            let tmp = match dir {
                "" => part_name(name),
                d => format!("{d}/{}", part_name(name)),
            };
            match self.sess()?.create(share, &tmp) {
                Ok(up) => {
                    return Ok(Writer {
                        up: Some(up),
                        fs: Arc::clone(self),
                        share: share.into(),
                        tmp,
                        dest: p.into(),
                        overwrite,
                    });
                }
                Err(e) if e.status == abi::EXISTS => last = Some(e),
                Err(e) => return Err(e),
            }
        }
        let why = last.map_or_else(String::new, |e| e.msg);
        Err(Error::new(
            abi::EXISTS,
            format!("smb: {share}/{p}: no free temp name ({why})"),
        ))
    }

    pub fn mkdir(&self, path: &str) -> Result<()> {
        let (share, p) = self.inner(path, "create folder")?;
        self.sess()?.mkdir(share, p)
    }

    pub fn remove_file(&self, path: &str) -> Result<()> {
        let (share, p) = self.inner(path, "delete")?;
        self.sess()?.remove_file(share, p)
    }

    pub fn remove_dir(&self, path: &str) -> Result<()> {
        let (share, p) = self.inner(path, "delete")?;
        self.sess()?.remove_dir(share, p)
    }

    pub fn rename(&self, from: &str, to: &str) -> Result<()> {
        let (sf, f) = self.inner(from, "rename")?;
        let (st, t) = self.inner(to, "rename")?;
        if sf != st {
            return Err(unsupported("move between shares: copy, then delete"));
        }
        // RULES: never a silent replace (SMB rename without replace refuses too). A case-only
        // rename in one folder finds itself on a case-insensitive share: not a clash (the
        // server's own no-replace rename still refuses a real other file).
        if f.to_lowercase() != t.to_lowercase() {
            self.exists_err(st, t)?;
        }
        self.sess()?.rename(sf, f, t, false)
    }
}

/// Upload into `tmp`; `finish` renames it to `dest`, drop deletes it.
pub struct Writer {
    up: Option<Box<dyn Upload>>,
    fs: Arc<Smb>,
    share: String,
    /// Share-relative temp path; empty once committed.
    tmp: String,
    dest: String,
    overwrite: bool,
}

impl Writer {
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        match self.up.as_mut() {
            Some(up) => up.write(data),
            None => Err(Error::new(abi::INTERNAL, "smb: closed")),
        }
    }

    pub fn finish(mut self) -> Result<()> {
        let up = self
            .up
            .take()
            .ok_or_else(|| Error::new(abi::INTERNAL, "smb: closed"))?;
        up.finish()?;
        // RULES: check the target is absent right before every rename (not only at open).
        if !self.overwrite {
            self.fs.exists_err(&self.share, &self.dest)?;
        }
        // One SET_INFO: atomic, the old file stays until the new one is in place.
        self.fs
            .sess()?
            .rename(&self.share, &self.tmp, &self.dest, self.overwrite)?;
        self.tmp.clear(); // committed: nothing to clean up
        Ok(())
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        drop(self.up.take()); // closes the handle
        if !self.tmp.is_empty()
            && let Ok(s) = self.fs.sess()
        {
            let _ = s.remove_file(&self.share, &self.tmp); // best effort
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Bookmarks;
    use crate::fake::{Fake, State};
    use commander_plugin_abi::Status;
    use std::sync::Mutex;

    fn no_marks() -> std::result::Result<Bookmarks, String> {
        Ok(Bookmarks::new())
    }

    fn marks() -> std::result::Result<Bookmarks, String> {
        config::parse_bookmarks(
            "[a]\nhost = \"h\"\nshare = \"pub\"\n[\"b:c\"]\nhost = \"h\"\n[srv]\nhost = \"h\"\n",
        )
    }

    fn broken_marks() -> std::result::Result<Bookmarks, String> {
        Err("smb.toml: broken".into())
    }

    fn server(url: &str, marks: Marks) -> (Arc<Mutex<State>>, Arc<Smb>) {
        let f = Fake::default();
        f.st.lock().unwrap().add_share("pub");
        f.st.lock().unwrap().add_share("docs");
        let st = Arc::clone(&f.st);
        let dial = move |_: &Target| -> Result<Box<dyn Session>> { Ok(Box::new(f.clone())) };
        (st, Arc::new(Smb::open_with(url, marks, &dial).unwrap()))
    }

    fn names(fs: &Smb, dir: &str) -> Vec<(String, u32)> {
        let mut v: Vec<_> = fs
            .list(dir)
            .unwrap()
            .all()
            .unwrap()
            .into_iter()
            .map(|i| (i.name, i.kind))
            .collect();
        v.sort();
        v
    }

    fn put(fs: &Arc<Smb>, p: &str, data: &[u8], overwrite: bool) -> Result<()> {
        let mut w = fs.writer(p, overwrite)?;
        w.write(data)?;
        w.finish()
    }

    fn read(fs: &Smb, p: &str, off: u64) -> String {
        let mut s = String::new();
        fs.reader(p, off).unwrap().read_to_string(&mut s).unwrap();
        s
    }

    fn st(r: Result<impl Sized>) -> Status {
        r.err().map_or(abi::OK, |e| e.status)
    }

    fn files(s: &Arc<Mutex<State>>) -> Vec<String> {
        s.lock().unwrap().paths()
    }

    #[test]
    fn bookmark_top() {
        let fs = Smb::open_with("smb://", marks, &|_| unreachable!()).unwrap();
        let want = [("a".into(), abi::KIND_DIR), ("srv".into(), abi::KIND_DIR)];
        assert_eq!(names(&fs, ""), want, "b:c is no valid name");
        assert_eq!(fs.stat("").unwrap().kind, abi::KIND_DIR);
        assert_eq!(fs.stat("a").unwrap().kind, abi::KIND_DIR);
        assert_eq!(st(fs.stat("zz")), abi::NOT_FOUND);
        assert_eq!(st(fs.list("a")), abi::UNSUPPORTED);
        assert_eq!(st(fs.remove_file("x")), abi::UNSUPPORTED);
        assert_eq!(st(fs.reader("x", 0)), abi::UNSUPPORTED);
        assert_eq!(st(Arc::new(fs).writer("x", true)), abi::UNSUPPORTED);
        let bad = Smb::open_with("smb://", broken_marks, &|_| unreachable!()).unwrap();
        assert_eq!(st(bad.list("")), abi::IO);
        assert_eq!(st(bad.stat("a")), abi::IO);
        let refuse = |_: &Target| -> Result<Box<dyn Session>> { unreachable!() };
        assert_eq!(
            st(Smb::open_with("ftp://h", no_marks, &refuse)),
            abi::INVALID
        );
        assert_eq!(
            st(Smb::open_with("smb://u:pw@h", no_marks, &refuse)),
            abi::INVALID,
            "no URL passwords"
        );
        let down = |_: &Target| -> Result<Box<dyn Session>> { Err(Error::new(abi::IO, "down")) };
        assert_eq!(st(Smb::open_with("smb://h", no_marks, &down)), abi::IO);
    }

    #[test]
    fn prompt_secret_reaches_the_dial_only() {
        let seen = Mutex::new(None);
        let dial = |t: &Target| -> Result<Box<dyn Session>> {
            *seen.lock().unwrap() = Some(t.clone());
            Ok(Box::new(Fake::default()))
        };
        Smb::open_with("smb://me@h\nsesame", no_marks, &dial).unwrap();
        let t = seen.lock().unwrap().take().unwrap();
        assert!(t.pass.as_ref().map(|p| p.as_str()) == Some("sesame"));
        assert_eq!((t.host.as_str(), t.user.as_str()), ("h", "me"));
        Smb::open_with("smb://srv", marks, &dial).unwrap();
        let t = seen.lock().unwrap().take().unwrap();
        assert!(t.pass.is_none());
    }

    #[test]
    fn server_root_lists_shares() {
        let (_st, fs) = server("smb://h", no_marks);
        let want = [
            ("docs".into(), abi::KIND_DIR),
            ("pub".into(), abi::KIND_DIR),
        ];
        assert_eq!(names(&fs, ""), want);
        assert_eq!(fs.stat("").unwrap().kind, abi::KIND_DIR);
        assert_eq!(fs.stat("pub").unwrap().kind, abi::KIND_DIR);
        assert_eq!(st(fs.stat("nope")), abi::NOT_FOUND);
        assert_eq!(st(fs.list("nope")), abi::NOT_FOUND);
        for r in [fs.mkdir("x"), fs.remove_dir("pub"), fs.remove_file("pub")] {
            assert_eq!(st(r), abi::UNSUPPORTED, "shares are not created or deleted");
        }
        assert_eq!(st(fs.reader("pub", 0)), abi::UNSUPPORTED);
        assert_eq!(st(fs.rename("pub", "pub2")), abi::UNSUPPORTED);
        put(&fs, "pub/a", b"x", false).unwrap();
        assert_eq!(
            st(fs.rename("pub/a", "docs/a")),
            abi::UNSUPPORTED,
            "across shares"
        );
        assert_eq!(names(&fs, "pub"), [("a".into(), abi::KIND_FILE)]);
    }

    #[test]
    fn roundtrip() {
        let (s, fs) = server("smb://h", no_marks);
        fs.mkdir("pub/d").unwrap();
        assert_eq!(st(fs.mkdir("pub/d")), abi::EXISTS);
        assert_eq!(st(fs.mkdir("pub/nope/x")), abi::NOT_FOUND);
        put(&fs, "pub/d/a b.txt", b"hello world", false).unwrap();
        s.lock().unwrap().put("pub", "d/bad:name", b"");
        assert_eq!(
            names(&fs, "pub/d"),
            [("a b.txt".into(), abi::KIND_FILE)],
            "host-unsafe names skipped"
        );
        let i = fs.stat("pub/d/a b.txt").unwrap();
        assert_eq!((i.kind, i.size), (abi::KIND_FILE, 11));
        assert_eq!(read(&fs, "pub/d/a b.txt", 0), "hello world");
        assert_eq!(read(&fs, "pub/d/a b.txt", 6), "world");
        assert_eq!(st(fs.reader("pub/d/zz", 0)), abi::NOT_FOUND);
        assert_eq!(st(put(&fs, "pub/d/a b.txt", b"x", false)), abi::EXISTS);
        put(&fs, "pub/d/a b.txt", b"new", true).unwrap();
        assert_eq!(read(&fs, "pub/d/a b.txt", 0), "new");
        let mut w = fs.writer("pub/d/gone", false).unwrap();
        w.write(b"partial").unwrap();
        drop(w); // abort
        assert_eq!(
            files(&s).len(),
            3,
            "aborted upload left nothing: {:?}",
            files(&s)
        );
        assert_eq!(st(fs.remove_dir("pub/d")), abi::NOT_EMPTY);
        put(&fs, "pub/c.txt", b"", false).unwrap();
        assert_eq!(st(fs.rename("pub/c.txt", "pub/d/a b.txt")), abi::EXISTS);
        fs.rename("pub/d/a b.txt", "pub/moved").unwrap();
        assert_eq!(st(fs.stat("pub/d/a b.txt")), abi::NOT_FOUND);
        assert_eq!(st(fs.rename("pub/zz", "pub/yy")), abi::NOT_FOUND);
        fs.remove_file("pub/moved").unwrap();
        s.lock()
            .unwrap()
            .shares
            .get_mut("pub")
            .unwrap()
            .remove("d/bad:name");
        fs.remove_dir("pub/d").unwrap();
        assert_eq!(st(fs.list("pub/d")), abi::NOT_FOUND);
    }

    #[test]
    fn bookmark_share_is_the_root() {
        let (s, fs) = server("smb://a", marks);
        put(&fs, "f", b"abc", false).unwrap();
        assert_eq!(names(&fs, ""), [("f".into(), abi::KIND_FILE)]);
        assert_eq!(fs.stat("").unwrap().kind, abi::KIND_DIR);
        assert!(s.lock().unwrap().paths().contains(&"pub/f".to_string()));
        assert_eq!(st(fs.mkdir("")), abi::UNSUPPORTED);
    }

    #[test]
    fn failed_replace_keeps_the_old_file() {
        let (s, fs) = server("smb://h", no_marks);
        put(&fs, "pub/a", b"old", false).unwrap();
        s.lock().unwrap().rename_fail = true;
        assert_eq!(st(put(&fs, "pub/a", b"new", true)), abi::DENIED);
        assert_eq!(read(&fs, "pub/a", 0), "old");
        assert_eq!(files(&s), ["pub/a"], "temp deleted");
    }

    #[test]
    fn existing_temp_names_are_never_written() {
        let (s, fs) = server("smb://h", no_marks);
        s.lock().unwrap().squat = 2;
        put(&fs, "pub/a", b"new", false).unwrap();
        assert_eq!(read(&fs, "pub/a", 0), "new");
        let (s, fs) = server("smb://h", no_marks);
        s.lock().unwrap().squat = PART_TRIES;
        assert_eq!(st(fs.writer("pub/a", false)), abi::EXISTS, "gives up");
        s.lock().unwrap().squat = 0;
        s.lock().unwrap().create_fail = true;
        assert_eq!(st(fs.writer("pub/a", false)), abi::DENIED);
    }

    #[test]
    fn target_created_during_upload_is_not_replaced() {
        let (s, fs) = server("smb://h", no_marks);
        let mut w = fs.writer("pub/a", false).unwrap();
        w.write(b"mine").unwrap();
        s.lock().unwrap().put("pub", "a", b"theirs");
        assert_eq!(st(w.finish()), abi::EXISTS);
        assert_eq!(read(&fs, "pub/a", 0), "theirs");
        assert_eq!(files(&s), ["pub/a"], "temp deleted");
    }

    #[test]
    fn upload_into_a_missing_dir_fails() {
        let (_s, fs) = server("smb://h", no_marks);
        assert_eq!(st(fs.writer("pub/nope/a", true)), abi::NOT_FOUND);
    }

    #[test]
    fn stat_errors_other_than_absent_abort_the_upload() {
        let (s, fs) = server("smb://h", no_marks);
        s.lock().unwrap().stat_fail = true;
        assert_eq!(st(fs.writer("pub/a", false)), abi::IO);
        assert_eq!(st(fs.rename("pub/a", "pub/b")), abi::IO);
    }

    #[test]
    fn closed_writer() {
        let (_s, fs) = server("smb://h", no_marks);
        let mut w = fs.writer("pub/a", false).unwrap();
        w.up = None;
        assert_eq!(st(w.write(b"x")), abi::INTERNAL);
        assert_eq!(st(w.finish()), abi::INTERNAL);
    }

    #[test]
    fn case_only_rename_skips_the_clash_check() {
        let (s, fs) = server("smb://h", no_marks);
        put(&fs, "pub/readme.txt", b"x", false).unwrap();
        // A case-insensitive server would say README.txt exists (it is the file itself).
        s.lock().unwrap().stat_fail = true;
        fs.rename("pub/readme.txt", "pub/README.txt").unwrap();
        assert_eq!(files(&s), ["pub/README.txt"]);
    }

    #[test]
    fn listings_come_in_batches_and_stop() {
        let (s, fs) = server("smb://h", no_marks);
        for n in ["a", "b", "c", "bad:x"] {
            s.lock().unwrap().put("pub", n, b"");
        }
        let mut l = fs.list("pub").unwrap();
        let first = l.next_batch(10, &|| false).unwrap();
        assert_eq!(first.len(), 2, "one server batch at a time");
        assert_eq!(
            l.next_batch(10, &|| false).unwrap().len(),
            1,
            "bad:x skipped"
        );
        assert!(l.next_batch(10, &|| false).unwrap().is_empty());
        let mut l = fs.list("pub").unwrap();
        assert_eq!(st(l.next_batch(10, &|| true)), abi::CANCELLED);
        let mut l = fs.list("pub").unwrap();
        l.max = 3;
        l.next_batch(10, &|| false).unwrap();
        let e = l.next_batch(10, &|| false).unwrap_err();
        assert!(e.msg.contains("more than 3 entries"), "{}", e.msg);
        assert!(l.next_batch(10, &|| false).unwrap().is_empty(), "stopped");
    }
}

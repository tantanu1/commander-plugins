//! SFTP semantics. Mount `sftp://` lists bookmarks; `sftp://<authority>` is one server, paths
//! are absolute (`/` + inner). One multiplexed SFTP session per mount, re-dialled after a
//! transport error. Uploads go to a temp name and are renamed on finish, so an aborted upload
//! leaves nothing at the target.
use crate::config::{self, Target};
use crate::ssh::{self, Conn};
use crate::ssh_config;
use commander_plugin_abi::glue::{Error, Item, PART_TRIES, Result, part_name, valid_name};
use commander_plugin_abi::{self as abi, archive_url};
use russh_sftp::client::SftpSession;
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::client::fs::{File, Metadata};
use russh_sftp::protocol::{OpenFlags, StatusCode};
use std::io::{Read, SeekFrom};
use std::sync::{Arc, Mutex, PoisonError};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use zeroize::Zeroizing;

/// Symlinks resolved (stat) per listing.
const MAX_PROBES: usize = 64;

/// `/` + inner path.
fn abs(path: &str) -> String {
    format!("/{path}")
}

fn parent_name(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

fn join(dir: &str, name: &str) -> String {
    match dir.is_empty() {
        true => name.to_owned(),
        false => format!("{dir}/{name}"),
    }
}

fn status(e: &SftpError) -> Option<StatusCode> {
    match e {
        SftpError::Status(s) => Some(s.status_code),
        _ => None,
    }
}

/// A server reply leaves the session usable; anything else (IO, timeout) may not.
fn broken(e: &SftpError) -> bool {
    status(e).is_none()
}

/// `e` as a plugin error about `what`.
fn ferr(e: SftpError, what: &str) -> Error {
    let st = match status(&e) {
        Some(StatusCode::NoSuchFile) => abi::NOT_FOUND,
        Some(StatusCode::PermissionDenied) => abi::DENIED,
        Some(StatusCode::OpUnsupported) => abi::UNSUPPORTED,
        _ => abi::IO,
    };
    let text = match &e {
        SftpError::Status(s) if !s.error_message.is_empty() => s.error_message.clone(),
        e => e.to_string(),
    };
    Error::new(st, format!("sftp: {what}: {text}"))
}

fn io_err(e: std::io::Error, what: &str) -> Error {
    Error::new(abi::IO, format!("sftp: {what}: {e}"))
}

/// Listing / stat item from SFTP attributes (`mtime` is whole seconds).
fn item(name: String, m: &Metadata) -> Item {
    let ty = m.file_type();
    Item {
        name,
        kind: match () {
            _ if ty.is_dir() => abi::KIND_DIR,
            _ if ty.is_symlink() => abi::KIND_SYMLINK,
            _ => abi::KIND_FILE,
        },
        size: m.size.unwrap_or(0),
        mtime: m.mtime.map(|s| i64::from(s) * 1_000_000_000),
        // The host never recurses through a link (delete would empty its target).
        link: ty.is_symlink(),
    }
}

/// `it` (a symlink) with its target's kind and size (`followed` = stat of the link).
fn resolve_link(
    mut it: Item,
    followed: std::result::Result<Metadata, SftpError>,
) -> std::result::Result<Item, SftpError> {
    if let Ok(m) = &followed {
        it.size = m.size.unwrap_or(0);
    }
    it.kind = link_kind(followed)?;
    Ok(it)
}

/// Kind of a symlink from following it: unresolvable (dangling, denied) = file.
fn link_kind(
    target: std::result::Result<Metadata, SftpError>,
) -> std::result::Result<u32, SftpError> {
    match target {
        Ok(m) if m.file_type().is_dir() => Ok(abi::KIND_DIR),
        Ok(_) => Ok(abi::KIND_FILE),
        Err(e) if !broken(&e) => Ok(abi::KIND_FILE),
        Err(e) => Err(e),
    }
}

type Marks = fn() -> std::result::Result<config::Bookmarks, String>;
pub type Dial = fn(&Target) -> Result<Conn>;

fn dial_user(t: &Target) -> Result<Conn> {
    ssh::connect(t, &ssh::Env::user())
}

pub struct Sftp {
    /// `None` = the `sftp://` top (bookmark list).
    target: Option<Target>,
    conn: Mutex<Option<Arc<Conn>>>,
    dial: Dial,
    /// Bookmark source (`sftp.toml`; injected by tests).
    marks: Marks,
}

impl Sftp {
    /// `config` = `sftp://<authority>` (empty = bookmark list).
    /// A secret after `archive_url::SECRET_SEP` = the key passphrase the user typed after a
    /// `NEED_PASSPHRASE`.
    pub fn open(config: &str) -> Result<Self> {
        Self::open_with(config, config::bookmarks, ssh_config::user_text, dial_user)
    }

    pub(crate) fn open_with(
        config: &str,
        marks: Marks,
        ssh: fn() -> String,
        dial: Dial,
    ) -> Result<Self> {
        let (config, secret) = archive_url::split_secret(config);
        let auth = config
            .strip_prefix("sftp://")
            .ok_or_else(|| Error::new(abi::INVALID, "sftp: mount must be sftp://..."))?;
        let mut fs = Self {
            target: None,
            conn: Mutex::default(),
            dial,
            marks,
        };
        if !auth.is_empty() {
            let mut t =
                config::resolve_in(auth, marks, &ssh()).map_err(|m| Error::new(abi::INVALID, m))?;
            t.passphrase = secret.map(|s| Zeroizing::new(s.to_owned()));
            // Connect now: a wrong host/key fails the mount, not the first listing.
            let c = dial(&t)?;
            fs.target = Some(t);
            *fs.lock() = Some(Arc::new(c));
        }
        Ok(fs)
    }

    fn target(&self) -> Result<&Target> {
        self.target.as_ref().ok_or_else(|| {
            Error::new(
                abi::UNSUPPORTED,
                "sftp: not supported on the bookmark list (open a bookmark first)",
            )
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Arc<Conn>>> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The live session, re-dialled if the last one broke.
    fn session(&self) -> Result<Arc<Conn>> {
        let t = self.target()?;
        let mut g = self.lock();
        if let Some(c) = g.as_ref().filter(|c| !c.closed()) {
            return Ok(Arc::clone(c));
        }
        let c = Arc::new((self.dial)(t)?);
        *g = Some(Arc::clone(&c));
        Ok(c)
    }

    /// Forget `c` if it is still the current session.
    fn drop_conn(&self, c: &Arc<Conn>) {
        let mut g = self.lock();
        if g.as_ref().is_some_and(|cur| Arc::ptr_eq(cur, c)) {
            *g = None;
        }
    }

    /// Run `f` on the session; a transport error drops it (the next op re-dials).
    fn run<T>(
        &self,
        what: &str,
        f: impl AsyncFnOnce(&SftpSession) -> std::result::Result<T, SftpError>,
    ) -> Result<T> {
        let c = self.session()?;
        let r = ssh::rt()?.block_on(f(&c.sftp));
        r.map_err(|e| {
            if broken(&e) {
                self.drop_conn(&c);
            }
            ferr(e, what)
        })
    }

    fn bookmarks(&self) -> Result<config::Bookmarks> {
        (self.marks)().map_err(|m| Error::new(abi::IO, m))
    }

    pub fn list(&self, dir: &str) -> Result<Vec<Item>> {
        if self.target.is_none() && dir.is_empty() {
            let names = self.bookmarks()?.into_keys().filter(|n| valid_name(n));
            return Ok(names.map(Item::dir).collect());
        }
        let p = abs(dir);
        self.run(&p, async |s| {
            let mut items = Vec::new();
            let mut probes = MAX_PROBES;
            for e in s.read_dir(&p).await? {
                // Non-UTF-8 names can't be addressed through the ABI: skipped.
                let Ok(name) = e.file_name().into_string() else {
                    continue;
                };
                if !valid_name(&name) {
                    continue;
                }
                let mut it = item(name, &e.metadata());
                if it.kind == abi::KIND_SYMLINK && probes > 0 {
                    probes -= 1;
                    let followed = s.metadata(abs(&join(dir, &it.name))).await;
                    it = resolve_link(it, followed)?;
                }
                items.push(it);
            }
            Ok(items)
        })
    }

    pub fn stat(&self, path: &str) -> Result<Item> {
        if self.target.is_none() {
            return match path.is_empty() || self.bookmarks()?.contains_key(path) {
                true => Ok(Item::dir("")),
                false => Err(Error::new(
                    abi::NOT_FOUND,
                    format!("sftp: no bookmark {path:?}"),
                )),
            };
        }
        let p = abs(path);
        // lstat first: a link must say so (the host never recurses through one).
        self.run(&p, async |s| {
            let it = item(String::new(), &s.symlink_metadata(&p).await?);
            match it.link {
                true => resolve_link(it, s.metadata(&p).await),
                false => Ok(it),
            }
        })
    }

    /// Absent = `Ok(false)`; other errors pass through. Not followed: a dangling link exists.
    fn exists(&self, path: &str) -> Result<bool> {
        let p = abs(path);
        match self.run(&p, async |s| s.symlink_metadata(&p).await) {
            Ok(_) => Ok(true),
            Err(e) if e.status == abi::NOT_FOUND => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn exists_err(&self, path: &str) -> Result<()> {
        match self.exists(path)? {
            true => Err(Error::new(
                abi::EXISTS,
                format!("sftp: {}: exists", abs(path)),
            )),
            false => Ok(()),
        }
    }

    pub fn reader(&self, path: &str, offset: u64) -> Result<Box<dyn Read + Send>> {
        let p = abs(path);
        let conn = self.session()?;
        let file = self.run(&p, async |s| {
            let mut f = s.open(&p).await?;
            if offset > 0 {
                f.seek(SeekFrom::Start(offset)).await?;
            }
            Ok(f)
        })?;
        Ok(Box::new(Download {
            file,
            _conn: conn,
            path: p,
        }))
    }

    pub fn writer(self: &Arc<Self>, path: &str, overwrite: bool) -> Result<Writer> {
        self.target()?;
        if !overwrite {
            self.exists_err(path)?;
        }
        let (dir, name) = parent_name(path);
        // EXCLUDE: never open an existing name (a symlink there would be written through).
        let flags = OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE;
        let mut last = None;
        for _ in 0..PART_TRIES {
            let tmp = abs(&join(dir, &part_name(name)));
            match self.run(&tmp, async |s| s.open_with_flags(&tmp, flags).await) {
                Ok(file) => return Ok(self.upload(file, tmp, path, overwrite)),
                // SFTP v3 says "failure" for an existing name: retry only if it exists.
                Err(e) if e.status == abi::IO && self.exists(&tmp[1..]).unwrap_or(false) => {
                    last = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        let why = last.map_or_else(String::new, |e| e.msg);
        Err(Error::new(
            abi::EXISTS,
            format!("sftp: {}: no free temp name ({why})", abs(path)),
        ))
    }

    fn upload(self: &Arc<Self>, file: File, tmp: String, path: &str, overwrite: bool) -> Writer {
        Writer {
            file: Some(file),
            fs: Arc::clone(self),
            tmp,
            dest: path.to_owned(),
            overwrite,
        }
    }

    pub fn mkdir(&self, path: &str) -> Result<()> {
        let p = abs(path);
        match self.run(&p, async |s| s.create_dir(&p).await) {
            Err(e) if e.status != abi::NOT_FOUND && self.exists(path).unwrap_or(false) => Err(
                Error::new(abi::EXISTS, format!("sftp: {p}: exists ({})", e.msg)),
            ),
            r => r,
        }
    }

    pub fn remove_file(&self, path: &str) -> Result<()> {
        let p = abs(path);
        self.run(&p, async |s| s.remove_file(&p).await)
    }

    pub fn remove_dir(&self, path: &str) -> Result<()> {
        let p = abs(path);
        match self.run(&p, async |s| s.remove_dir(&p).await) {
            // SFTP v3 has no "not empty" code: servers answer a generic failure.
            Err(e) if e.status == abi::IO && self.list(path).is_ok_and(|l| !l.is_empty()) => {
                Err(Error::new(abi::NOT_EMPTY, format!("sftp: {p}: not empty")))
            }
            r => r,
        }
    }

    pub fn rename(&self, from: &str, to: &str) -> Result<()> {
        self.target()?;
        self.exists_err(to)?;
        let (f, t) = (abs(from), abs(to));
        // SFTP v3 RENAME refuses an existing target (OpenSSH): never a silent replace.
        self.run(&f, async |s| s.rename(&f, &t).await)
    }
}

/// Download stream; keeps its session alive.
struct Download {
    file: File,
    _conn: Arc<Conn>,
    path: String,
}

impl Read for Download {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let rt = ssh::rt().map_err(|e| std::io::Error::other(e.msg))?;
        rt.block_on(self.file.read(buf))
            .map_err(|e| std::io::Error::new(e.kind(), format!("sftp: {}: {e}", self.path)))
    }
}

/// Upload into `tmp`; `finish` renames it to `dest`, drop deletes it.
pub struct Writer {
    file: Option<File>,
    fs: Arc<Sftp>,
    /// Absolute temp path; empty once committed or deliberately kept.
    tmp: String,
    /// Relative target path.
    dest: String,
    overwrite: bool,
}

impl Writer {
    pub fn write(&mut self, buf: &[u8]) -> Result<()> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| Error::new(abi::INTERNAL, "sftp: closed"))?;
        ssh::rt()?
            .block_on(file.write_all(buf))
            .map_err(|e| io_err(e, &abs(&self.dest)))
    }

    pub fn finish(mut self) -> Result<()> {
        let mut file = self
            .file
            .take()
            .ok_or_else(|| Error::new(abi::INTERNAL, "sftp: closed"))?;
        let dest = abs(&self.dest);
        // Waits for every write ack and the close.
        ssh::rt()?
            .block_on(file.shutdown())
            .map_err(|e| io_err(e, &dest))?;
        // RULES: check the target is absent right before every rename (not only at open).
        if !self.overwrite {
            self.fs.exists_err(&self.dest)?;
        }
        let tmp = self.tmp.clone();
        if self.overwrite {
            // posix-rename@openssh.com replaces atomically; Ok(false) = server lacks it.
            if self
                .fs
                .run(&dest, async |s| s.posix_rename(&tmp, &dest).await)?
            {
                self.tmp.clear();
                return Ok(());
            }
        }
        if let Err(e) = self.fs.run(&dest, async |s| s.rename(&tmp, &dest).await) {
            // Servers without posix-rename refuse an existing target: delete it, then retry.
            if !(self.overwrite && self.fs.exists(&self.dest)?) {
                return Err(e); // Drop deletes the temp; dest untouched
            }
            self.fs.remove_file(&self.dest)?;
            if let Err(e) = self.fs.run(&dest, async |s| s.rename(&tmp, &dest).await) {
                // The old file is gone: never delete the only copy of the new data.
                let kept = std::mem::take(&mut self.tmp);
                return Err(Error::new(
                    e.status,
                    format!("{} (new data kept at {kept})", e.msg),
                ));
            }
        }
        self.tmp.clear(); // committed: nothing to clean up
        Ok(())
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        if self.tmp.is_empty() {
            return;
        }
        let tmp = std::mem::take(&mut self.tmp);
        if let Ok(rt) = ssh::rt() {
            let _g = rt.enter();
            drop(self.file.take()); // closes the handle (the server keeps the partial file)
        }
        let _ = self.fs.run(&tmp, async |s| s.remove_file(&tmp).await); // best effort
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Bookmarks;
    use crate::fake::{self, Shared};
    use commander_plugin_abi::Status;
    use russh_sftp::protocol::FileAttributes;

    fn no_marks() -> std::result::Result<Bookmarks, String> {
        Ok(Bookmarks::new())
    }

    fn two_marks() -> std::result::Result<Bookmarks, String> {
        config::parse_bookmarks(
            "[a]\nhost = \"h\"\nuser = \"u\"\n[\"b:c\"]\nhost = \"h\"\nuser = \"u\"\n",
        )
    }

    fn broken_marks() -> std::result::Result<Bookmarks, String> {
        Err("sftp.toml: broken".into())
    }

    fn server(setup: impl FnOnce(&mut fake::State)) -> (Shared, Arc<Sftp>) {
        let st = Shared::default();
        setup(&mut st.lock().unwrap());
        let auth = fake::start(Arc::clone(&st));
        let fs =
            Sftp::open_with(&format!("sftp://{auth}"), no_marks, String::new, fake::dial).unwrap();
        (st, Arc::new(fs))
    }

    fn names(fs: &Sftp, dir: &str) -> Vec<(String, u32)> {
        let mut v: Vec<_> = fs
            .list(dir)
            .unwrap()
            .into_iter()
            .map(|i| (i.name, i.kind))
            .collect();
        v.sort();
        v
    }

    fn put(fs: &Arc<Sftp>, p: &str, data: &[u8], overwrite: bool) -> Result<()> {
        let mut w = fs.writer(p, overwrite)?;
        w.write(data)?;
        w.finish()
    }

    fn read(fs: &Sftp, p: &str, off: u64) -> String {
        let mut s = String::new();
        fs.reader(p, off).unwrap().read_to_string(&mut s).unwrap();
        s
    }

    fn st(r: Result<impl Sized>) -> Status {
        r.err().map_or(abi::OK, |e| e.status)
    }

    fn tree(s: &Shared) -> Vec<String> {
        s.lock().unwrap().tree.keys().cloned().collect()
    }

    #[test]
    fn paths() {
        assert_eq!(abs(""), "/");
        assert_eq!(abs("a/b"), "/a/b");
        assert_eq!(parent_name("a/b/c"), ("a/b", "c"));
        assert_eq!(parent_name("c"), ("", "c"));
        assert_eq!(join("", "x"), "x");
        assert_eq!(join("a", "x"), "a/x");
    }

    #[test]
    fn errors_map_to_status() {
        let status = |code, msg: &str| {
            SftpError::Status(russh_sftp::protocol::Status {
                id: 1,
                status_code: code,
                error_message: msg.into(),
                language_tag: String::new(),
            })
        };
        let s = |e| ferr(e, "/p").status;
        assert_eq!(s(status(StatusCode::NoSuchFile, "")), abi::NOT_FOUND);
        assert_eq!(s(status(StatusCode::PermissionDenied, "")), abi::DENIED);
        assert_eq!(s(status(StatusCode::OpUnsupported, "")), abi::UNSUPPORTED);
        assert_eq!(s(status(StatusCode::Failure, "")), abi::IO);
        assert_eq!(s(SftpError::Timeout), abi::IO);
        assert_eq!(
            ferr(status(StatusCode::Failure, "nope"), "/a b").msg,
            "sftp: /a b: nope"
        );
        assert_eq!(ferr(SftpError::Timeout, "/a").msg, "sftp: /a: Timeout");
        assert!(broken(&SftpError::IO("x".into())));
        assert!(!broken(&status(StatusCode::Failure, "")));
    }

    #[test]
    fn items_and_links() {
        let mut m = FileAttributes {
            size: Some(5),
            mtime: Some(2),
            permissions: Some(0o100644),
            ..FileAttributes::default()
        };
        let it = item("f".into(), &m);
        assert_eq!(
            (it.kind, it.size, it.mtime),
            (abi::KIND_FILE, 5, Some(2_000_000_000))
        );
        m.permissions = Some(0o120777);
        assert_eq!(item("l".into(), &m).kind, abi::KIND_SYMLINK);
        m.permissions = Some(0o040755);
        assert_eq!(item("d".into(), &m).kind, abi::KIND_DIR);
        assert_eq!(link_kind(Ok(m.clone())).unwrap(), abi::KIND_DIR);
        m.permissions = Some(0o100644);
        assert_eq!(link_kind(Ok(m)).unwrap(), abi::KIND_FILE);
        assert!(link_kind(Err(SftpError::Timeout)).is_err());
    }

    #[test]
    fn bookmark_top() {
        let fs = Sftp::open_with("sftp://", two_marks, String::new, fake::dial).unwrap();
        assert_eq!(
            names(&fs, ""),
            [("a".into(), abi::KIND_DIR)],
            "b:c is no valid name"
        );
        assert_eq!(fs.stat("").unwrap().kind, abi::KIND_DIR);
        assert_eq!(fs.stat("a").unwrap().kind, abi::KIND_DIR);
        assert_eq!(st(fs.stat("zz")), abi::NOT_FOUND);
        assert_eq!(st(fs.remove_file("x")), abi::UNSUPPORTED);
        assert_eq!(st(fs.reader("x", 0)), abi::UNSUPPORTED);
        assert_eq!(st(fs.list("a")), abi::UNSUPPORTED);
        assert_eq!(st(Arc::new(fs).writer("x", true)), abi::UNSUPPORTED);
        let bad = Sftp::open_with("sftp://", broken_marks, String::new, fake::dial).unwrap();
        assert_eq!(st(bad.list("")), abi::IO);
        assert_eq!(st(bad.stat("a")), abi::IO);
        assert_eq!(st(Sftp::open("ftp://h")), abi::INVALID, "foreign scheme");
        assert_eq!(
            st(Sftp::open("sftp://u:pw@h")),
            abi::INVALID,
            "no URL passwords"
        );
        let e = Sftp::open_with("sftp://u@fake:65535", no_marks, String::new, fake::dial)
            .err()
            .unwrap();
        assert_eq!(e.status, abi::IO, "dial errors fail the mount");
    }

    #[test]
    fn roundtrip() {
        let (_st, fs) = server(|_| {});
        fs.mkdir("d").unwrap();
        assert_eq!(st(fs.mkdir("d")), abi::EXISTS);
        assert_eq!(st(fs.mkdir("nope/x")), abi::NOT_FOUND);
        put(&fs, "d/a b.txt", b"hello world", false).unwrap();
        assert_eq!(
            names(&fs, "d"),
            [("a b.txt".into(), abi::KIND_FILE)],
            "b\\xff skipped"
        );
        let s = fs.stat("d/a b.txt").unwrap();
        assert_eq!((s.kind, s.size, s.name.as_str()), (abi::KIND_FILE, 11, ""));
        assert_eq!(s.mtime, Some(1_577_836_800_000_000_000));
        assert_eq!(fs.stat("d").unwrap().kind, abi::KIND_DIR);
        assert_eq!(fs.stat("").unwrap().kind, abi::KIND_DIR);
        assert_eq!(st(fs.stat("d/zz")), abi::NOT_FOUND);
        assert_eq!(read(&fs, "d/a b.txt", 0), "hello world");
        assert_eq!(read(&fs, "d/a b.txt", 6), "world");
        assert_eq!(st(fs.reader("d/zz", 0)), abi::NOT_FOUND);
        assert_eq!(st(put(&fs, "d/a b.txt", b"x", false)), abi::EXISTS);
        put(&fs, "d/a b.txt", b"new", true).unwrap();
        assert_eq!(read(&fs, "d/a b.txt", 0), "new");
        let mut w = fs.writer("d/gone", false).unwrap();
        w.write(b"partial").unwrap();
        drop(w); // abort
        assert_eq!(names(&fs, "d").len(), 1, "aborted upload left nothing");
        assert_eq!(st(fs.remove_dir("d")), abi::NOT_EMPTY);
        assert_eq!(st(fs.remove_dir("zz")), abi::NOT_FOUND);
        put(&fs, "c.txt", b"", false).unwrap();
        assert_eq!(st(fs.rename("c.txt", "d/a b.txt")), abi::EXISTS);
        fs.rename("d/a b.txt", "moved").unwrap();
        assert_eq!(st(fs.stat("d/a b.txt")), abi::NOT_FOUND);
        assert_eq!(st(fs.rename("zz", "yy")), abi::NOT_FOUND);
        assert_eq!(st(fs.remove_file("zz")), abi::NOT_FOUND);
        fs.remove_file("moved").unwrap();
        fs.remove_dir("d").unwrap();
        assert_eq!(st(fs.list("d")), abi::NOT_FOUND);
    }

    #[test]
    fn symlinks_are_followed() {
        let (_st, fs) = server(|s| {
            s.tree.insert("/d".into(), None);
            s.tree.insert("/f".into(), Some(b"abc".to_vec()));
            s.links.insert("/ld".into(), "/d".into());
            s.links.insert("/lf".into(), "/f".into());
            s.links.insert("/dangling".into(), "/nowhere".into());
        });
        let want = [
            ("d", abi::KIND_DIR),
            ("dangling", abi::KIND_FILE),
            ("f", abi::KIND_FILE),
            ("ld", abi::KIND_DIR),
            ("lf", abi::KIND_FILE),
        ];
        assert_eq!(names(&fs, ""), want.map(|(n, k)| (n.to_string(), k)));
        let lf = fs
            .list("")
            .unwrap()
            .into_iter()
            .find(|i| i.name == "lf")
            .unwrap();
        assert_eq!(lf.size, 3, "size of the target");
        assert_eq!(fs.stat("ld").unwrap().kind, abi::KIND_DIR);
        assert_eq!(fs.stat("lf").unwrap().size, 3);
        assert_eq!(
            st(fs.rename("f", "dangling")),
            abi::EXISTS,
            "a dangling link exists"
        );
        assert_eq!(st(put(&fs, "dangling", b"x", false)), abi::EXISTS);
    }

    #[test]
    fn overwrite_with_and_without_posix_rename() {
        for posix in [false, true] {
            let (st_, fs) = server(|s| {
                s.posix_rename = posix;
                s.tree.insert("/a".into(), Some(b"old".to_vec()));
            });
            put(&fs, "a", b"new", true).unwrap();
            assert_eq!(read(&fs, "a", 0), "new");
            assert_eq!(tree(&st_), ["/a"], "temp renamed away");
            let log = st_.lock().unwrap().log.join("\n");
            assert_eq!(log.contains("POSIX-RENAME"), posix, "{log}");
            put(&fs, "b", b"fresh", true).unwrap();
            assert_eq!(read(&fs, "b", 0), "fresh");
        }
    }

    #[test]
    fn failed_replace_keeps_the_new_data() {
        let (st_, fs) = server(|s| {
            s.rename_fail = true;
            s.tree.insert("/a".into(), Some(b"old".to_vec()));
        });
        let e = put(&fs, "a", b"new", true).unwrap_err();
        let kept = e
            .msg
            .split("kept at ")
            .nth(1)
            .unwrap()
            .trim_end_matches(')');
        assert!(
            kept.starts_with("/.a.") && kept.ends_with(".cmdr-part"),
            "{}",
            e.msg
        );
        let tree = &st_.lock().unwrap().tree;
        assert_eq!(tree.get(kept), Some(&Some(b"new".to_vec())));
    }

    #[test]
    fn existing_temp_names_are_never_written() {
        for link in [false, true] {
            let (st_, fs) = server(|s| {
                s.squat = 2;
                s.squat_link = link;
                s.tree.insert("/victim".into(), Some(b"precious".to_vec()));
            });
            put(&fs, "a", b"new", false).unwrap();
            assert_eq!(read(&fs, "a", 0), "new");
            let g = st_.lock().unwrap();
            assert_eq!(g.tree["/victim"], Some(b"precious".to_vec()), "link={link}");
            let squats = g.tree.keys().chain(g.links.keys());
            assert_eq!(squats.filter(|k| k.ends_with(".cmdr-part")).count(), 2);
        }
        let (_st, fs) = server(|s| s.squat = PART_TRIES);
        assert_eq!(st(fs.writer("a", false)), abi::EXISTS, "gives up");
    }

    #[test]
    fn links_are_flagged() {
        let (_st, fs) = server(|s| {
            s.tree.insert("/d".into(), None);
            s.links.insert("/ld".into(), "/d".into());
        });
        let all = fs.list("").unwrap();
        let link = |n: &str| all.iter().find(|i| i.name == n).unwrap().link;
        assert!(link("ld") && !link("d"));
        let s = fs.stat("ld").unwrap();
        assert!(s.link && s.kind == abi::KIND_DIR, "{s:?}");
        assert!(!fs.stat("d").unwrap().link);
    }

    #[test]
    fn failed_rename_without_overwrite_cleans_up() {
        let (st_, fs) = server(|s| s.rename_fail = true);
        assert_eq!(st(put(&fs, "n", b"x", false)), abi::DENIED);
        assert!(tree(&st_).is_empty(), "temp deleted, no target");
    }

    #[test]
    fn target_created_during_upload_is_not_replaced() {
        let (st_, fs) = server(|_| {});
        let mut w = fs.writer("a", false).unwrap();
        w.write(b"mine").unwrap();
        st_.lock()
            .unwrap()
            .tree
            .insert("/a".into(), Some(b"theirs".to_vec()));
        assert_eq!(st(w.finish()), abi::EXISTS);
        assert_eq!(read(&fs, "a", 0), "theirs");
        assert_eq!(tree(&st_), ["/a"], "temp deleted");
    }

    #[test]
    fn upload_into_a_missing_dir_fails() {
        let (_st, fs) = server(|_| {});
        assert_eq!(st(fs.writer("nope/a", true)), abi::NOT_FOUND);
    }

    #[test]
    fn broken_session_is_redialled() {
        let (_st, fs) = server(|s| {
            s.tree.insert("/x".into(), None);
        });
        let old = fs.session().unwrap();
        assert_eq!(st(fs.list("die")), abi::IO);
        assert_eq!(
            names(&fs, ""),
            [("x".into(), abi::KIND_DIR)],
            "next op re-dials"
        );
        assert!(!Arc::ptr_eq(&old, &fs.session().unwrap()), "a new session");
    }

    /// Live server: `COMMANDER_SFTP_TEST_URL=sftp://user@host[:port]/dir` (auth: agent or
    /// `~/.ssh/id_*`; host key in known_hosts) `cargo test -p commander_sftp -- --ignored`.
    #[test]
    #[ignore = "needs a live SFTP server (COMMANDER_SFTP_TEST_URL)"]
    fn live_roundtrip() {
        let url = std::env::var("COMMANDER_SFTP_TEST_URL").expect("COMMANDER_SFTP_TEST_URL");
        let rest = url.strip_prefix("sftp://").expect("sftp:// URL");
        let (auth, dir) = rest.split_once('/').unwrap_or((rest, ""));
        let fs = Arc::new(Sftp::open(&format!("sftp://{auth}")).expect("connect"));
        let base = join(dir.trim_end_matches('/'), "cmdr-sftp-test");
        let f = join(&base, "a b.txt");
        let _ = fs.remove_file(&f);
        let _ = fs.remove_dir(&base);
        fs.mkdir(&base).unwrap();
        put(&fs, &f, b"hello world", false).unwrap();
        assert_eq!(read(&fs, &f, 6), "world");
        put(&fs, &f, b"again", true).unwrap();
        assert_eq!(names(&fs, &base).len(), 1);
        fs.remove_file(&f).unwrap();
        fs.remove_dir(&base).unwrap();
    }
}

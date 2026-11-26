//! One archive mount: listing cached per archive (size, mtime); reads stream `7z e -so`;
//! writes stage the item in a private temp dir, then `7z a` / `d` / `rn` (serialized).
//! RAR is extract-only (unRAR licence); multi-volume and most other formats are read-only.
use crate::exe::{self, Done, Engine, Op};
use crate::slt::{self, Ent, Tree};
use commander_plugin_abi::archive_url;
use commander_plugin_abi::glue::{self, Error, Item, Result};
use commander_plugin_abi::names::is_device_name;
use commander_plugin_abi::stage::Stage;
use commander_plugin_abi::{AUTH, DENIED, EXISTS, INVALID, IO, NOT_EMPTY, NOT_FOUND, UNSUPPORTED};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

pub const SCHEME: &str = "sevenzip://";

/// What 7-Zip may do to this archive (by file name).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// `seven`: 7z format (headers get encrypted too when a password is set).
    Write {
        seven: bool,
    },
    ReadOnly(&'static str),
}

pub fn access(archive: &Path) -> Access {
    let name = archive
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let ext = name.rsplit_once('.').map_or("", |(_, e)| e);
    match ext {
        "7z" => Access::Write { seven: true },
        "zip" | "tar" | "wim" => Access::Write { seven: false },
        "rar" => Access::ReadOnly("RAR archives are extract-only (unRAR licence)"),
        e if e.starts_with('r') && e[1..].bytes().all(|b| b.is_ascii_digit()) && e.len() > 1 => {
            Access::ReadOnly("RAR archives are extract-only (unRAR licence)")
        }
        e if !e.is_empty() && e.bytes().all(|b| b.is_ascii_digit()) => {
            Access::ReadOnly("multi-volume archives are read-only")
        }
        _ => Access::ReadOnly("7-Zip can't update this archive type"),
    }
}

/// Archive file identity for the listing cache.
type Stamp = (u64, Option<SystemTime>);

pub struct SevenZip {
    archive: PathBuf,
    /// From the host's password prompt; memory only, never logged or put in error text.
    password: Option<String>,
    engine: Arc<dyn Engine>,
    access: Access,
    cache: Mutex<Option<(Stamp, Arc<Tree>)>>,
    /// 7z rewrites the whole archive: one write at a time.
    writing: Mutex<()>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn io_err(what: &str) -> impl FnOnce(io::Error) -> Error + '_ {
    move |e| {
        let st = match e.kind() {
            io::ErrorKind::NotFound => NOT_FOUND,
            io::ErrorKind::AlreadyExists => EXISTS,
            io::ErrorKind::PermissionDenied => DENIED,
            _ => IO,
        };
        Error::new(st, format!("{what}: {e}"))
    }
}

fn not_found(p: &str) -> Error {
    Error::new(NOT_FOUND, format!("{p:?} not in the archive"))
}

/// `a/b` -> ("a", "b"); `b` -> ("", "b").
fn split(p: &str) -> (&str, &str) {
    p.rsplit_once('/').unwrap_or(("", p))
}

impl SevenZip {
    /// `sevenzip://<encoded archive path>[\n<password>]`, with the user's 7-Zip.
    pub fn open(config: &str) -> Result<Self> {
        let exe = exe::find().ok_or_else(|| {
            Error::new(
                UNSUPPORTED,
                "7-Zip not found: install it (Windows: 7-zip.org; Linux/macOS: 7zz or 7z on PATH)",
            )
        })?;
        Self::with_engine(config, Arc::new(exe::Process(exe.to_path_buf())))
    }

    pub fn with_engine(config: &str, engine: Arc<dyn Engine>) -> Result<Self> {
        let (mount, password) = archive_url::split_secret(config);
        let bad = || Error::new(INVALID, "expected sevenzip://<archive path>");
        let seg = mount.strip_prefix(SCHEME).ok_or_else(bad)?;
        let archive = PathBuf::from(archive_url::decode(seg).ok_or_else(bad)?);
        if !archive.is_absolute() {
            return Err(bad());
        }
        let fs = Self {
            access: access(&archive),
            archive,
            password: password.map(str::to_owned),
            engine,
            cache: Mutex::new(None),
            writing: Mutex::new(()),
        };
        match fs.archive.metadata() {
            Ok(m) if m.is_file() => fs.check_password(&fs.tree()?)?,
            Ok(_) => return Err(Error::new(INVALID, "not an archive file")),
            // A new archive (Alt+F5 pack): its dir must exist and the type be writable.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs.writable()?;
                let dir = fs.archive.parent().filter(|d| d.is_dir());
                dir.ok_or_else(|| Error::new(NOT_FOUND, "archive folder not found"))?;
            }
            Err(e) => return Err(io_err("archive")(e)),
        }
        Ok(fs)
    }

    /// Encrypted items need a password; a given one is proven on the smallest of them
    /// (listing doesn't check it unless the headers are encrypted).
    fn check_password(&self, t: &Arc<Tree>) -> Result<()> {
        let Some(e) = t.smallest_encrypted() else {
            return Ok(());
        };
        if self.password.is_none() {
            return Err(Error::new(AUTH, "7-Zip: password required"));
        }
        self.run(&Op::Test(&e.raw), None, true).map(drop)
    }

    fn writable(&self) -> Result<bool> {
        match self.access {
            Access::Write { seven } => Ok(seven),
            Access::ReadOnly(why) => Err(Error::new(UNSUPPORTED, why)),
        }
    }

    fn run(&self, op: &Op, cwd: Option<&Path>, warnings_ok: bool) -> Result<Done> {
        let pw = self.password.as_deref();
        let seven = matches!(self.access, Access::Write { seven: true });
        let args = exe::argv(op, &self.archive, pw.is_some(), seven);
        let d = self
            .engine
            .run(&args, cwd, &exe::stdin(pw))
            .map_err(io_err("7-Zip"))?;
        match exe::ok(&d, warnings_ok) {
            true => Ok(d),
            false => Err(exe::failure(&d, pw.is_some())),
        }
    }

    fn stamp(&self) -> Result<Option<Stamp>> {
        match self.archive.metadata() {
            Ok(m) => Ok(Some((m.len(), m.modified().ok()))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err("archive")(e)),
        }
    }

    /// The listing, re-read when the archive file changed (or was just written by us).
    fn tree(&self) -> Result<Arc<Tree>> {
        let Some(stamp) = self.stamp()? else {
            return Ok(Arc::new(Tree::build(Vec::new()))); // not created yet
        };
        if let Some((s, t)) = &*lock(&self.cache)
            && *s == stamp
        {
            return Ok(Arc::clone(t));
        }
        let d = self.run(&Op::List, None, true)?;
        let t = Arc::new(Tree::build(slt::parse(&String::from_utf8_lossy(&d.out))));
        *lock(&self.cache) = Some((stamp, Arc::clone(&t)));
        Ok(t)
    }

    fn invalidate(&self) {
        *lock(&self.cache) = None;
    }

    fn ent(&self, path: &str) -> Result<(Arc<Tree>, Ent)> {
        let t = self.tree()?;
        let e = t.get(path).cloned().ok_or_else(|| not_found(path))?;
        Ok((t, e))
    }

    pub fn list(&self, dir: &str) -> Result<Vec<Item>> {
        let (t, e) = self.ent(dir)?;
        match e.is_dir {
            true => Ok(t.list(dir).unwrap_or_default()),
            false => Err(Error::new(INVALID, format!("{dir:?} is not a folder"))),
        }
    }

    pub fn stat(&self, path: &str) -> Result<Item> {
        self.ent(path).map(|(_, e)| slt::item("", &e))
    }

    pub fn reader(&self, path: &str, offset: u64) -> Result<Box<dyn Read + Send>> {
        let (_, e) = self.ent(path)?;
        if e.is_dir {
            return Err(Error::new(INVALID, format!("{path:?} is not a file")));
        }
        let pw = self.password.as_deref();
        let args = exe::argv(&Op::Read(&e.raw), &self.archive, pw.is_some(), false);
        let inner = self
            .engine
            .stream(&args, &exe::stdin(pw))
            .map_err(io_err("7-Zip"))?;
        let mut r = Checked {
            inner,
            left: e.size,
        };
        io::copy(&mut (&mut r).take(offset), &mut io::sink()).map_err(io_err("7-Zip"))?;
        Ok(Box::new(r))
    }

    /// Every segment a plain host-safe name (glue checked only `.`/`..`/empty): no `\`, `:`,
    /// controls, and on Windows no device name (`aux`): the item is staged as a real file.
    fn check_new(path: &str) -> Result<()> {
        let bad = |s: &str| !glue::valid_name(s) || (cfg!(windows) && is_device_name(s));
        match path.is_empty() || path.split('/').any(bad) {
            true => Err(Error::new(INVALID, format!("bad name {path:?}"))),
            false => Ok(()),
        }
    }

    /// An unlisted record (link, unsafe name, duplicate) under `raw`: a delete would take it.
    fn refuse_hidden(t: &Tree, raw: &str) -> Result<()> {
        match t.hides_under(raw) {
            true => Err(Error::new(
                DENIED,
                format!("{raw:?} holds items not shown (links / unsafe names): left as is"),
            )),
            false => Ok(()),
        }
    }

    /// Parent of `path` must be a folder here.
    fn parent_dir(&self, t: &Tree, path: &str) -> Result<()> {
        let (dir, _) = split(path);
        match t.get(dir) {
            Some(e) if e.is_dir => Ok(()),
            _ => Err(not_found(dir)),
        }
    }

    pub fn writer(self: &Arc<Self>, path: &str, overwrite: bool) -> Result<Writer> {
        self.writable()?;
        Self::check_new(path)?;
        let t = self.tree()?;
        self.parent_dir(&t, path)?;
        match t.get(path) {
            Some(e) if e.is_dir => return Err(Error::new(EXISTS, format!("{path:?} is a folder"))),
            Some(_) if !overwrite => return Err(Error::new(EXISTS, format!("{path:?} exists"))),
            _ => {}
        }
        let stage = new_stage()?;
        let file = stage.file(path).map_err(io_err("stage"))?;
        Ok(Writer {
            fs: Arc::clone(self),
            stage,
            path: path.to_owned(),
            file: Some(file),
        })
    }

    /// `7z a` of `rel` (staged under `stage`); `verify`: then `7z t` it, so a move only
    /// deletes its source once the archived copy reads back intact.
    fn add(&self, stage: &Stage, rel: &str, verify: bool) -> Result<()> {
        let _w = lock(&self.writing);
        let r = self.run(&Op::Add(&[rel]), Some(stage.path()), false);
        self.invalidate();
        r?;
        // `7z t` of a name that matches nothing exits 0 ("No files to process"): not a pass.
        if verify && exe::tested_none(&self.run(&Op::Test(rel), None, false)?) {
            return Err(Error::new(
                IO,
                format!("7-Zip: {rel:?} not found after adding it"),
            ));
        }
        Ok(())
    }

    pub fn mkdir(&self, path: &str) -> Result<()> {
        self.writable()?;
        Self::check_new(path)?;
        let t = self.tree()?;
        self.parent_dir(&t, path)?;
        if t.get(path).is_some() {
            return Err(Error::new(EXISTS, format!("{path:?} exists")));
        }
        let stage = new_stage()?;
        fs::create_dir_all(stage.path().join(path)).map_err(io_err("stage"))?;
        self.add(&stage, path, false)
    }

    fn edit(&self, op: &Op) -> Result<()> {
        self.writable()?;
        let _w = lock(&self.writing);
        let r = self.run(op, None, false);
        self.invalidate();
        r.map(drop)
    }

    pub fn remove_file(&self, path: &str) -> Result<()> {
        let (t, e) = self.ent(path)?;
        if e.is_dir {
            return Err(Error::new(INVALID, format!("{path:?} is not a file")));
        }
        Self::refuse_hidden(&t, &e.raw)?;
        self.edit(&Op::Delete(&[&e.raw]))
    }

    pub fn remove_dir(&self, path: &str) -> Result<()> {
        let (t, e) = self.ent(path)?;
        if path.is_empty() || !e.is_dir {
            return Err(Error::new(INVALID, format!("{path:?} is not a folder")));
        }
        if !t.list(path).unwrap_or_default().is_empty() {
            return Err(Error::new(NOT_EMPTY, format!("{path:?} is not empty")));
        }
        Self::refuse_hidden(&t, &e.raw)?;
        self.edit(&Op::Delete(&[&e.raw]))
    }

    /// Never replaces `to`. A folder takes everything below it along.
    pub fn rename(&self, from: &str, to: &str) -> Result<()> {
        let (t, e) = self.ent(from)?;
        if from.is_empty() {
            return Err(Error::new(INVALID, "cannot rename the archive root"));
        }
        Self::check_new(to)?;
        if t.get(to).is_some() {
            return Err(Error::new(EXISTS, format!("{to:?} exists")));
        }
        self.parent_dir(&t, to)?;
        self.edit(&Op::Rename(&e.raw, to))
    }
}

/// Private staging dir for one write (`cmdr-7z-*`).
fn new_stage() -> Result<Stage> {
    Stage::new("cmdr-7z").map_err(io_err("temp dir"))
}

/// Staged upload; `finish` adds it, dropping it discards the stage (nothing added).
pub struct Writer {
    fs: Arc<SevenZip>,
    stage: Stage,
    path: String,
    file: Option<File>,
}

impl Writer {
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        let f = self.file.as_mut().ok_or_else(|| Error::new(IO, "closed"))?;
        f.write_all(data).map_err(io_err("stage"))
    }

    pub fn finish(mut self) -> Result<()> {
        let f = self.file.take().ok_or_else(|| Error::new(IO, "closed"))?;
        f.sync_all().map_err(io_err("stage"))?;
        drop(f);
        self.fs.add(&self.stage, &self.path, true)
    }
}

/// A 7z stream checked to its end: exactly the listed size (when known), then EOF, so a
/// failed run (CRC / data error, wrong password) or extra data (duplicate names) is an error
/// and never a silently accepted copy.
struct Checked {
    inner: Box<dyn Read + Send>,
    /// Bytes still expected (None: size not listed, no cap).
    left: Option<u64>,
}

impl Read for Checked {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let Some(left) = self.left else {
            return self.inner.read(buf);
        };
        if left == 0 {
            // Drain to EOF: the stream reports 7z's exit status there.
            return match self.inner.read(&mut [0u8; 1])? {
                0 => Ok(0),
                _ => Err(io::Error::other("7-Zip returned more data than listed")),
            };
        }
        let cap = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        match self.inner.read(&mut buf[..cap])? {
            0 => Err(io::Error::other("7-Zip returned less data than listed")),
            n => {
                self.left = Some(left - n as u64);
                Ok(n)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::Fake;

    fn mount(arc: &Path, pw: Option<&str>, fake: &Arc<Fake>) -> Result<Arc<SevenZip>> {
        let mut cfg = format!("{SCHEME}{}", archive_url::encode(arc.to_str().unwrap()));
        if let Some(p) = pw {
            cfg = format!("{cfg}\n{p}");
        }
        let engine: Arc<dyn Engine> = fake.clone();
        SevenZip::with_engine(&cfg, engine).map(Arc::new)
    }

    fn names(fs: &SevenZip, dir: &str) -> Vec<String> {
        let mut v: Vec<_> = fs.list(dir).unwrap().into_iter().map(|i| i.name).collect();
        v.sort();
        v
    }

    fn read(fs: &SevenZip, p: &str, off: u64) -> String {
        let mut s = String::new();
        fs.reader(p, off).unwrap().read_to_string(&mut s).unwrap();
        s
    }

    fn put(fs: &Arc<SevenZip>, p: &str, body: &str, overwrite: bool) -> Result<()> {
        let mut w = fs.writer(p, overwrite)?;
        w.write(body.as_bytes())?;
        w.finish()
    }

    #[test]
    fn access_by_name() {
        let a = |n: &str| access(Path::new(n));
        assert_eq!(a("x.7Z"), Access::Write { seven: true });
        assert_eq!(a("x.zip"), Access::Write { seven: false });
        assert!(matches!(a("x.rar"), Access::ReadOnly(m) if m.contains("unRAR")));
        assert!(matches!(a("x.part1.rar"), Access::ReadOnly(m) if m.contains("unRAR")));
        assert!(matches!(a("x.r00"), Access::ReadOnly(m) if m.contains("unRAR")));
        assert!(matches!(a("x.7z.001"), Access::ReadOnly(m) if m.contains("multi")));
        assert!(matches!(a("x.iso"), Access::ReadOnly(_)));
        assert!(matches!(a("x.r"), Access::ReadOnly(m) if m.contains("update")));
        assert!(matches!(a("noext"), Access::ReadOnly(_)));
    }

    #[test]
    fn open_rules() {
        let t = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::default());
        let e: Arc<dyn Engine> = fake.clone();
        for bad in ["s3://x", "sevenzip://rel|a.7z", "sevenzip://%zz"] {
            let r = SevenZip::with_engine(bad, Arc::clone(&e));
            assert_eq!(r.err().unwrap().status, INVALID, "{bad}");
        }
        // New archive: writable type in an existing dir only.
        assert!(mount(&t.path().join("new.7z"), None, &fake).is_ok());
        let st = |p: PathBuf| mount(&p, None, &fake).err().unwrap().status;
        assert_eq!(st(t.path().join("new.rar")), UNSUPPORTED);
        assert_eq!(st(t.path().join("nodir").join("a.7z")), NOT_FOUND);
        assert_eq!(st(t.path().to_path_buf()), INVALID, "a dir");
    }

    #[test]
    fn browse_read_write_roundtrip() {
        let t = tempfile::tempdir().unwrap();
        let arc = t.path().join("a.7z");
        let fake = Arc::new(Fake::default());
        let fs = mount(&arc, None, &fake).unwrap();
        assert!(fs.list("").unwrap().is_empty());
        assert_eq!(fs.stat("").unwrap().kind, commander_plugin_abi::KIND_DIR);
        put(&fs, "-x.txt", "dash", false).unwrap();
        fs.mkdir("d").unwrap();
        put(&fs, "d/f.txt", "hello", false).unwrap();
        assert_eq!(fake.calls(), 3, "each write is one 7z run");
        assert_eq!(names(&fs, ""), ["-x.txt", "d"]);
        assert_eq!(read(&fs, "d/f.txt", 0), "hello");
        assert_eq!(read(&fs, "d/f.txt", 2), "llo");
        assert_eq!(fs.stat("d/f.txt").unwrap().size, 5);
        // Refusals: existing, missing parent, dir as file, etc.
        let st = |r: Result<()>| r.unwrap_err().status;
        assert_eq!(st(put(&fs, "d/f.txt", "x", false)), EXISTS);
        put(&fs, "d/f.txt", "new", true).unwrap();
        assert_eq!(read(&fs, "d/f.txt", 0), "new");
        assert_eq!(st(put(&fs, "nope/f", "x", false)), NOT_FOUND);
        assert_eq!(st(put(&fs, "d", "x", true)), EXISTS);
        assert_eq!(st(fs.mkdir("d")), EXISTS);
        assert!(fs.reader("d", 0).is_err() && fs.reader("zz", 0).is_err());
        assert_eq!(fs.list("d/f.txt").unwrap_err().status, INVALID);
        assert_eq!(fs.stat("zz").unwrap_err().status, NOT_FOUND);
        // An unfinished writer adds nothing.
        let mut w = fs.writer("gone.txt", false).unwrap();
        w.write(b"x").unwrap();
        drop(w);
        assert!(fs.stat("gone.txt").is_err());
        // Rename (dir takes children), delete.
        assert_eq!(st(fs.rename("d", "-x.txt")), EXISTS);
        assert_eq!(st(fs.rename("", "x")), INVALID);
        assert_eq!(st(fs.rename("d", "nope/e")), NOT_FOUND);
        fs.rename("d", "e").unwrap();
        assert_eq!(read(&fs, "e/f.txt", 0), "new");
        assert_eq!(st(fs.remove_dir("e")), NOT_EMPTY);
        assert_eq!(st(fs.remove_dir("")), INVALID);
        assert_eq!(st(fs.remove_file("e")), INVALID);
        fs.remove_file("e/f.txt").unwrap();
        fs.remove_dir("e").unwrap();
        assert_eq!(names(&fs, ""), ["-x.txt"]);
        assert_eq!(st(fs.remove_dir("-x.txt")), INVALID);
        // Engine failure surfaces with its status.
        fake.fail_next("ERROR: disk full");
        assert_eq!(st(fs.mkdir("q")), IO);
        assert!(fs.stat("q").is_err());
    }

    #[test]
    fn read_only_formats_refuse_writes() {
        let t = tempfile::tempdir().unwrap();
        let arc = t.path().join("a.rar");
        fs::write(&arc, "x").unwrap();
        let fake = Arc::new(Fake::default());
        fake.add("f.txt", "rar body", false);
        let fs = mount(&arc, None, &fake).unwrap();
        assert_eq!(read(&fs, "f.txt", 0), "rar body");
        let st = |r: Result<()>| r.unwrap_err().status;
        assert_eq!(st(put(&fs, "g", "x", false)), UNSUPPORTED);
        assert_eq!(st(fs.mkdir("g")), UNSUPPORTED);
        assert_eq!(st(fs.remove_file("f.txt")), UNSUPPORTED);
        assert_eq!(st(fs.rename("f.txt", "g")), UNSUPPORTED);
    }

    #[test]
    fn passwords() {
        let t = tempfile::tempdir().unwrap();
        let arc = t.path().join("e.zip");
        fs::write(&arc, "x").unwrap();
        let fake = Arc::new(Fake::default());
        fake.add("big.bin", "0123456789", true);
        fake.add("s.txt", "secret", true);
        fake.set_password("s3cr3t");
        let st = |pw| mount(&arc, pw, &fake).err().map(|e| e.status);
        assert_eq!(st(None), Some(AUTH), "encrypted items need a password");
        assert_eq!(st(Some("bad")), Some(AUTH), "proven on the smallest item");
        assert_eq!(fake.last_test(), "s.txt");
        let fs = mount(&arc, Some("s3cr3t"), &fake).unwrap();
        assert_eq!(read(&fs, "s.txt", 0), "secret");
        put(&fs, "n.txt", "x", false).unwrap();
        assert!(fake.saw_switch("-p"), "writes ask for the password too");
        assert!(!fake.argv_has("s3cr3t"), "never in argv");
        // Archive changed behind our back: re-listed.
        fake.add("late.txt", "l", false);
        fs::write(&arc, "longer now").unwrap();
        assert!(fs.stat("late.txt").is_ok());
    }

    #[test]
    fn reads_are_checked_to_the_end() {
        let t = tempfile::tempdir().unwrap();
        let arc = t.path().join("a.zip");
        fs::write(&arc, "x").unwrap();
        let fake = Arc::new(Fake::default());
        fake.add("f.txt", "body", false);
        let fs = mount(&arc, None, &fake).unwrap();
        let all = |fs: &SevenZip| {
            let mut v = Vec::new();
            fs.reader("f.txt", 0)
                .unwrap()
                .read_to_end(&mut v)
                .map(|_| v)
        };
        assert_eq!(all(&fs).unwrap(), b"body");
        fake.tail(false);
        let e = all(&fs).unwrap_err();
        assert!(
            e.to_string().contains("CRC"),
            "a failed 7z run is an error: {e}"
        );
        fake.tail(true);
        assert!(all(&fs).unwrap_err().to_string().contains("more data"));
        // Fewer bytes than listed, and no cap when the size is unknown.
        let mut short = Checked {
            inner: Box::new(&b"ab"[..]),
            left: Some(3),
        };
        let mut v = Vec::new();
        assert!(
            short
                .read_to_end(&mut v)
                .unwrap_err()
                .to_string()
                .contains("less")
        );
        let mut open = Checked {
            inner: Box::new(&b"abc"[..]),
            left: None,
        };
        v.clear();
        open.read_to_end(&mut v).unwrap();
        assert_eq!(
            (v.as_slice(), open.read(&mut []).unwrap()),
            (&b"abc"[..], 0)
        );
    }

    #[test]
    fn writes_are_verified_and_names_checked() {
        let t = tempfile::tempdir().unwrap();
        let arc = t.path().join("a.7z");
        let fake = Arc::new(Fake::default());
        let fs = mount(&arc, None, &fake).unwrap();
        fake.fail_on("t", "ERROR: CRC Failed : f");
        let e = put(&fs, "f", "x", false).unwrap_err();
        assert_eq!(e.status, IO, "a move must not delete its source: {}", e.msg);
        // 7z exits 0 when the test matches nothing: still a failed verify.
        fake.lose_next_add();
        let e = put(&fs, "lost", "x", false).unwrap_err();
        assert!(e.msg.contains("not found after adding"), "{}", e.msg);
        put(&fs, "kept", "x", false).unwrap();
        assert!(fake.saw_switch("-ssc"));
        let st = |r: Result<()>| r.unwrap_err().status;
        for bad in ["a\\b", "c:x", "x\u{1}"] {
            assert_eq!(st(put(&fs, bad, "x", false)), INVALID, "{bad:?}");
            assert_eq!(st(fs.mkdir(bad)), INVALID, "{bad:?}");
            assert_eq!(st(fs.rename("f", bad)), INVALID, "{bad:?}");
        }
        let dev = put(&fs, "d/aux.c", "x", false).err().map(|e| e.status);
        let want = if cfg!(windows) { INVALID } else { NOT_FOUND };
        assert_eq!(dev, Some(want), "device names: refused on Windows only");
    }

    #[test]
    fn deletes_never_take_hidden_items() {
        let t = tempfile::tempdir().unwrap();
        let arc = t.path().join("a.zip");
        fs::write(&arc, "x").unwrap();
        let fake = Arc::new(Fake::default());
        fake.add("d/ok.txt", "1", false);
        fake.add("d/../evil", "2", false); // unsafe: never listed
        fake.add("e/f", "3", false);
        let fs = mount(&arc, None, &fake).unwrap();
        fs.remove_file("d/ok.txt").unwrap();
        assert_eq!(
            fs.list("d").unwrap_err().status,
            NOT_FOUND,
            "implied dir gone"
        );
        fake.add("d/x", "1", false);
        fs::write(&arc, "changed").unwrap();
        fs.remove_file("d/x").unwrap();
        assert!(fake.calls() == 2);
        fake.add("g/../../h", "4", false);
        fake.add("g", "", false);
        fs::write(&arc, "changed again").unwrap();
        assert_eq!(fs.remove_file("g").unwrap_err().status, DENIED);
        fs.remove_file("e/f").unwrap();
    }

    #[test]
    fn stage_is_named_and_split() {
        let s = new_stage().unwrap();
        let name = s.path().file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("cmdr-7z-"), "{name}");
        assert_eq!(split("a/b/c"), ("a/b", "c"));
        assert_eq!(split("c"), ("", "c"));
    }
}

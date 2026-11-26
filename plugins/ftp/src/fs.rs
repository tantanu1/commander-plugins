//! FTP semantics. Mount `ftp://` lists bookmarks; `ftp[s]://<authority>` is one server, paths
//! are absolute (`/` + inner). Passive mode; idle control connections are pooled (NOOP-checked
//! before reuse); each transfer owns a connection until it ends. Uploads go to a temp name and
//! are renamed on finish, so an aborted upload leaves nothing at the target.
use crate::config::{self, Target};
use crate::list;
use commander_plugin_abi as abi;
use commander_plugin_abi::glue::{Error, Item, PART_TRIES, Result, part_name};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};
use suppaftp::rustls::{self, ClientConfig, RootCertStore};
use suppaftp::types::{FileType, FormatControl};
use suppaftp::{FtpError, FtpResult, RustlsConnector, RustlsFtpStream, TransferStream};

type Conn = RustlsFtpStream;
type Transfer = TransferStream<<Conn as Stream>::Tls>;

/// Names the TLS stream type of [`Conn`] (suppaftp keeps it private).
trait Stream {
    type Tls: suppaftp::TlsStream;
}
impl<T: suppaftp::TlsStream> Stream for suppaftp::ImplFtpStream<T> {
    type Tls = T;
}

const TIMEOUT: Duration = Duration::from_secs(30);
/// Idle control connections kept per mount.
const POOL: usize = 4;
/// Symlinks probed (CWD) per listing to tell dirs from files.
const MAX_PROBES: usize = 64;

/// `/` + inner path.
fn abs(path: &str) -> String {
    format!("/{path}")
}

fn parent_name(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

/// Server reply code of `e`, if it is a reply.
fn code(e: &FtpError) -> Option<u32> {
    match e {
        FtpError::UnexpectedResponse(r) => Some(r.status.code()),
        _ => None,
    }
}

/// 500/502/504: the server lacks the command (MLSD/MLST).
fn unsupported(e: &FtpError) -> bool {
    matches!(code(e), Some(500 | 502 | 504))
}

/// `what` = host or path; never contains a password.
fn ferr(e: FtpError, what: &str) -> Error {
    let (st, text) = match &e {
        FtpError::UnexpectedResponse(r) => {
            let text = String::from_utf8_lossy(&r.body).trim().to_owned();
            let low = text.to_ascii_lowercase();
            let st = match r.status.code() {
                530 | 331 | 332 => abi::AUTH,
                550 if low.contains("not empty") => abi::NOT_EMPTY,
                550 if low.contains("denied") || low.contains("permission") => abi::DENIED,
                550 => abi::NOT_FOUND,
                553 => abi::DENIED,
                500 | 502 | 504 => abi::UNSUPPORTED,
                _ => abi::IO,
            };
            (st, text)
        }
        FtpError::SecureError(m) => (abi::IO, format!("TLS: {m}")),
        e => (abi::IO, e.to_string()),
    };
    Error::new(st, format!("ftp: {what}: {text}"))
}

fn tls_config() -> Result<Arc<ClientConfig>> {
    static CFG: OnceLock<std::result::Result<Arc<ClientConfig>, String>> = OnceLock::new();
    CFG.get_or_init(|| {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Arc::new(cfg))
    })
    .clone()
    .map_err(|m| Error::new(abi::INTERNAL, format!("ftp: TLS setup: {m}")))
}

fn timeouts(s: &TcpStream) -> std::io::Result<()> {
    s.set_read_timeout(Some(TIMEOUT))?;
    s.set_write_timeout(Some(TIMEOUT))
}

/// New logged-in control connection (binary type, passive mode).
fn connect(t: &Target) -> Result<Conn> {
    let host = format!("{}:{}", t.host, t.port);
    let io = |e: std::io::Error| Error::new(abi::IO, format!("ftp: {host}: {e}"));
    let mut last = Error::new(abi::NOT_FOUND, format!("ftp: {host}: no address"));
    let addrs = (t.host.as_str(), t.port).to_socket_addrs().map_err(io)?;
    let mut conn = None;
    for a in addrs {
        match Conn::connect_timeout(a, TIMEOUT) {
            Ok(c) => {
                conn = Some(c);
                break;
            }
            Err(e) => last = ferr(e, &host),
        }
    }
    let mut c = conn.ok_or(last)?;
    timeouts(&c.get_ref()).map_err(io)?;
    if t.tls {
        c = c
            .into_secure(RustlsConnector::from(tls_config()?), &t.host)
            .map_err(|e| ferr(e, &host))?;
    }
    c.set_passive_nat_workaround(true); // servers behind NAT announce private PASV addresses
    let mut c = c.passive_stream_builder(|addr| {
        let s = TcpStream::connect_timeout(&addr, TIMEOUT).map_err(FtpError::ConnectionError)?;
        timeouts(&s).map_err(FtpError::ConnectionError)?;
        Ok(s)
    });
    c.login(&t.user, &t.pass).map_err(|e| match code(&e) {
        Some(530) => Error::new(abi::AUTH, format!("ftp: {host}: login failed")),
        _ => ferr(e, &host),
    })?;
    c.transfer_type(FileType::Binary)
        .map_err(|e| ferr(e, &host))?;
    Ok(c)
}

type Marks = fn() -> std::result::Result<config::Bookmarks, String>;

/// Pooled connections idle longer than this are dropped unchecked (servers time out idle
/// control connections; a dead one would cost a NOOP timeout).
const IDLE_MAX: Duration = Duration::from_secs(60);

pub struct Ftp {
    /// `None` = the `ftp://` top (bookmark list).
    target: Option<Target>,
    idle: Mutex<Vec<(Conn, Instant)>>,
    /// MLSD/MLST answered "not implemented" once: use LIST.
    no_mlsx: AtomicBool,
    /// Bookmark source (`ftp.toml`; injected by tests).
    marks: Marks,
}

impl Ftp {
    /// `config` = `ftp://<authority>` / `ftps://<authority>` (empty = bookmark list).
    pub fn open(config: &str) -> Result<Self> {
        Self::open_with(config, config::bookmarks)
    }

    fn open_with(config: &str, marks: Marks) -> Result<Self> {
        let invalid = || Error::new(abi::INVALID, "ftp: mount must be ftp://... or ftps://...");
        let (scheme, auth) = config.split_once("://").ok_or_else(invalid)?;
        let tls = match scheme {
            "ftp" => false,
            "ftps" => true,
            _ => return Err(invalid()),
        };
        let mut fs = Self {
            target: None,
            idle: Mutex::default(),
            no_mlsx: AtomicBool::new(false),
            marks,
        };
        if auth.is_empty() {
            return Ok(fs);
        }
        let t = config::resolve_in(auth, tls, marks).map_err(|m| Error::new(abi::INVALID, m))?;
        // Connect now: a wrong host/password fails the mount, not the first listing.
        let c = connect(&t)?;
        fs.target = Some(t);
        fs.put(c);
        Ok(fs)
    }

    fn target(&self) -> Result<&Target> {
        self.target.as_ref().ok_or_else(|| {
            Error::new(
                abi::UNSUPPORTED,
                "ftp: not supported on the bookmark list (open a bookmark first)",
            )
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<(Conn, Instant)>> {
        self.idle.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A recent idle connection that still answers, else a new one.
    fn take(&self) -> Result<Conn> {
        let t = self.target()?;
        loop {
            let pooled = self.lock().pop();
            let Some((mut c, since)) = pooled else {
                return connect(t);
            };
            if since.elapsed() < IDLE_MAX && c.noop().is_ok() {
                return Ok(c);
            } // else stale or timed out by the server: drop it
        }
    }

    fn put(&self, c: Conn) {
        let mut idle = self.lock();
        if idle.len() < POOL {
            idle.push((c, Instant::now()));
        }
    }

    /// Run `f` on a pooled connection; keep it unless the error may have broken it.
    fn run<T>(&self, f: impl FnOnce(&mut Conn) -> Result<T>) -> Result<T> {
        let mut c = self.take()?;
        let r = f(&mut c);
        if keep_conn(&r) {
            self.put(c);
        }
        r
    }

    /// Raw listing lines of the current dir (MLSD, else LIST) and which kind they are.
    fn lines(&self, c: &mut Conn) -> FtpResult<(Vec<String>, bool)> {
        if !self.no_mlsx.load(Ordering::Relaxed) {
            match c.mlsd(None) {
                Err(e) if unsupported(&e) => self.no_mlsx.store(true, Ordering::Relaxed),
                r => return r.map(|l| (l, true)),
            }
        }
        c.list(None).map(|l| (l, false))
    }

    fn items(&self, c: &mut Conn, dir: &str) -> Result<Vec<Item>> {
        c.cwd(abs(dir)).map_err(|e| ferr(e, &abs(dir)))?;
        let (lines, mlsd) = self.lines(c).map_err(|e| ferr(e, &abs(dir)))?;
        let parse = if mlsd { list::mlsd } else { list::list };
        let mut items: Vec<Item> = lines.iter().filter_map(|l| parse(l)).collect();
        // Links to dirs are common on FTP (`pub -> /srv/pub`): CWD tells. Flagged as links so
        // the host never recurses through them (delete would empty the target).
        let links = items.iter_mut().filter(|i| i.kind == abi::KIND_SYMLINK);
        for (n, it) in links.enumerate() {
            it.link = true;
            if n < MAX_PROBES {
                let p = abs(&join(dir, &it.name));
                it.kind = probe_kind(c.cwd(&p)).map_err(|e| ferr(e, &p))?;
            }
        }
        Ok(items)
    }

    fn bookmarks(&self) -> Result<config::Bookmarks> {
        (self.marks)().map_err(|m| Error::new(abi::IO, m))
    }

    pub fn list(&self, dir: &str) -> Result<Lister> {
        let items = match &self.target {
            None if dir.is_empty() => self
                .bookmarks()?
                .into_keys()
                .filter(|n| commander_plugin_abi::glue::valid_name(n))
                .map(Item::dir)
                .collect(),
            _ => self.run(|c| self.items(c, dir))?,
        };
        Ok(Lister(items.into()))
    }

    pub fn stat(&self, path: &str) -> Result<Item> {
        if path.is_empty() {
            return Ok(Item::dir(""));
        }
        if self.target.is_none() {
            return match self.bookmarks()?.contains_key(path) {
                true => Ok(Item::dir("")),
                false => Err(Error::new(
                    abi::NOT_FOUND,
                    format!("ftp: no bookmark {path:?}"),
                )),
            };
        }
        self.run(|c| {
            let p = abs(path);
            if !self.no_mlsx.load(Ordering::Relaxed) {
                match c.mlst(Some(&p)) {
                    Ok(line) => {
                        if let Some(it) = list::mlst(&line).filter(|i| i.kind != abi::KIND_SYMLINK)
                        {
                            return Ok(it);
                        }
                    }
                    Err(e) if unsupported(&e) => self.no_mlsx.store(true, Ordering::Relaxed),
                    Err(e) => return Err(ferr(e, &p)),
                }
            }
            // No (usable) MLST: find the name in its parent's listing.
            let (dir, name) = parent_name(path);
            let found = self.items(c, dir)?.into_iter().find(|i| i.name == name);
            found
                .map(|i| Item {
                    name: String::new(),
                    ..i
                })
                .ok_or_else(|| Error::new(abi::NOT_FOUND, format!("ftp: {p}: not found")))
        })
    }

    /// Absent = `Ok(false)`; other errors pass through. `path` is relative.
    fn exists(&self, path: &str) -> Result<bool> {
        match self.stat(path) {
            Ok(_) => Ok(true),
            Err(e) if e.status == abi::NOT_FOUND => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn exists_err(&self, path: &str) -> Result<()> {
        match self.exists(path)? {
            true => Err(Error::new(
                abi::EXISTS,
                format!("ftp: {}: exists", abs(path)),
            )),
            false => Ok(()),
        }
    }

    /// `offset` > 0 = resume (REST): binary transfers only.
    pub fn reader(&self, path: &str, offset: u64) -> Result<Box<dyn Read + Send>> {
        let p = abs(path);
        let text = self.target()?.mode.text(path);
        if text && offset > 0 {
            return Err(Error::new(
                abi::UNSUPPORTED,
                format!("ftp: {p}: resume needs binary transfer mode"),
            ));
        }
        let mut c = self.take()?;
        if offset > 0 {
            let off = usize::try_from(offset)
                .map_err(|_| Error::new(abi::INVALID, "ftp: offset too large"))?;
            c.resume_transfer(off).map_err(|e| ferr(e, &p))?;
        }
        if text {
            c.transfer_type(FileType::Ascii(FormatControl::Default))
                .map_err(|e| ferr(e, &p))?;
        }
        let data = c.retr_as_stream(&p).map_err(|e| ferr(e, &p))?;
        let dl = Download {
            data: Some(data),
            path: p,
            _conn: c,
        };
        Ok(match text && !cfg!(windows) {
            true => Box::new(Lf::new(dl)),
            false => Box::new(dl), // Windows keeps the wire's CRLF
        })
    }

    pub fn writer(self: &Arc<Self>, path: &str, overwrite: bool) -> Result<Writer> {
        let text = self.target()?.mode.text(path);
        if !overwrite {
            self.exists_err(path)?;
        }
        let (dir, name) = parent_name(path);
        // FTP has no exclusive create: a unique name that is absent right now (STOR to an
        // existing link would write through it).
        let free = (0..PART_TRIES)
            .map(|_| join(dir, &part_name(name)))
            .find_map(|t| match self.exists(&t) {
                Ok(false) => Some(Ok(t)),
                Ok(true) => None,
                Err(e) => Some(Err(e)),
            });
        let tmp = abs(&free.unwrap_or_else(|| {
            Err(Error::new(
                abi::EXISTS,
                format!("ftp: {}: no free temp name", abs(path)),
            ))
        })?);
        let mut c = self.take()?;
        if text {
            c.transfer_type(FileType::Ascii(FormatControl::Default))
                .map_err(|e| ferr(e, &tmp))?;
        }
        let data = c.put_with_stream(&tmp).map_err(|e| ferr(e, &tmp))?;
        Ok(Writer {
            data: Some(data),
            conn: Some(c),
            fs: Arc::clone(self),
            tmp,
            dest: path.to_owned(),
            overwrite,
            cr: text.then_some(false),
        })
    }

    /// Pool `c` after a text transfer: back to binary first (dropped if that fails).
    fn put_binary(&self, mut c: Conn) {
        if c.transfer_type(FileType::Binary).is_ok() {
            self.put(c);
        }
    }

    pub fn mkdir(&self, path: &str) -> Result<()> {
        let p = abs(path);
        let r = self.run(|c| c.mkdir(&p).map_err(|e| ferr(e, &p)));
        match r {
            Err(e) if self.exists(path).unwrap_or(false) => Err(Error::new(
                abi::EXISTS,
                format!("ftp: {p}: exists ({})", e.msg),
            )),
            r => r,
        }
    }

    pub fn remove_file(&self, path: &str) -> Result<()> {
        let p = abs(path);
        self.run(|c| c.rm(&p).map_err(|e| ferr(e, &p)))
    }

    pub fn remove_dir(&self, path: &str) -> Result<()> {
        let p = abs(path);
        self.run(|c| c.rmdir(&p).map_err(|e| ferr(e, &p)))
    }

    pub fn rename(&self, from: &str, to: &str) -> Result<()> {
        self.target()?;
        self.exists_err(to)?;
        let (f, t) = (abs(from), abs(to));
        self.run(|c| c.rename(&f, &t).map_err(|e| ferr(e, &f)))
    }
}

/// Keep a connection after `r`? Reply errors leave it usable; IO/internal ones may not.
fn keep_conn<T>(r: &Result<T>) -> bool {
    !matches!(r, Err(e) if e.status == abi::IO || e.status == abi::INTERNAL)
}

/// Kind of a symlink from `CWD` into it: a refusal = file; IO errors pass through.
fn probe_kind(cwd: FtpResult<()>) -> FtpResult<u32> {
    match cwd {
        Ok(()) => Ok(abi::KIND_DIR),
        Err(e) if code(&e).is_some() => Ok(abi::KIND_FILE),
        Err(e) => Err(e),
    }
}

fn join(dir: &str, name: &str) -> String {
    match dir.is_empty() {
        true => name.to_owned(),
        false => format!("{dir}/{name}"),
    }
}

/// Whole listing fetched up front (one data connection), handed out in batches.
pub struct Lister(VecDeque<Item>);

impl Lister {
    pub fn next_batch(&mut self, cap: usize) -> Vec<Item> {
        let n = cap.min(self.0.len());
        self.0.drain(..n).collect()
    }
}

/// RETR stream. Field order = drop order: the data socket closes before the connection.
struct Download {
    /// `None` once finished.
    data: Option<Transfer>,
    /// Absolute path (errors).
    path: String,
    _conn: Conn,
}

impl Read for Download {
    /// At the end the server's transfer reply is checked: a dropped data connection is an
    /// error, never a short file.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let Some(d) = self.data.as_mut() else {
            return Ok(0);
        };
        let n = d.read(buf)?;
        if n == 0
            && !buf.is_empty()
            && let Some(d) = self.data.take()
        {
            d.finish()
                .map_err(|e| std::io::Error::other(ferr(e, &self.path).msg))?;
        }
        Ok(n)
    }
}

/// Text download on an LF system: wire CRLF -> LF.
struct Lf<R> {
    inner: R,
    out: Vec<u8>,
    pos: usize,
    /// A CR held back from the last chunk (its LF may come next).
    cr: bool,
}

impl<R: Read> Lf<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            out: Vec::new(),
            pos: 0,
            cr: false,
        }
    }
}

impl<R: Read> Read for Lf<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut raw = [0u8; 1 << 16];
        while self.pos == self.out.len() {
            (self.out, self.pos) = (Vec::new(), 0);
            let n = self.inner.read(&mut raw)?;
            if n == 0 {
                if !std::mem::take(&mut self.cr) {
                    return Ok(0);
                }
                self.out.push(b'\r'); // a lone CR at the very end
            }
            from_crlf(&mut self.cr, &raw[..n], &mut self.out);
        }
        let n = buf.len().min(self.out.len() - self.pos);
        buf[..n].copy_from_slice(&self.out[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// CRLF -> LF; `cr`: a CR held back (from the end of the previous chunk).
fn from_crlf(cr: &mut bool, buf: &[u8], out: &mut Vec<u8>) {
    for &b in buf {
        if *cr && b != b'\n' {
            out.push(b'\r');
        }
        *cr = b == b'\r';
        if !*cr {
            out.push(b);
        }
    }
}

/// Every lone LF -> CRLF (text upload); `cr`: the last byte sent was a CR.
fn to_crlf(cr: &mut bool, buf: &[u8], out: &mut Vec<u8>) {
    for &b in buf {
        if b == b'\n' && !*cr {
            out.push(b'\r');
        }
        out.push(b);
        *cr = b == b'\r';
    }
}

/// STOR stream into `tmp`; `finish` renames it to `dest`, drop deletes it.
pub struct Writer {
    data: Option<Transfer>,
    conn: Option<Conn>,
    fs: Arc<Ftp>,
    /// Absolute temp path; empty once committed or deliberately kept.
    tmp: String,
    /// Relative target path.
    dest: String,
    overwrite: bool,
    /// Text transfer (lone LF -> CRLF): whether the last byte sent was a CR. `None` = binary.
    cr: Option<bool>,
}

impl Writer {
    pub fn write(&mut self, buf: &[u8]) -> Result<()> {
        let data = self
            .data
            .as_mut()
            .ok_or_else(|| Error::new(abi::INTERNAL, "ftp: closed"))?;
        let r = match &mut self.cr {
            None => data.write_all(buf),
            Some(cr) => {
                let mut out = Vec::with_capacity(buf.len() + buf.len() / 32);
                to_crlf(cr, buf, &mut out);
                data.write_all(&out)
            }
        };
        r.map_err(|e| Error::new(abi::IO, format!("ftp: {}: {e}", abs(&self.dest))))
    }

    /// Pool the transfer's connection again (back to binary after a text one).
    fn give_back(&self, c: Conn) {
        match self.cr {
            Some(_) => self.fs.put_binary(c),
            None => self.fs.put(c),
        }
    }

    pub fn finish(mut self) -> Result<()> {
        let (Some(data), Some(mut c)) = (self.data.take(), self.conn.take()) else {
            return Err(Error::new(abi::INTERNAL, "ftp: closed"));
        };
        let dest = abs(&self.dest);
        data.finish().map_err(|e| ferr(e, &dest))?;
        // RULES: check the target is absent right before every rename (not only at open).
        if !self.overwrite {
            self.fs.exists_err(&self.dest)?;
        }
        // Unix servers replace on rename; others refuse an existing target.
        if let Err(e) = c.rename(&self.tmp, &dest) {
            let replace = self.overwrite && code(&e).is_some() && self.fs.exists(&self.dest)?;
            if !replace {
                return Err(ferr(e, &dest)); // Drop deletes the temp; dest untouched
            }
            c.rm(&dest).map_err(|e| ferr(e, &dest))?;
            if let Err(e) = c.rename(&self.tmp, &dest) {
                // The old file is gone: never delete the only copy of the new data.
                let kept = std::mem::take(&mut self.tmp);
                let Error { status, msg } = ferr(e, &dest);
                return Err(Error::new(
                    status,
                    format!("{msg} (new data kept at {kept})"),
                ));
            }
        }
        self.tmp.clear(); // committed: nothing to clean up
        self.give_back(c);
        Ok(())
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        drop(self.data.take()); // ends the STOR (the server keeps the partial temp file)
        if self.tmp.is_empty() {
            return;
        }
        // Best effort: a fresh connection if the transfer's one is gone.
        let c = self.conn.take().map(Ok).unwrap_or_else(|| self.fs.take());
        if let Ok(mut c) = c
            && c.rm(&self.tmp).is_ok()
        {
            self.give_back(c);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

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
    fn reply_codes_map_to_status() {
        let reply = |code: u32, text: &str| {
            FtpError::UnexpectedResponse(suppaftp::types::Response::new(
                code.into(),
                text.as_bytes().to_vec(),
            ))
        };
        let st = |code, text| ferr(reply(code, text), "/p").status;
        assert_eq!(st(550, "550 No such file or directory"), abi::NOT_FOUND);
        assert_eq!(st(550, "550 Permission denied"), abi::DENIED);
        assert_eq!(st(550, "550 Directory not empty"), abi::NOT_EMPTY);
        assert_eq!(st(530, "530 Login incorrect"), abi::AUTH);
        assert_eq!(st(502, "502 MLSD not implemented"), abi::UNSUPPORTED);
        assert_eq!(st(451, "451 Local error"), abi::IO);
        let e = ferr(reply(550, "550 Nope"), "/a b");
        assert_eq!(e.msg, "ftp: /a b: 550 Nope");
    }

    use crate::config::Bookmarks;
    use crate::fake::{self, Shared};
    use std::net::TcpListener;
    use std::sync::atomic::AtomicU16;

    fn no_marks() -> std::result::Result<Bookmarks, String> {
        Ok(Bookmarks::new())
    }

    fn two_marks() -> std::result::Result<Bookmarks, String> {
        crate::config::parse_bookmarks("[a]\nhost = \"h\"\n[\"b:c\"]\nhost = \"h\"\n")
    }

    fn broken_marks() -> std::result::Result<Bookmarks, String> {
        Err("ftp.toml: broken".into())
    }

    fn server(setup: impl FnOnce(&mut fake::State)) -> (Shared, Arc<Ftp>) {
        let st = Shared::default();
        setup(&mut st.lock().unwrap());
        let port = fake::start(Arc::clone(&st));
        let fs = Ftp::open_with(&format!("ftp://u@127.0.0.1:{port}"), no_marks).unwrap();
        (st, Arc::new(fs))
    }

    fn names(fs: &Ftp, dir: &str) -> Vec<(String, u32)> {
        let mut l = fs.list(dir).unwrap();
        let v = l.next_batch(1);
        let rest = l.next_batch(100);
        v.into_iter()
            .chain(rest)
            .map(|i| (i.name, i.kind))
            .collect()
    }

    fn put(fs: &Arc<Ftp>, p: &str, data: &[u8], overwrite: bool) -> Result<()> {
        let mut w = fs.writer(p, overwrite)?;
        w.write(data)?;
        w.finish()
    }

    fn read(fs: &Ftp, p: &str, off: u64) -> String {
        let mut s = String::new();
        fs.reader(p, off).unwrap().read_to_string(&mut s).unwrap();
        s
    }

    fn st(r: Result<impl Sized>) -> Status {
        r.err().map_or(abi::OK, |e| e.status)
    }

    use commander_plugin_abi::Status;

    #[test]
    fn bookmark_top() {
        let fs = Ftp::open_with("ftp://", two_marks).unwrap();
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
        assert_eq!(st(Arc::new(fs).writer("x", true)), abi::UNSUPPORTED);
        let bad = Ftp::open_with("ftp://", broken_marks).unwrap();
        assert_eq!(st(bad.list("")), abi::IO);
        assert_eq!(st(bad.stat("a")), abi::IO);
        assert_eq!(st(Ftp::open("http://h")), abi::INVALID, "foreign scheme");
        assert_eq!(st(Ftp::open("nope")), abi::INVALID);
        assert_eq!(
            st(Ftp::open("ftp://u:pw@h")),
            abi::INVALID,
            "no URL passwords"
        );
    }

    #[test]
    fn roundtrip_over_mlsd() {
        let (_st, fs) = server(|_| {});
        fs.mkdir("d").unwrap();
        assert_eq!(st(fs.mkdir("d")), abi::EXISTS);
        assert_eq!(st(fs.mkdir("nope/x")), abi::NOT_FOUND);
        put(&fs, "d/a b.txt", b"hello world", false).unwrap();
        assert_eq!(names(&fs, "d"), [("a b.txt".into(), abi::KIND_FILE)]);
        let s = fs.stat("d/a b.txt").unwrap();
        assert_eq!((s.kind, s.size, s.name.as_str()), (abi::KIND_FILE, 11, ""));
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
    fn list_fallback_and_symlink_probe() {
        let (st_, fs) = server(|s| {
            s.no_mlsx = true;
            s.tree.insert("/d".into(), None);
            s.tree.insert("/f".into(), Some(b"abc".to_vec()));
            s.links.insert("/ld".into(), "/d".into());
            s.links.insert("/lf".into(), "/f".into());
        });
        let mut got = names(&fs, "");
        got.sort();
        let want = [
            ("d", abi::KIND_DIR),
            ("f", abi::KIND_FILE),
            ("ld", abi::KIND_DIR),
            ("lf", abi::KIND_FILE),
        ];
        assert_eq!(got, want.map(|(n, k)| (n.to_string(), k)));
        assert_eq!(fs.stat("f").unwrap().size, 3, "stat via the parent listing");
        assert_eq!(st(fs.stat("zz")), abi::NOT_FOUND);
        let log = st_.lock().unwrap().log.join("\n");
        assert_eq!(log.matches("MLSD").count(), 1, "MLSD tried once: {log}");
        assert_eq!(
            log.matches("MLST").count(),
            0,
            "MLST skipped after MLSD 502"
        );
    }

    #[test]
    fn mlsd_symlinks_and_stat() {
        let (_st, fs) = server(|s| {
            s.tree.insert("/d".into(), None);
            s.links.insert("/ld".into(), "/d".into());
        });
        assert!(names(&fs, "").contains(&("ld".into(), abi::KIND_DIR)));
        let all = fs.list("").unwrap().next_batch(10);
        let links: Vec<_> = all
            .iter()
            .filter(|i| i.link)
            .map(|i| i.name.as_str())
            .collect();
        assert_eq!(
            links,
            ["ld"],
            "links flagged: the host never recurses through them"
        );
        // MLST says "link": stat falls back to the listing (probed: dir).
        assert_eq!(fs.stat("ld").unwrap().kind, abi::KIND_DIR);
    }

    #[test]
    fn overwrite_on_a_server_that_wont_replace() {
        let (st_, fs) = server(|s| {
            s.no_replace = true;
            s.tree.insert("/a".into(), Some(b"old".to_vec()));
        });
        put(&fs, "a", b"new", true).unwrap();
        assert_eq!(read(&fs, "a", 0), "new");
        assert_eq!(st_.lock().unwrap().tree.len(), 1, "temp renamed away");
    }

    #[test]
    fn failed_replace_keeps_the_new_data() {
        let (st_, fs) = server(|s| {
            s.rnto_fail = true;
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
    fn failed_rename_without_overwrite_cleans_up() {
        let (st_, fs) = server(|s| s.rnto_fail = true);
        assert_eq!(st(put(&fs, "n", b"x", false)), abi::DENIED);
        assert!(
            st_.lock().unwrap().tree.is_empty(),
            "temp deleted, no target"
        );
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
        assert_eq!(st_.lock().unwrap().tree.len(), 1, "temp deleted");
    }

    #[test]
    fn dropped_connection_is_not_reused() {
        let (_st, fs) = server(|_| {});
        assert_eq!(st(fs.list("die")), abi::IO);
        assert!(fs.list("").is_ok(), "next op gets a fresh connection");
    }

    static AUTH_PORT: AtomicU16 = AtomicU16::new(0);

    fn bad_pass_marks() -> std::result::Result<Bookmarks, String> {
        let p = AUTH_PORT.load(Ordering::Relaxed);
        crate::config::parse_bookmarks(&format!(
            "[x]\nhost = \"127.0.0.1\"\nport = {p}\nuser = \"u\"\npassword = \"bad\"\n"
        ))
    }

    #[test]
    fn wrong_password_is_auth_and_never_echoed() {
        let port = fake::start(Shared::default());
        AUTH_PORT.store(port, Ordering::Relaxed);
        let e = Ftp::open_with("ftp://x", bad_pass_marks).err().unwrap();
        assert_eq!(e.status, abi::AUTH);
        assert!(!e.msg.contains("bad"), "{}", e.msg);
    }

    static MODE_PORT: AtomicU16 = AtomicU16::new(0);

    fn auto_marks() -> std::result::Result<Bookmarks, String> {
        let p = MODE_PORT.load(Ordering::Relaxed);
        crate::config::parse_bookmarks(&format!(
            "[x]\nhost = \"127.0.0.1\"\nport = {p}\nuser = \"u\"\nmode = \"auto\"\n"
        ))
    }

    #[test]
    fn text_mode_converts_line_ends_and_refuses_resume() {
        let st_ = Shared::default();
        MODE_PORT.store(fake::start(Arc::clone(&st_)), Ordering::Relaxed);
        let fs = Arc::new(Ftp::open_with("ftp://x", auto_marks).unwrap());
        put(&fs, "a.txt", b"l1\nl2\r\nl3\n", false).unwrap();
        assert_eq!(
            st_.lock().unwrap().tree["/a.txt"],
            Some(b"l1\nl2\nl3\n".to_vec()),
            "server stores its own LF"
        );
        let want = match cfg!(windows) {
            true => "l1\r\nl2\r\nl3\r\n",
            false => "l1\nl2\nl3\n",
        };
        assert_eq!(read(&fs, "a.txt", 0), want);
        assert_eq!(
            st(fs.reader("a.txt", 1)),
            abi::UNSUPPORTED,
            "no text resume"
        );
        // The pooled connection is binary again: a .bin round-trips unchanged.
        put(&fs, "b.bin", b"x\ny\r", false).unwrap();
        assert_eq!(read(&fs, "b.bin", 0), "x\ny\r");
        assert_eq!(read(&fs, "b.bin", 2), "y\r", "binary resumes");
        let log = st_.lock().unwrap().log.join("\n");
        assert!(log.contains("TYPE A") && log.contains("TYPE I"), "{log}");
    }

    #[test]
    fn line_end_converters_across_chunks() {
        let (mut cr, mut out) = (false, Vec::new());
        to_crlf(&mut cr, b"a\nb\r", &mut out);
        to_crlf(&mut cr, b"\nc\n", &mut out);
        assert_eq!(out, b"a\r\nb\r\nc\r\n");
        let lf = |chunks: &[&[u8]]| {
            struct Chunks<'a>(Vec<&'a [u8]>);
            impl Read for Chunks<'_> {
                fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                    let Some(c) = self.0.first().copied() else {
                        return Ok(0);
                    };
                    self.0.remove(0);
                    buf[..c.len()].copy_from_slice(c);
                    Ok(c.len())
                }
            }
            let mut s = Vec::new();
            let mut r = Lf::new(Chunks(chunks.to_vec()));
            let mut one = [0u8; 1]; // tiny reads drain `out` piecewise
            while r.read(&mut one).unwrap() == 1 {
                s.push(one[0]);
            }
            s
        };
        assert_eq!(lf(&[b"a\r", b"\nb\r", b"c\r\n"]), b"a\nb\rc\n");
        assert_eq!(lf(&[b"x\r"]), b"x\r", "a lone CR at the end is kept");
        assert_eq!(lf(&[b"\r", b"\r\n"]), b"\r\n");
    }

    #[test]
    fn cut_download_is_an_error_not_a_short_file() {
        let (_st, fs) = server(|s| {
            s.tree.insert("/f".into(), Some(b"0123456789".to_vec()));
            s.cut = Some(4);
        });
        let mut v = Vec::new();
        let e = fs.reader("f", 0).unwrap().read_to_end(&mut v).unwrap_err();
        assert!(e.to_string().contains("426"), "{e}");
        assert_eq!(v, b"0123");
    }

    #[test]
    fn unreachable_server() {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let e = Ftp::open_with(&format!("ftp://127.0.0.1:{port}"), no_marks)
            .err()
            .unwrap();
        assert_eq!(e.status, abi::IO, "{}", e.msg);
    }

    #[test]
    fn helpers() {
        assert!(keep_conn(&Ok(())));
        assert!(keep_conn::<()>(&Err(Error::new(abi::NOT_FOUND, ""))));
        assert!(!keep_conn::<()>(&Err(Error::new(abi::IO, ""))));
        assert!(!keep_conn::<()>(&Err(Error::new(abi::INTERNAL, ""))));
        let reply = FtpError::UnexpectedResponse(suppaftp::types::Response::new(
            550.into(),
            b"550 no".to_vec(),
        ));
        assert_eq!(probe_kind(Ok(())).unwrap(), abi::KIND_DIR);
        assert_eq!(probe_kind(Err(reply)).unwrap(), abi::KIND_FILE);
        assert!(probe_kind(Err(FtpError::BadResponse)).is_err());
        assert_eq!(
            ferr(FtpError::SecureError("x".into()), "h").msg,
            "ftp: h: TLS: x"
        );
        assert!(tls_config().is_ok());
    }

    /// Live server: `COMMANDER_FTP_TEST_URL=ftp://user@host[:port]/dir` (+
    /// `COMMANDER_FTP_TEST_PASS`) `cargo test -p commander_ftp -- --ignored`.
    #[test]
    #[ignore = "needs a live FTP server (COMMANDER_FTP_TEST_URL)"]
    fn live_roundtrip() {
        fn live() -> std::result::Result<Bookmarks, String> {
            let url = std::env::var("COMMANDER_FTP_TEST_URL").map_err(|e| e.to_string())?;
            let auth = url.split_once("://").unwrap().1.split('/').next().unwrap();
            let mut t = crate::config::parse_authority(auth, url.starts_with("ftps"))?;
            t.pass = std::env::var("COMMANDER_FTP_TEST_PASS").unwrap_or(t.pass);
            Ok(Bookmarks::from([("live".to_string(), t)]))
        }
        let url = std::env::var("COMMANDER_FTP_TEST_URL").expect("COMMANDER_FTP_TEST_URL");
        let dir = url
            .split_once("://")
            .unwrap()
            .1
            .split_once('/')
            .map_or("", |d| d.1);
        let fs = Arc::new(Ftp::open_with("ftp://live", live).expect("connect"));
        let base = join(dir.trim_end_matches('/'), "cmdr-ftp-test");
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

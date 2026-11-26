//! Parallel ranged downloads: an object with more than one chunk left after the read offset is
//! fetched by up to `download_parallel` workers (`Range` + `If-Match` per chunk) and handed to
//! the read stream in order. At most `download_parallel` chunks are in flight / buffered
//! besides the one being read (reorder window).
use crate::client::{Error, Req, Resp, Result};
use crate::fs::Store;
use commander_plugin_abi::{self as abi, glue::Cancel};
use std::collections::HashMap;
use std::io::{self, Cursor, Read};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

const MIB: u64 = 1 << 20;
/// Most bytes one read stream may hold: `(parallel + 1) x chunk` (window + the chunk read).
const MAX_BUFFER: u64 = 1 << 30;
/// An attempt that brought less than this made no progress.
const PROGRESS: usize = 64 << 10;
/// Attempts in a row without progress before a chunk fails.
const TRIES: u32 = 3;
/// How often a reader waiting for a chunk polls the host's cancel flag.
const POLL: Duration = Duration::from_millis(50);
const CHANGED: &str = "object changed during the download";

/// Download tuning from `s3.toml` (`download_parallel`, `download_chunk_mib`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Tuning {
    /// Ranged GETs in flight per read stream (1 = one plain GET).
    pub parallel: usize,
    /// Chunk bytes (> 0); up to one chunk after the offset = a single GET.
    pub chunk: u64,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            parallel: 8,
            chunk: 8 * MIB,
        }
    }
}

impl Tuning {
    /// Tolerant: a broken file or a bad / missing key keeps the default; values are clamped
    /// to 1..=32 workers and 1..=256 MiB chunks, and workers to `(parallel + 1) x chunk` <= 1 GiB.
    pub fn parse(text: &str) -> Self {
        let mut t = Self::default();
        let Ok(tab) = text.parse::<toml::Table>() else {
            return t;
        };
        let int = |k| tab.get(k).and_then(toml::Value::as_integer);
        if let Some(n) = int("download_parallel") {
            t.parallel = n.clamp(1, 32) as usize;
        }
        if let Some(n) = int("download_chunk_mib") {
            t.chunk = n.clamp(1, 256) as u64 * MIB;
        }
        t.parallel = t.parallel.min((MAX_BUFFER / t.chunk - 1).max(1) as usize);
        t
    }

    /// `$COMMANDER_S3_CONFIG`, else `s3.toml` next to Commander's config.toml.
    pub fn load() -> Self {
        abi::url::config_file("COMMANDER_S3_CONFIG", "s3.toml")
            .and_then(|p| abi::url::read_optional(&p).ok().flatten())
            .map_or_else(Self::default, |text| Self::parse(&text))
    }
}

fn header<'a>(resp: &'a Resp, name: &str) -> Option<&'a str> {
    resp.headers().get(name).and_then(|v| v.to_str().ok())
}

/// `Content-Range: bytes a-b/total` -> (a, total).
fn content_range(resp: &Resp) -> Option<(u64, u64)> {
    let (range, total) = header(resp, "content-range")?
        .strip_prefix("bytes ")?
        .split_once('/')?;
    Some((range.split_once('-')?.0.parse().ok()?, total.parse().ok()?))
}

/// Worth another attempt: network / body errors and 5xx (permanent ones carry their status).
fn transient(e: &Error) -> bool {
    e.status == abi::IO && (e.http == 0 || e.http >= 500)
}

fn io_err(e: Error) -> io::Error {
    io::Error::other(e.msg)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The read stream for the response to `Range: bytes=<offset>-<offset + chunk - 1>`: the
/// response itself when it holds the whole rest, parallel chunks when there is more, `None`
/// when the server sent no size or strong ETag to pin the chunks to (caller: a plain GET).
pub fn stream(
    store: &Arc<Store>,
    (bucket, key): (&str, &str),
    offset: u64,
    resp: Resp,
    cancelled: Cancel,
) -> Result<Option<Box<dyn Read + Send>>> {
    let body = |r: Resp| -> Box<dyn Read + Send> { Box::new(r.into_body().into_reader()) };
    let st = resp.status().as_u16();
    // a weak ETag can't pin byte ranges (If-Match compares strongly)
    let etag = header(&resp, "etag")
        .filter(|t| !t.starts_with("W/"))
        .map(str::to_owned);
    let total = match (st, content_range(&resp)) {
        (206, Some((a, total))) if a == offset => total,
        (206, _) => return Ok(None),
        _ if offset == 0 => return Ok(Some(body(resp))), // Range ignored: the whole object
        _ => {
            let msg = format!("s3: {bucket}/{key}: server ignored the Range request (HTTP {st})");
            return Err(Error::new(abi::IO, msg));
        }
    };
    let plan = Plan {
        start: offset,
        total,
        chunk: store.tuning.chunk,
    };
    if plan.count() <= 1 {
        return Ok(Some(body(resp)));
    }
    let Some(etag) = etag else {
        return Ok(None);
    };
    let obj = Obj {
        store: Arc::clone(store),
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        etag,
    };
    let p = Parallel::start(obj, plan, store.tuning.parallel, body(resp), cancelled)?;
    Ok(Some(Box::new(p)))
}

/// Byte range `start..total` in `chunk`-sized pieces.
#[derive(Debug, Clone, Copy)]
struct Plan {
    start: u64,
    total: u64,
    chunk: u64,
}

impl Plan {
    fn count(&self) -> u64 {
        (self.total.saturating_sub(self.start)).div_ceil(self.chunk)
    }

    fn range(&self, i: u64) -> (u64, u64) {
        let a = self.start + i * self.chunk;
        (a, (a + self.chunk).min(self.total))
    }
}

/// One object, pinned to the ETag of the first response.
struct Obj {
    store: Arc<Store>,
    bucket: String,
    key: String,
    etag: String,
}

impl Obj {
    fn err(&self, http: u16, why: &str) -> Error {
        Error {
            status: abi::IO,
            msg: format!("s3: {}/{}: {why}", self.bucket, self.key),
            http,
        }
    }

    /// GET bytes `a..b`, only while the object still has our ETag.
    fn get(&self, a: u64, b: u64) -> Result<Resp> {
        let r = Req::new("GET", Some(&self.bucket), &self.key)
            .h("range", format!("bytes={a}-{}", b - 1))
            .h("if-match", self.etag.clone());
        let resp = match self.store.c.send(&r) {
            Err(e) if e.http == 412 => return Err(self.err(412, CHANGED)),
            r => r?,
        };
        if header(&resp, "etag").is_some_and(|t| t != self.etag) {
            return Err(self.err(412, CHANGED)); // a server that ignores If-Match
        }
        match (resp.status().as_u16(), content_range(&resp)) {
            (206, Some((s, _))) if s == a => Ok(resp),
            (st, _) => Err(self.err(st, "server ignored the Range request")),
        }
    }

    /// Bytes `a..b`. A broken or short body resumes where it stopped; fails on a permanent
    /// error, a cancel, or after `TRIES` attempts in a row without progress.
    fn fetch(&self, a: u64, b: u64, stop: &dyn Fn() -> bool) -> Result<Vec<u8>> {
        let len = (b - a) as usize;
        let mut buf = Vec::with_capacity(len);
        let mut idle = 0;
        loop {
            let before = buf.len();
            let got = self
                .get(a + before as u64, b)
                .and_then(|resp| self.fill(resp, &mut buf, len, stop));
            if buf.len() == len {
                return Ok(buf);
            }
            if stop() {
                return Err(Error::new(abi::CANCELLED, "cancelled"));
            }
            let e = match got {
                Err(e) if !transient(&e) => return Err(e),
                Err(e) => e,
                Ok(()) => self.err(0, "connection closed early"),
            };
            idle = if buf.len() - before >= PROGRESS {
                0
            } else {
                idle + 1
            };
            if idle == TRIES {
                return Err(e);
            }
        }
    }

    /// Appends the body to `buf` (at most `len` bytes in all); stops early on `stop`.
    fn fill(
        &self,
        resp: Resp,
        buf: &mut Vec<u8>,
        len: usize,
        stop: &dyn Fn() -> bool,
    ) -> Result<()> {
        let mut body = resp.into_body().into_reader();
        let mut at = buf.len();
        buf.resize(len, 0);
        let r = loop {
            if at == len || stop() {
                break Ok(());
            }
            match body.read(&mut buf[at..]) {
                Ok(0) => break Ok(()),
                Ok(n) => at += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => break Err(self.err(0, &format!("read: {e}"))),
            }
        };
        buf.truncate(at);
        r
    }
}

/// Window state shared by the reader and its workers.
#[derive(Default)]
struct State {
    /// Next chunk a worker takes.
    next: u64,
    /// Chunk the reader holds or waits for: workers take chunks up to `base + window`, so
    /// `window` chunks are in flight / buffered besides the one being read.
    base: u64,
    /// Fetched chunks the reader hasn't reached yet.
    done: HashMap<u64, Result<Vec<u8>>>,
}

struct Shared {
    st: Mutex<State>,
    cv: Condvar,
    stop: AtomicBool,
    window: u64,
}

impl Shared {
    /// Next chunk to fetch, waiting while it is a window ahead of the reader. None = done.
    fn claim(&self, count: u64) -> Option<u64> {
        let mut st = lock(&self.st);
        loop {
            if self.stop.load(Relaxed) || st.next >= count {
                return None;
            }
            if st.next <= st.base + self.window {
                st.next += 1;
                return Some(st.next - 1);
            }
            st = self.cv.wait(st).unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Stop the workers (they quit after their current read) and drop the buffers.
    fn halt(&self) {
        self.stop.store(true, Relaxed);
        lock(&self.st).done.clear();
        self.cv.notify_all();
    }
}

fn worker(obj: &Obj, sh: &Shared, plan: Plan) {
    while let Some(i) = sh.claim(plan.count()) {
        let (a, b) = plan.range(i);
        // a panic must still deliver the chunk (as an error), or the reader waits forever
        let got = catch_unwind(AssertUnwindSafe(|| {
            obj.fetch(a, b, &|| sh.stop.load(Relaxed))
        }))
        .unwrap_or_else(|_| Err(Error::new(abi::INTERNAL, "s3: download worker panicked")));
        let mut st = lock(&sh.st);
        if sh.stop.load(Relaxed) {
            return;
        }
        st.done.insert(i, got);
        sh.cv.notify_all();
    }
}

/// In-order read stream over the chunks: chunk 0 straight from the first response, the rest
/// from the workers.
struct Parallel {
    obj: Arc<Obj>,
    sh: Arc<Shared>,
    plan: Plan,
    /// Current chunk, its source, next byte and end (absolute offsets).
    i: u64,
    cur: Box<dyn Read + Send>,
    pos: u64,
    end: u64,
    cancelled: Cancel,
    /// First error: every later read repeats it (never skips a chunk).
    failed: Option<String>,
}

impl Parallel {
    /// Workers for chunks 1.. ; chunk 0 is read from `first`.
    fn start(
        obj: Obj,
        plan: Plan,
        window: usize,
        first: Box<dyn Read + Send>,
        cancelled: Cancel,
    ) -> Result<Self> {
        let (obj, window) = (Arc::new(obj), window as u64);
        let sh = Arc::new(Shared {
            st: Mutex::new(State {
                next: 1,
                ..State::default()
            }),
            cv: Condvar::new(),
            stop: AtomicBool::new(false),
            window,
        });
        for _ in 0..window.min(plan.count() - 1) {
            let (o, s) = (Arc::clone(&obj), Arc::clone(&sh));
            let spawned = std::thread::Builder::new()
                .name("s3-get".into())
                .spawn(move || worker(&o, &s, plan));
            if let Err(e) = spawned {
                sh.halt();
                return Err(Error::new(abi::IO, format!("s3: download thread: {e}")));
            }
        }
        let (pos, end) = plan.range(0);
        Ok(Self {
            obj,
            sh,
            plan,
            i: 0,
            cur: Box::new(first.take(end - pos)),
            pos,
            end,
            cancelled,
            failed: None,
        })
    }

    fn cancel(&self) -> io::Error {
        self.sh.halt();
        io::Error::other("cancelled")
    }

    /// Chunk `i` once a worker has it (polls the cancel flag meanwhile).
    fn wait(&self, i: u64) -> io::Result<Vec<u8>> {
        let mut st = lock(&self.sh.st);
        st.base = i;
        self.sh.cv.notify_all();
        loop {
            if (self.cancelled)() {
                drop(st);
                return Err(self.cancel());
            }
            if let Some(r) = st.done.remove(&i) {
                return r.map_err(io_err);
            }
            st = self
                .sh
                .cv
                .wait_timeout(st, POLL)
                .map_or_else(|e| e.into_inner().0, |(st, _)| st);
        }
    }
}

impl Read for Parallel {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if let Some(m) = &self.failed {
            return Err(io::Error::other(m.clone()));
        }
        let r = self.next_bytes(out);
        if let Err(e) = &r {
            self.failed = Some(e.to_string());
            self.sh.halt();
        }
        r
    }
}

impl Parallel {
    fn next_bytes(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if (self.cancelled)() {
                return Err(self.cancel());
            }
            if self.pos < self.end {
                match self.cur.read(out) {
                    Ok(0) | Err(_) => {
                        // chunk 0's response broke off: fetch the rest of it
                        let stop = || (self.cancelled)() || self.sh.stop.load(Relaxed);
                        let rest = self.obj.fetch(self.pos, self.end, &stop);
                        self.cur = Box::new(Cursor::new(rest.map_err(io_err)?));
                    }
                    Ok(n) => {
                        self.pos += n as u64;
                        return Ok(n);
                    }
                }
                continue;
            }
            if self.i + 1 >= self.plan.count() {
                return Ok(0);
            }
            self.cur = Box::new(io::empty()); // free it before waiting
            self.i += 1;
            let data = self.wait(self.i)?;
            (self.pos, self.end) = self.plan.range(self.i);
            self.cur = Box::new(Cursor::new(data));
        }
    }
}

impl Drop for Parallel {
    fn drop(&mut self) {
        self.sh.halt();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Client;
    use crate::config::Config;
    use crate::sign::Creds;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::Instant;

    /// What the fake does with one ranged request (after the `hook`).
    #[derive(Clone, Copy, PartialEq)]
    enum Act {
        Serve,
        /// Send half the body, then close (a connection reset mid-body).
        Cut,
        Status(u16),
    }

    type Hook = Box<dyn Fn(&Fake, u64, usize) -> Act + Send + Sync>;

    /// Fake S3 object `b/k`: one thread per connection, so parallel ranges really overlap.
    struct Fake {
        data: Vec<u8>,
        etag: Mutex<String>,
        /// Honour `If-Match` (412); off = a server that ignores it.
        if_match: bool,
        ranges: bool,
        send_etag: bool,
        /// Content-Range claims a start one byte off.
        wrong_start: bool,
        /// Pause per 16 KiB piece sent (bench only).
        throttle: Option<Duration>,
        /// (range start, If-Match) per request; range starts fully served.
        log: Mutex<Vec<(u64, Option<String>)>>,
        served: Mutex<Vec<u64>>,
        cv: Condvar,
        /// (fake, range start, earlier requests for that start) -> action.
        hook: Hook,
    }

    fn data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 + i / 251) as u8).collect()
    }

    impl Fake {
        fn new(n: usize, hook: impl Fn(&Fake, u64, usize) -> Act + Send + Sync + 'static) -> Self {
            Self {
                data: data(n),
                etag: Mutex::new("\"v1\"".into()),
                if_match: true,
                ranges: true,
                send_etag: true,
                wrong_start: false,
                throttle: None,
                log: Mutex::default(),
                served: Mutex::default(),
                cv: Condvar::new(),
                hook: Box::new(hook),
            }
        }

        /// Blocks until `start` was served (10 s cap: then the test fails on its own).
        fn wait_served(&self, start: u64) {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut s = lock(&self.served);
            while !s.contains(&start) && Instant::now() < deadline {
                s = self.cv.wait_timeout(s, POLL).unwrap().0;
            }
        }

        fn starts(&self) -> Vec<u64> {
            lock(&self.log).iter().map(|l| l.0).collect()
        }

        fn handle(&self, s: TcpStream) {
            let mut r = BufReader::new(&s);
            let (mut range, mut im) = (None, None);
            let mut line = String::new();
            let _ = r.read_line(&mut line);
            loop {
                let mut h = String::new();
                if r.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                    break;
                }
                let (k, v) = h.split_once(':').unwrap_or_default();
                let v = v.trim().to_owned();
                match k.to_ascii_lowercase().as_str() {
                    "range" => range = Some(v),
                    "if-match" => im = Some(v),
                    _ => {}
                }
            }
            let len = self.data.len() as u64;
            let (a, b) = match range.as_deref().and_then(|r| r.strip_prefix("bytes=")) {
                Some(r) if self.ranges => {
                    let (a, b) = r.split_once('-').unwrap();
                    let a: u64 = a.parse().unwrap();
                    (a, b.parse().map_or(len, |b: u64| (b + 1).min(len)))
                }
                _ => (0, len),
            };
            let tries = {
                let mut log = lock(&self.log);
                log.push((a, im.clone()));
                log.iter().filter(|l| l.0 == a).count() - 1
            };
            let act = (self.hook)(self, a, tries);
            let etag = lock(&self.etag).clone();
            let code = match act {
                Act::Status(c) => c,
                _ if self.if_match && im.is_some_and(|m| m != etag) => 412,
                _ if a >= len => 416,
                _ if range.is_some() && self.ranges => 206,
                _ => 200,
            };
            let mut w = &s;
            let mut head = format!("HTTP/1.1 {code} X\r\nConnection: close\r\n");
            if self.send_etag {
                head += &format!("ETag: {etag}\r\n");
            }
            if code >= 300 {
                let _ = write!(w, "{head}Content-Length: 0\r\n\r\n");
                return;
            }
            if code == 206 {
                let s = a + u64::from(self.wrong_start);
                head += &format!("Content-Range: bytes {s}-{}/{len}\r\n", b - 1);
            }
            let body = &self.data[a as usize..b as usize];
            let _ = write!(w, "{head}Content-Length: {}\r\n\r\n", body.len());
            let body = match act {
                Act::Cut => &body[..body.len() / 2],
                _ => body,
            };
            for piece in body.chunks(16 << 10) {
                if w.write_all(piece).is_err() {
                    return;
                }
                if let Some(t) = self.throttle {
                    std::thread::sleep(t);
                }
            }
            let _ = w.flush();
            if act == Act::Serve {
                lock(&self.served).push(a);
                self.cv.notify_all();
            }
        }
    }

    /// Starts `fake`; a store for it with `parallel` workers and `chunk`-byte chunks.
    fn store(fake: &Arc<Fake>, parallel: usize, chunk: u64) -> Arc<Store> {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let f = Arc::clone(fake);
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let f = Arc::clone(&f);
                std::thread::spawn(move || f.handle(s));
            }
        });
        let cfg = Config {
            creds: Creds {
                access_key: "a".into(),
                secret_key: "s".into(),
                token: None,
            },
            region: "us-east-1".into(),
            endpoint: Some(url),
            path_style: true,
            profile: "p".into(),
            login: Vec::new(),
        };
        Arc::new(Store {
            c: Client::new(cfg),
            tuning: Tuning { parallel, chunk },
        })
    }

    fn never() -> Cancel {
        Box::new(|| false)
    }

    fn read_all(st: &Arc<Store>, offset: u64) -> std::result::Result<Vec<u8>, String> {
        let mut r = st
            .reader("b", "k", offset, Some(never()))
            .map_err(|e| e.msg)?;
        let mut v = Vec::new();
        r.read_to_end(&mut v).map_err(|e| e.to_string())?;
        Ok(v)
    }

    fn serve(_: &Fake, _: u64, _: usize) -> Act {
        Act::Serve
    }

    #[test]
    fn tuning_from_s3_toml() {
        let d = Tuning::default();
        assert_eq!((d.parallel, d.chunk), (8, 8 * MIB));
        let t = Tuning::parse("download_parallel = 4\ndownload_chunk_mib = 16\n");
        assert_eq!((t.parallel, t.chunk), (4, 16 * MIB));
        let t = Tuning::parse("download_parallel = 0\ndownload_chunk_mib = 9999");
        assert_eq!((t.parallel, t.chunk), (1, 256 * MIB), "clamped");
        let t = Tuning::parse("download_parallel = 32\ndownload_chunk_mib = 256");
        assert_eq!(t.parallel, 3, "(parallel + 1) x chunk <= 1 GiB");
        let t = Tuning::parse("download_parallel = \"x\"\nother = 1");
        assert_eq!(t, d, "bad value / unknown key: default");
        assert_eq!(Tuning::parse("[[broken"), d);
        let _ = Tuning::load(); // whatever this machine has: must not panic
    }

    #[test]
    fn large_object_in_parallel_ranges_is_byte_identical() {
        let fake = Arc::new(Fake::new(10_000, serve));
        let st = store(&fake, 4, 1000);
        assert!(read_all(&st, 0).unwrap() == fake.data);
        let mut starts = fake.starts();
        starts.sort_unstable();
        assert_eq!(starts, (0..10).map(|i| i * 1000).collect::<Vec<_>>());
        // the first request learns the ETag; every other range is pinned to it
        for (a, im) in lock(&fake.log).iter() {
            assert_eq!(im.as_deref(), (*a > 0).then_some("\"v1\""), "range {a}");
        }
    }

    #[test]
    fn out_of_order_completion_is_reassembled() {
        // chunk 1 is answered only after chunk 3 was served
        let fake = Arc::new(Fake::new(5_000, |f, a, _| {
            if a == 1000 {
                f.wait_served(3000);
            }
            Act::Serve
        }));
        let st = store(&fake, 3, 1000);
        assert!(read_all(&st, 0).unwrap() == fake.data);
        let served = lock(&fake.served).clone();
        let pos = |a| served.iter().position(|&s| s == a).unwrap();
        assert!(pos(3000) < pos(1000), "{served:?}");
    }

    #[test]
    fn a_broken_chunk_resumes_and_a_5xx_is_retried() {
        let fake = Arc::new(Fake::new(6_000, |_, a, tries| match (a, tries) {
            (0 | 3000, 0) => Act::Cut,
            (5000, 0) => Act::Status(503),
            _ => Act::Serve,
        }));
        let st = store(&fake, 4, 1000);
        assert!(read_all(&st, 0).unwrap() == fake.data);
        let starts = fake.starts();
        // chunk 0 (streamed) and chunk 3 resumed at their halves; chunk 5 asked twice
        assert!(
            starts.contains(&500) && starts.contains(&3500),
            "{starts:?}"
        );
        assert_eq!(starts.iter().filter(|&&a| a == 5000).count(), 2);
    }

    #[test]
    fn a_chunk_that_keeps_breaking_fails() {
        let fake = Arc::new(Fake::new(3_000, |_, a, _| match a {
            0 => Act::Serve,
            _ => Act::Cut,
        }));
        let st = store(&fake, 2, 1000);
        let mut r = st.reader("b", "k", 0, Some(never())).unwrap();
        let e = r.read_to_end(&mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("s3: b/k:"), "{e}");
        let again = r.read(&mut [0; 10]).unwrap_err().to_string();
        assert_eq!(again, e, "sticky: a retried read never skips the chunk");
    }

    #[test]
    fn object_changed_mid_download_fails() {
        for if_match in [true, false] {
            let mut fake = Fake::new(4_000, |f, a, _| {
                if a == 2000 {
                    *lock(&f.etag) = "\"v2\"".into();
                }
                Act::Serve
            });
            fake.if_match = if_match;
            let fake = Arc::new(fake);
            let st = store(&fake, 2, 1000);
            let e = read_all(&st, 0).unwrap_err();
            assert!(
                e.ends_with("s3: b/k: object changed during the download"),
                "{e}"
            );
        }
    }

    #[test]
    fn offsets_and_small_objects() {
        let fake = Arc::new(Fake::new(10_000, serve));
        let st = store(&fake, 4, 1000);
        for off in [1, 1500, 9000, 9500, 9999] {
            assert!(
                read_all(&st, off).unwrap() == fake.data[off as usize..],
                "{off}"
            );
        }
        assert!(read_all(&st, 10_000).unwrap().is_empty(), "416 = end");
        let n = fake.starts().len();
        read_all(&st, 9500).unwrap();
        assert_eq!(
            fake.starts().len(),
            n + 1,
            "the rest fits one chunk: one GET"
        );
        // parallel = 1: plain GETs
        let plain = store(&fake, 1, 1000);
        assert!(read_all(&plain, 0).unwrap() == fake.data);
        assert!(read_all(&plain, 9990).unwrap() == fake.data[9990..]);
        // no cancel flag from the host: one plain GET too
        let n = fake.starts().len();
        let mut v = Vec::new();
        st.reader("b", "k", 0, None)
            .unwrap()
            .read_to_end(&mut v)
            .unwrap();
        assert!(v == fake.data && fake.starts().len() == n + 1);
    }

    #[test]
    fn servers_without_ranges_or_etags() {
        // no Range support: offset 0 = the whole body, offset > 0 = an error
        let mut f = Fake::new(3_000, serve);
        f.ranges = false;
        let fake = Arc::new(f);
        let st = store(&fake, 4, 1000);
        assert!(read_all(&st, 0).unwrap() == fake.data);
        assert!(read_all(&st, 5).unwrap_err().contains("ignored the Range"));
        // no ETag to pin the chunks to: one plain GET instead
        let mut f = Fake::new(3_000, serve);
        f.send_etag = false;
        let fake = Arc::new(f);
        let st = store(&fake, 4, 1000);
        assert!(read_all(&st, 100).unwrap() == fake.data[100..]);
        assert_eq!(fake.starts(), [100, 100]);
        // a weak ETag can't pin ranges, a 206 for another start is not ours: plain GET too
        for weak in [true, false] {
            let mut f = Fake::new(3_000, serve);
            f.wrong_start = !weak;
            if weak {
                *lock(&f.etag) = "W/\"v1\"".into();
            }
            let fake = Arc::new(f);
            let st = store(&fake, 4, 1000);
            let got = read_all(&st, 100).unwrap();
            assert!(
                got == fake.data[100..] && fake.starts() == [100, 100],
                "weak {weak}"
            );
        }
    }

    fn obj(st: &Arc<Store>) -> Obj {
        Obj {
            store: Arc::clone(st),
            bucket: "b".into(),
            key: "k".into(),
            etag: "\"v1\"".into(),
        }
    }

    fn plan(total: u64) -> Plan {
        Plan {
            start: 0,
            total,
            chunk: 1000,
        }
    }

    #[test]
    fn reorder_window_holds_at_most_n_chunks() {
        let fake = Arc::new(Fake::new(10_000, serve));
        let st = store(&fake, 3, 1000);
        let first = Box::new(Cursor::new(fake.data[..1000].to_vec()));
        let mut p = Parallel::start(obj(&st), plan(10_000), 3, first, never()).unwrap();
        let mut buf = vec![0; 1000];
        p.read_exact(&mut buf).unwrap(); // reader holds chunk 0; 1..=3 may be fetched
        let ready = |p: &Parallel| {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut s = lock(&p.sh.st);
            while s.done.len() < 3 && Instant::now() < deadline {
                s = p.sh.cv.wait_timeout(s, POLL).unwrap().0;
            }
            (s.next, s.done.len())
        };
        assert_eq!(ready(&p), (4, 3), "chunk 4 waits for the reader");
        p.read_exact(&mut buf).unwrap(); // reader on chunk 1: chunk 4 may go
        assert_eq!(ready(&p), (5, 3));
        let mut rest = Vec::new();
        p.read_to_end(&mut rest).unwrap();
        assert!(rest == fake.data[2000..]);
    }

    #[test]
    fn cancel_while_waiting_stops_and_drops_buffers() {
        let cancel = Arc::new(AtomicBool::new(false));
        let c = Arc::clone(&cancel);
        // chunk 1 is held back until the host cancels; chunk 4 is only claimed once the reader
        // waits for chunk 1 (window), and its request cancels: the cancel lands inside wait()
        let fake = Arc::new(Fake::new(6_000, move |_, a, _| {
            if a == 4000 {
                c.store(true, Relaxed);
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            while a == 1000 && !c.load(Relaxed) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            Act::Serve
        }));
        let st = store(&fake, 3, 1000);
        let first = Box::new(Cursor::new(fake.data[..1000].to_vec()));
        let c = Arc::clone(&cancel);
        let flag: Cancel = Box::new(move || c.load(Relaxed));
        let mut p = Parallel::start(obj(&st), plan(6_000), 3, first, flag).unwrap();
        let mut v = Vec::new();
        let e = p.read_to_end(&mut v).unwrap_err();
        assert_eq!((e.to_string().as_str(), v.len()), ("cancelled", 1000));
        let mut buf = [0; 10];
        assert!(p.sh.stop.load(Relaxed) && lock(&p.sh.st).done.is_empty());
        assert_eq!(p.read(&mut buf).unwrap_err().to_string(), "cancelled");
        // fetch: complete data wins over a late stop; an unfinished one is CANCELLED
        let got = obj(&st).fetch(0, 1000, &|| false);
        assert!(got.is_ok_and(|v| v[..] == fake.data[..1000]));
        let e = obj(&st).fetch(1000, 3000, &|| true).unwrap_err();
        assert_eq!(e.status, abi::CANCELLED);
    }

    /// Speed on a fake throttled per connection (16 KiB per ms each): plain vs parallel.
    /// `cargo test -p commander_s3 bench_parallel -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn bench_parallel_download() {
        let mut f = Fake::new(32 << 20, serve);
        f.throttle = Some(Duration::from_millis(1));
        let fake = Arc::new(f);
        for parallel in [1, 8] {
            let st = store(&fake, parallel, MIB);
            let t = Instant::now();
            assert!(read_all(&st, 0).unwrap() == fake.data);
            println!("parallel {parallel}: {:?}", t.elapsed());
        }
    }
}

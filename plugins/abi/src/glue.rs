//! Shared C-ABI glue for Rust vfs plugins (feature `glue`): implement [`Fs`], then
//! `commander_plugin_abi::export_vfs!(MyFs);`. All unsafe lives here: handle boxing, borrowed
//! `{ptr,len}` strings, entry writing, panic catching, per-thread `last_error`, cancel polling.
use crate::{self as abi, Entry, Handle, Job, Status, Str};
use std::cell::RefCell;
use std::io::Read;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

/// Status + detail text for `last_error` (never put secrets in `msg`).
#[derive(Debug)]
pub struct Error {
    pub status: Status,
    pub msg: String,
}

impl Error {
    pub fn new(status: Status, msg: impl Into<String>) -> Self {
        Self {
            status,
            msg: msg.into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// The read stream's job cancel flag (`true` = the host cancelled).
pub type Cancel = Box<dyn Fn() -> bool + Send>;

/// Listing / stat item (`name` empty for stat).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub name: String,
    /// `abi::KIND_*`.
    pub kind: u32,
    pub size: u64,
    /// Unix ns.
    pub mtime: Option<i64>,
    /// A link (`kind` = its target's): sent as `abi::ATTR_LINK`.
    pub link: bool,
}

impl Item {
    pub fn dir(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: abi::KIND_DIR,
            size: 0,
            mtime: None,
            link: false,
        }
    }

    fn entry(&self) -> Entry {
        Entry {
            name: Str::new(&self.name),
            kind: self.kind,
            file_size: self.size,
            mtime_ns: self.mtime.unwrap_or(abi::MTIME_UNKNOWN),
            attrs: if self.link { abi::ATTR_LINK } else { 0 },
            ..Entry::default()
        }
    }
}

/// Keep the plugin library that contains this code loaded until the process exits. Call it
/// before starting background threads: an unload would unmap code they still run. Windows:
/// `GetModuleHandleExW(FROM_ADDRESS | PIN)`; unix: `dlopen(self, RTLD_NODELETE)`. `false` =
/// could not pin.
pub fn pin_module() -> bool {
    let me = pin_module as *const () as *const core::ffi::c_void;
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetModuleHandleExW(flags: u32, name: *const u16, module: *mut Handle) -> i32;
        }
        const PIN: u32 = 0x1;
        const FROM_ADDRESS: u32 = 0x4;
        let mut h: Handle = core::ptr::null_mut();
        // SAFETY: FROM_ADDRESS takes any address inside a module; `h` is a valid out pointer.
        unsafe { GetModuleHandleExW(PIN | FROM_ADDRESS, me.cast(), &raw mut h) != 0 }
    }
    #[cfg(unix)]
    {
        use core::ffi::{c_char, c_int, c_void};
        #[repr(C)]
        struct DlInfo {
            fname: *const c_char,
            fbase: *mut c_void,
            sname: *const c_char,
            saddr: *mut c_void,
        }
        #[cfg_attr(all(target_os = "linux", target_env = "gnu"), link(name = "dl"))]
        unsafe extern "C" {
            fn dladdr(addr: *const c_void, info: *mut DlInfo) -> c_int;
            fn dlopen(file: *const c_char, mode: c_int) -> *mut c_void;
        }
        // RTLD_NOLOAD: only re-reference the already loaded library, never load another file.
        const RTLD_NOW: c_int = 2;
        #[cfg(target_vendor = "apple")]
        const RTLD_NODELETE: c_int = 0x80;
        #[cfg(target_vendor = "apple")]
        const RTLD_NOLOAD: c_int = 0x10;
        #[cfg(not(target_vendor = "apple"))]
        const RTLD_NODELETE: c_int = 0x1000;
        #[cfg(target_os = "freebsd")]
        const RTLD_NOLOAD: c_int = 0x2000;
        #[cfg(not(any(target_vendor = "apple", target_os = "freebsd")))]
        const RTLD_NOLOAD: c_int = 0x4; // glibc / musl
        let mut info = DlInfo {
            fname: core::ptr::null(),
            fbase: core::ptr::null_mut(),
            sname: core::ptr::null(),
            saddr: core::ptr::null_mut(),
        };
        // SAFETY: `info` is a valid out struct; `fname` (checked) is a NUL-terminated path
        // owned by the loader; the extra dlopen handle is deliberately never closed.
        unsafe {
            dladdr(me, &raw mut info) != 0
                && !info.fname.is_null()
                && !dlopen(info.fname, RTLD_NOW | RTLD_NODELETE | RTLD_NOLOAD).is_null()
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = me;
        false
    }
}

/// Unique temp name for an upload of `name` (`.<name>.<pid>-<n>.cmdr-part`): never one another
/// upload (this or another process) is writing. Create it exclusively and retry on a clash.
pub fn part_name(name: &str) -> String {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!(".{name}.{}-{n}.cmdr-part", std::process::id())
}

/// Tries per upload before giving up on finding a free [`part_name`].
pub const PART_TRIES: usize = 8;

/// Host-safe plain name (the host rejects `/`, `\`, `:`, NUL, `.`, `..`): skip others.
pub fn valid_name(n: &str) -> bool {
    // Control chars (CR/LF, NUL) could forge lines in logs, history or listings.
    !n.is_empty()
        && n != "."
        && n != ".."
        && !n.contains(['/', '\\', ':'])
        && !n.contains(char::is_control)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's days_from_civil).
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

/// A plugin filesystem. Paths are validated ('/'-separated, "" = root, no `.`/`..`/empty
/// segment). `threading = "concurrent"`: one value is shared by all host threads.
pub trait Fs: Send + Sync + Sized + 'static {
    type Error: Into<Error>;
    type Lister: Send;
    type Writer: Send;
    /// For the panic message.
    const NAME: &'static str;

    fn open(config: &str) -> std::result::Result<Self, Self::Error>;
    fn list(self: &Arc<Self>, dir: &str) -> std::result::Result<Self::Lister, Self::Error>;
    /// Up to `cap` items; empty = done.
    fn next_batch(
        l: &mut Self::Lister,
        cap: usize,
        cancelled: &dyn Fn() -> bool,
    ) -> std::result::Result<Vec<Item>, Self::Error>;
    fn stat(&self, path: &str) -> std::result::Result<Item, Self::Error>;
    fn reader(
        &self,
        path: &str,
        offset: u64,
    ) -> std::result::Result<Box<dyn Read + Send>, Self::Error>;
    /// `reader` for streams whose `read` may wait long (parallel downloads): poll `cancelled`
    /// while waiting and fail; the glue then reports CANCELLED. Default: `reader`.
    fn reader_job(
        &self,
        path: &str,
        offset: u64,
        cancelled: Cancel,
    ) -> std::result::Result<Box<dyn Read + Send>, Self::Error> {
        drop(cancelled);
        self.reader(path, offset)
    }
    fn writer(
        self: &Arc<Self>,
        path: &str,
        overwrite: bool,
        size_hint: u64,
    ) -> std::result::Result<Self::Writer, Self::Error>;
    fn write(w: &mut Self::Writer, data: &[u8]) -> std::result::Result<(), Self::Error>;
    /// Commit. Dropping a writer without `finish` must abort (nothing at the target).
    fn finish(w: Self::Writer) -> std::result::Result<(), Self::Error>;
    fn mkdir(&self, path: &str) -> std::result::Result<(), Self::Error>;
    fn remove_file(&self, path: &str) -> std::result::Result<(), Self::Error>;
    fn remove_dir(&self, path: &str) -> std::result::Result<(), Self::Error>;
    /// Never replaces an existing `to`.
    fn rename(
        &self,
        from: &str,
        to: &str,
        cancelled: &dyn Fn() -> bool,
    ) -> std::result::Result<(), Self::Error>;
    /// Public text form of `path` (C ABI `public_url`): pure, no I/O, any thread. `None` = the
    /// host's own path (default).
    fn public_url(&self, _path: &str) -> Option<String> {
        None
    }
}

thread_local! {
    static LAST: RefCell<String> = const { RefCell::new(String::new()) };
    /// Last `public_url` answer (valid until the next call on this thread).
    static URL: RefCell<String> = const { RefCell::new(String::new()) };
}

/// Runs `f`, mapping errors and panics to a status (+ `last_error` text).
fn guard<F: Fs>(f: impl FnOnce() -> Result<()>) -> Status {
    let (st, msg) = match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => return abi::OK,
        Ok(Err(e)) => (e.status, e.msg),
        Err(_) => (abi::INTERNAL, format!("{} plugin panicked", F::NAME)),
    };
    LAST.with(|l| *l.borrow_mut() = msg);
    st
}

/// Borrowed job pointer (valid per the ABI until the matching end/close).
#[derive(Clone, Copy)]
struct JobRef(*const Job);

// SAFETY: only reads the cancel byte, an AtomicBool on the host side; the host keeps the Job
// alive until the matching end/close/finish/abort, whichever thread makes that call.
unsafe impl Send for JobRef {}

impl JobRef {
    fn cancelled(self) -> bool {
        // SAFETY: host keeps the job (and its flag) alive while we may use it.
        !self.0.is_null() && unsafe { (*self.0).cancelled() }
    }

    fn check(self) -> Result<()> {
        match self.cancelled() {
            true => Err(Error::new(abi::CANCELLED, "cancelled")),
            false => Ok(()),
        }
    }
}

/// Valid relative path ("" = root): UTF-8, no empty / `.` / `..` segment.
unsafe fn path<'a>(s: Str) -> Result<&'a str> {
    // SAFETY: host passes a live {ptr,len} for the call.
    let s = unsafe { s.as_str() }.ok_or_else(|| Error::new(abi::INVALID, "path is not UTF-8"))?;
    if !s.is_empty() && s.split('/').any(|c| c.is_empty() || c == "." || c == "..") {
        return Err(Error::new(abi::INVALID, format!("bad path {s:?}")));
    }
    Ok(s)
}

unsafe fn out<T>(p: *mut T, v: T) -> Result<()> {
    if p.is_null() {
        return Err(Error::new(abi::INVALID, "NULL out pointer"));
    }
    // SAFETY: non-NULL out pointer from the host.
    unsafe { p.write(v) };
    Ok(())
}

/// The `T` behind a handle we boxed; NULL = INVALID.
unsafe fn handle<'a, T>(h: Handle) -> Result<&'a mut T> {
    match h.is_null() {
        true => Err(Error::new(abi::INVALID, "NULL handle")),
        // SAFETY: a non-NULL handle is a live Box<T> from us (host contract).
        false => Ok(unsafe { &mut *(h as *mut T) }),
    }
}

unsafe fn fs_of<'a, F>(h: Handle) -> Result<&'a Arc<F>> {
    // SAFETY: `h` is NULL or a live Box<Arc<F>> from `open`.
    unsafe { handle::<Arc<F>>(h) }.map(|a| &*a)
}

fn boxed<T>(v: T) -> Handle {
    Box::into_raw(Box::new(v)) as Handle
}

/// Frees a handle we boxed (NULL = no-op); a panicking Drop is swallowed, never unwinds.
unsafe fn free<T>(h: Handle) {
    if h.is_null() {
        return;
    }
    // SAFETY: a live Box<T> from us, freed once (host contract).
    let b = unsafe { Box::from_raw(h as *mut T) };
    let _ = catch_unwind(AssertUnwindSafe(move || drop(b)));
}

unsafe extern "C" fn open<F: Fs>(config: Str, fs_out: *mut Handle) -> Status {
    guard::<F>(|| {
        // SAFETY: borrowed for the call.
        let cfg = unsafe { config.as_str() }
            .ok_or_else(|| Error::new(abi::INVALID, "config is not UTF-8"))?;
        let fs = F::open(cfg).map_err(Into::into)?;
        // SAFETY: host out pointer.
        unsafe { out(fs_out, boxed(Arc::new(fs))) }
    })
}

unsafe extern "C" fn close<F: Fs>(fs: Handle) {
    // SAFETY: from `open`, closed once.
    unsafe { free::<Arc<F>>(fs) }
}

unsafe extern "C" fn last_error() -> Str {
    // Lives in the thread-local until the next failing call on this thread.
    LAST.with(|l| Str::new(l.borrow().as_str()))
}

struct ListIt<F: Fs> {
    lister: F::Lister,
    /// Batch handed out last; entry names point into it.
    cur: Vec<Item>,
    job: JobRef,
}

unsafe extern "C" fn list_begin<F: Fs>(
    fs: Handle,
    dir: Str,
    job: *const Job,
    it: *mut Handle,
) -> Status {
    guard::<F>(|| {
        let job = JobRef(job);
        job.check()?;
        // SAFETY: host contract for every arg.
        unsafe {
            let lister = fs_of::<F>(fs)?.list(path(dir)?).map_err(Into::into)?;
            out(
                it,
                boxed(ListIt::<F> {
                    lister,
                    cur: Vec::new(),
                    job,
                }),
            )
        }
    })
}

unsafe extern "C" fn list_next<F: Fs>(
    it: Handle,
    buf: *mut Entry,
    entry_size: usize,
    cap: usize,
    n: *mut usize,
) -> Status {
    guard::<F>(|| {
        if n.is_null() || (buf.is_null() && cap > 0) {
            return Err(Error::new(abi::INVALID, "NULL buffer"));
        }
        // SAFETY: `it` from list_begin; `buf` holds `cap` entries of `entry_size` bytes;
        // names point into `it.cur`, unchanged until the next call on `it`.
        unsafe {
            let it = handle::<ListIt<F>>(it)?;
            it.job.check()?;
            let job = it.job;
            let mut batch =
                F::next_batch(&mut it.lister, cap, &|| job.cancelled()).map_err(Into::into)?;
            batch.truncate(cap);
            it.cur = batch;
            for (i, item) in it.cur.iter().enumerate() {
                item.entry().write_to(buf, entry_size, i);
            }
            out(n, it.cur.len())
        }
    })
}

unsafe extern "C" fn list_end<F: Fs>(it: Handle) {
    // SAFETY: from list_begin, ended once.
    unsafe { free::<ListIt<F>>(it) }
}

unsafe extern "C" fn stat<F: Fs>(
    fs: Handle,
    p: Str,
    _job: *const Job,
    o: *mut Entry,
    entry_size: usize,
) -> Status {
    guard::<F>(|| {
        if o.is_null() {
            return Err(Error::new(abi::INVALID, "NULL out pointer"));
        }
        // SAFETY: host contract. Name is empty, so nothing borrowed outlives the call.
        unsafe {
            let item = fs_of::<F>(fs)?.stat(path(p)?).map_err(Into::into)?;
            Entry {
                name: Str::EMPTY,
                ..item.entry()
            }
            .write_to(o, entry_size, 0);
        }
        Ok(())
    })
}

struct Reader {
    body: Box<dyn Read + Send>,
    job: JobRef,
}

unsafe extern "C" fn read_open<F: Fs>(
    fs: Handle,
    p: Str,
    offset: u64,
    job: *const Job,
    rd: *mut Handle,
) -> Status {
    guard::<F>(|| {
        let job = JobRef(job);
        job.check()?;
        // SAFETY: host contract.
        unsafe {
            let body = fs_of::<F>(fs)?
                .reader_job(path(p)?, offset, Box::new(move || job.cancelled()))
                .map_err(Into::into)?;
            out(rd, boxed(Reader { body, job }))
        }
    })
}

unsafe extern "C" fn read<F: Fs>(rd: Handle, buf: *mut u8, cap: usize, n: *mut usize) -> Status {
    guard::<F>(|| {
        if cap == 0 {
            // SAFETY: host out pointer.
            return unsafe { out(n, 0) };
        }
        if buf.is_null() {
            return Err(Error::new(abi::INVALID, "NULL buffer"));
        }
        // SAFETY: `rd` from read_open; `buf` is non-NULL with `cap` writable bytes.
        unsafe {
            let r = handle::<Reader>(rd)?;
            r.job.check()?;
            let dst = std::slice::from_raw_parts_mut(buf, cap);
            // B61: a read failing because of the cancel is CANCELLED, never IO / Interrupted.
            let got = r.body.read(dst).map_err(|e| match r.job.cancelled() {
                true => Error::new(abi::CANCELLED, "cancelled"),
                false => Error::new(abi::IO, format!("{}: read: {e}", F::NAME)),
            })?;
            out(n, got)
        }
    })
}

unsafe extern "C" fn read_close(rd: Handle) {
    // SAFETY: from read_open, closed once.
    unsafe { free::<Reader>(rd) }
}

struct WriteIt<F: Fs> {
    w: F::Writer,
    job: JobRef,
}

unsafe extern "C" fn write_open<F: Fs>(
    fs: Handle,
    p: Str,
    flags: u32,
    size_hint: u64,
    job: *const Job,
    wr: *mut Handle,
) -> Status {
    guard::<F>(|| {
        let job = JobRef(job);
        job.check()?;
        // SAFETY: host contract.
        unsafe {
            let overwrite = flags & abi::WRITE_OVERWRITE != 0;
            let w = fs_of::<F>(fs)?
                .writer(path(p)?, overwrite, size_hint)
                .map_err(Into::into)?;
            out(wr, boxed(WriteIt::<F> { w, job }))
        }
    })
}

unsafe extern "C" fn write<F: Fs>(wr: Handle, buf: *const u8, len: usize) -> Status {
    guard::<F>(|| {
        if len > 0 && buf.is_null() {
            return Err(Error::new(abi::INVALID, "NULL buffer"));
        }
        // SAFETY: `wr` from write_open; `buf` has `len` readable bytes.
        unsafe {
            let w = handle::<WriteIt<F>>(wr)?;
            w.job.check()?;
            if len == 0 {
                return Ok(());
            }
            F::write(&mut w.w, std::slice::from_raw_parts(buf, len)).map_err(Into::into)
        }
    })
}

unsafe extern "C" fn write_finish<F: Fs>(wr: Handle) -> Status {
    if wr.is_null() {
        return guard::<F>(|| Err(Error::new(abi::INVALID, "NULL handle")));
    }
    // SAFETY: from write_open; finish frees it (an error drops it = abort).
    let w = unsafe { Box::from_raw(wr as *mut WriteIt<F>) };
    guard::<F>(move || {
        w.job.check()?;
        F::finish(w.w).map_err(Into::into)
    })
}

unsafe extern "C" fn write_abort<F: Fs>(wr: Handle) {
    // SAFETY: from write_open, freed once; the writer's Drop aborts.
    unsafe { free::<WriteIt<F>>(wr) }
}

unsafe extern "C" fn mkdir<F: Fs>(fs: Handle, p: Str, _job: *const Job) -> Status {
    // SAFETY: host contract.
    guard::<F>(|| unsafe { fs_of::<F>(fs)?.mkdir(path(p)?).map_err(Into::into) })
}

unsafe extern "C" fn remove_file<F: Fs>(fs: Handle, p: Str, _job: *const Job) -> Status {
    // SAFETY: host contract.
    guard::<F>(|| unsafe { fs_of::<F>(fs)?.remove_file(path(p)?).map_err(Into::into) })
}

unsafe extern "C" fn remove_dir<F: Fs>(fs: Handle, p: Str, _job: *const Job) -> Status {
    // SAFETY: host contract.
    guard::<F>(|| unsafe { fs_of::<F>(fs)?.remove_dir(path(p)?).map_err(Into::into) })
}

unsafe extern "C" fn rename<F: Fs>(fs: Handle, from: Str, to: Str, job: *const Job) -> Status {
    let job = JobRef(job);
    guard::<F>(|| {
        // SAFETY: host contract.
        unsafe { fs_of::<F>(fs)?.rename(path(from)?, path(to)?, &|| job.cancelled()) }
            .map_err(Into::into)
    })
}

unsafe extern "C" fn public_url<F: Fs>(fs: Handle, p: Str, o: *mut Str) -> Status {
    guard::<F>(|| {
        // SAFETY: host contract.
        let url = unsafe { fs_of::<F>(fs)?.public_url(path(p)?) }
            .filter(|u| !u.contains(char::is_control))
            .ok_or_else(|| Error::new(abi::UNSUPPORTED, "no public form"))?;
        URL.with(|u| {
            let mut u2 = u.borrow_mut();
            *u2 = url;
            // SAFETY: host out pointer; the text lives in the thread-local until the next call.
            unsafe { out(o, Str::new(u2.as_str())) }
        })
    })
}

/// The full vtable for `F` (every fn supported).
pub const fn vtable<F: Fs>() -> abi::Vfs {
    abi::Vfs {
        size: size_of::<abi::Vfs>() as u32,
        open: Some(open::<F>),
        close: Some(close::<F>),
        last_error: Some(last_error),
        list_begin: Some(list_begin::<F>),
        list_next: Some(list_next::<F>),
        list_end: Some(list_end::<F>),
        stat: Some(stat::<F>),
        read_open: Some(read_open::<F>),
        read: Some(read::<F>),
        read_close: Some(read_close),
        write_open: Some(write_open::<F>),
        write: Some(write::<F>),
        write_finish: Some(write_finish::<F>),
        write_abort: Some(write_abort::<F>),
        mkdir: Some(mkdir::<F>),
        remove_file: Some(remove_file::<F>),
        remove_dir: Some(remove_dir::<F>),
        rename: Some(rename::<F>),
        public_url: Some(public_url::<F>),
    }
}

/// `static`-able plugin struct (only immutable pointers to statics).
pub struct PluginRef(abi::Plugin);

// SAFETY: holds only a pointer to an immutable `static` vtable.
unsafe impl Sync for PluginRef {}

impl PluginRef {
    pub const fn new(vfs: &'static abi::Vfs) -> Self {
        Self(abi::Plugin {
            size: size_of::<abi::Plugin>() as u32,
            abi: abi::CMDR_ABI,
            vfs,
            viewer: core::ptr::null(),
            columns: core::ptr::null(),
            commands: core::ptr::null(),
        })
    }

    /// The `cmdr_plugin_entry` answer: NULL unless the host speaks our ABI.
    pub fn entry(&'static self, host_abi: u32) -> *const abi::Plugin {
        match host_abi == abi::CMDR_ABI {
            true => &self.0,
            false => core::ptr::null(),
        }
    }
}

/// Exports `cmdr_plugin_entry` for the [`Fs`] type `$t`.
#[macro_export]
macro_rules! export_vfs {
    ($t:ty) => {
        static CMDR_VFS: $crate::Vfs = $crate::glue::vtable::<$t>();
        static CMDR_PLUGIN: $crate::glue::PluginRef = $crate::glue::PluginRef::new(&CMDR_VFS);

        /// # Safety
        /// Called by the host per the C ABI.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cmdr_plugin_entry(
            host_abi: u32,
            _host: *const $crate::Host,
        ) -> *const $crate::Plugin {
            CMDR_PLUGIN.entry(host_abi)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;

    /// In-memory flat fs: files only, "boom" panics, "deny" is DENIED.
    #[derive(Default)]
    struct Mem(Mutex<BTreeMap<String, Vec<u8>>>);

    impl Mem {
        fn files(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Vec<u8>>> {
            self.0.lock().unwrap()
        }
        fn check(p: &str) -> Result<()> {
            match p {
                "boom" => panic!("boom"),
                "deny" => Err(Error::new(abi::DENIED, "denied")),
                _ => Ok(()),
            }
        }
    }

    struct W(Arc<Mem>, String, Vec<u8>);

    impl Drop for W {
        fn drop(&mut self) {
            if self.1 == "dropboom" {
                panic!("drop boom");
            }
        }
    }

    impl Fs for Mem {
        type Error = Error;
        type Lister = Vec<Item>;
        type Writer = W;
        const NAME: &'static str = "mem";

        fn open(config: &str) -> Result<Self> {
            match config {
                "bad" => Err(Error::new(abi::AUTH, "no")),
                _ => Ok(Mem::default()),
            }
        }
        fn list(self: &Arc<Self>, dir: &str) -> Result<Vec<Item>> {
            Self::check(dir)?;
            let files = self.files();
            Ok(files
                .iter()
                .map(|(n, d)| Item {
                    name: n.clone(),
                    kind: abi::KIND_FILE,
                    size: d.len() as u64,
                    mtime: Some(7),
                    link: false,
                })
                .collect())
        }
        fn next_batch(l: &mut Vec<Item>, cap: usize, c: &dyn Fn() -> bool) -> Result<Vec<Item>> {
            assert!(!c());
            Ok(l.drain(..cap.min(l.len())).collect())
        }
        fn stat(&self, p: &str) -> Result<Item> {
            Self::check(p)?;
            let size = self.files().get(p).map(Vec::len);
            let size = size.ok_or_else(|| Error::new(abi::NOT_FOUND, "nf"))?;
            Ok(Item {
                name: "ignored".into(),
                kind: abi::KIND_FILE,
                size: size as u64,
                mtime: None,
                link: false,
            })
        }
        fn reader(&self, p: &str, off: u64) -> Result<Box<dyn Read + Send>> {
            let d = self.files().get(p).cloned();
            let d = d.ok_or_else(|| Error::new(abi::NOT_FOUND, "nf"))?;
            Ok(Box::new(std::io::Cursor::new(d[off as usize..].to_vec())))
        }
        fn reader_job(&self, p: &str, off: u64, c: Cancel) -> Result<Box<dyn Read + Send>> {
            match p {
                "flip" => Ok(Box::new(Flip(c))),
                _ => self.reader(p, off),
            }
        }
        fn writer(self: &Arc<Self>, p: &str, overwrite: bool, _: u64) -> Result<W> {
            if !overwrite && self.files().contains_key(p) {
                return Err(Error::new(abi::EXISTS, "exists"));
            }
            Ok(W(Arc::clone(self), p.into(), Vec::new()))
        }
        fn write(w: &mut W, data: &[u8]) -> Result<()> {
            w.2.extend_from_slice(data);
            Ok(())
        }
        fn finish(mut w: W) -> Result<()> {
            let (k, d) = (std::mem::take(&mut w.1), std::mem::take(&mut w.2));
            w.0.files().insert(k, d);
            Ok(())
        }
        fn mkdir(&self, p: &str) -> Result<()> {
            Self::check(p)
        }
        fn remove_file(&self, p: &str) -> Result<()> {
            self.files()
                .remove(p)
                .map(drop)
                .ok_or_else(|| Error::new(abi::NOT_FOUND, "nf"))
        }
        fn remove_dir(&self, p: &str) -> Result<()> {
            Self::check(p)
        }
        fn rename(&self, from: &str, to: &str, _: &dyn Fn() -> bool) -> Result<()> {
            let mut f = self.files();
            let d = f
                .remove(from)
                .ok_or_else(|| Error::new(abi::NOT_FOUND, "nf"))?;
            f.insert(to.into(), d);
            Ok(())
        }
        fn public_url(&self, p: &str) -> Option<String> {
            match p {
                "pub" => Some("x://pub".into()),
                "ctl" => Some("x://a\nb".into()),
                _ => None,
            }
        }
    }

    /// Read stream that sees the cancel flag, then the host cancels during its `read`.
    struct Flip(Cancel);
    static FLIP: AtomicBool = AtomicBool::new(false);

    impl Read for Flip {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            let seen = (self.0)();
            FLIP.store(true, core::sync::atomic::Ordering::Relaxed);
            Err(std::io::Error::other(format!("seen {seen}")))
        }
    }

    #[test]
    fn cancel_during_a_read_is_cancelled_not_io() {
        // SAFETY: test drives the vtable exactly like the host.
        unsafe {
            let v = &*(*P.entry(abi::CMDR_ABI)).vfs;
            let mut fs: Handle = core::ptr::null_mut();
            assert_eq!(v.open.unwrap()(s("ok"), &mut fs), abi::OK);
            let job = Job {
                size: size_of::<Job>() as u32,
                cancel: (&raw const FLIP).cast(),
                ctx: core::ptr::null_mut(),
                progress: None,
            };
            let mut rd: Handle = core::ptr::null_mut();
            assert_eq!(
                v.read_open.unwrap()(fs, s("flip"), 0, &job, &mut rd),
                abi::OK
            );
            let (mut buf, mut n) = ([0u8; 4], 0usize);
            assert_eq!(
                v.read.unwrap()(rd, buf.as_mut_ptr(), 4, &mut n),
                abi::CANCELLED
            );
            assert_eq!(err(), "cancelled");
            v.read_close.unwrap()(rd);
            // Without a cancel the same failure is IO (no job: the flag reads false).
            FLIP.store(false, core::sync::atomic::Ordering::Relaxed);
            let none = core::ptr::null();
            assert_eq!(
                v.read_open.unwrap()(fs, s("flip"), 0, none, &mut rd),
                abi::OK
            );
            assert_eq!(v.read.unwrap()(rd, buf.as_mut_ptr(), 4, &mut n), abi::IO);
            assert_eq!(err(), "mem: read: seen false");
            v.read_close.unwrap()(rd);
            v.close.unwrap()(fs);
        }
    }

    static V: abi::Vfs = vtable::<Mem>();
    static P: PluginRef = PluginRef::new(&V);

    fn s(x: &str) -> Str {
        Str::new(x)
    }

    fn err() -> String {
        // SAFETY: thread-local text, valid until the next failing call.
        unsafe { last_error().as_str().unwrap().to_owned() }
    }

    #[test]
    fn pins_and_temp_names() {
        // Unix: a PIE test binary can't be dlopen'ed (dladdr names argv[0]); only no crash.
        let pinned = pin_module();
        #[cfg(windows)]
        assert!(pinned, "the test binary's own module pins");
        let _ = pinned;
        let (a, b) = (part_name("f.txt"), part_name("f.txt"));
        assert!(a.starts_with(".f.txt.") && a.ends_with(".cmdr-part") && a != b);
        assert!(valid_name(&a));
        let it = Item {
            link: true,
            ..Item::dir("l")
        };
        assert_eq!(it.entry().attrs, abi::ATTR_LINK);
        assert_eq!(Item::dir("d").entry().attrs, 0);
    }

    #[test]
    fn full_roundtrip_through_the_vtable() {
        assert!(P.entry(abi::CMDR_ABI + 1).is_null());
        // SAFETY: test drives the vtable exactly like the host.
        unsafe {
            let p = &*P.entry(abi::CMDR_ABI);
            let v = &*p.vfs;
            let mut fs: Handle = core::ptr::null_mut();
            assert_eq!(v.open.unwrap()(s("bad"), &mut fs), abi::AUTH);
            assert_eq!(err(), "no");
            assert_eq!(
                v.open.unwrap()(s("ok"), core::ptr::null_mut()),
                abi::INVALID
            );
            assert_eq!(v.open.unwrap()(s("ok"), &mut fs), abi::OK);

            // write two files (second aborted, then a refused overwrite)
            let mut wr: Handle = core::ptr::null_mut();
            let none = core::ptr::null();
            assert_eq!(
                v.write_open.unwrap()(fs, s("a"), 0, 0, none, &mut wr),
                abi::OK
            );
            assert_eq!(v.write.unwrap()(wr, b"hello".as_ptr(), 5), abi::OK);
            assert_eq!(v.write.unwrap()(wr, core::ptr::null(), 0), abi::OK);
            assert_eq!(v.write.unwrap()(wr, core::ptr::null(), 3), abi::INVALID);
            assert_eq!(v.write_finish.unwrap()(wr), abi::OK);
            assert_eq!(
                v.write_open.unwrap()(fs, s("b"), 0, 0, none, &mut wr),
                abi::OK
            );
            v.write_abort.unwrap()(wr);
            assert_eq!(
                v.write_open.unwrap()(fs, s("a"), 0, 0, none, &mut wr),
                abi::EXISTS
            );
            let flag = abi::WRITE_OVERWRITE;
            assert_eq!(
                v.write_open.unwrap()(fs, s("a"), flag, 0, none, &mut wr),
                abi::OK
            );
            assert_eq!(v.write.unwrap()(wr, b"hello!".as_ptr(), 6), abi::OK);
            assert_eq!(v.write_finish.unwrap()(wr), abi::OK);

            // stat
            let mut e = Entry::default();
            let es = size_of::<Entry>();
            assert_eq!(v.stat.unwrap()(fs, s("a"), none, &mut e, es), abi::OK);
            assert_eq!(
                (e.file_size, e.name.len, e.mtime_ns),
                (6, 0, abi::MTIME_UNKNOWN)
            );
            assert_eq!(
                v.stat.unwrap()(fs, s("b"), none, &mut e, es),
                abi::NOT_FOUND
            );
            assert_eq!(
                v.stat.unwrap()(fs, s("a"), none, core::ptr::null_mut(), es),
                abi::INVALID
            );
            assert_eq!(
                v.stat.unwrap()(fs, s("x/../a"), none, &mut e, es),
                abi::INVALID
            );
            assert_eq!(
                v.stat.unwrap()(fs, s("a//b"), none, &mut e, es),
                abi::INVALID
            );
            let bad = Str {
                ptr: [0xffu8].as_ptr(),
                len: 1,
            };
            assert_eq!(v.stat.unwrap()(fs, bad, none, &mut e, es), abi::INVALID);
            assert_eq!(
                v.stat.unwrap()(fs, s("boom"), none, &mut e, es),
                abi::INTERNAL
            );
            assert_eq!(err(), "mem plugin panicked");

            // read with offset
            let mut rd: Handle = core::ptr::null_mut();
            assert_eq!(v.read_open.unwrap()(fs, s("a"), 1, none, &mut rd), abi::OK);
            let (mut buf, mut n) = ([0u8; 16], 0usize);
            assert_eq!(v.read.unwrap()(rd, buf.as_mut_ptr(), 0, &mut n), abi::OK);
            assert_eq!(n, 0);
            assert_eq!(
                v.read.unwrap()(rd, core::ptr::null_mut(), 4, &mut n),
                abi::INVALID
            );
            assert_eq!(v.read.unwrap()(rd, buf.as_mut_ptr(), 16, &mut n), abi::OK);
            assert_eq!(&buf[..n], b"ello!");
            v.read_close.unwrap()(rd);
            assert_eq!(
                v.read_open.unwrap()(fs, s("zz"), 0, none, &mut rd),
                abi::NOT_FOUND
            );

            // list in batches of 1 with a live (uncancelled) job
            let cancel = AtomicBool::new(false);
            let job = Job {
                size: size_of::<Job>() as u32,
                cancel: (&raw const cancel).cast(),
                ctx: core::ptr::null_mut(),
                progress: None,
            };
            let mut it: Handle = core::ptr::null_mut();
            assert_eq!(v.list_begin.unwrap()(fs, s(""), &job, &mut it), abi::OK);
            let mut ents = [Entry::default(); 2];
            assert_eq!(
                v.list_next.unwrap()(it, ents.as_mut_ptr(), es, 1, &mut n),
                abi::OK
            );
            assert_eq!(
                (n, ents[0].name.as_str(), ents[0].mtime_ns),
                (1, Some("a"), 7)
            );
            assert_eq!(
                v.list_next.unwrap()(it, core::ptr::null_mut(), es, 1, &mut n),
                abi::INVALID
            );
            assert_eq!(
                v.list_next.unwrap()(it, ents.as_mut_ptr(), es, 2, &mut n),
                abi::OK
            );
            assert_eq!(n, 0);
            cancel.store(true, core::sync::atomic::Ordering::Relaxed);
            assert_eq!(
                v.list_next.unwrap()(it, ents.as_mut_ptr(), es, 2, &mut n),
                abi::CANCELLED
            );
            v.list_end.unwrap()(it);
            assert_eq!(
                v.list_begin.unwrap()(fs, s(""), &job, &mut it),
                abi::CANCELLED
            );
            assert_eq!(
                v.list_begin.unwrap()(fs, s("deny"), none, &mut it),
                abi::DENIED
            );
            assert_eq!(
                v.read_open.unwrap()(fs, s("a"), 0, &job, &mut rd),
                abi::CANCELLED
            );
            assert_eq!(
                v.write_open.unwrap()(fs, s("q"), 0, 0, &job, &mut wr),
                abi::CANCELLED
            );

            // public_url: plugin text, or UNSUPPORTED (none / control chars / bad path)
            let mut url = Str::EMPTY;
            let pu = v.public_url.unwrap();
            assert_eq!(pu(fs, s("pub"), &mut url), abi::OK);
            assert_eq!(url.as_str(), Some("x://pub"));
            for p in ["a", "ctl"] {
                assert_eq!(pu(fs, s(p), &mut url), abi::UNSUPPORTED, "{p}");
            }
            assert_eq!(pu(fs, s("a/../b"), &mut url), abi::INVALID);
            assert_eq!(pu(fs, s("pub"), core::ptr::null_mut()), abi::INVALID);

            // path ops
            assert_eq!(v.mkdir.unwrap()(fs, s("d"), none), abi::OK);
            assert_eq!(v.remove_dir.unwrap()(fs, s("deny"), none), abi::DENIED);
            assert_eq!(v.rename.unwrap()(fs, s("a"), s("c"), none), abi::OK);
            assert_eq!(v.remove_file.unwrap()(fs, s("a"), none), abi::NOT_FOUND);
            assert_eq!(v.remove_file.unwrap()(fs, s("c"), none), abi::OK);
            // NULL handles: INVALID or no-op, never a crash; a panicking Drop never unwinds.
            let nul: Handle = core::ptr::null_mut();
            assert_eq!(v.stat.unwrap()(nul, s("a"), none, &mut e, es), abi::INVALID);
            assert_eq!(
                v.list_begin.unwrap()(nul, s(""), none, &mut it),
                abi::INVALID
            );
            assert_eq!(
                v.list_next.unwrap()(nul, ents.as_mut_ptr(), es, 1, &mut n),
                abi::INVALID
            );
            assert_eq!(
                v.read.unwrap()(nul, buf.as_mut_ptr(), 4, &mut n),
                abi::INVALID
            );
            assert_eq!(v.write.unwrap()(nul, b"x".as_ptr(), 1), abi::INVALID);
            assert_eq!(v.write_finish.unwrap()(nul), abi::INVALID);
            assert_eq!(v.mkdir.unwrap()(nul, s("d"), none), abi::INVALID);
            assert_eq!(v.remove_file.unwrap()(nul, s("d"), none), abi::INVALID);
            assert_eq!(v.remove_dir.unwrap()(nul, s("d"), none), abi::INVALID);
            assert_eq!(v.rename.unwrap()(nul, s("a"), s("b"), none), abi::INVALID);
            assert_eq!(pu(nul, s("pub"), &mut url), abi::INVALID);
            assert_eq!(
                v.read_open.unwrap()(nul, s("a"), 0, none, &mut rd),
                abi::INVALID
            );
            assert_eq!(
                v.write_open.unwrap()(nul, s("a"), 0, 0, none, &mut wr),
                abi::INVALID
            );
            v.close.unwrap()(nul);
            v.list_end.unwrap()(nul);
            v.read_close.unwrap()(nul);
            v.write_abort.unwrap()(nul);
            assert_eq!(v.list_begin.unwrap()(fs, s(""), none, &mut it), abi::OK);
            assert_eq!(
                v.list_next.unwrap()(it, ents.as_mut_ptr(), es, 1, core::ptr::null_mut()),
                abi::INVALID
            );
            v.list_end.unwrap()(it);
            assert_eq!(
                v.write_open.unwrap()(fs, s("dropboom"), 0, 0, none, &mut wr),
                abi::OK
            );
            v.write_abort.unwrap()(wr);
            v.close.unwrap()(fs);
        }
    }
}

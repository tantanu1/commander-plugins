//! `#[repr(C)]` mirror of `sdk/include/commander_plugin.h` (ABI v1). Shared by the host
//! (commander_core) and Rust plugins, so the types exist once. Rules live in the header.
#![cfg_attr(not(feature = "stage"), no_std)]

extern crate alloc;

pub mod archive_url;
pub mod auth;
pub mod ftp_mode;
#[cfg(feature = "glue")]
pub mod glue;
pub mod names;
#[cfg(feature = "stage")]
pub mod stage;
#[cfg(feature = "glue")]
pub mod url;

use core::ffi::c_void;
use core::mem::{offset_of, size_of};

pub const CMDR_ABI: u32 = 1;

/// Status code. Never a Rust enum on the wire (an out-of-range enum is UB).
pub type Status = i32;
pub const OK: Status = 0;
pub const NOT_FOUND: Status = 1;
pub const DENIED: Status = 2;
pub const EXISTS: Status = 3;
pub const IO: Status = 4;
pub const CANCELLED: Status = 5;
pub const UNSUPPORTED: Status = 6;
pub const INVALID: Status = 7;
pub const INTERNAL: Status = 8;
pub const AUTH: Status = 9;
pub const NOT_EMPTY: Status = 10;
/// Credentials expired / need a login; detail = [`auth::Expired::detail`]. Older hosts see
/// an unknown status (= INTERNAL error), so it is backward compatible.
pub const AUTH_EXPIRED: Status = 11;
/// A key file needs its passphrase; detail = [`auth::Passphrase::detail`]. The host asks the user
/// and reopens with the passphrase as the `open` secret (`archive_url::SECRET_SEP`). Older
/// hosts see an unknown status (= INTERNAL error with the message), so it is backward compatible.
pub const NEED_PASSPHRASE: Status = 12;

pub const KIND_FILE: u32 = 0;
pub const KIND_DIR: u32 = 1;
pub const KIND_SYMLINK: u32 = 2;

/// `Entry::attrs` bit: a link (`kind` = its target's). The host never recurses through it.
pub const ATTR_LINK: u32 = 1;

pub const WRITE_OVERWRITE: u32 = 1;

pub const LOG_ERROR: i32 = 0;
pub const LOG_WARN: i32 = 1;
pub const LOG_INFO: i32 = 2;
pub const LOG_DEBUG: i32 = 3;

/// `cmdr_entry.mtime_ns` when unknown.
pub const MTIME_UNKNOWN: i64 = i64::MIN;

/// Name of the one exported entry symbol.
pub const ENTRY_SYMBOL: &[u8] = b"cmdr_plugin_entry";

/// Opaque handle (fs, iterator, reader, writer).
pub type Handle = *mut c_void;

/// UTF-8 `{ptr,len}`, not NUL-terminated.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Str {
    pub ptr: *const u8,
    pub len: usize,
}

impl Str {
    pub const EMPTY: Str = Str {
        ptr: core::ptr::null(),
        len: 0,
    };

    /// Borrows `s`; valid while `s` is.
    pub const fn new(s: &str) -> Self {
        Self {
            ptr: s.as_ptr(),
            len: s.len(),
        }
    }

    /// Raw bytes (empty for a NULL ptr).
    ///
    /// # Safety
    /// `ptr` must be NULL or point at `len` readable bytes that outlive `'a`.
    pub unsafe fn bytes<'a>(self) -> &'a [u8] {
        match self.ptr.is_null() || self.len == 0 {
            true => &[],
            // SAFETY: caller guarantees ptr/len describe live memory.
            false => unsafe { core::slice::from_raw_parts(self.ptr, self.len) },
        }
    }

    /// `None` if not UTF-8.
    ///
    /// # Safety
    /// Same as [`Str::bytes`].
    pub unsafe fn as_str<'a>(self) -> Option<&'a str> {
        // SAFETY: forwarded caller contract.
        core::str::from_utf8(unsafe { self.bytes() }).ok()
    }
}

/// Extensible: the caller passes its `entry_size` (array stride); the plugin writes
/// `min(size_of::<Entry>(), entry_size)` bytes per entry and sets `size` to that.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Entry {
    /// Bytes of this entry the plugin filled.
    pub size: u32,
    pub kind: u32,
    pub name: Str,
    pub file_size: u64,
    pub mtime_ns: i64,
    pub attrs: u32,
    pub reserved: u32,
}

impl Default for Entry {
    fn default() -> Self {
        Self {
            size: size_of::<Entry>() as u32,
            kind: KIND_FILE,
            name: Str::EMPTY,
            file_size: 0,
            mtime_ns: MTIME_UNKNOWN,
            attrs: 0,
            reserved: 0,
        }
    }
}

/// Smallest entry a v1 host accepts (every field before `attrs`).
pub const ENTRY_MIN: usize = offset_of!(Entry, attrs);

impl Entry {
    /// Plugin side: store `e` as element `i` of the caller's array with stride `entry_size`,
    /// writing only what both sides know and recording that in `size`.
    ///
    /// # Safety
    /// `buf` has room for `i + 1` elements of `entry_size` bytes.
    pub unsafe fn write_to(mut self, buf: *mut Entry, entry_size: usize, i: usize) {
        let n = entry_size.min(size_of::<Entry>());
        self.size = n as u32;
        // SAFETY: caller guarantees the room; byte copy has no alignment needs.
        unsafe {
            let dst = buf.cast::<u8>().add(i * entry_size);
            core::ptr::copy_nonoverlapping((&raw const self).cast::<u8>(), dst, n);
        }
    }
}

pub type ProgressFn = unsafe extern "C" fn(ctx: *mut c_void, done: u64, total: u64);

#[repr(C)]
#[derive(Debug)]
pub struct Job {
    pub size: u32,
    /// NULL or a byte the host sets nonzero on cancel (an `AtomicBool` on the host side).
    pub cancel: *const u8,
    pub ctx: *mut c_void,
    pub progress: Option<ProgressFn>,
}

impl Job {
    /// Cancel flag set? Safe for a NULL `cancel`.
    ///
    /// # Safety
    /// `self.cancel` must be NULL or point at a live byte.
    pub unsafe fn cancelled(&self) -> bool {
        // SAFETY: the host's flag is an AtomicBool (same layout as u8); caller keeps it alive.
        !self.cancel.is_null()
            && unsafe { &*(self.cancel as *const core::sync::atomic::AtomicBool) }
                .load(core::sync::atomic::Ordering::Relaxed)
    }
}

pub type LogFn = unsafe extern "C" fn(ctx: *mut c_void, level: i32, msg: Str);

#[repr(C)]
#[derive(Debug)]
pub struct Host {
    pub size: u32,
    pub abi: u32,
    pub ctx: *mut c_void,
    pub log: Option<LogFn>,
}

pub type OpenFn = unsafe extern "C" fn(config: Str, fs_out: *mut Handle) -> Status;
pub type CloseFn = unsafe extern "C" fn(fs: Handle);
pub type LastErrorFn = unsafe extern "C" fn() -> Str;
pub type ListBeginFn =
    unsafe extern "C" fn(fs: Handle, dir: Str, job: *const Job, it_out: *mut Handle) -> Status;
pub type ListNextFn = unsafe extern "C" fn(
    it: Handle,
    buf: *mut Entry,
    entry_size: usize,
    cap: usize,
    n: *mut usize,
) -> Status;
pub type EndFn = unsafe extern "C" fn(h: Handle);
pub type StatFn = unsafe extern "C" fn(
    fs: Handle,
    path: Str,
    job: *const Job,
    out: *mut Entry,
    entry_size: usize,
) -> Status;
pub type ReadOpenFn = unsafe extern "C" fn(
    fs: Handle,
    path: Str,
    offset: u64,
    job: *const Job,
    rd_out: *mut Handle,
) -> Status;
pub type ReadFn =
    unsafe extern "C" fn(rd: Handle, buf: *mut u8, cap: usize, n: *mut usize) -> Status;
pub type WriteOpenFn = unsafe extern "C" fn(
    fs: Handle,
    path: Str,
    flags: u32,
    size_hint: u64,
    job: *const Job,
    wr_out: *mut Handle,
) -> Status;
pub type WriteFn = unsafe extern "C" fn(wr: Handle, buf: *const u8, len: usize) -> Status;
pub type FinishFn = unsafe extern "C" fn(wr: Handle) -> Status;
pub type PathFn = unsafe extern "C" fn(fs: Handle, path: Str, job: *const Job) -> Status;
pub type RenameFn = unsafe extern "C" fn(fs: Handle, from: Str, to: Str, job: *const Job) -> Status;
/// Optional, appended: see `public_url` in the header (pure, any thread, no serial lock).
pub type PublicUrlFn = unsafe extern "C" fn(fs: Handle, path: Str, out: *mut Str) -> Status;

/// VFS vtable. `None` = unsupported. Append-only.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Vfs {
    pub size: u32,
    pub open: Option<OpenFn>,
    pub close: Option<CloseFn>,
    pub last_error: Option<LastErrorFn>,
    pub list_begin: Option<ListBeginFn>,
    pub list_next: Option<ListNextFn>,
    pub list_end: Option<EndFn>,
    pub stat: Option<StatFn>,
    pub read_open: Option<ReadOpenFn>,
    pub read: Option<ReadFn>,
    pub read_close: Option<EndFn>,
    pub write_open: Option<WriteOpenFn>,
    pub write: Option<WriteFn>,
    pub write_finish: Option<FinishFn>,
    pub write_abort: Option<EndFn>,
    pub mkdir: Option<PathFn>,
    pub remove_file: Option<PathFn>,
    pub remove_dir: Option<PathFn>,
    pub rename: Option<RenameFn>,
    pub public_url: Option<PublicUrlFn>,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Plugin {
    pub size: u32,
    pub abi: u32,
    pub vfs: *const Vfs,
    pub viewer: *const c_void,
    pub columns: *const c_void,
    pub commands: *const c_void,
}

impl Default for Plugin {
    fn default() -> Self {
        Self {
            size: 0,
            abi: 0,
            vfs: core::ptr::null(),
            viewer: core::ptr::null(),
            columns: core::ptr::null(),
            commands: core::ptr::null(),
        }
    }
}

pub type EntryFn = unsafe extern "C" fn(host_abi: u32, host: *const Host) -> *const Plugin;

// Layout = the C header (64-bit targets; 32-bit follows the same C rules).
const P: usize = size_of::<usize>();
const _: () = {
    assert!(size_of::<Str>() == 2 * P);
    assert!(offset_of!(Entry, kind) == 4);
    assert!(offset_of!(Entry, name) == 8);
    assert!(offset_of!(Entry, file_size) == 8 + 2 * P);
    assert!(offset_of!(Entry, attrs) == 24 + 2 * P);
    assert!(size_of::<Entry>() == 32 + 2 * P);
    assert!(offset_of!(Job, cancel) == P);
    assert!(size_of::<Job>() == 4 * P);
    assert!(offset_of!(Host, ctx) == 8);
    assert!(size_of::<Host>() == 8 + 2 * P);
    assert!(offset_of!(Vfs, open) == P);
    assert!(offset_of!(Vfs, rename) == 18 * P);
    assert!(offset_of!(Vfs, public_url) == 19 * P);
    assert!(size_of::<Vfs>() == 20 * P);
    assert!(offset_of!(Plugin, vfs) == 8);
    assert!(size_of::<Plugin>() == 8 + 4 * P);
    assert!(size_of::<Option<OpenFn>>() == P);
};

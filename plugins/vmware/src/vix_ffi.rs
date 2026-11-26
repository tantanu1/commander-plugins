//! Thin VIX FFI shim (vix.h of the VMware VIX SDK). The library is loaded at run time from the
//! user's install and never unloaded (VIX keeps threads). Each `Vix` lives on its session's
//! worker thread; every job is waited for (`VixJob_Wait`) and released. No callbacks.
use crate::backend::Backend;
use crate::discover::Vm;
use crate::vix::{c_path, c_str, error, item, secret_c};
use commander_plugin_abi::glue::{Error, Item, Result};
use commander_plugin_abi::{self as abi};
use libloading::Library;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::Mutex;

type H = c_int;
type VixError = u64;
type Cb = *const c_void; // VixEventProc*: always NULL (we wait)

const NONE: c_int = 0;
const INVALID_HANDLE: H = 0;
const API_VERSION: c_int = -1;
const JOB_RESULT_HANDLE: c_int = 3010;
const ITEM_NAME: c_int = 3035;
const FILE_FLAGS: c_int = 3054;
const VM_VARIABLE_STRING: c_int = 3056;
const FILE_SIZE: c_int = 3061;
const FILE_MOD_TIME: c_int = 3062;
const VM_GUEST_VARIABLE: c_int = 1;
/// `VIX_PROPERTY_VM_ENCRYPTION_PASSWORD` (vix.h).
const VM_ENCRYPTION_PASSWORD: c_int = 7001;
const VMOPEN_NORMAL: c_int = 0;

type Job1 = unsafe extern "C" fn(H, *const c_char, Cb, *mut c_void) -> H;
type CopyFn = unsafe extern "C" fn(H, *const c_char, *const c_char, c_int, H, Cb, *mut c_void) -> H;

struct Api {
    host_connect: unsafe extern "C" fn(
        c_int,
        c_int,
        *const c_char,
        c_int,
        *const c_char,
        *const c_char,
        c_int,
        H,
        Cb,
        *mut c_void,
    ) -> H,
    host_disconnect: unsafe extern "C" fn(H),
    open_vm: unsafe extern "C" fn(H, *const c_char, c_int, H, Cb, *mut c_void) -> H,
    alloc_props: unsafe extern "C" fn(H, *mut H, c_int, ...) -> VixError,
    login: unsafe extern "C" fn(H, *const c_char, *const c_char, c_int, Cb, *mut c_void) -> H,
    list_dir: unsafe extern "C" fn(H, *const c_char, c_int, Cb, *mut c_void) -> H,
    file_info: Job1,
    copy_to_host: CopyFn,
    copy_to_guest: CopyFn,
    mkdir: unsafe extern "C" fn(H, *const c_char, H, Cb, *mut c_void) -> H,
    del_file: Job1,
    del_dir: unsafe extern "C" fn(H, *const c_char, c_int, Cb, *mut c_void) -> H,
    rename: CopyFn,
    read_var: unsafe extern "C" fn(H, c_int, *const c_char, c_int, Cb, *mut c_void) -> H,
    wait: unsafe extern "C" fn(H, c_int, ...) -> VixError,
    num_props: unsafe extern "C" fn(H, c_int) -> c_int,
    nth_props: unsafe extern "C" fn(H, c_int, c_int, ...) -> VixError,
    release: unsafe extern "C" fn(H),
    free: unsafe extern "C" fn(*mut c_void),
    error_text: unsafe extern "C" fn(VixError, *const c_char) -> *const c_char,
    _lib: Library,
}

/// Load `path` and resolve every function we use.
///
/// # Safety
/// Runs the library's initialisers: `path` must be a VIX library.
unsafe fn load(path: &Path) -> std::result::Result<Api, libloading::Error> {
    // Its own folder first: the 64-bit vix.dll sits next to the OpenSSL / libxml2 it needs.
    #[cfg(windows)]
    // SAFETY: the caller vouches `path` is a VIX library (its initialisers run here).
    let lib: Library = unsafe {
        use libloading::os::windows;
        windows::Library::load_with_flags(path, windows::LOAD_WITH_ALTERED_SEARCH_PATH)?.into()
    };
    #[cfg(not(windows))]
    // SAFETY: as above.
    let lib = unsafe { Library::new(path)? };
    macro_rules! sym {
        ($n:literal) => {
            // SAFETY: the type is the vix.h prototype of this export.
            unsafe { *lib.get(concat!($n, "\0").as_bytes())? }
        };
    }
    Ok(Api {
        host_connect: sym!("VixHost_Connect"),
        host_disconnect: sym!("VixHost_Disconnect"),
        open_vm: sym!("VixHost_OpenVM"),
        alloc_props: sym!("VixPropertyList_AllocPropertyList"),
        login: sym!("VixVM_LoginInGuest"),
        list_dir: sym!("VixVM_ListDirectoryInGuest"),
        file_info: sym!("VixVM_GetFileInfoInGuest"),
        copy_to_host: sym!("VixVM_CopyFileFromGuestToHost"),
        copy_to_guest: sym!("VixVM_CopyFileFromHostToGuest"),
        mkdir: sym!("VixVM_CreateDirectoryInGuest"),
        del_file: sym!("VixVM_DeleteFileInGuest"),
        del_dir: sym!("VixVM_DeleteDirectoryInGuest"),
        rename: sym!("VixVM_RenameFileInGuest"),
        read_var: sym!("VixVM_ReadVariable"),
        wait: sym!("VixJob_Wait"),
        num_props: sym!("VixJob_GetNumProperties"),
        nth_props: sym!("VixJob_GetNthProperties"),
        release: sym!("Vix_ReleaseHandle"),
        free: sym!("Vix_FreeBuffer"),
        error_text: sym!("Vix_GetErrorText"),
        _lib: lib,
    })
}

/// Loaded libraries, never unloaded.
static APIS: Mutex<Vec<(PathBuf, &'static Api)>> = Mutex::new(Vec::new());

fn api(path: &Path) -> std::result::Result<&'static Api, String> {
    let mut v = APIS.lock().unwrap_or_else(|p| p.into_inner()); // plain list
    if let Some((_, a)) = v.iter().find(|(p, _)| p == path) {
        return Ok(a);
    }
    // SAFETY: a VIX library from the user's VMware install or vmware.toml.
    let a: &'static Api = Box::leak(Box::new(unsafe { load(path) }.map_err(|e| e.to_string())?));
    v.push((path.to_path_buf(), a));
    Ok(a)
}

pub struct Vix {
    api: &'static Api,
    host: H,
    vm: H,
    kind: String,
}

/// [`crate::vix::open_with`]'s per-library step: load, connect, open the .vmx (with the VM
/// encryption password `vm_password` for an encrypted VM).
pub fn open(
    lib: &Path,
    vm: &Vm,
    provider: i32,
    vm_password: Option<&str>,
) -> Result<Box<dyn Backend>> {
    let api = api(lib).map_err(|e| Error::new(abi::IO, e))?;
    let vmx = c_path(&vm.vmx)?;
    let pw = vm_password.map(secret_c).transpose()?;
    // SAFETY: vix.h calls with valid C strings / NULL; jobs and the property list are waited
    // for and released once.
    unsafe {
        let job = (api.host_connect)(
            API_VERSION,
            provider,
            null(),
            0,
            null(),
            null(),
            0,
            INVALID_HANDLE,
            null(),
            null_mut(),
        );
        let host = wait_handle(api, job)?;
        let mut props = INVALID_HANDLE;
        if let Some(pw) = &pw {
            // The list copies the string; ours is wiped on drop.
            let e = (api.alloc_props)(
                host,
                &mut props as *mut H,
                VM_ENCRYPTION_PASSWORD,
                pw.as_ptr().cast::<c_char>(),
                NONE,
            );
            if let Err(e) = check(api, e, "VM password", false) {
                (api.host_disconnect)(host);
                return Err(e);
            }
        }
        let job = (api.open_vm)(host, vmx.as_ptr(), VMOPEN_NORMAL, props, null(), null_mut());
        let opened = wait_handle(api, job);
        if props != INVALID_HANDLE {
            (api.release)(props);
        }
        match opened {
            Ok(h) => Ok(Box::new(Vix {
                api,
                host,
                vm: h,
                kind: format!("VIX ({})", lib.display()),
            })),
            Err(e) => {
                (api.host_disconnect)(host);
                Err(e)
            }
        }
    }
}

fn text(api: &Api, e: VixError) -> String {
    // SAFETY: returns a static string (or NULL); never freed.
    let p = unsafe { (api.error_text)(e, null()) };
    match p.is_null() {
        true => "error".into(),
        // SAFETY: non-NULL NUL-terminated static text.
        false => unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned(),
    }
}

fn check(api: &Api, e: VixError, what: &str, login: bool) -> Result<()> {
    match e {
        0 => Ok(()),
        e => Err(error(e, &text(api, e), what, login)),
    }
}

/// Waits for a job that yields a handle (connect, open).
unsafe fn wait_handle(api: &Api, job: H) -> Result<H> {
    let mut h: H = INVALID_HANDLE;
    // SAFETY: property list terminated by NONE; out pointer matches the property type.
    let e = unsafe { (api.wait)(job, JOB_RESULT_HANDLE, &mut h as *mut H, NONE) };
    // SAFETY: `job` is a live job handle, released exactly once here.
    unsafe { (api.release)(job) };
    check(api, e, "connect", false).map(|()| h)
}

/// Takes a C string VIX allocated (NULL = empty) and frees it.
unsafe fn take(api: &Api, p: *mut c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: VIX returns a NUL-terminated buffer we must free with Vix_FreeBuffer.
    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
    // SAFETY: `p` came from VIX, is non-NULL and is freed once (not used after).
    unsafe { (api.free)(p.cast()) };
    s
}

impl Vix {
    /// Waits for a job without results.
    fn done(&self, job: H, what: &str) -> Result<()> {
        // SAFETY: NONE-terminated list; the job is released once.
        let e = unsafe { (self.api.wait)(job, NONE) };
        // SAFETY: `job` is live and released exactly once.
        unsafe { (self.api.release)(job) };
        check(self.api, e, what, false)
    }

    fn copy(&self, f: CopyFn, a: &CStr, b: &CStr, what: &str) -> Result<()> {
        // SAFETY: valid C strings, no property list, no callback.
        let job = unsafe {
            f(
                self.vm,
                a.as_ptr(),
                b.as_ptr(),
                0,
                INVALID_HANDLE,
                null(),
                null_mut(),
            )
        };
        self.done(job, what)
    }
}

impl Drop for Vix {
    fn drop(&mut self) {
        // SAFETY: our own handles, released once.
        unsafe {
            (self.api.release)(self.vm);
            (self.api.host_disconnect)(self.host);
        }
    }
}

impl Backend for Vix {
    fn kind(&self) -> &str {
        &self.kind
    }

    fn login(&mut self, user: &str, pass: &str) -> Result<()> {
        let u = c_str(user)?;
        let p = secret_c(pass)?;
        // SAFETY: valid C strings for the call.
        let job = unsafe {
            (self.api.login)(
                self.vm,
                u.as_ptr(),
                p.as_ptr().cast(),
                0,
                null(),
                null_mut(),
            )
        };
        // SAFETY: NONE-terminated property list; `job` is live.
        let e = unsafe { (self.api.wait)(job, NONE) };
        // SAFETY: `job` is released exactly once.
        unsafe { (self.api.release)(job) };
        check(self.api, e, "login", true)
    }

    fn list(&mut self, dir: &str, _abort: &dyn Fn() -> bool) -> Result<Vec<Item>> {
        let d = c_str(dir)?;
        let api = self.api;
        // SAFETY: the job is released on every path; property out pointers match their types.
        unsafe {
            let job = (api.list_dir)(self.vm, d.as_ptr(), 0, null(), null_mut());
            let e = (api.wait)(job, NONE);
            let r = check(api, e, "list", false).and_then(|()| {
                let n = (api.num_props)(job, ITEM_NAME);
                (0..n.max(0))
                    .map(|i| {
                        let (mut name, mut size, mut flags, mut mtime) =
                            (null_mut::<c_char>(), 0i64, 0 as c_int, 0i64);
                        let e = (api.nth_props)(
                            job,
                            i,
                            ITEM_NAME,
                            &mut name as *mut *mut c_char,
                            FILE_SIZE,
                            &mut size as *mut i64,
                            FILE_FLAGS,
                            &mut flags as *mut c_int,
                            FILE_MOD_TIME,
                            &mut mtime as *mut i64,
                            NONE,
                        );
                        let name = take(api, name);
                        check(api, e, "list", false).map(|()| item(name, size, flags, mtime))
                    })
                    .collect()
            });
            (api.release)(job);
            r
        }
    }

    fn stat(&mut self, path: &str) -> Result<Item> {
        let p = c_str(path)?;
        let api = self.api;
        let (mut size, mut flags, mut mtime) = (0i64, 0 as c_int, 0i64);
        // SAFETY: as in `list`.
        let e = unsafe {
            let job = (api.file_info)(self.vm, p.as_ptr(), null(), null_mut());
            let e = (api.wait)(
                job,
                FILE_SIZE,
                &mut size as *mut i64,
                FILE_FLAGS,
                &mut flags as *mut c_int,
                FILE_MOD_TIME,
                &mut mtime as *mut i64,
                NONE,
            );
            (api.release)(job);
            e
        };
        check(api, e, "stat", false).map(|()| item(String::new(), size, flags, mtime))
    }

    fn get(&mut self, guest: &str, host: &Path) -> Result<()> {
        self.copy(
            self.api.copy_to_host,
            &c_str(guest)?,
            &c_path(host)?,
            "copy from guest",
        )
    }

    fn put(&mut self, host: &Path, guest: &str) -> Result<()> {
        self.copy(
            self.api.copy_to_guest,
            &c_path(host)?,
            &c_str(guest)?,
            "copy to guest",
        )
    }

    fn mkdir(&mut self, path: &str) -> Result<()> {
        let p = c_str(path)?;
        // SAFETY: valid C string, no property list.
        let job =
            unsafe { (self.api.mkdir)(self.vm, p.as_ptr(), INVALID_HANDLE, null(), null_mut()) };
        self.done(job, "create folder")
    }

    fn remove_file(&mut self, path: &str) -> Result<()> {
        let p = c_str(path)?;
        // SAFETY: valid C string.
        let job = unsafe { (self.api.del_file)(self.vm, p.as_ptr(), null(), null_mut()) };
        self.done(job, "delete")
    }

    fn remove_dir(&mut self, path: &str) -> Result<()> {
        let p = c_str(path)?;
        // SAFETY: valid C string.
        let job = unsafe { (self.api.del_dir)(self.vm, p.as_ptr(), 0, null(), null_mut()) };
        self.done(job, "delete folder")
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        self.copy(self.api.rename, &c_str(from)?, &c_str(to)?, "rename")
    }

    fn ip(&mut self) -> Result<String> {
        let api = self.api;
        let mut s = null_mut::<c_char>();
        // SAFETY: as in `list`; the string is freed by `take`.
        let (e, ip) = unsafe {
            let job = (api.read_var)(
                self.vm,
                VM_GUEST_VARIABLE,
                c"ip".as_ptr(),
                0,
                null(),
                null_mut(),
            );
            let e = (api.wait)(job, VM_VARIABLE_STRING, &mut s as *mut *mut c_char, NONE);
            (api.release)(job);
            (e, take(api, s))
        };
        check(api, e, "guest IP", false)?;
        match ip.trim() {
            "" => Err(Error::new(abi::IO, "vmware: no guest IP yet")),
            ip => Ok(ip.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    /// Loads the installed VIX libraries and resolves every export we use. Calls nothing in
    /// VIX (no connect, no VM touched).
    #[test]
    #[ignore = "needs a VMware VIX install"]
    fn installed_vix_resolves() {
        let libs = crate::config::Config::default().vix_candidates();
        assert!(!libs.is_empty(), "no VIX found");
        for l in libs {
            super::api(&l).unwrap_or_else(|e| panic!("{}: {e}", l.display()));
            super::api(&l).unwrap(); // cached
            println!("ok: {}", l.display());
        }
    }
}

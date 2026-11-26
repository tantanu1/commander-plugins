//! VIX backend: the pure parts (result decoding, error mapping, library choice). The FFI calls
//! live in `vix_ffi.rs`.
use crate::backend::{Backend, is_vm_password, vm_password_error};
use crate::config::Config;
use crate::discover::Vm;
use commander_plugin_abi::glue::{Error, Item, Result};
use commander_plugin_abi::{self as abi, Status};
use std::ffi::CString;
use std::path::Path;
use zeroize::Zeroizing;

pub const ATTR_DIRECTORY: i32 = 0x1;
pub const ATTR_SYMLINK: i32 = 0x2;

/// One listing / file-info result.
pub fn item(name: String, size: i64, flags: i32, mtime_s: i64) -> Item {
    let dir = flags & ATTR_DIRECTORY != 0;
    Item {
        name,
        kind: if dir { abi::KIND_DIR } else { abi::KIND_FILE },
        size: if dir {
            0
        } else {
            u64::try_from(size).unwrap_or(0)
        },
        mtime: mtime_s.checked_mul(1_000_000_000),
        link: flags & ATTR_SYMLINK != 0,
    }
}

/// Status of a `VixError` (`VIX_ERROR_CODE` = the low 16 bits).
pub fn status_of(err: u64) -> Status {
    match err & 0xFFFF {
        4 | 2000 => abi::NOT_FOUND,      // FILE_NOT_FOUND, NOT_FOUND
        12 => abi::EXISTS,               // FILE_ALREADY_EXISTS
        13 | 3014 | 3015 => abi::DENIED, // FILE_ACCESS_ERROR, HOST/GUEST_USER_PERMISSIONS
        10 => abi::CANCELLED,
        6 | 3031 => abi::UNSUPPORTED,
        3 | 20001 | 20002 | 20004 => abi::INVALID, // INVALID_ARG, NOT_A_FILE/DIRECTORY, NAME_TOO_LONG
        35 => abi::AUTH,                           // AUTHENTICATION_FAIL
        _ => abi::IO,
    }
}

/// A failed VIX job as an error. `login`: an auth-ish failure is a wrong login (3015 there
/// means "authentication failure", elsewhere "no permission").
pub fn error(err: u64, text: &str, what: &str, login: bool) -> Error {
    let code = err & 0xFFFF;
    // CRYPTO_NEED_PASSWORD / CRYPTO_BAD_PASSWORD: an encrypted VM.
    if matches!(code, 17004 | 17005) {
        return vm_password_error(&format!("VIX {what}: {text}, VIX error {code}"));
    }
    let st = match code {
        3015 | 35 | 3033 if login => abi::AUTH,
        _ => status_of(err),
    };
    Error::new(
        st,
        format!("vmware (VIX {what}): {text} (VIX error {code})"),
    )
}

/// `s` as a C string (a NUL inside = invalid).
pub fn c_str(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Error::new(abi::INVALID, "vmware: NUL in a name"))
}

/// A password as a NUL-terminated buffer, built in place (no reallocation leaves an unwiped
/// copy behind) and wiped on drop.
pub fn secret_c(s: &str) -> Result<Zeroizing<Vec<u8>>> {
    if s.contains('\0') {
        return Err(Error::new(abi::INVALID, "vmware: NUL in a password"));
    }
    let mut v = Zeroizing::new(Vec::with_capacity(s.len() + 1));
    v.extend_from_slice(s.as_bytes());
    v.push(0);
    Ok(v)
}

/// A host path as a C string (VIX takes UTF-8).
pub fn c_path(p: &Path) -> Result<CString> {
    c_str(
        p.to_str()
            .ok_or_else(|| Error::new(abi::INVALID, "vmware: temp path is not UTF-8"))?,
    )
}

/// One library: load, connect, open the VM (with its encryption password, if any).
pub type TryOne = dyn Fn(&Path, &Vm, i32, Option<&str>) -> Result<Box<dyn Backend>>;

/// Opens `vm` through the first VIX library (of `libs`) that loads, connects and opens it. A
/// VM-password error ends the search (another library would say the same).
pub fn open_with(
    vm: &Vm,
    cfg: &Config,
    vm_password: Option<&str>,
    libs: Vec<std::path::PathBuf>,
    try_one: &TryOne,
) -> Result<Box<dyn Backend>> {
    if libs.is_empty() {
        return Err(Error::new(
            abi::IO,
            "VIX library not found (install the VMware VIX SDK, or set vix in vmware.toml)",
        ));
    }
    let mut why = Vec::new();
    for lib in libs {
        match try_one(&lib, vm, cfg.product.vix_provider(), vm_password) {
            Ok(b) => return Ok(b),
            Err(e) if is_vm_password(&e) => return Err(e),
            Err(e) => why.push(format!("{}: {}", lib.display(), e.msg)),
        }
    }
    Err(Error::new(abi::IO, why.join("; ")))
}

/// The real VIX backend for `vm`.
pub fn open(vm: &Vm, cfg: &Config, vm_password: Option<&str>) -> Result<Box<dyn Backend>> {
    open_with(
        vm,
        cfg,
        vm_password,
        cfg.vix_candidates(),
        &crate::vix_ffi::open,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::Fake;
    use std::path::PathBuf;

    #[test]
    fn decode_results() {
        let f = item("a".into(), 7, 0, 1_700_000_000);
        assert_eq!(
            (f.kind, f.size, f.mtime, f.link),
            (abi::KIND_FILE, 7, Some(1_700_000_000_000_000_000), false)
        );
        let d = item("d".into(), 4096, ATTR_DIRECTORY | ATTR_SYMLINK, i64::MAX);
        assert_eq!(
            (d.kind, d.size, d.mtime, d.link),
            (abi::KIND_DIR, 0, None, true)
        );
        assert_eq!(item("n".into(), -1, 0, 0).size, 0);
    }

    #[test]
    fn errors() {
        let base = 0x0001_0000_0000_0000u64; // VIX puts extra bits above the code
        assert_eq!(status_of(base | 4), abi::NOT_FOUND);
        assert_eq!(status_of(2000), abi::NOT_FOUND);
        assert_eq!(status_of(12), abi::EXISTS);
        assert_eq!(status_of(3015), abi::DENIED);
        assert_eq!(status_of(10), abi::CANCELLED);
        assert_eq!(status_of(6), abi::UNSUPPORTED);
        assert_eq!(status_of(20004), abi::INVALID);
        assert_eq!(status_of(35), abi::AUTH);
        assert_eq!(status_of(3016), abi::IO);
        let e = error(3015, "Authentication failure", "login", true);
        assert_eq!(e.status, abi::AUTH);
        assert!(e.msg.contains("VIX error 3015"), "{}", e.msg);
        assert_eq!(error(3015, "x", "copy", false).status, abi::DENIED);
        for code in [17004, 17005] {
            let e = error(code, "Bad password", "connect", false);
            assert!(is_vm_password(&e), "{}", e.msg);
            assert!(
                e.msg.contains("encrypted VM: enter the VM password"),
                "{}",
                e.msg
            );
            assert!(e.msg.contains(&format!("VIX error {code}")), "{}", e.msg);
        }
        assert!(c_str("a\0b").is_err());
        assert_eq!(c_str("ab").unwrap().as_bytes(), b"ab");
        assert!(c_path(Path::new("x")).is_ok());
        let s = secret_c("pw").unwrap();
        assert_eq!((s.as_slice(), s.capacity()), (&b"pw\0"[..], 3));
        assert_eq!(secret_c("a\0b").unwrap_err().status, abi::INVALID);
    }

    #[test]
    fn first_library_that_works_wins() {
        let vm = Vm {
            name: "v".into(),
            vmx: PathBuf::from("/v.vmx"),
            windows: false,
            encrypted: false,
        };
        let cfg = Config::default();
        let none = open_with(&vm, &cfg, None, vec![], &|_, _, _, _| unreachable!())
            .err()
            .unwrap();
        assert!(none.msg.contains("VIX library not found"));
        let libs = vec![PathBuf::from("a.dll"), PathBuf::from("b.dll")];
        let pick =
            |p: &Path, _: &Vm, provider: i32, pw: Option<&str>| -> Result<Box<dyn Backend>> {
                assert_eq!((provider, pw), (3, Some("vmpw")));
                match p == Path::new("b.dll") {
                    true => Ok(Box::new(Fake::posix())),
                    false => Err(Error::new(abi::IO, "version not found")),
                }
            };
        assert_eq!(
            open_with(&vm, &cfg, Some("vmpw"), libs.clone(), &pick)
                .unwrap()
                .kind(),
            "fake"
        );
        let no = |_: &Path, _: &Vm, _: i32, _: Option<&str>| -> Result<Box<dyn Backend>> {
            Err(Error::new(abi::IO, "no"))
        };
        let e = open_with(&vm, &cfg, None, libs.clone(), &no).err().unwrap();
        assert_eq!(e.msg, "a.dll: no; b.dll: no");
        // An encrypted VM: the first library's answer is final.
        let enc = |p: &Path, _: &Vm, _: i32, _: Option<&str>| -> Result<Box<dyn Backend>> {
            assert_eq!(p, Path::new("a.dll"), "no second try");
            Err(vm_password_error("VIX connect: x, VIX error 17004"))
        };
        assert!(is_vm_password(
            &open_with(&vm, &cfg, None, libs, &enc).err().unwrap()
        ));
    }
}

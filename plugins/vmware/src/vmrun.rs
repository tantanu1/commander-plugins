//! Fallback backend: one `vmrun` run per operation. vmrun signs in to the guest on every run
//! and takes the guest password on its command line (other local users/processes can read it
//! there while it runs): VIX is preferred, this is used only when VIX is unavailable.
//! Listings have names only: each entry costs one more run to tell folders from files, and a
//! file's size is known only by copying it (stat), so this backend is slow. Its output is read
//! as UTF-8: on Windows, vmrun prints non-ASCII guest names in the console code page, so such
//! names may come out garbled (a limitation of this fallback; VIX returns UTF-8).
use crate::backend::{Backend, cancelled, vm_password_error};
use crate::discover::{Out, Run, Vm};
use commander_plugin_abi::glue::{Error, Item, Result};
use commander_plugin_abi::stage::Stage;
use commander_plugin_abi::{self as abi, Status};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::Zeroizing;

pub struct Vmrun {
    exe: PathBuf,
    product: &'static str,
    vmx: PathBuf,
    windows: bool,
    account: Option<(String, Zeroizing<String>)>,
    /// VM encryption password (`-vp`) of an encrypted VM.
    vm_password: Option<Zeroizing<String>>,
    run: Arc<Run>,
    /// "vmrun" + why VIX was not used.
    kind: String,
}

/// Status of a vmrun error text.
pub fn status_of(msg: &str) -> Status {
    let m = msg.to_ascii_lowercase();
    let has = |s: &[&str]| s.iter().any(|w| m.contains(w));
    if has(&["user name or password", "authentication fail"]) {
        abi::AUTH
    } else if has(&["not found", "does not exist", "no such file"]) {
        abi::NOT_FOUND
    } else if has(&["already exists"]) {
        abi::EXISTS
    } else if has(&["permission", "access is denied", "access denied"]) {
        abi::DENIED
    } else {
        abi::IO
    }
}

/// `listDirectoryInGuest` output: "Directory list: N" then one name per line.
pub fn parse_dir_list(out: &str) -> Vec<String> {
    out.lines()
        .skip_while(|l| !l.starts_with("Directory list"))
        .skip(1)
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect()
}

/// `fileExistsInGuest` / `directoryExistsInGuest` output -> exists.
pub fn parse_exists(out: &Out) -> Option<bool> {
    let t = out.stdout.to_ascii_lowercase();
    if t.contains("does not exist") {
        Some(false)
    } else if t.contains("exists") {
        Some(true)
    } else {
        None
    }
}

fn join(dir: &str, sep: char, name: &str) -> String {
    match dir.ends_with(sep) {
        true => format!("{dir}{name}"),
        false => format!("{dir}{sep}{name}"),
    }
}

impl Vmrun {
    /// `why_not_vix`: shown with the backend name (the connect file). `vm_password`: the VM
    /// encryption password of an encrypted VM (passed as `-vp`, like the guest password).
    pub fn new(
        vm: &Vm,
        exe: PathBuf,
        product: &'static str,
        run: Arc<Run>,
        why_not_vix: Option<&str>,
        vm_password: Option<&str>,
    ) -> Self {
        Self {
            exe,
            product,
            vmx: vm.vmx.clone(),
            windows: vm.windows,
            account: None,
            vm_password: vm_password.map(|p| Zeroizing::new(p.to_owned())),
            run,
            kind: match why_not_vix {
                Some(w) => format!("vmrun (VIX unavailable: {w})"),
                None => "vmrun".into(),
            },
        }
    }

    fn sep(&self) -> char {
        if self.windows { '\\' } else { '/' }
    }

    /// Runs `vmrun -T <product> [-gu -gp] <cmd> <vmx> <args>`.
    fn exec(&self, cmd: &str, args: &[&std::ffi::OsStr]) -> Result<Out> {
        let mut v: Vec<OsString> = vec!["-T".into(), self.product.into()];
        if let Some(p) = &self.vm_password {
            v.extend(["-vp".into(), p.as_str().into()]);
        }
        if let Some((u, p)) = &self.account {
            v.extend(["-gu".into(), u.into(), "-gp".into(), p.as_str().into()]);
        }
        v.extend([cmd.into(), self.vmx.clone().into_os_string()]);
        v.extend(args.iter().map(|a| a.to_os_string()));
        // shortcut: this argv copy of the password is not wiped (OsString has no zeroize); it
        // is on vmrun's command line anyway. Upgrade if vmrun ever reads it from stdin.
        (self.run)(&self.exe, &v).map_err(|e| {
            Error::new(
                abi::IO,
                format!("vmware: cannot run {}: {e}", self.exe.display()),
            )
        })
    }

    /// [`Self::exec`] that must succeed; the stdout.
    fn call(&self, cmd: &str, args: &[&str]) -> Result<String> {
        let args: Vec<&std::ffi::OsStr> = args.iter().map(|a| a.as_ref()).collect();
        let o = self.exec(cmd, &args)?;
        let failed = o.code != Some(0) || o.stdout.trim_start().starts_with("Error");
        match failed {
            false => Ok(o.stdout),
            true => Err(fail(cmd, &o)),
        }
    }

    /// `fileExistsInGuest` / `directoryExistsInGuest`.
    fn probe(&self, cmd: &str, path: &str) -> Result<bool> {
        let o = self.exec(cmd, &[path.as_ref()])?;
        parse_exists(&o).ok_or_else(|| fail(cmd, &o))
    }

    fn copy(&self, cmd: &str, from: &std::ffi::OsStr, to: &std::ffi::OsStr) -> Result<()> {
        let o = self.exec(cmd, &[from, to])?;
        match o.code == Some(0) {
            true => Ok(()),
            false => Err(fail(cmd, &o)),
        }
    }
}

fn fail(cmd: &str, o: &Out) -> Error {
    let text = format!("{} {}", o.stdout.trim(), o.stderr.trim());
    let text = text.trim().trim_start_matches("Error:").trim();
    Error::new(status_of(text), format!("vmware (vmrun {cmd}): {text}"))
}

/// A failed sign-in that names the encryption: the VM password (`-vp`) is missing or wrong.
/// Only at sign-in (the VM's open): later, "encrypt" is about a guest file (EFS).
fn at_open(e: Error) -> Error {
    match e.msg.to_ascii_lowercase().contains("encrypt") {
        true => vm_password_error(&e.msg),
        false => e,
    }
}

impl Backend for Vmrun {
    fn kind(&self) -> &str {
        &self.kind
    }

    fn login(&mut self, user: &str, pass: &str) -> Result<()> {
        self.account = Some((user.into(), Zeroizing::new(pass.into())));
        // vmrun keeps no session: check the account once now (a wrong one asks again).
        let root = if self.windows { "C:\\" } else { "/" };
        self.probe("directoryExistsInGuest", root)
            .map(drop)
            .map_err(at_open)
            .inspect_err(|_| self.account = None)
    }

    fn list(&mut self, dir: &str, abort: &dyn Fn() -> bool) -> Result<Vec<Item>> {
        let names = parse_dir_list(&self.call("listDirectoryInGuest", &[dir])?);
        let mut out = Vec::with_capacity(names.len());
        for n in names {
            if abort() {
                return Err(cancelled());
            }
            let dir = self.probe("directoryExistsInGuest", &join(dir, self.sep(), &n))?;
            out.push(Item {
                kind: if dir { abi::KIND_DIR } else { abi::KIND_FILE },
                ..Item::dir(n)
            });
        }
        Ok(out)
    }

    fn stat(&mut self, path: &str) -> Result<Item> {
        if self.probe("directoryExistsInGuest", path)? {
            return Ok(Item::dir(""));
        }
        if !self.probe("fileExistsInGuest", path)? {
            return Err(Error::new(
                abi::NOT_FOUND,
                format!("vmware: {path}: not found"),
            ));
        }
        // No size from vmrun: copy the file to learn it (copies check the exact size).
        let s = Stage::new("cmdr-vmware")
            .map_err(|e| Error::new(abi::IO, format!("vmware: temp dir: {e}")))?;
        let host = s.path().join("f");
        self.get(path, &host)?;
        let size = std::fs::metadata(&host)
            .map_err(|e| Error::new(abi::IO, format!("vmware: {e}")))?
            .len();
        Ok(Item {
            kind: abi::KIND_FILE,
            size,
            ..Item::dir("")
        })
    }

    /// Two cheap probes, never a copy.
    fn exists(&mut self, path: &str) -> Result<bool> {
        Ok(self.probe("directoryExistsInGuest", path)? || self.probe("fileExistsInGuest", path)?)
    }

    fn get(&mut self, guest: &str, host: &Path) -> Result<()> {
        self.copy("CopyFileFromGuestToHost", guest.as_ref(), host.as_os_str())
    }

    fn put(&mut self, host: &Path, guest: &str) -> Result<()> {
        self.copy("CopyFileFromHostToGuest", host.as_os_str(), guest.as_ref())
    }

    fn mkdir(&mut self, path: &str) -> Result<()> {
        self.call("createDirectoryInGuest", &[path]).map(drop)
    }

    fn remove_file(&mut self, path: &str) -> Result<()> {
        self.call("deleteFileInGuest", &[path]).map(drop)
    }

    fn remove_dir(&mut self, path: &str) -> Result<()> {
        self.call("deleteDirectoryInGuest", &[path]).map(drop)
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        self.call("renameFileInGuest", &[from, to]).map(drop)
    }

    fn ip(&mut self) -> Result<String> {
        let out = self.call("getGuestIPAddress", &[])?;
        let ip = out.trim();
        match ip.is_empty() || ip.contains(char::is_whitespace) {
            true => Err(Error::new(abi::IO, format!("vmware: no guest IP ({ip})"))),
            false => Ok(ip.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn parsers() {
        assert_eq!(
            parse_dir_list("Directory list: 2\r\n.bashrc\r\nDocs\r\n\r\n"),
            [".bashrc", "Docs"]
        );
        assert!(parse_dir_list("Directory list: 0\n").is_empty());
        // Names are kept as is: spaces, Unicode, a name that looks like the header.
        assert_eq!(
            parse_dir_list(
                "Directory list: 3\n my file .txt\nDirectory list\n\u{e9}t\u{e9} \u{65e5}\n"
            ),
            [" my file .txt", "Directory list", "\u{e9}t\u{e9} \u{65e5}"]
        );
        assert!(parse_dir_list("junk").is_empty());
        let o = |s: &str| Out {
            stdout: s.into(),
            ..Out::default()
        };
        assert_eq!(parse_exists(&o("The directory exists.\n")), Some(true));
        assert_eq!(parse_exists(&o("The file does not exist.\n")), Some(false));
        assert_eq!(parse_exists(&o("Error: x")), None);
        assert_eq!(
            status_of("Invalid user name or password for the guest OS"),
            abi::AUTH
        );
        assert_eq!(status_of("A file was not found"), abi::NOT_FOUND);
        assert_eq!(status_of("The file already exists"), abi::EXISTS);
        assert_eq!(
            status_of("Insufficient permissions in the guest"),
            abi::DENIED
        );
        assert_eq!(status_of("The VMware Tools are not running"), abi::IO);
        assert_eq!(join("C:\\", '\\', "x"), "C:\\x");
        assert_eq!(join("/a", '/', "x"), "/a/x");
    }

    /// A scripted vmrun: answers by command; records every argv.
    fn fake(
        windows: bool,
        answer: fn(&str, &[String]) -> Out,
    ) -> (Vmrun, Arc<Mutex<Vec<Vec<String>>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = Arc::clone(&seen);
        let run = move |exe: &Path, a: &[OsString]| -> std::io::Result<Out> {
            assert_eq!(exe, Path::new("vmrun"));
            let a: Vec<String> = a.iter().map(|x| x.to_string_lossy().into_owned()).collect();
            s.lock().unwrap().push(a.clone());
            let at = a.iter().position(|x| x.ends_with(".vmx")).unwrap();
            Ok(answer(&a[at - 1], &a[at + 1..]))
        };
        let vm = Vm {
            name: "v".into(),
            vmx: PathBuf::from("/v/v.vmx"),
            windows,
            encrypted: false,
        };
        (
            Vmrun::new(&vm, PathBuf::from("vmrun"), "ws", Arc::new(run), None, None),
            seen,
        )
    }

    fn ok(s: &str) -> Out {
        Out {
            code: Some(0),
            stdout: s.into(),
            ..Out::default()
        }
    }

    fn guest(cmd: &str, args: &[String]) -> Out {
        let is_dir = |p: &str| p == "/" || p == "/d";
        let is_file = |p: &str| p == "/f.txt";
        match cmd {
            "directoryExistsInGuest" => ok(if is_dir(&args[0]) {
                "The directory exists."
            } else {
                "The directory does not exist."
            }),
            "fileExistsInGuest" => ok(if is_file(&args[0]) {
                "The file exists."
            } else {
                "The file does not exist."
            }),
            "listDirectoryInGuest" if args[0] == "/" => ok("Directory list: 2\nd\nf.txt\n"),
            "CopyFileFromGuestToHost" => {
                std::fs::write(&args[1], b"12345").unwrap();
                ok("")
            }
            "getGuestIPAddress" => ok("192.0.2.9\n"),
            "createDirectoryInGuest"
            | "deleteFileInGuest"
            | "deleteDirectoryInGuest"
            | "renameFileInGuest"
            | "CopyFileFromHostToGuest" => ok(""),
            _ => Out {
                code: Some(255),
                stdout: "Error: A file was not found".into(),
                ..Out::default()
            },
        }
    }

    #[test]
    fn operations_and_argv() {
        let (mut b, seen) = fake(false, guest);
        assert!(b.kind().starts_with("vmrun"));
        b.login("me", "pw").unwrap();
        let first = seen.lock().unwrap()[0].clone();
        assert_eq!(
            first,
            [
                "-T",
                "ws",
                "-gu",
                "me",
                "-gp",
                "pw",
                "directoryExistsInGuest",
                "/v/v.vmx",
                "/"
            ]
        );
        let items = b.list("/", &|| false).unwrap();
        let got: Vec<_> = items.iter().map(|i| (i.name.as_str(), i.kind)).collect();
        assert_eq!(got, [("d", abi::KIND_DIR), ("f.txt", abi::KIND_FILE)]);
        assert_eq!(b.list("/", &|| true).unwrap_err().status, abi::CANCELLED);
        assert_eq!(b.list("/x", &|| false).unwrap_err().status, abi::NOT_FOUND);
        assert_eq!(b.stat("/d").unwrap().kind, abi::KIND_DIR);
        let f = b.stat("/f.txt").unwrap();
        assert_eq!((f.kind, f.size), (abi::KIND_FILE, 5));
        assert_eq!(b.stat("/zz").unwrap_err().status, abi::NOT_FOUND);
        let before = seen.lock().unwrap().len();
        assert!(b.exists("/f.txt").unwrap() && b.exists("/d").unwrap());
        assert!(!b.exists("/zz").unwrap());
        let copies = seen.lock().unwrap()[before..]
            .iter()
            .filter(|a| a.iter().any(|x| x.starts_with("CopyFile")))
            .count();
        assert_eq!(copies, 0, "exists never copies the file");
        let d = tempfile::tempdir().unwrap();
        b.get("/f.txt", &d.path().join("x")).unwrap();
        b.put(&d.path().join("x"), "/up").unwrap();
        b.mkdir("/n").unwrap();
        b.remove_file("/n").unwrap();
        b.remove_dir("/n").unwrap();
        b.rename("/a", "/b").unwrap();
        assert_eq!(b.ip().unwrap(), "192.0.2.9");
        let last = seen.lock().unwrap().last().unwrap().clone();
        assert_eq!(last[last.len() - 2], "getGuestIPAddress");
    }

    #[test]
    fn failures() {
        let (mut b, _) = fake(true, |cmd, _| match cmd {
            "directoryExistsInGuest" => Out {
                code: Some(255),
                stdout: "Error: Invalid user name or password for the guest OS".into(),
                ..Out::default()
            },
            "getGuestIPAddress" => ok("Error: Unable to get the IP address"),
            "CopyFileFromGuestToHost" => Out {
                code: Some(255),
                stderr: "denied: permission".into(),
                ..Out::default()
            },
            _ => ok("odd output"),
        });
        let e = b.login("me", "bad").unwrap_err();
        assert_eq!(e.status, abi::AUTH, "{}", e.msg);
        assert!(!e.msg.contains("bad"), "never the password: {}", e.msg);
        assert!(b.account.is_none());
        assert_eq!(b.ip().unwrap_err().status, abi::IO);
        assert_eq!(
            b.get("C:\\x", Path::new("y")).unwrap_err().status,
            abi::DENIED
        );
        assert_eq!(b.stat("C:\\x").unwrap_err().status, abi::AUTH);
        let (mut b, _) = fake(false, |_, _| ok("   "));
        assert_eq!(b.ip().unwrap_err().status, abi::IO, "empty answer");
        let (mut b, _) = fake(false, |_, _| ok("x"));
        assert_eq!(b.login("u", "p").unwrap_err().status, abi::IO, "unparsable");
        let vm = Vm {
            name: "v".into(),
            vmx: PathBuf::from("/v/boom.vmx"),
            windows: false,
            encrypted: false,
        };
        let run = |_: &Path, _: &[OsString]| -> std::io::Result<Out> {
            Err(std::io::Error::other("gone"))
        };
        let mut b = Vmrun::new(
            &vm,
            PathBuf::from("vmrun"),
            "ws",
            Arc::new(run),
            Some("no dll"),
            None,
        );
        assert_eq!(b.kind(), "vmrun (VIX unavailable: no dll)");
        assert!(b.mkdir("/x").unwrap_err().msg.contains("cannot run vmrun"));
    }

    #[test]
    fn encrypted_vm_password() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let s = Arc::clone(&seen);
        let run = move |_: &Path, a: &[OsString]| -> std::io::Result<Out> {
            let a: Vec<String> = a.iter().map(|x| x.to_string_lossy().into_owned()).collect();
            let ok = a.windows(2).any(|w| w == ["-vp", "vmpw"]);
            s.lock().unwrap().push(a);
            Ok(match ok {
                true => Out {
                    code: Some(0),
                    stdout: "The directory exists.".into(),
                    ..Out::default()
                },
                false => Out {
                    code: Some(255),
                    stdout: "Error: The virtual machine is encrypted".into(),
                    ..Out::default()
                },
            })
        };
        let vm = Vm {
            name: "v".into(),
            vmx: PathBuf::from("/v/v.vmx"),
            windows: false,
            encrypted: true,
        };
        let run: Arc<Run> = Arc::new(run);
        let mut b = Vmrun::new(
            &vm,
            "vmrun".into(),
            "ws",
            Arc::clone(&run),
            None,
            Some("bad"),
        );
        let e = b.login("me", "guestpw").unwrap_err();
        assert!(crate::backend::is_vm_password(&e), "{}", e.msg);
        assert!(
            !e.msg.contains("bad") && !e.msg.contains("guestpw"),
            "{}",
            e.msg
        );
        let mut b = Vmrun::new(
            &vm,
            "vmrun".into(),
            "ws",
            Arc::clone(&run),
            None,
            Some("vmpw"),
        );
        b.login("me", "guestpw").unwrap();
        let argv = seen.lock().unwrap().last().unwrap().clone();
        assert_eq!(&argv[..4], ["-T", "ws", "-vp", "vmpw"]);
        // After sign-in, "encrypt" is a guest file's problem (EFS), not the VM password.
        let (mut b, _) = fake(true, |cmd, _| match cmd {
            "directoryExistsInGuest" => ok("The directory exists."),
            _ => Out {
                code: Some(255),
                stdout: "Error: The file is encrypted".into(),
                ..Out::default()
            },
        });
        b.login("me", "pw").unwrap();
        let e = b.get("C:\\x", Path::new("y")).unwrap_err();
        assert!(!crate::backend::is_vm_password(&e), "{}", e.msg);
        assert!(e.msg.contains("encrypted"), "{}", e.msg);
    }
}

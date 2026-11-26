//! Guest file operations of one VM ([`Backend`]: VIX, vmrun, or the test fake) and the
//! [`Session`] worker thread that owns it: every call of one VM runs on that one thread (VIX
//! handles are not documented as thread-safe), the caller waits and polls its cancel flag.
use commander_plugin_abi::glue::{self, Error, Item, Result};
use commander_plugin_abi::{self as abi};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::time::Duration;

/// Guest file operations on one VM. Paths are absolute guest paths (`C:\x`, `/x`).
pub trait Backend {
    /// "VIX" or "vmrun" (named in errors and the connect file).
    fn kind(&self) -> &str;
    /// Sign in to the guest (once per session; vmrun keeps the account for each call).
    fn login(&mut self, user: &str, pass: &str) -> Result<()>;
    /// Entries of `dir` (raw names); `abort` is checked between slow steps.
    fn list(&mut self, dir: &str, abort: &dyn Fn() -> bool) -> Result<Vec<Item>>;
    /// `NOT_FOUND` when absent; `name` is empty.
    fn stat(&mut self, path: &str) -> Result<Item>;
    /// `path` exists (file or folder). Default: [`Self::stat`]; vmrun overrides it (its stat
    /// copies the whole file to learn the size).
    fn exists(&mut self, path: &str) -> Result<bool> {
        match self.stat(path) {
            Ok(_) => Ok(true),
            Err(e) if e.status == abi::NOT_FOUND => Ok(false),
            Err(e) => Err(e),
        }
    }
    /// Copy guest file `guest` to the new host file `host`.
    fn get(&mut self, guest: &str, host: &Path) -> Result<()>;
    /// Copy host file `host` to `guest`, replacing it (callers pick a fresh name).
    fn put(&mut self, host: &Path, guest: &str) -> Result<()>;
    fn mkdir(&mut self, path: &str) -> Result<()>;
    fn remove_file(&mut self, path: &str) -> Result<()>;
    /// Deletes the whole tree (VIX does): callers check it is empty first.
    fn remove_dir(&mut self, path: &str) -> Result<()>;
    fn rename(&mut self, from: &str, to: &str) -> Result<()>;
    /// Guest IP address (VMware Tools); needs no login.
    fn ip(&mut self) -> Result<String>;
}

type Job = Box<dyn FnOnce(&mut dyn Backend) + Send>;

/// One VM's worker thread. Dropping the session ends the thread once its last job is done.
pub struct Session {
    tx: Sender<Job>,
}

fn dead() -> Error {
    Error::new(abi::IO, "vmware: the VM session stopped (try again)")
}

/// Start of every "VM encryption password needed / wrong" error (status `AUTH`): the mount
/// tells it from a wrong guest login by this text. Never carries the password.
pub const VM_PASSWORD: &str = "vmware: encrypted VM: enter the VM password";

/// An encrypted VM that did not open: no or a wrong VM password (`detail`: the backend's own
/// error text and code).
pub fn vm_password_error(detail: &str) -> Error {
    Error::new(abi::AUTH, format!("{VM_PASSWORD} ({detail})"))
}

pub fn is_vm_password(e: &Error) -> bool {
    e.status == abi::AUTH && e.msg.starts_with(VM_PASSWORD)
}

pub fn cancelled() -> Error {
    Error::new(abi::CANCELLED, "cancelled")
}

impl Session {
    /// Starts the worker; `make` builds the backend on it (handles never change threads).
    pub fn start(make: impl FnOnce() -> Result<Box<dyn Backend>> + Send + 'static) -> Result<Self> {
        // The worker may outlive a mount (a cancelled job finishes): keep our code mapped.
        glue::pin_module();
        let (tx, rx) = mpsc::channel::<Job>();
        let (ready_tx, ready_rx) = mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("vmware-session".into())
            .spawn(move || {
                let mut b = match make() {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                let _ = ready_tx.send(Ok(()));
                for job in rx {
                    job(&mut *b);
                }
            });
        spawned.map_err(|e| Error::new(abi::IO, format!("vmware: worker thread: {e}")))?;
        ready_rx.recv().map_err(|_| dead())??;
        Ok(Self { tx })
    }

    /// Runs `f` on the worker and waits, polling `cancel` every 50 ms. Cancelled = `CANCELLED`
    /// at once; `f` still runs to its end on the worker and sees its `abort` flag set (it
    /// cleans up there), so a cancel never leaves a half-done step behind.
    pub fn call<T: Send + 'static>(
        &self,
        cancel: &dyn Fn() -> bool,
        f: impl FnOnce(&mut dyn Backend, &dyn Fn() -> bool) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        if cancel() {
            return Err(cancelled());
        }
        let abort = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&abort);
        let (rtx, rrx) = mpsc::channel();
        let job: Job = Box::new(move |b| {
            let r = f(b, &|| seen.load(Ordering::Relaxed));
            let _ = rtx.send(r); // the caller may have gone (cancelled)
        });
        self.tx.send(job).map_err(|_| dead())?;
        loop {
            match rrx.recv_timeout(Duration::from_millis(50)) {
                Ok(r) => return r,
                Err(RecvTimeoutError::Timeout) if cancel() => {
                    abort.store(true, Ordering::Relaxed);
                    return Err(cancelled());
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err(dead()),
            }
        }
    }

    /// [`Self::call`] that is never cancelled by the caller.
    pub fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut dyn Backend) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        self.call(&|| false, move |b, _| f(b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::Fake;
    use std::sync::Mutex;

    #[test]
    fn calls_run_on_one_thread_and_cancel_returns_at_once() {
        let s = Session::start(|| Ok(Box::new(Fake::posix()) as Box<dyn Backend>)).unwrap();
        let t1 = s.run(|_| Ok(std::thread::current().id())).unwrap();
        let t2 = s.run(|_| Ok(std::thread::current().id())).unwrap();
        assert_eq!(t1, t2);
        assert_ne!(t1, std::thread::current().id());
        // A slow job: the caller gives up, the job sees `abort` and still finishes.
        let saw = Arc::new(Mutex::new(None));
        let saw2 = Arc::clone(&saw);
        let polls = std::sync::atomic::AtomicUsize::new(0);
        let later = || polls.fetch_add(1, Ordering::Relaxed) > 0; // not before the start
        assert_eq!(
            s.call(&|| true, |_, _| Ok(())).unwrap_err().status,
            abi::CANCELLED
        );
        let e = s
            .call(&later, move |_, abort| {
                std::thread::sleep(Duration::from_millis(120));
                *saw2.lock().unwrap() = Some(abort());
                Ok(())
            })
            .unwrap_err();
        assert_eq!(e.status, abi::CANCELLED);
        s.run(|_| Ok(())).unwrap(); // queued after the slow job: it has finished
        assert_eq!(*saw.lock().unwrap(), Some(true));
        // A panicking job kills the worker: later calls fail cleanly.
        assert_eq!(
            s.run(|_| -> Result<()> { panic!("boom") })
                .unwrap_err()
                .status,
            abi::IO
        );
        assert_eq!(s.run(|_| Ok(())).unwrap_err().status, abi::IO);
    }

    #[test]
    fn a_failed_connect_fails_start() {
        let e = Session::start(|| Err(Error::new(abi::IO, "no vix")))
            .err()
            .unwrap();
        assert_eq!(e.msg, "no vix");
        let e = Session::start(|| panic!("boom")).err().unwrap();
        assert_eq!(e.status, abi::IO);
    }
}

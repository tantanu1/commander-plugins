//! VMware guest vfs plugin (C ABI v1): `vmware://` = running VMs (+ `<vm>.connect.txt`),
//! `vmware://[user@]<vm>/<path>` = that guest's files through VMware Tools. Backend: VIX
//! (loaded at run time from the user's VMware install), else `vmrun`. The guest login is asked
//! with the host's password prompt (memory only). This file maps `fs` onto the ABI glue.
mod backend;
mod config;
mod discover;
#[cfg(test)]
mod fake;
mod fs;
mod vix;
mod vix_ffi;
mod vmrun;

use backend::Backend;
use commander_plugin_abi::glue::{self, Cancel, Item, Result};
use config::{Choice, Config};
use discover::Vm;
use fs::{Listing, Vmware, Writer};
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long [`running_vms`] reuses its answer.
const VMS_TTL: Duration = Duration::from_secs(3);

/// Running VMs of the configured product, cached for [`VMS_TTL`]: each stat / read of the VM
/// list would otherwise start vmrun (or a PowerShell process scan).
fn running_vms(cfg: &Config) -> Result<Vec<Vm>> {
    static CACHE: Mutex<Option<(Instant, Vec<Vm>)>> = Mutex::new(None);
    let mut c = CACHE.lock().unwrap_or_else(|p| p.into_inner()); // plain cache
    if let Some((at, v)) = c.as_ref()
        && at.elapsed() < VMS_TTL
    {
        return Ok(v.clone());
    }
    let read = |p: &std::path::Path| {
        std::fs::read(p)
            .ok()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    };
    let v = discover::running(
        &cfg.vmrun_path(),
        cfg.product.vmrun_type(),
        &discover::run,
        &read,
    )?;
    *c = Some((Instant::now(), v.clone()));
    Ok(v)
}

/// A backend for `vm` as `vmware.toml` asks: VIX, vmrun, or VIX falling back to vmrun.
/// `vm_password`: the VM encryption password of an encrypted VM.
fn connect(vm: &Vm, cfg: &Config, vm_password: Option<&str>) -> Result<Box<dyn Backend>> {
    connect_with(vm, cfg, vm_password, &vix::open)
}

fn connect_with(
    vm: &Vm,
    cfg: &Config,
    vm_password: Option<&str>,
    vix: &fs::Connect,
) -> Result<Box<dyn Backend>> {
    let vmrun = |why: Option<&str>| -> Box<dyn Backend> {
        let p = cfg.product.vmrun_type();
        Box::new(vmrun::Vmrun::new(
            vm,
            cfg.vmrun_path(),
            p,
            Arc::new(discover::run),
            why,
            vm_password,
        ))
    };
    match cfg.backend {
        Choice::Vmrun => Ok(vmrun(None)),
        Choice::Vix => vix(vm, cfg, vm_password),
        Choice::Auto => match vix(vm, cfg, vm_password) {
            Ok(b) => Ok(b),
            // An encrypted VM's password problem: vmrun would only say the same.
            Err(e) if backend::is_vm_password(&e) => Err(e),
            Err(e) => Ok(vmrun(Some(&e.msg))),
        },
    }
}

impl glue::Fs for Vmware {
    type Error = glue::Error;
    type Lister = Listing;
    type Writer = Writer;
    const NAME: &'static str = "vmware";

    fn open(config: &str) -> Result<Self> {
        Vmware::open(config)
    }

    fn list(self: &Arc<Self>, dir: &str) -> Result<Self::Lister> {
        Vmware::list(self, dir)
    }

    fn next_batch(l: &mut Listing, cap: usize, cancelled: &dyn Fn() -> bool) -> Result<Vec<Item>> {
        l.next_batch(cap, cancelled)
    }

    fn stat(&self, path: &str) -> Result<Item> {
        Vmware::stat(self, path)
    }

    fn reader(&self, path: &str, offset: u64) -> Result<Box<dyn Read + Send>> {
        Vmware::reader(self, path, offset, &|| false)
    }

    fn reader_job(
        &self,
        path: &str,
        offset: u64,
        cancelled: Cancel,
    ) -> Result<Box<dyn Read + Send>> {
        Vmware::reader(self, path, offset, &*cancelled)
    }

    fn writer(self: &Arc<Self>, path: &str, overwrite: bool, _hint: u64) -> Result<Writer> {
        Vmware::writer(self, path, overwrite)
    }

    fn write(w: &mut Writer, data: &[u8]) -> Result<()> {
        w.write(data)
    }

    fn finish(w: Writer) -> Result<()> {
        w.finish()
    }

    fn mkdir(&self, path: &str) -> Result<()> {
        Vmware::mkdir(self, path)
    }

    fn remove_file(&self, path: &str) -> Result<()> {
        Vmware::remove_file(self, path)
    }

    fn remove_dir(&self, path: &str) -> Result<()> {
        Vmware::remove_dir(self, path)
    }

    fn rename(&self, from: &str, to: &str, cancelled: &dyn Fn() -> bool) -> Result<()> {
        Vmware::rename(self, from, to, cancelled)
    }
}

commander_plugin_abi::export_vfs!(Vmware);

#[cfg(test)]
mod tests {
    use super::*;
    use commander_plugin_abi as abi;
    use fake::Fake;
    use glue::Fs;
    use std::path::PathBuf;

    fn vm() -> Vm {
        Vm {
            name: "v".into(),
            vmx: PathBuf::from("/v.vmx"),
            windows: false,
            encrypted: false,
        }
    }

    #[test]
    fn backend_choice() {
        let ok = |_: &Vm, _: &Config, _: Option<&str>| -> Result<Box<dyn Backend>> {
            Ok(Box::new(Fake::posix()))
        };
        let no = |_: &Vm, _: &Config, _: Option<&str>| -> Result<Box<dyn Backend>> {
            Err(glue::Error::new(abi::IO, "no vix"))
        };
        let enc = |_: &Vm, _: &Config, _: Option<&str>| -> Result<Box<dyn Backend>> {
            Err(backend::vm_password_error(
                "VIX connect: x, VIX error 17004",
            ))
        };
        let cfg = |backend| Config {
            backend,
            ..Config::default()
        };
        assert_eq!(
            connect_with(&vm(), &cfg(Choice::Auto), None, &ok)
                .unwrap()
                .kind(),
            "fake"
        );
        let b = connect_with(&vm(), &cfg(Choice::Auto), None, &no).unwrap();
        assert_eq!(b.kind(), "vmrun (VIX unavailable: no vix)");
        assert_eq!(
            connect_with(&vm(), &cfg(Choice::Vmrun), Some("vmpw"), &ok)
                .unwrap()
                .kind(),
            "vmrun"
        );
        assert_eq!(
            connect_with(&vm(), &cfg(Choice::Vix), None, &no)
                .err()
                .unwrap()
                .msg,
            "no vix"
        );
        // The real chain on this machine: never fails to give a backend in auto mode.
        assert!(connect(&vm(), &cfg(Choice::Vmrun), None).is_ok());
        let e = connect_with(&vm(), &cfg(Choice::Auto), Some("bad"), &enc)
            .err()
            .unwrap();
        assert!(backend::is_vm_password(&e), "no vmrun fallback: {}", e.msg);
    }

    /// The glue::Fs mapping, end to end against the fake guest.
    #[test]
    fn fs_trait_over_fake_guest() {
        let f = Fake::posix();
        let f2 = f.clone();
        let deps = fs::Deps {
            cfg: Config::default(),
            keys: Arc::default(),
            vms: Arc::new(|_| Ok(vec![vm()])),
            connect: Arc::new(move |_, _, _| Ok(Box::new(f2.clone()) as Box<dyn Backend>)),
        };
        let fs = Arc::new(Vmware::open_with("vmware://v\nme:pw", deps).unwrap());
        Fs::mkdir(&*fs, "d").unwrap();
        let mut w = Fs::writer(&fs, "d/a", false, 3).unwrap();
        <Vmware as Fs>::write(&mut w, b"abc").unwrap();
        <Vmware as Fs>::finish(w).unwrap();
        let mut l = Fs::list(&fs, "d").unwrap();
        let got = <Vmware as Fs>::next_batch(&mut l, 10, &|| false).unwrap();
        assert_eq!(got[0].name, "a");
        assert_eq!(Fs::stat(&*fs, "d/a").unwrap().size, 3);
        let mut s = String::new();
        Fs::reader(&*fs, "d/a", 1)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "bc");
        let mut s = String::new();
        Fs::reader_job(&*fs, "d/a", 0, Box::new(|| false))
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "abc");
        Fs::rename(&*fs, "d/a", "d/b", &|| false).unwrap();
        Fs::remove_file(&*fs, "d/b").unwrap();
        Fs::remove_dir(&*fs, "d").unwrap();
        assert_eq!(Fs::stat(&*fs, "d").unwrap_err().status, abi::NOT_FOUND);
        assert_eq!(
            <Vmware as Fs>::open("nope").err().unwrap().status,
            abi::INVALID
        );
    }
}

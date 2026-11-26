//! `vmware://` semantics over a [`Backend`]. `vmware://` lists the running VMs (folders) and
//! one `<vm>.connect.txt` each (guest IP + the sftp:// / smb:// addresses that open the guest in
//! Commander's own plugins). `vmware://[user@]<vm>` is that VM's guest: Windows guests show
//! drive letters (`C/Users` = `C:\Users`), others `/`. Reads copy the guest file into a private
//! temp dir first; writes go to a temp file, then to a guest temp name, then renamed in place.
//! An encrypted VM (vTPM) first asks for its VM encryption password, then the guest login.
use crate::backend::{Backend, Session, VM_PASSWORD, cancelled, is_vm_password};
use crate::config::Config;
use crate::discover::Vm;
use commander_plugin_abi::auth::Passphrase;
use commander_plugin_abi::glue::{Error, Item, PART_TRIES, Result, part_name, valid_name};
use commander_plugin_abi::stage::Stage;
use commander_plugin_abi::{self as abi, archive_url, url};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};
use zeroize::Zeroizing;

/// Running VMs (injected by tests).
pub type Vms = dyn Fn(&Config) -> Result<Vec<Vm>> + Send + Sync;
/// A backend for one VM, not signed in yet; the VM encryption password for an encrypted VM
/// (injected by tests).
pub type Connect = dyn Fn(&Vm, &Config, Option<&str>) -> Result<Box<dyn Backend>> + Send + Sync;

/// VM encryption passwords, per .vmx, for this process only (memory, wiped on drop). An entry
/// = the VM is known to be encrypted; `Some` = the password that opened it.
///
/// The host keeps one secret per mount (the last prompt's answer), so the VM password, asked
/// first, is kept here; the mount's secret then is the guest login.
#[derive(Default)]
pub struct VmKeys(Mutex<HashMap<PathBuf, Option<Zeroizing<String>>>>);

impl VmKeys {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<PathBuf, Option<Zeroizing<String>>>> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()) // plain map
    }

    /// (VM password asked or known, its password).
    fn get(&self, vmx: &std::path::Path) -> (bool, Option<Zeroizing<String>>) {
        match self.lock().get(vmx) {
            Some(pw) => (true, pw.clone()),
            None => (false, None),
        }
    }

    fn set(&self, vmx: &std::path::Path, pw: Option<Zeroizing<String>>) {
        self.lock().insert(vmx.to_path_buf(), pw);
    }
}

/// The process-wide [`VmKeys`] (each mount gets its own `Vmware`).
static KEYS: LazyLock<Arc<VmKeys>> = LazyLock::new(Arc::default);

/// Root entry with a VM's connect info.
const CONNECT: &str = ".connect.txt";

#[derive(Clone)]
pub struct Deps {
    pub cfg: Config,
    pub vms: Arc<Vms>,
    pub connect: Arc<Connect>,
    pub keys: Arc<VmKeys>,
}

pub struct Vmware {
    deps: Deps,
    /// `None` = the `vmware://` top (VM list).
    guest: Option<Guest>,
    /// Connect-file text per VM name: built by a listing (or the first stat / read), so size
    /// and content agree and a stat does not connect again.
    infos: Mutex<HashMap<String, Arc<[u8]>>>,
}

struct Guest {
    vm: Vm,
    sess: Session,
    /// Windows drive letters, probed once.
    drives: Mutex<Option<Vec<char>>>,
}

/// A mount-relative path inside a guest.
enum At {
    /// The Windows drive list.
    Drives,
    /// Absolute guest path; `root` = a drive root or `/` (never created, deleted or renamed).
    Path { guest: String, root: bool },
}

fn io(what: &str) -> impl Fn(std::io::Error) -> Error + '_ {
    move |e| Error::new(abi::IO, format!("vmware: {what}: {e}"))
}

fn unsupported(what: &str) -> Error {
    Error::new(abi::UNSUPPORTED, format!("vmware: {what}"))
}

/// Said at the login prompt when the backend is vmrun.
const VMRUN_WARN: &str =
    " (vmrun: the password is visible to other local processes; install VIX to avoid it)";

/// Ask the host for the guest login (`user` known: just its password, else `user:password`).
/// `backend`: its kind; vmrun gets [`VMRUN_WARN`].
fn need_login(vm: &str, user: Option<&str>, wrong: bool, backend: &str) -> Error {
    let why = if wrong {
        "wrong guest login"
    } else {
        "guest login needed"
    };
    let warn = match backend.starts_with("vmrun") {
        true => VMRUN_WARN,
        false => "",
    };
    let (msg, key) = match user {
        Some(u) => (
            format!("vmware: {why} for {u} on {vm}{warn}"),
            format!("{u}@{vm}"),
        ),
        None => (
            format!(
                "vmware: {why} for {vm}: type user:password (or set user in vmware.toml){warn}"
            ),
            format!("{vm} (user:password)"),
        ),
    };
    let x = Passphrase {
        msg,
        key,
        wrong,
        password: true,
    };
    Error::new(abi::NEED_PASSPHRASE, x.detail())
}

/// Ask the host for the VM encryption password of encrypted VM `vm` (`why`: the failed open).
fn need_vm_password(vm: &str, wrong: bool, why: Option<&Error>) -> Error {
    let detail = why.map_or(String::new(), |e| {
        format!(
            " {}",
            e.msg.strip_prefix(VM_PASSWORD).unwrap_or(&e.msg).trim()
        )
    });
    let x = Passphrase {
        msg: format!("{VM_PASSWORD} of {vm} (VM encryption password, not the guest login){detail}"),
        key: format!("{vm} (VM encryption password)"),
        wrong,
        password: true,
    };
    Error::new(abi::NEED_PASSPHRASE, x.detail())
}

/// `(user, vm)` of an authority: a VM name as is, else `user@name` (user `%XX`-decoded).
fn pick(auth: &str, vms: Vec<Vm>) -> Result<(Option<String>, Vm)> {
    let find = |name: &str| vms.iter().find(|v| v.name == name).cloned();
    if let Some(v) = find(auth) {
        return Ok((None, v));
    }
    let (user, vm) = match auth.split_once('@') {
        Some((u, n)) => (Some(url::pct_decode(u).ok_or_else(bad_user)?), n),
        None => (None, auth),
    };
    if user
        .as_deref()
        .is_some_and(|u| u.is_empty() || u.contains(char::is_control))
    {
        return Err(bad_user());
    }
    let v = find(vm).ok_or_else(|| {
        Error::new(
            abi::NOT_FOUND,
            format!("vmware: no running VM named {vm:?} (vmware:// lists them)"),
        )
    })?;
    Ok((user, v))
}

fn bad_user() -> Error {
    Error::new(abi::INVALID, "vmware: bad user name in the address")
}

/// `name` next to guest path `p` (same folder).
fn sibling(p: &str, sep: char, name: &str) -> String {
    let dir = p.rsplit_once(sep).map_or("", |(d, _)| d);
    format!("{dir}{sep}{name}")
}

fn exists_err(b: &mut dyn Backend, p: &str) -> Result<()> {
    match b.exists(p)? {
        true => Err(Error::new(abi::EXISTS, format!("vmware: {p}: exists"))),
        false => Ok(()),
    }
}

/// A Windows file name the guest can create as is: none of `\ : * ? " < > |` or control
/// characters (`:` would name an NTFS alternate data stream), not ending in `.` or space.
fn win_name_ok(c: &str) -> bool {
    !c.chars().any(|ch| ch < ' ' || "\\:*?\"<>|".contains(ch)) && !c.ends_with(['.', ' '])
}

/// The connect file of `vm`.
fn connect_text(vm: &Vm, backend: &str, ip: Result<String>) -> String {
    let mut t = format!(
        "VM: {}\r\nVMX: {}\r\nBackend: {backend}\r\n",
        vm.name,
        vm.vmx.display()
    );
    if vm.encrypted {
        t += "Encrypted VM: yes (opening its folder asks for the VM encryption password, then the guest login)\r\n";
    }
    match ip {
        Ok(ip) => {
            let host = if ip.contains(':') {
                format!("[{ip}]")
            } else {
                ip.clone()
            };
            t += &format!(
                "Guest IP: {ip}\r\n\r\nOpen the guest in Commander (type it in the path bar, or `cd <address>`):\r\n  sftp://<user>@{host}/   needs an SSH server in the guest\r\n  smb://<user>@{host}/    needs file sharing in the guest (Windows / Samba)\r\n"
            );
        }
        Err(e) => {
            t += &format!(
                "Guest IP: unknown ({}): is VMware Tools running?\r\n",
                e.msg
            )
        }
    }
    t += "\r\nBrowse the guest itself: open the folder of the same name (guest login, VMware Tools needed).\r\n";
    t
}

impl Vmware {
    pub fn open(config: &str) -> Result<Self> {
        let cfg = crate::config::load().map_err(|m| Error::new(abi::INVALID, m))?;
        let deps = Deps {
            cfg,
            vms: Arc::new(crate::running_vms),
            connect: Arc::new(crate::connect),
            keys: Arc::clone(&KEYS),
        };
        Self::open_with(config, deps)
    }

    /// `config` = `vmware://<authority>`; a secret after `archive_url::SECRET_SEP` = what the
    /// user typed at the last prompt: the VM encryption password while an encrypted VM has
    /// none that worked yet, else the guest login (the password, or `user:password`).
    pub fn open_with(config: &str, deps: Deps) -> Result<Self> {
        let (config, secret) = archive_url::split_secret(config);
        let auth = config
            .strip_prefix("vmware://")
            .ok_or_else(|| Error::new(abi::INVALID, "vmware: mount must be vmware://..."))?;
        if auth.is_empty() {
            return Ok(Self::new(deps, None));
        }
        let (user, vm) = pick(auth, (deps.vms)(&deps.cfg)?)?;
        let user = user.or_else(|| deps.cfg.user_for(&vm.name).map(String::from));
        let mut secret = secret;
        // `asked`: our last prompt for this VM was its VM password (entry without one).
        let (asked, mut vm_pw) = deps.keys.get(&vm.vmx);
        if (vm.encrypted || asked) && vm_pw.is_none() {
            // Only the answer to our VM password prompt is a VM password: a guest login the
            // host replays (a new session) is never tried as one.
            match secret.take() {
                Some(pw) if asked => vm_pw = Some(Zeroizing::new(pw.to_owned())),
                _ => {
                    deps.keys.set(&vm.vmx, None);
                    return Err(need_vm_password(&vm.name, false, None));
                }
            }
        }
        // Backend first (no login needed): it opens the VM, and the prompt says when it is
        // vmrun.
        let (connect, cfg, v) = (Arc::clone(&deps.connect), deps.cfg.clone(), vm.clone());
        let pw = vm_pw.clone();
        let started = Session::start(move || connect(&v, &cfg, pw.as_deref().map(String::as_str)));
        let sess = match started {
            Ok(s) => s,
            Err(e) if is_vm_password(&e) => {
                deps.keys.set(&vm.vmx, None);
                return Err(need_vm_password(&vm.name, vm_pw.is_some(), Some(&e)));
            }
            Err(e) => return Err(e),
        };
        if vm_pw.is_some() {
            deps.keys.set(&vm.vmx, vm_pw.clone());
        }
        let kind = sess.run(|b| Ok(b.kind().to_owned()))?;
        let ask = |user: Option<&str>, wrong| need_login(&vm.name, user, wrong, &kind);
        let Some(secret) = secret else {
            return Err(ask(user.as_deref(), false));
        };
        let (who, pass) = match (&user, secret.split_once(':')) {
            (Some(u), _) => (u.clone(), Zeroizing::new(secret.to_owned())),
            (None, Some((u, p))) if !u.is_empty() => (u.to_owned(), Zeroizing::new(p.to_owned())),
            (None, _) => return Err(ask(None, true)),
        };
        // Sign in now: a wrong login fails the mount (and asks again), not a listing.
        sess.run(move |b| b.login(&who, &pass)).map_err(|e| {
            if is_vm_password(&e) {
                // vmrun learns of the VM password only now.
                deps.keys.set(&vm.vmx, None);
                return need_vm_password(&vm.name, vm_pw.is_some(), Some(&e));
            }
            match e.status {
                abi::AUTH => ask(user.as_deref(), true),
                _ => e,
            }
        })?;
        let guest = Guest {
            vm,
            sess,
            drives: Mutex::new(None),
        };
        Ok(Self::new(deps, Some(guest)))
    }

    fn new(deps: Deps, guest: Option<Guest>) -> Self {
        Self {
            deps,
            guest,
            infos: Mutex::new(HashMap::new()),
        }
    }

    fn guest(&self) -> Result<&Guest> {
        self.guest
            .as_ref()
            .ok_or_else(|| unsupported("not supported on the VM list (open a VM first)"))
    }

    fn sep(&self) -> char {
        match self.guest.as_ref().is_some_and(|g| g.vm.windows) {
            true => '\\',
            false => '/',
        }
    }

    fn at(&self, path: &str) -> Result<At> {
        let g = self.guest()?;
        if !g.vm.windows {
            return Ok(At::Path {
                guest: format!("/{path}"),
                root: path.is_empty(),
            });
        }
        if path.is_empty() {
            return Ok(At::Drives);
        }
        let (drive, rest) = path.split_once('/').unwrap_or((path, ""));
        let d = drive
            .chars()
            .next()
            .filter(|c| c.is_ascii_alphabetic() && drive.len() == 1);
        let d =
            d.ok_or_else(|| Error::new(abi::NOT_FOUND, format!("vmware: {drive:?} is no drive")))?;
        if let Some(bad) = rest.split('/').find(|c| !win_name_ok(c)) {
            return Err(Error::new(
                abi::INVALID,
                format!("vmware: {bad:?} is not a valid Windows file name"),
            ));
        }
        Ok(At::Path {
            guest: format!("{}:\\{}", d.to_ascii_uppercase(), rest.replace('/', "\\")),
            root: rest.is_empty(),
        })
    }

    /// Guest path of an entry that may be changed (not the drive list or a root).
    fn entry(&self, path: &str, what: &str) -> Result<String> {
        match self.at(path)? {
            At::Path { guest, root: false } => Ok(guest),
            _ => Err(unsupported(&format!(
                "{what}: not on a drive or the root itself"
            ))),
        }
    }

    /// The VM list; each VM's connect text is built (and cached) here, so its size is real.
    fn top_items(&self, cancel: &dyn Fn() -> bool) -> Result<Vec<Item>> {
        let vms = (self.deps.vms)(&self.deps.cfg)?;
        let mut out = Vec::with_capacity(vms.len() * 2);
        for v in vms {
            if cancel() {
                return Err(cancelled());
            }
            let text = self.connect_bytes(&v);
            let info = Item {
                kind: abi::KIND_FILE,
                size: text.len() as u64,
                ..Item::dir(format!("{}{CONNECT}", v.name))
            };
            self.infos_lock().insert(v.name.clone(), text);
            out.extend([Item::dir(v.name), info]);
        }
        Ok(out)
    }

    fn infos_lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<[u8]>>> {
        self.infos.lock().unwrap_or_else(|p| p.into_inner()) // plain cache
    }

    /// The connect file's text, if `name` is one of a running VM (cached per VM).
    fn connect_info(&self, name: &str) -> Result<Option<Arc<[u8]>>> {
        let Some(vm) = name.strip_suffix(CONNECT) else {
            return Ok(None);
        };
        if let Some(t) = self.infos_lock().get(vm) {
            return Ok(Some(Arc::clone(t)));
        }
        let vms = (self.deps.vms)(&self.deps.cfg)?;
        let Some(v) = vms.into_iter().find(|v| v.name == vm) else {
            return Ok(None);
        };
        let text = self.connect_bytes(&v);
        self.infos_lock().insert(v.name, Arc::clone(&text));
        Ok(Some(text))
    }

    fn connect_bytes(&self, vm: &Vm) -> Arc<[u8]> {
        let (_, pw) = self.deps.keys.get(&vm.vmx);
        let pw = pw.as_deref().map(String::as_str);
        let text = match (self.deps.connect)(vm, &self.deps.cfg, pw) {
            Ok(mut b) => {
                let ip = b.ip();
                connect_text(vm, b.kind(), ip)
            }
            Err(e) => connect_text(vm, "none", Err(e)),
        };
        text.into_bytes().into()
    }

    fn drives(&self, cancel: &dyn Fn() -> bool) -> Result<Vec<char>> {
        let g = self.guest()?;
        let mut cache = g.drives.lock().unwrap_or_else(|p| p.into_inner()); // plain data
        if let Some(d) = cache.as_ref() {
            return Ok(d.clone());
        }
        let found = match &self.deps.cfg.drives {
            Some(d) => d.chars().map(|c| c.to_ascii_uppercase()).collect(),
            None => g.sess.call(cancel, |b, abort| {
                let mut v = Vec::new();
                for c in 'C'..='Z' {
                    if abort() {
                        return Err(cancelled());
                    }
                    // An empty CD drive or a broken mapping fails its stat: just not listed.
                    if b.stat(&format!("{c}:\\"))
                        .is_ok_and(|i| i.kind == abi::KIND_DIR)
                    {
                        v.push(c);
                    }
                }
                Ok(v)
            })?,
        };
        *cache = Some(found.clone());
        Ok(found)
    }

    pub fn list(self: &Arc<Self>, dir: &str) -> Result<Listing> {
        if self.guest.is_none() {
            if !dir.is_empty() {
                return Err(unsupported("open a VM first"));
            }
            let me = Arc::clone(self);
            return Ok(Listing::lazy(move |c| me.top_items(c)));
        }
        let me = Arc::clone(self);
        Ok(match self.at(dir)? {
            At::Drives => Listing::lazy(move |c| {
                Ok(me
                    .drives(c)?
                    .into_iter()
                    .map(|d| Item::dir(d.to_string()))
                    .collect())
            }),
            At::Path { guest, .. } => Listing::lazy(move |c| {
                me.guest()?
                    .sess
                    .call(c, move |b, abort| b.list(&guest, abort))
            }),
        })
    }

    pub fn stat(&self, path: &str) -> Result<Item> {
        if self.guest.is_none() {
            if path.is_empty() {
                return Ok(Item::dir(""));
            }
            if let Some(t) = self.connect_info(path)? {
                return Ok(Item {
                    kind: abi::KIND_FILE,
                    size: t.len() as u64,
                    ..Item::dir("")
                });
            }
            let vms = (self.deps.vms)(&self.deps.cfg)?;
            return match vms.iter().any(|v| v.name == path) {
                true => Ok(Item::dir("")),
                false => Err(Error::new(
                    abi::NOT_FOUND,
                    format!("vmware: no running VM {path:?}"),
                )),
            };
        }
        match self.at(path)? {
            At::Drives => Ok(Item::dir("")),
            At::Path { guest, .. } => self.guest()?.sess.run(move |b| b.stat(&guest)),
        }
    }

    pub fn reader(
        &self,
        path: &str,
        offset: u64,
        cancel: &dyn Fn() -> bool,
    ) -> Result<Box<dyn Read + Send>> {
        if self.guest.is_none() {
            let t = self
                .connect_info(path)?
                .ok_or_else(|| unsupported("read: open a VM first"))?;
            let mut c = Cursor::new(t);
            c.set_position(offset);
            return Ok(Box::new(c));
        }
        let p = self.entry(path, "read")?;
        let stage = Stage::new("cmdr-vmware").map_err(io("temp dir"))?;
        // The worker owns the stage until the copy is done: a cancelled read cleans up there.
        let (stage, mut f) = self.guest()?.sess.call(cancel, move |b, _| {
            let host = stage.path().join("f");
            b.get(&p, &host)?;
            let f = File::open(&host).map_err(io("temp file"))?;
            Ok((stage, f))
        })?;
        f.seek(SeekFrom::Start(offset)).map_err(io("temp file"))?;
        Ok(Box::new(Download { f, _stage: stage }))
    }

    pub fn writer(self: &Arc<Self>, path: &str, overwrite: bool) -> Result<Writer> {
        let dest = self.entry(path, "write")?;
        if !overwrite {
            let d = dest.clone();
            self.guest()?.sess.run(move |b| exists_err(b, &d))?;
        }
        let stage = Stage::new("cmdr-vmware").map_err(io("temp dir"))?;
        let f = stage.file("up").map_err(io("temp file"))?;
        Ok(Writer {
            f: Some(f),
            stage,
            fs: Arc::clone(self),
            dest,
            overwrite,
        })
    }

    pub fn mkdir(&self, path: &str) -> Result<()> {
        let p = self.entry(path, "create folder")?;
        self.guest()?.sess.run(move |b| {
            exists_err(b, &p)?;
            b.mkdir(&p)
        })
    }

    pub fn remove_file(&self, path: &str) -> Result<()> {
        let p = self.entry(path, "delete")?;
        self.guest()?.sess.run(move |b| b.remove_file(&p))
    }

    pub fn remove_dir(&self, path: &str) -> Result<()> {
        let p = self.entry(path, "delete")?;
        // The guest deletes a whole tree: only ever an empty folder here.
        self.guest()?.sess.run(move |b| {
            if !b.list(&p, &|| false)?.is_empty() {
                return Err(Error::new(
                    abi::NOT_EMPTY,
                    format!("vmware: {p}: not empty (hidden entries count too)"),
                ));
            }
            b.remove_dir(&p)
        })
    }

    pub fn rename(&self, from: &str, to: &str, cancel: &dyn Fn() -> bool) -> Result<()> {
        let (f, t) = (self.entry(from, "rename")?, self.entry(to, "rename")?);
        let windows = self.guest()?.vm.windows;
        self.guest()?.sess.call(cancel, move |b, abort| {
            // RULES: never a silent replace. A case-only rename on a Windows guest finds the
            // file itself: not a clash.
            if !(windows && f.to_lowercase() == t.to_lowercase()) {
                exists_err(b, &t)?;
            }
            if abort() {
                return Err(cancelled());
            }
            b.rename(&f, &t)
        })
    }
}

/// A listing fetched on the first `next_batch` (that one has the cancel flag).
type Fetch = Box<dyn FnOnce(&dyn Fn() -> bool) -> Result<Vec<Item>> + Send>;

pub struct Listing {
    fetch: Option<Fetch>,
    buf: std::vec::IntoIter<Item>,
}

impl Listing {
    fn lazy(f: impl FnOnce(&dyn Fn() -> bool) -> Result<Vec<Item>> + Send + 'static) -> Self {
        Self {
            fetch: Some(Box::new(f)),
            buf: Vec::new().into_iter(),
        }
    }

    /// Up to `cap` items; empty = done. Host-unsafe names are skipped.
    pub fn next_batch(&mut self, cap: usize, cancel: &dyn Fn() -> bool) -> Result<Vec<Item>> {
        if let Some(f) = self.fetch.take() {
            if cancel() {
                return Err(cancelled());
            }
            let mut v = f(cancel)?;
            v.retain(|i| valid_name(&i.name));
            self.buf = v.into_iter();
        }
        Ok(self.buf.by_ref().take(cap).collect())
    }
}

/// A guest file copied to the host; the temp dir goes with it.
struct Download {
    f: File,
    _stage: Stage,
}

impl Read for Download {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.f.read(buf)
    }
}

/// Upload: bytes go to a private temp file; `finish` copies it to a guest temp name next to the
/// target and renames it in place. Dropped unfinished = only the host temp, removed.
pub struct Writer {
    f: Option<File>,
    stage: Stage,
    fs: Arc<Vmware>,
    dest: String,
    overwrite: bool,
}

impl Writer {
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        let f = self
            .f
            .as_mut()
            .ok_or_else(|| Error::new(abi::INTERNAL, "vmware: closed"))?;
        f.write_all(data).map_err(io("temp file"))
    }

    pub fn finish(mut self) -> Result<()> {
        let f = self
            .f
            .take()
            .ok_or_else(|| Error::new(abi::INTERNAL, "vmware: closed"))?;
        f.sync_all().map_err(io("temp file"))?;
        drop(f); // closed before the guest copy reads it
        let (sep, dest, overwrite) = (self.fs.sep(), self.dest, self.overwrite);
        let host = self.stage.path().join("up");
        // The stage lives until this returns (its drop removes the host temp).
        let stage = self.stage;
        let r = self
            .fs
            .guest()?
            .sess
            .run(move |b| upload(b, &host, &dest, sep, overwrite));
        drop(stage);
        r
    }
}

/// Free guest temp name next to `dest`.
fn free_temp(b: &mut dyn Backend, dest: &str, sep: char) -> Result<String> {
    let name = dest.rsplit(sep).next().unwrap_or(dest);
    for _ in 0..PART_TRIES {
        let tmp = sibling(dest, sep, &part_name(name));
        if !b.exists(&tmp)? {
            return Ok(tmp);
        }
    }
    Err(Error::new(
        abi::EXISTS,
        format!("vmware: {dest}: no free temp name"),
    ))
}

/// Host file -> guest temp -> `dest`. A failed upload never loses the old file: on a POSIX
/// guest the rename replaces it atomically; on Windows (no replacing rename) the old file is
/// renamed aside first and put back if the final rename fails.
fn upload(
    b: &mut dyn Backend,
    host: &std::path::Path,
    dest: &str,
    sep: char,
    overwrite: bool,
) -> Result<()> {
    let tmp = free_temp(b, dest, sep)?;
    if let Err(e) = b.put(host, &tmp) {
        let _ = b.remove_file(&tmp); // a partial copy
        return Err(e);
    }
    let mut keep_tmp = false;
    let r = place(b, &tmp, dest, sep, overwrite, &mut keep_tmp);
    if r.is_err() && !keep_tmp {
        let _ = b.remove_file(&tmp);
    }
    r
}

/// Renames the uploaded `tmp` to `dest`. Sets `keep_tmp` when `tmp` holds the only copy of the
/// new data (the old file could not be put back either).
fn place(
    b: &mut dyn Backend,
    tmp: &str,
    dest: &str,
    sep: char,
    overwrite: bool,
    keep_tmp: &mut bool,
) -> Result<()> {
    // RULES: check the target right before the rename (not only at open).
    if !b.exists(dest)? {
        return b.rename(tmp, dest);
    }
    if !overwrite {
        return Err(Error::new(abi::EXISTS, format!("vmware: {dest}: exists")));
    }
    if sep == '/' {
        match b.rename(tmp, dest) {
            // A guest whose rename refuses to replace: the Windows way below.
            Err(e) if e.status == abi::EXISTS => {}
            r => return r,
        }
    }
    let old = free_temp(b, dest, sep)?;
    b.rename(dest, &old)?;
    let Err(e) = b.rename(tmp, dest) else {
        let _ = b.remove_file(&old); // best effort: the new file is in place
        return Ok(());
    };
    if b.rename(&old, dest).is_err() {
        *keep_tmp = true;
        return Err(Error::new(
            e.status,
            format!(
                "{}; old file kept as {old}, new data as {tmp} (rename them by hand)",
                e.msg
            ),
        ));
    }
    Err(e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{Fake, State};
    use commander_plugin_abi::Status;
    use std::path::PathBuf;

    fn vm(name: &str, windows: bool) -> Vm {
        Vm {
            name: name.into(),
            vmx: PathBuf::from(format!("/vms/{name}.vmx")),
            windows,
            encrypted: false,
        }
    }

    fn deps(fake: &Fake, cfg: Config) -> Deps {
        let f = fake.clone();
        Deps {
            cfg,
            vms: Arc::new(|_| Ok(vec![vm("lin", false), vm("win", true), vm("a@b", false)])),
            connect: Arc::new(move |_, _, _| Ok(Box::new(f.clone()) as Box<dyn Backend>)),
            keys: Arc::default(),
        }
    }

    /// One encrypted Windows VM "enc" whose VM password is "vmpw" (any backend kind).
    fn enc_deps(f: &Fake, from_vmx: bool, kind: &'static str) -> Deps {
        let mut fake = f.clone();
        fake.kind = kind;
        Deps {
            vms: Arc::new(move |_| {
                Ok(vec![Vm {
                    encrypted: from_vmx,
                    ..vm("enc", true)
                }])
            }),
            connect: Arc::new(move |_, _, pw| match pw {
                Some("vmpw") => Ok(Box::new(fake.clone()) as Box<dyn Backend>),
                _ => Err(crate::backend::vm_password_error(
                    "VIX connect: The password is incorrect, VIX error 17005",
                )),
            }),
            ..deps(f, Config::default())
        }
    }

    fn prompt(r: Result<Vmware>) -> Passphrase {
        let e = r.err().unwrap();
        assert_eq!(e.status, abi::NEED_PASSPHRASE, "{}", e.msg);
        for secret in ["vmpw", "badpw", "guestpw"] {
            assert!(!e.msg.contains(secret), "a password in an error: {}", e.msg);
        }
        Passphrase::parse(&e.msg)
    }

    #[test]
    fn encrypted_vm_asks_the_vm_password_then_the_guest_login() {
        for from_vmx in [true, false] {
            let f = Fake::windows();
            let d = enc_deps(&f, from_vmx, "VIX (x)");
            let open = |c: &str| Vmware::open_with(c, d.clone());
            // 1. No secret: the VM password (an .vmx without keySafe learns it from VIX).
            let p = prompt(open("vmware://me@enc"));
            assert_eq!(p.key, "enc (VM encryption password)", "{from_vmx}");
            assert!(
                p.msg.contains("encrypted VM: enter the VM password"),
                "{}",
                p.msg
            );
            assert!(p.msg.contains("not the guest login"), "{}", p.msg);
            assert!(!p.wrong, "{from_vmx}: first ask");
            if !from_vmx {
                assert!(
                    p.msg.contains("VIX error 17005"),
                    "real VIX text: {}",
                    p.msg
                );
            }
            // 2. A wrong VM password: asked again.
            let p = prompt(open("vmware://me@enc\nbadpw"));
            assert!(p.wrong && p.key.contains("VM encryption password"), "{p:?}");
            assert!(p.msg.contains("VIX error 17005"), "{}", p.msg);
            // 3. The right one: kept; now the guest login.
            let p = prompt(open("vmware://me@enc\nvmpw"));
            assert_eq!((p.key.as_str(), p.wrong), ("me@enc", false));
            // 4. The guest login (the mount's secret now): a wrong one re-asks the login only.
            let p = prompt(open("vmware://me@enc\nbadpw"));
            assert_eq!((p.key.as_str(), p.wrong), ("me@enc", true));
            let fs = Arc::new(open("vmware://me@enc\npw").unwrap());
            assert_eq!(names(&fs, "").len(), 2, "C and E");
            assert_eq!(f.st.lock().unwrap().user.as_deref(), Some("me"));
            // The connect file opens with the kept password.
            let top = Vmware::open_with("vmware://", d.clone()).unwrap();
            let t = read(&top, "enc.connect.txt", 0);
            assert!(t.contains("Guest IP: 192.0.2.7"), "{t}");
            assert_eq!(t.contains("Encrypted VM: yes"), from_vmx, "{t}");
        }
    }

    #[test]
    fn a_replayed_guest_login_is_not_tried_as_the_vm_password() {
        let f = Fake::windows();
        let tried = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
        let t = Arc::clone(&tried);
        let inner = enc_deps(&f, true, "VIX (x)");
        let c = Arc::clone(&inner.connect);
        let d = Deps {
            connect: Arc::new(move |v, cfg, pw| {
                t.lock().unwrap().push(pw.map(String::from));
                c(v, cfg, pw)
            }),
            ..inner
        };
        // A new process: no VM password yet; the host replays the remembered guest login.
        let p = prompt(Vmware::open_with("vmware://me@enc\nguestpw", d.clone()));
        assert!(
            p.key.contains("VM encryption password") && !p.wrong,
            "{p:?}"
        );
        assert!(
            tried.lock().unwrap().is_empty(),
            "guest password never used as VM password"
        );
        // Our own prompt's answer is.
        let p = prompt(Vmware::open_with("vmware://me@enc\nvmpw", d));
        assert_eq!(p.key, "me@enc");
        assert_eq!(*tried.lock().unwrap(), [Some("vmpw".to_string())]);
    }

    #[test]
    fn a_changed_vm_password_is_asked_again() {
        let f = Fake::windows();
        let d = enc_deps(&f, true, "VIX (x)");
        d.keys.set(
            &PathBuf::from("/vms/enc.vmx"),
            Some(Zeroizing::new("old".into())),
        );
        let p = prompt(Vmware::open_with("vmware://me@enc\npw", d.clone()));
        assert!(p.wrong && p.key.contains("VM encryption password"), "{p:?}");
        assert_eq!(
            d.keys.get(std::path::Path::new("/vms/enc.vmx")).1,
            None,
            "forgotten"
        );
        // Without a VM password the connect file says why (the backend's error text).
        let top = Vmware::open_with("vmware://", d).unwrap();
        let t = read(&top, "enc.connect.txt", 0);
        assert!(
            t.contains("Backend: none") && t.contains("VIX error 17005"),
            "{t}"
        );
    }

    #[test]
    fn vmrun_learns_of_the_vm_password_at_login() {
        // vmrun opens nothing up front: its login run reports the encryption.
        let f = Fake::windows();
        let mut vr = f.clone();
        vr.kind = "vmrun";
        struct Enc(Fake);
        impl Backend for Enc {
            fn kind(&self) -> &str {
                "vmrun"
            }
            fn login(&mut self, _: &str, _: &str) -> Result<()> {
                Err(crate::backend::vm_password_error(
                    "vmrun x: The VM is encrypted",
                ))
            }
            fn list(&mut self, d: &str, a: &dyn Fn() -> bool) -> Result<Vec<Item>> {
                self.0.list(d, a)
            }
            fn stat(&mut self, p: &str) -> Result<Item> {
                self.0.stat(p)
            }
            fn get(&mut self, g: &str, h: &std::path::Path) -> Result<()> {
                self.0.get(g, h)
            }
            fn put(&mut self, h: &std::path::Path, g: &str) -> Result<()> {
                self.0.put(h, g)
            }
            fn mkdir(&mut self, p: &str) -> Result<()> {
                self.0.mkdir(p)
            }
            fn remove_file(&mut self, p: &str) -> Result<()> {
                self.0.remove_file(p)
            }
            fn remove_dir(&mut self, p: &str) -> Result<()> {
                self.0.remove_dir(p)
            }
            fn rename(&mut self, f: &str, t: &str) -> Result<()> {
                self.0.rename(f, t)
            }
            fn ip(&mut self) -> Result<String> {
                self.0.ip()
            }
        }
        let d = Deps {
            connect: Arc::new(move |_, _, _| Ok(Box::new(Enc(vr.clone())) as Box<dyn Backend>)),
            ..deps(&f, Config::default())
        };
        let p = prompt(Vmware::open_with("vmware://me@win\nguestpw", d.clone()));
        assert!(
            p.key.contains("VM encryption password") && !p.wrong,
            "{p:?}"
        );
        let (known, pw) = d.keys.get(std::path::Path::new("/vms/win.vmx"));
        assert!(known && pw.is_none());
    }

    fn mount(fake: &Fake, url: &str) -> Arc<Vmware> {
        Arc::new(Vmware::open_with(url, deps(fake, Config::default())).unwrap())
    }

    fn st(r: Result<impl Sized>) -> Status {
        r.err().map_or(abi::OK, |e| e.status)
    }

    fn names(fs: &Arc<Vmware>, dir: &str) -> Vec<(String, u32)> {
        let mut l = fs.list(dir).unwrap();
        let mut v: Vec<_> = l
            .next_batch(1000, &|| false)
            .unwrap()
            .into_iter()
            .map(|i| (i.name, i.kind))
            .collect();
        assert!(l.next_batch(10, &|| false).unwrap().is_empty());
        v.sort();
        v
    }

    fn put(fs: &Arc<Vmware>, p: &str, data: &[u8], overwrite: bool) -> Result<()> {
        let mut w = fs.writer(p, overwrite)?;
        w.write(data)?;
        w.finish()
    }

    fn read(fs: &Vmware, p: &str, off: u64) -> String {
        let mut s = String::new();
        fs.reader(p, off, &|| false)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        s
    }

    fn paths(s: &Arc<Mutex<State>>) -> Vec<String> {
        s.lock().unwrap().paths()
    }

    #[test]
    fn top_lists_vms_and_connect_files() {
        let f = Fake::posix();
        let fs = mount(&f, "vmware://");
        let n = names(&fs, "");
        assert!(n.contains(&("lin".into(), abi::KIND_DIR)));
        assert!(n.contains(&("lin.connect.txt".into(), abi::KIND_FILE)));
        assert_eq!(n.len(), 6);
        assert_eq!(fs.stat("").unwrap().kind, abi::KIND_DIR);
        assert_eq!(fs.stat("win").unwrap().kind, abi::KIND_DIR);
        assert_eq!(st(fs.stat("zz")), abi::NOT_FOUND);
        let text = read(&fs, "lin.connect.txt", 0);
        assert!(text.contains("sftp://<user>@192.0.2.7/"), "{text}");
        assert!(text.contains("Backend: fake"));
        assert_eq!(fs.stat("lin.connect.txt").unwrap().size, text.len() as u64);
        assert_eq!(read(&fs, "lin.connect.txt", 4), &text[4..]);
        assert_eq!(st(fs.stat("zz.connect.txt")), abi::NOT_FOUND);
        assert_eq!(
            st(fs.reader("zz.connect.txt", 0, &|| false)),
            abi::UNSUPPORTED
        );
        assert_eq!(st(fs.list("lin")), abi::UNSUPPORTED);
        assert_eq!(st(fs.mkdir("x")), abi::UNSUPPORTED);
        assert_eq!(st(fs.writer("x", true)), abi::UNSUPPORTED);
        assert_eq!(st(fs.rename("a", "b", &|| false)), abi::UNSUPPORTED);
        assert_eq!(
            st(Vmware::open_with("smb://x", deps(&f, Config::default()))),
            abi::INVALID
        );
    }

    #[test]
    fn connect_info_is_built_once_per_listing() {
        let f = Fake::posix();
        let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (f2, n2) = (f.clone(), Arc::clone(&n));
        let d = Deps {
            connect: Arc::new(move |_, _, _| {
                n2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(Box::new(f2.clone()) as Box<dyn Backend>)
            }),
            ..deps(&f, Config::default())
        };
        let fs = Arc::new(Vmware::open_with("vmware://", d).unwrap());
        let calls = || n.load(std::sync::atomic::Ordering::Relaxed);
        let mut l = fs.list("").unwrap();
        let items = l.next_batch(100, &|| false).unwrap();
        assert_eq!(calls(), 3, "one connect per VM");
        let info = items.iter().find(|i| i.name == "lin.connect.txt").unwrap();
        let text = read(&fs, "lin.connect.txt", 0);
        assert_eq!(info.size, text.len() as u64, "listed size = content");
        assert_eq!(fs.stat("lin.connect.txt").unwrap().size, info.size);
        assert_eq!(calls(), 3, "stat / read reuse the text");
        assert_eq!(
            st(fs.list("").unwrap().next_batch(5, &|| true)),
            abi::CANCELLED
        );
        let mut l = fs.list("").unwrap();
        let n = std::sync::atomic::AtomicUsize::new(0);
        let late = || n.fetch_add(1, std::sync::atomic::Ordering::Relaxed) > 0;
        assert_eq!(st(l.next_batch(5, &late)), abi::CANCELLED, "between VMs");
    }

    #[test]
    fn connect_text_forms() {
        let v = vm("x", false);
        let t = connect_text(&v, "VIX", Ok("fe80::1".into()));
        assert!(t.contains("smb://<user>@[fe80::1]/"), "{t}");
        let t = connect_text(&v, "vmrun", Err(Error::new(abi::IO, "no tools")));
        assert!(
            t.contains("unknown (no tools)") && !t.contains("sftp://"),
            "{t}"
        );
        let down = Deps {
            connect: Arc::new(|_, _, _| Err(Error::new(abi::IO, "no vmware"))),
            ..deps(&Fake::posix(), Config::default())
        };
        let fs = Vmware::open_with("vmware://", down).unwrap();
        assert!(read(&fs, "lin.connect.txt", 0).contains("Backend: none"));
    }

    #[test]
    fn login_prompts() {
        let f = Fake::posix();
        let d = || deps(&f, Config::default());
        let ask = |r: Result<Vmware>| {
            let e = r.err().unwrap();
            assert_eq!(e.status, abi::NEED_PASSPHRASE, "{}", e.msg);
            Passphrase::parse(&e.msg)
        };
        let p = ask(Vmware::open_with("vmware://lin", d()));
        assert!(
            p.password && !p.wrong && p.key == "lin (user:password)",
            "{p:?}"
        );
        let p = ask(Vmware::open_with("vmware://me@lin", d()));
        assert_eq!((p.key.as_str(), p.wrong), ("me@lin", false));
        let p = ask(Vmware::open_with("vmware://me@lin\nbad", d()));
        assert_eq!((p.key.as_str(), p.wrong), ("me@lin", true));
        let p = ask(Vmware::open_with("vmware://lin\nnocolon", d()));
        assert!(p.wrong && p.key.contains("user:password"));
        let p = ask(Vmware::open_with("vmware://lin\nme:bad", d()));
        assert!(
            p.wrong && p.key.contains("user:password"),
            "re-ask user too"
        );
        Vmware::open_with("vmware://lin\nme:pw", d()).unwrap();
        assert_eq!(f.st.lock().unwrap().user.as_deref(), Some("me"));
        Vmware::open_with("vmware://you%40corp@lin\npw", d()).unwrap();
        assert_eq!(f.st.lock().unwrap().user.as_deref(), Some("you@corp"));
        Vmware::open_with("vmware://a@b\nz:pw", d()).unwrap(); // a VM name with `@`
        let cfg = Config {
            user: Some("cfguser".into()),
            ..Config::default()
        };
        let p = ask(Vmware::open_with("vmware://lin", deps(&f, cfg.clone())));
        assert_eq!(p.key, "cfguser@lin");
        Vmware::open_with("vmware://lin\npw", deps(&f, cfg)).unwrap();
        assert_eq!(f.st.lock().unwrap().user.as_deref(), Some("cfguser"));
        assert!(!p.msg.contains("vmrun"), "{}", p.msg);
        let mut vr = f.clone();
        vr.kind = "vmrun (VIX unavailable: x)";
        let via_vmrun = Deps {
            connect: Arc::new(move |_, _, _| Ok(Box::new(vr.clone()) as Box<dyn Backend>)),
            ..d()
        };
        let p = ask(Vmware::open_with("vmware://me@lin", via_vmrun.clone()));
        assert!(
            p.msg.contains("visible to other local processes"),
            "{}",
            p.msg
        );
        let p = ask(Vmware::open_with("vmware://me@lin\nbad", via_vmrun));
        assert!(p.wrong && p.msg.contains("vmrun"), "{}", p.msg);
        assert_eq!(st(Vmware::open_with("vmware://nope", d())), abi::NOT_FOUND);
        assert_eq!(st(Vmware::open_with("vmware://%zz@lin", d())), abi::INVALID);
        assert_eq!(st(Vmware::open_with("vmware://@lin", d())), abi::INVALID);
        let down = Deps {
            connect: Arc::new(|_, _, _| Err(Error::new(abi::IO, "no vmware"))),
            ..d()
        };
        assert_eq!(st(Vmware::open_with("vmware://lin\nme:pw", down)), abi::IO);
    }

    #[test]
    fn posix_roundtrip() {
        let f = Fake::posix();
        let fs = mount(&f, "vmware://lin\nme:pw");
        assert_eq!(fs.stat("").unwrap().kind, abi::KIND_DIR);
        fs.mkdir("d").unwrap();
        assert_eq!(st(fs.mkdir("d")), abi::EXISTS);
        put(&fs, "d/a.txt", b"hello world", false).unwrap();
        f.st.lock().unwrap().put("/d/bad:name", b"");
        assert_eq!(
            names(&fs, "d"),
            [("a.txt".into(), abi::KIND_FILE)],
            "host-unsafe skipped"
        );
        let i = fs.stat("d/a.txt").unwrap();
        assert_eq!((i.kind, i.size), (abi::KIND_FILE, 11));
        assert_eq!(read(&fs, "d/a.txt", 0), "hello world");
        assert_eq!(read(&fs, "d/a.txt", 6), "world");
        assert_eq!(st(fs.reader("d/zz", 0, &|| false)), abi::NOT_FOUND);
        assert_eq!(st(put(&fs, "d/a.txt", b"x", false)), abi::EXISTS);
        let before = f.st.lock().unwrap().log.len();
        put(&fs, "d/a.txt", b"new", true).unwrap();
        assert_eq!(read(&fs, "d/a.txt", 0), "new");
        let renames = f.st.lock().unwrap().log[before..]
            .iter()
            .filter(|l| l.starts_with("rename"))
            .count();
        assert_eq!(renames, 1, "POSIX replace: one atomic rename");
        let mut w = fs.writer("d/gone", false).unwrap();
        w.write(b"partial").unwrap();
        drop(w); // abort: nothing reached the guest
        assert_eq!(paths(&f.st), ["/", "/d", "/d/a.txt", "/d/bad:name"]);
        let e = fs.remove_dir("d").unwrap_err();
        assert_eq!(e.status, abi::NOT_EMPTY, "never a recursive delete");
        assert!(e.msg.contains("hidden"), "{}", e.msg);
        put(&fs, "c.txt", b"", false).unwrap();
        assert_eq!(st(fs.rename("c.txt", "d/a.txt", &|| false)), abi::EXISTS);
        fs.rename("d/a.txt", "moved", &|| false).unwrap();
        assert_eq!(st(fs.rename("x", "y", &|| true)), abi::CANCELLED);
        fs.remove_file("moved").unwrap();
        fs.remove_file("d/bad:name").unwrap();
        fs.remove_dir("d").unwrap();
        assert_eq!(st(fs.stat("d")), abi::NOT_FOUND);
        for r in [fs.mkdir(""), fs.remove_dir(""), fs.remove_file("")] {
            assert_eq!(st(r), abi::UNSUPPORTED, "the root itself");
        }
        assert_eq!(paths(&f.st), ["/", "/c.txt"]);
    }

    #[test]
    fn windows_drives_and_paths() {
        let f = Fake::windows();
        let fs = mount(&f, "vmware://win\nme:pw");
        assert_eq!(
            names(&fs, ""),
            [("C".into(), abi::KIND_DIR), ("E".into(), abi::KIND_DIR)]
        );
        let probes = f.st.lock().unwrap().log.len();
        names(&fs, "");
        assert_eq!(f.st.lock().unwrap().log.len(), probes, "drives probed once");
        assert_eq!(fs.stat("").unwrap().kind, abi::KIND_DIR);
        fs.mkdir("c/Users").unwrap();
        put(&fs, "C/Users/a.txt", b"abc", false).unwrap();
        assert!(paths(&f.st).contains(&"C:\\Users\\a.txt".to_string()));
        assert_eq!(names(&fs, "C/Users"), [("a.txt".into(), abi::KIND_FILE)]);
        fs.rename("C/Users/a.txt", "C/Users/A.TXT", &|| false)
            .unwrap();
        assert!(
            paths(&f.st).contains(&"C:\\Users\\A.TXT".to_string()),
            "case-only rename"
        );
        assert_eq!(st(fs.stat("nope")), abi::NOT_FOUND);
        assert_eq!(st(fs.stat("CD/x")), abi::NOT_FOUND);
        for bad in [
            "C/a\\b", "C/x:ads", "C/a*", "C/q?", "C/d/x.", "C/x ", "C/p|q", "C/t\tab",
        ] {
            assert_eq!(st(fs.stat(bad)), abi::INVALID, "{bad}");
        }
        assert_eq!(st(fs.mkdir("C/Users/x:s")), abi::INVALID);
        assert_eq!(st(put(&fs, "C/Users/f:s", b"x", false)), abi::INVALID);
        assert_eq!(
            st(fs.rename("C/Users/A.TXT", "C/Users/a.txt:s", &|| false)),
            abi::INVALID
        );
        assert!(win_name_ok("a.b c") && win_name_ok(""));
        assert_eq!(st(fs.remove_dir("C")), abi::UNSUPPORTED, "drive root");
        assert_eq!(st(fs.reader("", 0, &|| false)), abi::UNSUPPORTED);
        let mut l = fs.list("").unwrap();
        assert_eq!(st(l.next_batch(5, &|| true)), abi::CANCELLED);
        // Configured drives: no probe.
        let cfg = Config {
            drives: Some("cz".into()),
            ..Config::default()
        };
        let fs = Arc::new(Vmware::open_with("vmware://win\nme:pw", deps(&f, cfg)).unwrap());
        assert_eq!(
            names(&fs, ""),
            [("C".into(), abi::KIND_DIR), ("Z".into(), abi::KIND_DIR)]
        );
    }

    #[test]
    fn cancelled_drive_probe() {
        let f = Fake::windows();
        let fs = mount(&f, "vmware://win\nme:pw");
        let n = std::sync::atomic::AtomicUsize::new(0);
        // Cancel after the probe has started (first poll false, then true).
        let cancel = || n.fetch_add(1, std::sync::atomic::Ordering::Relaxed) > 0;
        let r = fs.drives(&cancel);
        assert!(r.is_ok() || st(r) == abi::CANCELLED);
    }

    #[test]
    fn failed_uploads_keep_the_old_file_and_leave_no_temp() {
        let f = Fake::posix();
        let fs = mount(&f, "vmware://lin\nme:pw");
        put(&fs, "a", b"old", false).unwrap();
        f.st.lock().unwrap().fail_put = true;
        assert_eq!(st(put(&fs, "a", b"new", true)), abi::IO);
        f.st.lock().unwrap().fail_put = false;
        f.st.lock().unwrap().fail_rename = true;
        assert_eq!(st(put(&fs, "a", b"new", true)), abi::DENIED);
        assert_eq!(st(put(&fs, "b", b"new", true)), abi::DENIED);
        f.st.lock().unwrap().fail_rename = false;
        assert_eq!(read(&fs, "a", 0), "old");
        assert_eq!(paths(&f.st), ["/", "/a"], "no temp left");
        // A target that appears during the upload is not replaced.
        let mut w = fs.writer("c", false).unwrap();
        w.write(b"mine").unwrap();
        f.st.lock().unwrap().put("/c", b"theirs");
        assert_eq!(st(w.finish()), abi::EXISTS);
        assert_eq!(read(&fs, "c", 0), "theirs");
        assert_eq!(paths(&f.st), ["/", "/a", "/c"]);
        f.st.lock().unwrap().fail_stat = true;
        assert_eq!(st(fs.writer("d", false)), abi::IO);
        assert_eq!(st(fs.rename("a", "e", &|| false)), abi::IO);
    }

    /// A guest whose renames number `fail` (1-based) fail.
    struct Flaky(Fake, usize, &'static [usize]);

    impl Backend for Flaky {
        fn kind(&self) -> &str {
            "flaky"
        }
        fn login(&mut self, u: &str, p: &str) -> Result<()> {
            self.0.login(u, p)
        }
        fn list(&mut self, d: &str, a: &dyn Fn() -> bool) -> Result<Vec<Item>> {
            self.0.list(d, a)
        }
        fn stat(&mut self, p: &str) -> Result<Item> {
            self.0.stat(p)
        }
        fn get(&mut self, g: &str, h: &std::path::Path) -> Result<()> {
            self.0.get(g, h)
        }
        fn put(&mut self, h: &std::path::Path, g: &str) -> Result<()> {
            self.0.put(h, g)
        }
        fn mkdir(&mut self, p: &str) -> Result<()> {
            self.0.mkdir(p)
        }
        fn remove_file(&mut self, p: &str) -> Result<()> {
            self.0.remove_file(p)
        }
        fn remove_dir(&mut self, p: &str) -> Result<()> {
            self.0.remove_dir(p)
        }
        fn rename(&mut self, f: &str, t: &str) -> Result<()> {
            self.1 += 1;
            match self.2.contains(&self.1) {
                true => Err(Error::new(abi::DENIED, "flaky")),
                false => self.0.rename(f, t),
            }
        }
        fn ip(&mut self) -> Result<String> {
            self.0.ip()
        }
    }

    fn flaky(f: &Fake, fail: &'static [usize]) -> Arc<Vmware> {
        let f2 = f.clone();
        let d = Deps {
            connect: Arc::new(move |_, _, _| {
                Ok(Box::new(Flaky(f2.clone(), 0, fail)) as Box<dyn Backend>)
            }),
            ..deps(f, Config::default())
        };
        Arc::new(Vmware::open_with("vmware://win\nme:pw", d).unwrap())
    }

    #[test]
    fn replace_rolls_back_when_the_final_rename_fails() {
        // Windows: old aside (rename 1), new in (2: fails), old back (3).
        let f = Fake::windows();
        f.st.lock().unwrap().put("C:\\a", b"old");
        let fs = flaky(&f, &[2]);
        assert_eq!(st(put(&fs, "C/a", b"new", true)), abi::DENIED);
        assert_eq!(read(&fs, "C/a", 0), "old");
        assert_eq!(paths(&f.st), ["C:\\", "C:\\a", "E:\\"]);
    }

    #[test]
    fn replace_that_cannot_roll_back_says_where_both_files_are() {
        let f = Fake::windows();
        f.st.lock().unwrap().put("C:\\a", b"old");
        let fs = flaky(&f, &[2, 3]);
        let e = put(&fs, "C/a", b"new", true).unwrap_err();
        assert_eq!(e.status, abi::DENIED);
        let p = paths(&f.st);
        assert_eq!(p.len(), 4, "old aside + new temp both kept: {p:?}");
        let (old, new) = (&p[1], &p[2]);
        assert!(e.msg.contains("old file kept as"), "{}", e.msg);
        assert!(
            e.msg.contains(old.as_str()) && e.msg.contains(new.as_str()),
            "{}",
            e.msg
        );
        let s = f.st.lock().unwrap();
        let mut data = [s.nodes[old].clone(), s.nodes[new].clone()];
        data.sort();
        assert_eq!(data, [Some(b"new".to_vec()), Some(b"old".to_vec())]);
    }

    #[test]
    fn posix_replace_falls_back_when_rename_refuses() {
        // A POSIX guest whose rename refuses an existing target: the aside way.
        let f = Fake::posix();
        f.st.lock().unwrap().put("/a", b"old");
        struct NoReplace(Fake);
        impl Backend for NoReplace {
            fn kind(&self) -> &str {
                "noreplace"
            }
            fn login(&mut self, u: &str, p: &str) -> Result<()> {
                self.0.login(u, p)
            }
            fn list(&mut self, d: &str, a: &dyn Fn() -> bool) -> Result<Vec<Item>> {
                self.0.list(d, a)
            }
            fn stat(&mut self, p: &str) -> Result<Item> {
                self.0.stat(p)
            }
            fn get(&mut self, g: &str, h: &std::path::Path) -> Result<()> {
                self.0.get(g, h)
            }
            fn put(&mut self, h: &std::path::Path, g: &str) -> Result<()> {
                self.0.put(h, g)
            }
            fn mkdir(&mut self, p: &str) -> Result<()> {
                self.0.mkdir(p)
            }
            fn remove_file(&mut self, p: &str) -> Result<()> {
                self.0.remove_file(p)
            }
            fn remove_dir(&mut self, p: &str) -> Result<()> {
                self.0.remove_dir(p)
            }
            fn rename(&mut self, f: &str, t: &str) -> Result<()> {
                match self.0.exists(t)? {
                    true => Err(Error::new(abi::EXISTS, "exists")),
                    false => self.0.rename(f, t),
                }
            }
            fn ip(&mut self) -> Result<String> {
                self.0.ip()
            }
        }
        let f2 = f.clone();
        let d = Deps {
            connect: Arc::new(move |_, _, _| {
                Ok(Box::new(NoReplace(f2.clone())) as Box<dyn Backend>)
            }),
            ..deps(&f, Config::default())
        };
        let fs = Arc::new(Vmware::open_with("vmware://lin\nme:pw", d).unwrap());
        put(&fs, "a", b"new", true).unwrap();
        assert_eq!(read(&fs, "a", 0), "new");
        assert_eq!(paths(&f.st), ["/", "/a"]);
    }

    #[test]
    fn temp_names_in_use_are_skipped() {
        let mut f = Fake::posix();
        f.login("u", "pw").unwrap();
        let t = free_temp(&mut f, "/a", '/').unwrap();
        assert!(t.starts_with("/.a.") && t.ends_with(".cmdr-part"), "{t}");
        f.st.lock().unwrap().fail_stat = true;
        assert_eq!(st(free_temp(&mut f, "/a", '/')), abi::IO);
        assert_eq!(sibling("C:\\x\\y", '\\', "z"), "C:\\x\\z");
        assert_eq!(sibling("/y", '/', "z"), "/z");
    }

    #[test]
    fn closed_writer() {
        let f = Fake::posix();
        let fs = mount(&f, "vmware://lin\nme:pw");
        let mut w = fs.writer("a", false).unwrap();
        w.f = None;
        assert_eq!(st(w.write(b"x")), abi::INTERNAL);
        assert_eq!(st(w.finish()), abi::INTERNAL);
    }
}

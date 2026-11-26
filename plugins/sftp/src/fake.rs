//! Test-only servers: an in-memory SFTP tree (russh-sftp's server side), reached either over an
//! in-process pipe ([`dial`], no SSH) or through a real SSH server on 127.0.0.1 ([`ssh_server`]).
use crate::config::Target;
use crate::ssh::{self, Conn};
use commander_plugin_abi as abi;
use commander_plugin_abi::glue::{Error, Result};
use russh::keys::{PrivateKey, PublicKey};
use russh::server::{Auth, ChannelOpenHandle, Msg, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId};
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Packet, SftpHandle, SftpString,
    Status, StatusCode, Version,
};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Default)]
pub struct State {
    /// Absolute path -> file bytes (`None` = dir). "/" is implicit.
    pub tree: BTreeMap<String, Option<Vec<u8>>>,
    /// Absolute path -> link target (absolute).
    pub links: BTreeMap<String, String>,
    /// Advertise and serve `posix-rename@openssh.com`.
    pub posix_rename: bool,
    /// Every RENAME fails (permission denied).
    pub rename_fail: bool,
    /// Every request seen (for asserts).
    pub log: Vec<String>,
    /// The next N `*.cmdr-part` names opened already exist: as symlinks to `/victim`
    /// (`squat_link`) or as plain files.
    pub squat: usize,
    pub squat_link: bool,
}

pub type Shared = Arc<Mutex<State>>;

fn parent(p: &str) -> &str {
    match p.rsplit_once('/') {
        Some(("", _)) | None => "/",
        Some((d, _)) => d,
    }
}

impl State {
    fn is_dir(&self, p: &str) -> bool {
        p == "/" || matches!(self.tree.get(p), Some(None))
    }

    fn exists(&self, p: &str) -> bool {
        p == "/" || self.tree.contains_key(p) || self.links.contains_key(p)
    }

    fn attrs(&self, p: &str, follow: bool) -> std::result::Result<FileAttributes, StatusCode> {
        let mut a = FileAttributes {
            mtime: Some(1_577_836_800), // 2020-01-01
            ..FileAttributes::default()
        };
        if let Some(t) = self.links.get(p) {
            if !follow {
                a.permissions = Some(0o120777);
                return Ok(a);
            }
            return self.attrs(t, true);
        }
        match (p == "/", self.tree.get(p)) {
            (true, _) | (_, Some(None)) => a.permissions = Some(0o040755),
            (_, Some(Some(d))) => {
                a.permissions = Some(0o100644);
                a.size = Some(d.len() as u64);
            }
            (_, None) => return Err(StatusCode::NoSuchFile),
        }
        Ok(a)
    }

    fn children(&self, d: &str) -> Vec<String> {
        let keys = self.tree.keys().chain(self.links.keys());
        keys.filter(|k| parent(k) == d).cloned().collect()
    }

    fn move_path(&mut self, from: &str, to: &str) {
        let moved: Vec<String> = self
            .tree
            .keys()
            .filter(|k| *k == from || k.starts_with(&format!("{from}/")))
            .cloned()
            .collect();
        for k in moved {
            let v = self.tree.remove(&k).unwrap_or(None);
            self.tree.insert(format!("{to}{}", &k[from.len()..]), v);
        }
        if let Some(t) = self.links.remove(from) {
            self.links.insert(to.into(), t);
        }
    }
}

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: String::new(),
        language_tag: String::new(),
    }
}

fn s(p: &SftpString) -> String {
    p.to_string_lossy().into_owned()
}

enum Open {
    File(String),
    Dir(Option<Vec<File>>),
}

/// One client's SFTP server.
struct Srv {
    st: Shared,
    open: HashMap<Vec<u8>, Open>,
    next: u32,
}

impl Srv {
    fn new(st: Shared) -> Self {
        Self {
            st,
            open: HashMap::new(),
            next: 0,
        }
    }

    fn lock(&self, req: String) -> std::sync::MutexGuard<'_, State> {
        let mut g = self.st.lock().unwrap();
        g.log.push(req);
        g
    }

    fn handle(&mut self, id: u32, o: Open) -> Handle {
        self.next += 1;
        let h = format!("h{}", self.next);
        self.open.insert(h.clone().into_bytes(), o);
        Handle {
            id,
            handle: SftpHandle::from(h),
        }
    }
}

/// SSH wire string at `b[*i..]`.
fn wire_str(b: &[u8], i: &mut usize) -> Option<String> {
    let n = u32::from_be_bytes(b.get(*i..*i + 4)?.try_into().ok()?) as usize;
    let v = b.get(*i + 4..*i + 4 + n)?;
    *i += 4 + n;
    String::from_utf8(v.to_vec()).ok()
}

impl russh_sftp::server::Handler for Srv {
    type Error = StatusCode;

    fn unimplemented(&self) -> StatusCode {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        _version: u32,
        _ext: HashMap<String, String>,
    ) -> std::result::Result<Version, StatusCode> {
        let mut v = Version::new();
        if self.st.lock().unwrap().posix_rename {
            v.extensions
                .insert("posix-rename@openssh.com".into(), "1".into());
        }
        Ok(v)
    }

    async fn open(
        &mut self,
        id: u32,
        filename: SftpString,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> std::result::Result<Handle, StatusCode> {
        let mut p = s(&filename);
        {
            let mut st = self.lock(format!("OPEN {p}"));
            if p.ends_with(".cmdr-part") && st.squat > 0 {
                st.squat -= 1;
                match st.squat_link {
                    true => st.links.insert(p.clone(), "/victim".into()).is_none(),
                    false => st.tree.insert(p.clone(), Some(b"squat".to_vec())).is_none(),
                };
            }
            if pflags.contains(OpenFlags::CREATE | OpenFlags::EXCLUDE) && st.exists(&p) {
                return Err(StatusCode::Failure);
            }
            // Like a real server: opening a symlink writes through to its target.
            p = st.links.get(&p).cloned().unwrap_or(p);
            if pflags.contains(OpenFlags::CREATE) {
                if !st.is_dir(parent(&p)) {
                    return Err(StatusCode::NoSuchFile);
                }
                if st.is_dir(&p) {
                    return Err(StatusCode::Failure);
                }
                if pflags.contains(OpenFlags::TRUNCATE) || !st.tree.contains_key(&p) {
                    st.tree.insert(p.clone(), Some(Vec::new()));
                }
            } else if !matches!(st.tree.get(&p), Some(Some(_))) {
                return Err(StatusCode::NoSuchFile);
            }
        }
        Ok(self.handle(id, Open::File(p)))
    }

    async fn close(
        &mut self,
        id: u32,
        handle: SftpHandle,
    ) -> std::result::Result<Status, StatusCode> {
        self.open.remove(handle.as_bytes());
        Ok(ok(id))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: SftpHandle,
        offset: u64,
        len: u32,
    ) -> std::result::Result<Data, StatusCode> {
        let Some(Open::File(p)) = self.open.get(handle.as_bytes()) else {
            return Err(StatusCode::Failure);
        };
        let st = self.st.lock().unwrap();
        let Some(Some(d)) = st.tree.get(p) else {
            return Err(StatusCode::NoSuchFile);
        };
        let off = usize::try_from(offset).unwrap_or(usize::MAX);
        if off >= d.len() {
            return Err(StatusCode::Eof);
        }
        let end = d.len().min(off + len as usize);
        Ok(Data {
            id,
            data: d[off..end].to_vec(),
        })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: SftpHandle,
        offset: u64,
        data: Vec<u8>,
    ) -> std::result::Result<Status, StatusCode> {
        let Some(Open::File(p)) = self.open.get(handle.as_bytes()) else {
            return Err(StatusCode::Failure);
        };
        let mut st = self.st.lock().unwrap();
        let Some(Some(d)) = st.tree.get_mut(p) else {
            return Err(StatusCode::NoSuchFile);
        };
        let off = offset as usize;
        if d.len() < off + data.len() {
            d.resize(off + data.len(), 0);
        }
        d[off..off + data.len()].copy_from_slice(&data);
        Ok(ok(id))
    }

    async fn stat(&mut self, id: u32, path: SftpString) -> std::result::Result<Attrs, StatusCode> {
        let p = s(&path);
        let attrs = self.lock(format!("STAT {p}")).attrs(&p, true)?;
        Ok(Attrs { id, attrs })
    }

    async fn lstat(&mut self, id: u32, path: SftpString) -> std::result::Result<Attrs, StatusCode> {
        let p = s(&path);
        let attrs = self.lock(format!("LSTAT {p}")).attrs(&p, false)?;
        Ok(Attrs { id, attrs })
    }

    async fn opendir(
        &mut self,
        id: u32,
        path: SftpString,
    ) -> std::result::Result<Handle, StatusCode> {
        let p = s(&path);
        let files = {
            if p == "/die" {
                // Ends the server task (lock not held): the pipe closes.
                panic!("fake: connection dies");
            }
            let st = self.lock(format!("OPENDIR {p}"));
            if !st.is_dir(&p) {
                return Err(StatusCode::NoSuchFile);
            }
            let mut files: Vec<File> = [".", ".."]
                .map(|n| File {
                    filename: n.into(),
                    longname: String::new(),
                    attrs: st.attrs("/", false).unwrap_or_default(),
                })
                .into();
            for c in st.children(&p) {
                files.push(File {
                    filename: c.rsplit('/').next().unwrap_or(&c).into(),
                    longname: String::new(),
                    attrs: st.attrs(&c, false)?,
                });
            }
            files.push(File {
                filename: SftpString::from(vec![b'b', 0xff]),
                longname: String::new(),
                attrs: FileAttributes::default(),
            }); // non-UTF-8: skipped by the client
            files
        };
        Ok(self.handle(id, Open::Dir(Some(files))))
    }

    async fn readdir(
        &mut self,
        id: u32,
        handle: SftpHandle,
    ) -> std::result::Result<Name, StatusCode> {
        match self.open.get_mut(handle.as_bytes()) {
            Some(Open::Dir(files)) => match files.take() {
                Some(files) => Ok(Name { id, files }),
                None => Err(StatusCode::Eof),
            },
            _ => Err(StatusCode::Failure),
        }
    }

    async fn remove(
        &mut self,
        id: u32,
        filename: SftpString,
    ) -> std::result::Result<Status, StatusCode> {
        let p = s(&filename);
        let mut st = self.lock(format!("REMOVE {p}"));
        if st.links.remove(&p).is_some() {
            return Ok(ok(id));
        }
        match st.tree.get(&p) {
            Some(Some(_)) => {
                st.tree.remove(&p);
                Ok(ok(id))
            }
            Some(None) => Err(StatusCode::Failure),
            None => Err(StatusCode::NoSuchFile),
        }
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: SftpString,
        _attrs: FileAttributes,
    ) -> std::result::Result<Status, StatusCode> {
        let p = s(&path);
        let mut st = self.lock(format!("MKDIR {p}"));
        if st.exists(&p) {
            return Err(StatusCode::Failure);
        }
        if !st.is_dir(parent(&p)) {
            return Err(StatusCode::NoSuchFile);
        }
        st.tree.insert(p, None);
        Ok(ok(id))
    }

    async fn rmdir(
        &mut self,
        id: u32,
        path: SftpString,
    ) -> std::result::Result<Status, StatusCode> {
        let p = s(&path);
        let mut st = self.lock(format!("RMDIR {p}"));
        if !st.is_dir(&p) {
            return Err(StatusCode::NoSuchFile);
        }
        if !st.children(&p).is_empty() {
            return Err(StatusCode::Failure);
        }
        st.tree.remove(&p);
        Ok(ok(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: SftpString,
        newpath: SftpString,
    ) -> std::result::Result<Status, StatusCode> {
        let (from, to) = (s(&oldpath), s(&newpath));
        let mut st = self.lock(format!("RENAME {from} {to}"));
        if st.rename_fail {
            return Err(StatusCode::PermissionDenied);
        }
        if !st.exists(&from) {
            return Err(StatusCode::NoSuchFile);
        }
        if st.exists(&to) {
            return Err(StatusCode::Failure);
        }
        st.move_path(&from, &to);
        Ok(ok(id))
    }

    async fn extended(
        &mut self,
        id: u32,
        request: String,
        data: Vec<u8>,
    ) -> std::result::Result<Packet, StatusCode> {
        if request != "posix-rename@openssh.com" {
            return Err(StatusCode::OpUnsupported);
        }
        let mut i = 0;
        let (Some(from), Some(to)) = (wire_str(&data, &mut i), wire_str(&data, &mut i)) else {
            return Err(StatusCode::BadMessage);
        };
        let mut st = self.lock(format!("POSIX-RENAME {from} {to}"));
        if !st.exists(&from) {
            return Err(StatusCode::NoSuchFile);
        }
        st.tree.remove(&to);
        st.move_path(&from, &to);
        Ok(Packet::Status(ok(id)))
    }
}

fn registry() -> &'static Mutex<HashMap<u16, Shared>> {
    static R: OnceLock<Mutex<HashMap<u16, Shared>>> = OnceLock::new();
    R.get_or_init(Mutex::default)
}

/// Registers `st` for [`dial`]; returns the mount authority (`u@fake:<id>`).
pub fn start(st: Shared) -> String {
    static NEXT: AtomicU16 = AtomicU16::new(1);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    registry().lock().unwrap().insert(id, st);
    format!("u@fake:{id}")
}

/// A [`crate::fs::Dial`]: SFTP over an in-process pipe to the tree registered under `t.port`.
pub fn dial(t: &Target) -> Result<Conn> {
    let st = registry().lock().unwrap().get(&t.port).cloned();
    let st = st.ok_or_else(|| Error::new(abi::IO, "fake: no such server"))?;
    ssh::rt()?.block_on(async {
        let (client, server) = tokio::io::duplex(1 << 16);
        russh_sftp::server::run(server, Srv::new(st)).await;
        let sftp = russh_sftp::client::SftpSession::new(client)
            .await
            .map_err(|e| Error::new(abi::IO, e.to_string()))?;
        Ok(Conn { sftp, ssh: None })
    })
}

/// Test keys (ed25519, made with ssh-keygen for these tests only).
pub const HOST_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAdq0iNvgJjRvuGWfgKaPs/Aqxc4BAU+HKLFm4maw0e7AAAAIhS8RCJUvEQ
iQAAAAtzc2gtZWQyNTUxOQAAACAdq0iNvgJjRvuGWfgKaPs/Aqxc4BAU+HKLFm4maw0e7A
AAAEDhezRLDZCnabirgvkYF/UEuWO4Wz7UtGfKg88M42hMgB2rSI2+AmNG+4ZZ+Apo+z8C
rFzgEBT4cosWbiZrDR7sAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
";
pub const HOST_PUB: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB2rSI2+AmNG+4ZZ+Apo+z8CrFzgEBT4cosWbiZrDR7s";
pub const USER_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBKzVvphGKXUlTXY7rgTmX1YzkowVT3N6QH5qoPVLoCbAAAAIgwLi1QMC4t
UAAAAAtzc2gtZWQyNTUxOQAAACBKzVvphGKXUlTXY7rgTmX1YzkowVT3N6QH5qoPVLoCbA
AAAEBNoThRJnAgRuhG+nUg4mRHjJrw5f9iclGGcCkhvE+gDkrNW+mEYpdSVNdjuuBOZfVj
OSjBVPc3pAfmqg9UugJsAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
";
pub const USER_PUB: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIErNW+mEYpdSVNdjuuBOZfVjOSjBVPc3pAfmqg9UugJs";
/// Passphrase "secret".
pub const ENCRYPTED_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAQ1u/Vij
nXbRH3evej/BZ2AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIMrJz8w9B4Nw9CeC
VVuhlwkDhGnfga3RTW9J7LTe51v8AAAAkCPazjkWaHGtJScsV4eah0puF8H1WH88aakTQ9
PelaqUIKzklz6VwRriXHdK7QfFWmtNHjuu3JbBxrq4EW70qNsZ5g1l+GPZuSTE7iTMi/Qr
GiIKxqq8oAlfNCkU6G3QrmbAmdjD0zHW2KxqP46JW/LiIb+mlYVVprVPZvye1IwDiwDClK
f1wRgqLPR30UhhXQ==
-----END OPENSSH PRIVATE KEY-----
";

/// Passphrase "other"; the test server does not accept this key.
pub const OTHER_ENCRYPTED_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDH4dmxm8
wQe0E8IBJ/UaNaAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAILkrMouAk4CkaHnK
q0aN0ldYnc/2zSb/dicajT/2wlgjAAAAkHJs5J4xW8nlD/QExu0SKjAv76jGaYIg3EucJZ
gtMza6Co89PSFTqcDOpp8i/kiUSz2lshgMPAa62SOsAF6Owy/pUsO9nXmyG/1jjOsekqs5
XJOvf316FKiZ98oIumNrdYjprlG9xC3cjHMGy2plE3S/jUPoL5p29UUZ9yNLYy2s0vDLMe
naMo0QzRdcgGSGmA==
-----END OPENSSH PRIVATE KEY-----
";

/// SSH side of the test server: one password, one client key, an `sftp` subsystem.
struct SshSrv {
    st: Shared,
    pass: &'static str,
    /// Accepted client keys ([`USER_KEY`], [`ENCRYPTED_KEY`]).
    keys: Vec<PublicKey>,
    chans: HashMap<ChannelId, Channel<Msg>>,
}

impl russh::server::Handler for SshSrv {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        _user: &str,
        pw: &str,
    ) -> std::result::Result<Auth, Self::Error> {
        Ok(match pw == self.pass {
            true => Auth::Accept,
            false => Auth::reject(),
        })
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> std::result::Result<Auth, Self::Error> {
        let k = key.public_key.key_data();
        Ok(match self.keys.iter().any(|a| a.key_data() == k) {
            true => Auth::Accept,
            false => Auth::reject(),
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        self.chans.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        match (name, self.chans.remove(&id)) {
            ("sftp", Some(ch)) => {
                session.channel_success(id)?;
                russh_sftp::server::run(ch.into_stream(), Srv::new(Arc::clone(&self.st))).await;
            }
            _ => session.channel_failure(id)?,
        }
        Ok(())
    }
}

/// SSH server on 127.0.0.1 serving `st` (host key [`HOST_KEY`], password `pass`, client key
/// [`USER_KEY`]); returns the port.
pub fn ssh_server(st: Shared, pass: &'static str) -> u16 {
    let rt = ssh::rt().unwrap();
    let l = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let port = l.local_addr().unwrap().port();
    let cfg = Arc::new(russh::server::Config {
        keys: vec![PrivateKey::from_openssh(HOST_KEY).unwrap()],
        auth_rejection_time: std::time::Duration::ZERO,
        auth_rejection_time_initial: Some(std::time::Duration::ZERO),
        ..Default::default()
    });
    // An encrypted key's public half is readable without the passphrase.
    let keys: Vec<PublicKey> = [USER_KEY, ENCRYPTED_KEY]
        .map(|k| PrivateKey::from_openssh(k).unwrap().public_key().clone())
        .into();
    rt.spawn(async move {
        while let Ok((sock, _)) = l.accept().await {
            let h = SshSrv {
                st: Arc::clone(&st),
                pass,
                keys: keys.clone(),
                chans: HashMap::new(),
            };
            let cfg = Arc::clone(&cfg);
            tokio::spawn(async move {
                if let Ok(s) = russh::server::run_stream(cfg, sock, h).await {
                    let _ = s.await;
                }
            });
        }
    });
    port
}

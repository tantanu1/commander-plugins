//! The real [`Session`]: the pure-Rust `smb2` client (SMB 2.0.2-3.1.1, NTLM, signing,
//! encryption) on one small tokio runtime. Metadata calls share one client behind a lock;
//! readers and writers own clones of the connection, so transfers run in parallel.
use crate::config::Target;
use crate::fs::{Batches, Session, Upload};
use commander_plugin_abi::auth::Passphrase;
use commander_plugin_abi::glue::{Error, Item, Result};
use commander_plugin_abi::{self as abi, Status};
use smb2::types::status::NtStatus;
use smb2::{
    ClientConfig, DirectoryReader, ErrorKind, FileReader, FileWriter, RenameOptions, SmbClient,
    Tree,
};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io::Read;
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::Duration;
use tokio::runtime::Runtime;

/// TCP connect + negotiate bound (each later request: smb2's 30 s response timeout).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Bytes fetched per READ round trip by a reader (smb2 splits it by the server's max).
const CHUNK: usize = 1 << 20;

pub fn rt() -> Result<&'static Runtime> {
    static RT: OnceLock<std::result::Result<Runtime, String>> = OnceLock::new();
    RT.get_or_init(|| {
        // The IO thread runs this library's code: never let an unload unmap it.
        commander_plugin_abi::glue::pin_module();
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("smb-io")
            .enable_all()
            .build()
            .map_err(|e| e.to_string())
    })
    .as_ref()
    .map_err(|m| Error::new(abi::INTERNAL, format!("smb: runtime: {m}")))
}

/// ABI status of an smb2 error.
fn status(kind: ErrorKind, nt: Option<NtStatus>) -> Status {
    match kind {
        ErrorKind::NotFound => abi::NOT_FOUND,
        ErrorKind::AccessDenied | ErrorKind::SharingViolation => abi::DENIED,
        ErrorKind::AlreadyExists => abi::EXISTS,
        ErrorKind::Cancelled => abi::CANCELLED,
        ErrorKind::Unsupported => abi::UNSUPPORTED,
        ErrorKind::InvalidName => abi::INVALID,
        ErrorKind::AuthRequired | ErrorKind::GuestSessionRefused | ErrorKind::SigningRequired => {
            abi::AUTH
        }
        _ if nt == Some(NtStatus::DIRECTORY_NOT_EMPTY) => abi::NOT_EMPTY,
        _ => abi::IO,
    }
}

/// `e` as a plugin error about `what` (smb2 messages never hold the password).
fn ferr(e: &smb2::Error, what: &str) -> Error {
    Error::new(status(e.kind(), e.status()), format!("smb: {what}: {e}"))
}

/// `user@host` as the password prompt names the account.
fn account(t: &Target) -> String {
    match t.domain.as_str() {
        "" => format!("{}@{}", t.user, t.host),
        d => format!("{d}\\{}@{}", t.user, t.host),
    }
}

/// Ask the host for the password of `t` (`wrong` = the last one was refused).
fn need_password(t: &Target, wrong: bool) -> Error {
    let why = match wrong {
        true => "wrong password",
        false => "password needed",
    };
    let who = account(t);
    let x = Passphrase {
        msg: format!("smb: {why} for {who}"),
        key: who,
        wrong,
        password: true,
    };
    Error::new(abi::NEED_PASSPHRASE, x.detail())
}

/// What a failed sign-in becomes: a named account asks for its password (again); a refused
/// guest login says how to sign in.
fn refused(t: &Target, e: &smb2::Error) -> Error {
    let auth = status(e.kind(), e.status()) == abi::AUTH;
    match (auth, t.user.is_empty()) {
        (true, false) => need_password(t, t.pass.is_some()),
        (true, true) => Error::new(
            abi::AUTH,
            format!(
                "smb: {}: guest access refused ({e}): sign in with smb://user@{0} or a bookmark",
                t.host
            ),
        ),
        _ => ferr(e, &t.host),
    }
}

/// Client settings for `t`; a named account without a password asks for one first.
fn client_config(t: &Target) -> Result<ClientConfig> {
    let pass = match (&t.pass, t.user.is_empty()) {
        (Some(p), _) => p.as_str(),
        (None, true) => "",
        (None, false) => return Err(need_password(t, false)),
    };
    let host = match t.host.contains(':') {
        true => format!("[{}]", t.host),
        false => t.host.clone(),
    };
    Ok(ClientConfig {
        addr: format!("{host}:{}", t.port),
        timeout: CONNECT_TIMEOUT,
        // No user: a named `Guest` login (servers that refuse anonymous often take it; smb2
        // treats the name as guest, never as an account).
        username: match t.user.as_str() {
            "" => "Guest".into(),
            u => u.into(),
        },
        // smb2 keeps its own copy for reconnects (documented in the plugin page).
        password: pass.to_owned(),
        domain: t.domain.clone(),
        auto_reconnect: true,
        // Else a server that only prefers encryption can be talked down to plaintext.
        require_encryption: t.encrypt,
        ..ClientConfig::default()
    })
}

/// Sign in to `t`.
pub fn dial(t: &Target) -> Result<Box<dyn Session>> {
    let cfg = client_config(t)?;
    let client = rt()?
        .block_on(SmbClient::connect(cfg))
        .map_err(|e| refused(t, &e))?;
    Ok(Box::new(Real {
        st: Mutex::new(State {
            client,
            trees: HashMap::new(),
        }),
    }))
}

/// Disk shares by name: no printers / IPC, no hidden `$` (admin) shares.
fn disk_shares(all: Vec<smb2::ShareInfo>) -> Vec<String> {
    const TYPE_MASK: u32 = 0x0FFF_FFFF; // STYPE_SPECIAL / STYPE_TEMPORARY are flags
    let disk = |s: &smb2::ShareInfo| s.share_type & TYPE_MASK == 0 && !s.name.ends_with('$');
    all.into_iter().filter(disk).map(|s| s.name).collect()
}

/// Unix ns of a Windows FILETIME (100 ns ticks since 1601); 0 = unknown.
fn unix_ns(ticks: u64) -> Option<i64> {
    const EPOCH_DIFF: i64 = 116_444_736_000_000_000;
    let t = i64::try_from(ticks).ok().filter(|&t| t != 0)?;
    (t - EPOCH_DIFF).checked_mul(100)
}

fn item(name: String, dir: bool, size: u64, modified: smb2::pack::FileTime, link: bool) -> Item {
    Item {
        name,
        kind: if dir { abi::KIND_DIR } else { abi::KIND_FILE },
        size: if dir { 0 } else { size },
        mtime: unix_ns(modified.0),
        // A junction / symlink: the host never recurses through it.
        link,
    }
}

struct State {
    client: SmbClient,
    /// Connected shares.
    trees: HashMap<String, Tree>,
}

struct Real {
    st: Mutex<State>,
}

impl Real {
    /// Run `f` with the client and share `share` (connected on first use).
    fn run<T>(
        &self,
        share: &str,
        what: &str,
        f: impl AsyncFnOnce(&mut SmbClient, &mut Tree) -> smb2::Result<T>,
    ) -> Result<T> {
        let rt = rt()?;
        let mut g = self.st.lock().unwrap_or_else(PoisonError::into_inner);
        let State { client, trees } = &mut *g;
        rt.block_on(async {
            let tree = match trees.entry(share.to_owned()) {
                Entry::Occupied(e) => e.into_mut(),
                Entry::Vacant(v) => v.insert(client.connect_share(share).await?),
            };
            f(client, tree).await
        })
        .map_err(|e| ferr(&e, &format!("{share}/{what}")))
    }
}

impl Session for Real {
    fn shares(&self) -> Result<Vec<String>> {
        let rt = rt()?;
        let mut g = self.st.lock().unwrap_or_else(PoisonError::into_inner);
        let all = rt
            .block_on(g.client.list_shares())
            .map_err(|e| ferr(&e, "shares"))?;
        Ok(disk_shares(all))
    }

    fn list(&self, share: &str, dir: &str) -> Result<Box<dyn Batches>> {
        let r = self.run(share, dir, async |c, t| {
            c.open_directory_reader(t, dir).await
        })?;
        Ok(Box::new(DirList {
            r: Some(r),
            what: format!("{share}/{dir}"),
        }))
    }

    fn stat(&self, share: &str, path: &str) -> Result<Item> {
        if path.is_empty() {
            // The share root: connecting proves it exists.
            return self.run(share, path, async |_, _| Ok(Item::dir("")));
        }
        let i = self.run(share, path, async |c, t| c.stat(t, path).await)?;
        let link = i.is_link();
        Ok(item(
            String::new(),
            i.is_directory,
            i.size,
            i.modified,
            link,
        ))
    }

    fn reader(&self, share: &str, path: &str, offset: u64) -> Result<Box<dyn Read + Send>> {
        let r = self.run(share, path, async |c, t| c.open_file_reader(t, path).await)?;
        Ok(Box::new(Download {
            r: Some(r),
            pos: offset,
            buf: Vec::new(),
            at: 0,
            what: format!("{share}/{path}"),
        }))
    }

    fn create(&self, share: &str, path: &str) -> Result<Box<dyn Upload>> {
        let w = self.run(share, path, async |c, t| {
            c.create_file_writer_exclusive(t, path).await
        })?;
        Ok(Box::new(Up {
            w: Some(w),
            what: format!("{share}/{path}"),
        }))
    }

    fn mkdir(&self, share: &str, path: &str) -> Result<()> {
        self.run(share, path, async |c, t| c.create_directory(t, path).await)
    }

    fn remove_file(&self, share: &str, path: &str) -> Result<()> {
        self.run(share, path, async |c, t| c.delete_file(t, path).await)
    }

    fn remove_dir(&self, share: &str, path: &str) -> Result<()> {
        self.run(share, path, async |c, t| c.delete_directory(t, path).await)
    }

    fn rename(&self, share: &str, from: &str, to: &str, replace: bool) -> Result<()> {
        let opts = RenameOptions::new().replace_if_exists(replace);
        self.run(share, from, async |c, t| {
            c.rename_with(t, from, to, opts).await
        })
    }
}

/// A listing, one server batch per [`Batches::next`] (the handle closes at the end / on drop).
struct DirList {
    r: Option<DirectoryReader>,
    what: String,
}

impl Batches for DirList {
    fn next(&mut self) -> Result<Option<Vec<Item>>> {
        let Some(r) = self.r.as_mut() else {
            return Ok(None);
        };
        let batch = rt()?
            .block_on(r.next_batch())
            .map_err(|e| ferr(&e, &self.what))?;
        let items = batch.map(|v| {
            let it = |e: smb2::DirectoryEntry| {
                let link = e.is_link();
                item(e.name, e.is_directory, e.size, e.modified, link)
            };
            v.into_iter().map(it).collect()
        });
        if items.is_none() {
            self.r = None; // done: the reader closed its handle itself
        }
        Ok(items)
    }
}

impl Drop for DirList {
    fn drop(&mut self) {
        if let (Some(r), Ok(rt)) = (self.r.take(), rt()) {
            let _ = rt.block_on(r.close()); // best effort (a cancelled listing)
        }
    }
}

/// Positioned reads in [`CHUNK`]s over one open handle (closed on drop).
struct Download {
    r: Option<FileReader>,
    pos: u64,
    buf: Vec<u8>,
    at: usize,
    what: String,
}

impl Read for Download {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.at == self.buf.len() {
            let r = self
                .r
                .as_ref()
                .ok_or_else(|| std::io::Error::other("smb: closed"))?;
            let rt = rt().map_err(|e| std::io::Error::other(e.msg))?;
            let want = out.len().max(CHUNK) as u64;
            self.buf = rt
                .block_on(r.read_at(self.pos, want))
                .map_err(|e| std::io::Error::other(format!("smb: {}: {e}", self.what)))?;
            self.pos += self.buf.len() as u64;
            self.at = 0;
        }
        let n = out.len().min(self.buf.len() - self.at);
        out[..n].copy_from_slice(&self.buf[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

impl Drop for Download {
    fn drop(&mut self) {
        if let (Some(r), Ok(rt)) = (self.r.take(), rt()) {
            let _ = rt.block_on(r.close()); // best effort
        }
    }
}

/// A new file being written (abandoned on drop).
struct Up {
    w: Option<FileWriter>,
    what: String,
}

impl Upload for Up {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        let w = self
            .w
            .as_mut()
            .ok_or_else(|| Error::new(abi::INTERNAL, "smb: closed"))?;
        rt()?
            .block_on(w.write_chunk(data))
            .map_err(|e| ferr(&e, &self.what))
    }

    fn finish(mut self: Box<Self>) -> Result<()> {
        let w = self
            .w
            .take()
            .ok_or_else(|| Error::new(abi::INTERNAL, "smb: closed"))?;
        // Flushes to stable storage, then closes.
        rt()?
            .block_on(w.finish())
            .map(drop)
            .map_err(|e| ferr(&e, &self.what))
    }
}

impl Drop for Up {
    fn drop(&mut self) {
        if let (Some(w), Ok(rt)) = (self.w.take(), rt()) {
            let _ = rt.block_on(w.abort()); // best effort; the caller deletes the file
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn target(user: &str, pass: Option<&str>) -> Target {
        Target {
            host: "nas".into(),
            port: 445,
            user: user.into(),
            pass: pass.map(|p| Zeroizing::new(p.into())),
            ..Target::default()
        }
    }

    #[test]
    fn errors_map_to_status() {
        use ErrorKind as K;
        let s = |k| status(k, None);
        assert_eq!(s(K::NotFound), abi::NOT_FOUND);
        assert_eq!(s(K::AccessDenied), abi::DENIED);
        assert_eq!(s(K::SharingViolation), abi::DENIED);
        assert_eq!(s(K::AlreadyExists), abi::EXISTS);
        assert_eq!(s(K::Cancelled), abi::CANCELLED, "never Interrupted (B61)");
        assert_eq!(s(K::Unsupported), abi::UNSUPPORTED);
        assert_eq!(s(K::InvalidName), abi::INVALID);
        assert_eq!(s(K::AuthRequired), abi::AUTH);
        assert_eq!(s(K::GuestSessionRefused), abi::AUTH);
        assert_eq!(s(K::SigningRequired), abi::AUTH);
        assert_eq!(s(K::TimedOut), abi::IO);
        assert_eq!(
            status(K::Other, Some(NtStatus::DIRECTORY_NOT_EMPTY)),
            abi::NOT_EMPTY
        );
        assert_eq!(status(K::Other, None), abi::IO);
        let e = ferr(&smb2::Error::Timeout, "pub/a");
        assert_eq!(e.status, abi::IO);
        assert!(e.msg.starts_with("smb: pub/a: "), "{}", e.msg);
        assert_eq!(ferr(&smb2::Error::Cancelled, "x").status, abi::CANCELLED);
    }

    #[test]
    fn sign_in_asks_for_the_password() {
        let e = client_config(&target("me", None)).err().unwrap();
        assert_eq!(e.status, abi::NEED_PASSPHRASE);
        let x = Passphrase::parse(&e.msg);
        assert!(x.password && !x.wrong && x.key == "me@nas", "{x:?}");
        let mut t = target("me", Some("hunter2"));
        t.domain = "CORP".into();
        let auth = smb2::Error::Auth {
            message: "logon failure".into(),
        };
        let e = refused(&t, &auth);
        let x = Passphrase::parse(&e.msg);
        assert!(x.wrong && x.key == "CORP\\me@nas", "{x:?}");
        assert!(!e.msg.contains("hunter2"));
        let guest = refused(&target("", None), &auth);
        assert_eq!(guest.status, abi::AUTH);
        assert!(guest.msg.contains("smb://user@nas"), "{}", guest.msg);
        assert_eq!(refused(&t, &smb2::Error::Timeout).status, abi::IO);
    }

    #[test]
    fn client_settings() {
        let c = client_config(&target("", None)).unwrap();
        assert_eq!((c.addr.as_str(), c.username.as_str()), ("nas:445", "Guest"));
        assert!(c.password.is_empty() && c.auto_reconnect);
        let mut t = target("me", Some("pw"));
        t.host = "fe80::1".into();
        t.port = 1445;
        t.domain = "D".into();
        let c = client_config(&t).unwrap();
        assert_eq!(c.addr, "[fe80::1]:1445");
        assert_eq!((c.password.as_str(), c.domain.as_str()), ("pw", "D"));
        assert!(!c.require_encryption);
        t.encrypt = true;
        assert!(client_config(&t).unwrap().require_encryption);
    }

    #[test]
    fn shares_and_items() {
        let si = |name: &str, ty| smb2::ShareInfo {
            name: name.into(),
            share_type: ty,
            comment: String::new(),
        };
        let all = vec![
            si("media", 0),
            si("IPC$", 0x8000_0003),
            si("C$", 0x8000_0000),
            si("printer", 1),
            si("temp", 0x4000_0000),
        ];
        assert_eq!(disk_shares(all), ["media", "temp"]);
        assert_eq!(unix_ns(0), None);
        assert_eq!(unix_ns(116_444_736_000_000_000), Some(0));
        assert_eq!(unix_ns(116_444_736_000_000_001), Some(100));
        assert_eq!(unix_ns(u64::MAX), None);
        let ft = smb2::pack::FileTime(116_444_736_010_000_000);
        let f = item("f".into(), false, 5, ft, false);
        assert_eq!(
            (f.kind, f.size, f.mtime),
            (abi::KIND_FILE, 5, Some(1_000_000_000))
        );
        let d = item("d".into(), true, 4096, ft, true);
        assert_eq!((d.kind, d.size, d.link), (abi::KIND_DIR, 0, true));
    }

    /// An in-process SMB server on 127.0.0.1: user `alice` / `pw` owns share `s`, share `pub`
    /// is public (guest). Its dir is kept alive by the returned guard.
    fn server() -> (String, tempfile::TempDir) {
        use smb_server::{Access, LocalFsBackend, Share, SmbServer};
        let dir = tempfile::tempdir().unwrap();
        let (s, p) = (dir.path().join("s"), dir.path().join("pub"));
        std::fs::create_dir_all(&s).unwrap();
        std::fs::create_dir_all(&p).unwrap();
        let srv = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .user("alice", "pw")
            .share(
                Share::new("s", LocalFsBackend::new(&s).unwrap()).user("alice", Access::ReadWrite),
            )
            .share(Share::new("pub", LocalFsBackend::new(&p).unwrap()).public())
            .build()
            .unwrap();
        let rt = rt().unwrap();
        let addr = rt.block_on(srv.bind()).unwrap();
        rt.spawn(srv.serve());
        (format!("127.0.0.1:{}", addr.port()), dir)
    }

    fn open(url: &str) -> Result<std::sync::Arc<crate::fs::Smb>> {
        crate::fs::Smb::open(url).map(std::sync::Arc::new)
    }

    #[test]
    fn real_client_against_an_in_process_server() {
        use crate::fs::Smb;
        let (addr, _dir) = server();
        // Sign-in: asks, then refuses a wrong password, then works.
        let e = open(&format!("smb://alice@{addr}")).err().unwrap();
        assert!(e.status == abi::NEED_PASSPHRASE && !Passphrase::parse(&e.msg).wrong);
        let e = open(&format!("smb://alice@{addr}\nnope")).err().unwrap();
        assert!(Passphrase::parse(&e.msg).wrong, "{}", e.msg);
        let fs = open(&format!("smb://alice@{addr}\npw")).unwrap();
        let shares: Vec<String> = fs
            .list("")
            .unwrap()
            .all()
            .unwrap()
            .into_iter()
            .map(|i| i.name)
            .collect();
        assert!(shares.contains(&"s".to_string()), "{shares:?}");
        assert!(!shares.iter().any(|s| s.ends_with('$')), "{shares:?}");
        assert_eq!(fs.stat("s").unwrap().kind, abi::KIND_DIR);
        assert_eq!(fs.stat("nope").unwrap_err().status, abi::NOT_FOUND);

        let put = |p: &str, data: &[u8], overwrite: bool| -> Result<()> {
            let mut w = Smb::writer(&fs, p, overwrite)?;
            w.write(data)?;
            w.finish()
        };
        let get = |p: &str, off: u64| {
            let mut s = String::new();
            fs.reader(p, off).unwrap().read_to_string(&mut s).unwrap();
            s
        };
        fs.mkdir("s/d").unwrap();
        assert_eq!(fs.mkdir("s/d").unwrap_err().status, abi::EXISTS);
        put("s/d/a b.txt", b"hello world", false).unwrap();
        assert_eq!(
            put("s/d/a b.txt", b"x", false).unwrap_err().status,
            abi::EXISTS
        );
        let i = fs.stat("s/d/a b.txt").unwrap();
        assert!(
            i.kind == abi::KIND_FILE && i.size == 11 && i.mtime.is_some(),
            "{i:?}"
        );
        assert_eq!(get("s/d/a b.txt", 6), "world");
        put("s/d/a b.txt", b"new", true).unwrap();
        assert_eq!(get("s/d/a b.txt", 0), "new");
        let big = vec![7u8; CHUNK + 5];
        put("s/big", &big, false).unwrap();
        let mut l = fs.list("s").unwrap();
        assert_eq!(l.next_batch(1, &|| false).unwrap().len(), 1);
        drop(l); // stopped early: the open listing handle is closed
        fs.rename("s/big", "s/BIG").unwrap(); // case only
        fs.rename("s/BIG", "s/big").unwrap();
        let mut back = Vec::new();
        fs.reader("s/big", 0)
            .unwrap()
            .read_to_end(&mut back)
            .unwrap();
        assert!(back == big, "multi-chunk read");
        let mut w = Smb::writer(&fs, "s/d/gone", false).unwrap();
        w.write(b"partial").unwrap();
        drop(w); // abort: the temp goes
        let names = |p: &str| -> Vec<String> {
            let mut v: Vec<_> = fs
                .list(p)
                .unwrap()
                .all()
                .unwrap()
                .into_iter()
                .map(|i| i.name)
                .collect();
            v.sort();
            v
        };
        assert_eq!(names("s/d"), ["a b.txt"]);
        assert_eq!(fs.remove_dir("s/d").unwrap_err().status, abi::NOT_EMPTY);
        fs.rename("s/d/a b.txt", "s/moved").unwrap();
        assert_eq!(
            fs.reader("s/d/a b.txt", 0).err().unwrap().status,
            abi::NOT_FOUND
        );
        fs.remove_file("s/moved").unwrap();
        fs.remove_file("s/big").unwrap();
        fs.remove_dir("s/d").unwrap();
        // (Not checked on disk: the server keeps its own `.smb-*` folders there on unix.)
        assert_eq!(names("s"), Vec::<String>::new());

        // Guest: the public share works, a refused guest login says how to sign in.
        let g = open(&format!("smb://{addr}")).unwrap();
        put_guest(&g);
        assert_eq!(
            g.list("s").err().map(|e| e.status),
            Some(abi::DENIED),
            "not for guests"
        );
    }

    fn put_guest(g: &std::sync::Arc<crate::fs::Smb>) {
        let mut w = crate::fs::Smb::writer(g, "pub/g", false).unwrap();
        w.write(b"guest").unwrap();
        w.finish().unwrap();
        assert_eq!(g.stat("pub/g").unwrap().size, 5);
        g.remove_file("pub/g").unwrap();
    }

    /// Live server: `COMMANDER_SMB_TEST_URL=smb://user@host/share/dir` with the password in
    /// `COMMANDER_SMB_TEST_PASS` (empty user = guest)
    /// `cargo test -p commander_smb -- --ignored`.
    #[test]
    #[ignore = "needs a live SMB server (COMMANDER_SMB_TEST_URL)"]
    fn live_roundtrip() {
        use crate::fs::Smb;
        use std::sync::Arc;
        let url = std::env::var("COMMANDER_SMB_TEST_URL").expect("COMMANDER_SMB_TEST_URL");
        let rest = url.strip_prefix("smb://").expect("smb:// URL");
        let (auth, dir) = rest.split_once('/').expect("smb://host/share");
        let pass = std::env::var("COMMANDER_SMB_TEST_PASS").unwrap_or_default();
        let fs = Arc::new(Smb::open(&format!("smb://{auth}\n{pass}")).expect("connect"));
        let base = format!("{}/cmdr-smb-test", dir.trim_end_matches('/'));
        let f = format!("{base}/a b.txt");
        let _ = fs.remove_file(&f);
        let _ = fs.remove_dir(&base);
        fs.mkdir(&base).unwrap();
        for (data, overwrite) in [(&b"hello world"[..], false), (b"again!", true)] {
            let mut w = fs.writer(&f, overwrite).unwrap();
            w.write(data).unwrap();
            w.finish().unwrap();
        }
        let mut s = String::new();
        fs.reader(&f, 2).unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "ain!");
        assert_eq!(fs.list(&base).unwrap().all().unwrap().len(), 1);
        fs.remove_file(&f).unwrap();
        fs.remove_dir(&base).unwrap();
    }
}

//! SSH transport: one shared tokio runtime (host threads `block_on` it), connect + host-key
//! check against `known_hosts` + auth (agent, key files, bookmark password), then the `sftp`
//! subsystem. Secrets never reach error text.
use crate::config::{self, Target};
use crate::known_hosts;
use commander_plugin_abi as abi;
use commander_plugin_abi::auth::Passphrase;
use commander_plugin_abi::glue::{Error, Result};
use commander_plugin_abi::url;
use data_encoding::BASE64;
use russh::client::{self, Handle};
use russh::keys::{
    self, Algorithm, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate,
};
use russh_sftp::client::SftpSession;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;
use tokio::runtime::Runtime;
use zeroize::Zeroizing;

pub const TIMEOUT: Duration = Duration::from_secs(30);

/// The plugin's runtime (one IO thread; callers drive their own futures with `block_on`).
pub fn rt() -> Result<&'static Runtime> {
    static RT: OnceLock<std::result::Result<Runtime, String>> = OnceLock::new();
    RT.get_or_init(|| {
        // The IO thread runs this library's code: never let an unload unmap it.
        commander_plugin_abi::glue::pin_module();
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("sftp-io")
            .enable_all()
            .build()
            .map_err(|e| e.to_string())
    })
    .as_ref()
    .map_err(|m| Error::new(abi::INTERNAL, format!("sftp: runtime: {m}")))
}

/// An open SFTP session; `ssh` keeps its connection alive (`None` in tests: in-memory pipe).
pub struct Conn {
    pub sftp: SftpSession,
    pub ssh: Option<Handle<Client>>,
}

impl Conn {
    pub fn closed(&self) -> bool {
        self.ssh.as_ref().is_some_and(Handle::is_closed)
    }
}

/// Where keys and trust come from (the user's `~/.ssh`; tests use their own).
pub struct Env {
    pub known_hosts: Option<PathBuf>,
    /// Tried when the bookmark names no `identity`.
    pub default_keys: Vec<PathBuf>,
    pub agent: bool,
    /// For the whole dial (TCP, handshake, auth incl. agent signing, subsystem, SFTP init).
    pub timeout: Duration,
}

impl Env {
    pub fn user() -> Self {
        let ssh = config::home().map(|h| h.join(".ssh"));
        Self {
            known_hosts: ssh.as_ref().map(|d| d.join("known_hosts")),
            default_keys: ssh
                .map(|d| {
                    ["id_ed25519", "id_ecdsa", "id_rsa"]
                        .map(|k| d.join(k))
                        .into_iter()
                        .filter(|p| p.is_file())
                        .collect()
                })
                .unwrap_or_default(),
            agent: true,
            timeout: TIMEOUT,
        }
    }
}

/// Host-key gate. The refusal text is kept for the error (russh only says "unknown key").
pub struct Client {
    name: String,
    /// known_hosts text (read once per dial) and its path for messages.
    known: String,
    file: String,
    refused: Arc<Mutex<Option<String>>>,
}

impl Client {
    fn verify(&self, key: &PublicKey) -> std::result::Result<(), String> {
        let blob = key.to_bytes().map_err(|e| format!("sftp: host key: {e}"))?;
        let ty = recorded_as(&key.algorithm()).to_owned();
        let v = known_hosts::check(&self.known, &self.name, &ty, &blob);
        let fp = key.fingerprint(HashAlg::Sha256).to_string();
        let entry = format!("{ty} {}", BASE64.encode(&blob));
        match known_hosts::refusal(v, &self.name, &fp, &entry, &self.file) {
            None => Ok(()),
            Some(m) => Err(m),
        }
    }
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let key = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            // A certificate's own key must be in known_hosts (no @cert-authority support).
            PublicKeyOrCertificate::Certificate(c) => PublicKey::new(c.public_key().clone(), ""),
        };
        let r = self.verify(&key);
        let ok = r.is_ok();
        *self.refused.lock().unwrap_or_else(PoisonError::into_inner) = r.err();
        Ok(ok)
    }
}

/// One auth attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    Agent,
    Key(PathBuf),
    Password,
}

/// Order like OpenSSH: the named key files first (bookmark `identity`, `~/.ssh/config`
/// `IdentityFile`s), then the agent (not with `IdentitiesOnly`); no named key = the agent then
/// the default key files; the bookmark password last.
pub fn plan(t: &Target, env: &Env) -> Vec<Auth> {
    let mut v: Vec<Auth> = t.identities.iter().cloned().map(Auth::Key).collect();
    if env.agent && !t.identities_only {
        v.push(Auth::Agent);
    }
    if t.identities.is_empty() {
        v.extend(env.default_keys.iter().cloned().map(Auth::Key));
    }
    if t.pass.is_some() {
        v.push(Auth::Password);
    }
    v
}

type Agent = keys::agent::client::AgentClient<
    Box<dyn keys::agent::client::AgentStream + Send + Unpin + 'static>,
>;

/// The running ssh agent: OpenSSH's (named pipe on Windows, `SSH_AUTH_SOCK` elsewhere), else
/// Pageant (Windows).
async fn agent() -> Option<Agent> {
    use keys::agent::client::AgentClient;
    #[cfg(windows)]
    {
        if let Ok(a) = AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await {
            return Some(a.dynamic());
        }
        AgentClient::connect_pageant()
            .await
            .ok()
            .map(|a| a.dynamic())
    }
    #[cfg(not(windows))]
    {
        AgentClient::connect_env().await.ok().map(|a| a.dynamic())
    }
}

/// Key passphrases that worked, per key file, until the plugin is unloaded (memory only; wiped
/// on drop).
static PASSPHRASES: Mutex<BTreeMap<PathBuf, Zeroizing<String>>> = Mutex::new(BTreeMap::new());

fn passphrases() -> std::sync::MutexGuard<'static, BTreeMap<PathBuf, Zeroizing<String>>> {
    PASSPHRASES.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Why a key file can't be used.
#[derive(Debug)]
enum KeyErr {
    /// Encrypted, and no passphrase or a refused one (`wrong`).
    Locked {
        wrong: bool,
    },
    Bad(keys::Error),
}

/// Key files a `NEED_PASSPHRASE` asked the user about (no working passphrase yet): only these
/// get the passphrase the host sends back, so it is never tried on another key.
static ASKED: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());

fn asked() -> std::sync::MutexGuard<'static, BTreeSet<PathBuf>> {
    ASKED.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Load key file `p`; an encrypted one with its cached passphrase, else, if the user was asked
/// about `p`, with `fresh` (the one just typed: taken, so it is tried on one key only); cached
/// when it works.
fn load_key(
    p: &Path,
    fresh: &mut Option<Zeroizing<String>>,
) -> std::result::Result<PrivateKey, KeyErr> {
    match keys::load_secret_key(p, None) {
        Err(keys::Error::KeyIsEncrypted) => {}
        r => return r.map_err(KeyErr::Bad),
    }
    let cached = passphrases().get(p).cloned();
    let (pw, is_cached) = match cached {
        Some(c) => (c, true),
        None => match fresh.take_if(|_| asked().contains(p)) {
            Some(f) => (f, false),
            None => return Err(KeyErr::Locked { wrong: false }),
        },
    };
    match keys::load_secret_key(p, Some(pw.as_str())) {
        Ok(k) => {
            asked().remove(p);
            passphrases().insert(p.to_owned(), pw);
            Ok(k)
        }
        Err(_) => {
            passphrases().remove(p);
            Err(KeyErr::Locked { wrong: !is_cached })
        }
    }
}

/// Runs [`plan`]; `Err` lists what was tried (never a secret). All failed and a key file needs
/// a passphrase: `NEED_PASSPHRASE` for the first such key (the host asks and reopens).
async fn authenticate(s: &mut Handle<Client>, t: &Target, env: &Env) -> Result<()> {
    let name = format!("{}@{}", t.user, known_hosts::lookup_name(&t.host, t.port));
    let io = |e: russh::Error| Error::new(abi::IO, format!("sftp: {name}: {e}"));
    let rsa = s.best_supported_rsa_hash().await.map_err(io)?.flatten();
    let mut tried = Vec::new();
    let mut fresh = t.passphrase.clone();
    let mut ask: Option<(PathBuf, Passphrase)> = None;
    for a in plan(t, env) {
        let ok = match &a {
            Auth::Agent => {
                let Some(mut ag) = agent().await else {
                    continue;
                };
                let ids = ag.request_identities().await.unwrap_or_default();
                tried.push(format!("agent ({} keys)", ids.len()));
                let mut ok = false;
                for id in ids {
                    let key = id.public_key().into_owned();
                    let r = s.authenticate_publickey_with(&t.user, key, rsa, &mut ag);
                    if r.await.is_ok_and(|r| r.success()) {
                        ok = true;
                        break;
                    }
                }
                ok
            }
            Auth::Key(p) => {
                let shown = p.display();
                match load_key(p, &mut fresh) {
                    Ok(k) => {
                        tried.push(shown.to_string());
                        let k = PrivateKeyWithHashAlg::new(Arc::new(k), rsa);
                        s.authenticate_publickey(&t.user, k)
                            .await
                            .map_err(io)?
                            .success()
                    }
                    Err(KeyErr::Locked { wrong }) => {
                        let (why, msg) = match wrong {
                            true => ("wrong passphrase", "wrong passphrase for key"),
                            false => ("passphrase needed", "passphrase needed for key"),
                        };
                        tried.push(format!("{shown} ({why})"));
                        ask.get_or_insert_with(|| {
                            let x = Passphrase {
                                msg: format!("sftp: {name}: {msg} {shown}"),
                                key: shown.to_string(),
                                wrong,
                                password: false,
                            };
                            (p.clone(), x)
                        });
                        false
                    }
                    Err(KeyErr::Bad(e)) => {
                        tried.push(format!("{shown} ({e})"));
                        false
                    }
                }
            }
            Auth::Password => {
                tried.push("password".into());
                let pass = t.pass.clone().unwrap_or_default();
                s.authenticate_password(&t.user, pass)
                    .await
                    .map_err(io)?
                    .success()
            }
        };
        if ok {
            return Ok(());
        }
    }
    if let Some((key, p)) = ask {
        asked().insert(key);
        return Err(Error::new(abi::NEED_PASSPHRASE, p.detail()));
    }
    let tried = match tried.is_empty() {
        true => "nothing: no agent, key file or bookmark password".to_owned(),
        false => tried.join(", "),
    };
    Err(Error::new(
        abi::AUTH,
        format!("sftp: {name}: authentication failed (tried {tried})"),
    ))
}

/// The type a known_hosts line records for a host-key algorithm (RSA signs with
/// `rsa-sha2-*` but is recorded as `ssh-rsa`).
fn recorded_as(a: &Algorithm) -> &str {
    match a {
        Algorithm::Rsa { .. } => "ssh-rsa",
        a => a.as_str(),
    }
}

/// Host-key algorithms to ask for: only the recorded types (like OpenSSH), in russh's order.
/// `None` = nothing recorded (or none supported): russh's defaults.
fn host_key_algos(recorded: &[String]) -> Option<Vec<Algorithm>> {
    let all = russh::Preferred::default().key;
    let v: Vec<Algorithm> = all
        .iter()
        .filter(|a| recorded.iter().any(|r| r == recorded_as(a)))
        .cloned()
        .collect();
    (!v.is_empty()).then_some(v)
}

/// Connect, verify the host key, log in and start the `sftp` subsystem, all within
/// [`TIMEOUT`] (a stuck agent signature or server can't hang a worker).
pub fn connect(t: &Target, env: &Env) -> Result<Conn> {
    let name = known_hosts::lookup_name(&t.host, t.port);
    let io = |e: &dyn std::fmt::Display| Error::new(abi::IO, format!("sftp: {name}: {e}"));
    let file = env.known_hosts.as_ref().ok_or_else(|| {
        Error::new(
            abi::AUTH,
            "sftp: no home directory (needed for ~/.ssh/known_hosts)",
        )
    })?;
    let known = url::read_optional(file)
        .map_err(|m| Error::new(abi::IO, m))?
        .unwrap_or_default();
    let recorded = known_hosts::recorded_types(&known, &name);
    let mut cfg = client::Config {
        keepalive_interval: Some(TIMEOUT),
        nodelay: true,
        ..client::Config::default()
    };
    if let Some(algos) = host_key_algos(&recorded) {
        cfg.preferred.key = algos.into();
    }
    let refused = Arc::default();
    let h = Client {
        name: name.clone(),
        known,
        file: file.display().to_string(),
        refused: Arc::clone(&refused),
    };
    let dial = async {
        let addr = (t.host.as_str(), t.port);
        let mut s = match client::connect(Arc::new(cfg), addr, h).await {
            Ok(s) => s,
            Err(e) => {
                let why = refused
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take();
                let no_host_key = matches!(
                    e,
                    russh::Error::NoCommonAlgo {
                        kind: russh::AlgorithmKind::Key,
                        ..
                    }
                );
                return Err(match why {
                    Some(m) => Error::new(abi::AUTH, m),
                    // The server lacks every recorded key type: never fall back to another.
                    None if no_host_key && !recorded.is_empty() => Error::new(
                        abi::AUTH,
                        format!(
                            "sftp: {name}: {e} (the host has a {} key recorded; refused)",
                            recorded.join(" / ")
                        ),
                    ),
                    None => io(&e),
                });
            }
        };
        authenticate(&mut s, t, env).await?;
        let ch = s.channel_open_session().await.map_err(|e| io(&e))?;
        ch.request_subsystem(true, "sftp")
            .await
            .map_err(|e| io(&e))?;
        let sftp = SftpSession::new(ch.into_stream())
            .await
            .map_err(|e| io(&e))?;
        sftp.set_timeout(TIMEOUT.as_secs());
        Ok(Conn { sftp, ssh: Some(s) })
    };
    let rt = rt()?;
    // The timer is made inside the runtime (an async block is lazy).
    rt.block_on(async { tokio::time::timeout(env.timeout, dial).await })
        .unwrap_or_else(|e| Err(io(&e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(identity: Option<&str>, pass: bool) -> Target {
        Target {
            host: "h".into(),
            port: 22,
            user: "u".into(),
            pass: pass.then(|| "pw".into()),
            identities: identity.into_iter().map(Into::into).collect(),
            identities_only: false,
            passphrase: None,
        }
    }

    #[test]
    fn auth_plan() {
        let env = Env {
            known_hosts: None,
            default_keys: vec!["d1".into(), "d2".into()],
            agent: true,
            timeout: TIMEOUT,
        };
        let k = |p: &str| Auth::Key(p.into());
        assert_eq!(
            plan(&target(None, true), &env),
            [Auth::Agent, k("d1"), k("d2"), Auth::Password]
        );
        assert_eq!(
            plan(&target(Some("mine"), false), &env),
            [k("mine"), Auth::Agent],
            "an explicit identity replaces the defaults"
        );
        let none = Env {
            agent: false,
            timeout: TIMEOUT,
            default_keys: Vec::new(),
            ..env
        };
        assert_eq!(plan(&target(None, false), &none), []);
        let only = Target {
            identities_only: true,
            ..target(Some("mine"), false)
        };
        assert_eq!(
            plan(
                &only,
                &Env {
                    agent: true,
                    ..none
                }
            ),
            [k("mine")],
            "IdentitiesOnly: no agent"
        );
        assert!(Env::user().agent);
    }

    use crate::fake;
    use std::path::Path;

    /// Own scratch dir per test (tests run in parallel).
    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cmdr-sftp-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn local(port: u16, pass: Option<&str>, identity: Option<&Path>) -> Target {
        Target {
            host: "127.0.0.1".into(),
            port,
            user: "me".into(),
            pass: pass.map(Into::into),
            identities: identity.into_iter().map(Into::into).collect(),
            identities_only: false,
            passphrase: None,
        }
    }

    /// `known_hosts` with `line` (`{name}` = the server's lookup name).
    fn env(dir: &Path, port: u16, line: &str) -> Env {
        let kh = dir.join("known_hosts");
        let name = known_hosts::lookup_name("127.0.0.1", port);
        std::fs::write(&kh, line.replace("{name}", &name)).unwrap();
        Env {
            known_hosts: Some(kh),
            default_keys: Vec::new(),
            agent: false, // never the developer's real agent
            timeout: TIMEOUT,
        }
    }

    fn list(c: &Conn) -> Vec<String> {
        let rd = rt().unwrap().block_on(c.sftp.read_dir("/")).unwrap();
        rd.map(|e| e.file_name().to_string_lossy().into_owned())
            .collect()
    }

    fn served() -> fake::Shared {
        let st = fake::Shared::default();
        st.lock().unwrap().tree.insert("/hello".into(), None);
        st
    }

    #[test]
    fn password_login_over_ssh() {
        let port = fake::ssh_server(served(), "pw");
        let d = scratch("pw");
        let e = env(&d, port, &format!("# x\n{{name}} {}\n", fake::HOST_PUB));
        let c = connect(&local(port, Some("pw"), None), &e).unwrap();
        assert!(list(&c).contains(&"hello".to_string()));
        assert!(!c.closed());
        let err = connect(&local(port, Some("wrong-pw"), None), &e)
            .err()
            .unwrap();
        assert_eq!(err.status, abi::AUTH);
        assert!(
            err.msg.contains("tried password") && !err.msg.contains("wrong-pw"),
            "{}",
            err.msg
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn key_file_login_and_encrypted_key() {
        let port = fake::ssh_server(served(), "pw");
        let d = scratch("key");
        let e = env(&d, port, &format!("{{name}} {}\n", fake::HOST_PUB));
        let key = d.join("id");
        std::fs::write(&key, fake::USER_KEY).unwrap();
        let c = connect(&local(port, None, Some(&key)), &e).unwrap();
        assert!(list(&c).contains(&"hello".to_string()));
        let err = connect(&local(port, None, Some(&d.join("missing"))), &e)
            .err()
            .unwrap();
        assert_eq!(err.status, abi::AUTH, "{}", err.msg);
        // Default keys are used when the bookmark names none.
        let e = Env {
            default_keys: vec![key],
            ..e
        };
        assert!(connect(&local(port, None, None), &e).is_ok());
        let none = Env {
            default_keys: Vec::new(),
            ..e
        };
        let err = connect(&local(port, None, None), &none).err().unwrap();
        assert!(err.msg.contains("tried nothing"), "{}", err.msg);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn encrypted_key_asks_for_its_passphrase() {
        let port = fake::ssh_server(served(), "pw");
        let d = scratch("enc");
        let e = env(&d, port, &format!("{{name}} {}\n", fake::HOST_PUB));
        let enc = d.join("enc");
        std::fs::write(&enc, fake::ENCRYPTED_KEY).unwrap();
        let with = |pw: Option<&str>| Target {
            passphrase: pw.map(|p| Zeroizing::new(p.into())),
            ..local(port, None, Some(&enc))
        };
        let asked = |pw: Option<&str>| {
            let err = connect(&with(pw), &e).err().unwrap();
            assert_eq!(err.status, abi::NEED_PASSPHRASE, "{}", err.msg);
            assert!(!err.msg.contains("hunter2"), "{}", err.msg);
            Passphrase::parse(&err.msg)
        };
        let p = asked(None);
        assert_eq!((p.key, p.wrong), (enc.display().to_string(), false));
        assert!(p.msg.contains("passphrase needed"), "{}", p.msg);
        let p = asked(Some("hunter2"));
        assert!(p.wrong && p.msg.contains("wrong passphrase"), "{}", p.msg);
        let c = connect(&with(Some("secret")), &e).unwrap();
        assert!(list(&c).contains(&"hello".to_string()));
        // Cached for the session: no second prompt, a stale typed one is not even tried.
        assert!(connect(&with(None), &e).is_ok());
        assert!(connect(&with(Some("hunter2")), &e).is_ok());
        // A password that works wins over asking.
        passphrases().remove(&enc);
        let t = Target {
            pass: Some("pw".into()),
            ..with(None)
        };
        assert!(connect(&t, &e).is_ok());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn typed_passphrase_goes_only_to_the_key_asked_about() {
        let port = fake::ssh_server(served(), "pw");
        let d = scratch("enc2");
        let e = env(&d, port, &format!("{{name}} {}\n", fake::HOST_PUB));
        let (a, b) = (d.join("a"), d.join("b"));
        std::fs::write(&a, fake::OTHER_ENCRYPTED_KEY).unwrap(); // the server rejects it
        std::fs::write(&b, fake::ENCRYPTED_KEY).unwrap();
        let with = |pw: Option<&str>| Target {
            passphrase: pw.map(|p| Zeroizing::new(p.into())),
            identities: vec![a.clone(), b.clone()],
            ..local(port, None, None)
        };
        let ask = |pw: Option<&str>| Passphrase::parse(&connect(&with(pw), &e).err().unwrap().msg);
        assert_eq!(ask(None).key, a.display().to_string());
        // A's passphrase: A decrypts (cached) but is refused; now B is asked about.
        let p = ask(Some("other"));
        assert_eq!((p.key, p.wrong), (b.display().to_string(), false));
        // B's passphrase reaches B (not swallowed by cached A) and connects.
        assert!(connect(&with(Some("secret")), &e).is_ok());
        assert!(!asked().contains(&a) && !asked().contains(&b));
        // A stale secret is never tried on a key nobody asked about.
        passphrases().remove(&b);
        let p = ask(Some("other"));
        assert_eq!((p.key, p.wrong), (b.display().to_string(), false));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn host_key_must_be_known() {
        let port = fake::ssh_server(served(), "pw");
        let d = scratch("hk");
        let t = local(port, Some("pw"), None);
        let err = connect(&t, &env(&d, port, "")).err().unwrap();
        assert_eq!(err.status, abi::AUTH);
        assert!(err.msg.contains("unknown host key SHA256:"), "{}", err.msg);
        let want = format!("[127.0.0.1]:{port} {}", fake::HOST_PUB);
        assert!(
            err.msg.contains(&want),
            "suggests the line to add: {}",
            err.msg
        );
        let other = format!("{{name}} ssh-ed25519 {}\n", fake::USER_PUB);
        let err = connect(&t, &env(&d, port, &other)).err().unwrap();
        assert!(err.msg.contains("HOST KEY CHANGED"), "{}", err.msg);
        let no_home = Env {
            known_hosts: None,
            default_keys: Vec::new(),
            agent: false,
            timeout: TIMEOUT,
        };
        let err = connect(&t, &no_home).err().unwrap();
        assert!(err.msg.contains("no home directory"), "{}", err.msg);
        // Only an RSA key recorded: ask for RSA only, never accept the server's ed25519.
        let rsa = "{name} ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ\n";
        let err = connect(&t, &env(&d, port, rsa)).err().unwrap();
        assert_eq!(err.status, abi::AUTH);
        assert!(
            err.msg.contains("has a ssh-rsa key recorded"),
            "{}",
            err.msg
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn recorded_types_pick_host_key_algorithms() {
        assert_eq!(host_key_algos(&[]), None);
        assert_eq!(host_key_algos(&["ssh-dss-unknown".into()]), None);
        let ed = host_key_algos(&["ssh-ed25519".into()]).unwrap();
        assert_eq!(ed, [Algorithm::Ed25519]);
        let rsa = host_key_algos(&["ssh-rsa".into()]).unwrap();
        assert!(!rsa.is_empty() && rsa.iter().all(|a| recorded_as(a) == "ssh-rsa"));
    }

    #[test]
    fn unreachable_server_is_io() {
        // Keep the port bound (a freed port can be reused by a parallel test's fake server):
        // accept and drop at once, so the SSH handshake fails with a plain IO error.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming() {
                drop(s);
            }
        });
        let d = scratch("unreach");
        // A recorded key must not turn a refused connection into a host-key refusal.
        let kh = format!("{{name}} {}\n", fake::HOST_PUB);
        let err = connect(&local(port, None, None), &env(&d, port, &kh))
            .err()
            .unwrap();
        assert_eq!(err.status, abi::IO, "{}", err.msg);
        assert!(!err.msg.contains("recorded"), "{}", err.msg);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_silent_server_times_out() {
        // Accepts TCP (backlog) but never speaks SSH.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let d = scratch("silent");
        let e = Env {
            timeout: Duration::from_millis(300),
            ..env(&d, port, "")
        };
        let err = connect(&local(port, None, None), &e).err().unwrap();
        assert_eq!(err.status, abi::IO);
        assert!(err.msg.contains("deadline"), "{}", err.msg);
        drop(l);
        std::fs::remove_dir_all(&d).unwrap();
    }
}

//! Test-only scripted FTP server on 127.0.0.1: in-memory tree, PASV data connections, the
//! commands suppaftp sends for our ops, plus knobs for server quirks and failures.
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct State {
    /// Absolute path -> file bytes (`None` = dir). "/" is implicit.
    pub tree: BTreeMap<String, Option<Vec<u8>>>,
    /// Absolute path -> link target (absolute).
    pub links: BTreeMap<String, String>,
    /// MLSD/MLST answer 502: LIST fallback.
    pub no_mlsx: bool,
    /// RNTO onto an existing path fails (Windows-like servers).
    pub no_replace: bool,
    /// Every RNTO fails.
    pub rnto_fail: bool,
    /// Every command seen (for asserts).
    pub log: Vec<String>,
    /// The next N `*.cmdr-part` names probed (MLST) already exist: as symlinks to `/victim`
    /// (`squat_link`) or as plain files.
    pub squat: usize,
    pub squat_link: bool,
    /// RETR sends only this many bytes, then fails the transfer (426).
    pub cut: Option<usize>,
}

/// `TYPE A` on a Unix server: LF on disk, CRLF on the wire.
fn wire(data: &[u8], ascii: bool) -> Vec<u8> {
    match ascii {
        true => data.iter().fold(Vec::new(), |mut v, &b| {
            if b == b'\n' {
                v.push(b'\r');
            }
            v.push(b);
            v
        }),
        false => data.to_vec(),
    }
}

/// The wire's CRLF back to the disk's LF (`TYPE A` upload).
fn disk(data: Vec<u8>, ascii: bool) -> Vec<u8> {
    match ascii {
        true => String::from_utf8(data)
            .unwrap()
            .replace("\r\n", "\n")
            .into(),
        false => data,
    }
}

pub type Shared = Arc<Mutex<State>>;

/// Serves until the process ends; returns the port.
pub fn start(state: Shared) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let st = Arc::clone(&state);
            std::thread::spawn(move || {
                let _ = session(s, &st);
            });
        }
    });
    port
}

fn parent(p: &str) -> &str {
    match p.rsplit_once('/') {
        Some(("", _)) | None => "/",
        Some((d, _)) => d,
    }
}

fn name(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

impl State {
    fn is_dir(&self, p: &str) -> bool {
        p == "/" || matches!(self.tree.get(p), Some(None))
    }

    fn exists(&self, p: &str) -> bool {
        p == "/" || self.tree.contains_key(p) || self.links.contains_key(p)
    }

    fn children(&self, d: &str) -> Vec<String> {
        self.tree
            .keys()
            .chain(self.links.keys())
            .filter(|k| parent(k) == d && *k != "/")
            .cloned()
            .collect()
    }

    fn line(&self, p: &str, mlsd: bool) -> String {
        let n = name(p);
        match (self.links.get(p), self.tree.get(p), mlsd) {
            (Some(t), _, true) => format!("type=OS.unix=slink:{t};modify=20200101000000; {n}"),
            (Some(t), _, false) => format!("lrwxrwxrwx 1 u g 4 Jan 01  2020 {n} -> {t}"),
            (_, Some(None), true) => format!("type=dir;modify=20200101000000; {n}"),
            (_, Some(None), false) => format!("drwxr-xr-x 2 u g 0 Jan 01  2020 {n}"),
            (_, Some(Some(d)), true) => {
                format!("type=file;size={};modify=20200101000000; {n}", d.len())
            }
            (_, Some(Some(d)), false) => format!("-rw-r--r-- 1 u g {} Jan 01  2020 {n}", d.len()),
            _ => String::new(),
        }
    }
}

/// The client's data connection, or an error after 10 s (a test never hangs on it).
fn accept(l: Option<TcpListener>) -> std::io::Result<TcpStream> {
    let l = l.ok_or_else(|| std::io::Error::other("no PASV before the data command"))?;
    l.set_nonblocking(true)?;
    let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match l.accept() {
            Ok((s, _)) => {
                s.set_nonblocking(false)?;
                return Ok(s);
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    && std::time::Instant::now() < end =>
            {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(e) => return Err(e),
        }
    }
}

fn session(s: TcpStream, st: &Shared) -> std::io::Result<()> {
    let mut out = s.try_clone()?;
    let mut rd = BufReader::new(s);
    let mut say = |m: &str| out.write_all(format!("{m}\r\n").as_bytes());
    say("220 fake")?;
    let (mut cwd, mut pasv, mut rest, mut rnfr) = ("/".to_string(), None, 0usize, None);
    let mut ascii = false;
    let mut line = String::new();
    loop {
        line.clear();
        if rd.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let l = line.trim_end_matches(['\r', '\n']);
        let (cmd, arg) = l.split_once(' ').unwrap_or((l, ""));
        let p = match arg.starts_with('/') {
            true => arg.to_string(),
            false => format!("{}/{arg}", cwd.trim_end_matches('/')),
        };
        let mut g = st.lock().unwrap();
        g.log.push(l.to_string());
        if cmd == "MLST" && arg.ends_with(".cmdr-part") && g.squat > 0 {
            g.squat -= 1;
            match g.squat_link {
                true => g.links.insert(arg.into(), "/victim".into()).is_none(),
                false => g.tree.insert(arg.into(), Some(b"squat".to_vec())).is_none(),
            };
        }
        let reply = match cmd {
            "USER" => "331 pass".into(),
            "PASS" if arg == "bad" => "530 Login incorrect".into(),
            "PASS" => "230 in".into(),
            "TYPE" => {
                ascii = arg.starts_with('A');
                "200 ok".into()
            }
            "NOOP" => "200 ok".into(),
            "CWD" if arg == "/die" => return Ok(()), // drops the connection
            "CWD" => {
                let p = g.links.get(&p).cloned().unwrap_or(p);
                match g.is_dir(&p) {
                    true => {
                        cwd = p;
                        "250 ok".into()
                    }
                    false => "550 No such directory".into(),
                }
            }
            "PASV" => {
                let l = TcpListener::bind("127.0.0.1:0")?;
                let port = l.local_addr()?.port();
                pasv = Some(l);
                format!(
                    "227 Entering Passive Mode (127,0,0,1,{},{})",
                    port >> 8,
                    port & 255
                )
            }
            "REST" => {
                rest = arg.parse().unwrap_or(0);
                "350 ok".into()
            }
            "MLSD" | "LIST" if g.no_mlsx && cmd == "MLSD" => "502 not implemented".into(),
            "MLSD" | "LIST" => {
                let body: String = g
                    .children(&cwd)
                    .iter()
                    .map(|c| g.line(c, cmd == "MLSD") + "\r\n")
                    .collect();
                drop(g);
                say("150 here")?;
                let mut d = accept(pasv.take())?;
                d.write_all(format!("total 1\r\n{body}").as_bytes())?;
                drop(d);
                "226 done".into()
            }
            "MLST" if g.no_mlsx => "502 not implemented".into(),
            "MLST" => match g.exists(arg) {
                true => format!("250-Listing\r\n {}\r\n250 End", {
                    let l = g.line(arg, true);
                    let (facts, _) = l.split_once("; ").unwrap();
                    format!("{facts}; {arg}")
                }),
                false => "550 No such file".into(),
            },
            "RETR" => match g.tree.get(&p).cloned().flatten() {
                None => "550 No such file".into(),
                Some(data) => {
                    let cut = g.cut;
                    drop(g);
                    say("150 sending")?;
                    let mut d = accept(pasv.take())?;
                    let data = wire(&data[rest.min(data.len())..], ascii);
                    d.write_all(&data[..cut.unwrap_or(data.len()).min(data.len())])?;
                    rest = 0;
                    drop(d);
                    match cut {
                        Some(_) => "426 Connection closed; transfer aborted".into(),
                        None => "226 done".into(),
                    }
                }
            },
            "STOR" => {
                drop(g);
                say("150 send it")?;
                let mut d = accept(pasv.take())?;
                let mut buf = Vec::new();
                d.read_to_end(&mut buf)?;
                st.lock().unwrap().tree.insert(p, Some(disk(buf, ascii)));
                "226 stored".into()
            }
            "MKD" => match (g.exists(&p), g.is_dir(parent(&p))) {
                (false, true) => {
                    g.tree.insert(p.clone(), None);
                    format!("257 \"{p}\" created")
                }
                _ => "550 Create directory operation failed".into(),
            },
            "RMD" => match (g.is_dir(&p), g.children(&p).is_empty()) {
                (true, true) => {
                    g.tree.remove(&p);
                    "250 removed".into()
                }
                (true, false) => "550 Directory not empty".into(),
                _ => "550 No such directory".into(),
            },
            "DELE" => match g.tree.get(&p) {
                Some(Some(_)) => {
                    g.tree.remove(&p);
                    "250 deleted".into()
                }
                _ => "550 No such file".into(),
            },
            "RNFR" => match g.exists(&p) {
                true => {
                    rnfr = Some(p);
                    "350 ready".into()
                }
                false => "550 No such file".into(),
            },
            "RNTO" => {
                let to = p;
                match rnfr.take() {
                    _ if g.rnto_fail => "553 Rename failed".into(),
                    _ if g.no_replace && g.exists(&to) => "550 File exists".into(),
                    Some(from) => {
                        let v = g.tree.remove(&from).unwrap_or(None);
                        g.tree.insert(to, v);
                        "250 renamed".into()
                    }
                    None => "503 RNFR first".into(),
                }
            }
            "QUIT" => {
                say("221 bye")?;
                return Ok(());
            }
            _ => "502 not implemented".into(),
        };
        say(&reply)?;
    }
}

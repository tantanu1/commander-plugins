//! In-memory stand-in for 7z.exe (tests): interprets our argv (`l`/`e`/`t`/`a`/`d`/`rn`),
//! checks the stdin password for encrypted items, and touches the archive file on writes.
use crate::exe::{Done, Engine};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Read};
use std::path::Path;
use std::sync::Mutex;

#[derive(Default)]
struct State {
    /// path ('/'-separated) -> (body, is_dir, encrypted)
    items: BTreeMap<String, (Vec<u8>, bool, bool)>,
    password: Option<String>,
    /// (only this command, else any; stderr text) of the next failing run.
    fail: Option<(Option<String>, String)>,
    /// Next `e` stream: Some(true) = extra bytes after the body, Some(false) = a CRC error.
    tail: Option<bool>,
    /// Next `a` reports success but stores nothing.
    lose_add: bool,
    writes: usize,
    last_test: String,
    argvs: Vec<Vec<String>>,
}

#[derive(Default)]
pub struct Fake(Mutex<State>);

fn done(code: i32, out: Vec<u8>, err: &str) -> Done {
    Done {
        code: Some(code),
        out,
        err: err.as_bytes().to_vec(),
    }
}

impl Fake {
    fn st(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap()
    }
    pub fn add(&self, path: &str, body: &str, encrypted: bool) {
        let v = (body.as_bytes().to_vec(), false, encrypted);
        self.st().items.insert(path.into(), v);
    }
    pub fn set_password(&self, pw: &str) {
        self.st().password = Some(pw.into());
    }
    pub fn fail_next(&self, msg: &str) {
        self.st().fail = Some((None, msg.into()));
    }
    pub fn fail_on(&self, cmd: &str, msg: &str) {
        self.st().fail = Some((Some(cmd.into()), msg.into()));
    }
    pub fn lose_next_add(&self) {
        self.st().lose_add = true;
    }
    pub fn tail(&self, extra: bool) {
        self.st().tail = Some(extra);
    }
    pub fn calls(&self) -> usize {
        self.st().writes
    }
    pub fn last_test(&self) -> String {
        self.st().last_test.clone()
    }
    pub fn saw_switch(&self, s: &str) -> bool {
        self.st().argvs.iter().flatten().any(|a| a == s)
    }
    pub fn argv_has(&self, s: &str) -> bool {
        self.st().argvs.iter().flatten().any(|a| a.contains(s))
    }

    /// The password line on stdin unlocks an encrypted item?
    fn unlocked(st: &State, encrypted: bool, stdin: &[u8]) -> Result<(), Done> {
        if !encrypted {
            return Ok(());
        }
        let given = String::from_utf8_lossy(stdin);
        match given.lines().next() {
            None => Err(done(
                255,
                b"Enter password (will not be echoed):".to_vec(),
                "Break signaled",
            )),
            Some(p) if Some(p) == st.password.as_deref() => Ok(()),
            Some(_) => Err(done(2, Vec::new(), "ERROR: Wrong password : x")),
        }
    }

    fn exec(&self, args: &[OsString], cwd: Option<&Path>, stdin: &[u8]) -> Result<Done, Done> {
        let a: Vec<String> = args
            .iter()
            .map(|x| x.to_string_lossy().into_owned())
            .collect();
        let mut st = self.st();
        st.argvs.push(a.clone());
        if let Some((cmd, msg)) = st.fail.take() {
            match cmd.as_ref().is_none_or(|c| *c == a[0]) {
                true => return Err(done(2, Vec::new(), &msg)),
                false => st.fail = Some((cmd, msg)),
            }
        }
        let dd = a.iter().position(|x| x == "--").expect("argv without --");
        let (archive, names) = (Path::new(&a[dd + 1]), &a[dd + 2..]);
        let enc = a[..dd].iter().any(|x| x == "-p");
        let out = match a[0].as_str() {
            "l" => {
                let mut s = String::from("7-Zip (fake)\n\n--\nPath = arc\n\n----------\n");
                for (p, (b, dir, e)) in &st.items {
                    let pm = |f: bool| if f { '+' } else { '-' };
                    s += &format!(
                        "Path = {p}\nSize = {}\nFolder = {}\nEncrypted = {}\n\n",
                        b.len(),
                        pm(*dir),
                        pm(*e)
                    );
                }
                s.into_bytes()
            }
            "e" | "t" => {
                let hit = st.items.get(&names[0]).cloned();
                st.last_test.clone_from(&names[0]);
                let (body, _, e) = hit.clone().unwrap_or_default();
                Self::unlocked(&st, e, stdin)?;
                match (a[0].as_str(), hit) {
                    // Like 7z: a test matching nothing still exits 0.
                    ("t", None) => b"No files to process\nEverything is Ok\n\nFiles: 0\n".to_vec(),
                    ("t", Some(_)) => b"Everything is Ok\n".to_vec(),
                    _ => body,
                }
            }
            cmd => {
                let cwd = cwd.unwrap_or(Path::new("."));
                let lose = std::mem::take(&mut st.lose_add);
                for n in names.iter().filter(|_| cmd == "a" && !lose) {
                    let p = cwd.join(n);
                    let v = match p.is_dir() {
                        true => (Vec::new(), true, false),
                        false => (std::fs::read(&p).unwrap(), false, enc),
                    };
                    st.items.insert(n.clone(), v);
                }
                let under = |k: &str, n: &str| k == n || k.starts_with(&format!("{n}/"));
                if cmd == "d" {
                    st.items.retain(|k, _| !names.iter().any(|n| under(k, n)));
                }
                if cmd == "rn" {
                    let (from, to) = (&names[0], &names[1]);
                    let moved: Vec<String> = st
                        .items
                        .keys()
                        .filter(|k| under(k, from))
                        .cloned()
                        .collect();
                    for k in moved {
                        let v = st.items.remove(&k).unwrap();
                        st.items.insert(format!("{to}{}", &k[from.len()..]), v);
                    }
                }
                st.writes += 1;
                let len = std::fs::metadata(archive).map_or(0, |m| m.len());
                std::fs::write(archive, vec![b'x'; len as usize + 1]).unwrap();
                Vec::new()
            }
        };
        Ok(done(0, out, ""))
    }
}

/// What a failed `e -so` looks like at EOF: an error after the data.
struct Broken;

impl Read for Broken {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("7-Zip failed (2): CRC Failed : x"))
    }
}

impl Engine for Fake {
    fn run(&self, args: &[OsString], cwd: Option<&Path>, stdin: &[u8]) -> io::Result<Done> {
        Ok(self.exec(args, cwd, stdin).unwrap_or_else(|d| d))
    }

    fn stream(&self, args: &[OsString], stdin: &[u8]) -> io::Result<Box<dyn Read + Send>> {
        let tail = self.st().tail.take();
        match self.exec(args, None, stdin) {
            Ok(d) => {
                let body = io::Cursor::new(d.out);
                Ok(match tail {
                    None => Box::new(body),
                    Some(true) => Box::new(body.chain(&b"more"[..])),
                    Some(false) => Box::new(body.chain(Broken)),
                })
            }
            Err(d) => Err(io::Error::other(
                String::from_utf8_lossy(&d.err).into_owned(),
            )),
        }
    }
}

//! In-memory guest for tests: behaves like VIX (put replaces, remove_dir is recursive, rename
//! replaces a file on POSIX guests and refuses any existing target on Windows). Shared state so tests can look inside and inject failures.
use crate::backend::Backend;
use commander_plugin_abi::glue::{Error, Item, Result};
use commander_plugin_abi::{self as abi};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct State {
    /// Absolute guest path -> file bytes (`None` = folder).
    pub nodes: BTreeMap<String, Option<Vec<u8>>>,
    pub sep: char,
    pub user: Option<String>,
    pub fail_put: bool,
    pub fail_rename: bool,
    pub fail_stat: bool,
    /// Calls made (`op path`), for tests.
    pub log: Vec<String>,
}

impl State {
    pub fn put(&mut self, path: &str, data: &[u8]) {
        self.nodes.insert(path.into(), Some(data.to_vec()));
    }

    pub fn dir(&mut self, path: &str) {
        self.nodes.insert(path.into(), None);
    }

    fn parent<'a>(&self, p: &'a str) -> &'a str {
        let i = p.trim_end_matches(self.sep).rfind(self.sep).unwrap_or(0);
        match &p[..i] {
            "" => &p[..1],                        // `/x` -> `/`
            d if d.ends_with(':') => &p[..i + 1], // `C:\x` -> `C:\`
            d => d,
        }
    }

    fn children(&self, dir: &str) -> Vec<String> {
        let dir = dir.trim_end_matches(self.sep);
        self.nodes
            .keys()
            .filter(|k| {
                let k = k.as_str();
                k.len() > dir.len() + 1 && k.starts_with(dir) && {
                    let rest = &k[dir.len()..];
                    rest.starts_with(self.sep) && !rest[1..].contains(self.sep)
                }
            })
            .cloned()
            .collect()
    }

    fn need(&self, p: &str) -> Result<&Option<Vec<u8>>> {
        self.nodes
            .get(p)
            .ok_or_else(|| Error::new(abi::NOT_FOUND, format!("fake: {p}: not found")))
    }
}

#[derive(Clone)]
pub struct Fake {
    pub st: Arc<Mutex<State>>,
    /// What `kind()` says ("fake"; tests set "vmrun").
    pub kind: &'static str,
}

impl Fake {
    pub fn posix() -> Self {
        let mut s = State {
            sep: '/',
            ..State::default()
        };
        s.dir("/");
        Self::with(s)
    }

    pub fn windows() -> Self {
        let mut s = State {
            sep: '\\',
            ..State::default()
        };
        s.dir("C:\\");
        s.dir("E:\\");
        Self::with(s)
    }

    fn with(s: State) -> Self {
        Self {
            st: Arc::new(Mutex::new(s)),
            kind: "fake",
        }
    }

    fn st(&self, op: &str, path: &str) -> Result<std::sync::MutexGuard<'_, State>> {
        let mut s = self.st.lock().unwrap();
        s.log.push(format!("{op} {path}"));
        match s.user.is_some() {
            true => Ok(s),
            false => Err(Error::new(abi::AUTH, "fake: not logged in")),
        }
    }
}

impl Backend for Fake {
    fn kind(&self) -> &'static str {
        self.kind
    }

    fn login(&mut self, user: &str, pass: &str) -> Result<()> {
        match pass == "pw" {
            true => {
                self.st.lock().unwrap().user = Some(user.into());
                Ok(())
            }
            false => Err(Error::new(abi::AUTH, "fake: wrong password")),
        }
    }

    fn list(&mut self, dir: &str, abort: &dyn Fn() -> bool) -> Result<Vec<Item>> {
        let s = self.st("list", dir)?;
        if s.need(dir)?.is_some() {
            return Err(Error::new(abi::IO, "fake: not a folder"));
        }
        if abort() {
            return Err(Error::new(abi::CANCELLED, "cancelled"));
        }
        Ok(s.children(dir)
            .into_iter()
            .map(|k| {
                let name = k.rsplit(s.sep).next().unwrap_or_default().to_string();
                let size = s.nodes[&k].as_ref().map_or(0, |d| d.len() as u64);
                Item {
                    kind: if s.nodes[&k].is_some() {
                        abi::KIND_FILE
                    } else {
                        abi::KIND_DIR
                    },
                    size,
                    mtime: Some(1_700_000_000_000_000_000),
                    ..Item::dir(name)
                }
            })
            .collect())
    }

    fn stat(&mut self, path: &str) -> Result<Item> {
        let s = self.st("stat", path)?;
        if s.fail_stat {
            return Err(Error::new(abi::IO, "fake: stat broke"));
        }
        let n = s.need(path)?;
        Ok(Item {
            kind: if n.is_some() {
                abi::KIND_FILE
            } else {
                abi::KIND_DIR
            },
            size: n.as_ref().map_or(0, |d| d.len() as u64),
            ..Item::dir("")
        })
    }

    fn get(&mut self, guest: &str, host: &Path) -> Result<()> {
        let s = self.st("get", guest)?;
        let data = s
            .need(guest)?
            .clone()
            .ok_or_else(|| Error::new(abi::IO, "fake: a folder"))?;
        std::fs::write(host, data).map_err(|e| Error::new(abi::IO, e.to_string()))
    }

    fn put(&mut self, host: &Path, guest: &str) -> Result<()> {
        let mut s = self.st("put", guest)?;
        if s.fail_put {
            return Err(Error::new(abi::IO, "fake: disk full"));
        }
        let parent = s.parent(guest).to_string();
        if s.need(&parent)?.is_some() {
            return Err(Error::new(abi::IO, "fake: parent is a file"));
        }
        let data = std::fs::read(host).map_err(|e| Error::new(abi::IO, e.to_string()))?;
        s.put(guest, &data);
        Ok(())
    }

    fn mkdir(&mut self, path: &str) -> Result<()> {
        let mut s = self.st("mkdir", path)?;
        let parent = s.parent(path).to_string();
        s.need(&parent)?;
        s.dir(path);
        Ok(())
    }

    fn remove_file(&mut self, path: &str) -> Result<()> {
        let mut s = self.st("rm", path)?;
        s.need(path)?;
        s.nodes.remove(path);
        Ok(())
    }

    fn remove_dir(&mut self, path: &str) -> Result<()> {
        let mut s = self.st("rmdir", path)?;
        s.need(path)?;
        let sep = s.sep;
        s.nodes
            .retain(|k, _| k != path && !k.starts_with(&format!("{path}{sep}")));
        Ok(())
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        let mut s = self.st("rename", from)?;
        if s.fail_rename {
            return Err(Error::new(abi::DENIED, "fake: rename refused"));
        }
        // POSIX rename(2) replaces a file; Windows refuses any existing target.
        let replaces = s.sep == '/' && matches!(s.nodes.get(to), Some(Some(_)));
        if s.nodes.contains_key(to) && !replaces {
            return Err(Error::new(abi::EXISTS, "fake: exists"));
        }
        let moved: Vec<String> = s
            .nodes
            .keys()
            .filter(|k| *k == from || k.starts_with(&format!("{from}{}", s.sep)))
            .cloned()
            .collect();
        if moved.is_empty() {
            return Err(Error::new(abi::NOT_FOUND, "fake: not found"));
        }
        for k in moved {
            let v = s.nodes.remove(&k).unwrap();
            s.nodes.insert(format!("{to}{}", &k[from.len()..]), v);
        }
        Ok(())
    }

    fn ip(&mut self) -> Result<String> {
        Ok("192.0.2.7".into())
    }
}

impl State {
    /// Every path (tests).
    pub fn paths(&self) -> Vec<String> {
        self.nodes.keys().cloned().collect()
    }
}

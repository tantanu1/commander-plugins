//! In-memory [`Session`] for the plugin-layer tests (no network): shares of `path -> None (dir)
//! | Some(bytes)`, plus knobs that make the next calls fail.
use crate::fs::{Batches, Session, Upload};
use commander_plugin_abi as abi;
use commander_plugin_abi::glue::{Error, Item, Result};
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::{Arc, Mutex};

type Tree = BTreeMap<String, Option<Vec<u8>>>;

#[derive(Default)]
pub struct State {
    pub shares: BTreeMap<String, Tree>,
    /// Renames fail with DENIED.
    pub rename_fail: bool,
    /// Creates fail with DENIED.
    pub create_fail: bool,
    /// Stats fail with IO.
    pub stat_fail: bool,
    /// The next N creates find their name taken (someone else's file appears there).
    pub squat: usize,
}

fn err(st: abi::Status, share: &str, p: &str) -> Error {
    Error::new(st, format!("fake: {share}/{p}"))
}

fn parent(p: &str) -> &str {
    p.rsplit_once('/').map_or("", |(d, _)| d)
}

impl State {
    pub fn add_share(&mut self, name: &str) {
        self.shares.insert(name.into(), Tree::new());
    }

    pub fn put(&mut self, share: &str, p: &str, data: &[u8]) {
        self.shares
            .get_mut(share)
            .unwrap()
            .insert(p.into(), Some(data.to_vec()));
    }

    /// Every entry as `share/path`.
    pub fn paths(&self) -> Vec<String> {
        let all = self
            .shares
            .iter()
            .flat_map(|(s, t)| t.keys().map(move |p| format!("{s}/{p}")));
        all.collect()
    }

    fn tree(&mut self, share: &str) -> Result<&mut Tree> {
        self.shares
            .get_mut(share)
            .ok_or_else(|| err(abi::NOT_FOUND, share, ""))
    }

    /// The parent of `p` is an existing dir.
    fn dir_ok(&mut self, share: &str, p: &str) -> Result<&mut Tree> {
        let t = self.tree(share)?;
        match parent(p) {
            "" => Ok(t),
            d if t.get(d) == Some(&None) => Ok(t),
            _ => Err(err(abi::NOT_FOUND, share, p)),
        }
    }
}

#[derive(Clone, Default)]
pub struct Fake {
    pub st: Arc<Mutex<State>>,
}

impl Fake {
    fn with<T>(&self, f: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        f(&mut self.st.lock().unwrap())
    }
}

impl Session for Fake {
    fn shares(&self) -> Result<Vec<String>> {
        self.with(|s| Ok(s.shares.keys().cloned().collect()))
    }

    /// Batches of 2 (a listing spans several server answers).
    fn list(&self, share: &str, dir: &str) -> Result<Box<dyn Batches>> {
        let me = self.clone();
        let t = self.with(|s| s.tree(share).cloned())?;
        if !dir.is_empty() && t.get(dir) != Some(&None) {
            return Err(err(abi::NOT_FOUND, share, dir));
        }
        let items = t.keys().filter(|p| parent(p) == dir && !p.is_empty());
        let names = items.map(|p| p.rsplit('/').next().unwrap_or(p).to_owned());
        let full = |n: &str| match dir {
            "" => n.to_owned(),
            d => format!("{d}/{n}"),
        };
        let all = names
            .collect::<Vec<_>>()
            .into_iter()
            .map(|n| me.stat(share, &full(&n)).map(|i| Item { name: n, ..i }))
            .collect::<Result<Vec<_>>>()?;
        let batches: Vec<Vec<Item>> = all.chunks(2).map(<[Item]>::to_vec).collect();
        Ok(Box::new(batches.into_iter()))
    }

    fn stat(&self, share: &str, p: &str) -> Result<Item> {
        self.with(|s| {
            if s.stat_fail {
                return Err(err(abi::IO, share, p));
            }
            let t = s.tree(share)?;
            match (p, t.get(p)) {
                ("", _) | (_, Some(None)) => Ok(Item::dir("")),
                (_, Some(Some(d))) => Ok(Item {
                    name: String::new(),
                    kind: abi::KIND_FILE,
                    size: d.len() as u64,
                    mtime: Some(0),
                    link: false,
                }),
                (_, None) => Err(err(abi::NOT_FOUND, share, p)),
            }
        })
    }

    fn reader(&self, share: &str, p: &str, offset: u64) -> Result<Box<dyn Read + Send>> {
        self.with(|s| match s.tree(share)?.get(p) {
            Some(Some(d)) => {
                let d = d.get(offset as usize..).unwrap_or_default().to_vec();
                Ok(Box::new(std::io::Cursor::new(d)) as Box<dyn Read + Send>)
            }
            _ => Err(err(abi::NOT_FOUND, share, p)),
        })
    }

    fn create(&self, share: &str, p: &str) -> Result<Box<dyn Upload>> {
        self.with(|s| {
            if s.create_fail {
                return Err(err(abi::DENIED, share, p));
            }
            let squat = s.squat > 0;
            s.squat = s.squat.saturating_sub(1);
            let t = s.dir_ok(share, p)?;
            if squat || t.contains_key(p) {
                t.entry(p.into()).or_insert(Some(b"squatter".to_vec()));
                return Err(err(abi::EXISTS, share, p));
            }
            t.insert(p.into(), Some(Vec::new()));
            Ok(())
        })?;
        Ok(Box::new(Up {
            fake: self.clone(),
            share: share.into(),
            path: p.into(),
        }))
    }

    fn mkdir(&self, share: &str, p: &str) -> Result<()> {
        self.with(|s| {
            let t = s.dir_ok(share, p)?;
            if t.contains_key(p) {
                return Err(err(abi::EXISTS, share, p));
            }
            t.insert(p.into(), None);
            Ok(())
        })
    }

    fn remove_file(&self, share: &str, p: &str) -> Result<()> {
        self.with(|s| match s.tree(share)?.remove(p) {
            Some(_) => Ok(()),
            None => Err(err(abi::NOT_FOUND, share, p)),
        })
    }

    fn remove_dir(&self, share: &str, p: &str) -> Result<()> {
        self.with(|s| {
            let t = s.tree(share)?;
            if t.keys().any(|k| parent(k) == p) {
                return Err(err(abi::NOT_EMPTY, share, p));
            }
            t.remove(p)
                .map(drop)
                .ok_or_else(|| err(abi::NOT_FOUND, share, p))
        })
    }

    fn rename(&self, share: &str, from: &str, to: &str, replace: bool) -> Result<()> {
        self.with(|s| {
            if s.rename_fail {
                return Err(err(abi::DENIED, share, from));
            }
            let t = s.dir_ok(share, to)?;
            if !replace && t.contains_key(to) {
                return Err(err(abi::EXISTS, share, to));
            }
            let v = t
                .remove(from)
                .ok_or_else(|| err(abi::NOT_FOUND, share, from))?;
            t.insert(to.into(), v);
            Ok(())
        })
    }
}

struct Up {
    fake: Fake,
    share: String,
    path: String,
}

impl Upload for Up {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        self.fake.with(|s| {
            match s.tree(&self.share)?.get_mut(&self.path) {
                Some(Some(d)) => d.extend_from_slice(data),
                _ => return Err(err(abi::IO, &self.share, &self.path)),
            }
            Ok(())
        })
    }

    fn finish(self: Box<Self>) -> Result<()> {
        Ok(())
    }
}

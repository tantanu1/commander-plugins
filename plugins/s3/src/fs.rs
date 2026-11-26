//! Filesystem semantics over S3: dirs = `/`-delimited prefixes (+ optional `dir/` markers).
//! Paths after `s3://`: `` = AWS profiles, `<profile>` = its buckets, `<profile>/<bucket>/key`;
//! `<bucket>/key` (first segment not a profile) = the first profile that can list the bucket.
use crate::client::{Client, Error, Req, Result};
use crate::config::Aws;
use crate::download::{self, Tuning};
use crate::xml::{self, Obj, Page};
use commander_plugin_abi::{self as abi, glue::Cancel};
use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};

/// Listing / stat item. `name` empty for stat.
#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    pub name: String,
    pub dir: bool,
    pub size: u64,
    /// unix ns.
    pub mtime: Option<i64>,
}

impl Item {
    fn dir(name: impl Into<String>, mtime: Option<i64>) -> Self {
        Self {
            name: name.into(),
            dir: true,
            size: 0,
            mtime,
        }
    }
}

const MIB: u64 = 1 << 20;
const MAX_PARTS: usize = 10_000;

/// Multipart part size for a total of `hint` bytes (`u64::MAX` = unknown): >= 8 MiB, whole
/// MiB, and big enough that the object fits in 10,000 parts.
pub fn part_size(hint: u64) -> usize {
    let need = match hint {
        u64::MAX => 16 * MIB,
        h => h.div_ceil(MAX_PARTS as u64).next_multiple_of(MIB),
    };
    need.max(8 * MIB) as usize
}

/// Host-safe plain name (the host rejects `/`, `\`, `:`, NUL, `.`, `..`): others are skipped.
pub(crate) fn valid_name(n: &str) -> bool {
    !n.is_empty() && n != "." && n != ".." && !n.contains(['/', '\\', ':', '\0'])
}

/// Page -> items relative to `prefix` (marker `prefix` itself and unsafe names dropped).
pub fn items_of(prefix: &str, page: Page) -> Vec<Item> {
    let dirs = page.dirs.into_iter().filter_map(|d| {
        let n = d.strip_prefix(prefix)?.strip_suffix('/')?;
        valid_name(n).then(|| Item::dir(n, None))
    });
    let files = page.files.into_iter().filter_map(|o| {
        let n = o.key.strip_prefix(prefix)?;
        valid_name(n).then(|| Item {
            name: n.to_owned(),
            dir: false,
            size: o.size,
            mtime: o.mtime,
        })
    });
    dirs.chain(files).collect()
}

/// Parent prefix of `key` (`a/b/c` -> `a/b`), `None` at the bucket root.
fn parent(key: &str) -> Option<&str> {
    key.rsplit_once('/').map(|(p, _)| p)
}

/// What a path after `s3://` addresses. A profile name wins over a bucket name.
#[derive(Debug, PartialEq, Eq)]
pub enum Target<'a> {
    Profiles,
    /// Buckets of a profile.
    Buckets(&'a str),
    /// `profile` None: the first profile that can list `bucket`. `key` "" = the bucket itself.
    Obj {
        profile: Option<&'a str>,
        bucket: &'a str,
        key: &'a str,
    },
}

/// Parse `full` (segments after `s3://`) against the known `profiles`.
pub fn target<'a>(full: &'a str, profiles: &[String]) -> Target<'a> {
    let full = full.trim_matches('/');
    if full.is_empty() {
        return Target::Profiles;
    }
    let (first, rest) = full.split_once('/').unwrap_or((full, ""));
    if !profiles.iter().any(|p| p == first) {
        return Target::Obj {
            profile: None,
            bucket: first,
            key: rest,
        };
    }
    match rest.split_once('/') {
        _ if rest.is_empty() => Target::Buckets(first),
        Some((bucket, key)) => Target::Obj {
            profile: Some(first),
            bucket,
            key,
        },
        None => Target::Obj {
            profile: Some(first),
            bucket: rest,
            key: "",
        },
    }
}

/// Try profiles in `order` until `probe` succeeds. NOT_FOUND stops at once (bucket names are
/// global: no other profile will find it). All fail: the first AUTH_EXPIRED error (a login
/// may fix it), else the first error.
pub fn first_ok<T>(
    order: &[String],
    mut probe: impl FnMut(&str) -> Result<T>,
) -> Result<(String, T)> {
    let mut errs = Vec::new();
    for p in order {
        match probe(p) {
            Ok(t) => return Ok((p.clone(), t)),
            Err(e) if e.status == abi::NOT_FOUND => return Err(e),
            Err(e) => errs.push(e),
        }
    }
    let i = errs
        .iter()
        .position(|e| e.status == abi::AUTH_EXPIRED)
        .unwrap_or(0);
    Err(errs.into_iter().nth(i).unwrap_or_else(|| {
        Error::new(
            abi::AUTH,
            "s3: no AWS profiles: run `aws configure` or set AWS_ACCESS_KEY_ID",
        )
    }))
}

/// bucket -> profile found by the fallback, for this process.
static BUCKETS: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(Mutex::default);

/// After an op on `bucket`: a rejection (AUTH / DENIED) forgets its cached profile, so the next
/// try runs the fallback again.
fn checked<T>(bucket: &str, r: Result<T>) -> Result<T> {
    if let Err(e) = &r
        && matches!(e.status, abi::AUTH | abi::DENIED)
    {
        lock(&BUCKETS).remove(bucket);
    }
    r
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn invalid(msg: String) -> Error {
    Error::new(abi::INVALID, msg)
}

fn unsupported(path: &str) -> Error {
    Error::new(
        abi::UNSUPPORTED,
        format!("s3: {path:?}: not supported on a bucket / the bucket or profile list"),
    )
}

/// One mount: `s3://` or `s3://<profile or bucket>`.
pub struct S3 {
    /// The mount's first segment ("" for `s3://`).
    authority: String,
    aws: Aws,
    profiles: Vec<String>,
    /// profile -> its client or why it has none (credentials read once per mount; the host
    /// drops the mount on an auth error, so a login resets this).
    stores: Mutex<HashMap<String, Result<Arc<Store>>>>,
    cli: Cli,
    /// Can this store list the bucket (fallback)? ListObjectsV2 max-keys 1; a fake in tests.
    probe: fn(&Store, &str) -> Result<()>,
    tuning: Tuning,
}

/// Runs the AWS CLI credential export ([`crate::config::aws_cli`]; a fake in tests).
type Cli = fn(&str) -> std::result::Result<String, String>;

/// Where a path resolved to.
enum At {
    Profiles,
    Buckets(Arc<Store>),
    Obj(Arc<Store>, String, String),
}

impl S3 {
    /// `config` = `s3://` or `s3://<profile or bucket>`.
    pub fn open(config: &str) -> Result<Self> {
        let rest = config
            .strip_prefix("s3://")
            .ok_or_else(|| invalid(format!("{config}: not an s3:// mount")))?;
        if rest.contains('/') {
            return Err(invalid(format!("{config}: bad bucket")));
        }
        Ok(Self {
            tuning: Tuning::load(),
            ..Self::with(rest, Aws::load(), crate::config::aws_cli)
        })
    }

    fn with(authority: &str, aws: Aws, cli: Cli) -> Self {
        Self {
            authority: authority.to_owned(),
            profiles: aws.profiles(),
            aws,
            stores: Mutex::default(),
            cli,
            probe: |st, b| st.page(b, "", false, None, Some(1)).map(drop),
            tuning: Tuning::default(),
        }
    }

    /// Client of profile `p` (made on first use: may run the AWS CLI).
    fn store(&self, p: &str) -> Result<Arc<Store>> {
        if let Some(s) = lock(&self.stores).get(p) {
            return s.clone();
        }
        let st = self.aws.config(p, &self.cli).map(|cfg| {
            Arc::new(Store {
                c: Client::new(cfg),
                tuning: self.tuning,
            })
        });
        lock(&self.stores).entry(p.to_owned()).or_insert(st).clone()
    }

    /// Store of the first profile that can list `bucket` (remembered per process).
    fn store_for_bucket(&self, bucket: &str) -> Result<Arc<Store>> {
        let known = lock(&BUCKETS).get(bucket).cloned();
        if let Some(p) = known {
            return self.store(&p); // its error (e.g. expired) is the one to show
        }
        let (p, st) = first_ok(&self.profiles, |p| {
            let st = self.store(p)?;
            (self.probe)(&st, bucket)?;
            Ok(st)
        })?;
        lock(&BUCKETS).insert(bucket.to_owned(), p);
        Ok(st)
    }

    /// Segments after `s3://` of mount-relative `path`.
    fn full(&self, path: &str) -> String {
        match (self.authority.as_str(), path) {
            (a, "") => a.to_owned(),
            ("", p) => p.to_owned(),
            (a, p) => format!("{a}/{p}"),
        }
    }

    /// Real S3 URL of a path under a profile (`<profile>/<bucket>/key` -> `s3://bucket/key`):
    /// the profile is a Commander level, not part of S3. No I/O. None: not under a profile
    /// (the profile / bucket lists, or an old-style `s3://bucket/...` path, already public).
    pub fn public_url(&self, path: &str) -> Option<String> {
        match target(&self.full(path), &self.profiles) {
            Target::Obj {
                profile: Some(_),
                bucket,
                key,
            } => Some(match key {
                "" => format!("s3://{bucket}"),
                k => format!("s3://{bucket}/{k}"),
            }),
            _ => None,
        }
    }

    fn at(&self, path: &str) -> Result<At> {
        let full = self.full(path);
        Ok(match target(&full, &self.profiles) {
            Target::Profiles => At::Profiles,
            Target::Buckets(p) => At::Buckets(self.store(p)?),
            Target::Obj {
                profile,
                bucket,
                key,
            } => {
                let st = match profile {
                    Some(p) => self.store(p)?,
                    None => self.store_for_bucket(bucket)?,
                };
                At::Obj(st, bucket.to_owned(), key.to_owned())
            }
        })
    }

    /// (store, bucket, key) of an object path; the lists / a bucket itself are not one.
    fn key(&self, path: &str) -> Result<(Arc<Store>, String, String)> {
        match self.at(path)? {
            At::Obj(st, b, k) if !k.is_empty() => Ok((st, b, k)),
            _ => Err(unsupported(path)),
        }
    }

    pub fn stat(&self, path: &str) -> Result<Item> {
        match self.at(path)? {
            At::Profiles | At::Buckets(_) => Ok(Item::dir("", None)),
            At::Obj(st, b, k) => checked(&b, st.stat(&b, &k)),
        }
    }

    pub fn list(self: &Arc<Self>, path: &str) -> Result<Lister> {
        match self.at(path)? {
            At::Profiles => Ok(Lister::items(
                self.profiles.iter().map(|p| Item::dir(p, None)).collect(),
            )),
            At::Buckets(st) => st.buckets(),
            At::Obj(st, b, k) => checked(&b, st.list(&b, &k)),
        }
    }

    /// `c` = the host's cancel flag (enables parallel chunks), None = one plain GET.
    pub fn reader(
        &self,
        path: &str,
        offset: u64,
        c: Option<Cancel>,
    ) -> Result<Box<dyn Read + Send>> {
        let (st, b, k) = self.key(path)?;
        checked(&b, st.reader(&b, &k, offset, c))
    }

    pub fn writer(&self, path: &str, overwrite: bool, hint: u64) -> Result<Writer> {
        let (st, b, k) = self.key(path)?;
        checked(&b, st.writer(&b, &k, overwrite, hint))
    }

    pub fn mkdir(&self, path: &str) -> Result<()> {
        let (st, b, k) = self.key(path)?;
        checked(&b, st.mkdir(&b, &k))
    }

    pub fn remove_file(&self, path: &str) -> Result<()> {
        let (st, b, k) = self.key(path)?;
        checked(&b, st.remove_file(&b, &k))
    }

    pub fn remove_dir(&self, path: &str) -> Result<()> {
        let (st, b, k) = self.key(path)?;
        checked(&b, st.remove_dir(&b, &k))
    }

    /// Within one profile only.
    pub fn rename(&self, from: &str, to: &str, cancelled: &dyn Fn() -> bool) -> Result<()> {
        let (fs, fb, fk) = self.key(from)?;
        let (ts, tb, tk) = self.key(to)?;
        if !Arc::ptr_eq(&fs, &ts) {
            return Err(Error::new(
                abi::UNSUPPORTED,
                "s3: moving between AWS profiles is not supported (copy instead)",
            ));
        }
        checked(&fb, fs.rename(&fb, &fk, &tb, &tk, cancelled))
    }
}

/// One profile's client: bucket/key operations.
pub struct Store {
    pub(crate) c: Client,
    pub(crate) tuning: Tuning,
}

impl Store {
    fn page(
        &self,
        b: &str,
        prefix: &str,
        delim: bool,
        token: Option<&str>,
        max: Option<u32>,
    ) -> Result<Page> {
        let mut r = Req::new("GET", Some(b), "")
            .q("list-type", "2")
            .q("prefix", prefix);
        if delim {
            r = r.q("delimiter", "/");
        }
        if let Some(t) = token {
            r = r.q("continuation-token", t);
        }
        if let Some(m) = max {
            r = r.q("max-keys", m.to_string());
        }
        xml::list_objects(&self.c.send_text(&r)?).map_err(|m| Error::new(abi::IO, m))
    }

    /// Any key under `prefix` (which ends in `/`)?
    fn has_prefix(&self, b: &str, prefix: &str) -> Result<bool> {
        let p = self.page(b, prefix, false, None, Some(1))?;
        Ok(!p.files.is_empty() || !p.dirs.is_empty())
    }

    fn head(&self, b: &str, k: &str) -> Result<Option<Item>> {
        let resp = match self.c.send(&Req::new("HEAD", Some(b), k)) {
            Err(e) if e.status == abi::NOT_FOUND => return Ok(None),
            r => r?,
        };
        let hdr = |n: &str| resp.headers().get(n).and_then(|v| v.to_str().ok());
        Ok(Some(Item {
            name: String::new(),
            dir: false,
            size: hdr("content-length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            mtime: hdr("last-modified").and_then(crate::sign::parse_http_date),
        }))
    }

    /// File (HEAD), else dir (prefix has keys), else absent.
    fn kind(&self, b: &str, k: &str) -> Result<Option<Item>> {
        if let Some(f) = self.head(b, k)? {
            return Ok(Some(f));
        }
        Ok(self
            .has_prefix(b, &format!("{k}/"))?
            .then(|| Item::dir("", None)))
    }

    fn parent_exists(&self, b: &str, k: &str) -> Result<bool> {
        match parent(k) {
            None => Ok(true),
            Some(p) => self.has_prefix(b, &format!("{p}/")),
        }
    }

    /// NOT_FOUND, or INVALID when `k` is the other kind (`dir` = what was expected).
    fn missing(&self, b: &str, k: &str, dir: bool) -> Error {
        let other = match dir {
            true => self.head(b, k).map(|h| h.is_some()),
            false => self.has_prefix(b, &format!("{k}/")),
        };
        match other {
            Ok(true) if dir => invalid(format!("s3: {b}/{k}: not a directory")),
            Ok(true) => invalid(format!("s3: {b}/{k}: is a directory")),
            Ok(false) => Error::new(abi::NOT_FOUND, format!("s3: {b}/{k}: not found")),
            Err(e) => e,
        }
    }

    fn put(&self, b: &str, k: &str, body: &[u8]) -> Result<()> {
        self.c
            .send(&Req::new("PUT", Some(b), k).body(body))
            .map(drop)
    }

    fn delete(&self, b: &str, k: &str) -> Result<()> {
        self.c.send(&Req::new("DELETE", Some(b), k)).map(drop)
    }

    /// After removing `k`, keep its parent dir visible with a marker (S3 drops empty prefixes).
    fn keep_parent(&self, b: &str, k: &str) {
        if let Some(p) = parent(k) {
            let pre = format!("{p}/");
            if let Ok(false) = self.has_prefix(b, &pre) {
                let _ = self.put(b, &pre, &[]);
            }
        }
    }

    fn stat(&self, b: &str, k: &str) -> Result<Item> {
        if k.is_empty() {
            let r = self.c.send(&Req::new("HEAD", Some(b), ""));
            return r.map(|_| Item::dir("", None));
        }
        self.kind(b, k)?
            .ok_or_else(|| Error::new(abi::NOT_FOUND, format!("s3: {b}/{k}: not found")))
    }

    /// ListBuckets.
    fn buckets(&self) -> Result<Lister> {
        let text = self.c.send_text(&Req::new("GET", None, ""))?;
        let items = xml::buckets(&text)
            .map_err(|m| Error::new(abi::IO, m))?
            .into_iter()
            .filter(|o| valid_name(&o.key))
            .map(|o| Item::dir(o.key, o.mtime))
            .collect();
        Ok(Lister::items(items))
    }

    /// First page fetched now (so a missing dir fails here), the rest lazily.
    fn list(self: &Arc<Self>, b: &str, k: &str) -> Result<Lister> {
        let prefix = match k.is_empty() {
            true => String::new(),
            false => format!("{k}/"),
        };
        let page = self.page(b, &prefix, true, None, None)?;
        if !k.is_empty() && page.dirs.is_empty() && page.files.is_empty() {
            return Err(self.missing(b, k, true));
        }
        let token = page.next.clone();
        Ok(Lister {
            s3: Some(Arc::clone(self)),
            bucket: b.to_owned(),
            queue: items_of(&prefix, page).into(),
            prefix,
            token,
        })
    }

    /// GetObject from `offset`. With `c` and `download_parallel` > 1 the first request asks
    /// for one chunk (learning the size + ETag) and the other chunks follow in parallel
    /// (`download`); else (or when the server gives no size / ETag) one plain GET.
    pub(crate) fn reader(
        self: &Arc<Self>,
        b: &str,
        k: &str,
        offset: u64,
        c: Option<Cancel>,
    ) -> Result<Box<dyn Read + Send>> {
        let c = c.filter(|_| self.tuning.parallel > 1);
        let mut r = Req::new("GET", Some(b), k);
        if c.is_some() {
            let end = offset.saturating_add(self.tuning.chunk - 1);
            r = r.h("range", format!("bytes={offset}-{end}"));
        } else if offset > 0 {
            r = r.h("range", format!("bytes={offset}-"));
        }
        match (self.c.send(&r), c) {
            (Ok(resp), Some(c)) => match download::stream(self, (b, k), offset, resp, c)? {
                Some(s) => Ok(s),
                None => self.reader(b, k, offset, None),
            },
            (Ok(resp), None) if offset > 0 && resp.status().as_u16() != 206 => Err(Error::new(
                abi::IO,
                format!(
                    "s3: {b}/{k}: server ignored the Range request (HTTP {})",
                    resp.status()
                ),
            )),
            (Ok(resp), None) => Ok(Box::new(resp.into_body().into_reader())),
            (Err(e), _) if e.http == 416 => Ok(Box::new(std::io::empty())),
            (Err(e), _) if e.status == abi::NOT_FOUND => Err(self.missing(b, k, false)),
            (Err(e), _) => Err(e),
        }
    }

    fn writer(self: &Arc<Self>, b: &str, k: &str, overwrite: bool, hint: u64) -> Result<Writer> {
        if !self.parent_exists(b, k)? {
            return Err(Error::new(
                abi::NOT_FOUND,
                format!("s3: {b}/{k}: parent dir missing"),
            ));
        }
        let exists = match self.head(b, k)? {
            Some(_) => !overwrite,
            None => self.has_prefix(b, &format!("{k}/"))?,
        };
        if exists {
            return Err(Error::new(
                abi::EXISTS,
                format!("s3: {b}/{k}: already exists"),
            ));
        }
        let part = part_size(hint);
        Ok(Writer {
            s3: Arc::clone(self),
            bucket: b.to_owned(),
            key: k.to_owned(),
            part,
            buf: Vec::new(),
            total: 0,
            upload: None,
        })
    }

    fn mkdir(&self, b: &str, k: &str) -> Result<()> {
        if self.kind(b, k)?.is_some() {
            return Err(Error::new(
                abi::EXISTS,
                format!("s3: {b}/{k}: already exists"),
            ));
        }
        if !self.parent_exists(b, k)? {
            return Err(Error::new(
                abi::NOT_FOUND,
                format!("s3: {b}/{k}: parent dir missing"),
            ));
        }
        self.put(b, &format!("{k}/"), &[])
    }

    fn remove_file(&self, b: &str, k: &str) -> Result<()> {
        if self.head(b, k)?.is_none() {
            return Err(self.missing(b, k, false));
        }
        self.delete(b, k)?;
        self.keep_parent(b, k);
        Ok(())
    }

    /// Empty dirs only: deletes the `dir/` marker.
    fn remove_dir(&self, b: &str, k: &str) -> Result<()> {
        let marker = format!("{k}/");
        let p = self.page(b, &marker, false, None, Some(2))?;
        if p.files.is_empty() {
            return Err(self.missing(b, k, true));
        }
        if p.files.iter().any(|o| o.key != marker) {
            return Err(Error::new(
                abi::NOT_EMPTY,
                format!("s3: {b}/{k}: not empty"),
            ));
        }
        self.delete(b, &marker)?;
        self.keep_parent(b, k);
        Ok(())
    }

    /// Server-side copy (CopyObject: single objects up to 5 GiB).
    fn copy(&self, fb: &str, fk: &str, tb: &str, tk: &str) -> Result<()> {
        let src = format!("/{fb}/{}", crate::sign::uri_encode(fk, false));
        self.c
            .send_text(&Req::new("PUT", Some(tb), tk).h("x-amz-copy-source", src))
            .map(drop)
    }

    /// Every object under `prefix` (no delimiter).
    fn all_keys(&self, b: &str, prefix: &str, cancelled: &dyn Fn() -> bool) -> Result<Vec<Obj>> {
        let mut keys = Vec::new();
        let mut token = None;
        loop {
            if cancelled() {
                return Err(Error::new(abi::CANCELLED, "cancelled"));
            }
            let p = self.page(b, prefix, false, token.as_deref(), None)?;
            keys.extend(p.files);
            token = p.next;
            if token.is_none() {
                return Ok(keys);
            }
        }
    }

    /// Never replaces. Files: copy + delete. Dirs: copy every key, then delete the sources;
    /// a failure/cancel during the copy phase deletes the copies made (source untouched).
    fn rename(
        &self,
        fb: &str,
        fk: &str,
        tb: &str,
        tk: &str,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<()> {
        if self.kind(tb, tk)?.is_some() {
            return Err(Error::new(
                abi::EXISTS,
                format!("s3: {tb}/{tk}: already exists"),
            ));
        }
        if !self.parent_exists(tb, tk)? {
            return Err(Error::new(
                abi::NOT_FOUND,
                format!("s3: {tb}/{tk}: parent dir missing"),
            ));
        }
        let Some(src) = self.kind(fb, fk)? else {
            return Err(Error::new(
                abi::NOT_FOUND,
                format!("s3: {fb}/{fk}: not found"),
            ));
        };
        if !src.dir {
            self.copy(fb, fk, tb, tk)?;
            self.delete(fb, fk)?;
            self.keep_parent(fb, fk);
            return Ok(());
        }
        let pre = format!("{fk}/");
        if fb == tb && tk.starts_with(&pre) {
            return Err(invalid("s3: cannot move a folder into itself".into()));
        }
        let keys = self.all_keys(fb, &pre, cancelled)?;
        let mut made: Vec<String> = Vec::with_capacity(keys.len());
        for o in &keys {
            let k = &o.key;
            let dst = format!("{tk}/{}", &k[pre.len()..]);
            let r = match cancelled() {
                true => Err(Error::new(abi::CANCELLED, "cancelled")),
                // Markers are empty: write them, as some servers (SeaweedFS) can't copy a "dir/" key.
                false if k.ends_with('/') && o.size == 0 => self.put(tb, &dst, &[]),
                false => self.copy(fb, k, tb, &dst),
            };
            if let Err(e) = r {
                for m in &made {
                    let _ = self.delete(tb, m);
                }
                return Err(e);
            }
            made.push(dst);
        }
        for o in &keys {
            self.delete(fb, &o.key)?;
        }
        self.keep_parent(fb, fk);
        Ok(())
    }
}

/// Streaming listing: one S3 page (<= 1000 keys) buffered at a time.
pub struct Lister {
    /// None: a fixed list (profiles, buckets).
    s3: Option<Arc<Store>>,
    bucket: String,
    prefix: String,
    token: Option<String>,
    queue: VecDeque<Item>,
}

impl Lister {
    fn items(items: Vec<Item>) -> Self {
        Self {
            s3: None,
            bucket: String::new(),
            prefix: String::new(),
            token: None,
            queue: items.into(),
        }
    }

    /// Up to `cap` items; empty = done. Fetches the next page when the buffer runs dry.
    pub fn next_batch(&mut self, cap: usize, cancelled: &dyn Fn() -> bool) -> Result<Vec<Item>> {
        while self.queue.is_empty() {
            if cancelled() {
                return Err(Error::new(abi::CANCELLED, "cancelled"));
            }
            let (Some(t), Some(s3)) = (self.token.take(), &self.s3) else {
                break;
            };
            let page = s3.page(&self.bucket, &self.prefix, true, Some(&t), None)?;
            self.token = page.next.clone();
            self.queue.extend(items_of(&self.prefix, page));
        }
        let n = cap.min(self.queue.len());
        Ok(self.queue.drain(..n).collect())
    }
}

/// Upload stream: buffers one part; small objects = one PUT, large = multipart.
/// Dropping an unfinished writer aborts the multipart upload.
pub struct Writer {
    s3: Arc<Store>,
    bucket: String,
    key: String,
    part: usize,
    buf: Vec<u8>,
    /// Bytes accepted so far.
    total: u64,
    /// (upload id, part ETags).
    upload: Option<(String, Vec<String>)>,
}

impl Writer {
    pub fn write(&mut self, mut data: &[u8]) -> Result<()> {
        self.total += data.len() as u64;
        while !data.is_empty() {
            let take = (self.part - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buf.len() == self.part {
                self.flush_part()?;
            }
        }
        Ok(())
    }

    fn flush_part(&mut self) -> Result<()> {
        let (b, k) = (Some(self.bucket.as_str()), self.key.as_str());
        if self.upload.is_none() {
            let text = self
                .s3
                .c
                .send_text(&Req::new("POST", b, k).q("uploads", "").no_retry())?;
            let id = xml::upload_id(&text).map_err(|m| Error::new(abi::IO, m))?;
            self.upload = Some((id, Vec::new()));
        }
        let Some((id, etags)) = self.upload.as_mut() else {
            return Err(Error::new(abi::INTERNAL, "no upload"));
        };
        if etags.len() == MAX_PARTS {
            return Err(Error::new(
                abi::IO,
                "s3: object needs more than 10000 parts",
            ));
        }
        let resp = self.s3.c.send(
            &Req::new("PUT", b, k)
                .q("partNumber", (etags.len() + 1).to_string())
                .q("uploadId", id.as_str())
                .body(&self.buf),
        )?;
        let etag = resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| Error::new(abi::IO, "s3: UploadPart without ETag"))?;
        etags.push(etag.to_owned());
        self.buf.clear();
        Ok(())
    }

    pub fn finish(mut self) -> Result<()> {
        if self.upload.is_none() {
            return self.s3.put(&self.bucket, &self.key, &self.buf);
        }
        if !self.buf.is_empty() {
            self.flush_part()?;
        }
        if let Some((id, etags)) = &self.upload {
            let body = xml::complete_body(etags);
            let r = self.s3.c.send_text(
                &Req::new("POST", Some(&self.bucket), &self.key)
                    .q("uploadId", id.as_str())
                    .body(body.as_bytes()),
            );
            match r {
                // A retried Complete whose first response was lost: the upload is already
                // gone (NoSuchUpload). Accept if the object is there with our size.
                Err(e) if e.status == abi::NOT_FOUND => {
                    match self.s3.head(&self.bucket, &self.key)? {
                        Some(o) if o.size == self.total => {}
                        _ => return Err(e),
                    }
                }
                r => {
                    r?;
                }
            }
        }
        self.upload = None; // completed: nothing to abort
        Ok(())
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        if let Some((id, _)) = self.upload.take() {
            let r = Req::new("DELETE", Some(&self.bucket), &self.key).q("uploadId", id);
            let _ = self.s3.c.send(&r);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::Obj;

    #[test]
    fn part_sizing() {
        assert_eq!(part_size(0), 8 << 20);
        assert_eq!(part_size(100 << 20), 8 << 20);
        assert_eq!(part_size(u64::MAX), 16 << 20);
        // 1 TiB / 10000 = 104.9 MiB -> 105 MiB.
        let p = part_size(1 << 40);
        assert_eq!(p, 105 << 20);
        assert!((p as u64) * 10_000 >= 1 << 40);
        // 5 TiB max object still fits.
        assert!(part_size(5 << 40) as u64 * 10_000 >= 5 << 40);
    }

    #[test]
    fn prefix_items() {
        let o = |k: &str, size| Obj {
            key: k.into(),
            size,
            mtime: None,
        };
        let page = Page {
            dirs: vec!["d/sub/".into(), "d/a:b/".into(), "d//".into()],
            files: vec![o("d/", 0), o("d/f.txt", 5), o("d/c:x", 1), o("d/..", 1)],
            next: None,
        };
        let items = items_of("d/", page);
        assert_eq!(
            items,
            [
                Item::dir("sub", None),
                Item {
                    name: "f.txt".into(),
                    dir: false,
                    size: 5,
                    mtime: None
                }
            ]
        );
        let root = Page {
            dirs: vec!["top/".into()],
            files: vec![o("x", 1)],
            next: None,
        };
        assert_eq!(items_of("", root).len(), 2);
        assert_eq!(parent("a/b/c"), Some("a/b"));
        assert_eq!(parent("a"), None);
    }

    const CREDS: &str = "[default]\naws_access_key_id = A\naws_secret_access_key = S\n\
                         [dev]\naws_access_key_id = B\naws_secret_access_key = T\n";
    const CONF: &str = "[profile bare]\nregion = eu-west-1\n[profile none]\nregion = x\n";

    fn no_cli(_: &str) -> std::result::Result<String, String> {
        Err("no cli in tests".into())
    }

    fn s3(authority: &str, creds: &str, conf: &str) -> S3 {
        S3::with(authority, Aws::fixture(creds, conf), no_cli)
    }

    /// Live round trip against an S3-compatible server (MinIO etc.). Needs
    /// COMMANDER_S3_TEST_BUCKET (existing; found via the profile fallback), credentials (env
    /// keys or a profile) and for MinIO etc. AWS_ENDPOINT_URL + COMMANDER_S3_PATH_STYLE=1.
    /// `cargo test -p commander_s3 -- --ignored`
    #[test]
    #[ignore = "needs a live S3-compatible endpoint"]
    fn live_round_trip() {
        let Ok(bucket) = std::env::var("COMMANDER_S3_TEST_BUCKET") else {
            eprintln!("COMMANDER_S3_TEST_BUCKET unset: skipped");
            return;
        };
        let fs = Arc::new(S3::open(&format!("s3://{bucket}")).unwrap());
        let root = format!("cmdr-test-{}", std::process::id());
        let p = |s: &str| format!("{root}/{s}");
        let never = || false;
        fs.mkdir(&root).unwrap();
        assert_eq!(fs.mkdir(&root).unwrap_err().status, abi::EXISTS);
        assert_eq!(fs.mkdir(&p("x/y")).unwrap_err().status, abi::NOT_FOUND);
        fs.mkdir(&p("d")).unwrap();
        // Small (single PUT) and multipart (> 8 MiB part) uploads.
        let small = b"hello world".to_vec();
        let big: Vec<u8> = (0..11 << 20).map(|i: u32| (i % 251) as u8).collect();
        fs.mkdir(&p("d/sub")).unwrap();
        for (name, data) in [
            ("d/żółw 🐢.txt", &small),
            ("d/big.bin", &big),
            ("d/sub/a+b c.txt", &small),
        ] {
            let mut w = fs.writer(&p(name), false, data.len() as u64).unwrap();
            for chunk in data.chunks(1 << 20) {
                w.write(chunk).unwrap();
            }
            w.finish().unwrap();
        }
        assert_eq!(
            fs.writer(&p("d/big.bin"), false, 1).err().unwrap().status,
            abi::EXISTS
        );
        let mut l = fs.list(&p("d")).unwrap();
        let mut names: Vec<_> = l.next_batch(100, &never).unwrap();
        names.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(names.len(), 3);
        assert_eq!(
            (names[0].name.as_str(), names[0].size),
            ("big.bin", 11 << 20)
        );
        assert!(names[1].dir && names[1].name == "sub");
        assert!(fs.stat(&p("d")).unwrap().dir);
        assert_eq!(fs.stat(&p("d/big.bin")).unwrap().size, 11 << 20);
        // Whole > 10 MiB body streams (no ureq body cap).
        let mut all = Vec::new();
        fs.reader(&p("d/big.bin"), 0, Some(Box::new(|| false)))
            .unwrap()
            .read_to_end(&mut all)
            .unwrap();
        assert!(all == big, "full read differs");
        let mut tail = Vec::new();
        fs.reader(&p("d/big.bin"), (11 << 20) - 5, None)
            .unwrap()
            .read_to_end(&mut tail)
            .unwrap();
        assert_eq!(tail, big[big.len() - 5..]);
        let mut s = String::new();
        fs.reader(&p("d/żółw 🐢.txt"), 6, None)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "world");
        // Aborted multipart leaves nothing.
        let mut w = fs.writer(&p("d/aborted"), false, u64::MAX).unwrap();
        w.write(&big).unwrap();
        drop(w);
        assert_eq!(fs.stat(&p("d/aborted")).unwrap_err().status, abi::NOT_FOUND);
        // Rename dir, non-empty refusal, deletes.
        fs.rename(&p("d"), &p("e"), &never).unwrap();
        assert_eq!(fs.stat(&p("d")).unwrap_err().status, abi::NOT_FOUND);
        let mut s = String::new();
        fs.reader(&p("e/sub/a+b c.txt"), 0, None)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "hello world", "nested subdir + '+' key moved");
        fs.remove_file(&p("e/sub/a+b c.txt")).unwrap();
        fs.remove_dir(&p("e/sub")).unwrap();
        assert_eq!(fs.remove_dir(&p("e")).unwrap_err().status, abi::NOT_EMPTY);
        fs.remove_file(&p("e/big.bin")).unwrap();
        fs.remove_file(&p("e/żółw 🐢.txt")).unwrap();
        fs.remove_dir(&p("e")).unwrap();
        assert!(fs.stat(&root).unwrap().dir, "parent kept by marker");
        fs.remove_dir(&root).unwrap();
        assert_eq!(fs.stat(&root).unwrap_err().status, abi::NOT_FOUND);
    }

    #[test]
    fn url_targets_profile_wins() {
        let profiles = ["default".to_owned(), "dev".to_owned()];
        let t = |s| target(s, &profiles);
        assert_eq!(t(""), Target::Profiles);
        assert_eq!(t("/"), Target::Profiles);
        assert_eq!(t("dev"), Target::Buckets("dev"));
        assert_eq!(t("dev/"), Target::Buckets("dev"));
        let obj = |profile, bucket, key| Target::Obj {
            profile,
            bucket,
            key,
        };
        assert_eq!(t("dev/b"), obj(Some("dev"), "b", ""));
        assert_eq!(t("dev/b/x/y"), obj(Some("dev"), "b", "x/y"));
        assert_eq!(t("bkt"), obj(None, "bkt", ""), "not a profile: a bucket");
        assert_eq!(t("bkt/x/y"), obj(None, "bkt", "x/y"));
        assert_eq!(t("devx/k"), obj(None, "devx", "k"), "whole-segment match");
    }

    #[test]
    fn fallback_order_and_error_choice() {
        let order: Vec<String> = ["default", "a", "b"].map(String::from).into();
        let mut tried = Vec::new();
        let r = first_ok(&order, |p| {
            tried.push(p.to_owned());
            match p {
                "a" => Ok(7),
                _ => Err(Error::new(abi::DENIED, "no")),
            }
        });
        assert_eq!(r.unwrap(), ("a".to_owned(), 7));
        assert_eq!(tried, ["default", "a"], "stops at the first success");
        let all = |st: &dyn Fn(&str) -> i32| {
            first_ok::<()>(&order, |p| Err(Error::new(st(p), p.to_owned()))).unwrap_err()
        };
        let e = all(&|_| abi::DENIED);
        assert_eq!(
            (e.status, e.msg.as_str()),
            (abi::DENIED, "default"),
            "first error"
        );
        let e = all(&|p| match p {
            "b" => abi::AUTH_EXPIRED,
            _ => abi::DENIED,
        });
        assert_eq!(
            (e.status, e.msg.as_str()),
            (abi::AUTH_EXPIRED, "b"),
            "a login may fix it"
        );
        let e = first_ok::<()>(&[], |_| Ok(())).unwrap_err();
        assert!(
            e.status == abi::AUTH && e.msg.contains("no AWS profiles"),
            "{}",
            e.msg
        );
    }

    #[test]
    fn public_url_drops_the_profile_level() {
        let top = s3("", CREDS, CONF);
        let dev = s3("dev", CREDS, CONF);
        let old = s3("bkt", CREDS, CONF);
        let cases = [
            (&top, "dev/b/k/x.txt", Some("s3://b/k/x.txt")),
            (&top, "dev/b", Some("s3://b")),
            (&dev, "b/dir", Some("s3://b/dir")),
            (&dev, "b", Some("s3://b")),
            (&top, "", None),      // the profile list
            (&top, "dev", None),   // a profile's bucket list
            (&dev, "", None),      // same, as the mount root
            (&old, "k", None),     // old-style s3://bucket/key: already public
            (&top, "bkt/k", None), // first segment not a profile: a bucket
        ];
        for (fs, path, want) in cases {
            assert_eq!(
                fs.public_url(path).as_deref(),
                want,
                "{}/{path}",
                fs.authority
            );
        }
        let g = <S3 as abi::glue::Fs>::public_url(&dev, "b/k");
        assert_eq!(g.as_deref(), Some("s3://b/k"), "glue impl forwards");
    }

    #[test]
    fn profile_and_bucket_lists_without_network() {
        let fs = Arc::new(s3("", CREDS, CONF));
        assert_eq!(fs.profiles, ["default", "bare", "dev", "none"]);
        let mut l = fs.list("").unwrap();
        let names: Vec<_> = l.next_batch(10, &|| false).unwrap();
        assert!(names.iter().all(|i| i.dir));
        assert_eq!(
            names.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(),
            fs.profiles
        );
        assert!(l.next_batch(10, &|| false).unwrap().is_empty());
        assert!(fs.stat("").unwrap().dir && fs.stat("dev").unwrap().dir);
        // A profile / bucket is not an object.
        for p in ["", "dev", "dev/b"] {
            assert_eq!(fs.mkdir(p).unwrap_err().status, abi::UNSUPPORTED, "{p:?}");
        }
        assert_eq!(
            fs.reader("dev", 0, None).err().unwrap().status,
            abi::UNSUPPORTED
        );
        assert_eq!(
            fs.writer("dev", false, 0).err().unwrap().status,
            abi::UNSUPPORTED
        );
        assert_eq!(fs.remove_file("").unwrap_err().status, abi::UNSUPPORTED);
        assert_eq!(fs.remove_dir("dev").unwrap_err().status, abi::UNSUPPORTED);
        // One client per profile; a profile without credentials is an AUTH error.
        assert!(Arc::ptr_eq(
            &fs.store("dev").unwrap(),
            &fs.store("dev").unwrap()
        ));
        assert_eq!(fs.stat("none").unwrap_err().status, abi::AUTH);
        let never = || false;
        let e = fs.rename("default/b/x", "dev/b/y", &never).unwrap_err();
        assert!(
            e.status == abi::UNSUPPORTED && e.msg.contains("profiles"),
            "{}",
            e.msg
        );
        // A profile mount: its root is the bucket list.
        let dev = s3("dev", CREDS, CONF);
        assert!(dev.stat("").unwrap().dir);
        assert!(matches!(dev.at("b/k").unwrap(), At::Obj(_, b, k) if b == "b" && k == "k"));
        assert_eq!(S3::open("http://x").err().unwrap().status, abi::INVALID);
        assert_eq!(S3::open("s3://a/b").err().unwrap().status, abi::INVALID);
    }

    #[test]
    fn bucket_fallback_uses_the_cache_and_reports_failures() {
        let fs = s3("", CREDS, CONF);
        lock(&BUCKETS).insert("cached-bkt".into(), "dev".into());
        let (st, b, k) = fs.key("cached-bkt/a/b").unwrap();
        assert!(Arc::ptr_eq(&st, &fs.store("dev").unwrap()));
        assert_eq!((b.as_str(), k.as_str()), ("cached-bkt", "a/b"));
        // Bucket mount (`s3://cached-bkt`): same resolution.
        let mount = s3("cached-bkt", CREDS, CONF);
        assert!(
            matches!(mount.at("x").unwrap(), At::Obj(_, b, k) if b == "cached-bkt" && k == "x")
        );
        // Every profile fails before any request (no credentials): the first error.
        let none = s3("", "", CONF);
        let e = none.stat("some-bkt/k").unwrap_err();
        assert!(
            e.status == abi::AUTH && e.msg.contains("profile bare"),
            "{}",
            e.msg
        );
        // Store errors are cached per mount (no second CLI run / config read).
        assert!(none.store("bare").is_err());
        assert!(matches!(lock(&none.stores).get("bare"), Some(Err(_))));
    }

    #[test]
    fn bucket_fallback_finds_caches_and_forgets() {
        let mut fs = s3("", CREDS, CONF);
        fs.probe = |st, _| match st.c.profile() {
            "dev" => Ok(()),
            _ => Err(Error::new(abi::DENIED, "no")),
        };
        let (st, b, _) = fs.key("fb-new/k").unwrap();
        assert!(Arc::ptr_eq(&st, &fs.store("dev").unwrap()) && b == "fb-new");
        assert_eq!(
            lock(&BUCKETS).get("fb-new").map(String::as_str),
            Some("dev")
        );
        // A rejection forgets the pick; other errors keep it.
        assert!(checked("fb-new", Err::<(), _>(Error::new(abi::IO, "x"))).is_err());
        assert!(lock(&BUCKETS).contains_key("fb-new"));
        assert!(checked("fb-new", Err::<(), _>(Error::new(abi::DENIED, "x"))).is_err());
        assert!(!lock(&BUCKETS).contains_key("fb-new"));
        // NoSuchBucket from the first profile: that answer, nothing cached.
        fs.probe = |_, _| Err(Error::new(abi::NOT_FOUND, "NoSuchBucket"));
        assert_eq!(fs.stat("fb-gone/k").unwrap_err().status, abi::NOT_FOUND);
        assert!(!lock(&BUCKETS).contains_key("fb-gone"));
    }

    #[test]
    fn not_found_stops_the_fallback() {
        let order: Vec<String> = ["a", "b"].map(String::from).into();
        let mut tried = 0;
        let e = first_ok::<()>(&order, |_| {
            tried += 1;
            Err(Error::new(abi::NOT_FOUND, "NoSuchBucket"))
        })
        .unwrap_err();
        assert_eq!((e.status, tried), (abi::NOT_FOUND, 1));
    }

    #[test]
    fn same_profile_rename_reaches_the_bucket() {
        let url = crate::client::mock(|m, _| match m {
            "HEAD" => (404, String::new()),
            _ => (200, "<ListBucketResult></ListBucketResult>".into()),
        });
        let conf = format!("[profile dev]\nendpoint_url = {url}\n");
        let fs = s3("", CREDS, &conf);
        let e = fs.rename("dev/b/x", "dev/b/y", &|| false).unwrap_err();
        assert_eq!(e.status, abi::NOT_FOUND, "{}", e.msg);
        assert!(e.msg.contains("b/x: not found"), "{}", e.msg);
        let fs = Arc::new(fs);
        let mut l = fs.list("dev/b").unwrap();
        assert!(l.next_batch(10, &|| false).unwrap().is_empty());
        assert_eq!(fs.stat("dev/b").unwrap_err().status, abi::NOT_FOUND);
        assert!(fs.list("dev").is_ok(), "ListBuckets (no <Buckets>: empty)");
    }

    /// Object ops end to end against a canned server: `f` exists ("hello"), nothing else.
    #[test]
    fn object_ops_against_a_server() {
        let url = crate::client::mock(|m, p| match (m, p) {
            ("HEAD", "/b/f" | "/b/") => (200, String::new()),
            ("GET", "/b/f") => (200, "hello".into()),
            ("GET", p)
                if p.starts_with("/b/?") && (p.ends_with("prefix=") || p.contains("prefix=&")) =>
            {
                (
                    200,
                    "<ListBucketResult><Contents><Key>f</Key><Size>5</Size></Contents>\
                 <CommonPrefixes><Prefix>d/</Prefix></CommonPrefixes></ListBucketResult>"
                        .into(),
                )
            }
            ("GET", p) if p.starts_with("/b/?") => (200, "<ListBucketResult/>".into()),
            ("GET", "/") => (
                200,
                "<ListAllMyBucketsResult><Buckets><Bucket><Name>b</Name></Bucket>\
                 </Buckets></ListAllMyBucketsResult>"
                    .into(),
            ),
            ("PUT" | "DELETE", _) => (200, String::new()),
            _ => (404, String::new()),
        });
        let conf = format!("[profile dev]\nendpoint_url = {url}\n");
        let fs = Arc::new(s3("", CREDS, &conf));
        let never = || false;
        let names = |mut l: Lister| {
            let v = l.next_batch(10, &never).unwrap();
            v.into_iter().map(|i| i.name).collect::<Vec<_>>()
        };
        assert_eq!(names(fs.list("dev").unwrap()), ["b"]);
        assert_eq!(names(fs.list("dev/b").unwrap()), ["d", "f"]);
        assert!(!fs.stat("dev/b/f").unwrap().dir);
        assert!(fs.stat("dev/b").unwrap().dir);
        let mut s = String::new();
        fs.reader("dev/b/f", 0, None)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "hello");
        assert_eq!(
            fs.reader("dev/b/gone", 0, None).err().unwrap().status,
            abi::NOT_FOUND
        );
        assert_eq!(fs.mkdir("dev/b/f").unwrap_err().status, abi::EXISTS);
        assert_eq!(
            fs.writer("dev/b/f", false, 5).err().unwrap().status,
            abi::EXISTS
        );
        let mut w = fs.writer("dev/b/f", true, 5).unwrap();
        w.write(b"world").unwrap();
        w.finish().unwrap();
        fs.remove_file("dev/b/f").unwrap();
        assert_eq!(
            fs.remove_file("dev/b/gone").unwrap_err().status,
            abi::NOT_FOUND
        );
        assert_eq!(
            fs.rename("dev/b/f", "dev/b/f", &never).unwrap_err().status,
            abi::EXISTS
        );
        fs.rename("dev/b/f", "dev/b/g", &never).unwrap();
    }
}

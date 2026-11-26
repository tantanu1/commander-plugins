//! S3 vfs plugin (C ABI v1). Mount `s3://` (bucket list) or `s3://bucket/...`.
//! This file only maps `fs` onto the shared ABI glue (`commander_plugin_abi::glue`); S3
//! semantics live in `fs`, HTTP/signing in `client`/`sign`.
mod client;
mod config;
mod download;
mod fs;
mod sign;
mod xml;

use client::{Error, Result};
use commander_plugin_abi::{self as abi, glue};
use fs::{Item, Lister, S3, Writer};
use std::io::Read;
use std::sync::Arc;

impl From<Error> for glue::Error {
    fn from(e: Error) -> Self {
        glue::Error::new(e.status, e.msg)
    }
}

impl From<Item> for glue::Item {
    fn from(it: Item) -> Self {
        glue::Item {
            name: it.name,
            kind: if it.dir {
                abi::KIND_DIR
            } else {
                abi::KIND_FILE
            },
            size: it.size,
            mtime: it.mtime,
            link: false,
        }
    }
}

impl glue::Fs for S3 {
    type Error = Error;
    type Lister = Lister;
    type Writer = Writer;
    const NAME: &'static str = "s3";

    fn open(config: &str) -> Result<Self> {
        S3::open(config)
    }

    fn list(self: &Arc<Self>, dir: &str) -> Result<Lister> {
        S3::list(self, dir)
    }

    fn next_batch(
        l: &mut Lister,
        cap: usize,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<glue::Item>> {
        Ok(l.next_batch(cap, cancelled)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    fn stat(&self, path: &str) -> Result<glue::Item> {
        S3::stat(self, path).map(Into::into)
    }

    fn reader(&self, path: &str, offset: u64) -> Result<Box<dyn Read + Send>> {
        S3::reader(self, path, offset, None)
    }

    fn reader_job(&self, path: &str, offset: u64, c: glue::Cancel) -> Result<Box<dyn Read + Send>> {
        S3::reader(self, path, offset, Some(c))
    }

    fn writer(self: &Arc<Self>, path: &str, overwrite: bool, hint: u64) -> Result<Writer> {
        S3::writer(self, path, overwrite, hint)
    }

    fn write(w: &mut Writer, data: &[u8]) -> Result<()> {
        w.write(data)
    }

    fn finish(w: Writer) -> Result<()> {
        w.finish()
    }

    fn mkdir(&self, path: &str) -> Result<()> {
        S3::mkdir(self, path)
    }

    fn remove_file(&self, path: &str) -> Result<()> {
        S3::remove_file(self, path)
    }

    fn remove_dir(&self, path: &str) -> Result<()> {
        S3::remove_dir(self, path)
    }

    fn rename(&self, from: &str, to: &str, cancelled: &dyn Fn() -> bool) -> Result<()> {
        S3::rename(self, from, to, cancelled)
    }

    fn public_url(&self, path: &str) -> Option<String> {
        S3::public_url(self, path)
    }
}

commander_plugin_abi::export_vfs!(S3);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversions_and_open() {
        let e: glue::Error = Error::new(abi::AUTH, "no creds").into();
        assert_eq!((e.status, e.msg.as_str()), (abi::AUTH, "no creds"));
        let file = Item {
            name: "k".into(),
            dir: false,
            size: 5,
            mtime: Some(1),
        };
        let g: glue::Item = file.into();
        assert_eq!((g.kind, g.size, g.mtime), (abi::KIND_FILE, 5, Some(1)));
        let dir = Item {
            name: "d".into(),
            dir: true,
            size: 0,
            mtime: None,
        };
        assert_eq!(glue::Item::from(dir).kind, abi::KIND_DIR);
        let bad = <S3 as glue::Fs>::open("http://x");
        assert_eq!(bad.err().map(|e| e.status), Some(abi::INVALID));
    }
}

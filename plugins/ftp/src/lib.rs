//! FTP / FTPS vfs plugin (C ABI v1): `ftp://[user[:pass]@]host[:port]/path`, `ftps://` =
//! explicit TLS, `ftp://<bookmark>` from `ftp.toml`, `ftp://` = bookmark list.
//! This file only maps `fs` onto the shared ABI glue; FTP semantics live in `fs`.
mod config;
#[cfg(test)]
mod fake;
mod fs;
mod list;

use commander_plugin_abi::glue::{self, Item, Result};
use fs::{Ftp, Lister, Writer};
use std::io::Read;
use std::sync::Arc;

impl glue::Fs for Ftp {
    type Error = glue::Error;
    type Lister = Lister;
    type Writer = Writer;
    const NAME: &'static str = "ftp";

    fn open(config: &str) -> Result<Self> {
        Ftp::open(config)
    }

    fn list(self: &Arc<Self>, dir: &str) -> Result<Lister> {
        Ftp::list(self, dir)
    }

    fn next_batch(l: &mut Lister, cap: usize, _cancelled: &dyn Fn() -> bool) -> Result<Vec<Item>> {
        Ok(l.next_batch(cap))
    }

    fn stat(&self, path: &str) -> Result<Item> {
        Ftp::stat(self, path)
    }

    fn reader(&self, path: &str, offset: u64) -> Result<Box<dyn Read + Send>> {
        Ftp::reader(self, path, offset)
    }

    fn writer(self: &Arc<Self>, path: &str, overwrite: bool, _hint: u64) -> Result<Writer> {
        Ftp::writer(self, path, overwrite)
    }

    fn write(w: &mut Writer, data: &[u8]) -> Result<()> {
        w.write(data)
    }

    fn finish(w: Writer) -> Result<()> {
        w.finish()
    }

    fn mkdir(&self, path: &str) -> Result<()> {
        Ftp::mkdir(self, path)
    }

    fn remove_file(&self, path: &str) -> Result<()> {
        Ftp::remove_file(self, path)
    }

    fn remove_dir(&self, path: &str) -> Result<()> {
        Ftp::remove_dir(self, path)
    }

    fn rename(&self, from: &str, to: &str, _cancelled: &dyn Fn() -> bool) -> Result<()> {
        Ftp::rename(self, from, to)
    }
}

commander_plugin_abi::export_vfs!(Ftp);

#[cfg(test)]
mod tests {
    use super::*;
    use commander_plugin_abi as abi;
    use glue::Fs;

    /// The glue::Fs mapping, end to end against the in-process fake server.
    #[test]
    fn fs_trait_over_fake_server() {
        let port = fake::start(fake::Shared::default());
        let fs = Arc::new(<Ftp as Fs>::open(&format!("ftp://u@127.0.0.1:{port}")).unwrap());
        Fs::mkdir(&*fs, "d").unwrap();
        let mut w = Fs::writer(&fs, "d/a", false, 3).unwrap();
        <Ftp as Fs>::write(&mut w, b"abc").unwrap();
        <Ftp as Fs>::finish(w).unwrap();
        let mut l = Fs::list(&fs, "d").unwrap();
        let got = <Ftp as Fs>::next_batch(&mut l, 10, &|| false).unwrap();
        assert_eq!(got[0].name, "a");
        assert_eq!(Fs::stat(&*fs, "d/a").unwrap().size, 3);
        let mut s = String::new();
        Fs::reader(&*fs, "d/a", 1)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "bc");
        Fs::rename(&*fs, "d/a", "d/b", &|| false).unwrap();
        Fs::remove_file(&*fs, "d/b").unwrap();
        Fs::remove_dir(&*fs, "d").unwrap();
        assert_eq!(Fs::stat(&*fs, "d").unwrap_err().status, abi::NOT_FOUND);
    }
}

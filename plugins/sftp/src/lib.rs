//! SFTP vfs plugin (C ABI v1): `sftp://[user@]host[:port]/path`, `sftp://<bookmark>` from
//! `sftp.toml`, `sftp://` = bookmark list; hosts may be `~/.ssh/config` aliases. Auth: key
//! files (passphrase via `NEED_PASSPHRASE` + the host prompt), ssh-agent / Pageant, bookmark
//! password; host keys must be in `~/.ssh/known_hosts`. This file only maps `fs` onto the
//! shared ABI glue.
mod config;
#[cfg(test)]
mod fake;
mod fs;
mod known_hosts;
mod ssh;
mod ssh_config;

use commander_plugin_abi::glue::{self, Item, Result};
use fs::{Sftp, Writer};
use std::io::Read;
use std::sync::Arc;

impl glue::Fs for Sftp {
    type Error = glue::Error;
    type Lister = std::vec::IntoIter<Item>;
    type Writer = Writer;
    const NAME: &'static str = "sftp";

    fn open(config: &str) -> Result<Self> {
        Sftp::open(config)
    }

    fn list(self: &Arc<Self>, dir: &str) -> Result<Self::Lister> {
        Sftp::list(self, dir).map(Vec::into_iter)
    }

    fn next_batch(l: &mut Self::Lister, cap: usize, _: &dyn Fn() -> bool) -> Result<Vec<Item>> {
        Ok(l.take(cap).collect())
    }

    fn stat(&self, path: &str) -> Result<Item> {
        Sftp::stat(self, path)
    }

    fn reader(&self, path: &str, offset: u64) -> Result<Box<dyn Read + Send>> {
        Sftp::reader(self, path, offset)
    }

    fn writer(self: &Arc<Self>, path: &str, overwrite: bool, _hint: u64) -> Result<Writer> {
        Sftp::writer(self, path, overwrite)
    }

    fn write(w: &mut Writer, data: &[u8]) -> Result<()> {
        w.write(data)
    }

    fn finish(w: Writer) -> Result<()> {
        w.finish()
    }

    fn mkdir(&self, path: &str) -> Result<()> {
        Sftp::mkdir(self, path)
    }

    fn remove_file(&self, path: &str) -> Result<()> {
        Sftp::remove_file(self, path)
    }

    fn remove_dir(&self, path: &str) -> Result<()> {
        Sftp::remove_dir(self, path)
    }

    fn rename(&self, from: &str, to: &str, _: &dyn Fn() -> bool) -> Result<()> {
        Sftp::rename(self, from, to)
    }
}

commander_plugin_abi::export_vfs!(Sftp);

#[cfg(test)]
mod tests {
    use super::*;
    use commander_plugin_abi as abi;
    use glue::Fs;

    /// The glue::Fs mapping, end to end against the in-memory server.
    #[test]
    fn fs_trait_over_fake_server() {
        let auth = fake::start(fake::Shared::default());
        let marks = || Ok(config::Bookmarks::new());
        let fs = Arc::new(
            // A key passphrase from the host prompt never reaches the authority.
            Sftp::open_with(
                &format!("sftp://{auth}\nsesame"),
                marks,
                String::new,
                fake::dial,
            )
            .unwrap(),
        );
        Fs::mkdir(&*fs, "d").unwrap();
        let mut w = Fs::writer(&fs, "d/a", false, 3).unwrap();
        <Sftp as Fs>::write(&mut w, b"abc").unwrap();
        <Sftp as Fs>::finish(w).unwrap();
        let mut l = Fs::list(&fs, "d").unwrap();
        let got = <Sftp as Fs>::next_batch(&mut l, 10, &|| false).unwrap();
        assert_eq!(got[0].name, "a");
        assert!(
            <Sftp as Fs>::next_batch(&mut l, 10, &|| false)
                .unwrap()
                .is_empty()
        );
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
        assert_eq!(
            <Sftp as Fs>::open("nope").err().unwrap().status,
            abi::INVALID
        );
    }
}

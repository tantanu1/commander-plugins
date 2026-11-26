//! SMB vfs plugin (C ABI v1): `smb://[user@]host[:port]/share/path`, `smb://<bookmark>` from
//! `smb.toml`, `smb://` = bookmark list, `smb://host` = its shares. Auth: NTLM with the bookmark
//! password or the host prompt (`NEED_PASSPHRASE` + `password=1`), guest when no user is given.
//! This file only maps `fs` onto the shared ABI glue.
mod client;
mod config;
#[cfg(test)]
mod fake;
mod fs;

use commander_plugin_abi::glue::{self, Item, Result};
use fs::{Listing, Smb, Writer};
use std::io::Read;
use std::sync::Arc;

impl glue::Fs for Smb {
    type Error = glue::Error;
    type Lister = Listing;
    type Writer = Writer;
    const NAME: &'static str = "smb";

    fn open(config: &str) -> Result<Self> {
        Smb::open(config)
    }

    fn list(self: &Arc<Self>, dir: &str) -> Result<Self::Lister> {
        Smb::list(self, dir)
    }

    fn next_batch(l: &mut Listing, cap: usize, cancelled: &dyn Fn() -> bool) -> Result<Vec<Item>> {
        l.next_batch(cap, cancelled)
    }

    fn stat(&self, path: &str) -> Result<Item> {
        Smb::stat(self, path)
    }

    fn reader(&self, path: &str, offset: u64) -> Result<Box<dyn Read + Send>> {
        Smb::reader(self, path, offset)
    }

    fn writer(self: &Arc<Self>, path: &str, overwrite: bool, _hint: u64) -> Result<Writer> {
        Smb::writer(self, path, overwrite)
    }

    fn write(w: &mut Writer, data: &[u8]) -> Result<()> {
        w.write(data)
    }

    fn finish(w: Writer) -> Result<()> {
        w.finish()
    }

    fn mkdir(&self, path: &str) -> Result<()> {
        Smb::mkdir(self, path)
    }

    fn remove_file(&self, path: &str) -> Result<()> {
        Smb::remove_file(self, path)
    }

    fn remove_dir(&self, path: &str) -> Result<()> {
        Smb::remove_dir(self, path)
    }

    fn rename(&self, from: &str, to: &str, _: &dyn Fn() -> bool) -> Result<()> {
        Smb::rename(self, from, to)
    }
}

commander_plugin_abi::export_vfs!(Smb);

#[cfg(test)]
mod tests {
    use super::*;
    use commander_plugin_abi as abi;
    use glue::Fs;

    /// The glue::Fs mapping, end to end against the in-memory session.
    #[test]
    fn fs_trait_over_fake_session() {
        let f = fake::Fake::default();
        f.st.lock().unwrap().add_share("s");
        let dial =
            move |_: &config::Target| -> Result<Box<dyn fs::Session>> { Ok(Box::new(f.clone())) };
        let marks = || Ok(config::Bookmarks::new());
        let fs = Arc::new(Smb::open_with("smb://h", marks, &dial).unwrap());
        Fs::mkdir(&*fs, "s/d").unwrap();
        let mut w = Fs::writer(&fs, "s/d/a", false, 3).unwrap();
        <Smb as Fs>::write(&mut w, b"abc").unwrap();
        <Smb as Fs>::finish(w).unwrap();
        let mut l = Fs::list(&fs, "s/d").unwrap();
        let got = <Smb as Fs>::next_batch(&mut l, 10, &|| false).unwrap();
        assert_eq!(got[0].name, "a");
        assert!(
            <Smb as Fs>::next_batch(&mut l, 10, &|| false)
                .unwrap()
                .is_empty()
        );
        assert_eq!(Fs::stat(&*fs, "s/d/a").unwrap().size, 3);
        let mut s = String::new();
        Fs::reader(&*fs, "s/d/a", 1)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "bc");
        Fs::rename(&*fs, "s/d/a", "s/d/b", &|| false).unwrap();
        Fs::remove_file(&*fs, "s/d/b").unwrap();
        Fs::remove_dir(&*fs, "s/d").unwrap();
        assert_eq!(Fs::stat(&*fs, "s/d").unwrap_err().status, abi::NOT_FOUND);
        assert_eq!(
            <Smb as Fs>::open("nope").err().unwrap().status,
            abi::INVALID
        );
        assert!(
            <Smb as Fs>::open("smb://").is_ok(),
            "bookmark list needs no server"
        );
    }
}

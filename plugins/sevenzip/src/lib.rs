//! Archives through the user's installed 7-Zip (C ABI v1 vfs): `sevenzip://<archive>/<inner>`
//! where `<archive>` is the fs path encoded by `archive_url`. Nothing is bundled: 7z.exe /
//! 7zz is found at runtime (not installed = `open` fails with UNSUPPORTED and a hint).
//! This file only maps `fs` onto the shared ABI glue.
mod exe;
#[cfg(test)]
mod fake;
mod fs;
mod slt;

use commander_plugin_abi::glue::{self, Item, Result};
use fs::{SevenZip, Writer};
use std::io::Read;
use std::sync::Arc;

impl glue::Fs for SevenZip {
    type Error = glue::Error;
    type Lister = std::vec::IntoIter<Item>;
    type Writer = Writer;
    const NAME: &'static str = "sevenzip";

    fn open(config: &str) -> Result<Self> {
        SevenZip::open(config)
    }

    fn list(self: &Arc<Self>, dir: &str) -> Result<Self::Lister> {
        SevenZip::list(self, dir).map(Vec::into_iter)
    }

    fn next_batch(l: &mut Self::Lister, cap: usize, _: &dyn Fn() -> bool) -> Result<Vec<Item>> {
        Ok(l.take(cap).collect())
    }

    fn stat(&self, path: &str) -> Result<Item> {
        SevenZip::stat(self, path)
    }

    fn reader(&self, path: &str, offset: u64) -> Result<Box<dyn Read + Send>> {
        SevenZip::reader(self, path, offset)
    }

    fn writer(self: &Arc<Self>, path: &str, overwrite: bool, _hint: u64) -> Result<Writer> {
        SevenZip::writer(self, path, overwrite)
    }

    fn write(w: &mut Writer, data: &[u8]) -> Result<()> {
        w.write(data)
    }

    fn finish(w: Writer) -> Result<()> {
        w.finish()
    }

    fn mkdir(&self, path: &str) -> Result<()> {
        SevenZip::mkdir(self, path)
    }

    fn remove_file(&self, path: &str) -> Result<()> {
        SevenZip::remove_file(self, path)
    }

    fn remove_dir(&self, path: &str) -> Result<()> {
        SevenZip::remove_dir(self, path)
    }

    fn rename(&self, from: &str, to: &str, _: &dyn Fn() -> bool) -> Result<()> {
        SevenZip::rename(self, from, to)
    }
}

commander_plugin_abi::export_vfs!(SevenZip);

#[cfg(test)]
mod tests {
    use super::*;
    use commander_plugin_abi::archive_url;
    use glue::Fs;

    /// Every glue::Fs fn against the fake 7z, plus the exported entry point.
    #[test]
    fn glue_mapping_over_fake() {
        let t = tempfile::tempdir().unwrap();
        let arc = t.path().join("a.7z");
        let cfg = format!("sevenzip://{}", archive_url::encode(arc.to_str().unwrap()));
        let engine: Arc<dyn exe::Engine> = Arc::new(fake::Fake::default());
        let fs = Arc::new(SevenZip::with_engine(&cfg, engine).unwrap());
        Fs::mkdir(&*fs, "d").unwrap();
        let mut w = Fs::writer(&fs, "d/f", false, 3).unwrap();
        <SevenZip as Fs>::write(&mut w, b"abc").unwrap();
        <SevenZip as Fs>::finish(w).unwrap();
        let mut l = Fs::list(&fs, "d").unwrap();
        assert_eq!(
            <SevenZip as Fs>::next_batch(&mut l, 9, &|| false).unwrap()[0].name,
            "f"
        );
        assert!(
            <SevenZip as Fs>::next_batch(&mut l, 9, &|| false)
                .unwrap()
                .is_empty()
        );
        assert_eq!(Fs::stat(&*fs, "d/f").unwrap().size, 3);
        let mut s = String::new();
        Fs::reader(&*fs, "d/f", 1)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "bc");
        Fs::rename(&*fs, "d/f", "d/g", &|| false).unwrap();
        Fs::remove_file(&*fs, "d/g").unwrap();
        Fs::remove_dir(&*fs, "d").unwrap();
        assert!(Fs::stat(&*fs, "d").is_err());
        assert!(<SevenZip as Fs>::open("not a mount").is_err());
        // SAFETY: the host's call: our ABI, no host struct needed.
        let p = unsafe { cmdr_plugin_entry(commander_plugin_abi::CMDR_ABI, std::ptr::null()) };
        assert!(!p.is_null());
    }

    /// The glue::Fs mapping against the real 7-Zip (whatever this machine has).
    #[test]
    #[ignore = "needs 7-Zip installed (never downloaded by tests)"]
    fn live_roundtrip() {
        let t = tempfile::tempdir().unwrap();
        let arc = t.path().join("live.7z");
        let cfg = format!("sevenzip://{}", archive_url::encode(arc.to_str().unwrap()));
        let fs = Arc::new(<SevenZip as Fs>::open(&cfg).unwrap());
        Fs::mkdir(&*fs, "d").unwrap();
        // Windows file names can't hold `*` (writes are staged as real files).
        let star = if cfg!(windows) {
            "st[r].txt"
        } else {
            "st*r.txt"
        };
        for (p, body) in [
            ("d/-a.txt", "dash"),
            ("@l.txt", "at"),
            (star, "star"),
            ("żółw 🐢.txt", "turtle"),
        ] {
            let mut w = Fs::writer(&fs, p, false, 0).unwrap();
            <SevenZip as Fs>::write(&mut w, body.as_bytes()).unwrap();
            <SevenZip as Fs>::finish(w).unwrap();
        }
        let mut l = Fs::list(&fs, "").unwrap();
        let mut names: Vec<_> = <SevenZip as Fs>::next_batch(&mut l, 9, &|| false)
            .unwrap()
            .into_iter()
            .map(|i| i.name)
            .collect();
        names.sort();
        assert_eq!(names, ["@l.txt", "d", star, "żółw 🐢.txt"]);
        let read = |p: &str| {
            let mut s = String::new();
            Fs::reader(&*fs, p, 0)
                .unwrap()
                .read_to_string(&mut s)
                .unwrap();
            s
        };
        assert_eq!(read("d/-a.txt"), "dash");
        assert_eq!(read(star), "star", "no wildcard match");
        assert_eq!(read("żółw 🐢.txt"), "turtle", "UTF-8 names both ways");
        Fs::rename(&*fs, "d", "e", &|| false).unwrap();
        assert_eq!(read("e/-a.txt"), "dash");
        Fs::remove_file(&*fs, "e/-a.txt").unwrap();
        Fs::remove_dir(&*fs, "e").unwrap();
        assert!(Fs::stat(&*fs, "e").is_err());
        assert_eq!(read("@l.txt"), "at", "a root name deletes nothing below");

        // Encrypted: no password = AUTH, wrong = AUTH, right = readable.
        let enc = t.path().join("enc.zip");
        let ecfg = format!("sevenzip://{}", archive_url::encode(enc.to_str().unwrap()));
        let e = Arc::new(<SevenZip as Fs>::open(&format!("{ecfg}\npw")).unwrap());
        let mut w = Fs::writer(&e, "s.txt", false, 0).unwrap();
        <SevenZip as Fs>::write(&mut w, b"secret").unwrap();
        <SevenZip as Fs>::finish(w).unwrap();
        let st = |c: &str| <SevenZip as Fs>::open(c).err().map(|e| e.status);
        assert_eq!(st(&ecfg), Some(commander_plugin_abi::AUTH));
        assert_eq!(
            st(&format!("{ecfg}\nbad")),
            Some(commander_plugin_abi::AUTH)
        );
        let ok = <SevenZip as Fs>::open(&format!("{ecfg}\npw")).unwrap();
        let mut s = String::new();
        ok.reader("s.txt", 0)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "secret");

        // Case twins (tar keeps both): reads and deletes hit exactly one (-ssc).
        let tar = t.path().join("twins.tar");
        let tcfg = format!("sevenzip://{}", archive_url::encode(tar.to_str().unwrap()));
        let tw = Arc::new(<SevenZip as Fs>::open(&tcfg).unwrap());
        for (p, body) in [("a.txt", "lower"), ("A.txt", "UPPER")] {
            let mut w = Fs::writer(&tw, p, false, 0).unwrap();
            <SevenZip as Fs>::write(&mut w, body.as_bytes()).unwrap();
            <SevenZip as Fs>::finish(w).unwrap();
        }
        let get = |p: &str| {
            let mut s = String::new();
            tw.reader(p, 0).unwrap().read_to_string(&mut s).map(|_| s)
        };
        assert_eq!(get("a.txt").unwrap(), "lower");
        assert_eq!(get("A.txt").unwrap(), "UPPER");
        Fs::remove_file(&*tw, "A.txt").unwrap();
        assert_eq!(get("a.txt").unwrap(), "lower", "twin survives the delete");
        assert!(Fs::stat(&*tw, "A.txt").is_err());

        // A corrupted item: the read fails at the end instead of passing as a good copy.
        let src = t.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("c.txt"), "x".repeat(4096)).unwrap();
        let bad = t.path().join("bad.7z");
        let exe = exe::find().unwrap();
        let st = std::process::Command::new(exe)
            .args(["a", "-bd", "-y", "-mx0", "--"])
            .arg(&bad)
            .arg("c.txt")
            .current_dir(&src)
            .output()
            .unwrap()
            .status;
        assert!(st.success());
        let mut b = std::fs::read(&bad).unwrap();
        let at = b.windows(8).position(|w| w == b"xxxxxxxx").unwrap();
        b[at + 100] = b'y';
        std::fs::write(&bad, b).unwrap();
        let bcfg = format!("sevenzip://{}", archive_url::encode(bad.to_str().unwrap()));
        let bfs = <SevenZip as Fs>::open(&bcfg).unwrap();
        let mut out = Vec::new();
        let r = bfs.reader("c.txt", 0).unwrap().read_to_end(&mut out);
        assert!(r.is_err(), "CRC error surfaces ({} bytes read)", out.len());
    }
}

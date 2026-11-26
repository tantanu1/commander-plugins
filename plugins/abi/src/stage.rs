//! Private temp dir for staging one archive write (or one extracted item); removed on drop.
//! Shared by the host (WCX packers) and the 7-Zip plugin.
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Stage(PathBuf);

impl Stage {
    /// Fresh `<temp>/<prefix>-<pid>-<n>`: owner-only on unix (plaintext may sit there).
    pub fn new(prefix: &str) -> io::Result<Self> {
        static N: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir();
        for _ in 0..100 {
            let n = N.fetch_add(1, Ordering::Relaxed);
            let dir = base.join(format!("{prefix}-{}-{n}", std::process::id()));
            #[cfg(unix)]
            let b = {
                let mut b = fs::DirBuilder::new();
                std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
                b
            };
            #[cfg(not(unix))]
            let b = fs::DirBuilder::new();
            match b.create(&dir) {
                Ok(()) => return Ok(Self(dir)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::other("no free temp dir name"))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    /// New file at `rel` ('/'-separated, validated by the caller) under the stage; never
    /// replaces one.
    pub fn file(&self, rel: &str) -> io::Result<File> {
        let p = self.0.join(rel);
        if let Some(d) = p.parent() {
            fs::create_dir_all(d)?;
        }
        File::create_new(&p)
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        // Only ever our own fresh dir under the temp dir (created by `new`).
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_is_private_and_removed() {
        let s = Stage::new("cmdr-stage-test").unwrap();
        let dir = s.path().to_path_buf();
        s.file("a/b.txt").unwrap();
        assert!(s.file("a/b.txt").is_err(), "never replaces");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "owner only");
        }
        drop(s);
        assert!(!dir.exists());
    }
}

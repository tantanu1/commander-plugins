//! FTP transfer mode of an `ftp.toml` bookmark (`mode`), shared by the ftp plugin (which
//! transfers with it) and the host (cm_FtpSelectTransferMode, and the copy size check that a
//! text transfer may break): one list, so the two can't drift.

/// Transfer type. Text = `TYPE A`: line ends differ between the wire and the disk, so sizes
/// and offsets don't match the listing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TransferMode {
    #[default]
    Binary,
    Ascii,
    /// Text for [`TEXT_EXTS`], binary for the rest.
    Auto,
}

/// Extensions `auto` transfers as text (lowercase).
pub const TEXT_EXTS: &[&str] = &[
    "txt", "htm", "html", "css", "js", "json", "xml", "ini", "cfg", "conf", "log", "csv", "md",
    "php", "pl", "py", "sh", "bat", "cmd", "c", "h", "cpp", "rs", "java", "sql",
];

impl TransferMode {
    /// The bookmark value (`text` = `ascii`); unknown = `None`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "binary" => Some(Self::Binary),
            "ascii" | "text" => Some(Self::Ascii),
            "auto" => Some(Self::Auto),
            _ => None,
        }
    }

    /// The bookmark value written for it.
    pub fn key(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::Ascii => "ascii",
            Self::Auto => "auto",
        }
    }

    /// Transfer `path` ('/'-separated) as text?
    pub fn text(self, path: &str) -> bool {
        let name = path.rsplit('/').next().unwrap_or(path);
        let ext = name.rsplit_once('.').map(|(_, e)| e);
        match self {
            Self::Binary => false,
            Self::Ascii => true,
            Self::Auto => ext.is_some_and(|e| TEXT_EXTS.iter().any(|t| t.eq_ignore_ascii_case(e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes() {
        for m in [
            TransferMode::Binary,
            TransferMode::Ascii,
            TransferMode::Auto,
        ] {
            assert_eq!(TransferMode::parse(m.key()), Some(m));
        }
        assert_eq!(TransferMode::parse("text"), Some(TransferMode::Ascii));
        assert_eq!(TransferMode::parse("ebcdic"), None);
        assert!(TransferMode::Ascii.text("a.bin") && !TransferMode::Binary.text("a.txt"));
        assert!(TransferMode::Auto.text("d/README.TXT") && TransferMode::Auto.text("x.rs"));
        assert!(!TransferMode::Auto.text("a.zip") && !TransferMode::Auto.text("txt"));
        assert!(!TransferMode::Auto.text("d.txt/x"));
    }
}

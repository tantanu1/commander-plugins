//! `vmware.toml` (optional, next to Commander's config.toml; env `COMMANDER_VMWARE_CONFIG`)
//! and where the VMware tools live (config override, registry, well-known paths).
use commander_plugin_abi::url;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Which VMware product runs the VMs (`vmrun -T`, VIX service provider).
#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Product {
    Ws,
    Player,
    Fusion,
}

impl Default for Product {
    fn default() -> Self {
        match cfg!(target_os = "macos") {
            true => Self::Fusion,
            false => Self::Ws,
        }
    }
}

impl Product {
    pub fn vmrun_type(self) -> &'static str {
        match self {
            Self::Ws => "ws",
            Self::Player => "player",
            Self::Fusion => "fusion",
        }
    }

    /// `VIX_SERVICEPROVIDER_*` (Fusion speaks the Workstation provider).
    pub fn vix_provider(self) -> i32 {
        match self {
            Self::Ws | Self::Fusion => 3,
            Self::Player => 4,
        }
    }
}

/// Which backend to use.
#[derive(Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Choice {
    /// VIX if it loads and connects, else vmrun.
    #[default]
    Auto,
    Vix,
    Vmrun,
}

#[derive(Deserialize, Debug, Default, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub product: Product,
    #[serde(default)]
    pub backend: Choice,
    /// VIX library tried first (e.g. `Vix64AllProductsDyn.dll` or a `64bit\vix.dll`).
    pub vix: Option<PathBuf>,
    pub vmrun: Option<PathBuf>,
    /// Guest user for every VM without its own entry in `users`.
    pub user: Option<String>,
    /// Guest user per VM (by the name shown in `vmware://`).
    #[serde(default)]
    pub users: BTreeMap<String, String>,
    /// Windows guests: drive letters to show (e.g. "CD"); default = probe C..Z.
    pub drives: Option<String>,
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, String> {
        let c: Self = toml::from_str(text).map_err(|e| format!("vmware.toml: {}", e.message()))?;
        let bad = |s: &str| s.contains(char::is_control);
        if c.user.as_deref().is_some_and(bad) || c.users.values().any(|u| bad(u)) {
            return Err("vmware.toml: bad user name (control character)".into());
        }
        if c.drives
            .as_deref()
            .is_some_and(|d| d.contains(|ch: char| !ch.is_ascii_alphabetic()))
        {
            return Err("vmware.toml: drives must be letters, like \"CD\"".into());
        }
        Ok(c)
    }

    /// Guest user for `vm` (`None` = ask with the password).
    pub fn user_for(&self, vm: &str) -> Option<&str> {
        self.users
            .get(vm)
            .or(self.user.as_ref())
            .map(String::as_str)
    }

    /// VIX libraries to try, in order (only existing files).
    pub fn vix_candidates(&self) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = self.vix.iter().cloned().collect();
        v.extend(default_vix());
        v.into_iter().filter(|p| p.is_file()).collect()
    }

    /// vmrun to run (`vmrun` on PATH when none is found).
    pub fn vmrun_path(&self) -> PathBuf {
        let found = self.vmrun.iter().cloned().chain(default_vmrun());
        found
            .into_iter()
            .find(|p| p.is_file())
            .unwrap_or_else(|| PathBuf::from("vmrun"))
    }
}

/// [`Config`] from `vmware.toml`; a missing file = defaults.
pub fn load() -> Result<Config, String> {
    load_from(url::config_file("COMMANDER_VMWARE_CONFIG", "vmware.toml").as_deref())
}

/// [`Config`] from file `p` (none / missing = defaults).
fn load_from(p: Option<&Path>) -> Result<Config, String> {
    match p {
        Some(p) => url::read_optional(p)?.map_or(Ok(Config::default()), |t| Config::parse(&t)),
        None => Ok(Config::default()),
    }
}

/// `Workstation-*/64bit/vix.dll` under the VIX SDK dir, newest version first.
fn sdk_vix(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<(Vec<u32>, PathBuf)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let ver = name.strip_prefix("Workstation-")?;
            let key = ver.split('.').map(|n| n.parse().unwrap_or(0)).collect();
            Some((key, e.path().join("64bit").join("vix.dll")))
        })
        .collect();
    v.sort_by(|a, b| b.0.cmp(&a.0));
    v.into_iter().map(|(_, p)| p).collect()
}

#[cfg(windows)]
fn install_dir(product: &str) -> Option<PathBuf> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY};
    let key = format!("SOFTWARE\\VMware, Inc.\\{product}");
    let k = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(key, KEY_READ | KEY_WOW64_32KEY)
        .ok()?;
    k.get_value::<String, _>("InstallPath")
        .ok()
        .map(PathBuf::from)
}

#[cfg(windows)]
fn program_files_x86(rel: &str) -> PathBuf {
    let base =
        std::env::var_os("ProgramFiles(x86)").unwrap_or_else(|| "C:\\Program Files (x86)".into());
    Path::new(&base).join("VMware").join(rel)
}

#[cfg(windows)]
fn default_vix() -> Vec<PathBuf> {
    let dir = install_dir("VMware VIX").unwrap_or_else(|| program_files_x86("VMware VIX"));
    // The wrapper first: it picks the right build for the product (when its config knows it).
    let mut v = vec![dir.join("Vix64AllProductsDyn.dll")];
    v.extend(sdk_vix(&dir));
    v
}

#[cfg(windows)]
fn default_vmrun() -> Vec<PathBuf> {
    let ws = install_dir("VMware Workstation")
        .unwrap_or_else(|| program_files_x86("VMware Workstation"));
    vec![ws.join("vmrun.exe")]
}

#[cfg(target_os = "macos")]
fn default_vix() -> Vec<PathBuf> {
    let _ = sdk_vix; // Windows layout only
    vec![PathBuf::from(
        "/Applications/VMware Fusion.app/Contents/Public/libvixAllProducts.dylib",
    )]
}

#[cfg(target_os = "macos")]
fn default_vmrun() -> Vec<PathBuf> {
    vec![PathBuf::from(
        "/Applications/VMware Fusion.app/Contents/Library/vmrun",
    )]
}

#[cfg(not(any(windows, target_os = "macos")))]
fn default_vix() -> Vec<PathBuf> {
    let _ = sdk_vix; // Windows layout only
    [
        "/usr/lib/vmware-vix/libvixAllProducts.so",
        "/usr/lib/libvixAllProducts.so",
    ]
    .map(PathBuf::from)
    .into()
}

#[cfg(not(any(windows, target_os = "macos")))]
fn default_vmrun() -> Vec<PathBuf> {
    vec![PathBuf::from("/usr/bin/vmrun")]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_users() {
        let c = Config::parse(
            "product = \"player\"\nbackend = \"vmrun\"\nuser = \"me\"\ndrives = \"CD\"\n[users]\n\"Win 11\" = \"admin\"\n",
        )
        .unwrap();
        assert_eq!((c.product, c.backend), (Product::Player, Choice::Vmrun));
        assert_eq!(c.user_for("Win 11"), Some("admin"));
        assert_eq!(c.user_for("other"), Some("me"));
        assert_eq!(c.drives.as_deref(), Some("CD"));
        assert_eq!(Config::default().user_for("x"), None);
        assert_eq!(Config::default().backend, Choice::Auto);
        assert!(
            Config::parse("nope = 1")
                .unwrap_err()
                .contains("vmware.toml")
        );
        assert!(Config::parse("user = \"a\\nb\"").is_err());
        assert!(Config::parse("[users]\nx = \"a\\u0000\"").is_err());
        assert!(Config::parse("drives = \"C:\"").is_err());
    }

    #[test]
    fn products() {
        assert_eq!(Product::Ws.vmrun_type(), "ws");
        assert_eq!(Product::Player.vmrun_type(), "player");
        assert_eq!(Product::Fusion.vmrun_type(), "fusion");
        assert_eq!(Product::Player.vix_provider(), 4);
        assert_eq!(Product::Fusion.vix_provider(), 3);
        assert_eq!(Product::Ws.vix_provider(), 3);
    }

    #[test]
    fn tool_paths() {
        let d = tempfile::tempdir().unwrap();
        for v in ["Workstation-9.0.0", "Workstation-17.0.0", "other"] {
            std::fs::create_dir_all(d.path().join(v).join("64bit")).unwrap();
        }
        let got = sdk_vix(d.path());
        assert_eq!(got.len(), 2);
        assert!(
            got[0].starts_with(d.path().join("Workstation-17.0.0")),
            "newest first"
        );
        let lib = d.path().join("vix.dll");
        std::fs::write(&lib, b"").unwrap();
        let run = d.path().join("vmrun");
        std::fs::write(&run, b"").unwrap();
        let c = Config {
            vix: Some(lib.clone()),
            vmrun: Some(run.clone()),
            ..Config::default()
        };
        assert_eq!(c.vix_candidates()[0], lib);
        assert_eq!(c.vmrun_path(), run);
        let none = Config {
            vmrun: Some(d.path().join("missing")),
            ..Config::default()
        };
        let p = none.vmrun_path();
        assert!(p == Path::new("vmrun") || p.is_file());
    }

    #[test]
    fn load_reads_the_file() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("vmware.toml");
        assert_eq!(load_from(None).unwrap(), Config::default());
        assert_eq!(
            load_from(Some(&f)).unwrap(),
            Config::default(),
            "missing file"
        );
        std::fs::write(&f, "user = \"u\"").unwrap();
        assert_eq!(load_from(Some(&f)).unwrap().user.as_deref(), Some("u"));
        std::fs::write(&f, "bad =").unwrap();
        assert!(load_from(Some(&f)).is_err());
    }
}

//! Running VMs: `vmrun list`, else the command lines of `vmware-vmx` processes (last argument =
//! the .vmx). Names come from the .vmx `displayName` (made host-safe and unique).
use commander_plugin_abi::glue::{Error, Result, valid_name};
use commander_plugin_abi::{self as abi};
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

/// One running VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vm {
    /// Unique, host-safe name (`vmware://<name>`).
    pub name: String,
    pub vmx: PathBuf,
    /// Windows guest (drive letters at the top) vs. one `/` tree.
    pub windows: bool,
    /// The .vmx names `encryption.keySafe`: an encrypted VM (Workstation encrypts every VM with
    /// a vTPM); opening it needs the VM encryption password. Only the key name is looked at.
    pub encrypted: bool,
}

/// What a finished subprocess said.
#[derive(Debug, Clone, Default)]
pub struct Out {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// Runs `prog args` (never a shell, no window); injected by tests.
pub type Run = dyn Fn(&Path, &[OsString]) -> io::Result<Out> + Send + Sync;

/// The real [`Run`]: stdin closed (a prompt fails instead of hanging).
pub fn run(prog: &Path, args: &[OsString]) -> io::Result<Out> {
    use std::process::{Command, Stdio};
    let mut c = Command::new(prog);
    c.args(args).stdin(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000; // GUI host: no console flash
        c.creation_flags(CREATE_NO_WINDOW);
    }
    let o = c.output()?;
    Ok(Out {
        code: o.status.code(),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    })
}

/// `vmrun list` output: "Total running VMs: N" then one .vmx path per line.
pub fn parse_list(out: &str) -> Vec<PathBuf> {
    out.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("Total running VMs"))
        .map(PathBuf::from)
        .collect()
}

/// The .vmx path at the end of a process command line: a quoted last argument (Windows), else
/// the first ` /...vmx` tail that `exists` (unquoted `ps` lines may hold spaces in the path).
pub fn vmx_from_line(line: &str, exists: &dyn Fn(&Path) -> bool) -> Option<PathBuf> {
    let line = line.trim();
    if let Some(body) = line.strip_suffix('"') {
        let p = &body[body.rfind('"')? + 1..];
        return p.to_ascii_lowercase().ends_with(".vmx").then(|| p.into());
    }
    if !line.to_ascii_lowercase().ends_with(".vmx") {
        return None;
    }
    let starts = line.match_indices(' ').map(|(i, _)| i + 1);
    starts
        .map(|i| Path::new(&line[i..]))
        .find(|p| exists(p))
        .map(Path::to_path_buf)
}

/// `|XX` hex escapes in .vmx values (VMware writes `"` as `|22`).
fn unescape(v: &str) -> String {
    let mut out = Vec::with_capacity(v.len());
    let b = v.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hex = b
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok());
        match (b[i], hex.and_then(|h| u8::from_str_radix(h, 16).ok())) {
            (b'|', Some(c)) => {
                out.push(c);
                i += 3;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Value of `key = "value"` in a .vmx text (keys are case-insensitive).
pub fn vmx_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        k.trim()
            .eq_ignore_ascii_case(key)
            .then(|| unescape(v.trim().trim_matches('"')))
    })
}

/// `key` is set in the .vmx `text` (its value is never read).
pub fn vmx_has(text: &str, key: &str) -> bool {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .any(|(k, _)| k.trim().eq_ignore_ascii_case(key))
}

/// Host-safe form of a display name (`/ \ :` and control chars -> `_`).
fn safe(name: &str) -> String {
    name.trim()
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect()
}

/// VMs from their .vmx paths and texts (`None` = unreadable): sorted, unique names.
pub fn name_vms(found: Vec<(PathBuf, Option<String>)>) -> Vec<Vm> {
    let mut out: Vec<Vm> = Vec::new();
    for (vmx, text) in found {
        let text = text.unwrap_or_default();
        let stem = vmx.file_stem().map(|s| s.to_string_lossy().into_owned());
        let base = [vmx_value(&text, "displayName"), stem]
            .into_iter()
            .flatten()
            .map(|n| safe(&n))
            .find(|n| valid_name(n))
            .unwrap_or_else(|| "VM".into());
        let mut name = base.clone();
        let mut n = 1;
        while out.iter().any(|v| v.name.eq_ignore_ascii_case(&name)) {
            n += 1;
            name = format!("{base} ({n})");
        }
        let os = vmx_value(&text, "guestOS")
            .unwrap_or_default()
            .to_ascii_lowercase();
        out.push(Vm {
            name,
            vmx,
            windows: os.starts_with("win") || os.contains("windows"),
            encrypted: vmx_has(&text, "encryption.keySafe"),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// .vmx paths of running VMs: `vmrun -T <product> list`, else the process scan.
pub fn running_vmx(vmrun: &Path, product: &str, run: &Run) -> Result<Vec<PathBuf>> {
    let args = ["-T", product, "list"].map(OsString::from);
    let why = match run(vmrun, &args) {
        Ok(o) if o.code == Some(0) => return Ok(parse_list(&o.stdout)),
        Ok(o) => format!("{} {}", o.stdout.trim(), o.stderr.trim()),
        Err(e) => e.to_string(),
    };
    match process_scan(run) {
        Ok(v) => Ok(v),
        Err(e) => Err(Error::new(
            abi::IO,
            format!(
                "vmware: cannot list running VMs (vmrun: {}; process scan: {e})",
                why.trim()
            ),
        )),
    }
}

/// .vmx paths from `vmware-vmx` process command lines.
fn process_scan(run: &Run) -> io::Result<Vec<PathBuf>> {
    let exists = |p: &Path| p.is_file();
    #[cfg(windows)]
    let lines = {
        let q = "Get-CimInstance Win32_Process -Filter 'Name like ''vmware-vmx%''' | ForEach-Object CommandLine";
        let args = ["-NoProfile", "-NonInteractive", "-Command", q].map(OsString::from);
        run(Path::new("powershell.exe"), &args)?.stdout
    };
    #[cfg(target_os = "linux")]
    let lines = {
        let _ = run;
        proc_lines()
    };
    #[cfg(not(any(windows, target_os = "linux")))]
    let lines = {
        let args = ["-axww", "-o", "args="].map(OsString::from);
        run(Path::new("ps"), &args)?.stdout
    };
    Ok(lines
        .lines()
        .filter(|l| l.contains("vmware-vmx"))
        .filter_map(|l| vmx_from_line(l, &exists))
        .collect())
}

/// `/proc/*/cmdline` as text lines (args joined by spaces; the .vmx is checked to exist).
#[cfg(target_os = "linux")]
fn proc_lines() -> String {
    let mut out = String::new();
    for e in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        if let Ok(b) = std::fs::read(e.path().join("cmdline")) {
            out.push_str(&String::from_utf8_lossy(&b).replace('\0', " "));
            out.push('\n');
        }
    }
    out
}

/// Running VMs, named. `read` gives a .vmx text (injected by tests).
pub fn running(
    vmrun: &Path,
    product: &str,
    run: &Run,
    read: &dyn Fn(&Path) -> Option<String>,
) -> Result<Vec<Vm>> {
    let vmx = running_vmx(vmrun, product, run)?;
    Ok(name_vms(
        vmx.into_iter()
            .map(|p| {
                let t = read(&p);
                (p, t)
            })
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmrun_list() {
        let out = "Total running VMs: 2\r\nC:\\VMs\\Ubuntu 64-bit\\Ubuntu 64-bit.vmx\r\nC:\\VMs\\T\\VM#1.vmx\r\n\r\n";
        let v = parse_list(out);
        assert_eq!(v.len(), 2);
        assert_eq!(v[1], PathBuf::from("C:\\VMs\\T\\VM#1.vmx"));
        assert!(parse_list("Total running VMs: 0\n").is_empty());
    }

    #[test]
    fn process_lines() {
        let no = |_: &Path| false;
        let win = r#""C:\Program Files (x86)\VMware\VMware Workstation\x64\vmware-vmx.exe" -T querytoken -s vmx.stdio.keep=TRUE -# "product=1;name=VMware Workstation;" -@ "pipe=\\.\pipe\vmx1;" "C:\VMs\My VM\My VM.vmx""#;
        assert_eq!(
            vmx_from_line(win, &no),
            Some(PathBuf::from(r"C:\VMs\My VM\My VM.vmx"))
        );
        assert_eq!(vmx_from_line(r#""x.exe" "C:\a.txt""#, &no), None);
        assert_eq!(vmx_from_line(r#"x.exe "#, &no), None);
        assert_eq!(vmx_from_line(r#"bad""#, &no), None, "unbalanced quote");
        let ps = "/usr/lib/vmware/bin/vmware-vmx -s a=b -# product=1;name=VMware Workstation; /home/u/my vms/a.vmx";
        let yes = |p: &Path| p == Path::new("/home/u/my vms/a.vmx");
        assert_eq!(
            vmx_from_line(ps, &yes),
            Some(PathBuf::from("/home/u/my vms/a.vmx"))
        );
        assert_eq!(vmx_from_line(ps, &no), None, "nothing exists");
    }

    #[test]
    fn vmx_values_and_names() {
        let text = ".encoding = \"UTF-8\"\nDisplayName = \"Win |22Dev|22 / 11\"\nguestOS = \"windows11-64\"\nvtpm.present = \"TRUE\"\nencryption.keySafe = \"vmware:key/list/(pair/(null/...))\"\n";
        assert_eq!(
            vmx_value(text, "displayName").as_deref(),
            Some("Win \"Dev\" / 11")
        );
        assert_eq!(vmx_value(text, "nope"), None);
        assert_eq!(unescape("a|zz|7"), "a|zz|7", "not hex: kept");
        let vms = name_vms(vec![
            (PathBuf::from("/v/b.vmx"), Some(text.into())),
            (
                PathBuf::from("/v/ubuntu.vmx"),
                Some("displayName = \"Ub\"\nguestOS = \"ubuntu-64\"".into()),
            ),
            (
                PathBuf::from("/w/ubuntu.vmx"),
                Some("displayName = \"ub\"".into()),
            ),
            (PathBuf::from("/v/plain.vmx"), None),
            (
                PathBuf::from("/v/..vmx"),
                Some("displayName = \"..\"".into()),
            ),
        ]);
        let names: Vec<_> = vms.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, ["Ub", "VM", "Win \"Dev\" _ 11", "plain", "ub (2)"]);
        assert!(vms[2].windows && !vms[0].windows && !vms[3].windows);
        assert!(vms[2].encrypted && !vms[0].encrypted && !vms[3].encrypted);
        assert!(!vmx_has("encryption.keySafeX = 1", "encryption.keySafe"));
    }

    #[test]
    fn running_prefers_vmrun_then_scans() {
        let ok = |_: &Path, a: &[OsString]| -> io::Result<Out> {
            assert_eq!(a, ["-T", "ws", "list"].map(OsString::from));
            Ok(Out {
                code: Some(0),
                stdout: "Total running VMs: 1\n/v/a.vmx\n".into(),
                ..Out::default()
            })
        };
        let read = |_: &Path| Some("displayName = \"A\"".to_string());
        let vms = running(Path::new("vmrun"), "ws", &ok, &read).unwrap();
        assert_eq!(
            (vms[0].name.as_str(), vms[0].vmx.as_path()),
            ("A", Path::new("/v/a.vmx"))
        );
        // vmrun fails: the process scan (finds nothing real here) answers instead.
        let fail = |p: &Path, _: &[OsString]| -> io::Result<Out> {
            match p == Path::new("vmrun") {
                true => Ok(Out {
                    code: Some(255),
                    stdout: "Error: x".into(),
                    ..Out::default()
                }),
                false => Ok(Out::default()),
            }
        };
        let got = running(Path::new("vmrun"), "ws", &fail, &read);
        assert!(got.is_ok(), "{:?}", got.err().map(|e| e.msg));
        let gone =
            |_: &Path, _: &[OsString]| -> io::Result<Out> { Err(io::Error::other("no exe")) };
        if !cfg!(target_os = "linux") {
            let e = running(Path::new("vmrun"), "ws", &gone, &read).unwrap_err();
            assert!(e.msg.contains("no exe"), "{}", e.msg);
        }
    }

    #[test]
    fn real_runner() {
        let me = std::env::current_exe().unwrap();
        let o = run(&me, &["--list".into()]).unwrap();
        assert_eq!(o.code, Some(0));
        assert!(run(Path::new("/no/such/prog"), &[]).is_err());
    }
}

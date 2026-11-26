//! The user's 7-Zip: locate it, build argv (never a shell), run it, map its failures.
//! Names always follow `--` (so `-x` / `@list` are names, not switches / list files) and
//! `-spd` turns wildcard matching off (`*`, `?` are literal). Passwords go to 7z's stdin
//! prompt, never into argv (visible in process lists).
use commander_plugin_abi::glue::Error;
use commander_plugin_abi::{AUTH, INVALID, IO, NOT_FOUND, UNSUPPORTED};
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::OnceLock;

/// What to run against the archive.
pub enum Op<'a> {
    List,
    /// Extract one item to stdout.
    Read(&'a str),
    /// Test one item (password check).
    Test(&'a str),
    /// Add paths relative to the working dir.
    Add(&'a [&'a str]),
    Delete(&'a [&'a str]),
    /// One (from, to) pair; a dir renames everything below it too.
    Rename(&'a str, &'a str),
}

/// Full argv after the program name. `pw`: a password will be on stdin; writes then ask for
/// one (`-p` alone = prompt) so added items are encrypted too (7z: headers as well).
pub fn argv(op: &Op, archive: &Path, pw: bool, seven: bool) -> Vec<OsString> {
    let (cmd, names): (&str, Vec<&str>) = match op {
        Op::List => ("l", vec![]),
        Op::Read(n) => ("e", vec![n]),
        Op::Test(n) => ("t", vec![n]),
        Op::Add(n) => ("a", n.to_vec()),
        Op::Delete(n) => ("d", n.to_vec()),
        Op::Rename(a, b) => ("rn", vec![a, b]),
    };
    // -ssc: names match case-sensitively (Windows default is not: `a.txt` would also hit
    // `A.txt`, so a read concatenates both and a delete takes both).
    let mut v: Vec<OsString> = vec![cmd.into(), "-bd".into(), "-y".into(), "-ssc".into()];
    if cfg!(windows) {
        v.push("-sccUTF-8".into()); // else names come back in the OEM code page
    }
    match op {
        Op::List => v.push("-slt".into()),
        Op::Read(_) => v.extend(["-so".into(), "-spd".into()]),
        _ => v.push("-spd".into()),
    }
    if pw && matches!(op, Op::Add(_) | Op::Delete(_) | Op::Rename(..)) {
        v.push("-p".into());
        if seven {
            v.push("-mhe=on".into());
        }
    }
    v.push("--".into());
    v.push(archive.into());
    v.extend(names.into_iter().map(OsString::from));
    v
}

/// stdin for a run: the password once per prompt (writes ask twice: enter + verify).
pub fn stdin(pw: Option<&str>) -> Vec<u8> {
    pw.map(|p| format!("{p}\n{p}\n").into_bytes())
        .unwrap_or_default()
}

/// A finished run.
pub struct Done {
    pub code: Option<i32>,
    pub out: Vec<u8>,
    pub err: Vec<u8>,
}

/// Runs 7-Zip (a fake in tests).
pub trait Engine: Send + Sync {
    fn run(&self, args: &[OsString], cwd: Option<&Path>, stdin: &[u8]) -> io::Result<Done>;
    /// stdout as a stream; a failed run surfaces as a read error at the end.
    fn stream(&self, args: &[OsString], stdin: &[u8]) -> io::Result<Box<dyn Read + Send>>;
}

/// Failure of a run -> status + short text. `pw`: a password was supplied.
pub fn failure(d: &Done, pw: bool) -> Error {
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&d.err),
        String::from_utf8_lossy(&d.out)
    );
    let has = |s: &str| text.contains(s);
    let status = if has("Wrong password") || (!pw && has("Enter password")) {
        AUTH
    } else if has("Can not open the file as archive") || has("Unexpected end of archive") {
        INVALID
    } else if has("Not implemented") || has("Unsupported") {
        UNSUPPORTED
    } else if has("cannot find") || has("No such file") {
        NOT_FOUND
    } else {
        IO
    };
    let msg = match status {
        AUTH if pw => "7-Zip: wrong password".to_owned(),
        AUTH => "7-Zip: password required".to_owned(),
        _ => {
            // Last few meaningful lines; 7z never echoes the password.
            let lines: Vec<&str> = text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with("Enter password"))
                .collect();
            let tail = lines[lines.len().saturating_sub(3)..].join(" | ");
            let code = d.code.map_or("killed".into(), |c| c.to_string());
            format!("7-Zip failed ({code}): {}", truncate(&tail, 300))
        }
    };
    Error::new(status, msg)
}

fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// A successful `t` that tested nothing (no name matched): "No files to process" / "Files: 0".
pub fn tested_none(d: &Done) -> bool {
    let out = String::from_utf8_lossy(&d.out);
    out.contains("No files to process") || out.lines().any(|l| l.trim() == "Files: 0")
}

/// 7z exit codes: 0 ok, 1 warning (non-fatal), 2+ error.
pub fn ok(d: &Done, warnings_ok: bool) -> bool {
    d.code == Some(0) || (warnings_ok && d.code == Some(1))
}

/// The user's 7-Zip, found once per process.
pub fn find() -> Option<&'static Path> {
    static EXE: OnceLock<Option<PathBuf>> = OnceLock::new();
    EXE.get_or_init(|| locate(std::env::var_os("COMMANDER_7Z").map(PathBuf::from)))
        .as_deref()
}

/// First existing absolute candidate: `env` override, install locations, PATH.
fn locate(env: Option<PathBuf>) -> Option<PathBuf> {
    env.into_iter()
        .chain(installed())
        .chain(on_path())
        .find(|p| p.is_absolute() && p.is_file())
}

#[cfg(windows)]
fn installed() -> Vec<PathBuf> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    let mut v = Vec::new();
    for hive in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
        if let Ok(k) = RegKey::predef(hive).open_subkey("SOFTWARE\\7-Zip") {
            for val in ["Path64", "Path"] {
                if let Ok(dir) = k.get_value::<String, _>(val) {
                    v.push(Path::new(&dir).join("7z.exe"));
                }
            }
        }
    }
    for var in ["ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(dir) = std::env::var_os(var) {
            v.push(Path::new(&dir).join("7-Zip").join("7z.exe"));
        }
    }
    v
}

#[cfg(not(windows))]
fn installed() -> Vec<PathBuf> {
    Vec::new()
}

/// `7zz` (official) then `7z` (p7zip) in absolute PATH dirs only (a relative entry could
/// pick up a planted binary from the current dir).
fn on_path() -> Vec<PathBuf> {
    let names: &[&str] = match cfg!(windows) {
        true => &["7z.exe", "7zz.exe"],
        false => &["7zz", "7z"],
    };
    let dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    names
        .iter()
        .flat_map(|n| dirs.iter().map(move |d| d.join(n)))
        .filter(|p| p.is_absolute())
        .collect()
}

/// The real 7-Zip process.
pub struct Process(pub PathBuf);

impl Process {
    fn command(&self, args: &[OsString], cwd: Option<&Path>, stdin: &[u8]) -> Command {
        let mut c = Command::new(&self.0);
        c.args(args)
            .stdin(match stdin.is_empty() {
                true => Stdio::null(), // a prompt reads EOF and fails instead of hanging
                false => Stdio::piped(),
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(d) = cwd {
            c.current_dir(d);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000; // GUI host: no console flash
            c.creation_flags(CREATE_NO_WINDOW);
        }
        c
    }

    fn spawn(&self, args: &[OsString], cwd: Option<&Path>, stdin: &[u8]) -> io::Result<Child> {
        let mut child = self.command(args, cwd, stdin).spawn()?;
        if let Some(mut i) = child.stdin.take() {
            // Small (a password line or two): fits the pipe buffer, 7z reads it at its prompt.
            let _ = i.write_all(stdin);
        }
        Ok(child)
    }
}

/// Drains a pipe on a thread (keeps 7z from blocking on a full stderr pipe).
fn drain(mut r: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = r.read_to_end(&mut v);
        v
    })
}

impl Engine for Process {
    fn run(&self, args: &[OsString], cwd: Option<&Path>, stdin: &[u8]) -> io::Result<Done> {
        let o = self.spawn(args, cwd, stdin)?.wait_with_output()?;
        Ok(Done {
            code: o.status.code(),
            out: o.stdout,
            err: o.stderr,
        })
    }

    fn stream(&self, args: &[OsString], stdin: &[u8]) -> io::Result<Box<dyn Read + Send>> {
        let mut child = self.spawn(args, None, stdin)?;
        let out = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("no stdout"))?;
        let err = child.stderr.take().map(drain);
        Ok(Box::new(Stream {
            child,
            out,
            err,
            pw: !stdin.is_empty(),
        }))
    }
}

/// stdout of a running `e -so`; killed when dropped early.
struct Stream {
    child: Child,
    out: ChildStdout,
    err: Option<std::thread::JoinHandle<Vec<u8>>>,
    pw: bool,
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.out.read(buf)?;
        if n > 0 || buf.is_empty() {
            return Ok(n);
        }
        let Some(err) = self.err.take() else {
            return Ok(0); // already checked
        };
        let code = self.child.wait()?.code();
        let d = Done {
            code,
            out: Vec::new(),
            err: err.join().unwrap_or_default(),
        };
        match ok(&d, true) {
            true => Ok(0),
            false => Err(io::Error::other(failure(&d, self.pw).msg)),
        }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        if self.err.is_some() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[OsString]) -> Vec<String> {
        v.iter().map(|o| o.to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn names_never_become_switches() {
        let a = Path::new("arc.7z");
        for op in [
            Op::Read("-pevil"),
            Op::Test("@list"),
            Op::Add(&["-r", "@x", "*"]),
            Op::Delete(&["-sdel"]),
            Op::Rename("-a", "-b"),
        ] {
            let v = s(&argv(&op, a, false, true));
            let dd = v.iter().position(|x| x == "--").unwrap();
            assert_eq!(v[dd + 1], "arc.7z");
            // Every name sits after `--`; before it only our own switches.
            assert!(v[1..dd].iter().all(|x| x.starts_with('-')), "{v:?}");
            assert!(
                !v[..dd]
                    .iter()
                    .any(|x| x.contains("evil") || x == "-r" || x == "-sdel")
            );
            assert!(v.contains(&"-spd".to_owned()), "wildcards off: {v:?}");
            assert!(
                !v[..dd].iter().any(|x| x.starts_with("-p") && x.len() > 2),
                "{v:?}"
            );
        }
        let l = s(&argv(&Op::List, a, true, true));
        assert_eq!(l[0], "l");
        assert!(l.contains(&"-slt".into()) && !l.contains(&"-p".into()));
        let w = s(&argv(&Op::Add(&["f"]), a, true, true));
        assert!(w.contains(&"-p".into()) && w.contains(&"-mhe=on".into()));
        let z = s(&argv(&Op::Delete(&["f"]), Path::new("a.zip"), true, false));
        assert!(z.contains(&"-p".into()) && !z.contains(&"-mhe=on".into()));
        assert_eq!(
            s(&argv(&Op::Rename("x", "y"), a, false, true))
                .last()
                .unwrap(),
            "y"
        );
        assert!(s(&argv(&Op::Read("x"), a, false, true)).contains(&"-so".into()));
        assert_eq!(stdin(Some("pw")), b"pw\npw\n");
        assert!(stdin(None).is_empty());
    }

    fn done(code: i32, err: &str) -> Done {
        Done {
            code: Some(code),
            out: b"Enter password (will not be echoed):".to_vec(),
            err: err.as_bytes().to_vec(),
        }
    }

    #[test]
    fn failures_map_to_status() {
        assert_eq!(failure(&done(255, "Break signaled"), false).status, AUTH);
        assert_eq!(failure(&done(255, "Break signaled"), true).status, IO);
        let wrong = failure(&done(2, "ERROR: Wrong password : a.txt"), true);
        assert_eq!(
            (wrong.status, wrong.msg.as_str()),
            (AUTH, "7-Zip: wrong password")
        );
        let cases = [
            ("Can not open the file as archive", INVALID),
            ("E_NOTIMPL Not implemented", UNSUPPORTED),
            ("The system cannot find the file specified.", NOT_FOUND),
            ("disk full", IO),
        ];
        for (e, st) in cases {
            assert_eq!(failure(&done(2, e), true).status, st, "{e}");
        }
        let long = failure(&done(2, &"x".repeat(1000)), true);
        assert!(
            long.msg.len() < 340 && long.msg.contains("(2)"),
            "{}",
            long.msg
        );
        let killed = Done {
            code: None,
            out: vec![],
            err: vec![],
        };
        assert!(failure(&killed, false).msg.contains("killed"));
        assert!(ok(&done(1, ""), true) && !ok(&done(1, ""), false) && ok(&done(0, ""), false));
    }

    #[test]
    fn path_candidates_are_absolute() {
        assert!(on_path().iter().all(|p| p.is_absolute()));
        let _ = installed();
        let t = tempfile::tempdir().unwrap();
        let exe = t.path().join("my7z");
        std::fs::write(&exe, "").unwrap();
        assert_eq!(locate(Some(exe.clone())), Some(exe), "override wins");
        let rel = locate(Some("my7z".into()));
        assert!(
            rel.is_none_or(|p| p.is_absolute()),
            "relative override ignored"
        );
    }

    #[test]
    fn every_op_is_case_sensitive() {
        for op in [
            Op::List,
            Op::Read("a"),
            Op::Test("a"),
            Op::Add(&["a"]),
            Op::Delete(&["a"]),
            Op::Rename("a", "b"),
        ] {
            assert!(s(&argv(&op, Path::new("x"), false, false)).contains(&"-ssc".into()));
        }
    }

    /// A shell standing in for 7z: (program, args running `script`).
    fn shell(script: &str) -> (Process, Vec<OsString>) {
        match cfg!(windows) {
            true => {
                let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
                let cmd = Path::new(&root).join("System32").join("cmd.exe");
                (Process(cmd), vec!["/C".into(), script.into()])
            }
            false => (Process("/bin/sh".into()), vec!["-c".into(), script.into()]),
        }
    }

    #[test]
    fn process_runs_streams_and_reports_failure() {
        let (p, a) = shell("echo hello");
        let d = p.run(&a, Some(Path::new(".")), b"").unwrap();
        assert!(ok(&d, false) && String::from_utf8_lossy(&d.out).contains("hello"));
        // stdin reaches the child (7z's password prompt reads it).
        let (p, a) = shell(if cfg!(windows) { "more" } else { "cat" });
        let d = p.run(&a, None, b"pw-line\n").unwrap();
        assert!(String::from_utf8_lossy(&d.out).contains("pw-line"));
        let mut s = String::new();
        let (p, a) = shell("echo streamed");
        p.stream(&a, b"").unwrap().read_to_string(&mut s).unwrap();
        assert!(s.contains("streamed"));
        // A failed run: data first, then the error at EOF (and only once).
        let (p, a) = shell("echo partial&& exit 2");
        let mut r = p.stream(&a, b"x\n").unwrap();
        let mut buf = Vec::new();
        let e = r.read_to_end(&mut buf).unwrap_err();
        assert!(String::from_utf8_lossy(&buf).contains("partial"));
        assert!(e.to_string().contains("(2)"), "{e}");
        assert_eq!(r.read(&mut [0u8; 4]).unwrap(), 0);
        assert_eq!(r.read(&mut []).unwrap(), 0);
        // Dropped early: the child is killed, not waited for.
        let (p, a) = shell(if cfg!(windows) {
            "ping -n 30 127.0.0.1"
        } else {
            "sleep 30"
        });
        drop(p.stream(&a, b"").unwrap());
        assert!(Process("/no/such/7z".into()).run(&[], None, b"").is_err());
    }

    /// Live: the user's 7-Zip lists, streams and reports a missing password.
    #[test]
    #[ignore = "needs 7-Zip installed (never downloaded by tests)"]
    fn live_process() {
        let exe = find().expect("7-Zip not found");
        let t = tempfile::tempdir().unwrap();
        std::fs::write(t.path().join("-a.txt"), "hello").unwrap();
        let p = Process(exe.to_path_buf());
        let arc = t.path().join("x.7z");
        let d = p
            .run(
                &argv(&Op::Add(&["-a.txt"]), &arc, true, true),
                Some(t.path()),
                &stdin(Some("pw")),
            )
            .unwrap();
        assert!(ok(&d, false), "{}", String::from_utf8_lossy(&d.out));
        let d = p
            .run(&argv(&Op::List, &arc, false, true), None, b"")
            .unwrap();
        assert!(!ok(&d, true));
        assert_eq!(
            failure(&d, false).status,
            AUTH,
            "header encrypted, no password"
        );
        let mut s = String::new();
        p.stream(
            &argv(&Op::Read("-a.txt"), &arc, true, true),
            &stdin(Some("pw")),
        )
        .unwrap()
        .read_to_string(&mut s)
        .unwrap();
        assert_eq!(s, "hello");
        let mut r = p
            .stream(
                &argv(&Op::Read("-a.txt"), &arc, true, true),
                &stdin(Some("bad")),
            )
            .unwrap();
        assert!(r.read_to_end(&mut Vec::new()).is_err(), "wrong password");
    }
}

//! Spec of version 0.1a, step 3: starting other programs (claim L03.1, 🛡,
//! its runtime part; the static part is in build_spec.rs).
//!
//! Frozen by the owner's approval. The code PR includes it unchanged, in
//! crates/logbook-exec/src/lib.rs:
//!
//!     #[cfg(test)]
//!     #[rustfmt::skip]
//!     #[path = "../../../verify/spec/step3/exec_spec.rs"]
//!     mod spec_step3;
//!
//! logbook-exec is the only part of Logbook that starts programs (F-L03). It
//! knows a fixed list of read-only requests; each becomes one program with
//! fixed arguments, and text from logs never becomes an option.
//!
//! What the code must provide:
//!   - `PROGRAMS`: the program names it may start: journalctl, coredumpctl,
//!     pacman, dpkg, rpm, snap, fwupdmgr, rpm-ostree; in tests also env,
//!     sleep, yes, cat, readlink and ls (for the test requests below);
//!   - `SEARCH_DIRS = ["/usr/bin", "/bin"]`: the only places programs are
//!     looked for (never $PATH); `resolve(name) -> Option<PathBuf>`: the
//!     first regular, executable file of that name there that belongs to root
//!     and can't be changed by group or others, None for a name not in
//!     PROGRAMS;
//!   - `ENV`: the whole environment of every child: LC_ALL=C and
//!     PATH=/usr/bin:/bin, nothing inherited;
//!   - `enum PackageManager { Pacman, Dpkg, Rpm }`;
//!   - `enum Request { JournalExport { after_cursor: Option<String> },
//!     CoredumpList, PackageOwner { manager: PackageManager, path: PathBuf },
//!     SnapChanges, FwupdHistory, RpmOstreeStatus }`, and, only in tests,
//!     `TestEnv` (env), `TestSleep` (sleep 30), `TestFlood` (yes),
//!     `TestStdin` (cat), `TestStderr` (readlink /proc/self/fd/2) and
//!     `TestFds` (ls /proc/self/fd);
//!   - a path for a package lookup is absolute, without "..", NUL, newline
//!     or the wildcard characters * ? [ \ (dpkg reads them as patterns), at
//!     most 4096 bytes; a journal cursor is "x=hex" parts joined by ";", at
//!     most 512 bytes;
//!   - `plan(&Request) -> Result<Plan, ExecError>` with
//!     `Plan { program: &'static str, args: Vec<OsString> }`: checks the
//!     request's text and builds the arguments, without starting anything;
//!   - `run(&Request, Limits) -> Result<Output, ExecError>`: starts the
//!     planned program with ENV only, stdin and stderr on /dev/null (error
//!     output could hold hostile text and has no limit), no other open file
//!     of Logbook's, and stops it (kill, then wait, so no zombie is left)
//!     when it runs longer than `limits.timeout` or writes more than
//!     `limits.max_output` bytes; `Limits::default()` is 30 s and 64 MiB;
//!     `Output { stdout: Vec<u8>, success: bool }`;
//!   - `ExecError::{BadArgument(String), NotFound(&'static str), Timeout,
//!     TooMuchOutput, Io(std::io::Error)}`.
//!
//! Checked by review, not by these tests: that resolve() refuses a program
//! that doesn't belong to root or that others can change (placing such a
//! file in /usr/bin needs root rights, which tests don't have).

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::{plan, resolve, run, ExecError, Limits, PackageManager, Request, ENV, PROGRAMS, SEARCH_DIRS};

fn args(list: &[&str]) -> Vec<OsString> {
    list.iter().map(OsString::from).collect()
}

/// L03.1: each request is one listed program with fixed arguments.
#[test]
fn l03_1_requests_map_to_fixed_programs_and_arguments() {
    let cursor = "s=8f1e2a;i=1a2b;b=5c6d;m=12ab;t=63f0c1;x=9e8d".to_owned();
    let cases: Vec<(Request, &str, Vec<OsString>)> = vec![
        (Request::JournalExport { after_cursor: None }, "journalctl", args(&["--output=export", "--no-pager"])),
        (Request::JournalExport { after_cursor: Some(cursor.clone()) }, "journalctl",
         args(&["--output=export", "--no-pager", &format!("--after-cursor={cursor}")])),
        (Request::CoredumpList, "coredumpctl", args(&["list", "--json=short", "--no-pager"])),
        (Request::PackageOwner { manager: PackageManager::Pacman, path: "/usr/bin/bash".into() }, "pacman",
         args(&["-Qo", "/usr/bin/bash"])),
        (Request::PackageOwner { manager: PackageManager::Dpkg, path: "/usr/bin/bash".into() }, "dpkg",
         args(&["-S", "/usr/bin/bash"])),
        (Request::PackageOwner { manager: PackageManager::Rpm, path: "/usr/bin/bash".into() }, "rpm",
         args(&["-qf", "/usr/bin/bash"])),
        (Request::SnapChanges, "snap", args(&["changes"])),
        (Request::FwupdHistory, "fwupdmgr", args(&["get-history", "--json"])),
        (Request::RpmOstreeStatus, "rpm-ostree", args(&["status", "--json"])),
    ];
    for (request, program, want) in cases {
        let p = plan(&request).expect("a valid request");
        assert_eq!(p.program, program);
        assert_eq!(p.args, want, "{program}");
        assert!(PROGRAMS.contains(&p.program));
    }
    assert_eq!(SEARCH_DIRS, ["/usr/bin", "/bin"]);
    let env: Vec<(&str, &str)> = ENV.to_vec();
    assert_eq!(env, [("LC_ALL", "C"), ("PATH", "/usr/bin:/bin")]);
}

/// L03.1: text from a log never becomes an option or a relative path, and
/// odd text is refused instead of passed on.
#[test]
fn l03_1_log_text_never_becomes_an_option() {
    let bad_paths: Vec<PathBuf> = vec![
        "-rf".into(), "--version".into(), "relative/bin".into(), "".into(), "/usr/../etc/shadow".into(),
        "/usr/bin/with\nnewline".into(), PathBuf::from(OsStr::from_bytes(b"/usr/bin/nul\0byte")),
        "/usr/bin/*".into(), "/usr/bin/ba?h".into(), "/usr/bin/[ab]ash".into(), "/usr/bin/back\\slash".into(),
        PathBuf::from(format!("/{}", "a".repeat(5000))),
    ];
    for path in bad_paths {
        for manager in [PackageManager::Pacman, PackageManager::Dpkg, PackageManager::Rpm] {
            let r = plan(&Request::PackageOwner { manager, path: path.clone() });
            assert!(matches!(r, Err(ExecError::BadArgument(_))), "{path:?} must be refused");
        }
    }
    for bad in ["", "--follow", "s=abc; --since=1", "S=ABC", "s=abc i=1", "s=xyz", "s=abc;", &"s=a".repeat(300)] {
        let r = plan(&Request::JournalExport { after_cursor: Some(bad.to_owned()) });
        assert!(matches!(r, Err(ExecError::BadArgument(_))), "cursor {bad:?} must be refused");
    }
}

/// L03.1: programs are found only in the fixed folders, never through
/// $PATH, and only names on the list are found at all.
#[test]
fn l03_1_programs_are_found_only_in_fixed_folders() {
    let evil = std::env::temp_dir().join(format!("logbook-spec3-path-{}", std::process::id()));
    std::fs::create_dir_all(&evil).unwrap();
    for name in ["journalctl", "env", "cat"] {
        let fake = evil.join(name);
        std::fs::write(&fake, b"#!/bin/sh\necho fake\n").unwrap();
        std::fs::set_permissions(&fake, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    }
    let old_path = std::env::var_os("PATH").unwrap_or_default();
    std::env::set_var("PATH", format!("{}:{}", evil.display(), old_path.to_string_lossy()));
    for name in ["env", "cat"] {
        let found = resolve(name).expect("a test program exists in /usr/bin or /bin");
        assert!(SEARCH_DIRS.iter().any(|d| found.parent() == Some(std::path::Path::new(d))), "{name}: {found:?}");
        let meta = std::fs::metadata(&found).unwrap();
        use std::os::unix::fs::MetadataExt;
        assert!(meta.uid() == 0 && meta.mode() & 0o022 == 0, "{name}: must belong to root, unchangeable by others");
    }
    // run() itself, not only resolve(): the planted env must not be the one started.
    let out = run(&Request::TestEnv, Limits::default()).expect("env runs");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("fake"), "run() started a program from $PATH");
    if let Some(found) = resolve("journalctl") {
        assert!(!found.starts_with(&evil), "journalctl was taken from $PATH");
    }
    for not_listed in ["sh", "bash", "rm", "/bin/sh", "../bin/sh", "curl"] {
        assert_eq!(resolve(not_listed), None, "{not_listed} isn't on the list");
    }
    std::env::set_var("PATH", old_path);
    let _ = std::fs::remove_dir_all(&evil);
}

/// L03.1: a child gets ENV and nothing else from Logbook's environment.
#[test]
fn l03_1_children_get_a_clean_environment() {
    std::env::set_var("LOGBOOK_SPEC_SECRET", "must not reach a child");
    std::env::set_var("LD_PRELOAD", "/nonexistent/logbook-spec.so");
    let out = run(&Request::TestEnv, Limits::default()).expect("env runs");
    std::env::remove_var("LD_PRELOAD");
    let mut lines: Vec<String> = String::from_utf8(out.stdout).unwrap().lines().map(str::to_owned).collect();
    lines.sort();
    assert_eq!(lines, ["LC_ALL=C", "PATH=/usr/bin:/bin"]);
}

/// L03.1: a child reads nothing from Logbook: its input is empty.
#[test]
fn l03_1_children_get_no_input() {
    let started = Instant::now();
    let out = run(&Request::TestStdin, Limits::default()).expect("cat runs");
    assert!(out.success && out.stdout.is_empty());
    assert!(started.elapsed() < Duration::from_secs(5), "cat waited for input");
}

/// L03.1: a child's error output goes nowhere (it could hold hostile text and
/// has no size limit), and it gets no open file of Logbook's but its three
/// standard ones.
#[test]
fn l03_1_children_get_no_error_output_and_no_open_files() {
    let out = run(&Request::TestStderr, Limits::default()).expect("readlink runs");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "/dev/null");
    // An open file of the test process, as Logbook has its store open.
    let _store = std::fs::File::open("/proc/self/status").unwrap();
    let out = run(&Request::TestFds, Limits::default()).expect("ls runs");
    let fds: Vec<String> = String::from_utf8_lossy(&out.stdout).split_whitespace().map(str::to_owned).collect();
    // 0, 1, 2 and ls's own handle of the folder it lists.
    assert!(fds.len() <= 4 && ["0", "1", "2"].iter().all(|f| fds.iter().any(|x| x == f)), "open in the child: {fds:?}");
}

/// L03.1: a hanging child is stopped at the time limit, and none is left.
#[test]
fn l03_1_a_hanging_program_is_stopped() {
    let started = Instant::now();
    let r = run(&Request::TestSleep, Limits { timeout: Duration::from_millis(500), ..Limits::default() });
    assert!(matches!(r, Err(ExecError::Timeout)), "{r:?}");
    assert!(started.elapsed() < Duration::from_secs(5), "the time limit wasn't kept");
    assert_eq!(children_named("sleep"), 0, "the stopped program is still running");
}

/// L03.1: a child that writes without end is stopped at the output limit.
#[test]
fn l03_1_output_is_limited() {
    let started = Instant::now();
    let r = run(&Request::TestFlood, Limits { max_output: 1 << 20, ..Limits::default() });
    assert!(matches!(r, Err(ExecError::TooMuchOutput)), "{r:?}");
    assert!(started.elapsed() < Duration::from_secs(10), "the output limit wasn't kept");
    assert_eq!(children_named("yes"), 0, "the stopped program is still running");
}

/// Children of this process with that name, zombies included (from /proc).
fn children_named(name: &str) -> usize {
    let me = std::process::id().to_string();
    std::fs::read_dir("/proc").unwrap().filter_map(Result::ok).filter(|e| {
        let stat = std::fs::read_to_string(e.path().join("stat")).unwrap_or_default();
        // pid (comm) state ppid …
        let Some((comm, rest)) = stat.split_once(") ") else { return false };
        let fields: Vec<&str> = rest.split(' ').collect();
        // A zombie counts too: a stopped child must also be waited for.
        comm.ends_with(&format!("({name}")) && fields.get(1) == Some(&me.as_str())
    }).count()
}

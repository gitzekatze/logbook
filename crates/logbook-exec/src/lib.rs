//! The only part of Logbook that starts programs, from a fixed list of
//! read-only requests (F-L03).
//!
//! Each [`Request`] becomes one program from [`PROGRAMS`] with fixed
//! arguments ([`plan`]); text from logs (a file path, a journal cursor) is
//! checked first and can never become an option. [`run`] finds the program
//! only in [`SEARCH_DIRS`], never through `$PATH`, starts it with [`ENV`] as
//! its whole environment, nothing to read, its error output thrown away and no
//! open file of Logbook's, and stops it at the time and output limits.
//!
//! Spec: verify/spec/step3/exec_spec.rs (included below).

use std::ffi::OsString;
use std::fmt;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

/// The programs Logbook may start; in tests also the ones the test requests
/// use (env, sleep, yes, cat, readlink, ls).
pub const PROGRAMS: &[&str] = if cfg!(test) {
    &[
        "journalctl",
        "coredumpctl",
        "pacman",
        "dpkg",
        "rpm",
        "snap",
        "fwupdmgr",
        "rpm-ostree",
        "env",
        "sleep",
        "yes",
        "cat",
        "readlink",
        "ls",
    ]
} else {
    &[
        "journalctl",
        "coredumpctl",
        "pacman",
        "dpkg",
        "rpm",
        "snap",
        "fwupdmgr",
        "rpm-ostree",
    ]
};

/// The only folders programs are looked for in, in this order.
pub const SEARCH_DIRS: [&str; 2] = ["/usr/bin", "/bin"];

/// The whole environment of every program Logbook starts: nothing of
/// Logbook's own environment (no LD_PRELOAD, no secrets) reaches it.
pub const ENV: [(&str, &str); 2] = [("LC_ALL", "C"), ("PATH", "/usr/bin:/bin")];

/// The longest file path a package lookup takes, in bytes.
const MAX_PATH: usize = 4096;
/// The longest journal cursor, in bytes.
const MAX_CURSOR: usize = 512;
/// Bytes a path for a package lookup may not contain: NUL and newline, and
/// the wildcard characters dpkg would read as a pattern.
const NOT_IN_PATHS: &[u8] = b"\0\n*?[\\";
/// How often a program that closed its output is checked for its end.
const POLL: Duration = Duration::from_millis(10);

/// The package managers a file's owner can be asked of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Pacman,
    Dpkg,
    Rpm,
}

/// Everything Logbook may ask another program, read-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// The journal in export format, after a cursor if given.
    JournalExport { after_cursor: Option<String> },
    /// The list of saved crashes.
    CoredumpList,
    /// Which package a file belongs to.
    PackageOwner {
        manager: PackageManager,
        path: PathBuf,
    },
    /// Snap's recent changes.
    SnapChanges,
    /// Firmware update history.
    FwupdHistory,
    /// rpm-ostree's deployments.
    RpmOstreeStatus,
    /// Tests: `env`, which prints the environment it got.
    #[cfg(test)]
    TestEnv,
    /// Tests: `sleep 30`, which hangs.
    #[cfg(test)]
    TestSleep,
    /// Tests: `yes`, which writes without end.
    #[cfg(test)]
    TestFlood,
    /// Tests: `cat`, which copies its input.
    #[cfg(test)]
    TestStdin,
    /// Tests: `readlink /proc/self/fd/2`, where its error output goes.
    #[cfg(test)]
    TestStderr,
    /// Tests: `ls /proc/self/fd`, its open files.
    #[cfg(test)]
    TestFds,
}

/// The program a request becomes, and its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub program: &'static str,
    pub args: Vec<OsString>,
}

/// When a program ends or is stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The longest a program may run.
    pub timeout: Duration,
    /// The most bytes a program may write.
    pub max_output: usize,
}

impl Default for Limits {
    /// 30 seconds and 64 MiB.
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_output: 64 << 20,
        }
    }
}

/// What a program wrote, and whether it ended successfully.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub stdout: Vec<u8>,
    pub success: bool,
}

/// Why a request wasn't answered.
#[derive(Debug)]
pub enum ExecError {
    /// Text from a log that can't be passed on safely.
    BadArgument(String),
    /// The program isn't installed in a trusted place.
    NotFound(&'static str),
    /// The program ran longer than the time limit and was stopped.
    Timeout,
    /// The program wrote more than the output limit and was stopped.
    TooMuchOutput,
    /// Starting or reading the program failed.
    Io(std::io::Error),
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadArgument(what) => write!(f, "refused to pass on {what}"),
            Self::NotFound(program) => write!(f, "{program} isn't installed in /usr/bin or /bin"),
            Self::Timeout => f.write_str("the program ran too long and was stopped"),
            Self::TooMuchOutput => f.write_str("the program wrote too much and was stopped"),
            Self::Io(e) => write!(f, "the program couldn't be run: {e}"),
        }
    }
}

impl std::error::Error for ExecError {}

/// A file path from a log that may be passed to a package manager: absolute
/// (so never an option), no "..", no NUL, newline or wildcard, at most
/// 4096 bytes.
fn valid_path(path: &Path) -> bool {
    let bytes = path.as_os_str().as_bytes();
    path.is_absolute()
        && bytes.len() <= MAX_PATH
        && !bytes.iter().any(|b| NOT_IN_PATHS.contains(b))
        && path.components().all(|c| c != Component::ParentDir)
}

/// A journal cursor: "x=hex" parts joined by ";" (a lowercase letter, then
/// lowercase hex digits), at most 512 bytes.
fn valid_cursor(cursor: &str) -> bool {
    cursor.len() <= MAX_CURSOR
        && cursor.split(';').all(|part| match part.split_once('=') {
            Some((key, value)) => {
                key.len() == 1
                    && key.bytes().all(|b| b.is_ascii_lowercase())
                    && !value.is_empty()
                    && value
                        .bytes()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            }
            None => false,
        })
}

fn args(list: &[&str]) -> Vec<OsString> {
    list.iter().map(OsString::from).collect()
}

/// The program and arguments for a request, after checking its text.
/// Nothing is started.
///
/// # Errors
/// [`ExecError::BadArgument`] for a path or cursor that can't be passed on.
pub fn plan(request: &Request) -> Result<Plan, ExecError> {
    let (program, args) = match request {
        Request::JournalExport { after_cursor } => {
            let mut list = args(&["--output=export", "--no-pager"]);
            if let Some(cursor) = after_cursor {
                if !valid_cursor(cursor) {
                    return Err(ExecError::BadArgument(format!(
                        "the journal cursor {cursor:?}"
                    )));
                }
                list.push(format!("--after-cursor={cursor}").into());
            }
            ("journalctl", list)
        }
        Request::CoredumpList => ("coredumpctl", args(&["list", "--json=short", "--no-pager"])),
        Request::PackageOwner { manager, path } => {
            if !valid_path(path) {
                return Err(ExecError::BadArgument(format!("the path {path:?}")));
            }
            let (program, option) = match manager {
                PackageManager::Pacman => ("pacman", "-Qo"),
                PackageManager::Dpkg => ("dpkg", "-S"),
                PackageManager::Rpm => ("rpm", "-qf"),
            };
            (program, vec![option.into(), path.clone().into_os_string()])
        }
        Request::SnapChanges => ("snap", args(&["changes"])),
        Request::FwupdHistory => ("fwupdmgr", args(&["get-history", "--json"])),
        Request::RpmOstreeStatus => ("rpm-ostree", args(&["status", "--json"])),
        #[cfg(test)]
        Request::TestEnv => ("env", Vec::new()),
        #[cfg(test)]
        Request::TestSleep => ("sleep", args(&["30"])),
        #[cfg(test)]
        Request::TestFlood => ("yes", Vec::new()),
        #[cfg(test)]
        Request::TestStdin => ("cat", Vec::new()),
        #[cfg(test)]
        Request::TestStderr => ("readlink", args(&["/proc/self/fd/2"])),
        #[cfg(test)]
        Request::TestFds => ("ls", args(&["/proc/self/fd"])),
    };
    Ok(Plan { program, args })
}

/// A program file that may be started: a regular, executable file that
/// belongs to root and that neither its group nor others can change.
fn trusted_program(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| {
        m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0 && m.mode() & 0o111 != 0
    })
}

/// Where a listed program is: the first trusted file of that name in
/// [`SEARCH_DIRS`]. None for a name not in [`PROGRAMS`] or not installed
/// there. `$PATH` is never read.
#[must_use]
pub fn resolve(name: &str) -> Option<PathBuf> {
    if !PROGRAMS.contains(&name) {
        return None;
    }
    SEARCH_DIRS
        .iter()
        .map(|dir| Path::new(dir).join(name))
        .find(|path| trusted_program(path))
}

/// Ends a program that is stopped early, and waits for it, so none is left
/// behind (not even as a zombie).
fn stop(child: &mut Child) {
    // It may have ended already; either way it is waited for.
    let _ = child.kill();
    let _ = child.wait();
}

/// Answers a request: starts its program and returns what it wrote.
///
/// # Errors
/// [`ExecError::BadArgument`] as in [`plan`]; [`ExecError::NotFound`] when
/// the program isn't installed in a trusted place; [`ExecError::Timeout`] or
/// [`ExecError::TooMuchOutput`] when it was stopped at a limit;
/// [`ExecError::Io`] when it couldn't be started or read.
// The one place in Logbook that starts programs (F-L03); the architecture
// check allows this exception only in logbook-exec.
#[allow(clippy::disallowed_methods)]
pub fn run(request: &Request, limits: Limits) -> Result<Output, ExecError> {
    let plan = plan(request)?;
    let program = resolve(plan.program).ok_or(ExecError::NotFound(plan.program))?;
    let deadline = Instant::now()
        .checked_add(limits.timeout)
        .ok_or_else(|| ExecError::BadArgument(format!("the time limit {:?}", limits.timeout)))?;
    let mut child = Command::new(program)
        .args(&plan.args)
        .env_clear()
        .envs(ENV)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(ExecError::Io)?;
    let Some(pipe) = child.stdout.take() else {
        stop(&mut child);
        return Err(ExecError::Io(std::io::Error::other("no output pipe")));
    };

    // Read on a thread of its own, so the time limit holds while the program
    // writes nothing. One byte more than the limit is enough to know it was
    // passed.
    let most = u64::try_from(limits.max_output)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut stdout = Vec::new();
        let read = pipe.take(most).read_to_end(&mut stdout).map(|_| stdout);
        // The receiver is gone only when run() already gave up.
        let _ = sender.send(read);
    });
    let stdout = match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(Ok(stdout)) => stdout,
        Ok(Err(e)) => {
            stop(&mut child);
            return Err(ExecError::Io(e));
        }
        Err(RecvTimeoutError::Timeout) => {
            stop(&mut child);
            return Err(ExecError::Timeout);
        }
        Err(RecvTimeoutError::Disconnected) => {
            stop(&mut child);
            return Err(ExecError::Io(std::io::Error::other(
                "the output reader stopped",
            )));
        }
    };
    if stdout.len() > limits.max_output {
        stop(&mut child);
        return Err(ExecError::TooMuchOutput);
    }

    // The output is closed; the program may still be running.
    loop {
        if let Some(status) = child.try_wait().map_err(ExecError::Io)? {
            return Ok(Output {
                stdout,
                success: status.success(),
            });
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            stop(&mut child);
            return Err(ExecError::Timeout);
        }
        std::thread::sleep(left.min(POLL));
    }
}

#[cfg(test)]
#[rustfmt::skip]
#[path = "../../../verify/spec/step3/exec_spec.rs"]
mod spec_step3;

#[cfg(test)]
mod tests {
    use super::*;

    /// L03.1: a path of exactly the longest length passes, one byte more
    /// doesn't.
    #[test]
    fn l03_1_the_path_limit_is_4096_bytes() {
        let at = |len: usize| PathBuf::from(format!("/{}", "a".repeat(len - 1)));
        assert!(valid_path(&at(MAX_PATH)));
        assert!(!valid_path(&at(MAX_PATH + 1)));
        let request = |path| Request::PackageOwner {
            manager: PackageManager::Dpkg,
            path,
        };
        assert!(plan(&request(at(MAX_PATH))).is_ok());
        assert!(matches!(
            plan(&request(at(MAX_PATH + 1))),
            Err(ExecError::BadArgument(_))
        ));
        assert!(valid_path(Path::new("/usr/lib/x86_64-linux-gnu/libc.so.6")));
        assert!(
            valid_path(Path::new("/usr/bin/./bash")),
            "a '.' part is harmless"
        );
    }

    /// L03.1: each rule of a cursor part counts on its own.
    #[test]
    fn l03_1_cursor_parts() {
        for good in ["s=a", "s=0", "s=0123456789abcdef", "s=1;i=2;x=ff"] {
            assert!(valid_cursor(good), "{good:?} is a cursor");
        }
        for bad in [
            "S=abc", "ss=abc", "=abc", "s=", "s=ABC", "s=12g", "s", ";", "s=1;;i=2", "s==1",
        ] {
            assert!(!valid_cursor(bad), "{bad:?} isn't a cursor");
        }
    }

    /// L03.1: a cursor of exactly the longest length passes, one byte more
    /// doesn't.
    #[test]
    fn l03_1_the_cursor_limit_is_512_bytes() {
        let at = |len: usize| format!("s={}", "a".repeat(len - 2));
        assert_eq!(at(MAX_CURSOR).len(), MAX_CURSOR);
        assert!(valid_cursor(&at(MAX_CURSOR)));
        assert!(!valid_cursor(&at(MAX_CURSOR + 1)));
        let request = |cursor| Request::JournalExport {
            after_cursor: Some(cursor),
        };
        assert!(plan(&request(at(MAX_CURSOR))).is_ok());
        assert!(matches!(
            plan(&request(at(MAX_CURSOR + 1))),
            Err(ExecError::BadArgument(_))
        ));
    }

    /// L03.1: only a regular, executable file of root's that nobody else can
    /// change may be started. (A root-owned file that others can change can't
    /// be made without root rights; review checks that case.)
    #[test]
    fn l03_1_only_trusted_program_files() {
        let env = resolve("env").expect("env is installed");
        assert!(trusted_program(&env));
        assert!(
            !trusted_program(Path::new("/usr/bin")),
            "a folder isn't a program"
        );
        assert!(
            !trusted_program(Path::new("/etc/passwd")),
            "a file that can't be executed"
        );
        assert!(!trusted_program(Path::new(
            "/nonexistent/logbook-exec-test"
        )));
        let own = std::env::temp_dir().join(format!("logbook-exec-own-{}", std::process::id()));
        std::fs::write(&own, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&own, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let mine = !trusted_program(&own);
        std::fs::remove_file(&own).unwrap();
        assert!(mine, "a program that doesn't belong to root");
    }

    /// L03.1: output of exactly the limit is kept, one byte more stops the
    /// program. `env` writes "LC_ALL=C\nPATH=/usr/bin:/bin\n".
    #[test]
    fn l03_1_the_output_limit_is_exact() {
        let size = "LC_ALL=C\nPATH=/usr/bin:/bin\n".len();
        let limit = |max_output| Limits {
            max_output,
            ..Limits::default()
        };
        let out = run(&Request::TestEnv, limit(size)).expect("exactly the limit is kept");
        assert_eq!(out.stdout.len(), size);
        assert!(out.success);
        let r = run(&Request::TestEnv, limit(size - 1));
        assert!(matches!(r, Err(ExecError::TooMuchOutput)), "{r:?}");
    }

    /// The limits the spec names: 30 seconds and 64 MiB.
    #[test]
    fn l03_1_default_limits() {
        assert_eq!(
            Limits::default(),
            Limits {
                timeout: Duration::from_secs(30),
                max_output: 64 * 1024 * 1024
            }
        );
    }

    /// A time limit too large to count is refused, not a crash.
    #[test]
    fn l03_1_an_endless_time_limit_is_refused() {
        let r = run(
            &Request::TestEnv,
            Limits {
                timeout: Duration::MAX,
                ..Limits::default()
            },
        );
        assert!(matches!(r, Err(ExecError::BadArgument(_))), "{r:?}");
    }

    /// Every error says what happened.
    #[test]
    fn errors_say_what_happened() {
        let cases = [
            (
                ExecError::BadArgument("the path \"x\"".into()),
                "refused to pass on the path \"x\"",
            ),
            (
                ExecError::NotFound("rpm"),
                "rpm isn't installed in /usr/bin or /bin",
            ),
            (
                ExecError::Timeout,
                "the program ran too long and was stopped",
            ),
            (
                ExecError::TooMuchOutput,
                "the program wrote too much and was stopped",
            ),
            (
                ExecError::Io(std::io::Error::other("broken")),
                "the program couldn't be run: broken",
            ),
        ];
        for (error, text) in cases {
            assert_eq!(error.to_string(), text);
        }
    }
}

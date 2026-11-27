//! Network block and file-access limits that every Logbook program applies to
//! itself as its very first step (F-L02, F-L03).
//!
//! - [`deny_network`] installs a seccomp filter (a small program the kernel
//!   runs for every system call) on every thread of the process: no socket
//!   but a local one ([`Profile::LocalSockets`]) or none at all
//!   ([`Profile::NoSockets`]), no io_uring, and no other architecture or ABI
//!   that could get around the filter. The filter is built as data by
//!   [`network_filter`], so its rules can be checked call by call.
//! - [`restrict_files`] limits which folders the process may read, write and
//!   run programs from, with Landlock (the kernel's file-access limit for a
//!   program's own process).
//!
//! Both are one-way: neither the process nor any program it starts can lift
//! them again (no_new_privs).
//!
//! Spec: verify/spec/step3/ (filter_spec.rs and build_spec.rs below,
//! network_spec.rs and files_spec.rs in tests/).

use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use landlock::{
    path_beneath_rules, Access, AccessFs, BitFlags, LandlockStatus, RestrictSelfAttr, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
};

/// Why a guard could not be applied. Every Logbook program prints it and
/// ends: running without its guard would be protection for show.
#[derive(Debug, PartialEq, Eq)]
pub struct GuardError(String);

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for GuardError {}

/// Which sockets a program may still open after [`deny_network`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Local (AF_UNIX) sockets only: D-Bus, Wayland, the journal. For the
    /// collector, the `logbook` command and the window.
    LocalSockets,
    /// No socket at all. For `logbook-mcp`, which talks only through its
    /// standard input and output.
    NoSockets,
}

/// One instruction of a classic-BPF program, as the kernel's
/// `struct sock_filter` holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterInstruction {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

// Classic-BPF instructions the filter uses.
/// Load a 32-bit word of seccomp_data at offset k.
const LOAD: u16 = 0x20;
/// Jump if the loaded word equals k.
const JUMP_IF_EQUAL: u16 = 0x15;
/// Jump if the loaded word has any bit of k set.
const JUMP_IF_ANY_BIT: u16 = 0x45;
/// Return k as the verdict.
const RETURN: u16 = 0x06;

// Where seccomp_data keeps what the filter reads (little-endian x86_64).
const AT_NUMBER: u32 = 0;
const AT_ARCH: u32 = 4;
/// The lower 32 bits of the first argument: the socket family is an int, so
/// the kernel ignores the upper half, and so does the filter.
const AT_FIRST_ARGUMENT: u32 = 16;

const ARCH_X86_64: u32 = 0xC000_003E;
/// Set in the call number of an x32-ABI call, a way around filters that check
/// numbers only.
const X32_BIT: u32 = 0x4000_0000;
const SYS_SOCKET: u32 = 41;
const SYS_SOCKETPAIR: u32 = 53;
const SYS_IO_URING_SETUP: u32 = 425;
const SYS_IO_URING_ENTER: u32 = 426;
const SYS_IO_URING_REGISTER: u32 = 427;
const AF_UNIX: u32 = 1;

// Verdicts.
const ALLOW: u32 = 0x7FFF_0000;
const KILL_PROCESS: u32 = 0x8000_0000;
/// SECCOMP_RET_ERRNO with EPERM: the call fails as "not permitted".
const REFUSE: u32 = 0x0005_0001;

/// The network filter for x86_64, as data (`deny_network` installs exactly
/// this).
///
/// - Any other architecture, and any x32 call, kills the process.
/// - `socket` and `socketpair` are refused (EPERM) for every family but
///   AF_UNIX with [`Profile::LocalSockets`], for every family with
///   [`Profile::NoSockets`].
/// - The three io_uring calls are refused: io_uring could open sockets
///   without the socket call.
/// - Everything else is allowed.
///
/// A jump goes `jt` (if true) or `jf` (if false) instructions past the next
/// one; the comments name each target.
#[must_use]
pub fn network_filter(profile: Profile) -> Vec<FilterInstruction> {
    let step = |code, jt, jf, k| FilterInstruction { code, jt, jf, k };
    // Instruction 11: a local socket is allowed (to 12) only with LocalSockets.
    let local_socket_jump = match profile {
        Profile::LocalSockets => 0,
        Profile::NoSockets => 1,
    };
    vec![
        step(LOAD, 0, 0, AT_ARCH),                          // 0
        step(JUMP_IF_EQUAL, 0, 12, ARCH_X86_64),            // 1: else to 14, kill
        step(LOAD, 0, 0, AT_NUMBER),                        // 2
        step(JUMP_IF_ANY_BIT, 10, 0, X32_BIT),              // 3: x32 to 14, kill
        step(JUMP_IF_EQUAL, 5, 0, SYS_SOCKET),              // 4: to 10
        step(JUMP_IF_EQUAL, 4, 0, SYS_SOCKETPAIR),          // 5: to 10
        step(JUMP_IF_EQUAL, 6, 0, SYS_IO_URING_SETUP),      // 6: to 13, refuse
        step(JUMP_IF_EQUAL, 5, 0, SYS_IO_URING_ENTER),      // 7: to 13, refuse
        step(JUMP_IF_EQUAL, 4, 0, SYS_IO_URING_REGISTER),   // 8: to 13, refuse
        step(RETURN, 0, 0, ALLOW),                          // 9: any other call
        step(LOAD, 0, 0, AT_FIRST_ARGUMENT),                // 10: the socket family
        step(JUMP_IF_EQUAL, local_socket_jump, 1, AF_UNIX), // 11: else to 13
        step(RETURN, 0, 0, ALLOW),                          // 12
        step(RETURN, 0, 0, REFUSE),                         // 13
        step(RETURN, 0, 0, KILL_PROCESS),                   // 14
    ]
}

/// Set once this process has installed its own network filter.
static NETWORK_BLOCKED: AtomicBool = AtomicBool::new(false);

/// Blocks the network for this process: the first call of every Logbook
/// program (F-L02), whose error ends the program.
///
/// Sets no_new_privs (neither the process nor its children can gain rights or
/// lift the filter), then installs [`network_filter`] on every thread of the
/// process at once (TSYNC). If any part fails, nothing is claimed: the error
/// says why, and [`network_blocked`] stays false. Calling it again is
/// harmless; a second filter can only add limits.
///
/// # Errors
/// When the kernel refuses no_new_privs or the filter, for example because
/// another thread of the process runs under a filter of its own and so can't
/// be given this one.
pub fn deny_network(profile: Profile) -> Result<(), GuardError> {
    let program: seccompiler::BpfProgram = network_filter(profile)
        .into_iter()
        .map(|i| seccompiler::sock_filter {
            code: i.code,
            jt: i.jt,
            jf: i.jf,
            k: i.k,
        })
        .collect();
    seccompiler::apply_filter_all_threads(&program)
        .map_err(|e| GuardError(format!("the network block couldn't be installed: {e}")))?;
    NETWORK_BLOCKED.store(true, Ordering::SeqCst);
    Ok(())
}

/// Whether this process installed its network filter itself, with
/// [`deny_network`]. Merely running under some filter doesn't count: systemd,
/// Flatpak or Docker show "Seccomp: 2" in /proc too. For `status` and
/// `doctor`.
#[must_use]
pub fn network_blocked() -> bool {
    NETWORK_BLOCKED.load(Ordering::SeqCst)
}

/// What a program may do below each folder, everything else being refused.
/// Write includes read; execute includes read (programs and the libraries
/// they load).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileAccess {
    pub read: Vec<PathBuf>,
    pub write: Vec<PathBuf>,
    pub execute: Vec<PathBuf>,
}

/// How far the kernel enforces [`restrict_files`], for `status` and `doctor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileLimit {
    /// Landlock version 3 or newer, every file right of that version limited
    /// (version 3 is the first that also limits truncating files).
    Enforced { abi: u8 },
    /// Landlock versions 1 and 2: some file rights (truncating) stay open.
    Partial { abi: u8 },
    /// No Landlock (kernels before 5.13, or switched off): no file limit.
    NotSupported,
}

/// The first Landlock version that limits every way of changing a file.
const FULL_FILE_LIMITS_FROM: u8 = 3;

/// The newest Landlock version this code limits every file right of. On an
/// older kernel the rights it doesn't have are left out (Landlock's
/// best-effort mode); a newer kernel counts as this version.
const NEWEST_LANDLOCK: ABI = ABI::V10;

/// Limits this process, every thread it starts and every program it runs to
/// `access`, for good: a later call can only narrow the limit further
/// (F-L03). On kernels with Landlock version 8 or newer the limit also
/// covers threads that already run; on older ones it covers the calling
/// thread and what it starts, so programs call it before starting threads.
///
/// The kernel's Landlock version is detected: every file right that version
/// knows is limited, and the result says how far that goes. A version newer
/// than this code knows counts with the rights the code knows.
///
/// # Errors
/// When a folder in `access` doesn't exist or can't be opened (a mistake in
/// the caller's list, which Landlock itself would skip without a word), or
/// the kernel refuses the limit. The process is then not limited by this
/// call.
pub fn restrict_files(access: &FileAccess) -> Result<FileLimit, GuardError> {
    const WHY: &str = "the file-access limit couldn't be applied";
    let fail = |e: landlock::RulesetError| GuardError(format!("{WHY}: {e}"));
    if let Some(missing) = [&access.read, &access.write, &access.execute]
        .into_iter()
        .flatten()
        .find(|path| std::fs::metadata(path).is_err())
    {
        return Err(GuardError(format!(
            "{WHY}: {} can't be opened",
            missing.display()
        )));
    }
    let [read, execute, write] = rights(NEWEST_LANDLOCK);
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(NEWEST_LANDLOCK))
        .map_err(fail)?
        .create()
        .map_err(fail)?
        .add_rules(path_beneath_rules(&access.read, read))
        .map_err(fail)?
        .add_rules(path_beneath_rules(&access.execute, execute))
        .map_err(fail)?
        .add_rules(path_beneath_rules(&access.write, write))
        .map_err(fail)?
        .all_threads(true)
        .map_err(fail)?
        .restrict_self()
        .map_err(fail)?;
    Ok(file_limit(status.ruleset, status.landlock))
}

/// The rights below a read, an execute and a write folder. Running a program
/// is allowed only below an execute folder: Landlock's own "read" set
/// includes it, so reading is spelled out here, and writing gets every
/// right but that one.
fn rights(abi: ABI) -> [BitFlags<AccessFs>; 3] {
    let read = AccessFs::ReadFile | AccessFs::ReadDir;
    let mut write = AccessFs::from_all(abi);
    write.remove(AccessFs::Execute);
    [read, read | AccessFs::Execute, write]
}

/// What the kernel's answer means for [`FileLimit`]: never more than the
/// version whose rights this code limits.
fn file_limit(ruleset: RulesetStatus, landlock: LandlockStatus) -> FileLimit {
    let abi = match landlock {
        LandlockStatus::Available { effective_abi, .. } => {
            version(effective_abi).min(version(NEWEST_LANDLOCK))
        }
        LandlockStatus::NotEnabled | LandlockStatus::NotImplemented => 0,
    };
    if ruleset == RulesetStatus::NotEnforced || abi == 0 {
        FileLimit::NotSupported
    } else if abi < FULL_FILE_LIMITS_FROM {
        FileLimit::Partial { abi }
    } else {
        FileLimit::Enforced { abi }
    }
}

/// The number of a Landlock version, 0 for none. `ABI` may get new versions,
/// so it can't be cast; the number is the first that maps to it.
fn version(abi: ABI) -> u8 {
    (1..=u8::MAX)
        .find(|n| ABI::from(i32::from(*n)) == abi)
        .unwrap_or(0)
}

#[cfg(test)]
#[rustfmt::skip]
#[path = "../../../verify/spec/step3/filter_spec.rs"]
mod spec_step3_filter;

#[cfg(test)]
#[rustfmt::skip]
#[path = "../../../verify/spec/step3/build_spec.rs"]
mod spec_step3_build;

#[cfg(test)]
mod tests {
    use super::*;

    /// The kernel's answer, as Landlock reports it, for every version.
    fn available(abi: ABI) -> LandlockStatus {
        LandlockStatus::Available {
            effective_abi: abi,
            kernel_abi: None,
        }
    }

    /// Versions 3 and newer limit every file right; 1 and 2 leave truncating
    /// open; without Landlock nothing is limited, whatever else is reported.
    #[test]
    fn l03_2_the_file_limit_reports_what_the_kernel_enforces() {
        use RulesetStatus::{FullyEnforced, NotEnforced, PartiallyEnforced};
        let cases = [
            (
                FullyEnforced,
                available(ABI::V1),
                FileLimit::Partial { abi: 1 },
            ),
            (
                PartiallyEnforced,
                available(ABI::V2),
                FileLimit::Partial { abi: 2 },
            ),
            (
                PartiallyEnforced,
                available(ABI::V3),
                FileLimit::Enforced { abi: 3 },
            ),
            (
                PartiallyEnforced,
                available(ABI::V8),
                FileLimit::Enforced { abi: 8 },
            ),
            (
                FullyEnforced,
                available(ABI::V9),
                FileLimit::Enforced { abi: 9 },
            ),
            (
                FullyEnforced,
                available(ABI::V10),
                FileLimit::Enforced { abi: 10 },
            ),
            (NotEnforced, available(ABI::V6), FileLimit::NotSupported),
            (
                NotEnforced,
                LandlockStatus::NotEnabled,
                FileLimit::NotSupported,
            ),
            (
                NotEnforced,
                LandlockStatus::NotImplemented,
                FileLimit::NotSupported,
            ),
            (
                PartiallyEnforced,
                LandlockStatus::NotImplemented,
                FileLimit::NotSupported,
            ),
        ];
        for (ruleset, landlock, want) in cases {
            let case = format!("{ruleset:?}, {landlock:?}");
            assert_eq!(file_limit(ruleset, landlock), want, "{case}");
        }
        // A kernel newer than this code counts with the rights the code knows.
        let newer = LandlockStatus::Available {
            effective_abi: ABI::V10,
            kernel_abi: Some(42),
        };
        assert_eq!(
            file_limit(PartiallyEnforced, newer),
            FileLimit::Enforced { abi: 10 }
        );
    }

    /// L03.2: a read folder allows reading only, an execute folder reading
    /// and running programs, a write folder everything but running programs.
    #[test]
    fn l03_2_only_execute_folders_may_run_programs() {
        use AccessFs::{Execute, MakeReg, ReadDir, ReadFile, RemoveFile, Truncate, WriteFile};
        for abi in [ABI::V1, ABI::V3, NEWEST_LANDLOCK] {
            let [read, execute, write] = rights(abi);
            assert_eq!(read, ReadFile | ReadDir, "{abi:?}");
            assert_eq!(execute, ReadFile | ReadDir | Execute, "{abi:?}");
            assert!(
                !write.contains(Execute),
                "{abi:?}: writing must not allow running"
            );
            for right in [ReadFile, ReadDir, WriteFile, MakeReg, RemoveFile] {
                assert!(
                    write.contains(right),
                    "{abi:?}: write folders need {right:?}"
                );
            }
        }
        assert!(rights(NEWEST_LANDLOCK)[2].contains(Truncate));
        assert_eq!(
            rights(NEWEST_LANDLOCK)[2] | Execute,
            AccessFs::from_all(NEWEST_LANDLOCK),
            "a write folder has every other right"
        );
    }

    /// A thread that runs under a seccomp filter of its own, as a library
    /// could leave one: the network filter can't be put on it, so
    /// deny_network must fail rather than leave that thread open.
    fn with_a_thread_under_its_own_filter(test: impl FnOnce()) {
        let (ready, wait_ready) = std::sync::mpsc::channel();
        let (done, wait_done) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let allow_all = vec![seccompiler::sock_filter {
                code: RETURN,
                jt: 0,
                jf: 0,
                k: ALLOW,
            }];
            seccompiler::apply_filter(&allow_all).expect("a thread-only filter applies");
            ready.send(()).expect("the test waits");
            wait_done.recv().expect("the test ends the thread");
        });
        wait_ready.recv().expect("the thread is ready");
        test();
        done.send(()).expect("the thread waits");
        thread.join().expect("the thread ends");
    }

    /// L02.2, fail-closed: if the filter can't cover every thread, the guard
    /// refuses instead of protecting only some of them, and doesn't claim a
    /// block.
    #[test]
    fn l02_2_deny_network_fails_closed_when_a_thread_cannot_be_covered() {
        with_a_thread_under_its_own_filter(|| {
            assert!(deny_network(Profile::LocalSockets).is_err());
            assert!(deny_network(Profile::NoSockets).is_err());
            assert!(
                !network_blocked(),
                "a failed guard must not count as the block"
            );
        });
    }

    /// The reason reaches the user: each program prints it when it refuses.
    #[test]
    fn the_refusal_says_why() {
        with_a_thread_under_its_own_filter(|| {
            let e = deny_network(Profile::LocalSockets).unwrap_err();
            let text = e.to_string();
            assert!(
                text.starts_with("the network block couldn't be installed: "),
                "{text}"
            );
            assert!(
                text.len() > "the network block couldn't be installed: ".len(),
                "{text}"
            );
        });
        // A folder that doesn't exist, in any of the three lists: refused
        // before anything is limited (Landlock alone would skip it quietly).
        let missing = PathBuf::from("/nonexistent/logbook-guard-test");
        let lists = [
            FileAccess {
                read: vec![missing.clone()],
                ..FileAccess::default()
            },
            FileAccess {
                write: vec![missing.clone()],
                ..FileAccess::default()
            },
            FileAccess {
                execute: vec![missing.clone()],
                ..FileAccess::default()
            },
        ];
        for access in lists {
            let e = restrict_files(&access).unwrap_err();
            assert_eq!(
                e.to_string(),
                "the file-access limit couldn't be applied: \
                 /nonexistent/logbook-guard-test can't be opened"
            );
        }
    }
}

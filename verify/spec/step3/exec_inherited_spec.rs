//! Spec of version 0.1a, step 3, addition: a started program gets no file
//! that Logbook itself inherited open (claim L03.1, 🛡, its runtime part).
//!
//! Frozen by the owner's approval. The code PR includes it unchanged, in
//! crates/logbook-exec/src/lib.rs, next to exec_spec.rs:
//!
//!     #[cfg(test)]
//!     #[rustfmt::skip]
//!     #[path = "../../../verify/spec/step3/exec_inherited_spec.rs"]
//!     mod spec_step3_inherited;
//!
//! Logbook's own files never reach a child: Rust opens every file with
//! close-on-exec. But whoever starts Logbook (a launcher, a terminal, a test
//! runner) may hand it files that are open without that flag, and a child
//! would inherit them. So before it starts a program, run() marks every
//! file of the process from 3 upwards close-on-exec, every time.
//!
//! It does the marking and the start while holding a lock, so that no
//! thread that takes the lock can open a file without close-on-exec in
//! between. Logbook's own Rust code never opens one, but a test can; without
//! the lock the guarantee would depend on timing. Waiting for the lock counts
//! towards the program's time limit.
//!
//! What the code must provide, in addition to exec_spec.rs:
//!   - `SPAWN_LOCK: std::sync::Mutex<()>` in the crate root (it may stay
//!     private to the crate). run() takes it before marking the files and
//!     releases it as soon as the program has started, before waiting for
//!     its output, so starts take turns but runs don't. A poisoned lock (a
//!     thread panicked while holding it) is taken all the same;
//!   - run() marks every open file from 3 upwards close-on-exec under that
//!     lock, on every call, and only then starts the program.
//!
//! The test plants files the way an inheriting parent would leave them:
//! open, without close-on-exec, at a high number (200 or more), so they
//! can't be mistaken for a file the child opens itself (ls's own folder
//! handle takes the lowest free number). It plants them while holding
//! SPAWN_LOCK, so another test's run() can't start a program between the
//! planting and the marking.
//!
//! Checked by review, not by these tests: that the lock is released right
//! after the start (a test would need a long-running child, which the
//! zombie checks of exec_spec.rs would count).
//!
//! Known limits, because closing files in the child itself would need
//! unsafe code, which Logbook forbids:
//!   - a thread that doesn't take the lock (a C library's own thread) could
//!     open a file without close-on-exec between the marking and the start;
//!     the libraries Logbook uses open their files close-on-exec;
//!   - on kernels without close_range's close-on-exec mode (before 5.11),
//!     marking goes through /proc/self/fd, or, without it, through the
//!     numbers below 65536; a file inherited at a higher number would stay
//!     open. Programs that limit their own files (Landlock) keep
//!     /proc/self/fd readable.
//!
//! Dev-dependency: rustix (features fs, std).

use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::{mpsc, PoisonError};
use std::time::Duration;

use rustix::io::{fcntl_dupfd_cloexec, fcntl_getfd, fcntl_setfd, FdFlags};

use crate::{run, Limits, Request, SPAWN_LOCK};

/// A file open without close-on-exec at number 200 or more, planted while
/// no program can start.
fn plant(source: &File) -> OwnedFd {
    let _lock = SPAWN_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let planted = fcntl_dupfd_cloexec(source, 200).unwrap();
    fcntl_setfd(&planted, FdFlags::empty()).unwrap();
    assert!(planted.as_raw_fd() >= 200);
    assert!(!fcntl_getfd(&planted).unwrap().contains(FdFlags::CLOEXEC),
            "the test's planted file must start without close-on-exec");
    planted
}

/// L03.1: a file Logbook inherited open, without close-on-exec, doesn't
/// reach a program it starts, and is marked close-on-exec afterwards; on
/// every call, not only the first.
#[test]
fn l03_1_children_get_no_inherited_file() {
    let source = File::open("/proc/self/status").unwrap();
    for round in 1..=2 {
        let planted = plant(&source);
        let number = planted.as_raw_fd().to_string();
        let out = run(&Request::TestFds, Limits::default()).expect("ls runs");
        let fds: Vec<String> = String::from_utf8_lossy(&out.stdout).split_whitespace().map(str::to_owned).collect();
        assert!(!fds.contains(&number), "round {round}: the inherited file {number} reached the child: {fds:?}");
        // 0, 1, 2 and ls's own handle of the folder it lists, nothing else.
        assert!(fds.len() <= 4, "round {round}: open in the child: {fds:?}");
        assert!(fcntl_getfd(&planted).unwrap().contains(FdFlags::CLOEXEC),
                "round {round}: run() must leave the inherited file marked close-on-exec");
    }
}

/// L03.1: run() starts a program only while it holds SPAWN_LOCK: as long as
/// another thread holds it, nothing starts; once it is free, the run
/// completes.
#[test]
fn l03_1_programs_start_only_under_the_spawn_lock() {
    let held = SPAWN_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let (done, finished) = mpsc::channel();
    let waiting = std::thread::spawn(move || {
        let r = run(&Request::TestStdin, Limits::default());
        done.send(()).unwrap();
        r
    });
    assert!(finished.recv_timeout(Duration::from_millis(300)).is_err(),
            "run() started a program while another thread held SPAWN_LOCK");
    drop(held);
    finished.recv_timeout(Duration::from_secs(10)).expect("run() goes on once the lock is free");
    assert!(waiting.join().unwrap().is_ok_and(|out| out.success));
}

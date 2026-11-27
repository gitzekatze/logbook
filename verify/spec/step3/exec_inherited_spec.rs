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
//! file of the process from 3 upwards close-on-exec, and does that and the
//! start itself while holding a lock, so that no thread can slip a file in
//! between the two.
//!
//! What the code must provide, in addition to exec_spec.rs:
//!   - `SPAWN_LOCK: std::sync::Mutex<()>` in the crate root (it may stay
//!     private to the crate): run() holds it from marking the files until
//!     the program has started;
//!   - run() marks every open file from 3 upwards close-on-exec under that
//!     lock, every time, and only then starts the program.
//!
//! The test plants a file the way an inheriting parent would leave it: a
//! duplicate made with dup(), which clears close-on-exec. It plants it
//! while holding SPAWN_LOCK, so another test's run() can't start a program
//! between the planting and the marking.
//!
//! Dev-dependency: rustix (features fs, std).

use std::os::fd::AsRawFd;

use rustix::io::{dup, fcntl_getfd, FdFlags};

use crate::{run, Limits, Request, SPAWN_LOCK};

/// L03.1: a file Logbook inherited open, without close-on-exec, doesn't
/// reach a program it starts, and is marked close-on-exec afterwards.
#[test]
fn l03_1_children_get_no_inherited_file() {
    let source = std::fs::File::open("/proc/self/status").unwrap();
    let planted = {
        let _lock = SPAWN_LOCK.lock().unwrap();
        let planted = dup(&source).unwrap();
        assert!(!fcntl_getfd(&planted).unwrap().contains(FdFlags::CLOEXEC),
                "the test's planted file must start without close-on-exec");
        planted
    };
    let number = planted.as_raw_fd().to_string();
    let out = run(&Request::TestFds, Limits::default()).expect("ls runs");
    let fds: Vec<String> = String::from_utf8_lossy(&out.stdout).split_whitespace().map(str::to_owned).collect();
    assert!(!fds.contains(&number), "the inherited file {number} reached the child: {fds:?}");
    assert!(fcntl_getfd(&planted).unwrap().contains(FdFlags::CLOEXEC),
            "run() must leave the inherited file marked close-on-exec");
    // 0, 1, 2 and ls's own handle of the folder it lists, nothing else.
    assert!(fds.len() <= 4, "open in the child: {fds:?}");
}

//! Spec of version 0.1a, step 3: file-access limits (claim L03.2, 🛡).
//!
//! Frozen by the owner's approval. The code PR includes it unchanged as an
//! integration test of its own, crates/logbook-guard/tests/files.rs:
//!
//!     #[cfg(test)]
//!     #[rustfmt::skip]
//!     #[path = "../../../verify/spec/step3/files_spec.rs"]
//!     mod spec_step3_files;
//!
//! A test binary of its own: the limit applies to the whole process.
//! Dev-dependency: rustix (feature fs).
//!
//! What logbook-guard must provide (F-L03):
//!   - `FileAccess { read: Vec<PathBuf>, write: Vec<PathBuf>, execute: Vec<PathBuf> }`:
//!     what a program may do below each folder (write includes read; execute
//!     includes read, for programs and the libraries they load);
//!   - `restrict_files(&FileAccess) -> Result<FileLimit, GuardError>`, using
//!     Landlock (the kernel's file-access limit for a program's own process):
//!     everything not allowed is refused, for every thread, for good;
//!   - `FileLimit::{Enforced { abi: u8 }, Partial { abi: u8 }, NotSupported}`:
//!     Enforced when the kernel's Landlock version is 3 or newer (version 3
//!     also limits truncating files) and every right of that version is
//!     limited; Partial on versions 1 and 2; NotSupported without Landlock
//!     (before 5.13), so the program runs and `status` shows what is missing.
//!     A version newer than the code knows counts with the rights the code
//!     knows.
//!
//! The collector applies its own limit (its sources to read, its folders to
//! write, the programs it starts and their libraries to execute, single files
//! such as /dev/null and /etc/machine-id) in step 8, which extends FileAccess
//! for single files; `logbook mcp` (write nowhere) and the terminal command
//! have claims of their own (L03.6, L03.7). This proves the mechanism.

use std::path::{Path, PathBuf};

use logbook_guard::{restrict_files, FileAccess, FileLimit};

fn folder(root: &Path, name: &str) -> PathBuf {
    let p = root.join(name);
    std::fs::create_dir_all(&p).unwrap();
    std::fs::write(p.join("existing.txt"), b"before the limit").unwrap();
    p
}

/// L03.2: after the limit, writing works only below the write folders,
/// reading only below the read and write folders.
#[test]
fn l03_2_writes_outside_the_allowed_folders_fail() {
    let root = std::env::temp_dir().join(format!("logbook-spec3-files-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let own = folder(&root, "own");
    let sources = folder(&root, "sources");
    let elsewhere = folder(&root, "elsewhere");

    let elsewhere_dir = elsewhere.join("empty");
    std::fs::create_dir(&elsewhere_dir).unwrap();
    let limit = restrict_files(&FileAccess {
        read: vec![sources.clone()],
        write: vec![own.clone()],
        execute: vec![],
    })
    .expect("the limit applies");
    assert!(matches!(limit, FileLimit::Enforced { abi } if abi >= 3),
            "this test needs a kernel with Landlock version 3 or newer, got {limit:?}");

    // Allowed.
    std::fs::write(own.join("new.txt"), b"mine").expect("writing in its own folder works");
    std::fs::read(own.join("existing.txt")).expect("reading its own folder works");
    std::fs::read(sources.join("existing.txt")).expect("reading a source works");
    std::fs::create_dir(own.join("sub")).expect("making a folder in its own folder works");
    // Refused.
    let refused = |what: &str, r: std::io::Result<()>| {
        assert_eq!(r.map_err(|e| e.raw_os_error()), Err(Some(13)), "{what} must be refused (EACCES)");
    };
    refused("writing a new file elsewhere", std::fs::write(elsewhere.join("new.txt"), b"x"));
    refused("changing a file elsewhere", std::fs::write(elsewhere.join("existing.txt"), b"x"));
    refused("writing into a source", std::fs::write(sources.join("existing.txt"), b"x"));
    refused("a new file among the sources", std::fs::write(sources.join("new.txt"), b"x"));
    refused("reading elsewhere", std::fs::read(elsewhere.join("existing.txt")).map(drop));
    refused("moving its own file out", std::fs::rename(own.join("new.txt"), elsewhere.join("moved.txt")));
    refused("deleting elsewhere", std::fs::remove_file(elsewhere.join("existing.txt")));
    refused("a folder elsewhere", std::fs::create_dir(elsewhere.join("sub")));
    refused("listing a folder elsewhere", std::fs::read_dir(&elsewhere).map(drop));
    refused("removing a folder elsewhere", std::fs::remove_dir(&elsewhere_dir));
    refused("a link elsewhere", std::os::unix::fs::symlink("/etc/passwd", elsewhere.join("link")));
    refused("a FIFO elsewhere", rustix::fs::mknodat(rustix::fs::CWD, elsewhere.join("fifo"),
        rustix::fs::FileType::Fifo, rustix::fs::Mode::from_raw_mode(0o600), 0).map_err(std::io::Error::from));
    let linked = std::fs::hard_link(elsewhere.join("existing.txt"), own.join("pulled-in.txt"));
    assert!(linked.is_err(), "a file from elsewhere must not be pulled into its own folder by a hard link");
    refused("reading a system file", std::fs::read("/etc/passwd").map(drop));
    // For good: the limit can't be widened again.
    let again = restrict_files(&FileAccess { read: vec![], write: vec![elsewhere.clone()], execute: vec![] });
    assert!(again.is_ok());
    refused("writing elsewhere after a second, wider limit", std::fs::write(elsewhere.join("later.txt"), b"x"));
}

//! Spec of version 0.1a, step 3: what the build itself must show (claims
//! L02.1 and L03.1, 🛡, their static parts).
//!
//! Frozen by the owner's approval. The code PR includes it unchanged, in
//! crates/logbook-guard/src/lib.rs:
//!
//!     #[cfg(test)]
//!     #[rustfmt::skip]
//!     #[path = "../../../verify/spec/step3/build_spec.rs"]
//!     mod spec_step3_build;
//!
//! Second checks next to cargo-deny (deny.toml), clippy's disallowed methods
//! (clippy.toml) and scripts/arch-check.py: they read the repository's files
//! themselves, so a change to one tool's configuration alone doesn't pass.

use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

/// Crates that would give Logbook network code: HTTP clients and servers,
/// TLS, async network runtimes and socket helpers.
const NETWORK_CRATES: &[&str] = &[
    "reqwest", "hyper", "hyper-util", "h2", "h3", "ureq", "curl", "curl-sys", "isahc", "attohttpc", "surf",
    "axum", "actix-web", "warp", "tiny_http", "rustls", "native-tls", "openssl", "openssl-sys", "quinn",
    "tokio", "async-std", "smol", "mio", "socket2", "trust-dns-resolver", "hickory-resolver", "websocket",
    "tungstenite", "tokio-tungstenite", "lettre", "ssh2", "libssh2-sys",
];

/// L02.1: no network crate is anywhere in the build (Cargo.lock), and
/// deny.toml bans at least the network clients, servers and TLS crates.
#[test]
fn l02_1_no_network_crates_in_the_build() {
    let lock = std::fs::read_to_string(repo().join("Cargo.lock")).unwrap();
    let names: Vec<&str> = lock.lines().filter_map(|l| l.strip_prefix("name = \"")?.strip_suffix('"')).collect();
    assert!(names.len() > 10, "Cargo.lock looks empty");
    let found: Vec<&&str> = names.iter().filter(|n| NETWORK_CRATES.contains(n)).collect();
    assert!(found.is_empty(), "network crates in the build: {found:?}");
    let deny = std::fs::read_to_string(repo().join("deny.toml")).unwrap();
    for must in ["reqwest", "hyper", "h2", "ureq", "curl", "rustls", "native-tls", "openssl", "axum", "warp"] {
        assert!(deny.contains(&format!("crate = \"{must}\"")), "deny.toml must ban {must}");
    }
}

/// L03.1: no code outside logbook-exec starts a program: no
/// std::process::Command, no exec or spawn calls, in any crate's sources or
/// tests (the frozen specs included).
#[test]
fn l03_1_only_logbook_exec_starts_programs() {
    let mut offenders = Vec::new();
    let mut todo = vec![repo().join("crates"), repo().join("verify/spec")];
    while let Some(dir) = todo.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                if !p.ends_with("logbook-exec") && !p.ends_with("target") {
                    todo.push(p);
                }
            } else if p.extension().is_some_and(|e| e == "rs") && !p.ends_with("build_spec.rs") && !p.ends_with("exec_spec.rs") {
                let text = std::fs::read_to_string(&p).unwrap();
                for word in ["process::Command", "Command::new", "CommandExt", "posix_spawn", "execve", "execvp",
                             "fork(", "pre_exec"] {
                    if text.contains(word) {
                        offenders.push(format!("{}: {word}", p.display()));
                    }
                }
            }
        }
    }
    assert!(offenders.is_empty(), "programs may be started only by logbook-exec:\n{}", offenders.join("\n"));
}

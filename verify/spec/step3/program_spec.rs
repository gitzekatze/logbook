//! Spec of version 0.1a, step 3: every program blocks the network first
//! (claim L02.2, 🛡).
//!
//! Frozen by the owner's approval. The code PR includes it unchanged in each
//! of the four programs' main.rs (collector, `logbook`, `logbook-mcp`,
//! `logbook-gtk`):
//!
//!     #[cfg(test)]
//!     #[rustfmt::skip]
//!     #[path = "../../../verify/spec/step3/program_spec.rs"]
//!     mod spec_step3;
//!
//! Each program declares its profile and blocks the network as the very first
//! statement of main, ending at once if that fails:
//!
//!     const PROFILE: logbook_guard::Profile = logbook_guard::Profile::LocalSockets;
//!
//!     fn main() -> ExitCode {
//!         if let Err(e) = logbook_guard::deny_network(PROFILE) {
//!             eprintln!("…: {e}");
//!             return ExitCode::FAILURE;
//!         }
//!         …
//!
//! scripts/arch-check.py checks exactly this form (a `let _ =` that throws the
//! error away fails it) and that only `logbook-mcp` has NoSockets. This test
//! doesn't run main (later it runs for good, or opens a window); it checks
//! the declared profile and proves, in the program's own test binary, that the
//! profile blocks what it must.
//!
//! Dev-dependency of each program: rustix (feature net).

use logbook_guard::{deny_network, network_blocked, Profile};
use rustix::io::Errno;
use rustix::net::{socket, AddressFamily, SocketType};

/// L02.2: the program has the right profile, and that profile blocks the
/// network in this process: no internet socket, and for `logbook-mcp` no
/// socket at all.
#[test]
fn l02_2_the_program_blocks_the_network_first() {
    let mcp = env!("CARGO_BIN_NAME") == "logbook-mcp";
    let want = if mcp { Profile::NoSockets } else { Profile::LocalSockets };
    assert_eq!(super::PROFILE, want, "{} has the wrong profile", env!("CARGO_BIN_NAME"));
    deny_network(super::PROFILE).expect("the program's profile applies");
    assert!(network_blocked());
    assert_eq!(socket(AddressFamily::INET, SocketType::STREAM, None).map(drop), Err(Errno::PERM));
    assert_eq!(socket(AddressFamily::INET6, SocketType::DGRAM, None).map(drop), Err(Errno::PERM));
    let local = socket(AddressFamily::UNIX, SocketType::STREAM, None).map(drop);
    if mcp {
        assert_eq!(local, Err(Errno::PERM), "logbook-mcp may open no socket at all");
    } else {
        assert_eq!(local, Ok(()), "local sockets stay allowed");
    }
}

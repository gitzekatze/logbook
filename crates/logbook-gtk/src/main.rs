//! The `logbook-gtk` program. Not built yet: it blocks the network, says so
//! and ends.
//!
//! Every Logbook program blocks the network as its very first step (F-L02).
//! The architecture check (scripts/arch-check.py) fails unless main starts
//! with exactly this call, and unless only `logbook-mcp` has `NoSockets`.

use std::process::ExitCode;

/// Which sockets the program may still open (F-L02). Local sockets only: Wayland, D-Bus and the journal.
const PROFILE: logbook_guard::Profile = logbook_guard::Profile::LocalSockets;

fn main() -> ExitCode {
    if let Err(e) = logbook_guard::deny_network(PROFILE) {
        eprintln!("logbook-gtk: {e}");
        return ExitCode::FAILURE;
    }
    eprintln!("logbook-gtk: not built yet");
    ExitCode::FAILURE
}

#[cfg(test)]
#[rustfmt::skip]
#[path = "../../../verify/spec/step3/program_spec.rs"]
mod spec_step3;

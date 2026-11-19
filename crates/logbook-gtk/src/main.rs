//! The `logbook-gtk` program. Phase 0: it refuses to run.
//!
//! Every Logbook program blocks the network as its very first step (F-L02).
//! The architecture check (scripts/arch-check.py) fails if this call is not
//! the first statement of `main`.

use std::process::ExitCode;

fn main() -> ExitCode {
    if let Err(e) = logbook_guard::deny_network() {
        eprintln!("logbook-gtk: {e}");
        return ExitCode::FAILURE;
    }
    eprintln!("logbook-gtk: not built yet (Phase 0)");
    ExitCode::FAILURE
}

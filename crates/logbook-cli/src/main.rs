//! The `logbook` program. Not built yet: it blocks the network, says so
//! and ends.
//!
//! Every Logbook program blocks the network as its very first step (F-L02).
//! The architecture check (scripts/arch-check.py) fails unless main starts
//! with exactly this call, and unless only `logbook-mcp` has `NoSockets`.

use std::process::ExitCode;

/// Which sockets the program may still open (F-L02). Local sockets only: D-Bus and the journal.
const PROFILE: logbook_guard::Profile = logbook_guard::Profile::LocalSockets;

fn main() -> ExitCode {
    if let Err(e) = logbook_guard::deny_network(PROFILE) {
        eprintln!("logbook: {e}");
        return ExitCode::FAILURE;
    }
    eprintln!("logbook: not built yet");
    ExitCode::FAILURE
}

#[cfg(test)]
#[rustfmt::skip]
#[path = "../../../verify/spec/step3/program_spec.rs"]
mod spec_step3;

#[cfg(test)]
mod tests {
    use std::process::ExitCode;

    /// L02.2: main blocks the network, then, until the program is built,
    /// says so and ends with a failure, never as a success. (ExitCode can't
    /// be compared directly, so its debug form is.)
    #[test]
    fn l02_2_main_blocks_the_network_and_ends_until_built() {
        assert_eq!(
            format!("{:?}", super::main()),
            format!("{:?}", ExitCode::FAILURE)
        );
        assert!(logbook_guard::network_blocked());
    }
}

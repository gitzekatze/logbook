//! The `logbook` program. Phase 0: it refuses to run.
//!
//! Every Logbook program blocks the network as its very first step (F-L02).
//! The architecture check (scripts/arch-check.py) fails if this call is not
//! the first statement of `main`.

use std::process::ExitCode;

fn main() -> ExitCode {
    if let Err(e) = logbook_guard::deny_network() {
        eprintln!("logbook: {e}");
        return ExitCode::FAILURE;
    }
    eprintln!("logbook: not built yet (Phase 0)");
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use std::process::ExitCode;

    /// Without its network block the program refuses to run (fail-closed):
    /// main ends with the failure code. ExitCode can't be compared directly,
    /// so its debug form is.
    #[test]
    fn refuses_to_run_without_the_network_block() {
        assert_eq!(
            format!("{:?}", super::main()),
            format!("{:?}", ExitCode::FAILURE)
        );
    }
}

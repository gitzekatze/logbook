//! Network block and file-access limits that every Logbook program applies to
//! itself as its very first step (F-L02, F-L03).
//!
//! Phase 0: not implemented yet, and therefore **fail-closed**: `deny_network`
//! returns an error, so every Logbook program refuses to run. A stub that
//! pretended to succeed would be protection for show.

use std::fmt;

/// Why a guard could not be applied.
#[derive(Debug, PartialEq, Eq)]
pub struct GuardError(&'static str);

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for GuardError {}

/// Blocks network sockets for this process (seccomp; F-L02).
///
/// Phase 0: always fails, so no Logbook program can run without the block.
pub fn deny_network() -> Result<(), GuardError> {
    Err(GuardError(
        "the network block is not implemented yet, so Logbook refuses to run",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Until the real block exists, the guard must refuse rather than pretend.
    #[test]
    fn deny_network_fails_closed_until_implemented() {
        assert!(deny_network().is_err());
    }

    /// The reason reaches the user: each program prints it when it refuses.
    #[test]
    fn the_refusal_says_why() {
        let e = deny_network().unwrap_err();
        assert_eq!(
            e.to_string(),
            "the network block is not implemented yet, so Logbook refuses to run"
        );
    }
}

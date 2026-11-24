//! The `logbook-mcp` program refuses to run while the network block isn't
//! implemented (fail-closed, F-L02): it ends with an error and says why.

use std::process::Command;

#[test]
fn refuses_to_run_and_says_why() {
    let out = Command::new(env!("CARGO_BIN_EXE_logbook-mcp"))
        .output()
        .expect("the program starts");
    assert!(
        !out.status.success(),
        "logbook-mcp must not succeed without its network block"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("logbook-mcp: the network block is not implemented yet"),
        "unexpected message: {err}"
    );
}

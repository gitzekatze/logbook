//! Spec of version 0.1a, step 3: the network block (claim L02.2, 🛡).
//!
//! Frozen by the owner's approval. The code PR includes it unchanged as an
//! integration test of its own, crates/logbook-guard/tests/network.rs:
//!
//!     #[cfg(test)]
//!     #[rustfmt::skip]
//!     #[path = "../../../verify/spec/step3/network_spec.rs"]
//!     mod spec_step3_network;
//!
//! A test binary of its own, because the block applies to the whole process
//! and can't be lifted. One test function, so the order (before, after) holds.
//! The filter itself, every system call and architecture, is checked as data
//! in filter_spec.rs; this proves the kernel applies it.
//!
//! What logbook-guard must provide:
//!   - `enum Profile { LocalSockets, NoSockets }`: LocalSockets for the
//!     collector, the `logbook` command and the window (D-Bus, Wayland, the
//!     journal); NoSockets for `logbook-mcp`, which talks only through its
//!     standard input and output;
//!   - `deny_network(Profile) -> Result<(), GuardError>`, the first call of
//!     every Logbook program (F-L02), whose error ends the program. It sets
//!     no_new_privs (neither the process nor its children can gain rights or
//!     lift the filter), then installs `network_filter(profile)`
//!     (filter_spec.rs) on every thread of the process (TSYNC);
//!   - `network_blocked() -> bool`: whether this process installed the
//!     filter itself (not merely runs under some filter: systemd, Flatpak or
//!     Docker set "Seccomp: 2" too), for `status` and `doctor`.
//!
//! Not covered, on purpose: a connection the parent process hands over
//! already open. Closing it would need unsafe code, which Logbook forbids; a
//! parent that holds a connection could use it itself, and Logbook writes
//! only to files and sockets it opened.
//!
//! Dev-dependencies: rustix (features net, process), io-uring, seccompiler
//! (only to install a harmless outside filter).

use std::io::Read;
use std::sync::mpsc;

use logbook_guard::{deny_network, network_blocked, Profile};
use rustix::io::Errno;
use rustix::net::{socket, socketpair, AddressFamily, SocketFlags, SocketType};

fn status_field(name: &str) -> String {
    let mut s = String::new();
    std::fs::File::open("/proc/self/status").unwrap().read_to_string(&mut s).unwrap();
    s.lines().find_map(|l| l.strip_prefix(name)).map(|v| v.trim().to_owned()).unwrap_or_default()
}

fn try_socket(family: AddressFamily, kind: SocketType) -> Result<(), Errno> {
    socket(family, kind, None).map(drop)
}

/// L02.2: after deny_network(LocalSockets), the process can open no socket
/// of any family but AF_UNIX, on any thread, through io_uring neither, and
/// knows that it is protected.
#[test]
fn l02_2_the_guard_blocks_the_network_for_the_whole_process() {
    // --- before
    assert!(!network_blocked(), "this process hasn't installed its filter yet");
    // Some other filter, as systemd, Flatpak or Docker would install: it
    // must not count as Logbook's network block.
    let allow_all: seccompiler::BpfProgram = vec![seccompiler::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0x7FFF_0000 }];
    seccompiler::apply_filter(&allow_all).expect("a harmless outside filter applies");
    // On this thread only, so read this thread's status.
    let thread_status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
    assert!(thread_status.lines().any(|l| l.split_whitespace().collect::<Vec<_>>() == ["Seccomp:", "2"]));
    assert!(!network_blocked(), "an outside filter must not count as the network block");
    try_socket(AddressFamily::INET, SocketType::DGRAM).expect("an internet socket works before the guard");
    let io_uring_before = io_uring::IoUring::new(4).map(drop);
    assert!(io_uring_before.is_ok(), "the test needs io_uring to show that the guard blocks it: {io_uring_before:?}");
    // A thread that started before the guard.
    let (go, wait) = mpsc::channel::<()>();
    let early = std::thread::spawn(move || {
        wait.recv().unwrap();
        try_socket(AddressFamily::INET, SocketType::STREAM)
    });

    // --- the guard
    deny_network(Profile::LocalSockets).expect("the guard applies");

    // --- after
    assert!(network_blocked(), "network_blocked() must report the filter");
    assert_eq!(status_field("Seccomp:"), "2", "/proc/self/status must show the filter");
    assert_eq!(status_field("NoNewPrivs:"), "1", "no_new_privs must be set");
    // Every family but AF_UNIX (1), whether or not this kernel knows it: the
    // filter answers first. Among them INET, INET6, PACKET, NETLINK, VSOCK,
    // TIPC, Bluetooth, ALG and XDP.
    for raw in (0u16..=45).filter(|f| *f != 1) {
        let family = AddressFamily::from_raw(raw);
        for kind in [SocketType::STREAM, SocketType::DGRAM, SocketType::RAW] {
            assert_eq!(try_socket(family, kind), Err(Errno::PERM), "family {raw}, {kind:?} must be refused");
        }
        assert_eq!(socketpair(family, SocketType::STREAM, SocketFlags::empty(), None).map(drop), Err(Errno::PERM),
                   "socketpair of family {raw} must be refused");
    }
    try_socket(AddressFamily::UNIX, SocketType::STREAM).expect("local sockets stay allowed (D-Bus, the journal)");
    try_socket(AddressFamily::UNIX, SocketType::DGRAM).expect("local datagram sockets stay allowed");
    socketpair(AddressFamily::UNIX, SocketType::STREAM, SocketFlags::empty(), None).expect("local socket pairs stay allowed");
    let io_uring_after = io_uring::IoUring::new(4).map(drop);
    assert_eq!(io_uring_after.map_err(|e| e.raw_os_error()), Err(Some(1)), "io_uring must be refused with EPERM");
    go.send(()).unwrap();
    assert_eq!(early.join().unwrap(), Err(Errno::PERM), "a thread started before the guard must be blocked too");
    // Applying it again (two parts of a program calling it) is harmless.
    deny_network(Profile::LocalSockets).expect("the guard can be applied twice");
    assert_eq!(try_socket(AddressFamily::INET, SocketType::DGRAM), Err(Errno::PERM));
}

//! Spec of version 0.1a, step 3: the network filter as data (claim L02.2, 🛡).
//!
//! Frozen by the owner's approval. The code PR includes it unchanged, in
//! crates/logbook-guard/src/lib.rs:
//!
//!     #[cfg(test)]
//!     #[rustfmt::skip]
//!     #[path = "../../../verify/spec/step3/filter_spec.rs"]
//!     mod spec_step3_filter;
//!
//! The seccomp filter is a small program in classic BPF that the kernel runs
//! for every system call. Some of its most important rules can't be tried
//! from safe Rust: calls of another architecture (32-bit x86) and of the x32
//! ABI, a known way around filters that check only call numbers. So the
//! filter is built as data, `network_filter(Profile) -> Vec<FilterInstruction>`
//! with `FilterInstruction { code: u16, jt: u8, jf: u8, k: u32 }`, and
//! `deny_network` installs exactly that. This file runs it on an interpreter
//! of its own for every case; network_spec.rs proves the kernel applies it.
//!
//! The filter is for x86_64 (the only architecture Logbook is built for so
//! far; another one gets its own filter and its own cases here). It must:
//!   - kill the process for any architecture but x86_64, and for any call
//!     with the x32 bit (0x4000_0000) set;
//!   - refuse with EPERM: `socket` and `socketpair` for every family but
//!     AF_UNIX (Profile::LocalSockets) or for every family (NoSockets), and
//!     `io_uring_setup`, `io_uring_enter`, `io_uring_register` (io_uring
//!     could open sockets without the socket call);
//!   - allow everything else.

use crate::{network_filter, Profile};

const ARCH_X86_64: u32 = 0xC000_003E;
const ARCH_I386: u32 = 0x4000_0003;
const ARCH_AARCH64: u32 = 0xC000_00B7;
const X32_BIT: u32 = 0x4000_0000;
const ALLOW: u32 = 0x7FFF_0000;
const KILL_PROCESS: u32 = 0x8000_0000;
const EPERM: u32 = 0x0005_0001;
const SOCKET: u32 = 41;
const SOCKETPAIR: u32 = 53;
const IO_URING: [u32; 3] = [425, 426, 427];
const AF_UNIX: u64 = 1;

/// seccomp_data as the kernel lays it out: nr, arch, instruction pointer,
/// six 64-bit arguments, little-endian.
fn data(arch: u32, nr: u32, args: [u64; 6]) -> Vec<u8> {
    let mut d = Vec::with_capacity(64);
    d.extend_from_slice(&nr.to_le_bytes());
    d.extend_from_slice(&arch.to_le_bytes());
    d.extend_from_slice(&0u64.to_le_bytes());
    for a in args {
        d.extend_from_slice(&a.to_le_bytes());
    }
    d
}

/// A classic-BPF interpreter for what seccomp filters use: loads of 32-bit
/// words from seccomp_data, constant jumps, AND, return. Anything else fails
/// the test instead of being guessed at.
fn run(program: &[crate::FilterInstruction], input: &[u8]) -> u32 {
    interpret(program, input).unwrap_or_else(|e| panic!("{e}"))
}

fn interpret(program: &[crate::FilterInstruction], input: &[u8]) -> Result<u32, String> {
    let (mut a, mut pc) = (0u32, 0usize);
    for _ in 0..program.len() + 1 {
        let ins = program.get(pc).ok_or_else(|| format!("the filter jumps out of itself at {pc}"))?;
        let k = ins.k;
        match ins.code {
            0x20 => {
                // BPF_LD | BPF_W | BPF_ABS
                let at = k as usize;
                a = u32::from_le_bytes(input[at..at + 4].try_into().unwrap());
                pc += 1;
            }
            0x54 => {
                a &= k; // BPF_ALU | BPF_AND | BPF_K
                pc += 1;
            }
            0x05 => pc += 1 + k as usize, // BPF_JMP | BPF_JA
            0x15 | 0x25 | 0x35 | 0x45 => {
                let taken = match ins.code {
                    0x15 => a == k,
                    0x25 => a > k,
                    0x35 => a >= k,
                    _ => a & k != 0,
                };
                pc += 1 + if taken { ins.jt } else { ins.jf } as usize;
            }
            0x06 => return Ok(k), // BPF_RET | BPF_K
            other => return Err(format!("instruction {other:#x} at {pc} isn't one this check knows")),
        }
    }
    Err("the filter runs in a loop".into())
}

fn verdict(profile: Profile, arch: u32, nr: u32, arg0: u64) -> u32 {
    run(&network_filter(profile), &data(arch, nr, [arg0, 1, 0, 0, 0, 0]))
}

/// L02.2: other architectures and the x32 ABI are killed, whatever the call.
#[test]
fn l02_2_the_filter_kills_other_architectures_and_x32() {
    for profile in [Profile::LocalSockets, Profile::NoSockets] {
        for arch in [ARCH_I386, ARCH_AARCH64, 0, u32::MAX] {
            for nr in [0, 1, SOCKET, SOCKETPAIR, 102, 359, 425] {
                assert_eq!(verdict(profile, arch, nr, AF_UNIX), KILL_PROCESS, "{profile:?}: arch {arch:#x}, call {nr}");
            }
        }
        for nr in [0, 1, SOCKET, SOCKETPAIR, 425, 512, 0x3FFF_FFFF] {
            assert_eq!(verdict(profile, ARCH_X86_64, nr | X32_BIT, AF_UNIX), KILL_PROCESS, "{profile:?}: x32 call {nr}");
        }
    }
}

/// L02.2: with LocalSockets, sockets of every family but AF_UNIX are refused,
/// io_uring too, everything else allowed.
#[test]
fn l02_2_the_local_sockets_filter() {
    let p = Profile::LocalSockets;
    for family in (0u64..=64).filter(|f| *f != AF_UNIX) {
        assert_eq!(verdict(p, ARCH_X86_64, SOCKET, family), EPERM, "socket family {family}");
        assert_eq!(verdict(p, ARCH_X86_64, SOCKETPAIR, family), EPERM, "socketpair family {family}");
    }
    // The family is an int: the kernel ignores the upper 32 bits, so must the filter.
    assert_eq!(verdict(p, ARCH_X86_64, SOCKET, AF_UNIX), ALLOW);
    assert_eq!(verdict(p, ARCH_X86_64, SOCKET, AF_UNIX | (1 << 32)), ALLOW);
    assert_eq!(verdict(p, ARCH_X86_64, SOCKET, 2 | (1 << 32)), EPERM);
    assert_eq!(verdict(p, ARCH_X86_64, SOCKETPAIR, AF_UNIX), ALLOW);
    for nr in IO_URING {
        assert_eq!(verdict(p, ARCH_X86_64, nr, 0), EPERM, "io_uring call {nr}");
    }
    for nr in [0, 1, 2, 3, 42, 44, 45, 46, 47, 49, 50, 51, 54, 55, 57, 59, 60, 231, 257, 424, 428, 435] {
        assert_eq!(verdict(p, ARCH_X86_64, nr, 2), ALLOW, "call {nr} must stay allowed");
    }
}

/// L02.2: with NoSockets, no socket at all, not even a local one.
#[test]
fn l02_2_the_no_sockets_filter() {
    let p = Profile::NoSockets;
    for family in 0u64..=64 {
        assert_eq!(verdict(p, ARCH_X86_64, SOCKET, family), EPERM, "socket family {family}");
        assert_eq!(verdict(p, ARCH_X86_64, SOCKETPAIR, family), EPERM, "socketpair family {family}");
    }
    for nr in IO_URING {
        assert_eq!(verdict(p, ARCH_X86_64, nr, 0), EPERM);
    }
    for nr in [0, 1, 2, 3, 59, 60, 231, 257] {
        assert_eq!(verdict(p, ARCH_X86_64, nr, 2), ALLOW, "call {nr} must stay allowed");
    }
}

/// The interpreter's own check: it refuses what it doesn't know, so a filter
/// can't pass by using instructions this check would misread.
#[test]
fn the_interpreter_refuses_unknown_instructions() {
    let unknown = [crate::FilterInstruction { code: 0x87, jt: 0, jf: 0, k: 0 }];
    let r = interpret(&unknown, &data(ARCH_X86_64, 0, [0; 6]));
    assert!(r.is_err_and(|e| e.contains("isn't one this check knows")));
    let runaway = [crate::FilterInstruction { code: 0x15, jt: 5, jf: 5, k: 0 }];
    assert!(interpret(&runaway, &data(ARCH_X86_64, 0, [0; 6])).is_err());
}

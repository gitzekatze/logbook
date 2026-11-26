#!/bin/sh
# The only way to run Logbook's tests on a desktop: inside a container.
# Logbook's tests install seccomp filters and Landlock limits on their own
# process, start programs and use a lot of memory; a mistake in them must not
# reach the desktop session.
#
#   scripts/test-in-container.sh WORKTREE [COMMAND ...]
#
# COMMAND runs in a copy of WORKTREE; without one it is
# `cargo test --workspace --locked`. Examples:
#   scripts/test-in-container.sh . make check
#   scripts/test-in-container.sh . cargo test -p logbook-guard
#   scripts/test-in-container.sh . python3 scripts/breaks-check.py --only L02.2
#
# Isolation:
#   - rootless podman: its own processes (it can't see or signal the
#     desktop's), an ordinary user inside;
#   - the worktree is mounted read-only and copied in, so nothing a test
#     writes (saved proptest cases included) reaches it;
#   - a memory cap with no swap (LOGBOOK_TEST_MEMORY, default 10G) through a
#     systemd scope, so a runaway test can't starve the desktop;
#   - no network while COMMAND runs: the dependencies are fetched first, in a
#     separate step that runs nothing but `cargo fetch --locked`.
# seccomp=unconfined: the tests install their own seccomp filter and need
# io_uring and Landlock, which podman's default filter refuses; the
# container's other limits stay.
#
# The image is built once from scripts/container/Containerfile (the same
# Ubuntu as CI); a missing image is reported, not built behind your back.
# Downloaded crates and build output are kept between runs in
# LOGBOOK_TEST_CACHE (default ~/.cache/logbook-tests), one build folder per
# worktree name.
set -eu
[ $# -ge 1 ] || { echo "usage: $0 WORKTREE [COMMAND ...]" >&2; exit 2; }
wt=$(realpath -- "$1")
shift
[ -f "$wt/Cargo.toml" ] || { echo "not a Logbook worktree: $wt" >&2; exit 2; }
[ $# -ge 1 ] || set -- cargo test --workspace --locked

image=${LOGBOOK_TEST_IMAGE:-localhost/logbook-tests:1}
memory=${LOGBOOK_TEST_MEMORY:-10G}
cache=${LOGBOOK_TEST_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/logbook-tests}
jobs=${LOGBOOK_TEST_JOBS:-8}
name=$(basename -- "$wt")

if ! podman image exists "$image"; then
    echo "The test image $image is missing. Build it once (a few minutes, about 2 GB):" >&2
    echo "  podman build -t $image $(dirname -- "$(realpath -- "$0")")/container" >&2
    exit 2
fi
mkdir -p "$cache/registry" "$cache/target-$name"

# in_container NETWORK SCRIPT [ARG ...]: runs SCRIPT with sh in a fresh copy
# of the worktree (/tmp/w), with ARG as its "$@".
in_container() {
    network=$1
    script=$2
    shift 2
    systemd-run --user --scope -q -p MemoryMax="$memory" -p MemorySwapMax=0 \
      podman run --rm --init --userns=keep-id --network="$network" \
        --security-opt seccomp=unconfined --security-opt label=disable \
        -e CARGO_TARGET_DIR=/cache/target -e CARGO_BUILD_JOBS="$jobs" -e TMPDIR=/tmp \
        -v "$wt:/src:ro" \
        -v "$cache/registry:/home/tester/.cargo/registry" \
        -v "$cache/target-$name:/cache/target" \
        "$image" sh -c '
          mkdir /tmp/w && tar -C /src --exclude=./target --exclude=./.git -cf - . | tar -C /tmp/w -xf - &&
          cd /tmp/w && '"$script" sh "$@"
}

# 1. The dependencies, with network, running nothing but cargo fetch.
in_container pasta 'exec cargo fetch --locked -q'
# 2. The command, without network.
in_container none 'CARGO_NET_OFFLINE=true exec "$@"' "$@"

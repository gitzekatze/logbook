#!/bin/sh
# Who checks the checker? Breaks each rule of scripts/arch-check.py on purpose,
# in a scratch copy, and expects the check to fail every time. The untouched
# copy must pass. Exit 1 if any break goes unnoticed.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT
failed=0

fresh() {
    rm -rf "$SCRATCH/ws"
    mkdir -p "$SCRATCH/ws"
    (cd "$ROOT" && tar --exclude=./target --exclude=./.git -cf - .) | (cd "$SCRATCH/ws" && tar -xf -)
}

check() { python3 "$ROOT/scripts/arch-check.py" "$SCRATCH/ws" >/dev/null 2>&1; }

expect_fail() { # description; the break was applied to $SCRATCH/ws before
    if check; then
        echo "NOT CAUGHT: $1"
        failed=1
    else
        echo "caught:     $1"
    fi
}

adddep() { # crate, dependency
    sed -i "s/^\[dependencies\]$/[dependencies]\n$2.workspace = true/" "$SCRATCH/ws/crates/$1/Cargo.toml"
}

fresh
if check; then echo "passes:     the untouched workspace"; else echo "FAILS:      the untouched workspace"; failed=1; fi

fresh; adddep logbook-mcp logbook-store-write
expect_fail "the AI interface depends on the store writer"

fresh; adddep logbook-render logbook-store-write; adddep logbook-mcp logbook-render
expect_fail "the AI interface reaches the store writer through another crate"

fresh; adddep logbook-gtk logbook-exec
expect_fail "the window depends on the crate that starts programs"

fresh; adddep logbook-query logbook-undo
expect_fail "the shared read functions depend on undo"

fresh; sed -i 's/^workspace = true$/workspace = false/' "$SCRATCH/ws/crates/logbook-collector/Cargo.toml"
expect_fail "a crate leaves the workspace lints"

fresh; printf '\n[lints.rust]\nunsafe_code = "allow"\n' >> "$SCRATCH/ws/crates/logbook-derive/Cargo.toml"
expect_fail "a crate adds its own lint settings"

fresh; printf '#[allow(clippy::disallowed_methods)]\nfn x() {}\n' >> "$SCRATCH/ws/crates/logbook-readers/src/lib.rs"
expect_fail "a reader allows starting programs itself"

fresh; printf '#[expect(clippy::disallowed_types)]\nfn x() {}\n' >> "$SCRATCH/ws/crates/logbook-exec/src/lib.rs"
expect_fail "a crate allows std::net"

fresh; sed -i 's/^    if let Err(e) = logbook_guard::deny_network() {$/    eprintln!("start");\n&/' "$SCRATCH/ws/crates/logbook-mcp/src/main.rs"
expect_fail "the AI interface does something before blocking the network"

fresh; sed -i 's/logbook_guard::deny_network()/logbook_guard::deny_nothing()/' "$SCRATCH/ws/crates/logbook-gtk/src/main.rs"
expect_fail "the window doesn't call the network block"

fresh; mkdir -p "$SCRATCH/ws/crates/logbook-extra/src"
printf '[package]\nname = "logbook-extra"\nversion = "0.0.0"\nedition = "2021"\n' > "$SCRATCH/ws/crates/logbook-extra/Cargo.toml"
expect_fail "a crate folder outside the workspace, unseen by every check"

fresh; printf 'fn main() {}\n' > "$SCRATCH/ws/crates/logbook-query/src/main.rs"
expect_fail "an extra program without the network block"

exit $failed

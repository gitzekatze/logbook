#!/bin/sh
# Gate item 4 ("a test is lost") for a pull request: runs the tests of the
# base and of this change and compares them with the BASE commit's copy of
# the gate (--tests-only). CI runs it on every pull request (ci.yml, "No test
# lost"); locally: make lost BASE=main.
#
#   scripts/tests-lost.sh BASE
#
# The change's own tests and code run here, so this lives in CI, not in the
# "Needs your approval" check. CI's file can't change without that check
# flagging it, so a quiet gate means this step ran as written.
set -eu
[ $# -eq 1 ] || { echo "usage: scripts/tests-lost.sh BASE"; exit 2; }
ROOT=$(git rev-parse --show-toplevel)
BASE=$(git -C "$ROOT" merge-base "$1" HEAD)
SCRATCH=$(mktemp -d)
cleanup() { git -C "$ROOT" worktree remove --force "$SCRATCH/base" 2>/dev/null || true; rm -rf "$SCRATCH"; }
trap cleanup EXIT

git -C "$ROOT" worktree add -q --detach "$SCRATCH/base" "$BASE"
(cd "$SCRATCH/base" && CARGO_TARGET_DIR="$ROOT/target/lost-base" \
    cargo test --workspace --locked --no-fail-fast) > "$SCRATCH/base.txt" 2>&1 || true
(cd "$ROOT" && cargo test --workspace --locked --no-fail-fast) > "$SCRATCH/head.txt" 2>&1 || true

if git -C "$ROOT" show "$BASE:scripts/gate.py" > "$SCRATCH/gate.py" 2>/dev/null \
    && grep -q -- '--tests-only' "$SCRATCH/gate.py"; then
    GATE="$SCRATCH/gate.py"
else
    echo "The base's gate can't compare test runs yet, so this change's copy is used."
    echo "(This change touches scripts/, so \"Needs your approval\" flags it anyway.)"
    GATE="$ROOT/scripts/gate.py"
fi
python3 "$GATE" --repo "$ROOT" "$BASE" HEAD --tests-only \
    --base-tests "$SCRATCH/base.txt" --head-tests "$SCRATCH/head.txt"

#!/bin/sh
# Runs the gate as the BASE commit's copy, never the change's own copy, so a
# change can't switch off its own gate (SAM audit P2). On GitHub the same is
# done by a pull_request_target job that checks out only the base branch.
#
#   scripts/gate-run.sh BASE HEAD [gate.py options …]
set -eu
[ $# -ge 2 ] || { echo "usage: scripts/gate-run.sh BASE HEAD [options]"; exit 2; }
REPO=$(git rev-parse --show-toplevel)
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
if ! git -C "$REPO" show "$1:scripts/gate.py" > "$TMP" 2>/dev/null; then
    echo "## This change needs your approval"
    echo "- the base commit has no gate yet, so nothing can judge this change for you"
    exit 1
fi
python3 "$TMP" --repo "$REPO" "$@"

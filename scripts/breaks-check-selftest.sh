#!/bin/sh
# Who checks the checker? Runs scripts/breaks-check.py on the practice crate in
# verify/selftest/practice, whose breaks are made to give every verdict, and
# compares the verdicts exactly. Then: only caught breaks must pass, and an
# empty break list outside phase 0 must fail. Exit 1 on any difference.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PRACTICE="$ROOT/verify/selftest/practice"
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT
failed=0

python3 "$ROOT/scripts/breaks-check.py" --root "$PRACTICE" > "$SCRATCH/out" 2>&1 && {
    echo "WRONG:      the practice list passed although it holds uncaught breaks"; failed=1; } || true

expect() { # patch, verdict, meaning
    if grep -q "^VERDICT $1 $2 " "$SCRATCH/out"; then
        echo "right:      $3 -> $2"
    else
        echo "WRONG:      $3: expected $2, got: $(grep "^VERDICT $1 " "$SCRATCH/out" || echo nothing)"
        failed=1
    fi
}
expect A90.1-parent-folder-allowed.patch caught       "a break the claim's test notices"
expect A90.1-absolute-allowed.patch      caught       "a second break of the same claim"
expect A90.1-unsafe-code.patch           caught       "unsafe code, refused by the lint"
expect A90.2-cut-to-4.patch              not-caught   "a break a weak test misses"
expect A90.2-wrong-claim.patch           other-claim  "a break caught only by another claim's test"
expect A90.1-does-not-compile.patch      broken-build "a break that doesn't compile proves nothing"
expect A90.1-stale.patch                 stale        "a patch the code has moved away from"
expect A90.1-header-mismatch.patch       invalid      "file name and header disagree"
n=$(grep -c '^VERDICT ' "$SCRATCH/out")
if [ "$n" -ne 8 ]; then echo "WRONG:      expected 8 verdicts, got $n"; failed=1; fi

# Only caught breaks: the list must pass.
cp -r "$PRACTICE" "$SCRATCH/good"
rm -rf "$SCRATCH/good/target"
find "$SCRATCH/good/verify/breaks" -name '*.patch' \
    ! -name 'A90.1-parent-folder-allowed.patch' ! -name 'A90.1-unsafe-code.patch' -delete
if python3 "$ROOT/scripts/breaks-check.py" --root "$SCRATCH/good" >/dev/null 2>&1; then
    echo "right:      only caught breaks -> the list passes"
else
    echo "WRONG:      only caught breaks, but the list failed"; failed=1
fi

# No breaks outside phase 0: a check with nothing to check fails.
rm -f "$SCRATCH/good/verify/breaks/"*.patch
if python3 "$ROOT/scripts/breaks-check.py" --root "$SCRATCH/good" >/dev/null 2>&1; then
    echo "WRONG:      an empty break list passed outside phase 0"; failed=1
else
    echo "right:      an empty break list outside phase 0 -> fails"
fi

exit $failed

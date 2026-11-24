#!/bin/sh
# Who checks the checker? Feeds scripts/claims-check.py a small registry and
# made-up test results, each with one deliberate flaw, and expects the check to
# fail every time. The flawless set must pass. Exit 1 if any flaw goes unnoticed.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT
failed=0
REG="$SCRATCH/verify/claims.toml"
RES="$SCRATCH/results.txt"

fresh() {
    rm -rf "$SCRATCH/verify"
    mkdir -p "$SCRATCH/verify/breaks"
    cat > "$REG" <<'EOF'
[registry]
milestones = ["0.1a", "0.1b"]
current = "0.1a"
proof_kinds = ["CONF", "UNIT"]

[functions."F-A01"]
name = "Collector service"
version = "0.1"

[functions."F-A02"]
name = "Resume"
version = "0.1"

[functions."F-G05"]
name = "Viewing a report"
version = "0.1"
proven_by = ["F-A01"]

[functions.global]
name = "Global invariants"
version = "0.1"

[[claim]]
id = "A01.1"
function = "F-A01"
due = "0.1a"
security = false
proofs = ["UNIT"]
text = "starts after login"

[[claim]]
id = "A01.2"
function = "F-A01"
due = "0.1a"
security = true
proofs = ["UNIT"]
text = "a second instance ends at once"

[[claim]]
id = "A02.1"
function = "F-A02"
due = "0.1b"
security = false
proofs = ["CONF"]
text = "not due yet"

[[claim]]
id = "G1"
function = "global"
due = "0.1a"
security = false
proofs = ["CONF"]
text = "determinism"
EOF
    : > "$SCRATCH/verify/breaks/A01.2-two-collectors.patch"
    cat > "$RES" <<'EOF'
running 3 tests
test tests::a01_1_starts_after_login ... ok
test tests::a01_2_second_instance_ends ... ok
test g1_same_input_same_events ... ok
test tests::helper_without_claim ... ok
EOF
}

check() { python3 "$ROOT/scripts/claims-check.py" --registry "$REG" --results "$RES" >/dev/null 2>&1; }

expect_fail() {
    if check; then echo "NOT CAUGHT: $1"; failed=1; else echo "caught:     $1"; fi
}

fresh
if check; then echo "passes:     the flawless set"; else echo "FAILS:      the flawless set"; failed=1; fi

fresh; sed -i '/a01_1_/d' "$RES"
expect_fail "a due claim without any test"

fresh; sed -i 's/a01_1_starts_after_login ... ok/a01_1_starts_after_login ... ignored/' "$RES"
expect_fail "the only test of a due claim was skipped (ignored)"

fresh; sed -i 's/a01_1_starts_after_login ... ok/a01_1_starts_after_login ... FAILED/' "$RES"
expect_fail "a test of a due claim failed"

fresh; echo "test tests::a01_1_second_test ... FAILED" >> "$RES"
expect_fail "one of two tests of a due claim failed"

fresh; echo "test tests::a01_9_typo_in_claim ... ok" >> "$RES"
expect_fail "a test names a claim that doesn't exist"

fresh; sed -i 's/g1_same_input/g7_same_input/' "$RES"
expect_fail "a global invariant proven under the wrong ID"

fresh; rm "$SCRATCH/verify/breaks/A01.2-two-collectors.patch"
expect_fail "a due security claim without its break"

fresh; printf '\n[[claim]]\nid = "A01.1"\nfunction = "F-A01"\ndue = "0.1b"\nsecurity = false\nproofs = ["UNIT"]\ntext = "duplicate"\n' >> "$REG"
expect_fail "a duplicate claim ID"

fresh; sed -i '0,/function = "F-A01"/s//function = "F-A09"/' "$REG"
expect_fail "a claim of an unknown function"

fresh; sed -i '0,/proofs = \["UNIT"\]/s//proofs = ["MAGIC"]/' "$REG"
expect_fail "an unknown proof kind"

fresh; sed -i '0,/proofs = \["UNIT"\]/s//proofs = []/' "$REG"
expect_fail "a claim without any proof kind"

fresh; sed -i '0,/due = "0.1a"/s//due = "0.9"/' "$REG"
expect_fail "a claim due in an unknown milestone"

fresh; sed -i '0,/text = "starts after login"/s//texte = "starts after login"/' "$REG"
expect_fail "a misspelt field, which would otherwise be ignored"

fresh; printf '\n[functions."F-A03"]\nname = "Import"\nversion = "0.1"\n' >> "$REG"
expect_fail "a function without any claim"

fresh; sed -i 's/current = "0.1a"/current = "0.3"/' "$REG"
expect_fail "the current milestone doesn't exist"

fresh; sed -i 's/helper_without_claim ... ok/helper_without_claim ... FAILED/' "$RES"
expect_fail "a test without a claim failed"

fresh; sed -i 's/helper_without_claim ... ok/helper_without_claim ... ignored/' "$RES"
expect_fail "a test without a claim was skipped"

fresh; echo "test tests::a02_1_early_work ... ignored" >> "$RES"
expect_fail "a test of a claim not yet due was skipped"

fresh; : > "$RES"
expect_fail "no test results at all"

fresh; sed -i 's/current = "0.1a"/current = "0.1b"/' "$REG"
expect_fail "moving to the next milestone makes its claims due (A02.1 unproven)"

# Steps: once one claim of a step has a test, every claim of that step is due.
step_fresh() {
    fresh
    sed -i 's/current = "0.1a"/current = "phase0"/' "$REG"
    sed -i '/^id = "A01.1"/a step = 1' "$REG"
    sed -i '/^id = "A01.2"/a step = 1' "$REG"
    sed -i '/^id = "G1"/a step = 2' "$REG"
}
step_fresh
if check; then echo "passes:     a started step with all its claims proven"; else echo "FAILS:      a started step with all its claims proven"; failed=1; fi

step_fresh; sed -i '/a01_2_/d' "$RES"
expect_fail "a started step leaves one of its claims without a test"

step_fresh; rm "$SCRATCH/verify/breaks/A01.2-two-collectors.patch"
expect_fail "a started step has a security claim without its break"

step_fresh; sed -i '/a01_/d' "$RES"
if check; then echo "passes:     a step not started yet is not due before its milestone"; else echo "FAILS:      a step not started yet is not due before its milestone"; failed=1; fi

step_fresh; sed -i '0,/step = 1/s//step = "one"/' "$REG"
expect_fail "a step that isn't a whole number"

exit $failed

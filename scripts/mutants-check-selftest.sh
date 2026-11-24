#!/bin/sh
# Who checks the checker? Feeds scripts/mutants-check.py made-up cargo-mutants
# results, each with one flaw, and expects it to fail; the flawless set must
# pass. Exit 1 if any flaw goes unnoticed.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
S=$(mktemp -d)
trap 'rm -rf "$S"' EXIT
failed=0

fresh() {
    rm -rf "$S/root" "$S/out"
    mkdir -p "$S/root/verify" "$S/out/mutants.out"
    printf '[threshold]\nlogbook-model = 75\n' > "$S/root/verify/mutation.toml"
    cat > "$S/root/verify/mutants-accepted.toml" <<'EOT'
[[accepted]]
file = "crates/logbook-model/src/time.rs"
mutant = "replace < with <= in is_canonical_time"
reason = "equivalent: the two sides are never equal there"
EOT
    O="$S/out/mutants.out"
    printf '%s\n' \
      "crates/logbook-model/src/id.rs:40:9: replace EventId::as_str -> &str with \"\"" \
      "crates/logbook-model/src/id.rs:51:20: replace == with != in EventId::parse" \
      "crates/logbook-model/src/raw.rs:9:5: replace raw_line -> (String, bool) with (String::new(), false)" > "$O/caught.txt"
    printf '%s\n' "crates/logbook-model/src/time.rs:60:12: replace < with <= in is_canonical_time" > "$O/missed.txt"
    printf '%s\n' "crates/logbook-model/src/time.rs:12:5: replace utc_time -> Option<String> with None" > "$O/timeout.txt"
    printf '%s\n' "crates/logbook-model/src/event.rs:9:1: replace check -> Result<(), ModelError> with Ok(Default::default())" > "$O/unviable.txt"
}
check() { python3 "$ROOT/scripts/mutants-check.py" --root "$S/root" "$S/out" >"$S/log" 2>&1; }
expect_fail() { if check; then echo "NOT CAUGHT: $1"; failed=1; else echo "caught:     $1"; fi; }

fresh
if check; then echo "passes:     the flawless set (4 of 5 caught, the survivor accepted)"; else echo "FAILS:      the flawless set"; cat "$S/log"; failed=1; fi
grep -q "4 of 5 caught (80.0 %), 1 didn't compile" "$S/log" || { echo "WRONG:      counts or share"; cat "$S/log"; failed=1; }

fresh; echo "crates/logbook-model/src/id.rs:70:5: replace is_simple_name -> bool with true" >> "$S/out/mutants.out/missed.txt"
expect_fail "a survivor that isn't accepted"

fresh; sed -i 's/^reason = .*/reason = " "/' "$S/root/verify/mutants-accepted.toml"
expect_fail "an accepted survivor without a reason"

fresh; printf '[threshold]\nlogbook-model = 90\n' > "$S/root/verify/mutation.toml"
expect_fail "a crate below its threshold (80 % < 90 %)"

fresh; printf '[threshold]\nlogbook-store = 90\n' > "$S/root/verify/mutation.toml"
expect_fail "mutants of a crate with no threshold"

fresh; rm "$S/out/mutants.out/"*.txt
expect_fail "no mutants at all"

fresh; rm -rf "$S/out/mutants.out"
expect_fail "no cargo-mutants results"

fresh; echo "this isn't a mutant line" >> "$S/out/mutants.out/caught.txt"
expect_fail "a line it can't read"

fresh; sed -i 's/in is_canonical_time"/in is_canonical_time_other"/' "$S/root/verify/mutants-accepted.toml"
expect_fail "an accepted entry for another mutant doesn't cover this survivor"

fresh; : > "$S/out/mutants.out/missed.txt"
if check && grep -q "matches no survivor any more" "$S/log"; then echo "right:      a stale accepted entry is reported"; else echo "WRONG:      a stale accepted entry"; failed=1; fi

exit $failed

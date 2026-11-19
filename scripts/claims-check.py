#!/usr/bin/env python3
"""Logbook's map check (build plan V01, function F-L08).

    scripts/claims-check.py                     check against the current milestone
    scripts/claims-check.py --milestone 0.1a    check as if 0.1a were being built
    scripts/claims-check.py --results FILE      use saved `cargo test` output
                                                instead of running the tests
    scripts/claims-check.py --registry FILE     another registry (for the self-test)
    scripts/claims-check.py --summary           counts per milestone, no check

It reads verify/claims.toml and the result of an actual test run, and fails if:

  * the registry is malformed: unknown fields, a duplicate ID, an unknown
    function or milestone or proof kind, a function without claims;
  * a test is named after a claim that doesn't exist (a typo would otherwise
    leave the real claim unproven while looking proven);
  * a claim that is due (its milestone is the current one or earlier) has no
    test that ran and passed, or one of its tests failed or was ignored
    (skipped counts as failed);
  * a due security claim has no break in verify/breaks/<ID>-*.patch.

The check reads which tests RAN and PASSED, not which test files exist: a test
switched off by any trick is simply missing from the run.

Conformance cases (V02) will prove claims too, through the claims listed in
their case.toml; they are added to this check with the conformance runner
(version 0.1a).

Its own test: scripts/claims-check-selftest.sh.
"""
import argparse
import pathlib
import re
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
CLAIM_ID = re.compile(r"^(?:[A-L]\d\d\.\d+|G\d)$")
FUNCTION_ID = re.compile(r"^(?:F-[A-L]\d\d|F-[A-L]|global)$")
TEST_LINE = re.compile(r"^test (\S+) \.\.\. (ok|FAILED|ignored)\b")
TEST_CLAIM = re.compile(r"^(?:([a-l])(\d\d)_(\d+)|g(\d))_")
CLAIM_FIELDS = {"id", "function", "due", "security", "proofs", "text", "break"}
FUNCTION_FIELDS = {"name", "version", "proven_by"}


def claim_of_test(name):
    """'tests::a02_1_resume…' -> 'A02.1', 'g4_no_canary' -> 'G4', else None."""
    m = TEST_CLAIM.match(name.rsplit("::", 1)[-1])
    if not m:
        return None
    if m.group(4):
        return "G" + m.group(4)
    return f"{m.group(1).upper()}{m.group(2)}.{m.group(3)}"


def check_registry(reg):
    problems = []
    meta = reg.get("registry", {})
    milestones = meta.get("milestones", [])
    kinds = set(meta.get("proof_kinds", []))
    current = meta.get("current")
    if not milestones or not kinds:
        problems.append("[registry] needs milestones and proof_kinds")
    if current != "phase0" and current not in milestones:
        problems.append(f"[registry] current = {current!r} is not a milestone")
    functions = reg.get("functions", {})
    for fid, f in functions.items():
        if not FUNCTION_ID.match(fid):
            problems.append(f"function {fid!r}: malformed ID")
        extra = set(f) - FUNCTION_FIELDS
        if extra:
            problems.append(f"function {fid}: unknown fields {sorted(extra)}")
        for other in f.get("proven_by", []):
            if other not in functions:
                problems.append(f"function {fid}: proven_by names unknown function {other}")
    seen = set()
    claims = reg.get("claim", [])
    for c in claims:
        cid = c.get("id", "?")
        extra = set(c) - CLAIM_FIELDS
        missing = CLAIM_FIELDS - {"break"} - set(c)
        if extra:
            problems.append(f"claim {cid}: unknown fields {sorted(extra)}")
        if missing:
            problems.append(f"claim {cid}: missing fields {sorted(missing)}")
            continue
        if not CLAIM_ID.match(cid):
            problems.append(f"claim {cid!r}: malformed ID")
        if cid in seen:
            problems.append(f"claim {cid}: duplicate ID")
        seen.add(cid)
        if c["function"] not in functions:
            problems.append(f"claim {cid}: unknown function {c['function']}")
        elif c["function"].startswith("F-") and len(c["function"]) == 5 and not cid.startswith(c["function"][2:]):
            problems.append(f"claim {cid}: ID doesn't match its function {c['function']}")
        if c["due"] not in milestones:
            problems.append(f"claim {cid}: due = {c['due']!r} is not a milestone")
        if not isinstance(c["security"], bool):
            problems.append(f"claim {cid}: security must be true or false")
        bad = [p for p in c["proofs"] if p not in kinds]
        if not c["proofs"] or bad:
            problems.append(f"claim {cid}: proofs {c['proofs']} (unknown or empty)")
        if not c["text"].strip():
            problems.append(f"claim {cid}: empty text")
    for fid, f in functions.items():
        if not f.get("proven_by") and not any(c.get("function") == fid for c in claims):
            problems.append(f"function {fid}: has no claim and isn't proven_by another function")
    return problems


def run_tests():
    """The output of an actual test run (all tests, even after a failure)."""
    proc = subprocess.run(
        ["cargo", "test", "--workspace", "--locked", "--no-fail-fast"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    return proc.stdout + proc.stderr


def test_results(text):
    """claim ID -> list of (test name, status); plus tests naming unknown claims later."""
    results = {}
    for line in text.splitlines():
        m = TEST_LINE.match(line.strip())
        if m:
            name, status = m.groups()
            cid = claim_of_test(name)
            if cid:
                results.setdefault(cid, []).append((name, status))
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--registry", default=str(ROOT / "verify" / "claims.toml"))
    ap.add_argument("--milestone")
    ap.add_argument("--results")
    ap.add_argument("--summary", action="store_true")
    args = ap.parse_args()

    registry_path = pathlib.Path(args.registry)
    with open(registry_path, "rb") as f:
        reg = tomllib.load(f)
    breaks_dir = registry_path.parent / "breaks"

    problems = check_registry(reg)
    if problems:
        return report(problems, "The claim registry is malformed")

    milestones = reg["registry"]["milestones"]
    current = args.milestone or reg["registry"]["current"]
    if current != "phase0" and current not in milestones:
        return report([f"unknown milestone {current!r}"], "Map check failed")
    claims = reg["claim"]

    if args.summary:
        for m in milestones:
            mine = [c for c in claims if c["due"] == m]
            sec = sum(c["security"] for c in mine)
            print(f"  {m:5} {len(mine):4} claims, {sec:3} security")
        print(f"  total {len(claims)} claims, {sum(c['security'] for c in claims)} security, "
              f"{len(reg['functions'])} functions")
        return 0

    text = pathlib.Path(args.results).read_text(encoding="utf-8") if args.results else run_tests()
    results = test_results(text)
    if not any(TEST_LINE.match(line.strip()) for line in text.splitlines()):
        return report(["no test results found: a check with nothing to check fails"], "Map check failed")

    known = {c["id"] for c in claims}
    problems = []
    # Every test counts, not only the claim tests: a failed or skipped helper
    # test fails the check too (no silent skips, build plan section 2).
    for line in text.splitlines():
        m = TEST_LINE.match(line.strip())
        if m and m.group(2) != "ok":
            problems.append(f"test {m.group(1)} {m.group(2)}")
    for cid, tests in sorted(results.items()):
        if cid not in known:
            names = ", ".join(n for n, _ in tests)
            problems.append(f"test {names} names claim {cid}, which doesn't exist")

    due_index = milestones.index(current) if current != "phase0" else -1
    due = [c for c in claims if milestones.index(c["due"]) <= due_index]
    proven = 0
    for c in due:
        tests = results.get(c["id"], [])
        bad = [f"{n} {s}" for n, s in tests if s != "ok"]
        if bad:
            problems.append(f"{c['id']} ({c['function']}): " + "; ".join(bad))
        elif not tests:
            problems.append(f"{c['id']} ({c['function']}) is due in {c['due']} but no test proves it: {c['text']}")
        else:
            proven += 1
        if c["security"] and not list(breaks_dir.glob(f"{c['id']}-*.patch")):
            problems.append(f"{c['id']} is a security claim due in {c['due']} without its break in verify/breaks/{c['id']}-*.patch")

    if problems:
        return report(problems, f"Map check failed (milestone {current})")
    print(f"Map check passed (milestone {current}): {proven} of {len(due)} due claims proven; "
          f"{len(claims)} claims registered.")
    return 0


def report(problems, title):
    print(f"{title}:")
    for p in problems:
        print("  -", p)
    print(f"  ({len(problems)} problems)")
    return 1


if __name__ == "__main__":
    sys.exit(main())

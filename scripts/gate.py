#!/usr/bin/env python3
"""Logbook's gate, "Needs your approval" (build plan V13).

    scripts/gate.py BASE HEAD [--base-tests F --head-tests F] [--approved-sha SHA]
    scripts/gate.py BASE HEAD --tests-only --base-tests F --head-tests F

Says whether a change from BASE to HEAD (two git commits) needs the owner. It
reads the change only as text through git; it never runs the change's code.
In CI it runs as the BASE branch's copy (scripts/gate-run.sh locally,
pull_request_target on GitHub), so a change can't switch off its own gate.

The owner is needed when the change
  1. touches a protected file (PROTECTED below: the checks, the claims and
     breaks, the expected results, the limits, the security crates, CI, the
     test computers with their watchers and probes);
  2. adds or changes an outside crate in Cargo.lock (new crate, other
     version, other checksum, other source);
  3. adds a line that can switch a test or a lint off: #[ignore],
     #[should_panic], #[cfg(any())] and other always-false conditions,
     #[allow(…)] / #[expect(…)], cfg_attr(…, ignore);
  4. loses a test: a test that ran and passed on BASE doesn't run and pass on
     HEAD (deleted, renamed, skipped, failing). This reads the test RUNS
     (--base-tests / --head-tests: `cargo test` output), not the files, so a
     test switched off by any trick shows up here.

On GitHub, items 1-3 run in the "Needs your approval" check
(.github/workflows/approval.yml, which never runs the change's code), and
item 4 runs in CI with --tests-only (ci.yml, "No test lost"), because the
tests have to run. --tests-only checks item 4 alone, and an approval doesn't
count there: a lost test is fixed, not approved.

Exit codes:  0  nothing needs the owner, or the owner approved exactly HEAD
             1  needs the owner's approval (the reasons are printed)
             2  wrong use

--approved-sha: the commit the owner approved. It counts only if it is HEAD
itself: an approval doesn't carry over to later pushes.

Weakening a test's assertions without any of the above (e.g. an early
`return;` in an unprotected test) is not seen here; it is caught by the break
list and mutation testing, which make the weakened test's claim fail.
"""
import argparse
import collections
import fnmatch
import re
import subprocess
import sys
import tomllib

PROTECTED = [
    "verify/*",
    "conformance/*/expected/*",
    "conformance/*/case.toml",
    "scripts/*",
    "Makefile",
    ".github/*",
    "CODEOWNERS",
    "Cargo.toml",
    "deny.toml",
    "clippy.toml",
    "rust-toolchain*",
    "dist/*.service",
    "vm/*",
    "crates/logbook-guard/*",
    "crates/logbook-exec/*",
    "crates/logbook-redact/*",
    "crates/logbook-render/*",
    "*/snapshots/*",
]

SWITCH_OFF = [
    (re.compile(r"#\s*\[\s*ignore\b"), "#[ignore] skips a test"),
    (re.compile(r"\bshould_panic\b"), "#[should_panic] turns a failure into a pass"),
    (re.compile(r"cfg\s*\(\s*any\s*\(\s*\)\s*\)"), "#[cfg(any())] removes code from the build"),
    (re.compile(r"cfg\s*\(\s*not\s*\(\s*all\s*\(\s*\)\s*\)\s*\)"), "#[cfg(not(all()))] removes code from the build"),
    (re.compile(r"cfg\s*\(\s*not\s*\(\s*test\s*\)\s*\)"), "#[cfg(not(test))] hides code from the tests"),
    (re.compile(r"cfg\s*\(\s*feature\s*="), "a feature condition can remove tests from the normal run"),
    (re.compile(r"cfg_attr\s*\([^)]*\b(?:ignore|allow|expect)\b"), "cfg_attr(…) can switch a test or lint off"),
    (re.compile(r"#!?\s*\[\s*(?:allow|expect)\s*\("), "#[allow(…)] / #[expect(…)] switches a lint off"),
]

TEST_LINE = re.compile(r"^test (\S+) \.\.\. (ok|FAILED|ignored)\b")


def git(repo, *args):
    p = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, check=False)
    if p.returncode != 0:
        raise SystemExit(f"gate: git {' '.join(args)} failed: {p.stderr.strip()}")
    return p.stdout


def protected(path):
    return any(fnmatch.fnmatch(path, pat) for pat in PROTECTED)


def lock_packages(text):
    if not text.strip():
        return {}
    data = tomllib.loads(text)
    return {(p["name"], p.get("version", "")): (p.get("source"), p.get("checksum"))
            for p in data.get("package", [])}


def show(repo, rev, path):
    p = subprocess.run(["git", "-C", repo, "show", f"{rev}:{path}"], capture_output=True, text=True, check=False)
    return p.stdout if p.returncode == 0 else ""


def passed_tests(path):
    """Passed test names, counted: the same name may exist in several crates."""
    out = collections.Counter()
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = TEST_LINE.match(line.strip())
            if m and m.group(2) == "ok":
                out[m.group(1)] += 1
    return out


def reasons_for(repo, base, head, base_tests=None, head_tests=None):
    reasons = []

    # 1. protected files (renames count for both names)
    for line in git(repo, "diff", "--name-status", "-M", base, head).splitlines():
        parts = line.split("\t")
        for path in parts[1:]:
            if protected(path):
                reasons.append(f"protected file changed: {path} ({parts[0][0]})")

    # 2. outside crates
    old, new = lock_packages(show(repo, base, "Cargo.lock")), lock_packages(show(repo, head, "Cargo.lock"))
    for key in sorted(set(new) - set(old)):
        src = new[key][0]
        if src is not None:          # Logbook's own crates have no source
            reasons.append(f"outside crate added or changed version: {key[0]} {key[1]}")
    for key in sorted(set(new) & set(old)):
        if new[key] != old[key]:
            reasons.append(f"outside crate changed source or checksum: {key[0]} {key[1]}")

    # 3. added lines that can switch a test or lint off
    diff = git(repo, "diff", "-U0", base, head, "--", "*.rs")
    current = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            current = line[6:] if line.startswith("+++ b/") else None
        elif line.startswith("+") and not line.startswith("+++") and current:
            for pattern, why in SWITCH_OFF:
                if pattern.search(line):
                    reasons.append(f"{current}: {why}: {line[1:].strip()}")

    # 4. tests lost
    if base_tests and head_tests:
        lost = passed_tests(base_tests) - passed_tests(head_tests)
        for name in sorted(lost.elements()):
            reasons.append(f"test passed before but doesn't run and pass now: {name}")
    return reasons


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("head")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--base-tests")
    ap.add_argument("--head-tests")
    ap.add_argument("--approved-sha")
    ap.add_argument("--tests-only", action="store_true")
    args = ap.parse_args()
    if bool(args.base_tests) != bool(args.head_tests):
        print("gate: give both --base-tests and --head-tests, or neither")
        return 2
    if args.tests_only:
        if not args.base_tests or args.approved_sha:
            print("gate: --tests-only needs both test runs and takes no approval")
            return 2
        if not passed_tests(args.base_tests):
            print("gate: no passed test in the base run; a comparison with nothing compares nothing")
            return 2
        lost = passed_tests(args.base_tests) - passed_tests(args.head_tests)
        if not lost:
            print("No test that passed before is lost.")
            return 0
        print("## Tests lost")
        for name in sorted(lost.elements()):
            print(f"- test passed before but doesn't run and pass now: {name}")
        return 1

    head_sha = git(args.repo, "rev-parse", args.head).strip()
    reasons = reasons_for(args.repo, args.base, args.head, args.base_tests, args.head_tests)
    if not reasons:
        print("Nothing in this change needs your approval.")
        return 0
    approved = bool(args.approved_sha) and git(args.repo, "rev-parse", args.approved_sha).strip() == head_sha
    print("## Approved by you on exactly this commit" if approved else "## This change needs your approval")
    for r in reasons:
        print("-", r)
    if not args.base_tests:
        print("(test runs not compared: --base-tests/--head-tests not given)")
    return 0 if approved else 1


if __name__ == "__main__":
    sys.exit(main())

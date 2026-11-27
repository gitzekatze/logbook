#!/usr/bin/env python3
"""Logbook's cheat list (build plan V14): proof that checks can't be weakened unseen.

    scripts/cheats-check.py            every cheat in verify/cheats/
    scripts/cheats-check.py --only X   one cheat (file name without .patch)

A cheat is a known way to weaken Logbook's checks, saved as a patch with a
header:

    Cheat: hide a test module with #[cfg(any())]
    Expect: owner      the gate must say "needs your approval"
            checks     a check must fail (arch, claims or breaks), which no
                       approval can turn green
            none       a harmless control: the gate must stay quiet and all
                       checks pass (no false alarms)

The current working tree is copied into a scratch git repository and
committed as the base. Each cheat is applied and committed as the head, the
test suite runs on both, and then:
  * the gate runs as the BASE commit's copy (a cheat that edits the gate
    can't help itself),
  * the checks run on the head.

Built-in scenarios check what patches can't: an approval counts only for
exactly the approved commit; a test lost only in the test runs (not in the
files) is still found; and retiring a test (verify/tests-retired.toml) needs
the owner and a reason, and counts only in the change that retires it.

Verdicts: flagged / caught / quiet (as expected), NOT CAUGHT, FALSE ALARM,
stale (the patch no longer applies: update it). Exit 1 unless all as expected.
"""
import argparse
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
HEADER = re.compile(r"^(Cheat|Expect):\s*(.*?)\s*$")
CODE_CHANGE = re.compile(r"^diff --git a/(\S+)", re.M)
TEST_LINE = re.compile(r"^test (\S+) \.\.\. (ok|FAILED|ignored)\b")


def run(cmd, cwd, env=None):
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, check=False)
    return p.returncode, p.stdout + p.stderr


def git(ws, *args):
    code, out = run(["git", *args], ws)
    if code:
        raise RuntimeError(f"git {' '.join(args)}: {out.strip()}")
    return out


def header(text):
    h = {}
    for line in text.splitlines():
        if line.startswith("diff --git"):
            break
        m = HEADER.match(line)
        if m:
            h[m.group(1)] = m.group(2)
    return h


def tests(ws, env, out_file):
    _, out = run(["cargo", "test", "--workspace", "--locked", "--no-fail-fast"], ws, env)
    out_file.write_text(out)
    return out_file


def gate(base_gate, ws, base, head, base_tests, head_tests, approved=None):
    cmd = [sys.executable, str(base_gate), "--repo", str(ws), base, head,
           "--base-tests", str(base_tests), "--head-tests", str(head_tests)]
    if approved:
        cmd += ["--approved-sha", approved]
    return run(cmd, ws)


def checks(ws, head_tests, env, details=None):
    """Names of the checks that fail on the head; their output goes into
    `details` (for explaining an unexpected verdict)."""
    failed = []
    for name, cmd in (("arch", [sys.executable, "scripts/arch-check.py", str(ws)]),
                      ("claims", [sys.executable, "scripts/claims-check.py", "--results", str(head_tests)]),
                      ("breaks", [sys.executable, "scripts/breaks-check.py"])):
        code, out = run(cmd, ws, env)
        if code:
            failed.append(name)
            if details is not None:
                details.append(f"--- {name}:\n{out.strip()[-3000:]}")
    return failed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only")
    args = ap.parse_args()
    cheats = sorted((REPO / "verify" / "cheats").glob("*.patch"))
    if args.only:
        cheats = [c for c in cheats if c.stem == args.only]
    if not cheats:
        print("Cheat list failed: no cheats (a check with nothing to check fails).")
        return 1

    env = dict(os.environ)
    env["CARGO_TARGET_DIR"] = str(REPO / "target" / "cheats")
    bad = 0
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        ws = tmp / "ws"
        shutil.copytree(REPO, ws, symlinks=True,
                        ignore=lambda d, n: [x for x in n if x in ("target", ".git")] if pathlib.Path(d) == REPO else [])
        git(ws, "init", "-q", "-b", "main")
        git(ws, "add", "-A")
        git(ws, "-c", "user.email=gate@test", "-c", "user.name=gate", "commit", "-qm", "base")
        base = git(ws, "rev-parse", "HEAD").strip()
        base_gate = tmp / "base-gate.py"
        base_gate.write_text(git(ws, "show", f"{base}:scripts/gate.py"))
        base_tests = tests(ws, env, tmp / "base-tests.txt")

        for c in cheats:
            text = c.read_text(encoding="utf-8")
            h = header(text)
            expect = h.get("Expect")
            if expect not in ("owner", "checks", "none") or "Cheat" not in h:
                print(f"VERDICT {c.stem} invalid -- header needs Cheat: and Expect: owner|checks|none")
                bad += 1
                continue
            git(ws, "checkout", "-q", "-f", base)
            git(ws, "clean", "-qfd")
            code, out = run(["git", "apply", "--index", str(c)], ws)
            if code:
                print(f"VERDICT {c.stem} stale -- the patch no longer applies")
                bad += 1
                continue
            git(ws, "-c", "user.email=cheat@test", "-c", "user.name=cheat", "commit", "-qm", c.stem)
            head = git(ws, "rev-parse", "HEAD").strip()
            touched = CODE_CHANGE.findall(text)
            code_changed = any(p.endswith((".rs", ".toml", ".lock")) for p in touched)
            head_tests = tests(ws, env, tmp / "head-tests.txt") if code_changed else base_tests
            g, gout = gate(base_gate, ws, base, head, base_tests, head_tests)
            details = []
            failed = checks(ws, head_tests, env, details)
            if expect == "owner":
                ok = g == 1
                verdict = "flagged" if ok else "NOT CAUGHT"
                why = (gout.strip().splitlines()[1] if ok and len(gout.strip().splitlines()) > 1 else "the gate stayed quiet")
            elif expect == "checks":
                ok = bool(failed)
                verdict = "caught" if ok else "NOT CAUGHT"
                why = f"failing: {', '.join(failed)}" if failed else "every check passed"
            else:
                ok = g == 0 and not failed
                verdict = "quiet" if ok else "FALSE ALARM"
                why = "gate quiet, checks pass" if ok else f"gate exit {g}, failing: {', '.join(failed) or 'none'}"
            print(f"VERDICT {c.stem} {verdict} -- {why}")
            if not ok:
                # Explain it: what the gate found, what failed, which tests didn't pass.
                print(f"--- gate (exit {g}):\n{gout.strip()[-3000:]}")
                for d in details:
                    print(d)
                print("--- tests not passing on the head:")
                for line in head_tests.read_text().splitlines():
                    if line.startswith("test ") and not line.rstrip().endswith(" ok"):
                        print("   ", line)
            bad += not ok

        bad += scenarios(ws, base, base_gate, base_tests, tmp, env)
    total = len(cheats) + SCENARIOS
    print(f"Cheat list {'passed' if not bad else 'failed'}: {total - bad} of {total} as expected.")
    return 1 if bad else 0


SCENARIOS = 11


def scenarios(ws, base, base_gate, base_tests, tmp, env):
    """Approval binding and test-run comparison, which patches can't express."""
    bad = 0

    def report(name, ok, why):
        nonlocal bad
        print(f"VERDICT scenario:{name} {'as-expected' if ok else 'NOT CAUGHT'} -- {why}")
        bad += not ok

    git(ws, "checkout", "-q", "-f", base)
    git(ws, "clean", "-qfd")
    (ws / "deny.toml").write_text((ws / "deny.toml").read_text() + "\n# change 1\n")
    git(ws, "-c", "user.email=c@t", "-c", "user.name=c", "commit", "-qam", "protected change")
    first = git(ws, "rev-parse", "HEAD").strip()
    g, _ = gate(base_gate, ws, base, first, base_tests, base_tests, approved=first)
    report("approval-of-this-commit", g == 0, f"approved exactly this commit -> exit {g} (expect 0)")
    g, _ = gate(base_gate, ws, base, first, base_tests, base_tests, approved=base)
    report("approval-of-another-commit", g == 1, f"approval names the base, not this commit -> exit {g} (expect 1)")

    (ws / "deny.toml").write_text((ws / "deny.toml").read_text() + "\n# change 2, pushed after approval\n")
    git(ws, "-c", "user.email=c@t", "-c", "user.name=c", "commit", "-qam", "pushed after approval")
    second = git(ws, "rev-parse", "HEAD").strip()
    g, _ = gate(base_gate, ws, base, second, base_tests, base_tests, approved=first)
    report("push-after-approval", g == 1, f"approval of the previous push -> exit {g} (expect 1)")

    # A test that vanished from the runs only (no file change the gate could
    # see): the first test that passed on the base, every test of that name.
    git(ws, "checkout", "-q", "-f", base)
    passed = [m.group(1) for m in map(TEST_LINE.match, base_tests.read_text().splitlines()) if m and m.group(2) == "ok"]
    victim = passed[0]
    lost = tmp / "lost-tests.txt"
    lost.write_text("\n".join(l for l in base_tests.read_text().splitlines()
                              if not l.startswith(f"test {victim} ")))
    g, out = gate(base_gate, ws, base, base, base_tests, lost)
    report("test-lost-in-runs-only", g == 1 and "doesn't run and pass now" in out,
           f"a passing test missing from the head's run -> exit {g} (expect 1)")

    # --tests-only (CI's "No test lost"): only the runs count, and no approval.
    def tests_only(head_tests, *extra, base_rev=base, head_rev=second):
        return run([sys.executable, str(base_gate), "--repo", str(ws), base_rev, head_rev, "--tests-only",
                    "--base-tests", str(base_tests), "--head-tests", str(head_tests), *extra], ws)
    g, _ = tests_only(base_tests)
    report("tests-only-ignores-files", g == 0, f"protected file changed, no test lost -> exit {g} (expect 0)")
    g, _ = tests_only(lost)
    report("tests-only-finds-lost-test", g == 1, f"a passing test missing from the head's run -> exit {g} (expect 1)")
    g, _ = tests_only(lost, "--approved-sha", second)
    report("tests-only-takes-no-approval", g == 2, f"an approval offered for a lost test -> exit {g} (expect 2: refused)")

    # Retiring a test (verify/tests-retired.toml): only an entry the change
    # adds counts, it needs a reason, and the file needs the owner.
    def commit_retired(entries, message):
        (ws / "verify" / "tests-retired.toml").write_text(entries)
        git(ws, "add", "-A")
        git(ws, "-c", "user.email=c@t", "-c", "user.name=c", "commit", "-qm", message)
        return git(ws, "rev-parse", "HEAD").strip()
    git(ws, "checkout", "-q", "-f", base)
    count = passed.count(victim)
    entry = f'[[retired]]\ntest = "{victim}"\ncount = {count}\nreason = "what it checked is no longer true"\n'
    retiring = commit_retired(entry, "retire a test")
    g, _ = tests_only(lost, head_rev=retiring)
    report("retired-test-not-lost", g == 0, f"the change retires the missing test -> exit {g} (expect 0)")
    g, _ = gate(base_gate, ws, base, retiring, base_tests, lost)
    report("retiring-needs-the-owner", g == 1, f"the change retires a test -> exit {g} (expect 1: needs approval)")
    later = commit_retired(entry + "\n# a later change\n", "a later change")
    g, _ = tests_only(lost, base_rev=retiring, head_rev=later)
    report("old-retirement-hides-nothing", g == 1,
           f"an entry already on the base, the test lost again -> exit {g} (expect 1)")
    git(ws, "checkout", "-q", "-f", base)
    no_reason = commit_retired(f'[[retired]]\ntest = "{victim}"\ncount = {count}\n', "retire without a reason")
    g, _ = tests_only(lost, head_rev=no_reason)
    report("retiring-needs-a-reason", g == 2, f"an entry without a reason -> exit {g} (expect 2: refused)")
    return bad


if __name__ == "__main__":
    sys.exit(main())

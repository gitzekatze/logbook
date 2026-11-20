#!/usr/bin/env python3
"""Logbook's break list (build plan V11): proof that the tests catch mistakes.

    scripts/breaks-check.py                 every break in verify/breaks/
    scripts/breaks-check.py --only B09.2    the breaks of one claim
    scripts/breaks-check.py --root DIR      another workspace (the self-test's practice crate)

A break is a deliberate, realistic mistake in the code, saved as a patch:
verify/breaks/<claim ID>-<short name>.patch. The lines before the first
`diff --git` are its header:

    Claim: B09.2
    Break: read the core file to get a backtrace
    Caught-by: test

Each break is applied to a scratch copy of the workspace, and the copy is
checked. Verdicts:

    caught        what Caught-by names failed, as it should:
                    test    a test named after the claim failed (the copy must
                            still compile: a break that doesn't compile proves
                            nothing about the tests)
                    clippy  a lint failed (unsafe code, Command::new, std::net …),
                            not a plain compile error
                    arch    scripts/arch-check.py failed
    not-caught    everything passed: the claim's proof doesn't notice the mistake
    stale         the patch no longer applies (the code moved): update it
    broken-build  Caught-by: test, but the copy doesn't compile
    other-claim   tests failed, but none of the claim's own tests
    invalid       the header is missing or wrong, or the claim doesn't exist

The check passes only if every break is "caught". With no breaks at all it
fails, except in phase 0 (registry current = "phase0").

Its own test: scripts/breaks-check-selftest.sh, on a small practice crate.
"""
import argparse
import importlib.util
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

REPO = pathlib.Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("claims_check", REPO / "scripts" / "claims-check.py")
claims_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(claims_check)

CAUGHT_BY = {"test", "clippy", "arch"}
HEADER = re.compile(r"^(Claim|Break|Caught-by):\s*(.*?)\s*$")
LINT_SIGNS = ("requested on the command line", "#[deny(", "#[forbid(", "implied by")


def header_of(patch_text):
    fields = {}
    for line in patch_text.splitlines():
        if line.startswith("diff --git"):
            break
        m = HEADER.match(line)
        if m:
            fields[m.group(1)] = m.group(2)
    return fields


def copy_workspace(root, dest):
    def ignore(dirpath, names):
        if pathlib.Path(dirpath) == root:
            return [n for n in names if n in ("target", ".git")]
        return []
    shutil.copytree(root, dest, ignore=ignore, symlinks=True)


def run(cmd, cwd, env):
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, check=False)
    return p.returncode, p.stdout + p.stderr


def judge(patch, root, claims, env):
    text = patch.read_text(encoding="utf-8")
    h = header_of(text)
    file_claim = patch.name.split("-", 1)[0]
    if not {"Claim", "Break", "Caught-by"} <= set(h):
        return "invalid", "header needs Claim:, Break: and Caught-by:"
    if h["Claim"] != file_claim:
        return "invalid", f"file name says {file_claim}, header says {h['Claim']}"
    if h["Claim"] not in claims:
        return "invalid", f"claim {h['Claim']} doesn't exist"
    if h["Caught-by"] not in CAUGHT_BY:
        return "invalid", f"Caught-by must be one of {sorted(CAUGHT_BY)}"
    if "diff --git" not in text:
        return "invalid", "no patch after the header"

    with tempfile.TemporaryDirectory() as tmp:
        ws = pathlib.Path(tmp) / "ws"
        copy_workspace(root, ws)
        code, out = run(["git", "apply", "--check", str(patch)], ws, env)
        if code != 0:
            return "stale", out.strip().splitlines()[-1] if out.strip() else "does not apply"
        run(["git", "apply", str(patch)], ws, env)

        how = h["Caught-by"]
        if how == "arch":
            code, out = run([sys.executable, str(REPO / "scripts" / "arch-check.py"), str(ws)], ws, env)
            return ("caught", "the architecture check failed") if code else ("not-caught", "the architecture check passed")
        if how == "clippy":
            code, out = run(["cargo", "clippy", "--workspace", "--all-targets", "--locked", "--", "-D", "warnings"], ws, env)
            if code == 0:
                return "not-caught", "clippy passed"
            if re.search(r"error\[E\d+\]", out):
                return "broken-build", "a compile error, not a lint: the break must compile"
            if any(s in out for s in LINT_SIGNS):
                return "caught", "a lint failed"
            return "broken-build", "clippy failed without a lint error"

        code, out = run(["cargo", "test", "--workspace", "--locked", "--no-fail-fast"], ws, env)
        results = {}
        for line in out.splitlines():
            m = claims_check.TEST_LINE.match(line.strip())
            if m:
                results[m.group(1)] = m.group(2)
        if (code != 0 and not results) or re.search(r"error\[E\d+\]|could not compile", out):
            return "broken-build", "the copy doesn't compile"
        mine = {n: s for n, s in results.items() if claims_check.claim_of_test(n) == h["Claim"]}
        failed_mine = [n for n, s in mine.items() if s == "FAILED"]
        if failed_mine:
            return "caught", "failed: " + ", ".join(failed_mine)
        failed_any = [n for n, s in results.items() if s == "FAILED"]
        if failed_any:
            return "other-claim", "only other tests failed: " + ", ".join(failed_any)
        if not mine:
            return "not-caught", f"no test of {h['Claim']} ran"
        return "not-caught", f"all {len(mine)} tests of {h['Claim']} passed"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(REPO))
    ap.add_argument("--only")
    args = ap.parse_args()
    root = pathlib.Path(args.root).resolve()
    with open(root / "verify" / "claims.toml", "rb") as f:
        reg = tomllib.load(f)
    claims = {c["id"] for c in reg.get("claim", [])}
    patches = sorted((root / "verify" / "breaks").glob("*.patch"))
    if args.only:
        patches = [p for p in patches if p.name.startswith(args.only + "-")]

    if not patches:
        if reg.get("registry", {}).get("current") == "phase0" and not args.only:
            print("Break list: no breaks yet (phase 0).")
            return 0
        print("Break list failed: no breaks to check (a check with nothing to check fails).")
        return 1

    env = dict(os.environ)
    # One build folder for all breaks of this workspace, so each copy builds only what changed.
    try:
        label = "logbook" if root == REPO else str(root.relative_to(REPO))
    except ValueError:
        label = str(root)
    env["CARGO_TARGET_DIR"] = str(REPO / "target" / "breaks" / re.sub(r"[^A-Za-z0-9]+", "_", label).strip("_"))

    bad = 0
    for p in patches:
        verdict, why = judge(p, root, claims, env)
        print(f"VERDICT {p.name} {verdict} -- {why}")
        bad += verdict != "caught"
    print(f"Break list {'passed' if not bad else 'failed'}: {len(patches) - bad} of {len(patches)} breaks caught.")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

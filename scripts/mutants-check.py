#!/usr/bin/env python3
"""Logbook's mutation check (build plan V10).

    scripts/mutants-check.py OUT [OUT ...]

OUT is a folder cargo-mutants wrote (holding mutants.out/ or being it). For
each crate the check fails if:
  * a mutant survived (no test noticed it) and isn't in
    verify/mutants-accepted.toml with a reason;
  * the share of caught mutants is below the crate's threshold in
    verify/mutation.toml (timeouts count as caught; mutants that don't
    compile count as neither);
  * there are mutants of a crate with no threshold;
  * cargo-mutants found nothing at all (a check with nothing to check fails).
A failed baseline (the unchanged code failing its tests) is cargo-mutants'
exit code 4; the CI job fails on it before this check runs.
An accepted entry that matches no surviving mutant any more is reported, so
the list doesn't fill with stale entries.

Its own test: scripts/mutants-check-selftest.sh.
"""
import argparse
import collections
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
LINE = re.compile(r"^(?P<file>[^:\s]+):(?P<line>\d+):(?P<col>\d+): (?P<what>.+)$")
CRATE = re.compile(r"^crates/([^/]+)/")


def entries(folder, name):
    path = folder / name
    if not path.exists():
        return []
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        m = LINE.match(raw.strip())
        if not m:
            raise SystemExit(f"mutants-check: can't read line in {path}: {raw!r}")
        out.append((m["file"], m["what"]))
    return out


def crate_of(file):
    m = CRATE.match(file)
    return m.group(1) if m else "(outside crates/)"


def results_folder(out):
    out = pathlib.Path(out)
    return out / "mutants.out" if (out / "mutants.out").is_dir() else out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out", nargs="+")
    ap.add_argument("--root", default=str(ROOT))
    args = ap.parse_args()
    root = pathlib.Path(args.root)
    with open(root / "verify" / "mutation.toml", "rb") as f:
        thresholds = tomllib.load(f)["threshold"]
    with open(root / "verify" / "mutants-accepted.toml", "rb") as f:
        accepted_list = tomllib.load(f).get("accepted", [])
    problems = []
    for a in accepted_list:
        if set(a) != {"file", "mutant", "reason"} or not str(a.get("reason", "")).strip():
            problems.append(f"accepted entry needs exactly file, mutant and a reason: {a}")
    accepted = {(a.get("file"), a.get("mutant")) for a in accepted_list}

    count = collections.defaultdict(collections.Counter)
    missed, seen_any = [], False
    for out in args.out:
        folder = results_folder(out)
        if not folder.is_dir():
            problems.append(f"{out}: no cargo-mutants results")
            continue
        for kind, name in (("caught", "caught.txt"), ("caught", "timeout.txt"),
                           ("missed", "missed.txt"), ("unviable", "unviable.txt")):
            for file, what in entries(folder, name):
                seen_any = True
                count[crate_of(file)][kind] += 1
                if kind == "missed":
                    missed.append((file, what))
    if not seen_any:
        problems.append("no mutants at all: a check with nothing to check fails")

    used = set()
    for file, what in missed:
        if (file, what) in accepted:
            used.add((file, what))
        else:
            problems.append(f"survived: {file}: {what}")
    for a in sorted(accepted - used, key=str):
        print(f"note: accepted entry matches no survivor any more (remove it): {a[0]}: {a[1]}")

    for crate, c in sorted(count.items()):
        judged = c["caught"] + c["missed"]
        share = 100.0 * c["caught"] / judged if judged else 100.0
        limit = thresholds.get(crate)
        line = f"{crate}: {c['caught']} of {judged} caught ({share:.1f} %), {c['unviable']} didn't compile"
        if limit is None:
            problems.append(f"{line}; no threshold in verify/mutation.toml")
        elif share < limit:
            problems.append(f"{line}; below the threshold of {limit} %")
        else:
            print(f"{line}; threshold {limit} %")

    if problems:
        print("Mutation check failed:")
        for p in problems:
            print("  -", p)
        print(f"  ({len(problems)} problems)")
        return 1
    print("Mutation check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

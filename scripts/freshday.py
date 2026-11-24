#!/usr/bin/env python3
"""Fresh days (build plan V04, step P7): test days nobody can prepare for.

    scripts/freshday.py plan SEED [--distro D]   the day a seed decides, as JSON
    scripts/freshday.py compare DAY [--reader R] [--break B]
                                                 read a recorded day and compare it
                                                 with what the harness did
    scripts/freshday.py selftest                 the checks below, without a test computer

A seed (a number chosen at run time) decides the day: which packages from the
distribution's pool are installed, upgraded or removed, which programs crash
with which signal, how long the computer sleeps, how far the clock jumps, and
the pauses between. The same seed always gives the same day, so a failed day
can be replayed exactly; scripts/vm.py acts it out on a test computer.

The harness log (what the test computer really did, harness.jsonl) is the
expected result. A reader turns the recorded sources into events, and the
comparison must find exactly the harness's events. Until Logbook exists, the
reader is the stand-in below: the simplest correct reading of the sources.
Logbook takes its place later (logbook --source-root DAY/sources --json).

The comparison is only worth something if it notices a wrong reader. So the
stand-in can be broken on purpose (--break); every break must make the
comparison fail, on the synthetic day of the self-test and on every real
fresh day in CI.
"""
import argparse
import collections
import json
import pathlib
import random
import re
import sys
import tomllib

REPO = pathlib.Path(__file__).resolve().parent.parent
KINDS = ["install", "upgrade", "remove", "crash", "sleep", "clock-jump"]
PROGRAMS = ["python3", "sleep", "sh"]
SIGNALS = {"SIGSEGV": 11, "SIGABRT": 6, "SIGBUS": 7, "SIGFPE": 8}
JUMPS = [-3, -2, -1, 1, 2, 3]
MIN_JUMP_S = 1800  # a gap smaller than this is a sleep or noise, not a clock jump


def pool(distro):
    with open(REPO / "vm" / "images.toml", "rb") as f:
        return list(tomllib.load(f)[distro]["pool"])


# ---------------------------------------------------------------- the plan

def plan(seed, distro="arch", packages=None):
    """The day for this seed. Every kind of step occurs at least once, in a
    random order, plus 1-4 random extra steps; each step only where it can
    happen (remove only what is installed, install only what isn't)."""
    rng = random.Random(f"logbook-fresh-day:{distro}:{seed}")
    packages = sorted(packages if packages is not None else pool(distro))
    kinds = KINDS[:] + [rng.choice(KINDS) for _ in range(rng.randint(1, 4))]
    rng.shuffle(kinds)
    installed, steps = set(), []
    pending = kinds
    while pending:
        kind = pending.pop(0)
        free = [p for p in packages if p not in installed]
        if kind == "remove" and not installed:
            if any(k in ("install", "upgrade") for k in pending):
                pending.append(kind)    # later, once something is installed
                continue
            kind = "install"            # nothing left installs: install now,
            pending.append("remove")    # and remove afterwards
        if kind in ("install", "upgrade") and not free:
            kind = "remove"
        step = {"kind": kind}
        if kind in ("install", "upgrade"):
            step["package"] = rng.choice(free)
            installed.add(step["package"])
        elif kind == "remove":
            step["package"] = rng.choice(sorted(installed))
            installed.discard(step["package"])
        elif kind == "crash":
            step["program"] = rng.choice(PROGRAMS)
            step["signal"] = rng.choice(sorted(SIGNALS))
        elif kind == "sleep":
            step["seconds"] = rng.randint(5, 15)
        elif kind == "clock-jump":
            step["hours"] = rng.choice(JUMPS)
        step["pause"] = rng.randint(1, 5)
        steps.append(step)
    return {"seed": seed, "distro": distro, "steps": steps}


# ------------------------------------------------- the harness's events

def harness_events(day):
    """What the test computer really did, as comparable events."""
    out = []
    for line in (pathlib.Path(day) / "harness.jsonl").read_text().splitlines():
        h = json.loads(line)
        a = h["action"]
        if a == "installed":
            out.append(("installed", h["package"], h["version"]))
        elif a == "upgraded":
            out.append(("upgraded", h["package"], h["from"], h["to"]))
        elif a == "removed":
            out.append(("removed", h["package"], h["version"]))
        elif a == "crash":
            out.append(("crash", h["program"], int(h["signal"])))
        elif a == "sleep":
            out.append(("sleep",))
        elif a == "clock-jump":
            out.append(("clock-jump", int(h["hours"])))
    return out


# ---------------------------------------------- the stand-in for Logbook

ALPM = re.compile(r"\[ALPM\] (installed|upgraded|downgraded|removed) (\S+) \((.+)\)$")


def journal_entries(data):
    """(wall clock µs, since-boot µs, MESSAGE) per entry of a journal export
    file (Journal Export Format: NAME=value lines, binary fields as NAME, a
    64-bit little-endian length and the bytes; an empty line ends an entry)."""
    out, entry, i = [], {}, 0
    while i < len(data):
        nl = data.find(b"\n", i)
        if nl < 0:
            break
        line = data[i:nl]
        if not line:
            if "__REALTIME_TIMESTAMP" in entry and "__MONOTONIC_TIMESTAMP" in entry:
                out.append((int(entry["__REALTIME_TIMESTAMP"]), int(entry["__MONOTONIC_TIMESTAMP"]),
                            entry.get("MESSAGE", "")))
            entry, i = {}, nl + 1
        elif b"=" in line:
            name, _, value = line.partition(b"=")
            entry[name.decode()] = value.decode(errors="replace")
            i = nl + 1
        else:
            size = int.from_bytes(data[nl + 1:nl + 9], "little")
            i = nl + 9 + size + 1
    return out


def program_of(exe):
    name = exe.rsplit("/", 1)[-1]
    if name.startswith("python"):
        return "python3"
    if name in ("bash", "sh", "dash"):
        return "sh"
    return name


def standin(day, broken=None):
    """Reads the recorded sources of a day into events, the way Logbook must.
    broken: one of BREAKS, to prove the comparison notices a wrong reader."""
    src = pathlib.Path(day) / "sources"
    start = json.loads((src / "start.json").read_text())
    out = []
    for line in (src / "pacman.log").read_text(errors="replace").splitlines():
        m = ALPM.search(line)
        if not m:
            continue
        what, pkg, ver = m.groups()
        if what in ("upgraded", "downgraded"):
            old, new = ver.split(" -> ")
            if broken == "skip-upgrades":
                continue
            out.append(("upgraded", pkg, old, new))
        elif what == "installed":
            out.append(("installed", pkg, ver + ("x" if broken == "version-off" else "")))
        elif what == "removed" and broken != "ignore-removals":
            out.append(("removed", pkg, ver))
    for c in json.loads((src / "coredumps.json").read_text() or "[]"):
        sig = c["sig"] + (1 if broken == "wrong-signal" else 0)
        out.append(("crash", program_of(c["exe"]), sig))
    entries = [e for e in journal_entries((src / "journal.export").read_bytes()) if e[1] >= start["since_boot_us"]]
    sleeps = sum(1 for e in entries if e[2].startswith("PM: suspend entry ("))
    if broken != "drop-sleeps":
        out += [("sleep",)] * sleeps
    offsets = [r - m for r, m, _ in entries]
    for a, b in zip(offsets, offsets[1:]):
        gap = (b - a) / 1e6
        if abs(gap) >= MIN_JUMP_S:
            hours = round(gap / 3600)
            if broken == "forward-only" and hours < 0:
                continue
            out.append(("clock-jump", hours))
    return out


BREAKS = ["skip-upgrades", "version-off", "ignore-removals", "wrong-signal", "drop-sleeps", "forward-only"]
# Breaks every day can show: the plan holds each kind of step at least once.
# forward-only needs a backward jump, which a day may not have.
ALWAYS_SHOWN = ["skip-upgrades", "version-off", "ignore-removals", "wrong-signal", "drop-sleeps"]


def compare(expected, got):
    """Missing and unexpected events; both empty means the reader is right."""
    e, g = collections.Counter(expected), collections.Counter(got)
    return sorted((e - g).elements()), sorted((g - e).elements())


def check_day(day, out=print):
    """Compares the stand-in with the harness, then proves every break is
    noticed. Returns the number of problems."""
    expected = harness_events(day)
    bad = 0
    if not expected:
        out("WRONG:  the harness log has no events; a day of nothing proves nothing")
        return 1
    missing, extra = compare(expected, standin(day))
    for ev in missing:
        out(f"WRONG:  the harness did {ev}, but the reader didn't find it")
    for ev in extra:
        out(f"WRONG:  the reader found {ev}, which the harness didn't do")
    bad += bool(missing or extra)
    if not (missing or extra):
        out(f"right:  the reader found exactly the {len(expected)} events the harness made")
    for b in BREAKS:
        shown = compare(expected, standin(day, broken=b)) != ([], [])
        if shown:
            out(f"right:  broken reader ({b}) -> the comparison fails")
        elif b in ALWAYS_SHOWN or (b == "forward-only" and any(e[0] == "clock-jump" and e[1] < 0 for e in expected)):
            out(f"WRONG:  broken reader ({b}) -> the comparison didn't notice")
            bad += 1
        else:
            out(f"(this day has no step that break {b} would change)")
    return bad


# ------------------------------------------------- self-test, no computer

def fake_day(seed, folder):
    """A synthetic recording of a plan, as a perfect test computer would make
    it: the harness log and the sources, written independently of standin()."""
    folder = pathlib.Path(folder)
    (folder / "sources").mkdir(parents=True)
    p = plan(seed, packages=["aa", "bb", "cc", "dd"])
    harness, pac, cores, journal = [], [], [], []
    real, mono = 1_800_000_000_000_000, 60_000_000
    versions = {}

    def tick(seconds):
        nonlocal real, mono
        real += int(seconds * 1e6)
        mono += int(seconds * 1e6)
        journal.append((real, mono, "tick"))

    for s in p["steps"]:
        k = s["kind"]
        if k in ("install", "upgrade"):
            if k == "upgrade":
                pac.append(f"[ALPM] installed {s['package']} (1.0-1)")
                harness.append({"action": "installed", "package": s["package"], "version": "1.0-1"})
                pac.append(f"[ALPM] upgraded {s['package']} (1.0-1 -> 1.1-1)")
                harness.append({"action": "upgraded", "package": s["package"], "from": "1.0-1", "to": "1.1-1"})
                versions[s["package"]] = "1.1-1"
            else:
                pac.append(f"[ALPM] installed {s['package']} (2.0-1)")
                harness.append({"action": "installed", "package": s["package"], "version": "2.0-1"})
                versions[s["package"]] = "2.0-1"
        elif k == "remove":
            ver = versions.pop(s["package"])
            pac.append(f"[ALPM] removed {s['package']} ({ver})")
            harness.append({"action": "removed", "package": s["package"], "version": ver})
        elif k == "crash":
            exe = {"python3": "/usr/bin/python3.14", "sleep": "/usr/bin/sleep", "sh": "/usr/bin/bash"}[s["program"]]
            cores.append({"exe": exe, "sig": SIGNALS[s["signal"]], "uid": 1000})
            harness.append({"action": "crash", "program": s["program"], "signal": SIGNALS[s["signal"]]})
        elif k == "sleep":
            journal.append((real, mono, "PM: suspend entry (deep)"))
            real += s["seconds"] * 1_000_000     # the wall clock runs on, since-boot time doesn't
            journal.append((real, mono, "PM: suspend exit"))
            harness.append({"action": "sleep", "seconds": s["seconds"]})
        elif k == "clock-jump":
            real += s["hours"] * 3_600_000_000
            harness.append({"action": "clock-jump", "hours": s["hours"]})
        tick(s["pause"])
    export = b"".join(f"__REALTIME_TIMESTAMP={r}\n__MONOTONIC_TIMESTAMP={m}\nMESSAGE={msg}\n\n".encode()
                      for r, m, msg in journal)
    (folder / "harness.jsonl").write_text("".join(json.dumps(h) + "\n" for h in harness))
    (folder / "sources" / "pacman.log").write_text("".join(f"[2026-01-01T00:00:00+0000] {l}\n" for l in pac))
    (folder / "sources" / "coredumps.json").write_text(json.dumps(cores))
    (folder / "sources" / "journal.export").write_bytes(export)
    (folder / "sources" / "start.json").write_text(json.dumps({"since_boot_us": 0}))
    return p


def selftest():
    import tempfile
    bad = 0

    def report(ok, text):
        nonlocal bad
        print(f"{'right' if ok else 'WRONG'}:  {text}")
        bad += not ok

    pk = ["aa", "bb", "cc", "dd"]
    report(plan(7, packages=pk) == plan(7, packages=pk), "the same seed gives the same day")
    days = {json.dumps(plan(s, packages=pk)["steps"]) for s in range(300)}
    report(len(days) == 300, f"300 seeds give 300 different days ({len(days)})")
    valid = True
    for s in range(300):
        installed, kinds = set(), set()
        for st in plan(s, packages=pk)["steps"]:
            kinds.add(st["kind"])
            if st["kind"] in ("install", "upgrade"):
                valid &= st["package"] not in installed
                installed.add(st["package"])
            elif st["kind"] == "remove":
                valid &= st["package"] in installed
                installed.discard(st["package"])
        valid &= kinds == set(KINDS)
    report(valid, "every day has each kind of step, and each step can happen where it is")
    report(plan(7, "arch", pk) != plan(7, "debian", pk), "the same seed gives another day on another distribution")
    for seed in (1, 2, 3, 42, 1234):
        with tempfile.TemporaryDirectory() as tmp:
            fake_day(seed, tmp)
            lines = []
            n = check_day(tmp, out=lines.append)
            report(n == 0, f"synthetic day {seed}: correct reader passes, every break is noticed"
                   + ("" if n == 0 else ":\n    " + "\n    ".join(lines)))
    # A comparison that always passes must be caught too.
    with tempfile.TemporaryDirectory() as tmp:
        fake_day(5, tmp)
        h = pathlib.Path(tmp) / "harness.jsonl"
        h.write_text(h.read_text() + json.dumps({"action": "sleep", "seconds": 5}) + "\n")
        report(check_day(tmp, out=lambda _: None) > 0, "a step the sources don't show -> the day fails")
        h.write_text("")
        report(check_day(tmp, out=lambda _: None) > 0, "an empty harness log -> the day fails")
    print(f"Fresh-day self-test {'passed' if not bad else 'failed'}.")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan"); p.add_argument("seed", type=int); p.add_argument("--distro", default="arch")
    p = sub.add_parser("compare"); p.add_argument("day")
    sub.add_parser("selftest")
    a = ap.parse_args()
    if a.cmd == "plan":
        print(json.dumps(plan(a.seed, a.distro), indent=1))
        return 0
    if a.cmd == "compare":
        n = check_day(a.day)
        print(f"Fresh day {'passed' if not n else 'failed'}.")
        return 1 if n else 0
    return selftest()


if __name__ == "__main__":
    sys.exit(main())

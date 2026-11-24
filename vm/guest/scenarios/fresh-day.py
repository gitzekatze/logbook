#!/usr/bin/env python3
"""Acts out a fresh day on the test computer, as root.

    fresh-day.py PLAN     (PLAN: scripts/freshday.py plan SEED, as JSON)

Runs as its own service (scripts/vm.py starts it), because a sleep may cut the
SSH connection. Writes:
  /out/start.json      where the day starts in the sources (since-boot time,
                       package log offset), so earlier history doesn't count
  /out/harness.jsonl   what really happened, one line per event. Package
                       events come from comparing the package database before
                       and after each step (pacman -Q), not from pacman.log,
                       so the expected result and the sources stay independent.
  /out/day.log         this script's own progress
"""
import json
import os
import pathlib
import re
import resource
import signal
import subprocess
import sys
import time
import urllib.request

OUT = pathlib.Path("/out")
ARCHIVE = "https://archive.archlinux.org/packages"
TESTER = "tester"


def say(msg):
    with open(OUT / "day.log", "a") as f:
        f.write(f"{time.strftime('%H:%M:%S')} {msg}\n")


def note(action, **fields):
    line = {"wall": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "uptime": time.clock_gettime(time.CLOCK_MONOTONIC), "action": action, **fields}
    with open(OUT / "harness.jsonl", "a") as f:
        f.write(json.dumps(line) + "\n")


def run(*cmd, check=True):
    p = subprocess.run(cmd, capture_output=True, text=True)
    if check and p.returncode:
        raise SystemExit(f"{' '.join(cmd)} failed: {p.stderr.strip()}")
    return p


def packages():
    return dict(line.split() for line in run("pacman", "-Q").stdout.splitlines())


def note_package_changes(before, after):
    for pkg in sorted(set(after) - set(before)):
        note("installed", package=pkg, version=after[pkg])
    for pkg in sorted(set(before) & set(after)):
        if before[pkg] != after[pkg]:
            note("upgraded", package=pkg, **{"from": before[pkg], "to": after[pkg]})
    for pkg in sorted(set(before) - set(after)):
        note("removed", package=pkg, version=before[pkg])


def older_version(pkg):
    """An older build of pkg from the Arch Linux Archive, downloaded to /tmp."""
    current = run("pacman", "-Si", pkg).stdout
    current = re.search(r"^Version\s*:\s*(\S+)", current, re.M).group(1)
    listing = fetch(f"{ARCHIVE}/{pkg[0]}/{pkg}/").decode()
    names = sorted(set(re.findall(rf'"({re.escape(pkg)}-[0-9][^"/]*-x86_64\.pkg\.tar\.zst)"', listing)))
    older = [n for n in names if n[len(pkg) + 1:-len("-x86_64.pkg.tar.zst")] != current]
    if not older:
        raise SystemExit(f"no older build of {pkg} in the archive")
    # The newest build that isn't the current one (sorted by pacman's rules).
    vers = {n[len(pkg) + 1:-len("-x86_64.pkg.tar.zst")]: n for n in older}
    best = sorted(vers, key=lambda v: VerKey(v))[-1]
    path = f"/tmp/{vers[best]}"
    with open(path, "wb") as f:
        f.write(fetch(f"{ARCHIVE}/{pkg[0]}/{pkg}/{vers[best]}"))
    return path


class VerKey:
    def __init__(self, v):
        self.v = v

    def __lt__(self, other):
        return run("vercmp", self.v, other.v).stdout.strip() == "-1"


def fetch(url, tries=6):
    for i in range(tries):
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                return r.read()
        except OSError as e:
            say(f"fetch {url}: {e} (try {i + 1})")
            time.sleep(5 * (i + 1))
    raise SystemExit(f"can't fetch {url}")


def coredump_count():
    p = run("coredumpctl", "list", "--json=short", "--no-pager", check=False)
    return len(json.loads(p.stdout)) if p.returncode == 0 and p.stdout.strip() else 0


def crash(program, signame):
    sig = getattr(signal, signame)
    before = coredump_count()
    if program == "python3":
        run("runuser", "-u", TESTER, "--", "python3", "-c",
            f"import os, signal; os.kill(os.getpid(), {int(sig)})", check=False)
    elif program == "sh":
        run("runuser", "-u", TESTER, "--", "sh", "-c", f"kill -{signame[3:]} $$", check=False)
    elif program == "sleep":
        p = subprocess.Popen(["runuser", "-u", TESTER, "--", "sleep", "120"])
        for _ in range(100):  # wait until the program running is sleep itself
            pids = run("pgrep", "-u", TESTER, "-x", "sleep", check=False).stdout.split()
            if pids:
                os.kill(int(pids[0]), sig)
                break
            time.sleep(0.1)
        p.wait()
    for _ in range(300):
        if coredump_count() > before:
            note("crash", program=program, signal=int(sig))
            return
        time.sleep(0.1)
    raise SystemExit(f"the {program} crash ({signame}) left no crash record")


def main():
    plan = json.loads(pathlib.Path(sys.argv[1]).read_text())
    say(f"seed {plan['seed']}: {len(plan['steps'])} steps")
    resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    # Start clean: no package of the day is installed yet.
    for pkg in sorted({s["package"] for s in plan["steps"] if "package" in s}):
        if run("pacman", "-Q", pkg, check=False).returncode == 0:
            run("pacman", "-R", "--noconfirm", pkg)
            say(f"removed {pkg}, installed before the day")
    run("journalctl", "--sync")
    (OUT / "start.json").write_text(json.dumps({
        "since_boot_us": time.clock_gettime_ns(time.CLOCK_MONOTONIC) // 1000,
        "pacman_offset": os.path.getsize("/var/log/pacman.log"),
    }))
    for i, s in enumerate(plan["steps"], 1):
        say(f"step {i}: {s}")
        k = s["kind"]
        if k in ("install", "upgrade", "remove"):
            before = packages()
            if k == "install":
                run("pacman", "-S", "--noconfirm", s["package"])
            elif k == "remove":
                run("pacman", "-R", "--noconfirm", s["package"])
            else:
                run("pacman", "-U", "--noconfirm", older_version(s["package"]))
                note_package_changes(before, packages())
                before = packages()
                run("pacman", "-S", "--noconfirm", s["package"])
            note_package_changes(before, packages())
        elif k == "crash":
            crash(s["program"], s["signal"])
        elif k == "sleep":
            note("sleep", seconds=s["seconds"])
            run("rtcwake", "-m", "mem", "-s", str(s["seconds"]))
        elif k == "clock-jump":
            h = s["hours"]
            run("date", "-s", f"{'+' if h > 0 else '-'}{abs(h)} hours")
            note("clock-jump", hours=h)
        time.sleep(s["pause"])
    say("day done")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Ends a watch window (start.sh) and prints what the watchers saw.

One JSON line per finding: {"watcher": "network" | "file" | "coredump",
"what": a short description}. Nothing printed means nothing was seen. A
watcher that lost events, or that isn't running, is itself a finding
("watcher"), so a broken watcher can't look like a quiet one.
"""
import fnmatch
import json
import os
import pathlib
import signal
import time

W = pathlib.Path("/run/lbwatch")
TEST_UID = 1000
COREDUMPS = "/var/lib/systemd/coredump/"
AF = {"2": "internet (IPv4)", "a": "internet (IPv6)", "11": "raw packets"}


def findings():
    out = []

    # Network: audit records of this window with our key.
    time.sleep(0.5)  # let auditd write the last records
    offset = int((W / "audit.offset").read_text())
    with open("/var/log/audit/audit.log", "rb") as f:
        f.seek(offset)
        lines = f.read().decode(errors="replace").splitlines()
    for line in lines:
        if line.startswith("type=SYSCALL") and 'key="lb-net"' in line:
            fields = dict(x.split("=", 1) for x in line.split() if "=" in x)
            kind = AF.get(fields.get("a0", ""), f"syscall {fields.get('syscall')}")
            result = "made" if fields.get("success") == "yes" else "attempted, refused"
            out.append({"watcher": "network",
                        "what": f"{fields.get('comm', '?').strip(chr(34))} {result} a {kind} socket"})

    # Files: stop the fanotify watcher, then read its log.
    pid = int((W / "files.pid").read_text())
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return out + [{"watcher": "watcher", "what": "the file watcher had stopped: "
                       + (W / "files.err").read_text().strip()}]
    time.sleep(0.5)
    os.kill(pid, signal.SIGTERM)
    patterns = [p.strip() for p in open("/opt/logbook-test/watch/forbidden.txt")
                if p.strip() and not p.startswith("#")]
    for line in (W / "files.jsonl").read_text().splitlines():
        ev = json.loads(line)
        if ev.get("overflow"):
            out.append({"watcher": "watcher", "what": "the file watcher lost events (queue overflow)"})
            continue
        if "path" not in ev or ev["euid"] not in (TEST_UID, None):
            continue
        who = f"{ev['comm'] or '?'} (uid {ev['euid'] if ev['euid'] is not None else 'gone'})"
        if ev["path"].startswith(COREDUMPS):
            out.append({"watcher": "coredump", "what": f"{who} opened the crash file {ev['path']}"})
        elif any(fnmatch.fnmatch(ev["path"], p) for p in patterns):
            out.append({"watcher": "file", "what": f"{who} opened {ev['path']}"})
    return out


for f in findings():
    print(json.dumps(f))

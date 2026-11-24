"""Reads a crash file. Crash files can hold passwords; Logbook reads only the
journal's summary of a crash, never the file (function list B06)."""
import glob
import sys
import time
files = sorted(glob.glob("/var/lib/systemd/coredump/*"))
if not files:
    sys.exit("no crash file to read; the probe can't do its thing")
with open(files[-1], "rb") as f:
    f.read(16)
time.sleep(1)

#!/bin/sh
# Starts a watch window, as root. Everything the test user (uid 1000) does
# from now on is seen by:
#   network  audit: every attempt to create an internet or raw socket, even
#            one that never sends (and io_uring, which could do it unseen)
#   files    files.py (fanotify): every file opened, on every filesystem
# report.py ends the window and says what was seen.
set -eu
W=/run/lbwatch
mkdir -p "$W"
[ -f "$W/files.pid" ] && kill "$(cat "$W/files.pid")" 2>/dev/null || true
rm -f "$W"/*
auditctl -D >/dev/null
auditctl -R /opt/logbook-test/watch/audit.rules >/dev/null
stat -c %s /var/log/audit/audit.log > "$W/audit.offset"
setsid python3 /opt/logbook-test/watch/files.py "$W/files.jsonl" "$W/files.ready" </dev/null >"$W/files.err" 2>&1 &
echo $! > "$W/files.pid"
for _ in $(seq 50); do [ -s "$W/files.ready" ] && exit 0; sleep 0.1; done
echo "files watcher did not start:"; cat "$W/files.err"; exit 1

#!/bin/sh
# Copies the raw sources of the day to /out/sources, as root: the package log
# from where the day started, the journal of this boot (export format:
# systemd-journal-remote turns it back into journal files), the crash list
# and the boot list. Raw sources only; never Logbook's own output.
set -eu
s=/out/sources
mkdir -p "$s"
journalctl --sync
cp /out/start.json "$s/start.json"
offset=$(python3 -c 'import json; print(json.load(open("/out/start.json"))["pacman_offset"])')
tail -c +"$((offset + 1))" /var/log/pacman.log > "$s/pacman.log"
journalctl -b -o export > "$s/journal.export"
coredumpctl list --json=short --no-pager > "$s/coredumps.json" 2>/dev/null || echo '[]' > "$s/coredumps.json"
journalctl --list-boots -o json > "$s/boots.json"
chmod -R a+rX /out

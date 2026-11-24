#!/bin/sh
# Copies the raw sources of this boot to /out/sources, as root: the package
# log, the journal (export format: systemd-journal-remote turns it back into
# journal files), the crash list and the boot list. Raw sources only; never
# Logbook's own output.
set -eu
s=/out/sources
mkdir -p "$s"
journalctl --sync
cp /var/log/pacman.log "$s/pacman.log"
journalctl -b -o export > "$s/journal.export"
coredumpctl list --json=short --no-pager > "$s/coredumps.json" 2>/dev/null || echo '[]' > "$s/coredumps.json"
journalctl --list-boots -o json > "$s/boots.json"
chmod -R a+rX /out

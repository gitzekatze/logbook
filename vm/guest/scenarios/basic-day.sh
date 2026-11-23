#!/bin/sh
# One small day with one of each kind of event Logbook 0.1a records:
# install, upgrade, crash, sleep, clock jump, removal. Real packages from the
# distribution's real servers; every step is noted in /out/harness.jsonl.
set -eu
. /opt/logbook-test/scenarios/lib.sh
pkg=tree

old=$(curl -fsS "https://archive.archlinux.org/packages/${pkg%"${pkg#?}"}/$pkg/" \
      | grep -o "$pkg-[0-9][^\"]*-x86_64.pkg.tar.zst\"" | tr -d '"' | tail -2 | head -1)
oldver=$(echo "$old" | sed "s/^$pkg-//; s/-x86_64.pkg.tar.zst$//")
# The archive is slow at times: fetch with retries, then install the file.
curl -fsS --retry 5 --retry-all-errors --connect-timeout 20 -o "/tmp/$old" \
    "https://archive.archlinux.org/packages/${pkg%"${pkg#?}"}/$pkg/$old"
pacman -U --noconfirm "/tmp/$old" >/dev/null
note install package=$pkg version=$oldver
sleep 2

pacman -S --noconfirm $pkg >/dev/null
note upgrade package=$pkg from=$oldver to="$(pacman -Q $pkg | cut -d' ' -f2)"
sleep 2

ulimit -c unlimited
runuser -u tester -- python3 -c 'import os, signal; os.kill(os.getpid(), signal.SIGSEGV)' || true
note crash user=tester program=python3 signal=SIGSEGV
sleep 3

note sleep-start mode=mem seconds=10
rtcwake -m mem -s 10 >/dev/null
note sleep-end
sleep 2

date -s '+2 hours' >/dev/null
note clock-jump by=+2h
sleep 2

pacman -R --noconfirm $pkg >/dev/null
note remove package=$pkg

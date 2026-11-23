#!/bin/sh
# Runs one probe as the test user (uid 1000), as root: probes/run.sh NAME
# Each probe does exactly one thing a watcher must see (or, "quiet",
# nothing at all). Exit 0 = the probe did its thing; anything else means the
# probe itself is broken, which the self-test reports.
set -eu
name=$1
if [ "$name" = coredump ]; then
    # A crash of the test user's own program, so a crash file exists that the
    # user may read (systemd-coredump grants the owner access).
    before=$(ls /var/lib/systemd/coredump 2>/dev/null | wc -l)
    # The login session's core limit is 0; root raises it for this crash only.
    ulimit -c unlimited
    runuser -u tester -- sh -c 'sleep 30 & kill -SEGV $!; wait' || true
    for _ in $(seq 300); do
        [ "$(ls /var/lib/systemd/coredump 2>/dev/null | wc -l)" -gt "$before" ] && break
        sleep 0.1
    done
fi
cd /tmp
exec runuser -u tester -- python3 "/opt/logbook-test/probes/$name.py"

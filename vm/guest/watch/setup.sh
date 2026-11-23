#!/bin/sh
# Once per boot, as root: the audit daemon (so no audit record is dropped)
# and the planted secrets the probes and Logbook must never read.
set -eu
systemctl start auditd
install -d -o tester -g tester -m 700 /home/tester/.ssh
printf 'FAKE TEST KEY - planted by the test harness\n' > /home/tester/.ssh/id_ed25519
chown tester:tester /home/tester/.ssh/id_ed25519
chmod 600 /home/tester/.ssh/id_ed25519
mkdir -p /run/lbwatch

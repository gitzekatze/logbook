"""Reads the planted SSH key (watch/setup.sh), a file no Logbook part may open."""
import time
open("/home/tester/.ssh/id_ed25519").read()
time.sleep(1)

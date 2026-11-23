"""Does nothing a watcher should report: reads an ordinary file."""
import time
open("/etc/os-release").read()
time.sleep(1)

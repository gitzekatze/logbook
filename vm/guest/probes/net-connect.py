"""Opens an internet connection (to the host's discard port; refused or not)."""
import socket
import time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
s.connect_ex(("10.0.2.2", 9))
s.close()
time.sleep(1)

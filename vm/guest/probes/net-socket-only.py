"""Creates an internet socket and never sends anything: still a finding."""
import socket
import time
socket.socket(socket.AF_INET6, socket.SOCK_DGRAM).close()
time.sleep(1)

#!/usr/bin/env python3
"""File watcher: every file opened on the test computer, through fanotify.

    files.py LOG READY

Marks every filesystem (or, where that isn't possible, every mount) for
"opened" and "opened to run" events. fanotify works below the system calls,
so an open through io_uring or any other path is seen too.

It uses permission events: the opening process waits until this watcher has
looked it up and answered "allow" (it always allows). So the process can't be
gone before its user is known, and every event has a real euid. Each event is
written to LOG as one JSON line: pid, euid, comm and path. Root's own events
are left out unless they touch a crash file; report.py decides what is a
finding. If the watcher dies, the kernel lets waiting opens through.

Runs as root (fanotify needs CAP_SYS_ADMIN), until it is killed.
"""
import ctypes
import json
import os
import struct
import sys

FAN_CLOEXEC = 0x1
FAN_CLASS_CONTENT = 0x4
FAN_ALLOW = 0x1
FAN_UNLIMITED_QUEUE = 0x10
FAN_MARK_ADD = 0x1
FAN_MARK_MOUNT = 0x10
FAN_MARK_FILESYSTEM = 0x100
FAN_OPEN_PERM = 0x10000
FAN_OPEN_EXEC_PERM = 0x40000
FAN_Q_OVERFLOW = 0x4000
AT_FDCWD = -100
META = struct.Struct("IBBHQii")
RESPONSE = struct.Struct("iI")
COREDUMPS = "/var/lib/systemd/coredump/"
SKIP_FS = {"proc", "sysfs", "cgroup2", "devpts", "mqueue", "debugfs", "tracefs", "securityfs",
           "pstore", "bpf", "configfs", "fusectl", "hugetlbfs", "efivarfs", "autofs", "binfmt_misc"}

libc = ctypes.CDLL(None, use_errno=True)
libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p]


def mounts():
    seen = set()
    with open("/proc/self/mountinfo") as f:
        for line in f:
            left, right = line.split(" - ", 1)
            point = left.split()[4].replace("\\040", " ")
            fstype = right.split()[0]
            if fstype not in SKIP_FS and point not in seen:
                seen.add(point)
                yield point


def euid(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("Uid:"):
                    return int(line.split()[2])
    except OSError:
        return None
    return None


def comm(pid):
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except OSError:
        return None


def main():
    log_path, ready = sys.argv[1], sys.argv[2]
    # Everything the loop below needs is opened and loaded BEFORE the marks:
    # with permission events, an open by this watcher itself would wait for
    # this watcher's own answer, forever.
    me = os.getpid()
    log = open(log_path, "a", buffering=1)
    ready_file = open(ready, "w")  # written (not opened) once the marks are set
    log.write(json.dumps({"pid": me, "euid": euid(me), "comm": comm(me), "path": os.readlink("/proc/self/exe")})[:0])
    RESPONSE.pack(0, FAN_ALLOW)
    META.unpack_from(bytes(META.size))
    fd = libc.fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_UNLIMITED_QUEUE, os.O_RDONLY | os.O_LARGEFILE)
    if fd < 0:
        raise SystemExit(f"fanotify_init: {os.strerror(ctypes.get_errno())}")
    marked = []
    for point in mounts():
        for how in (FAN_MARK_FILESYSTEM, FAN_MARK_MOUNT):
            if libc.fanotify_mark(fd, FAN_MARK_ADD | how, FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM, AT_FDCWD, point.encode()) == 0:
                marked.append(point)
                break
        else:
            print(f"files.py: can't watch {point}: {os.strerror(ctypes.get_errno())}", file=sys.stderr)
    if "/" not in marked:
        raise SystemExit("files.py: the root filesystem can't be watched; refusing to pretend")
    with log:
        log.write(json.dumps({"watching": marked}) + "\n")
        ready_file.write("ready\n")
        ready_file.close()
        while True:
            buf = os.read(fd, 65536)
            off = 0
            while off + META.size <= len(buf):
                length, _, _, _, mask, efd, pid = META.unpack_from(buf, off)
                off += length
                if mask & FAN_Q_OVERFLOW:
                    log.write(json.dumps({"overflow": True}) + "\n")
                    continue
                if efd < 0:
                    continue
                try:
                    path = os.readlink(f"/proc/self/fd/{efd}")
                    uid, name = (0, None) if pid == me else (euid(pid), comm(pid))
                finally:
                    os.write(fd, RESPONSE.pack(efd, FAN_ALLOW))
                    os.close(efd)
                if pid == me:
                    continue
                if uid == 0 and not path.startswith(COREDUMPS):
                    continue
                log.write(json.dumps({"pid": pid, "euid": uid, "comm": name, "path": path}) + "\n")


if __name__ == "__main__":
    main()

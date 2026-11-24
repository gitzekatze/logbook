#!/usr/bin/env python3
"""Facts about a distribution as it ships: the VERIFY points of Logbook's
function list (build plan step P8). Runs as root on an untouched copy of the
official image; "tester" (uid 1000) is the normal user.

    facts.py OUT.json

Facts about the system as shipped are taken first. Then one small package is
installed with the distribution's own package manager, so that its logs have
an entry to look at, and a few tools are added to test how they behave for a
normal user. Every fact records how it was found (command, exit code, output
excerpt); a fact that couldn't be found says why instead of guessing.
"""
import json
import os
import pathlib
import platform
import shutil
import stat
import subprocess
import sys
import time

USER = "tester"
F = {}


def run(cmd, user=None, timeout=600):
    """cmd (a shell string), as root or as the normal user."""
    full = ["runuser", "-u", USER, "--", "sh", "-c", cmd] if user else ["sh", "-c", cmd]
    try:
        p = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return {"cmd": cmd, "as": user or "root", "exit": p.returncode,
                "out": p.stdout[-1500:], "err": p.stderr[-800:]}
    except subprocess.TimeoutExpired:
        return {"cmd": cmd, "as": user or "root", "exit": None, "err": f"timed out after {timeout} s"}


def file_info(path):
    p = pathlib.Path(path)
    if not p.exists():
        return {"path": path, "exists": False}
    s = p.stat()
    import grp
    import pwd
    info = {"path": path, "exists": True, "mode": oct(stat.S_IMODE(s.st_mode)),
            "owner": pwd.getpwuid(s.st_uid).pw_name, "group": grp.getgrgid(s.st_gid).gr_name}
    if shutil.which("getfacl"):
        info["acl"] = run(f"getfacl -p {path} 2>/dev/null | grep -v '^#'")["out"].split()
    info["tester_can_read"] = run(f"cat {path} >/dev/null 2>&1 || test -x {path}", user=True)["exit"] == 0
    parent = p.parent
    ps = parent.stat()
    info["folder"] = {"path": str(parent), "mode": oct(stat.S_IMODE(ps.st_mode)),
                      "owner": pwd.getpwuid(ps.st_uid).pw_name, "group": grp.getgrgid(ps.st_gid).gr_name}
    return info


def os_release():
    out = {}
    for line in pathlib.Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v.strip('"')
    return out


def family(osr):
    ids = [osr.get("ID", "")] + osr.get("ID_LIKE", "").split()
    for fam in ("arch", "debian", "fedora", "suse"):
        if any(fam in i for i in ids):
            return fam
    return "unknown"


INSTALL = {
    "arch": "pacman -Sy --noconfirm {p}",
    "debian": "apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -yq {p}",
    "fedora": "dnf install -y -q {p}",
    "suse": "zypper -n -q install {p}",
}
OWNER = {"arch": "pacman -Qo /usr/bin/bash", "debian": "dpkg -S /usr/bin/bash",
         "fedora": "rpm -qf /usr/bin/bash", "suse": "rpm -qf /usr/bin/bash"}


def journal():
    conf = run("cat /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf "
               "/usr/lib/systemd/journald.conf.d/*.conf 2>/dev/null | grep -i '^ *Storage'")
    reads = run("journalctl --system -b -n 5 -q --no-pager -o short 2>&1; echo LINES=$(journalctl --system -b -q --no-pager 2>/dev/null | wc -l)", user=True)
    return {
        "persistent_folder": file_info("/var/log/journal"),
        "volatile_folder": file_info("/run/log/journal"),
        "storage_setting": conf["out"].strip() or "not set (default: persistent if /var/log/journal exists)",
        "tester_groups": run(f"id {USER}")["out"].strip(),
        "tester_reads_system_journal": reads,
        "journal_groups": run("getent group systemd-journal adm wheel")["out"].strip(),
        "reads_system_journal_by_group": journal_by_group(),
    }


def journal_by_group():
    """For each candidate group: a fresh user in only that group, and whether
    it sees system messages. Tests what really grants access, ACLs included."""
    out = {}
    for i, g in enumerate(("systemd-journal", "adm", "wheel", "sudo")):
        if run(f"getent group {g}")["exit"] != 0:
            out[g] = "group doesn't exist"
            continue
        name = f"jprobe{i}"
        run(f"useradd -M -G {g} {name}")
        r = run(f"runuser -u {name} -- journalctl --system -b -q --no-pager 2>/dev/null | wc -l")
        out[g] = int(r["out"].strip() or 0) > 0
        run(f"userdel {name}")
    return out


def crashes():
    return {
        "core_pattern": pathlib.Path("/proc/sys/kernel/core_pattern").read_text().strip(),
        "coredump_folder": file_info("/var/lib/systemd/coredump"),
        "coredumpctl_present": bool(shutil.which("coredumpctl")),
        "apport_present": pathlib.Path("/usr/share/apport").exists(),
        "abrt_present": bool(shutil.which("abrt-cli")),
    }


def packages(fam):
    out = {"install_tree": run(INSTALL[fam].format(p="tree"))}
    if fam == "arch":
        out["pacman_log"] = file_info("/var/log/pacman.log")
        out["pacman_log_tail"] = run("tail -n 3 /var/log/pacman.log")["out"]
    if fam == "debian":
        for name, path in (("dpkg_log", "/var/log/dpkg.log"), ("apt_history", "/var/log/apt/history.log")):
            out[name] = file_info(path)
            out[name + "_tail"] = run(f"tail -n 6 {path}")["out"]
        out["dpkg_log_rotated"] = run("ls -l /var/log/dpkg.log* /var/log/apt/ 2>&1")["out"]
        out["logrotate_dpkg"] = run("cat /etc/logrotate.d/dpkg /etc/logrotate.d/apt 2>&1")["out"]
    if fam == "fedora":
        out["dnf_version"] = run("dnf --version | head -n 3")["out"]
        out["dnf5_history_json_as_user"] = run("dnf5 history list --json 2>&1 | head -c 1200", user=True)
        out["dnf5_history_json_as_root"] = run("dnf5 history list --json 2>&1 | head -c 600")
        out["dnf5_database"] = file_info("/usr/lib/sysimage/libdnf5/transaction_history.sqlite")
        out["dnf4_database"] = file_info("/var/lib/dnf/history.sqlite")
    if fam == "suse":
        out["zypp_history"] = file_info("/var/log/zypp/history")
        out["zypp_history_tail"] = run("tail -n 4 /var/log/zypp/history")["out"]
        out["zypp_conf_history"] = run("grep -i history /etc/zypp/zypp.conf 2>&1")["out"]
        out["zypp_logrotate"] = run("cat /etc/logrotate.d/zypp-history.lr /etc/logrotate.d/zypper* 2>&1")["out"]
    t0 = time.monotonic()
    owner = [run(OWNER[fam], user=True) for _ in range(5)]
    out["owner_lookup"] = {"cmd": OWNER[fam], "exit": owner[0]["exit"], "out": owner[0]["out"].strip(),
                           "seconds_per_lookup": round((time.monotonic() - t0) / 5, 3)}
    return out


def snaps():
    if not shutil.which("snap"):
        return {"snap_present": False}
    return {"snap_present": True, "snap_changes_as_user": run("snap changes 2>&1", user=True),
            "snap_changes_as_root": run("snap changes 2>&1")}


def firmware(fam):
    inst = run(INSTALL[fam].format(p="fwupd"))
    out = {"install_fwupd": {"exit": inst["exit"], "err": inst["err"][-300:]}}
    if shutil.which("fwupdmgr"):
        out["get_history_json_as_user"] = run("timeout 60 fwupdmgr get-history --json 2>&1 | head -c 800", user=True)
    for name in ("bios_version", "bios_date", "bios_vendor", "product_name"):
        out[f"dmi_{name}"] = file_info(f"/sys/class/dmi/id/{name}")
    return out


def snapshots():
    out = {"snapper_present": bool(shutil.which("snapper")), "timeshift_present": bool(shutil.which("timeshift"))}
    if out["snapper_present"]:
        out["snapper_list_as_user"] = run("snapper list 2>&1 | head -n 5", user=True)
        out["snapper_configs"] = run("ls /etc/snapper/configs 2>&1")["out"]
    out["snapshots_folder"] = file_info("/.snapshots")
    out["root_filesystem"] = run("findmnt -n -o FSTYPE /")["out"].strip()
    return out


def secure_delete():
    """Does SQLite's secure_delete clear a deleted secret in WAL mode, before
    and after a checkpoint? Run as the normal user in a fresh folder."""
    code = r'''
import sqlite3, json, os, tempfile
d = tempfile.mkdtemp()
db = os.path.join(d, "t.db")
c = sqlite3.connect(db)
c.execute("PRAGMA journal_mode=WAL")
c.execute("PRAGMA secure_delete=ON")
c.execute("CREATE TABLE t(x TEXT)")
c.execute("INSERT INTO t VALUES (?)", ("SECRET-" + "q7" * 200,))
c.commit()
c.execute("DELETE FROM t")
c.commit()
def found():
    out = {}
    for f in (db, db + "-wal"):
        out[os.path.basename(f)] = os.path.exists(f) and b"SECRET-q7" in open(f, "rb").read()
    return out
before = found()
c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
after = found()
c.close()
print(json.dumps({"sqlite": sqlite3.sqlite_version, "after_delete": before, "after_checkpoint": after}))
'''
    script = pathlib.Path("/tmp/secure_delete_test.py")
    script.write_text(code)
    script.chmod(0o644)
    r = run(f"python3 {script}", user=True)
    try:
        return json.loads(r["out"])
    except ValueError:
        return {"error": r}


def main():
    osr = os_release()
    fam = family(osr)
    F["system"] = {"id": osr.get("ID"), "version": osr.get("VERSION_ID"), "name": osr.get("PRETTY_NAME"),
                   "family": fam, "kernel": platform.release(),
                   "systemd": run("systemctl --version | head -n 1")["out"].strip()}
    F["journal"] = journal()
    F["crashes"] = crashes()
    for name, fn in (("packages", lambda: packages(fam)), ("snap", snaps), ("firmware", lambda: firmware(fam)),
                     ("snapshots", snapshots), ("sqlite_secure_delete_wal", secure_delete)):
        try:
            F[name] = fn()
        except Exception as e:  # a fact that couldn't be found says why
            F[name] = {"error": f"{type(e).__name__}: {e}"}
    pathlib.Path(sys.argv[1]).write_text(json.dumps(F, indent=1, sort_keys=True))
    os.chmod(sys.argv[1], 0o644)


if __name__ == "__main__":
    main()

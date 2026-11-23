#!/usr/bin/env python3
"""Logbook's test computers (build plan V08, step P6).

    scripts/vm.py prepare DISTRO        fetch and check the image, build the prepared disk
    scripts/vm.py run DISTRO CMD [OUT]  boot a throwaway copy, run CMD as root, fetch /out to OUT
    scripts/vm.py shell DISTRO          boot a throwaway copy and open a shell (for people)
    scripts/vm.py selftest DISTRO       prove every watcher (vm/guest/watch) with its probe
    scripts/vm.py scenario DISTRO NAME OUT
                                        act out vm/guest/scenarios/NAME.sh, record the day to
                                        OUT and check that every step left its trace

A test computer is the distribution's official image (vm/images.toml, pinned
by its SHA-256), started with QEMU. "prepare" boots it once, creates the test
user (uid 1000) and installs the watchers' tools; that prepared disk is kept
in target/vm/. Every run starts from a throwaway copy of it, which is deleted
afterwards, so no run sees what an earlier one left behind.

The harness steers the computer over SSH with a key made for target/vm/ only.
vm/guest/ is copied to /opt/logbook-test on every boot.

Resources: 2 GB of memory and 2 processors per computer (the machine rules
in the build plan). Needs: qemu-system-x86_64, qemu-img, ssh, mkfs.vfat,
mcopy, curl, and /dev/kvm.
"""
import argparse
import contextlib
import hashlib
import json
import os
import pathlib
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import tomllib

REPO = pathlib.Path(__file__).resolve().parent.parent
TARGET = REPO / "target" / "vm"
GUEST = REPO / "vm" / "guest"
MEMORY_MB = 2048
CPUS = 2
DISK = "20G"
USER = "tester"


def log(msg):
    print(f"vm: {msg}", file=sys.stderr, flush=True)


def images():
    with open(REPO / "vm" / "images.toml", "rb") as f:
        return tomllib.load(f)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def base_image(distro):
    """The official image, downloaded once and refused if its fingerprint differs."""
    spec = images()[distro]
    path = TARGET / pathlib.PurePosixPath(spec["url"]).name
    if not path.exists():
        TARGET.mkdir(parents=True, exist_ok=True)
        log(f"downloading {spec['url']}")
        part = path.with_suffix(".part")
        subprocess.run(["curl", "-fL", "--proto", "=https", "-o", str(part), spec["url"]], check=True)
        part.rename(path)
    got = sha256(path)
    if got != spec["sha256"]:
        raise SystemExit(f"vm: {path.name}: fingerprint {got} is not the pinned {spec['sha256']}; refusing it")
    return path


def ssh_key():
    key = TARGET / "key"
    if not key.exists():
        TARGET.mkdir(parents=True, exist_ok=True)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "logbook-test", "-f", str(key)], check=True)
    return key


def seed(distro, workdir):
    """cloud-init's NoCloud seed: a small FAT disk labelled CIDATA."""
    pub = (ssh_key().with_suffix(".pub")).read_text().strip()
    user_data = "\n".join([
        "#cloud-config",
        "users:",
        f"  - name: {USER}",
        "    uid: 1000",
        "    shell: /bin/bash",
        "    lock_passwd: true",
        "    sudo: ALL=(ALL) NOPASSWD:ALL",
        f"    ssh_authorized_keys: [{json.dumps(pub)}]",
        "ssh_pwauth: false",
        "",
    ])
    meta = f"instance-id: logbook-{distro}\nlocal-hostname: testbox\n"
    (workdir / "user-data").write_text(user_data)
    (workdir / "meta-data").write_text(meta)
    img = workdir / "seed.img"
    subprocess.run(["mkfs.vfat", "-n", "CIDATA", "-C", str(img), "2048"], check=True, capture_output=True)
    subprocess.run(["mcopy", "-i", str(img), str(workdir / "user-data"), str(workdir / "meta-data"), "::"], check=True)
    return img


def die_with_parent():
    import ctypes
    import signal
    ctypes.CDLL(None).prctl(1, signal.SIGKILL)  # PR_SET_PDEATHSIG


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Computer:
    """One running test computer."""

    def __init__(self, disk, seed_img, workdir):
        self.port = free_port()
        self.console = workdir / "console.log"
        self.monitor = workdir / "monitor.sock"
        cmd = [
            "qemu-system-x86_64", "-enable-kvm", "-cpu", "host",
            "-m", str(MEMORY_MB), "-smp", str(CPUS),
            "-display", "none", "-serial", f"file:{self.console}",
            "-drive", f"file={disk},if=virtio,format=qcow2",
            "-drive", f"file={seed_img},if=virtio,format=raw,readonly=on",
            "-nic", f"user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:{self.port}-:22",
            "-device", "virtio-rng-pci",
            # Sleep to memory (S3) is off by default in QEMU; scenarios need it.
            "-global", "PIIX4_PM.disable_s3=0",
            # QEMU's monitor, so the harness can wake a sleeping computer.
            "-monitor", f"unix:{self.monitor},server=on,wait=off",
        ]
        # QEMU dies with the harness, so a stopped or killed run leaves no computer behind.
        self.proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, preexec_fn=die_with_parent)

    def ssh_cmd(self, *extra):
        return ["ssh", "-i", str(ssh_key()), "-p", str(self.port),
                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-o", "BatchMode=yes", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=5",
                *extra, f"{USER}@127.0.0.1"]

    def wait(self, seconds=300):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if self.proc.poll() is not None:
                raise SystemExit(f"vm: QEMU stopped (exit {self.proc.returncode}); see {self.console}")
            if subprocess.run(self.ssh_cmd() + ["true"], capture_output=True).returncode == 0:
                return
            time.sleep(3)
        raise SystemExit(f"vm: no SSH after {seconds} s; see target/vm/last-console.log")

    def sh(self, script, check=True, capture=False, timeout=3600):
        """Run a shell script as root on the test computer."""
        p = subprocess.run(self.ssh_cmd() + ["sudo", "sh", "-c", shlex.quote(script)],
                           capture_output=capture, text=True, timeout=timeout)
        if check and p.returncode:
            raise SystemExit(f"vm: command failed (exit {p.returncode}): {script}\n{p.stderr if capture else ''}")
        return p

    def put(self, local, remote):
        tar = subprocess.Popen(["tar", "-C", str(local), "-c", "."], stdout=subprocess.PIPE)
        subprocess.run(self.ssh_cmd() + ["sudo", "sh", "-c",
                       shlex.quote(f"rm -rf {remote} && mkdir -p {remote} && tar -C {remote} -x")],
                       stdin=tar.stdout, check=True)
        tar.wait()

    def get(self, remote, local):
        local.mkdir(parents=True, exist_ok=True)
        ssh = subprocess.Popen(self.ssh_cmd() + ["sudo", "tar", "-C", remote, "-c", "."], stdout=subprocess.PIPE)
        subprocess.run(["tar", "-C", str(local), "-x"], stdin=ssh.stdout, check=True)
        ssh.wait()

    def wake(self):
        """Wakes the computer if it sleeps (QEMU's system_wakeup); harmless if awake."""
        try:
            with socket.socket(socket.AF_UNIX) as s:
                s.settimeout(5)
                s.connect(str(self.monitor))
                s.sendall(b"system_wakeup\n")
                time.sleep(0.2)
        except OSError:
            pass

    def stop(self):
        # Keep the last console output for diagnosis (the run folder is deleted).
        if self.console.exists():
            shutil.copyfile(self.console, TARGET / "last-console.log")
        if self.proc.poll() is None:
            try:
                subprocess.run(self.ssh_cmd() + ["sudo", "systemctl", "poweroff"], capture_output=True, timeout=30)
            except subprocess.TimeoutExpired:
                pass
            try:
                self.proc.wait(60)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()


def prepared(distro):
    return TARGET / f"{distro}-prepared.qcow2"


def stamp_text(distro):
    return json.dumps(images()[distro], sort_keys=True)


def prepare(distro, force=False):
    disk, stamp = prepared(distro), TARGET / f"{distro}-prepared.stamp"
    if disk.exists() and not force and stamp.exists() and stamp.read_text() == stamp_text(distro):
        return disk
    base = base_image(distro)
    disk.unlink(missing_ok=True)
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-b", base.name, "-F", "qcow2", str(disk), DISK],
                   check=True, cwd=TARGET)
    spec = images()[distro]
    with tempfile.TemporaryDirectory(dir=TARGET) as tmp:
        tmp = pathlib.Path(tmp)
        c = Computer(disk, seed(distro, tmp), tmp)
        try:
            log(f"preparing {distro} (first boot, cloud-init, packages)")
            c.wait()
            c.sh("cloud-init status --wait >/dev/null || true")
            c.sh(spec["install"].format(packages=" ".join(spec["packages"])))
            # A fixed state for every run: no automatic time sync (scenarios move the
            # clock themselves), so nothing may wait for it at boot; journal kept on disk.
            c.sh("systemctl disable --now systemd-timesyncd 2>/dev/null || true; "
                 "systemctl mask systemd-time-wait-sync.service; mkdir -p /var/log/journal")
            c.sh("sync")
        finally:
            c.stop()
    stamp.write_text(stamp_text(distro))
    log(f"prepared {disk}")
    return disk


@contextlib.contextmanager
def booted(distro):
    """A throwaway copy of the prepared computer, with vm/guest/ copied in."""
    disk = prepare(distro)
    runs = TARGET / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=runs) as tmp:
        tmp = pathlib.Path(tmp)
        overlay = tmp / "disk.qcow2"
        subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-b", str(disk), "-F", "qcow2", str(overlay)],
                       check=True)
        c = Computer(overlay, seed(distro, tmp), tmp)
        try:
            c.wait()
            c.put(GUEST, "/opt/logbook-test")
            c.sh("mkdir -p /out && chmod 755 /out")
            yield c
        finally:
            c.stop()


def run(distro, command, out):
    with booted(distro) as c:
        rc = c.sh(command, check=False).returncode
        if out:
            c.get("/out", pathlib.Path(out))
    return rc


def shell(distro):
    with booted(distro) as c:
        log(f"shell on the test computer; it is deleted when you leave")
        subprocess.run(c.ssh_cmd("-t"))
    return 0


# The watchers' proof (step P6 "done when"). Each probe does one thing; the
# watchers must report exactly the listed kinds, and nothing for "quiet".
PROBES = {
    "quiet": set(),
    "net-connect": {"network"},
    "net-socket-only": {"network"},
    "secret-file": {"file"},
    "coredump": {"coredump"},
}


def selftest(distro):
    bad = 0
    with booted(distro) as c:
        c.sh("sh /opt/logbook-test/watch/setup.sh", timeout=60)
        for probe, expected in PROBES.items():
            c.sh("sh /opt/logbook-test/watch/start.sh", timeout=60)
            ran = c.sh(f"sh /opt/logbook-test/probes/run.sh {shlex.quote(probe)}", check=False, capture=True,
                       timeout=120)
            out = c.sh("python3 /opt/logbook-test/watch/report.py", capture=True, timeout=60).stdout
            findings = [json.loads(line) for line in out.splitlines() if line.strip()]
            if ran.returncode:
                findings.append({"watcher": "probe", "what": f"the probe itself failed: {ran.stderr.strip()}"})
            got = {f["watcher"] for f in findings}
            ok = got == expected
            bad += not ok
            want = ", ".join(sorted(expected)) or "nothing"
            seen = "; ".join(f"{f['watcher']}: {f['what']}" for f in findings) or "nothing"
            print(f"{'right' if ok else 'WRONG'}:  probe {probe}: expected {want}, watchers saw {seen}")
    total = len(PROBES)
    print(f"Watcher self-test {'passed' if not bad else 'failed'}: {total - bad} of {total} probes as expected.")
    return 1 if bad else 0


# Where each harness step must leave a trace in the recorded sources. This is
# what makes a recording trustworthy as a test day: the harness log says what
# happened, and the sources must show it independently.
def traces(step, src):
    a = step["action"]
    if a == "install":
        return f"[ALPM] installed {step['package']} ({step['version']})" in src["pacman"]
    if a == "upgrade":
        return f"[ALPM] upgraded {step['package']} ({step['from']} -> {step['to']})" in src["pacman"]
    if a == "remove":
        return f"[ALPM] removed {step['package']} (" in src["pacman"]
    if a == "crash":
        return any(c.get("sig") == 11 and c.get("uid") == 1000 for c in src["coredumps"])
    if a == "sleep-start":
        return b"MESSAGE=PM: suspend entry (" in src["journal"]
    if a == "sleep-end":
        return b"MESSAGE=PM: suspend exit" in src["journal"]
    if a == "clock-jump":
        return b"MESSAGE=Time has been changed" in src["journal"]
    return False


def check_recording(out):
    out = pathlib.Path(out)
    steps = [json.loads(line) for line in (out / "harness.jsonl").read_text().splitlines()]
    src = {
        "pacman": (out / "sources" / "pacman.log").read_text(errors="replace"),
        "journal": (out / "sources" / "journal.export").read_bytes(),
        "coredumps": json.loads((out / "sources" / "coredumps.json").read_text() or "[]"),
    }
    bad = 0
    for step in steps:
        ok = traces(step, src)
        bad += not ok
        print(f"{'right' if ok else 'WRONG'}:  {step['action']} left its trace in the sources"
              if ok else f"WRONG:  {step['action']} left no trace in the sources: {step}")
    if not steps:
        print("WRONG:  the harness log is empty; a recording of nothing proves nothing")
        bad += 1
    print(f"Recording check {'passed' if not bad else 'failed'}: {len(steps) - bad} of {len(steps)} steps traced.")
    return 1 if bad else 0


def scenario(distro, name, out):
    out = pathlib.Path(out)
    if out.exists() and any(out.iterdir()):
        print(f"vm: {out} is not empty; give a new folder")
        return 2
    with booted(distro) as c:
        # The scenario runs inside the computer as its own service: sleep and
        # clock jumps may cut the SSH connection, so the harness only starts
        # it, then checks in (reconnecting as needed) until it has finished.
        c.sh(f"systemd-run --unit=lb-scenario --property=StandardOutput=file:/out/scenario.log "
             f"--property=StandardError=inherit sh /opt/logbook-test/scenarios/{shlex.quote(name)}.sh")
        started = time.monotonic()
        end = started + 900
        while True:
            if time.monotonic() > end:
                raise SystemExit("vm: the scenario didn't finish within 15 minutes")
            time.sleep(5)
            # The scenario's own alarm should end a sleep; if it doesn't fire
            # (it may not in a virtual machine), the harness wakes the computer.
            if time.monotonic() - started > 30:
                c.wake()
            try:
                p = c.sh("systemctl show -p ActiveState,Result,ExecMainStatus --value lb-scenario",
                         check=False, capture=True, timeout=30)
            except subprocess.TimeoutExpired:
                continue
            if p.returncode:
                continue
            state, result, status = (p.stdout.split() + ["", "", ""])[:3]
            if state in ("inactive", "failed"):
                break
        c.sh("sh /opt/logbook-test/scenarios/record.sh", timeout=300)
        c.get("/out", out)
    log(f"scenario {name}: {result} (exit {status}); its output is in {out / 'scenario.log'}")
    if result != "success":
        print(f"WRONG:  the scenario itself failed ({result}, exit {status}); see {out / 'scenario.log'}")
        return 1
    return check_recording(out)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prepare"); p.add_argument("distro"); p.add_argument("--force", action="store_true")
    p = sub.add_parser("run"); p.add_argument("distro"); p.add_argument("command"); p.add_argument("out", nargs="?")
    p = sub.add_parser("shell"); p.add_argument("distro")
    p = sub.add_parser("selftest"); p.add_argument("distro")
    p = sub.add_parser("scenario"); p.add_argument("distro"); p.add_argument("name"); p.add_argument("out")
    a = ap.parse_args()
    if a.distro not in images():
        print(f"vm: unknown test computer {a.distro!r}; known: {', '.join(images())}")
        return 2
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        print("vm: /dev/kvm is not usable; a test computer can't start")
        return 2
    if a.cmd == "prepare":
        prepare(a.distro, a.force)
        return 0
    if a.cmd == "run":
        return run(a.distro, a.command, a.out)
    if a.cmd == "shell":
        return shell(a.distro)
    if a.cmd == "scenario":
        return scenario(a.distro, a.name, a.out)
    return selftest(a.distro)


if __name__ == "__main__":
    sys.exit(main())

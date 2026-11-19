#!/usr/bin/env python3
"""Logbook's architecture check: which crate may do what.

    scripts/arch-check.py          check the workspace, exit 1 on any violation

The rules come from the function map ("Crates: who may do what") and turn
design intentions into limits that hold even if code is wrong:

  * only logbook-collector can reach logbook-store-write (one writer, F-D04)
  * only logbook-cli and logbook-gtk can reach logbook-undo (F-K01)
  * only logbook-readers, logbook-collector and logbook-cli can reach
    logbook-exec, the only crate that starts programs (F-L03)
    -> logbook-mcp reaches none of the three (F-J05)
  * every crate uses the workspace lints and nothing else
    (unsafe_code = "forbid", no unwrap/panic, no Command::new, no std::net)
  * only logbook-exec may allow clippy::disallowed_methods; no crate may
    allow clippy::disallowed_types
  * the programs are exactly the four known ones, and each calls
    logbook_guard::deny_network() as the first statement of main (F-L02)

"Reach" means directly or through other Logbook crates. Dev-dependencies
(tests only) are not counted: they are not built into the programs.

Its own test: scripts/arch-check-selftest.sh breaks each rule on purpose in a
scratch copy and expects this check to fail every time.
"""
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parent.parent

# target crate -> the only crates that may reach it
REACH_ONLY = {
    "logbook-store-write": {"logbook-collector"},
    "logbook-undo": {"logbook-cli", "logbook-gtk"},
    "logbook-exec": {"logbook-readers", "logbook-collector", "logbook-cli"},
}
PROGRAMS = {
    "logbook-collector": "logbook-collector",
    "logbook-cli": "logbook",
    "logbook-mcp": "logbook-mcp",
    "logbook-gtk": "logbook-gtk",
}
ALLOW_METHODS_ONLY_IN = {"logbook-exec"}
ALLOW_ATTR = re.compile(r"#!?\[\s*(?:allow|expect)\s*\(([^\]]*)\]")


def load(path):
    with open(path, "rb") as f:
        return tomllib.load(f)


def main():
    problems = []
    ws = load(ROOT / "Cargo.toml")
    members = ws["workspace"]["members"]

    on_disk = sorted(p.parent.relative_to(ROOT).as_posix() for p in (ROOT / "crates").glob("*/Cargo.toml"))
    for d in on_disk:
        if d not in members:
            problems.append(f"{d} is a crate folder but not a workspace member, so no check would see it")

    crates = {}
    for m in members:
        manifest = load(ROOT / m / "Cargo.toml")
        name = manifest["package"]["name"]
        crates[name] = (ROOT / m, manifest)

    # 1. lints: exactly the workspace lints
    for name, (_, manifest) in crates.items():
        if manifest.get("lints") != {"workspace": True}:
            problems.append(f"{name}: [lints] must be exactly `workspace = true` (forbid unsafe, no unwrap, no Command::new …)")

    # 2. who may reach whom
    deps = {}
    for name, (_, manifest) in crates.items():
        direct = set()
        for table in ("dependencies", "build-dependencies"):
            direct |= {d for d in manifest.get(table, {}) if d in crates}
        for target in manifest.get("target", {}).values():
            for table in ("dependencies", "build-dependencies"):
                direct |= {d for d in target.get(table, {}) if d in crates}
        deps[name] = direct

    def reaches(start):
        seen, todo = set(), list(deps[start])
        while todo:
            c = todo.pop()
            if c not in seen:
                seen.add(c)
                todo.extend(deps.get(c, ()))
        return seen

    for name in crates:
        r = reaches(name)
        for target, allowed in REACH_ONLY.items():
            if target in r and name not in allowed:
                problems.append(f"{name} reaches {target}; only {', '.join(sorted(allowed))} may")

    # 3. allowed lint exceptions in the source
    for name, (path, _) in crates.items():
        for rs in sorted(path.rglob("*.rs")):
            text = rs.read_text(encoding="utf-8")
            for m in ALLOW_ATTR.finditer(text):
                inner = m.group(1)
                rel = rs.relative_to(ROOT)
                if "disallowed_types" in inner:
                    problems.append(f"{rel}: allows clippy::disallowed_types (std::net); no crate may")
                if "disallowed_methods" in inner and name not in ALLOW_METHODS_ONLY_IN:
                    problems.append(f"{rel}: allows clippy::disallowed_methods; only logbook-exec may start programs")
                if "unsafe_code" in inner:
                    problems.append(f"{rel}: tries to allow unsafe_code")

    # 4. programs: exactly the known ones, network block first
    for name, (path, manifest) in crates.items():
        bins = {b["name"] for b in manifest.get("bin", [])}
        if (path / "src" / "main.rs").exists() and not bins:
            bins = {name}
        expected = {PROGRAMS[name]} if name in PROGRAMS else set()
        if bins != expected:
            problems.append(f"{name}: programs {sorted(bins)} but expected {sorted(expected)}")
        if name in PROGRAMS:
            main_rs = path / "src" / "main.rs"
            first = first_statement_of_main(main_rs) if main_rs.exists() else None
            if first is None or "logbook_guard::deny_network()" not in first:
                problems.append(f"{name}: the first statement of main must call logbook_guard::deny_network() (found: {first!r})")

    if problems:
        print("Architecture check failed:")
        for p in problems:
            print("  -", p)
        return 1
    print(f"Architecture check passed: {len(crates)} crates, {len(PROGRAMS)} programs.")
    return 0


def first_statement_of_main(path):
    """The first line of code inside `fn main`, comments and blank lines skipped."""
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        if re.match(r"\s*fn\s+main\s*\(", line):
            rest = line.split("{", 1)[1] if "{" in line else ""
            for candidate in [rest] + lines[i + 1:]:
                s = candidate.strip()
                if s and not s.startswith("//"):
                    return s
    return None


if __name__ == "__main__":
    sys.exit(main())

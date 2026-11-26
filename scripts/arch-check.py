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
  * the programs are exactly the four known ones, and each blocks the
    network as the very first statement of main, ending if that fails
    (F-L02), in exactly this form:

        fn main() -> ExitCode {
            if let Err(e) = logbook_guard::deny_network(PROFILE) {
                eprintln!(…);
                return ExitCode::FAILURE;
            }

    with `const PROFILE: logbook_guard::Profile = logbook_guard::Profile::…;`
    NoSockets for logbook-mcp, LocalSockets for the others. A `let _ =` that
    throws the guard's error away, a block that goes on instead of ending, or
    a local `logbook_guard` that shadows the real crate fails the check.

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
# The socket profile each program must declare (F-L02): logbook-mcp talks only
# through its standard input and output, so it gets no socket at all.
PROFILES = {
    "logbook-collector": "LocalSockets",
    "logbook-cli": "LocalSockets",
    "logbook-mcp": "NoSockets",
    "logbook-gtk": "LocalSockets",
}
MAIN_SIGNATURE = "fn main() -> ExitCode {"
GUARD_FIRST = "if let Err(e) = logbook_guard::deny_network(PROFILE) {"
GUARD_END = "return ExitCode::FAILURE;"
SHADOW = re.compile(r"\bmod\s+logbook_guard\b|\bas\s+logbook_guard\b|\bextern\s+crate\b[^;]*\blogbook_guard\b")
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
            problems.extend(f"{name}: {p}" for p in guard_problems(main_rs, PROFILES[name]))

    if problems:
        print("Architecture check failed:")
        for p in problems:
            print("  -", p)
        return 1
    print(f"Architecture check passed: {len(crates)} crates, {len(PROGRAMS)} programs.")
    return 0


def code_lines(text):
    """The lines of code, stripped, with blank lines and // comments left out."""
    out = []
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith("//"):
            out.append(s)
    return out


def guard_problems(main_rs, profile):
    """What is wrong with a program's network block (F-L02), as a list."""
    if not main_rs.exists():
        return ["src/main.rs is missing"]
    text = main_rs.read_text(encoding="utf-8")
    lines = code_lines(text)
    problems = []
    want = f"const PROFILE: logbook_guard::Profile = logbook_guard::Profile::{profile};"
    declared = [l for l in lines if re.match(r"(pub(\([^)]*\))?\s+)?(const|static)\s+PROFILE\b", l)]
    if declared != [want]:
        problems.append(f"the profile must be declared once as `{want}` (found: {declared!r})")
    if "let _ =" in text and "deny_network" in text:
        for l in lines:
            if l.startswith("let _ =") and "deny_network" in l:
                problems.append(f"the guard's error must end the program, not be thrown away: {l!r}")
    if SHADOW.search(text):
        problems.append("a local logbook_guard would shadow the real crate")
    if lines.count(MAIN_SIGNATURE) != 1:
        return problems + [f"main must be declared exactly once as `{MAIN_SIGNATURE}`"]
    body = lines[lines.index(MAIN_SIGNATURE) + 1:]
    if not body or body[0] != GUARD_FIRST:
        found = body[0] if body else None
        return problems + [f"the first statement of main must be `{GUARD_FIRST}` (found: {found!r})"]
    # The guard's block: up to its closing brace, ending the program.
    block = []
    for l in body[1:]:
        if l == "}":
            break
        block.append(l)
    else:
        return problems + ["the guard's block in main isn't closed"]
    if not block or block[-1] != GUARD_END or any("return" in l for l in block[:-1]):
        problems.append(f"the guard's block must end with `{GUARD_END}` (found: {block!r})")
    return problems


if __name__ == "__main__":
    sys.exit(main())

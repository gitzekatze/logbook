#!/usr/bin/env python3
"""Writes verify/cheats/*.patch from the list below.

    scripts/cheats-make.py

Each cheat is made in a scratch copy of the working tree and saved as a patch.
When the code moves and scripts/cheats-check.py reports a cheat as "stale",
adjust its entry here and run this again. The cheats are protected files:
every change needs the owner's approval.
"""
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
OUT = REPO / "verify" / "cheats"
OUT.mkdir(parents=True, exist_ok=True)

MODEL = "crates/logbook-model/src/lib.rs"
GUARD = "crates/logbook-guard/src/lib.rs"


def append(path, text):
    return lambda ws: (ws / path).write_text((ws / path).read_text() + text)


def sub(path, old, new, count=1):
    def f(ws):
        t = (ws / path).read_text()
        if old not in t:
            raise SystemExit(f"{path}: {old!r} not found")
        (ws / path).write_text(t.replace(old, new, count))
    return f


def delete(path):
    return lambda ws: (ws / path).unlink()


CHEATS = [
    ("ignore-test", "owner", "add a claim test that is skipped with #[ignore]",
     append(MODEL, "\n#[cfg(test)]\nmod cheat {\n    #[test]\n    #[ignore]\n    fn c01_1_event_model_fields() {}\n}\n")),
    ("cfg-any-hides-tests", "owner", "hide a test module with #[cfg(any())], always false",
     append(MODEL, "\n#[cfg(any())]\nmod tests {\n    #[test]\n    fn c01_1_event_model_fields() {}\n}\n")),
    ("cfg-feature-hides-tests", "owner", "hide tests behind a feature nobody turns on",
     append(MODEL, "\n#[cfg(feature = \"slow\")]\nmod tests {\n    #[test]\n    fn c01_1_event_model_fields() {}\n}\n")),
    ("should-panic", "owner", "turn a failing test into a passing one with #[should_panic]",
     append(MODEL, "\n#[cfg(test)]\nmod cheat {\n    #[test]\n    #[should_panic]\n    fn c01_1_event_model_fields() {\n        panic!(\"broken\");\n    }\n}\n")),
    ("allow-lint", "owner", "switch a lint off with #[allow(clippy::unwrap_used)]",
     append(MODEL, "\n#[allow(clippy::unwrap_used)]\npub fn first(v: &[u8]) -> u8 {\n    *v.first().unwrap()\n}\n")),
    ("delete-guard-test", "owner", "delete the network guard's test",
     sub(GUARD, "    /// Until the real block exists, the guard must refuse rather than pretend.\n    #[test]\n    fn deny_network_fails_closed_until_implemented() {\n        assert!(deny_network().is_err());\n    }\n", "")),
    ("guard-test-returns-early", "owner", "make the guard's test pass without checking anything",
     sub(GUARD, "        assert!(deny_network().is_err());", "        return;\n        #[allow(unreachable_code)]\n        assert!(deny_network().is_err());")),
    ("rename-guard-test", "owner", "rename the guard's test so it no longer matches what it proved",
     sub(GUARD, "fn deny_network_fails_closed_until_implemented", "fn deny_network_works")),
    ("guard-pretends", "owner", "the network guard pretends to succeed",
     sub(GUARD, "    Err(GuardError(\n        \"the network block is not implemented yet, so Logbook refuses to run\",\n    ))", "    Ok(())")),
    ("claim-due-later", "owner", "move a security claim to a later milestone so it isn't due",
     sub("verify/claims.toml", 'id = "L02.2"\nfunction = "F-L02"\ndue = "0.1a"', 'id = "L02.2"\nfunction = "F-L02"\ndue = "1.0"')),
    ("delete-break", "owner", "delete a break from the break list",
     delete("verify/breaks/L02.2-mcp-skips-network-block.patch")),
    ("gate-approves-everything", "owner", "change the gate so it finds nothing",
     sub("scripts/gate.py", "    return reasons\n", "    return []\n")),
    ("ci-drops-break-list", "owner", "remove the break list from CI",
     sub(".github/workflows/ci.yml", "      - name: Break list - every deliberate mistake is caught\n        run: python3 scripts/breaks-check.py\n", "")),
    ("makefile-drops-selftest", "owner", "remove the self-tests from make check",
     sub("Makefile", "check: fmt clippy arch deny claims breaks selftest cheats", "check: fmt clippy arch deny claims breaks cheats")),
    ("deny-allows-http-client", "owner", "lift the ban on an HTTP client",
     sub("deny.toml", '    { crate = "reqwest" },\n', "")),
    ("workspace-allows-unsafe", "owner", "allow unsafe code for the whole workspace",
     sub("Cargo.toml", 'unsafe_code = "forbid"', 'unsafe_code = "allow"')),
    ("outside-crate-added", "owner", "add an outside crate through Cargo.lock",
     append("Cargo.lock", '\n[[package]]\nname = "ureq"\nversion = "3.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "0000000000000000000000000000000000000000000000000000000000000000"\n')),
    ("crate-leaves-lints", "checks", "a crate leaves the workspace lints (not a protected file)",
     sub("crates/logbook-model/Cargo.toml", "[lints]\nworkspace = true", "[lints]\nworkspace = false")),
    ("mcp-reaches-store-writer", "checks", "the AI interface depends on the store writer (not a protected file)",
     sub("crates/logbook-mcp/Cargo.toml", "logbook-guard.workspace = true", 'logbook-guard.workspace = true\nlogbook-store-write = { path = "../logbook-store-write" }')),
    ("harmless-readme", "none", "a harmless wording change: must NOT need the owner",
     sub("README.md", "Everything stays\non your computer", "Everything stays\nhere, on your computer")),
    ("harmless-code", "none", "ordinary new code without tests: must NOT need the owner",
     append(MODEL, "\n/// Number of lanes.\npub const LANES: usize = 7;\n")),
]


def git(ws, *a):
    subprocess.run(["git", "-C", str(ws), *a], check=True, capture_output=True)


for name, expect, text, change in CHEATS:
    with tempfile.TemporaryDirectory() as tmp:
        ws = pathlib.Path(tmp) / "ws"
        shutil.copytree(REPO, ws, ignore=lambda d, n: [x for x in n if x in ("target", ".git")] if pathlib.Path(d) == REPO else [])
        git(ws, "init", "-q")
        git(ws, "add", "-A")
        git(ws, "-c", "user.email=x@x", "-c", "user.name=x", "commit", "-qm", "base")
        change(ws)
        git(ws, "add", "-A")
        diff = subprocess.run(["git", "-C", str(ws), "diff", "--cached", "--binary"], capture_output=True, text=True, check=True).stdout
        if not diff:
            raise SystemExit(f"{name}: no change")
        (OUT / f"{name}.patch").write_text(f"Cheat: {text}\nExpect: {expect}\n\n{diff}")
print(f"{len(CHEATS)} cheats written to {OUT}")

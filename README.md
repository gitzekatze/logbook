# Logbook

**What happened on your computer, and when.**

Logbook keeps a timeline of your Linux system: updates and installs, crashes,
start-ups and shutdowns, settings changes and hardware health. For every
problem it shows what changed just before it, in plain words. Everything stays
on your computer; Logbook has no network at all.

## Status

**Phase 0: nothing runs yet.** The repository holds the empty crates and the
checks that every line of code will have to pass. Every Logbook program
refuses to start until its network block exists.

## How the code is kept honest

- No unsafe code in Logbook's own crates, no network code, no `.unwrap()`.
- Only one crate writes the store, only one starts programs, only one changes
  settings, and the AI interface reaches none of them
  (`scripts/arch-check.py`).
- Every check has its own test that breaks the rule on purpose
  (`make selftest`).

`make check` runs every check, the same as CI.

## License

GPL-3.0-or-later.

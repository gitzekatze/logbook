//! Spec of version 0.1a, step 2: the store (writing side).
//! Claims: D01.3, D01.4, D02.1, D03.1, D03.2, D03.3, D04.1, D04.3, D05.1,
//! D05.2 (verify/claims.toml, step = 2). D04.2 is in read_only_spec.rs, L10.1
//! and L10.2 in permissions_spec.rs.
//!
//! Frozen by the owner's approval. The code PR includes it unchanged, in
//! crates/logbook-store-write/src/lib.rs:
//!
//!     #[cfg(test)]
//!     #[rustfmt::skip]
//!     #[path = "../../../verify/spec/step2/store_spec.rs"]
//!     mod spec_step2;
//!
//! What the code must provide.
//!
//! In logbook-store (reading side, used by every part of Logbook):
//!   - `STORE_SCHEMA_VERSION: u32` (1), `STORE_SCHEMA: &str` (the text of
//!     schema/store-v1.sql), `DB_FILE: &str` ("logbook.db");
//!   - `default_dir(xdg_data_home: Option<&OsStr>, home: Option<&OsStr>)
//!     -> Option<PathBuf>`: `$XDG_DATA_HOME/logbook` if that is set and
//!     absolute, else `$HOME/.local/share/logbook` if HOME is absolute, else None;
//!   - `Reader::open(dir) -> Result<Reader, StoreError>`; never creates a
//!     store; one connection, used by every query (and by
//!     `connection_for_tests`, read_only_spec.rs); no read transaction stays
//!     open between calls, so checkpoints can finish;
//!     `reader.events()` (by time, then id), `reader.event(&EventId)`,
//!     `reader.count()`;
//!   - `StoreError`, with `NewerSchema { found: u32, supported: u32 }`
//!     (message: a newer Logbook made the store), `Unsafe(String)` (the
//!     store folder or a file in it isn't what it must be: see
//!     permissions_spec.rs) and `Invalid(String)` (an event the model
//!     refuses).
//!
//! In logbook-store-write (only the collector may use it):
//!   - `Writer::open(dir, now_micros) -> Result<(Writer, OpenReport), StoreError>`:
//!     creates folder and store if missing (permissions: L10); checks a
//!     present store (PRAGMA quick_check) and replaces a damaged one: the
//!     database and its WAL are moved aside as
//!     `logbook.db.damaged-<YYYYMMDDTHHMMSSZ of now>` (and `…-wal`), with
//!     `-2`, `-3`, … added if that name exists; its `-shm` is removed (D01.4);
//!     refuses a newer store (D01.3); restores wrong permissions (L10.1);
//!     turns on `PRAGMA secure_delete`, so deleted rows are overwritten;
//!     `OpenReport { replaced_damaged: Option<PathBuf>, fixed_permissions: Vec<PathBuf> }`;
//!   - `writer.insert(&Event) -> Result<(), StoreError>`: checks the event
//!     (`Event::check`, refusing with `Invalid`), stores it; the same ID
//!     again replaces it;
//!   - `Retention::default()`, `retention.days(Lane) -> u32`,
//!     `retention.set(Lane, days)` (at most 36500: a hundred years);
//!     `writer.prune(now_micros, &Retention) -> Result<u64, StoreError>`
//!     deletes the events whose retained_from (schema) is older than their
//!     lane's retention (an event exactly at the limit stays) and returns how
//!     many;
//!   - `DEFAULT_SIZE_LIMIT: u64` (500 MB); `writer.used_bytes()`: the
//!     database pages in use, (page_count − freelist_count) × page_size;
//!     `writer.enforce_size_limit(limit, now_micros) -> Result<SizeReport, StoreError>`
//!     with `SizeReport { info: u64, problem: u64, serious: u64 }`: deletes
//!     info first, then problem, serious last, oldest first within each,
//!     until used_bytes() <= limit; the logbook lane is never pruned by size;
//!   - after prune and enforce_size_limit, `PRAGMA wal_checkpoint(TRUNCATE)`
//!     (retried while a reader is busy), so deleted content is gone from the
//!     WAL file too and the WAL doesn't grow;
//!   - what the store itself notices becomes an event in the logbook lane
//!     (reader "logbook", severity problem), so the window shows it: kind
//!     `logbook.store_replaced` (a gap), `logbook.permissions_fixed`,
//!     `logbook.pruned_early`.
//!
//! The collector crate declares its dependency on logbook-store-write now
//! (D04.3), though it uses it only from step 8.
//!
//! In logbook-model: `raw_window(lines: &[String]) -> (Vec<String>, u64)`
//! (D03.2), and the `testing` module behind a feature `testing`.
//!
//! Dev-dependencies: rusqlite, proptest, sha2, logbook-model (feature testing).
//!
//! Not testable here, and covered elsewhere: readers in separate processes
//! (only logbook-exec may start programs; the test computers run collector
//! and readers as real programs, step 8); a store folder owned by another
//! user (needs a second user: test computers, step 8).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use logbook_model::{raw_window, utc_time, Event, EventId, Lane, Severity};
use logbook_store::{Reader, StoreError, DB_FILE, STORE_SCHEMA, STORE_SCHEMA_VERSION};
use proptest::prelude::*;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{Retention, Writer, DEFAULT_SIZE_LIMIT};

const STORE_V1: &str = include_str!("../../../schema/store-v1.sql");
const STORE_V1_SHA256: &str = "5adbd3cb129186031ad9d4e9225ba08f7964b917854cc5b61917e1a323ac89a8";
/// 2026-11-24T12:00:00Z, the "now" of these tests.
const NOW: i64 = 1_795_521_600_000_000;
const DAY: i64 = 86_400_000_000;

// ================================================================ the schema

#[test]
fn store_schema_is_the_one_of_version_1() {
    assert_eq!(STORE_SCHEMA_VERSION, 1);
    assert_eq!(STORE_SCHEMA, STORE_V1, "the code must use schema/store-v1.sql unchanged");
    let got: String = Sha256::digest(STORE_V1.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(got, STORE_V1_SHA256, "schema/store-v1.sql was edited; a change needs version 2 and a migration");
    let dir = TempDir::new();
    let (w, _) = Writer::open(dir.path(), NOW).unwrap();
    let db = sqlite(dir.path());
    let version: u32 = db.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
    assert_eq!(version, 1);
    let mut names: Vec<String> = db
        .prepare("SELECT name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'").unwrap()
        .query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
    names.sort();
    assert_eq!(names, ["event_sources", "event_sources_by_record", "events", "events_by_lane", "events_by_severity",
                       "events_by_time", "forget_markers", "meta", "raw_records", "raw_records_by_time"]);
    let mode: String = db.query_row("PRAGMA journal_mode", [], |r| r.get(0)).unwrap();
    assert_eq!(mode, "wal", "WAL lets readers read while the collector writes (F-D04)");
    drop(w);
}

#[test]
fn the_store_lives_where_xdg_says() {
    use logbook_store::default_dir;
    use std::ffi::OsStr;
    let p = |s: &str| Some(PathBuf::from(s));
    assert_eq!(default_dir(Some(OsStr::new("/data")), Some(OsStr::new("/home/u"))), p("/data/logbook"));
    assert_eq!(default_dir(None, Some(OsStr::new("/home/u"))), p("/home/u/.local/share/logbook"));
    assert_eq!(default_dir(Some(OsStr::new("")), Some(OsStr::new("/home/u"))), p("/home/u/.local/share/logbook"));
    assert_eq!(default_dir(Some(OsStr::new("relative")), Some(OsStr::new("/home/u"))), p("/home/u/.local/share/logbook"));
    assert_eq!(default_dir(None, None), None);
    assert_eq!(default_dir(None, Some(OsStr::new("relative"))), None);
}

/// The model's rules hold in the store too: an event the model refuses is
/// never stored.
#[test]
fn the_store_refuses_events_the_model_refuses() {
    let dir = TempDir::new();
    let (mut w, _) = Writer::open(dir.path(), NOW).unwrap();
    let mut long = event(1, NOW, Lane::System, Severity::Info);
    long.raw = vec!["x".into(); 21];
    let mut zero = event(2, NOW, Lane::System, Severity::Info);
    zero.count = 0;
    for bad in [long, zero] {
        assert!(matches!(w.insert(&bad), Err(StoreError::Invalid(_))), "stored an invalid event");
    }
    drop(w);
    assert_eq!(Reader::open(dir.path()).unwrap().count().unwrap(), 0);
}

// ===================================================================== D01.3

/// An older Logbook refuses a newer store with a clear message, and leaves
/// it exactly as it was.
#[test]
fn d01_3_an_older_logbook_refuses_a_newer_store() {
    let dir = TempDir::new();
    {
        let (mut w, _) = Writer::open(dir.path(), NOW).unwrap();
        w.insert(&event(1, NOW, Lane::Updates, Severity::Info)).unwrap();
    }
    sqlite(dir.path()).execute_batch("PRAGMA user_version = 2").unwrap();
    let db = dir.path().join(DB_FILE);
    let before = std::fs::read(&db).unwrap();
    for result in [Writer::open(dir.path(), NOW).map(|_| ()), Reader::open(dir.path()).map(|_| ())] {
        match result {
            Err(e @ StoreError::NewerSchema { found: 2, supported: 1 }) => {
                assert!(e.to_string().contains("newer Logbook"), "unclear message: {e}");
            }
            other => panic!("a newer store must be refused, got {other:?}"),
        }
    }
    assert_eq!(std::fs::read(&db).unwrap(), before, "the newer store was changed");
}

// ===================================================================== D01.4

/// A healthy store survives being opened again, after a clean end or after a
/// crash that left its WAL behind: every committed event is there, nothing
/// is reported damaged.
#[test]
fn d01_4_a_healthy_store_is_kept() {
    let dir = TempDir::new();
    let (mut w, _) = Writer::open(dir.path(), NOW).unwrap();
    for n in 0..50 {
        w.insert(&event(n, NOW - n as i64, Lane::System, Severity::Info)).unwrap();
    }
    // A crash: the files as they are while the writer still runs.
    let crashed = TempDir::new();
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(crashed.path()).unwrap();
    }
    for f in store_files(dir.path()) {
        std::fs::copy(&f, crashed.path().join(f.file_name().unwrap())).unwrap();
    }
    assert!(crashed.path().join(format!("{DB_FILE}-wal")).exists(), "the crash image holds a WAL");
    drop(w);
    for (case, path) in [("clean end", dir.path()), ("after a crash", crashed.path())] {
        let (w, report) = Writer::open(path, NOW + 1).unwrap();
        drop(w);
        assert_eq!(report.replaced_damaged, None, "{case}: a healthy store was taken for damaged");
        let events = Reader::open(path).unwrap().events().unwrap();
        assert_eq!(events.len(), 50, "{case}: committed events got lost");
        assert!(events.iter().all(|e| e.kind != "logbook.store_replaced"), "{case}");
    }
}

/// A damaged store is detected, moved aside together with its WAL, named
/// after the time, replaced by a new one, and the gap is recorded.
#[test]
fn d01_4_a_damaged_store_is_moved_aside_and_replaced_with_a_gap() {
    for damage in ["garbage", "truncated", "empty pages", "garbage with its old WAL"] {
        let dir = TempDir::new();
        let db = dir.path().join(DB_FILE);
        let (mut w, _) = Writer::open(dir.path(), NOW).unwrap();
        for n in 0..200 {
            w.insert(&event(n, NOW - n as i64 * 1000, Lane::System, Severity::Info)).unwrap();
        }
        let with_wal = damage.ends_with("WAL");
        if with_wal {
            // Keep the WAL of the running writer, as a crash would.
            for f in store_files(dir.path()) {
                std::fs::copy(&f, f.with_extension(format!("{}.keep", f.extension().unwrap().to_string_lossy()))).unwrap();
            }
        }
        drop(w);
        if with_wal {
            for f in std::fs::read_dir(dir.path()).unwrap() {
                let f = f.unwrap().path();
                if let Some(orig) = f.to_string_lossy().strip_suffix(".keep") {
                    std::fs::rename(&f, orig).unwrap();
                }
            }
        }
        let good = std::fs::read(&db).unwrap();
        let damaged: Vec<u8> = match damage {
            "truncated" => good[..good.len() / 2].to_vec(),
            "empty pages" => {
                let mut bytes = good.clone();
                let page = 4096.min(bytes.len() / 4);
                for b in &mut bytes[page..page * 3] {
                    *b = 0x55;
                }
                bytes
            }
            _ => b"this is not a database at all".repeat(100),
        };
        std::fs::write(&db, &damaged).unwrap();
        let wal = dir.path().join(format!("{DB_FILE}-wal"));
        let old_wal = if with_wal { Some(std::fs::read(&wal).unwrap()) } else {
            let _ = std::fs::remove_file(&wal);
            let _ = std::fs::remove_file(dir.path().join(format!("{DB_FILE}-shm")));
            None
        };
        let (w, report) = Writer::open(dir.path(), NOW + DAY).unwrap();
        drop(w);
        let moved = report.replaced_damaged.unwrap_or_else(|| panic!("{damage}: the damage wasn't noticed"));
        let name = moved.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(name, "logbook.db.damaged-20261125T120000Z", "{damage}");
        assert_eq!(moved.parent(), Some(dir.path()));
        assert_eq!(std::fs::read(&moved).unwrap(), damaged, "{damage}: the damaged store must be kept unchanged");
        if let Some(old_wal) = old_wal {
            let moved_wal = dir.path().join(format!("{name}-wal"));
            assert_eq!(std::fs::read(&moved_wal).ok(), Some(old_wal), "{damage}: the old WAL must go with it");
        }
        let events = Reader::open(dir.path()).unwrap().events().unwrap();
        assert_eq!(events.len(), 1, "{damage}: a new store holds only the gap");
        let gap = &events[0];
        assert_eq!((gap.lane, gap.kind.as_str(), gap.severity), (Lane::Logbook, "logbook.store_replaced", Severity::Problem));
        assert_eq!(gap.source.reader, "logbook");
    }
}

/// A second damaged store in the same second doesn't overwrite the first copy.
#[test]
fn d01_4_damaged_copies_never_overwrite_each_other() {
    let dir = TempDir::new();
    for round in 0..3u8 {
        drop(Writer::open(dir.path(), NOW).unwrap());
        for f in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(dir.path().join(format!("{DB_FILE}{f}")));
        }
        std::fs::write(dir.path().join(DB_FILE), vec![round; 5000]).unwrap();
        let (w, report) = Writer::open(dir.path(), NOW).unwrap();
        drop(w);
        let want = ["logbook.db.damaged-20261124T120000Z", "logbook.db.damaged-20261124T120000Z-2",
                    "logbook.db.damaged-20261124T120000Z-3"][round as usize];
        assert_eq!(report.replaced_damaged.unwrap().file_name().unwrap().to_string_lossy(), want);
        assert_eq!(std::fs::read(dir.path().join(want)).unwrap(), vec![round; 5000]);
    }
}

// ===================================================================== D02.1

#[test]
fn d02_1_default_retention() {
    let mut r = Retention::default();
    for lane in Lane::ALL {
        let want = match lane {
            Lane::Privacy => 30,
            Lane::Hardware => 730,
            _ => 180,
        };
        assert_eq!(r.days(lane), want, "{lane:?}");
    }
    r.set(Lane::System, u32::MAX);
    assert_eq!(r.days(Lane::System), 36_500, "retention is capped at a hundred years");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Per lane, events beyond the retention are deleted and the others kept,
    /// exactly at the limit included. A simulated clock (NOW).
    #[test]
    fn d02_1_retention_keeps_exactly_the_events_within_each_lane(
        events in prop::collection::vec((0usize..7, 0i64..800 * DAY, 0usize..3), 1..60),
        privacy_days in prop::option::of(1u32..400),
    ) {
        let dir = TempDir::new();
        let (mut w, _) = Writer::open(dir.path(), NOW).unwrap();
        let mut retention = Retention::default();
        if let Some(d) = privacy_days {
            retention.set(Lane::Privacy, d);
        }
        let mut want_kept = Vec::new();
        for (n, (lane, age, sev)) in events.iter().enumerate() {
            let lane = Lane::ALL[*lane];
            let limit = i64::from(retention.days(lane)) * DAY;
            // Some events sit exactly at the limit, some one microsecond beyond it.
            let age = match n % 5 { 0 => limit, 1 => limit + 1, _ => *age };
            let e = event(n as u64, NOW - age, lane, Severity::ALL[*sev]);
            if age <= limit {
                want_kept.push(e.id.clone());
            }
            w.insert(&e).unwrap();
        }
        let deleted = w.prune(NOW, &retention).unwrap();
        let mut kept: Vec<EventId> = Reader::open(dir.path()).unwrap().events().unwrap().into_iter().map(|e| e.id).collect();
        want_kept.sort();
        kept.sort();
        prop_assert_eq!(deleted as usize, events.len() - kept.len());
        prop_assert_eq!(kept, want_kept);
    }
}

/// Retention counts from an event's latest time: a folded event last seen
/// yesterday stays, however long ago it began. An event whose time is
/// uncertain (a wrong clock, F-A08) stays as long as it was stored recently.
#[test]
fn d02_1_retention_counts_from_the_latest_time() {
    let dir = TempDir::new();
    let (mut w, _) = Writer::open(dir.path(), NOW).unwrap();
    let mut folded = event(1, NOW - 200 * DAY, Lane::System, Severity::Problem);
    folded.count = 5;
    folded.last_time = utc_time(NOW - DAY);
    let mut long = event(2, NOW - 400 * DAY, Lane::Privacy, Severity::Info);
    long.end = utc_time(NOW - 2 * DAY);
    let mut wrong_clock = event(3, 0, Lane::System, Severity::Info);
    wrong_clock.time_uncertain = true;
    let gone = event(4, NOW - 200 * DAY, Lane::System, Severity::Info);
    for e in [&folded, &long, &wrong_clock, &gone] {
        w.insert(e).unwrap();
    }
    assert_eq!(w.prune(NOW, &Retention::default()).unwrap(), 1);
    let kept: Vec<EventId> = Reader::open(dir.path()).unwrap().events().unwrap().into_iter().map(|e| e.id).collect();
    assert!(kept.contains(&folded.id) && kept.contains(&long.id) && kept.contains(&wrong_clock.id));
    assert!(!kept.contains(&gone.id));
}

/// Deleted content leaves no trace in the store's files: not in the database
/// (secure_delete), not in the WAL (checkpoint), not from replaced versions.
#[test]
fn d02_1_deleted_events_leave_no_trace_in_the_files() {
    let dir = TempDir::new();
    let (mut w, _) = Writer::open(dir.path(), NOW).unwrap();
    for n in 0..30 {
        w.insert(&event(100 + n, NOW, Lane::System, Severity::Info)).unwrap();
    }
    let mut secret = event(1, NOW - 300 * DAY, Lane::Privacy, Severity::Info);
    secret.summary = "Microphone used by SECRET-MARKER-ONE.".into();
    w.insert(&secret).unwrap();
    secret.summary = "Microphone used by SECRET-MARKER-TWO.".into();
    w.insert(&secret).unwrap();
    assert_eq!(w.prune(NOW, &Retention::default()).unwrap(), 1);
    for f in store_files(dir.path()) {
        let bytes = std::fs::read(&f).unwrap();
        for marker in ["SECRET-MARKER-ONE", "SECRET-MARKER-TWO"] {
            assert!(!contains(&bytes, marker.as_bytes()), "{marker} is still in {}", f.display());
        }
    }
    let wal = dir.path().join(format!("{DB_FILE}-wal"));
    assert!(std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0) == 0, "the WAL wasn't checkpointed");
    drop(w);
}

// ===================================================================== D03

/// The raw lines can still be read from the store: they don't depend on the
/// journal or any other source still existing.
#[test]
fn d03_1_raw_lines_read_back_from_the_store() {
    let dir = TempDir::new();
    let (mut w, _) = Writer::open(dir.path(), NOW).unwrap();
    let mut e = event(7, NOW, Lane::Crashes, Severity::Serious);
    e.raw = (0..20).map(|i| format!("line {i}: segfault at 0x{i:04x} \u{fffd}")).collect();
    e.raw_lossy = true;
    w.insert(&e).unwrap();
    drop(w);
    let back = Reader::open(dir.path()).unwrap().event(&e.id).unwrap().expect("the event is stored");
    assert_eq!(back, e);
}

proptest! {
    /// At most 20 lines; more are cut to the first 10 and the last 10, and
    /// the rest is counted.
    #[test]
    fn d03_2_raw_window_keeps_first_and_last_ten(n in 0usize..80) {
        let lines: Vec<String> = (0..n).map(|i| format!("line {i}")).collect();
        let (kept, omitted) = raw_window(&lines);
        if n <= 20 {
            prop_assert_eq!(&kept, &lines);
            prop_assert_eq!(omitted, 0);
        } else {
            prop_assert_eq!(&kept[..10], &lines[..10]);
            prop_assert_eq!(&kept[10..], &lines[n - 10..]);
            prop_assert_eq!(kept.len(), 20);
            prop_assert_eq!(omitted, (n - 20) as u64);
        }
    }
}

/// Raw lines are stored unchanged, private details and control characters
/// included; the privacy filter applies only on output (F-G02).
#[test]
fn d03_3_raw_lines_are_stored_unchanged() {
    let dir = TempDir::new();
    let (mut w, _) = Writer::open(dir.path(), NOW).unwrap();
    let mut e = event(9, NOW, Lane::System, Severity::Problem);
    e.raw = vec![
        "user max logged in from 192.168.1.5 on host max-laptop".into(),
        "/home/max/Documents/tax 2026.pdf opened".into(),
        "\u{1b}[31mred\u{1b}[0m \u{202e}reversed\u{202c} tab\there".into(),
        "wifi 'Max Home' aa:bb:cc:dd:ee:ff".into(),
    ];
    w.insert(&e).unwrap();
    drop(w);
    let json: String = sqlite(dir.path())
        .query_row("SELECT json FROM events WHERE id = ?1", [e.id.as_str()], |r| r.get(0)).unwrap();
    let stored: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(stored["raw"], json!(e.raw));
}

// ===================================================================== D04

/// One writer and several readers at the same time: no locking errors, and
/// every reader finally sees everything.
#[test]
fn d04_1_one_writer_and_readers_at_the_same_time() {
    let dir = TempDir::new();
    let (mut w, _) = Writer::open(dir.path(), NOW).unwrap();
    let path = dir.path().to_owned();
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let start = Arc::new(Barrier::new(5));
    let readers: Vec<_> = (0..4)
        .map(|_| {
            let (path, done, start) = (path.clone(), done.clone(), start.clone());
            std::thread::spawn(move || {
                let r = Reader::open(&path).expect("a reader opens while the writer writes");
                start.wait();
                let mut reads = 0u64;
                loop {
                    let finished = done.load(Ordering::SeqCst);
                    r.count().expect("count while writing");
                    r.events().expect("read while writing");
                    reads += 1;
                    if finished {
                        break;
                    }
                }
                (reads, r.count().expect("the final count"))
            })
        })
        .collect();
    start.wait();
    for n in 0..2000u64 {
        w.insert(&event(n, NOW - n as i64, Lane::Updates, Severity::Info)).expect("write while reading");
    }
    done.store(true, Ordering::SeqCst);
    for reader in readers {
        let (reads, count) = reader.join().expect("a reader thread failed");
        assert!(reads > 0);
        assert_eq!(count, 2000);
    }
}

/// Only the collector depends on the store writer: no normal or build
/// dependency, under its own name or renamed, in any crate (tests may). A
/// second check next to scripts/arch-check.py, which also follows indirect
/// dependencies.
#[test]
fn d04_3_only_the_collector_depends_on_the_store_writer() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut users = Vec::new();
    let mut manifests = Vec::new();
    let mut todo = vec![crates.to_owned()];
    while let Some(d) = todo.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() && p.file_name().is_some_and(|n| n != "target") {
                todo.push(p);
            } else if p.file_name().is_some_and(|n| n == "Cargo.toml") {
                manifests.push(p);
            }
        }
    }
    for manifest in &manifests {
        let text = std::fs::read_to_string(manifest).unwrap();
        let mut section = String::new();
        for line in text.lines().map(str::trim) {
            if line.starts_with('[') {
                section = line.to_owned();
            }
            let runtime = section.contains("dependencies") && !section.contains("dev-dependencies");
            if runtime && (line.contains("logbook-store-write") || line.contains("logbook_store_write")) {
                let name = manifest.parent().unwrap().file_name().unwrap().to_string_lossy().into_owned();
                if name != "logbook-store-write" && !users.contains(&name) {
                    users.push(name);
                }
            }
        }
    }
    assert!(manifests.len() >= 15, "found only {} crates", manifests.len());
    assert_eq!(users, ["logbook-collector"], "only the collector may depend on logbook-store-write");
}

// ===================================================================== D05

#[test]
fn d05_1_the_default_limit_is_500_mb_and_used_bytes_are_database_pages() {
    assert_eq!(DEFAULT_SIZE_LIMIT, 500 * 1024 * 1024);
    let dir = TempDir::new();
    let (mut w, _) = Writer::open(dir.path(), NOW).unwrap();
    for n in 0..300 {
        // Half of them old enough to be pruned, so free pages exist.
        let mut e = event(n, if n % 2 == 0 { NOW - 400 * DAY } else { NOW }, Lane::System, Severity::Info);
        e.raw = vec!["z".repeat(300); 3];
        w.insert(&e).unwrap();
    }
    w.prune(NOW, &Retention::default()).unwrap();
    let db = sqlite(dir.path());
    let page = |q: &str| db.query_row(q, [], |r| r.get::<_, i64>(0)).unwrap();
    assert!(page("PRAGMA freelist_count") > 0, "the test needs free pages");
    let pages = page("PRAGMA page_count") - page("PRAGMA freelist_count");
    assert_eq!(w.used_bytes().unwrap(), (pages * page("PRAGMA page_size")) as u64);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// Over the limit, pruning deletes info events first, then problem
    /// events, serious ones last, and the oldest first within each, until
    /// the store is under the limit. The logbook lane is never pruned by size.
    #[test]
    fn d05_1_over_the_limit_pruning_goes_info_problem_serious(
        events in prop::collection::vec((0usize..3, 0i64..100 * DAY), 150..400),
        share in 10u64..90,
    ) {
        let dir = TempDir::new();
        let (mut w, _) = Writer::open(dir.path(), NOW).unwrap();
        let mut all = Vec::new();
        for (n, (sev, age)) in events.iter().enumerate() {
            let lane = if n % 50 == 0 { Lane::Logbook } else { Lane::System };
            let mut e = event(n as u64, NOW - age, lane, Severity::ALL[*sev]);
            e.raw = vec!["x".repeat(400); 5];
            w.insert(&e).unwrap();
            all.push(e);
        }
        let limit = w.used_bytes().unwrap() * share / 100;
        let report = w.enforce_size_limit(limit, NOW).unwrap();
        prop_assert!(w.used_bytes().unwrap() <= limit, "still over the limit");
        let kept: std::collections::BTreeSet<EventId> =
            Reader::open(dir.path()).unwrap().events().unwrap().into_iter().map(|e| e.id).collect();
        prop_assert!(all.iter().filter(|e| e.lane == Lane::Logbook).all(|e| kept.contains(&e.id)),
            "a logbook-lane event was pruned by size");
        let prunable: Vec<&Event> = all.iter().filter(|e| e.lane != Lane::Logbook).collect();
        for (rank, sev) in Severity::ALL.iter().enumerate() {
            let (deleted, stayed): (Vec<&&Event>, Vec<&&Event>) =
                prunable.iter().filter(|e| e.severity == *sev).partition(|e| !kept.contains(&e.id));
            let count = [report.info, report.problem, report.serious][rank];
            prop_assert_eq!(deleted.len() as u64, count, "{:?} count", sev);
            if let (Some(newest_gone), Some(oldest_left)) =
                (deleted.iter().map(|e| (&e.time, &e.id)).max(), stayed.iter().map(|e| (&e.time, &e.id)).min()) {
                prop_assert!(newest_gone <= oldest_left, "{:?}: a newer event went before an older one", sev);
            }
            if !deleted.is_empty() {
                for lower in &Severity::ALL[..rank] {
                    prop_assert!(prunable.iter().filter(|e| e.severity == *lower).all(|e| !kept.contains(&e.id)),
                        "{:?} events were deleted while {:?} events were left", sev, lower);
                }
            }
        }
    }
}

/// Early pruning is recorded as an event the window shows; nothing is
/// recorded when the store is under its limit. Afterwards the WAL is empty.
#[test]
fn d05_2_early_pruning_is_recorded_for_the_window() {
    let dir = TempDir::new();
    let (mut w, _) = Writer::open(dir.path(), NOW).unwrap();
    for n in 0..300 {
        let mut e = event(n, NOW - n as i64 * DAY / 10, Lane::System, Severity::Info);
        e.raw = vec!["y".repeat(500); 4];
        w.insert(&e).unwrap();
    }
    let under = w.enforce_size_limit(u64::MAX, NOW).unwrap();
    assert_eq!((under.info, under.problem, under.serious), (0, 0, 0));
    let notes = |dir: &Path| -> Vec<Event> {
        Reader::open(dir).unwrap().events().unwrap().into_iter().filter(|e| e.kind == "logbook.pruned_early").collect()
    };
    assert!(notes(dir.path()).is_empty(), "nothing was pruned, so nothing may be recorded");
    let limit = w.used_bytes().unwrap() / 2;
    let report = w.enforce_size_limit(limit, NOW).unwrap();
    assert!(report.info > 0);
    let recorded = notes(dir.path());
    assert_eq!(recorded.len(), 1);
    let note = &recorded[0];
    assert_eq!((note.lane, note.severity, note.source.reader.as_str()), (Lane::Logbook, Severity::Problem, "logbook"));
    assert_eq!(note.details["info"], json!(report.info));
    assert_eq!(note.details["problem"], json!(report.problem));
    assert_eq!(note.details["serious"], json!(report.serious));
    let wal = dir.path().join(format!("{DB_FILE}-wal"));
    assert_eq!(std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0), 0, "the WAL wasn't checkpointed");
}

// =================================================================== helpers

/// A valid event with the given number (its ID), time, lane and severity.
fn event(n: u64, time_micros: i64, lane: Lane, severity: Severity) -> Event {
    let id = EventId::derive("spec", &n.to_le_bytes(), 0).unwrap();
    serde_json::from_value(json!({
        "id": id.as_str(), "time": utc_time(time_micros).unwrap(), "last_time": null, "end": null,
        "utc_offset": 3600, "lane": lane, "kind": "spec.example", "template": "spec.example",
        "severity": severity,
        "subject": {"type": "program", "name": "example", "version": null, "source_kind": "unknown",
                    "package": null, "path": null},
        "summary": format!("Example event {n}."), "details": {"n": n}, "count": 1, "first_time": false,
        "links": [], "raw": [], "raw_omitted": 0, "raw_lossy": false,
        "source": {"reader": "spec", "mode": "live"}, "rules_version": 1, "time_uncertain": false
    }))
    .unwrap()
}

/// A plain connection to the store's database, for looking inside.
fn sqlite(dir: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(dir.join(DB_FILE)).unwrap()
}

/// The store's database files that exist.
fn store_files(dir: &Path) -> Vec<PathBuf> {
    ["", "-wal", "-shm"].iter().map(|s| dir.join(format!("{DB_FILE}{s}"))).filter(|p| p.exists()).collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// A folder of its own for each test, removed afterwards. path() is the
/// store folder inside it, which the store creates itself (as it would in
/// ~/.local/share/logbook).
struct TempDir {
    root: PathBuf,
    store: PathBuf,
}

impl TempDir {
    fn new() -> TempDir {
        static N: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "logbook-spec2-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let store = root.join("logbook");
        TempDir { root, store }
    }

    fn path(&self) -> &Path {
        &self.store
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

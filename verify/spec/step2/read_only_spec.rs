//! Spec of version 0.1a, step 2: readers can't write (claim D04.2, 🛡).
//!
//! Frozen by the owner's approval. The code PR includes it unchanged, in
//! crates/logbook-store/src/lib.rs:
//!
//!     #[cfg(test)]
//!     #[rustfmt::skip]
//!     #[path = "../../../verify/spec/step2/read_only_spec.rs"]
//!     mod spec_step2;
//!
//! Every part of Logbook except the collector reads the store through
//! `Reader`. Its connection is opened read-only AND with `PRAGMA query_only`,
//! so even a write attempt fails at the database, whatever the code above it
//! does (F-D04). The code must provide, for tests only,
//! `Reader::connection_for_tests(&self) -> &rusqlite::Connection`, returning
//! the one connection every query of the reader uses.
//!
//! This file builds its store with rusqlite and the schema text alone, so it
//! doesn't depend on the writing side.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{Reader, DB_FILE, STORE_SCHEMA};

/// A store with one event row, made without the writer.
fn store(dir: &Path) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let db = dir.join(DB_FILE);
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch(STORE_SCHEMA).unwrap();
    c.execute_batch("PRAGMA user_version = 1; PRAGMA journal_mode = WAL;").unwrap();
    c.execute(
        "INSERT INTO events (id, time, lane, severity, retained_from, stored_at, json) VALUES ('ev-0', 't', 'system', 'info', 't', 't', '{}')",
        [],
    )
    .unwrap();
    db
}

/// D04.2: a write attempt through a reader's connection fails at the
/// database, for every kind of write, and changes nothing.
#[test]
fn d04_2_a_reader_cannot_write_even_by_mistake() {
    let dir = TempDir::new();
    let db = store(dir.path());
    let before = std::fs::read(&db).unwrap();
    let reader = Reader::open(dir.path()).unwrap();
    let c = reader.connection_for_tests();
    let query_only: i64 = c.query_row("PRAGMA query_only", [], |r| r.get(0)).unwrap();
    assert_eq!(query_only, 1, "the reader's connection must run with PRAGMA query_only = ON");
    for sql in [
        "INSERT INTO events (id, time, lane, severity, retained_from, stored_at, json) VALUES ('ev-1', 't', 'system', 'info', 't', 't', '{}')",
        "UPDATE events SET severity = 'serious'",
        "DELETE FROM events",
        "DROP TABLE events",
        "CREATE TABLE mine (x INTEGER)",
        "PRAGMA user_version = 9",
        "INSERT INTO meta (key, value) VALUES ('k', 'v')",
        "VACUUM",
    ] {
        assert!(c.execute_batch(sql).is_err(), "the reader could run: {sql}");
    }
    // query_only can't simply be switched off: the file is opened read-only too.
    let _ = c.execute_batch("PRAGMA query_only = OFF");
    assert!(c.execute_batch("DELETE FROM events").is_err(), "a reader that switched query_only off could write");
    drop(reader);
    assert_eq!(std::fs::read(&db).unwrap(), before, "the store changed through a reader");
}

/// A reader never creates a store: a missing one is an error, and nothing
/// appears on disk.
#[test]
fn a_reader_does_not_create_a_store() {
    let dir = TempDir::new();
    assert!(Reader::open(dir.path()).is_err());
    assert!(!dir.path().exists(), "the reader created the store folder");
}

struct TempDir {
    root: PathBuf,
    store: PathBuf,
}

impl TempDir {
    fn new() -> TempDir {
        static N: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "logbook-spec2r-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
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

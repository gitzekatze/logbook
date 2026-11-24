//! Logbook's store, the writing side (F-D01 to F-D05, F-L10). Only the
//! collector may use this crate (architecture check; claim D04.3).
//!
//! [`Writer::open`] makes sure the store folder is private (folder.rs),
//! replaces a damaged store, refuses a newer one, and turns on
//! `secure_delete`, so deleted rows are overwritten. Whatever the store
//! notices itself (a replaced store, restored permissions, early pruning)
//! becomes an event in the logbook lane, so the window shows it.
//!
//! The tests are the frozen spec of version 0.1a, step 2:
//! `verify/spec/step2/store_spec.rs` here, `permissions_spec.rs` as an
//! integration test (tests/permissions.rs).

mod folder;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use logbook_model::{utc_time, Event, EventId, Lane, Severity};
use logbook_store::{
    schema_version, StoreError, BUSY_TIMEOUT, DB_FILE, STORE_SCHEMA, STORE_SCHEMA_VERSION,
};
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};

/// The store's size limit by default (F-D05).
pub const DEFAULT_SIZE_LIMIT: u64 = 500 * 1024 * 1024;
/// The longest retention a lane can have: a hundred years.
pub const MAX_RETENTION_DAYS: u32 = 36_500;
const DAY_MICROS: i64 = 86_400_000_000;
/// The writer's connection.
const WRITE_FLAGS: OpenFlags =
    OpenFlags::SQLITE_OPEN_READ_WRITE.union(OpenFlags::SQLITE_OPEN_NO_MUTEX);
/// The health check's connection: read-only, so checking changes nothing.
const CHECK_FLAGS: OpenFlags =
    OpenFlags::SQLITE_OPEN_READ_ONLY.union(OpenFlags::SQLITE_OPEN_NO_MUTEX);

/// What [`Writer::open`] had to do.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OpenReport {
    /// Where a damaged store was moved to.
    pub replaced_damaged: Option<PathBuf>,
    /// Folder and files whose permissions were restored.
    pub fixed_permissions: Vec<PathBuf>,
}

/// Events deleted per severity by [`Writer::enforce_size_limit`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SizeReport {
    pub info: u64,
    pub problem: u64,
    pub serious: u64,
}

/// How many days each lane keeps its events (F-D02).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retention {
    days: BTreeMap<Lane, u32>,
}

impl Default for Retention {
    /// 180 days, the privacy lane 30, hardware health 2 years.
    fn default() -> Self {
        let days = Lane::ALL
            .iter()
            .map(|lane| {
                let days = match lane {
                    Lane::Privacy => 30,
                    Lane::Hardware => 730,
                    _ => 180,
                };
                (*lane, days)
            })
            .collect();
        Retention { days }
    }
}

impl Retention {
    /// The lane's retention in days.
    pub fn days(&self, lane: Lane) -> u32 {
        self.days.get(&lane).copied().unwrap_or(180)
    }

    /// Sets a lane's retention, at most [`MAX_RETENTION_DAYS`].
    pub fn set(&mut self, lane: Lane, days: u32) {
        self.days.insert(lane, days.min(MAX_RETENTION_DAYS));
    }
}

/// The store's one writer.
pub struct Writer {
    connection: Connection,
    now: i64,
}

impl Writer {
    /// Opens the store in `dir`, creating it if needed. `now_micros` is the
    /// current time (a parameter, so tests can set the clock).
    pub fn open(dir: &Path, now_micros: i64) -> Result<(Writer, OpenReport), StoreError> {
        let mut report = OpenReport {
            fixed_permissions: folder::secure(dir)?,
            ..OpenReport::default()
        };
        let db = dir.join(DB_FILE);
        if db.exists() {
            if !is_healthy(&db)? {
                report.replaced_damaged = Some(move_aside(dir, now_micros)?);
                folder::create_file(&db)?;
            }
        } else {
            folder::create_file(&db)?;
        }
        let connection = Connection::open_with_flags(&db, WRITE_FLAGS)?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        let version = schema_version(&connection)?;
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA secure_delete = ON;
             PRAGMA foreign_keys = ON;",
        )?;
        if version == 0 {
            let tx = connection.unchecked_transaction()?;
            tx.execute_batch(STORE_SCHEMA)?;
            tx.execute_batch(&format!("PRAGMA user_version = {STORE_SCHEMA_VERSION}"))?;
            tx.commit()?;
        }
        let mut writer = Writer {
            connection,
            now: now_micros,
        };
        if let Some(moved) = &report.replaced_damaged {
            writer.note(
                "logbook.store_replaced",
                "The store was damaged; it was set aside and a new one started, so earlier events are missing.",
                json!({ "moved_to": moved.to_string_lossy() }),
            )?;
        }
        if !report.fixed_permissions.is_empty() {
            let paths: Vec<_> = report
                .fixed_permissions
                .iter()
                .map(|p| p.to_string_lossy())
                .collect();
            writer.note(
                "logbook.permissions_fixed",
                "The store's permissions had been changed; they were made private again.",
                json!({ "paths": paths }),
            )?;
        }
        Ok((writer, report))
    }

    /// Stores an event; the same ID again replaces it. The model's checks
    /// run first: an invalid event is never stored.
    pub fn insert(&mut self, event: &Event) -> Result<(), StoreError> {
        event
            .check()
            .map_err(|e| StoreError::Invalid(e.to_string()))?;
        let json = serde_json::to_string(event).map_err(|e| StoreError::Invalid(e.to_string()))?;
        let stored_at = self.now_text();
        let retained_from = retained_from(event, &stored_at);
        self.connection.execute(
            "INSERT OR REPLACE INTO events (id, time, lane, severity, retained_from, stored_at, json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            (
                event.id.as_str(),
                &event.time,
                event.lane.as_str(),
                event.severity.as_str(),
                &retained_from,
                &stored_at,
                &json,
            ),
        )?;
        Ok(())
    }

    /// Deletes the events older than their lane's retention; an event
    /// exactly at the limit stays. Returns how many were deleted.
    pub fn prune(&mut self, now_micros: i64, retention: &Retention) -> Result<u64, StoreError> {
        let tx = self.connection.unchecked_transaction()?;
        let mut deleted = 0;
        for lane in Lane::ALL {
            let cutoff = utc_time(now_micros - i64::from(retention.days(lane)) * DAY_MICROS)
                .unwrap_or_else(|| "0000".to_owned());
            deleted += tx.execute(
                "DELETE FROM events WHERE lane = ?1 AND retained_from < ?2",
                (lane.as_str(), &cutoff),
            )? as u64;
        }
        tx.commit()?;
        self.checkpoint()?;
        Ok(deleted)
    }

    /// The database pages in use, in bytes: (page_count − freelist_count) × page_size.
    pub fn used_bytes(&self) -> Result<u64, StoreError> {
        let pragma = |name: &str| -> Result<i64, StoreError> {
            Ok(self
                .connection
                .query_row(&format!("PRAGMA {name}"), [], |r| r.get(0))?)
        };
        let pages = pragma("page_count")? - pragma("freelist_count")?;
        Ok(u64::try_from(pages * pragma("page_size")?).unwrap_or(0))
    }

    /// Keeps the store under `limit` bytes (F-D05): deletes info events
    /// first, then problem events, serious ones last, oldest first within
    /// each. The logbook lane is never pruned by size. Early pruning is
    /// recorded as an event.
    pub fn enforce_size_limit(
        &mut self,
        limit: u64,
        now_micros: i64,
    ) -> Result<SizeReport, StoreError> {
        let mut report = SizeReport::default();
        self.now = now_micros;
        let mut note_id = None;
        // The note takes room too: record it after each round of deleting,
        // and go on while it pushes the store over the limit again and
        // anything is left to delete.
        while self.delete_until(limit, &mut report)? > 0 {
            let id = match &note_id {
                Some(id) => EventId::clone(id),
                None => note_id
                    .insert(self.note_id("logbook.pruned_early")?)
                    .clone(),
            };
            let note = self.note_event(
                id,
                "logbook.pruned_early",
                "The store reached its size limit, so old events were deleted earlier than their lane's retention.",
                json!({ "info": report.info, "problem": report.problem, "serious": report.serious }),
            )?;
            self.insert(&note)?;
        }
        if note_id.is_some() {
            self.checkpoint()?;
        }
        Ok(report)
    }

    /// Deletes the lowest-ranked event (info before problem before serious,
    /// oldest first, never the logbook lane) until the store is under
    /// `limit`. Returns how many it deleted.
    fn delete_until(&mut self, limit: u64, report: &mut SizeReport) -> Result<u64, StoreError> {
        let mut deleted = 0;
        while self.used_bytes()? > limit {
            let Some((severity, id)) = self.lowest()? else {
                break;
            };
            self.connection
                .execute("DELETE FROM events WHERE id = ?1", [&id])?;
            match severity {
                Severity::Info => report.info += 1,
                Severity::Problem => report.problem += 1,
                Severity::Serious => report.serious += 1,
            }
            deleted += 1;
        }
        Ok(deleted)
    }

    /// The event the size limit deletes next, if any.
    fn lowest(&self) -> Result<Option<(Severity, String)>, StoreError> {
        let mut query = self.connection.prepare_cached(
            "SELECT id FROM events WHERE severity = ?1 AND lane != 'logbook' ORDER BY time, id LIMIT 1",
        )?;
        for severity in Severity::ALL {
            let mut rows = query.query([severity.as_str()])?;
            if let Some(row) = rows.next()? {
                return Ok(Some((severity, row.get(0)?)));
            }
        }
        Ok(None)
    }

    /// Empties the WAL into the database, so deleted content is gone from
    /// both files and the WAL doesn't grow. Retries while a reader is busy.
    fn checkpoint(&self) -> Result<(), StoreError> {
        for _ in 0..100 {
            let busy: i64 =
                self.connection
                    .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
            if busy == 0 {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }

    fn now_text(&self) -> String {
        utc_time(self.now).unwrap_or_else(|| "1970-01-01T00:00:00.000000Z".to_owned())
    }

    /// A fresh, never repeated ID for something the store records itself.
    fn note_id(&mut self, kind: &str) -> Result<EventId, StoreError> {
        let n: i64 = self.connection.query_row(
            "INSERT INTO meta (key, value) VALUES ('notes', '1')
             ON CONFLICT (key) DO UPDATE SET value = CAST(value AS INTEGER) + 1
             RETURNING CAST(value AS INTEGER)",
            [],
            |r| r.get(0),
        )?;
        EventId::derive("logbook", format!("{kind}:{n}").as_bytes(), 0)
            .map_err(|e| StoreError::Invalid(e.to_string()))
    }

    /// Records something the store noticed itself, in the logbook lane.
    fn note(&mut self, kind: &str, summary: &str, details: Value) -> Result<(), StoreError> {
        let id = self.note_id(kind)?;
        let event = self.note_event(id, kind, summary, details)?;
        self.insert(&event)
    }

    fn note_event(
        &self,
        id: EventId,
        kind: &str,
        summary: &str,
        details: Value,
    ) -> Result<Event, StoreError> {
        serde_json::from_value(json!({
            "id": id.as_str(), "time": self.now_text(), "last_time": null, "end": null, "utc_offset": 0,
            "lane": "logbook", "kind": kind, "template": kind, "severity": "problem",
            "subject": {"type": "system", "name": "Logbook store", "version": null, "source_kind": "none",
                        "package": null, "path": null},
            "summary": summary, "details": details, "count": 1, "first_time": false, "links": [],
            "raw": [], "raw_omitted": 0, "raw_lossy": false,
            "source": {"reader": "logbook", "mode": "live"}, "rules_version": 1, "time_uncertain": false
        }))
        .map_err(|e| StoreError::Invalid(e.to_string()))
    }
}

/// The time retention counts from (F-D02): the latest of time, last_time and
/// end; for an event whose time is uncertain, at least when it was stored.
fn retained_from(event: &Event, stored_at: &str) -> String {
    let latest = [
        Some(&event.time),
        event.last_time.as_ref(),
        event.end.as_ref(),
    ]
    .into_iter()
    .flatten()
    .max()
    .map_or_else(String::new, Clone::clone);
    if event.time_uncertain && stored_at > latest.as_str() {
        stored_at.to_owned()
    } else {
        latest
    }
}

/// Whether the store can be used: it opens, isn't newer than this Logbook
/// (that is an error, not damage) and passes SQLite's quick check. Opened
/// read-only: a check must never change what it checks.
fn is_healthy(db: &Path) -> Result<bool, StoreError> {
    let Ok(c) = Connection::open_with_flags(db, CHECK_FLAGS) else {
        return Ok(false);
    };
    match schema_version(&c) {
        Err(e @ StoreError::NewerSchema { .. }) => return Err(e),
        Err(_) => return Ok(false),
        Ok(_) => {}
    }
    Ok(
        matches!(c.query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0)), Ok(s) if s == "ok"),
    )
}

/// Moves a damaged store and its WAL aside as `logbook.db.damaged-<time>`
/// (with -2, -3, … if taken), removes its -shm, and returns the new name.
fn move_aside(dir: &Path, now_micros: i64) -> Result<PathBuf, StoreError> {
    let stamp: String = utc_time(now_micros)
        .unwrap_or_default()
        .chars()
        .take(19)
        .filter(|c| c.is_ascii_digit() || *c == 'T')
        .collect();
    let base = format!("{DB_FILE}.damaged-{stamp}Z");
    let mut name = base.clone();
    let mut n = 1;
    while dir.join(&name).exists() || dir.join(format!("{name}-wal")).exists() {
        n += 1;
        name = format!("{base}-{n}");
    }
    let moved = dir.join(&name);
    std::fs::rename(dir.join(DB_FILE), &moved)?;
    let wal = dir.join(format!("{DB_FILE}-wal"));
    if wal.exists() {
        std::fs::rename(&wal, dir.join(format!("{name}-wal")))?;
    }
    let shm = dir.join(format!("{DB_FILE}-shm"));
    if shm.exists() {
        std::fs::remove_file(shm)?;
    }
    Ok(moved)
}

// The frozen spec: protected, included unchanged, never reformatted.
#[cfg(test)]
#[rustfmt::skip]
#[path = "../../../verify/spec/step2/store_spec.rs"]
mod spec_step2;

#[cfg(test)]
mod tests {
    use super::*;
    use logbook_store::Reader;

    const NOW: i64 = 1_795_521_600_000_000;

    fn temp(name: &str) -> (PathBuf, PathBuf) {
        let root =
            std::env::temp_dir().join(format!("logbook-writer-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let dir = root.join("logbook");
        (root, dir)
    }

    fn event(n: u64, lane: &str, raw: Vec<String>) -> Event {
        let id = EventId::derive("test", &n.to_le_bytes(), 0).unwrap();
        serde_json::from_value(json!({
            "id": id.as_str(), "time": utc_time(NOW - n as i64).unwrap(), "last_time": null, "end": null,
            "utc_offset": 0, "lane": lane, "kind": "test.example", "template": "test.example", "severity": "info",
            "subject": {"type": "system", "name": "x", "version": null, "source_kind": "none", "package": null, "path": null},
            "summary": "Example.", "details": {}, "count": 1, "first_time": false, "links": [], "raw": raw,
            "raw_omitted": 0, "raw_lossy": false, "source": {"reader": "test", "mode": "live"},
            "rules_version": 1, "time_uncertain": false
        }))
        .unwrap()
    }

    /// Over the limit with nothing deletable left (only the logbook lane):
    /// the size limit ends, deletes nothing and records nothing.
    #[test]
    fn size_limit_with_only_the_logbook_lane_left_ends_without_a_note() {
        let (root, dir) = temp("logbook-only");
        let (mut w, _) = Writer::open(&dir, NOW).unwrap();
        for n in 0..20 {
            w.insert(&event(n, "logbook", vec!["l".repeat(500); 4]))
                .unwrap();
        }
        let report = w.enforce_size_limit(1, NOW).unwrap();
        assert_eq!(report, SizeReport::default());
        drop(w);
        let events = Reader::open(&dir).unwrap().events().unwrap();
        assert_eq!(events.len(), 20);
        assert!(events.iter().all(|e| e.kind != "logbook.pruned_early"));
        std::fs::remove_dir_all(root).unwrap();
    }

    /// The size limit deletes no more than it must: one large event over a
    /// store that was exactly at the limit, and only that event goes.
    #[test]
    fn size_limit_deletes_exactly_enough() {
        let (root, dir) = temp("exact");
        let (mut w, _) = Writer::open(&dir, NOW).unwrap();
        for n in 1..40 {
            w.insert(&event(n, "system", vec!["s".repeat(200)]))
                .unwrap();
        }
        let limit = w.used_bytes().unwrap();
        // The oldest event, large enough to need pages of its own.
        w.insert(&event(1000, "system", vec!["L".repeat(1000); 20]))
            .unwrap();
        assert!(w.used_bytes().unwrap() > limit);
        let report = w.enforce_size_limit(limit, NOW).unwrap();
        assert_eq!(
            report,
            SizeReport {
                info: 1,
                problem: 0,
                serious: 0
            }
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}

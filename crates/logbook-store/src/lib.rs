//! Logbook's store, the reading side (F-D01 to F-D05).
//!
//! The store is a SQLite database in the user's data folder
//! (`~/.local/share/logbook/logbook.db`), in the shape of
//! `schema/store-v1.sql`. Exactly one program writes it: the collector,
//! through `logbook-store-write`. Every other part reads through [`Reader`],
//! whose connection is opened read-only and with `query_only`, so even a
//! write attempt fails at the database (F-D04).
//!
//! The tests are the frozen spec of version 0.1a, step 2:
//! `verify/spec/step2/read_only_spec.rs` here, the others in
//! `logbook-store-write`.

use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use logbook_model::{Event, EventId};
use rusqlite::{Connection, OpenFlags};

/// The store schema version this crate implements.
pub const STORE_SCHEMA_VERSION: u32 = 1;
/// The store schema: `schema/store-v1.sql`, unchanged.
pub const STORE_SCHEMA: &str = include_str!("../../../schema/store-v1.sql");
/// The database file in the store folder.
pub const DB_FILE: &str = "logbook.db";
/// A reader's connection: read-only (with query_only on top, F-D04).
const READ_FLAGS: OpenFlags =
    OpenFlags::SQLITE_OPEN_READ_ONLY.union(OpenFlags::SQLITE_OPEN_NO_MUTEX);
/// How long a connection waits for another one's lock before giving up.
pub const BUSY_TIMEOUT: Duration = Duration::from_secs(10);

/// What can go wrong with the store.
#[derive(Debug)]
pub enum StoreError {
    /// The store was made by a newer Logbook (F-D01).
    NewerSchema {
        found: u32,
        supported: u32,
    },
    /// The store folder or a file in it isn't what it must be (F-L10).
    Unsafe(String),
    /// An event the model refuses (F-C01).
    Invalid(String),
    /// There is no store at this place.
    Missing(PathBuf),
    /// A stored event can't be read back.
    Data(String),
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::NewerSchema { found, supported } => write!(
                f,
                "the store was made by a newer Logbook (store version {found}; this Logbook knows up to {supported}); \
                 update Logbook to read it"
            ),
            StoreError::Unsafe(why) => write!(f, "the store isn't safe to use: {why}"),
            StoreError::Invalid(why) => write!(f, "invalid event: {why}"),
            StoreError::Missing(path) => write!(f, "there is no store at {}", path.display()),
            StoreError::Data(why) => write!(f, "a stored event can't be read: {why}"),
            StoreError::Io(e) => write!(f, "{e}"),
            StoreError::Sqlite(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Sqlite(e)
    }
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e)
    }
}

/// The store folder: `$XDG_DATA_HOME/logbook` if XDG_DATA_HOME is set and
/// absolute, else `$HOME/.local/share/logbook` if HOME is absolute, else None
/// (the XDG base directory rules).
pub fn default_dir(xdg_data_home: Option<&OsStr>, home: Option<&OsStr>) -> Option<PathBuf> {
    if let Some(xdg) = xdg_data_home.map(Path::new).filter(|p| p.is_absolute()) {
        return Some(xdg.join("logbook"));
    }
    let home = Path::new(home?);
    home.is_absolute()
        .then(|| home.join(".local/share/logbook"))
}

/// The store's schema version, refusing one newer than this crate knows.
pub fn schema_version(c: &Connection) -> Result<u32, StoreError> {
    let found: u32 = c.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if found > STORE_SCHEMA_VERSION {
        return Err(StoreError::NewerSchema {
            found,
            supported: STORE_SCHEMA_VERSION,
        });
    }
    Ok(found)
}

/// An event from its stored JSON; the model checks it again on the way out.
pub fn decode(json: &str) -> Result<Event, StoreError> {
    serde_json::from_str(json).map_err(|e| StoreError::Data(e.to_string()))
}

/// Reads the store; can't write it.
pub struct Reader {
    // The one connection every query uses.
    connection: Connection,
}

impl Reader {
    /// Opens an existing store read-only. Never creates one.
    pub fn open(dir: &Path) -> Result<Reader, StoreError> {
        let db = dir.join(DB_FILE);
        if !db.is_file() {
            return Err(StoreError::Missing(db));
        }
        let connection = Connection::open_with_flags(&db, READ_FLAGS)?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        // A second layer under the read-only file: even a write that reached
        // SQLite is refused (F-D04).
        connection.execute_batch("PRAGMA query_only = ON")?;
        schema_version(&connection)?;
        Ok(Reader { connection })
    }

    /// Every event, by time, then ID.
    pub fn events(&self) -> Result<Vec<Event>, StoreError> {
        let mut query = self
            .connection
            .prepare("SELECT json FROM events ORDER BY time, id")?;
        let rows = query.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for json in rows {
            out.push(decode(&json?)?);
        }
        Ok(out)
    }

    /// One event by its ID.
    pub fn event(&self, id: &EventId) -> Result<Option<Event>, StoreError> {
        let mut query = self
            .connection
            .prepare("SELECT json FROM events WHERE id = ?1")?;
        let mut rows = query.query([id.as_str()])?;
        match rows.next()? {
            Some(row) => Ok(Some(decode(&row.get::<_, String>(0)?)?)),
            None => Ok(None),
        }
    }

    /// How many events the store holds.
    pub fn count(&self) -> Result<u64, StoreError> {
        let n: i64 = self
            .connection
            .query_row("SELECT count(*) FROM events", [], |r| r.get(0))?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// The reader's connection, for tests that try to write through it.
    #[cfg(test)]
    pub fn connection_for_tests(&self) -> &Connection {
        &self.connection
    }
}

// The frozen spec: protected, included unchanged, never reformatted.
#[cfg(test)]
#[rustfmt::skip]
#[path = "../../../verify/spec/step2/read_only_spec.rs"]
mod spec_step2;

-- Logbook's store, schema version 1 (functions F-D01 to F-D07, F-C12).
-- The database file is logbook.db in the store folder; PRAGMA user_version = 1.
-- Changing this needs schema/store-v2.sql and a migration (F-D01), not an edit.
-- Both layers of F-C12 exist from the start, so no data migration is ever
-- needed to add them.

-- Settings of the store itself (reserved for the migration history).
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

-- Layer 1: raw records as the readers delivered them, kept 30 days by
-- default (F-C12). position says where the record is in its source (the
-- same bytes the event ID is derived from, step 1); text is the record,
-- invalid UTF-8 replaced (lossy = 1).
CREATE TABLE raw_records (
    reader    TEXT NOT NULL,
    position  BLOB NOT NULL,
    time      TEXT NOT NULL,
    text      TEXT NOT NULL,
    lossy     INTEGER NOT NULL CHECK (lossy IN (0, 1)),
    stored_at TEXT NOT NULL,
    PRIMARY KEY (reader, position)
) STRICT;

-- Layer 2: one row per event. json is the event in the shape of
-- schema/event-v1.schema.json; time, lane and severity repeat fields of it
-- for searching. retained_from is the time retention counts from: the latest
-- of time, last_time and end, or, for an event whose time is uncertain, the
-- later of that and stored_at (F-D02).
CREATE TABLE events (
    id            TEXT PRIMARY KEY,
    time          TEXT NOT NULL,
    lane          TEXT NOT NULL,
    severity      TEXT NOT NULL,
    retained_from TEXT NOT NULL,
    stored_at     TEXT NOT NULL,
    json          TEXT NOT NULL
) STRICT;

-- Which raw records each event was derived from, so forgetting an event
-- also forgets its raw records (F-D07).
CREATE TABLE event_sources (
    event_id TEXT NOT NULL REFERENCES events (id) ON DELETE CASCADE,
    reader   TEXT NOT NULL,
    position BLOB NOT NULL,
    PRIMARY KEY (event_id, reader, position)
) STRICT;

-- Forget markers (F-D07): forgotten data isn't brought back by a re-import.
-- lane NULL means every lane.
CREATE TABLE forget_markers (
    lane      TEXT,
    from_time TEXT NOT NULL,
    to_time   TEXT NOT NULL,
    made_at   TEXT NOT NULL
) STRICT;

CREATE INDEX events_by_time ON events (time, id);
CREATE INDEX events_by_lane ON events (lane, retained_from);
CREATE INDEX events_by_severity ON events (severity, time, id);
CREATE INDEX raw_records_by_time ON raw_records (time);
CREATE INDEX event_sources_by_record ON event_sources (reader, position);

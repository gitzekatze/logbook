//! Logbook's event model, stable event IDs and the versioned schema
//! (functions F-C01 and F-C12).
//!
//! Every reader's output becomes an [`Event`]. Its JSON form is the public
//! contract of `--json` and the AI interface: `schema/event-v1.schema.json`.
//! Reading an event checks everything that schema checks, plus the rules the
//! schema can't express, so no part of Logbook can hold an event that breaks
//! the contract.
//!
//! The tests are the frozen spec of version 0.1a, step 1:
//! `verify/spec/step1/model_spec.rs`.

mod event;
mod id;
mod raw;
mod time;

pub use event::{
    Event, Lane, Link, LinkStrength, Severity, Source, SourceKind, SourceMode, Subject, SubjectType,
};
pub use id::{EventId, ModelError};
pub use raw::raw_line;
pub use time::{is_canonical_time, utc_time};

/// The version of the event schema this crate implements.
pub const EVENT_SCHEMA_VERSION: u32 = 1;

#[cfg(test)]
pub mod testing;

// The frozen spec: protected, included unchanged, never reformatted.
#[cfg(test)]
#[rustfmt::skip]
#[path = "../../../verify/spec/step1/model_spec.rs"]
mod spec_step1;

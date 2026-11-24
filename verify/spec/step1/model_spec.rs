//! Spec of version 0.1a, step 1: the event model and stable IDs.
//! Claims: C01.2, C01.3, C12.4, G7 (verify/claims.toml, step = 1).
//!
//! Written before the code and frozen by the owner's approval (build plan,
//! section 4). The code PR includes this file unchanged, in
//! crates/logbook-model/src/lib.rs:
//!
//!     #[cfg(test)]
//!     #[path = "../../../verify/spec/step1/model_spec.rs"]
//!     mod spec_step1;
//!
//! What the code must provide (crate logbook-model):
//!   - `EVENT_SCHEMA_VERSION: u32`, equal to `x-logbook-version` of
//!     schema/event-v1.schema.json.
//!   - `Event` (serde Serialize + Deserialize) with exactly the schema's
//!     fields, and the value types `Lane`, `Severity`, `SubjectType`,
//!     `SourceKind`, `SourceMode`, `LinkStrength`, each with a constant `ALL`
//!     listing every value. Reading an event refuses everything the schema
//!     refuses, plus the rules the schema can't express (its description):
//!     a real calendar date; end and last_time not before time; last_time
//!     set exactly when count > 1; raw_omitted > 0 only when count > 1. The
//!     model guards its own shape; the tests don't do it for it.
//!   - `EventId::derive(reader: &str, position: &[u8], part: u32)
//!     -> Result<EventId, ModelError>` and `EventId::as_str(&self) -> &str`:
//!     "ev-" + the first 32 hex digits of
//!     SHA-256("logbook-event-v1" 0x00 reader 0x00 part-as-4-bytes-little-endian position).
//!     `position` says WHERE the record is in its source (journal cursor,
//!     file and byte offset), never its text, so two identical lines are two
//!     records. `part` numbers the events derived from one record (0, 1, …).
//!     Each reader's spec defines its position. reader must match
//!     ^[a-z0-9_]+$, otherwise ModelError.
//!   - `utc_time(unix_micros: i64) -> Option<String>`: the canonical time
//!     text, exactly 6 decimal places; None before 1970 or after 9999.
//!   - `raw_line(bytes: &[u8]) -> (String, bool)`: the line as text, with
//!     bytes that aren't valid UTF-8 replaced by U+FFFD; the bool says
//!     whether any were replaced (the event's raw_lossy).
//!   - `testing::any_event()`: a proptest strategy over all valid events
//!     (cfg(test) is enough), covering the whole model (see the last test).
//!
//! Dev-dependencies the tests use: proptest, serde_json, sha2, regex.
//!
//! Not in this step: deriving events from raw records (C12.1, G3: step 7),
//! per-kind details schemas (the step that creates each kind), the version
//! wrapper of --json output (step 9). A fold whose first raw record is older
//! than the raw layer (30 days) gets a new ID when re-derived; that is
//! expected and covered with re-deriving in step 7.

use std::collections::BTreeSet;

use proptest::prelude::*;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::testing::any_event;
use crate::{
    raw_line, utc_time, Event, EventId, Lane, LinkStrength, Severity, SourceKind, SourceMode, SubjectType,
    EVENT_SCHEMA_VERSION,
};

const SCHEMA_V1: &str = include_str!("../../../schema/event-v1.schema.json");
/// Fingerprint of schema/event-v1.schema.json. A new, removed or changed
/// field needs a new schema file and a new version, not an edit.
const SCHEMA_V1_SHA256: &str = "e63a940895a62c8c957bf5fa029674563a9948be862278314a3e383493f10876";

fn schema() -> Value {
    serde_json::from_str(SCHEMA_V1).expect("the schema is valid JSON")
}

// ======================================================================= C01.2
// A field change without a version change fails.

#[test]
fn c01_2_schema_file_is_the_one_of_version_1() {
    assert_eq!(EVENT_SCHEMA_VERSION, 1);
    assert_eq!(schema()["x-logbook-version"], json!(EVENT_SCHEMA_VERSION));
    let got = hex(&Sha256::digest(SCHEMA_V1.as_bytes()));
    assert_eq!(got, SCHEMA_V1_SHA256, "schema/event-v1.schema.json was edited; a change needs version 2");
}

/// The Rust type has exactly the schema's fields, at every level.
#[test]
fn c01_2_event_fields_are_exactly_the_schema_fields() {
    let s = schema();
    let v = serde_json::to_value(full_event()).expect("an event serialises");
    assert_same_keys(&v, &s, "event");
    assert_same_keys(&v["subject"], &s["properties"]["subject"], "subject");
    assert_same_keys(&v["source"], &s["properties"]["source"], "source");
    assert_same_keys(&v["links"][0], &s["properties"]["links"]["items"], "link");
}

/// Every value list of the code is exactly the schema's list: a value the
/// tests never produce (say a new lane) can't hide in the code.
#[test]
fn c01_2_value_lists_are_exactly_the_schema_lists() {
    let s = schema();
    let p = &s["properties"];
    assert_same_values(&Lane::ALL, &p["lane"], "lane");
    assert_same_values(&Severity::ALL, &p["severity"], "severity");
    assert_same_values(&SubjectType::ALL, &p["subject"]["properties"]["type"], "subject type");
    assert_same_values(&SourceKind::ALL, &p["subject"]["properties"]["source_kind"], "source kind");
    assert_same_values(&SourceMode::ALL, &p["source"]["properties"]["mode"], "source mode");
    assert_same_values(&LinkStrength::ALL, &p["links"]["items"]["properties"]["strength"], "link strength");
}

fn assert_same_keys(value: &Value, schema: &Value, what: &str) {
    let got: BTreeSet<&String> = value.as_object().expect("an object").keys().collect();
    let want: BTreeSet<&String> = schema["properties"].as_object().expect("properties").keys().collect();
    assert_eq!(got, want, "the {what} fields differ from the schema");
}

fn assert_same_values<T: Serialize>(all: &[T], schema: &Value, what: &str) {
    let got: Vec<Value> = all.iter().map(|v| serde_json::to_value(v).unwrap()).collect();
    let want = schema["enum"].as_array().expect("an enum").clone();
    assert_eq!(got, want, "the {what} values differ from the schema (same values, same order)");
}

// ======================================================================= C01.3
// Reading an event back gives the same event, and the model refuses exactly
// what the schema (with its stated extra rules) refuses.

proptest! {
    #[test]
    fn c01_3_reading_an_event_back_changes_nothing(event in any_event()) {
        let once = serde_json::to_string(&event).unwrap();
        let back: Event = serde_json::from_str(&once).unwrap();
        prop_assert_eq!(&back, &event);
        prop_assert_eq!(serde_json::to_string(&back).unwrap(), once);
    }

    /// Two-sided: take a valid event, change one thing anywhere (a value, a
    /// removed field, an added field), and the model accepts it exactly when
    /// the schema and its extra rules accept it.
    #[test]
    fn c01_3_model_and_schema_agree_on_changed_events(
        event in any_event(), pick in any::<prop::sample::Index>(), value in any::<prop::sample::Index>(), how in 0u8..3,
    ) {
        let mut v = serde_json::to_value(&event).unwrap();
        let paths = pointers(&v, "");
        let path = &paths[pick.index(paths.len())];
        let pool = value_pool();
        match how {
            0 => *v.pointer_mut(path).unwrap() = pool[value.index(pool.len())].clone(),
            1 => remove(&mut v, path),
            _ => add_unknown(&mut v, path),
        }
        let schema_ok = validate(&v, &schema(), "event").is_empty() && extra_rules(&v).is_empty();
        let model_ok = serde_json::from_value::<Event>(v.clone()).is_ok();
        prop_assert_eq!(model_ok, schema_ok, "model {} what the schema {}: {} at {}\n{:#}",
            if model_ok { "accepts" } else { "refuses" }, if schema_ok { "accepts" } else { "refuses" },
            ["changed value", "removed", "added field"][how as usize], path, v);
    }

    /// Times: text order is time order, for every pair.
    #[test]
    fn c01_3_time_text_sorts_like_time(a in 0i64..253_402_300_799_999_999, b in 0i64..253_402_300_799_999_999) {
        let (ta, tb) = (utc_time(a).unwrap(), utc_time(b).unwrap());
        prop_assert_eq!(ta.cmp(&tb), a.cmp(&b), "{} vs {}", ta, tb);
        prop_assert!(time_ok(&ta));
    }
}

#[test]
fn c01_3_the_model_refuses_broken_events() {
    for (what, e) in broken_events() {
        assert!(serde_json::from_value::<Event>(e).is_err(), "the model accepted a broken event: {what}");
    }
}

#[test]
fn c01_3_times_have_one_spelling() {
    assert_eq!(utc_time(0).as_deref(), Some("1970-01-01T00:00:00.000000Z"));
    assert_eq!(utc_time(1_795_473_921_721_966).as_deref(), Some("2026-11-23T22:45:21.721966Z"));
    assert_eq!(utc_time(951_782_400_000_000).as_deref(), Some("2000-02-29T00:00:00.000000Z"));
    assert_eq!(utc_time(253_402_300_799_999_999).as_deref(), Some("9999-12-31T23:59:59.999999Z"));
    assert_eq!(utc_time(-1), None);
    assert_eq!(utc_time(253_402_300_800_000_000), None);
}

#[test]
fn c01_3_raw_lines_keep_their_text_and_mark_lost_bytes() {
    assert_eq!(raw_line(b"[ALPM] upgraded linux"), ("[ALPM] upgraded linux".to_owned(), false));
    assert_eq!(raw_line("Ärger mit 漢字 \u{202e}".as_bytes()), ("Ärger mit 漢字 \u{202e}".to_owned(), false));
    assert_eq!(raw_line(b"tab\tand \x1b[31m escape"), ("tab\tand \x1b[31m escape".to_owned(), false));
    assert_eq!(raw_line(b"bad \xff\xfe end"), ("bad \u{fffd}\u{fffd} end".to_owned(), true));
    assert_eq!(raw_line(b""), (String::new(), false));
}

// ======================================================================= C12.4
// The ID depends only on the reader, the record's position and the part.

/// Known answers. These IDs are part of the public contract: a change of the
/// derivation would change every stored ID and break every link and undo.
#[test]
fn c12_4_ids_have_their_known_values() {
    let journal: &[u8] = b"s=8f1e2a;i=1a2b;b=5c6d;m=12ab;t=63f0c1;x=9e8d";
    let cases: [(&str, &[u8], u32, &str); 5] = [
        ("pacman", b"pacman.log:1873442", 0, "ev-b1cd9f58c8f91843c04205319b7fe1be"),
        ("journal", journal, 0, "ev-978a146ec96ae90f84ad5a2d9dec8d6d"),
        ("journal", journal, 1, "ev-c9ac86c0f60d028d7fbcb7a2651d984b"),
        ("coredump", b"", 0, "ev-bed66f3df78fcd8f017434f1cb180d60"),
        ("pacman", b"\xff\xfe binary \x00 bytes", u32::MAX, "ev-663fce1f9e365b35650ca8f7592fd677"),
    ];
    for (reader, position, part, want) in cases {
        let id = EventId::derive(reader, position, part).expect("a valid reader name");
        assert_eq!(id.as_str(), want, "ID of {reader}/{position:?}/{part}");
    }
}

/// A reader name outside ^[a-z0-9_]+$ is refused, so the separator can't be
/// forged.
#[test]
fn c12_4_reader_names_are_refused_unless_simple() {
    for bad in ["", "Pacman", "pac man", "pac\0man", "pac-man", "pacman/", "ä"] {
        assert!(EventId::derive(bad, b"x", 0).is_err(), "reader name {bad:?} must be refused");
    }
}

proptest! {
    /// The same record gives the same ID in any order, with repetitions in
    /// between: no counter, no clock, no randomness.
    #[test]
    fn c12_4_ids_depend_only_on_reader_position_and_part(
        records in prop::collection::vec(("[a-z0-9_]{1,12}", prop::collection::vec(any::<u8>(), 0..64), any::<u32>()), 1..40)
    ) {
        let first: Vec<String> = records.iter()
            .map(|(r, k, p)| EventId::derive(r, k, *p).unwrap().as_str().to_owned()).collect();
        let mut reversed: Vec<String> = records.iter().rev()
            .map(|(r, k, p)| EventId::derive(r, k, *p).unwrap().as_str().to_owned()).collect();
        reversed.reverse();
        prop_assert_eq!(&first, &reversed);
        for (i, (r, k, p)) in records.iter().enumerate() {
            let _ = EventId::derive(r, k, *p);
            let again = EventId::derive(r, k, *p).unwrap();
            prop_assert_eq!(again.as_str(), first[i].as_str());
        }
    }

    /// Different records, or different parts of one record, get different IDs.
    #[test]
    fn c12_4_different_records_or_parts_get_different_ids(
        a in ("[a-z0-9_]{1,12}", prop::collection::vec(any::<u8>(), 0..64), 0u32..4),
        b in ("[a-z0-9_]{1,12}", prop::collection::vec(any::<u8>(), 0..64), 0u32..4),
    ) {
        prop_assume!(a != b);
        let (ia, ib) = (EventId::derive(&a.0, &a.1, a.2).unwrap(), EventId::derive(&b.0, &b.1, b.2).unwrap());
        prop_assert_ne!(ia.as_str(), ib.as_str());
    }
}

// ========================================================================== G7
// All --json and AI-interface output is valid against the versioned schema.

proptest! {
    #[test]
    fn g7_every_event_matches_the_schema(event in any_event()) {
        let v = serde_json::to_value(&event).unwrap();
        let mut problems = validate(&v, &schema(), "event");
        problems.extend(extra_rules(&v));
        prop_assert!(problems.is_empty(), "{:#?}\n{:#}", problems, v);
    }
}

/// The extremes: every field set, nulls, 20 raw lines, other scripts, control
/// characters in raw lines (the model stores them; renderers make them
/// harmless, G5).
#[test]
fn g7_extreme_events_match_the_schema() {
    let s = schema();
    let mut e = serde_json::to_value(full_event()).unwrap();
    assert!(validate(&e, &s, "event").is_empty() && extra_rules(&e).is_empty());
    e["end"] = Value::Null;
    e["last_time"] = Value::Null;
    e["count"] = json!(1);
    e["raw_omitted"] = json!(0);
    e["subject"] = json!({"type": "device", "name": "Logitech MX 漢字", "version": null,
                          "source_kind": "none", "package": null, "path": null});
    e["links"] = json!([]);
    e["raw"] = json!(vec!["\u{202e}evil\u{1b}[31m 漢字 \u{fffd}"; 20]);
    e["raw_lossy"] = json!(true);
    e["utc_offset"] = json!(50400);
    let back: Event = serde_json::from_value(e.clone()).expect("the extreme event reads back");
    let again = serde_json::to_value(back).unwrap();
    assert_eq!(again, e);
    assert!(validate(&again, &s, "event").is_empty() && extra_rules(&again).is_empty());
}

/// The test's own check: the validator and the extra rules refuse every
/// broken event, so G7 can't pass with checks that accept everything.
#[test]
fn g7_the_validator_refuses_broken_events() {
    let s = schema();
    for (what, e) in broken_events() {
        let problems = [validate(&e, &s, "event"), extra_rules(&e)].concat();
        assert!(!problems.is_empty(), "the checks accepted a broken event: {what}");
    }
}

// ================================================================ the generator

/// any_event() covers the whole model, so C01.3, C12.4 and G7 don't run on a
/// narrow corner only.
#[test]
fn any_event_covers_the_model() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    let s = schema();
    let p = &s["properties"];
    let mut want = BTreeSet::new();
    for (name, list) in [
        ("lane", &p["lane"]),
        ("severity", &p["severity"]),
        ("subject", &p["subject"]["properties"]["type"]),
        ("source_kind", &p["subject"]["properties"]["source_kind"]),
        ("mode", &p["source"]["properties"]["mode"]),
        ("strength", &p["links"]["items"]["properties"]["strength"]),
    ] {
        for value in list["enum"].as_array().unwrap() {
            want.insert(format!("{name}={value}"));
        }
    }
    for flag in ["end_set", "end_null", "folded", "single", "links", "details", "non_ascii", "lossy",
                 "omitted", "uncertain", "first_time", "negative_offset", "version_null", "package_set"] {
        want.insert(flag.to_owned());
    }
    let mut seen = BTreeSet::new();
    let mut runner = TestRunner::deterministic();
    for _ in 0..3000 {
        let v = serde_json::to_value(any_event().new_tree(&mut runner).unwrap().current()).unwrap();
        for (name, value) in [("lane", &v["lane"]), ("severity", &v["severity"]), ("subject", &v["subject"]["type"]),
                              ("source_kind", &v["subject"]["source_kind"]), ("mode", &v["source"]["mode"])] {
            seen.insert(format!("{name}={value}"));
        }
        for link in v["links"].as_array().unwrap() {
            seen.insert(format!("strength={}", link["strength"]));
        }
        let text = format!("{}{}", v["summary"], v["subject"]["name"]);
        for (flag, on) in [
            ("end_set", !v["end"].is_null()), ("end_null", v["end"].is_null()),
            ("folded", v["count"].as_u64() > Some(1)), ("single", v["count"] == json!(1)),
            ("links", !v["links"].as_array().unwrap().is_empty()),
            ("details", !v["details"].as_object().unwrap().is_empty()),
            ("non_ascii", !text.is_ascii()), ("lossy", v["raw_lossy"] == json!(true)),
            ("omitted", v["raw_omitted"].as_u64() > Some(0)), ("uncertain", v["time_uncertain"] == json!(true)),
            ("first_time", v["first_time"] == json!(true)), ("negative_offset", v["utc_offset"].as_i64() < Some(0)),
            ("version_null", v["subject"]["version"].is_null()), ("package_set", !v["subject"]["package"].is_null()),
        ] {
            if on {
                seen.insert(flag.to_owned());
            }
        }
    }
    let missing: Vec<_> = want.difference(&seen).collect();
    assert!(missing.is_empty(), "any_event() never produces: {missing:?}");
}

// ====================================================================== helpers

/// An event with every field set.
fn full_event() -> Event {
    serde_json::from_value(json!({
        "id": "ev-b1cd9f58c8f91843c04205319b7fe1be",
        "time": "2026-11-20T09:15:02.000000Z",
        "last_time": "2026-11-20T09:40:00.500000Z",
        "end": "2026-11-20T09:41:09.250000Z",
        "utc_offset": 3600,
        "lane": "updates",
        "kind": "update.transaction",
        "template": "update.transaction",
        "severity": "info",
        "subject": {"type": "package", "name": "linux", "version": "6.17.2-1", "source_kind": "package",
                    "package": "linux", "path": "/usr/lib/modules/6.17.2-arch1-1/vmlinuz"},
        "summary": "Updated the Linux kernel from 6.17.1 to 6.17.2.",
        "details": {"from": "6.17.1-1", "to": "6.17.2-1", "packages": 1},
        "count": 2,
        "first_time": false,
        "links": [{"kind": "right_after", "id": "ev-978a146ec96ae90f84ad5a2d9dec8d6d",
                   "reason": "The kernel was updated 3 minutes before.", "strength": "strong"}],
        "raw": ["[2026-11-20T10:15:02+0100] [ALPM] upgraded linux (6.17.1-1 -> 6.17.2-1)"],
        "raw_omitted": 1,
        "raw_lossy": false,
        "source": {"reader": "pacman", "mode": "live"},
        "rules_version": 1,
        "time_uncertain": false
    }))
    .expect("the full sample event fits the model")
}

/// One change at a time to an otherwise valid event; each breaks the schema
/// or one of its extra rules.
fn broken_events() -> Vec<(String, Value)> {
    let good = serde_json::to_value(full_event()).unwrap();
    let mut broken = Vec::new();
    for (path, value) in [
        ("/lane", json!("weather")),
        ("/severity", json!("fine")),
        ("/id", json!("ev-123")),
        ("/time", json!("2026-11-20 10:15")),
        ("/time", json!("2026-11-20T09:15:02Z")),
        ("/time", json!("2026-11-20T09:15:02.25Z")),
        ("/time", json!("2026-02-30T09:15:02.000000Z")),
        ("/time", json!("2026-13-01T09:15:02.000000Z")),
        ("/time", json!("2026-11-20T25:15:02.000000Z")),
        ("/time", json!("2025-02-29T00:00:00.000000Z")),
        ("/end", json!("2026-11-20T09:15:01.999999Z")),
        ("/last_time", json!("2026-11-20T09:15:01.000000Z")),
        ("/last_time", Value::Null),
        ("/count", json!(0)),
        ("/count", json!(1)),
        ("/kind", json!("Update")),
        ("/kind", json!("update._")),
        ("/kind", json!("update")),
        ("/template", json!("")),
        ("/summary", json!("")),
        ("/summary", json!("   ")),
        ("/summary", json!(" Updated.")),
        ("/summary", json!("Updated.\nAnd more.")),
        ("/source/mode", json!("guessed")),
        ("/source/reader", json!("Pac Man")),
        ("/subject/type", json!("cat")),
        ("/subject/name", json!("")),
        ("/subject/source_kind", json!("magic")),
        ("/links/0/id", json!("ev-XYZ")),
        ("/links/0/kind", json!("Right After")),
        ("/links/0/strength", json!("certain")),
        ("/links/0/reason", json!("")),
        ("/first_time", json!("no")),
        ("/details", json!([1, 2])),
        ("/utc_offset", json!(60000)),
        ("/utc_offset", json!(1.5)),
        ("/raw_omitted", json!(-1)),
        ("/rules_version", json!(0)),
    ] {
        let mut e = good.clone();
        *e.pointer_mut(path).unwrap() = value.clone();
        broken.push((format!("{path} = {value}"), e));
    }
    let mut single = good.clone();
    single["count"] = json!(1);
    single["last_time"] = Value::Null;
    single["raw_omitted"] = json!(3);
    broken.push(("raw_omitted on an event that wasn't folded".into(), single));
    for (what, path, key) in [("extra field", "", "mood"), ("extra subject field", "/subject", "colour"),
                              ("extra link field", "/links/0", "why"), ("extra source field", "/source", "host")] {
        let mut e = good.clone();
        e.pointer_mut(path).unwrap().as_object_mut().unwrap().insert(key.into(), json!("x"));
        broken.push((what.into(), e));
    }
    for field in ["lane", "rules_version", "raw_lossy", "last_time"] {
        let mut e = good.clone();
        e.as_object_mut().unwrap().remove(field);
        broken.push((format!("missing {field}"), e));
    }
    let mut long = good.clone();
    long["raw"] = json!(vec!["x"; 21]);
    broken.push(("21 raw lines".into(), long));
    broken
}

/// The schema's extra rules (its description), checked here independently of
/// the model.
fn extra_rules(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let time = v["time"].as_str().unwrap_or("");
    for field in ["time", "last_time", "end"] {
        if let Some(t) = v.get(field).and_then(Value::as_str) {
            if !time_ok(t) {
                out.push(format!("{field}: {t} is not a real date and time"));
            }
            if field != "time" && t < time {
                out.push(format!("{field} is before time"));
            }
        }
    }
    let folded = v["count"].as_u64().is_some_and(|c| c > 1);
    if v.get("last_time").is_some_and(|t| t.is_null() == folded) {
        out.push("last_time must be set exactly when count > 1".into());
    }
    if v["raw_omitted"].as_u64().is_some_and(|n| n > 0) && !folded {
        out.push("raw_omitted > 0 needs count > 1".into());
    }
    out
}

/// A canonical time with a real calendar date and clock time.
fn time_ok(t: &str) -> bool {
    let re = regex::Regex::new(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.[0-9]{6}Z$").unwrap();
    let Some(c) = re.captures(t) else { return false };
    let n = |i: usize| c[i].parse::<u32>().unwrap();
    let (y, m, d) = (n(1), n(2), n(3));
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    (1..=12).contains(&m) && d >= 1 && d <= days[(m - 1) as usize] && n(4) < 24 && n(5) < 60 && n(6) < 60
}

/// Every JSON pointer inside a value (for the two-sided test). Inside
/// details anything goes, so its inner values aren't changed one by one.
fn pointers(v: &Value, at: &str) -> Vec<String> {
    let mut out = vec![at.to_owned()];
    match v {
        Value::Object(o) if !at.ends_with("/details") => {
            for (k, x) in o {
                out.extend(pointers(x, &format!("{at}/{k}")));
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                out.extend(pointers(x, &format!("{at}/{i}")));
            }
        }
        _ => {}
    }
    out.retain(|p| !p.is_empty());
    out
}

fn remove(v: &mut Value, path: &str) {
    let (parent, last) = path.rsplit_once('/').unwrap();
    match v.pointer_mut(parent).unwrap() {
        Value::Object(o) => {
            o.remove(last);
        }
        Value::Array(a) => {
            a.remove(last.parse::<usize>().unwrap());
        }
        _ => {}
    }
}

fn add_unknown(v: &mut Value, path: &str) {
    let (parent, _) = path.rsplit_once('/').unwrap();
    if let Value::Object(o) = v.pointer_mut(parent).unwrap() {
        o.insert("unknown_field".into(), json!(1));
    }
}

/// Values the two-sided test puts anywhere: valid and invalid ones of every type.
fn value_pool() -> Vec<Value> {
    vec![
        Value::Null, json!(true), json!(false), json!(0), json!(1), json!(2), json!(-1), json!(1.5),
        json!(60000), json!(-43200), json!(""), json!(" "), json!("x"), json!("Ä 漢字"), json!("a\nb"),
        json!("ev-123"), json!("ev-978a146ec96ae90f84ad5a2d9dec8d6d"), json!("2026-11-20T09:15:02.000000Z"),
        json!("2026-11-20T10:00:00.000000Z"), json!("2026-11-20T09:00:00.000000Z"),
        json!("2026-02-30T00:00:00.000000Z"), json!("2026-11-20T09:15:02Z"), json!("info"), json!("serious"),
        json!("crashes"), json!("weather"), json!("package"), json!("flatpak"), json!("none"), json!("live"),
        json!("strong"), json!("weak"), json!("update.transaction"), json!("Update"), json!("pacman"),
        json!([]), json!(["x"]), json!(vec!["x"; 21]), json!({}), json!({"a": 1}),
    ]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A small JSON Schema validator for exactly what schema/event-v1 uses:
/// type (with null), enum, pattern, minLength, minimum, maximum, required,
/// additionalProperties: false, properties, items, maxItems.
fn validate(v: &Value, s: &Value, at: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(list) = s.get("enum").and_then(Value::as_array) {
        if !list.contains(v) {
            out.push(format!("{at}: {v} is not one of {list:?}"));
        }
    }
    let types: Vec<&str> = match s.get("type") {
        Some(Value::String(t)) => vec![t.as_str()],
        Some(Value::Array(ts)) => ts.iter().filter_map(Value::as_str).collect(),
        _ => vec![],
    };
    if !types.is_empty() {
        let ok = types.iter().any(|t| match *t {
            "string" => v.is_string(),
            "integer" => v.is_i64() || v.is_u64(),
            "boolean" => v.is_boolean(),
            "object" => v.is_object(),
            "array" => v.is_array(),
            "null" => v.is_null(),
            _ => false,
        });
        if !ok {
            out.push(format!("{at}: {v} is not of type {types:?}"));
            return out;
        }
    }
    if let Some(text) = v.as_str() {
        if let Some(p) = s.get("pattern").and_then(Value::as_str) {
            if !regex::Regex::new(p).unwrap().is_match(text) {
                out.push(format!("{at}: {text:?} doesn't match {p}"));
            }
        }
        if let Some(n) = s.get("minLength").and_then(Value::as_u64) {
            if (text.chars().count() as u64) < n {
                out.push(format!("{at}: shorter than {n}"));
            }
        }
    }
    if let Some(n) = v.as_i64() {
        if s.get("minimum").and_then(Value::as_i64).is_some_and(|min| n < min) {
            out.push(format!("{at}: {n} is below the minimum"));
        }
        if s.get("maximum").and_then(Value::as_i64).is_some_and(|max| n > max) {
            out.push(format!("{at}: {n} is above the maximum"));
        }
    }
    if let Some(obj) = v.as_object() {
        let props = s.get("properties").and_then(Value::as_object);
        for name in s.get("required").and_then(Value::as_array).into_iter().flatten() {
            let name = name.as_str().unwrap();
            if !obj.contains_key(name) {
                out.push(format!("{at}: missing {name}"));
            }
        }
        for (k, val) in obj {
            match props.and_then(|p| p.get(k)) {
                Some(ps) => out.extend(validate(val, ps, &format!("{at}.{k}"))),
                None if s.get("additionalProperties") == Some(&Value::Bool(false)) => {
                    out.push(format!("{at}: unknown field {k}"))
                }
                None => {}
            }
        }
    }
    if let Some(items) = v.as_array() {
        if let Some(max) = s.get("maxItems").and_then(Value::as_u64) {
            if items.len() as u64 > max {
                out.push(format!("{at}: more than {max} items"));
            }
        }
        if let Some(is) = s.get("items") {
            for (i, item) in items.iter().enumerate() {
                out.extend(validate(item, is, &format!("{at}[{i}]")));
            }
        }
    }
    out
}

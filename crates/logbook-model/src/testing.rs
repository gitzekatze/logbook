//! Test helpers: a generator of valid events for property tests (proptest).

use proptest::prelude::*;
use serde_json::Value;

use crate::event::{MAX_RAW_LINES, UTC_OFFSETS};
use crate::{
    raw_line, utc_time, Event, EventId, Lane, Link, LinkStrength, Severity, Source, SourceKind,
    SourceMode, Subject, SubjectType,
};

fn one_of<T: Copy + std::fmt::Debug + 'static>(all: &'static [T]) -> impl Strategy<Value = T> {
    prop::sample::select(all)
}

/// One line of text in several scripts, no white space at the ends.
fn sentence() -> impl Strategy<Value = String> {
    "[A-Za-zÄÖÜäöüß漢字0-9][A-Za-z ÄÖÜäöüß漢字0-9.,:'()-]{0,40}[A-Za-z.ä漢)]"
}

fn dotted_name() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9]{0,8}(\\.[a-z0-9]{1,8}(_[a-z0-9]{1,5}){0,2}){1,3}"
}

fn event_id() -> impl Strategy<Value = EventId> {
    (
        "[a-z0-9_]{1,10}",
        prop::collection::vec(any::<u8>(), 0..24),
        0u32..4,
    )
        .prop_map(|(reader, position, part)| EventId::derive(&reader, &position, part).unwrap())
}

fn subject() -> impl Strategy<Value = Subject> {
    (
        one_of(&SubjectType::ALL),
        "[A-Za-zÄäß漢字][A-Za-z0-9 ._+ÄäöÖß漢字-]{0,24}",
        prop::option::of("[0-9][0-9a-z.:+~-]{0,14}"),
        one_of(&SourceKind::ALL),
        prop::option::of("[a-z0-9][a-z0-9.+-]{0,20}"),
        prop::option::of("/[A-Za-z0-9/._-]{1,40}"),
    )
        .prop_map(
            |(kind, name, version, source_kind, package, path)| Subject {
                kind,
                name,
                version,
                source_kind,
                package,
                path,
            },
        )
}

fn link() -> impl Strategy<Value = Link> {
    (
        "[a-z0-9]{1,8}(_[a-z0-9]{1,6}){0,2}",
        event_id(),
        sentence(),
        one_of(&LinkStrength::ALL),
    )
        .prop_map(|(kind, id, reason, strength)| Link {
            kind,
            id,
            reason,
            strength,
        })
}

/// Raw lines from arbitrary bytes, so some aren't valid UTF-8.
fn raw_lines() -> impl Strategy<Value = (Vec<String>, bool)> {
    prop::collection::vec(prop::collection::vec(any::<u8>(), 0..40), 0..=MAX_RAW_LINES).prop_map(
        |lines| {
            let mut lossy = false;
            let raw = lines
                .iter()
                .map(|bytes| {
                    let (text, lost) = raw_line(bytes);
                    lossy |= lost;
                    text
                })
                .collect();
            (raw, lossy)
        },
    )
}

fn details() -> impl Strategy<Value = serde_json::Map<String, Value>> {
    let value = prop_oneof![
        any::<i64>().prop_map(Value::from),
        any::<bool>().prop_map(Value::from),
        ".{0,20}".prop_map(Value::from),
        Just(Value::Null),
    ];
    prop::collection::btree_map("[a-z][a-z_]{0,10}", value, 0..5)
        .prop_map(|m| m.into_iter().collect())
}

/// Every valid event: all lanes, severities, subject and source kinds, link
/// strengths; folded and single events; with and without durations, links,
/// details, lost bytes and omitted raw lines.
pub fn any_event() -> impl Strategy<Value = Event> {
    // 2000-01-01 to 2100-01-01, in microseconds.
    let start = 946_684_800_000_000i64..4_102_444_800_000_000i64;
    let later = prop::option::of(0i64..864_000_000_000);
    (
        (
            event_id(),
            start,
            later.clone(),
            later,
            UTC_OFFSETS,
            one_of(&Lane::ALL),
            dotted_name(),
            dotted_name(),
        ),
        (
            one_of(&Severity::ALL),
            subject(),
            sentence(),
            details(),
            1u64..6,
            any::<bool>(),
        ),
        (
            prop::collection::vec(link(), 0..4),
            raw_lines(),
            0u64..30,
            any::<(SourceMode, bool)>(),
            "[a-z0-9_]{1,12}",
            1u64..5,
        ),
    )
        .prop_map(
            |(
                (id, time, last, end, utc_offset, lane, kind, template),
                (severity, subject, summary, details, count, first_time),
                (links, (raw, raw_lossy), omitted, (mode, time_uncertain), reader, rules_version),
            )| {
                let folded = count > 1;
                Event {
                    id,
                    time: utc_time(time).unwrap(),
                    last_time: folded.then(|| utc_time(time + last.unwrap_or(1)).unwrap()),
                    end: end.map(|d| utc_time(time + d).unwrap()),
                    utc_offset,
                    lane,
                    kind,
                    template,
                    severity,
                    subject,
                    summary,
                    details,
                    count,
                    first_time,
                    links,
                    raw,
                    raw_omitted: if folded { omitted } else { 0 },
                    raw_lossy,
                    source: Source { reader, mode },
                    rules_version,
                    time_uncertain,
                }
            },
        )
}

impl Arbitrary for SourceMode {
    type Parameters = ();
    type Strategy = BoxedStrategy<SourceMode>;
    fn arbitrary_with(_: ()) -> Self::Strategy {
        one_of(&SourceMode::ALL).boxed()
    }
}

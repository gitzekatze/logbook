//! The event (F-C01), in the shape of `schema/event-v1.schema.json`.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::id::{is_simple_name, EventId, ModelError};
use crate::time::is_canonical_time;

pub use crate::raw::MAX_RAW_LINES;
/// The UTC offsets that exist: UTC-12 to UTC+14, in seconds.
pub const UTC_OFFSETS: std::ops::RangeInclusive<i32> = -43_200..=50_400;

macro_rules! value_list {
    ($(#[$doc:meta])* $name:ident { $($variant:ident = $text:literal),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub enum $name {
            $(#[serde(rename = $text)] $variant),+
        }

        impl $name {
            /// Every value, in the schema's order.
            pub const ALL: [$name; [$($text),+].len()] = [$($name::$variant),+];

            /// The value as written in JSON.
            pub fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $text),+
                }
            }
        }
    };
}

value_list!(
    /// The lane an event belongs to.
    Lane { Updates = "updates", System = "system", Crashes = "crashes", Settings = "settings",
           Privacy = "privacy", Hardware = "hardware", Logbook = "logbook" }
);
value_list!(
    /// How much an event matters.
    Severity { Info = "info", Problem = "problem", Serious = "serious" }
);
value_list!(
    /// What an event is about.
    SubjectType { Program = "program", Package = "package", Device = "device", Service = "service",
                  System = "system", Setting = "setting" }
);
value_list!(
    /// Where a subject comes from (F-C09); `None` for subjects that aren't programs.
    SourceKind { Package = "package", Flatpak = "flatpak", Snap = "snap", AppImage = "appimage",
                 File = "file", Sandbox = "sandbox", Unknown = "unknown", None = "none" }
);
value_list!(
    /// Whether a reader saw the event live or imported it later.
    SourceMode { Live = "live", Imported = "imported" }
);
value_list!(
    /// How strong a "happened right after" link is (F-C06).
    LinkStrength { Strong = "strong", Weak = "weak" }
);

/// Who or what an event is about.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    #[serde(rename = "type")]
    pub kind: SubjectType,
    pub name: String,
    // Nullable but required: `deserialize_with` keeps serde from reading a
    // missing field as null.
    #[serde(deserialize_with = "Option::deserialize")]
    pub version: Option<String>,
    pub source_kind: SourceKind,
    #[serde(deserialize_with = "Option::deserialize")]
    pub package: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub path: Option<String>,
}

/// A link to a related event, with the reason in plain words (F-C06).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Link {
    pub kind: String,
    pub id: EventId,
    pub reason: String,
    pub strength: LinkStrength,
}

/// Which reader produced an event, and how.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub reader: String,
    pub mode: SourceMode,
}

/// One event. Reading one (from JSON or the store) checks every rule of the
/// schema and the extra rules in its description; see [`Event::check`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "EventFields")]
pub struct Event {
    pub id: EventId,
    pub time: String,
    pub last_time: Option<String>,
    pub end: Option<String>,
    pub utc_offset: i32,
    pub lane: Lane,
    pub kind: String,
    pub template: String,
    pub severity: Severity,
    pub subject: Subject,
    pub summary: String,
    pub details: Map<String, Value>,
    pub count: u64,
    pub first_time: bool,
    pub links: Vec<Link>,
    pub raw: Vec<String>,
    pub raw_omitted: u64,
    pub raw_lossy: bool,
    pub source: Source,
    pub rules_version: u64,
    pub time_uncertain: bool,
}

/// The fields as read, before the checks.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventFields {
    id: EventId,
    time: String,
    #[serde(deserialize_with = "Option::deserialize")]
    last_time: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    end: Option<String>,
    utc_offset: i32,
    lane: Lane,
    kind: String,
    template: String,
    severity: Severity,
    subject: Subject,
    summary: String,
    details: Map<String, Value>,
    count: u64,
    first_time: bool,
    links: Vec<Link>,
    raw: Vec<String>,
    raw_omitted: u64,
    raw_lossy: bool,
    source: Source,
    rules_version: u64,
    time_uncertain: bool,
}

impl TryFrom<EventFields> for Event {
    type Error = ModelError;

    fn try_from(f: EventFields) -> Result<Self, ModelError> {
        let event = Event {
            id: f.id,
            time: f.time,
            last_time: f.last_time,
            end: f.end,
            utc_offset: f.utc_offset,
            lane: f.lane,
            kind: f.kind,
            template: f.template,
            severity: f.severity,
            subject: f.subject,
            summary: f.summary,
            details: f.details,
            count: f.count,
            first_time: f.first_time,
            links: f.links,
            raw: f.raw,
            raw_omitted: f.raw_omitted,
            raw_lossy: f.raw_lossy,
            source: f.source,
            rules_version: f.rules_version,
            time_uncertain: f.time_uncertain,
        };
        event.check()?;
        Ok(event)
    }
}

impl Event {
    /// Every rule of the schema that the types don't already guarantee, and
    /// the extra rules of its description.
    pub fn check(&self) -> Result<(), ModelError> {
        let fail = |what: String| Err(ModelError(what));
        if !is_canonical_time(&self.time) {
            return fail(format!("time {:?} isn't a canonical UTC time", self.time));
        }
        for (name, value) in [("last_time", &self.last_time), ("end", &self.end)] {
            if let Some(t) = value {
                if !is_canonical_time(t) {
                    return fail(format!("{name} {t:?} isn't a canonical UTC time"));
                }
                // Canonical times sort as text in time order.
                if t.as_str() < self.time.as_str() {
                    return fail(format!("{name} is before time"));
                }
            }
        }
        let folded = self.count > 1;
        if self.count == 0 {
            return fail("count is 0".into());
        }
        if self.last_time.is_some() != folded {
            return fail("last_time must be set exactly when count > 1".into());
        }
        if self.raw_omitted > 0 && !folded {
            return fail("raw_omitted > 0 needs count > 1".into());
        }
        if !UTC_OFFSETS.contains(&self.utc_offset) {
            return fail(format!(
                "utc_offset {} is outside UTC-12 to UTC+14",
                self.utc_offset
            ));
        }
        if !is_dotted_name(&self.kind) {
            return fail(format!("kind {:?} isn't of the form word.word", self.kind));
        }
        if !is_dotted_name(&self.template) {
            return fail(format!(
                "template {:?} isn't of the form word.word",
                self.template
            ));
        }
        if !is_sentence(&self.summary) {
            return fail(
                "summary must be one line without control characters or spaces at the ends".into(),
            );
        }
        if self.subject.name.is_empty() {
            return fail("subject name is empty".into());
        }
        for link in &self.links {
            if !is_word_name(&link.kind) {
                return fail(format!(
                    "link kind {:?} isn't of the form word_word",
                    link.kind
                ));
            }
            if !is_sentence(&link.reason) {
                return fail(
                    "link reason must be one line without control characters or spaces at the ends"
                        .into(),
                );
            }
        }
        if self.raw.len() > MAX_RAW_LINES {
            return fail(format!(
                "{} raw lines; at most {MAX_RAW_LINES}",
                self.raw.len()
            ));
        }
        if !is_simple_name(&self.source.reader) {
            return fail(format!(
                "reader name {:?} isn't of the form [a-z0-9_]+",
                self.source.reader
            ));
        }
        if self.rules_version == 0 {
            return fail("rules_version is 0".into());
        }
        Ok(())
    }
}

/// `^[a-z0-9]+(_[a-z0-9]+)*$`
fn is_word_name(s: &str) -> bool {
    !s.is_empty()
        && s.split('_').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

/// `^[a-z][a-z0-9]*(\.[a-z0-9]+(_[a-z0-9]+)*)+$`, e.g. `update.transaction`.
fn is_dotted_name(s: &str) -> bool {
    let mut parts = s.split('.');
    let first = parts.next().unwrap_or("");
    let starts_with_letter = first.bytes().next().is_some_and(|b| b.is_ascii_lowercase());
    let rest: Vec<&str> = parts.collect();
    starts_with_letter
        && first
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && !rest.is_empty()
        && rest.iter().all(|p| is_word_name(p))
}

/// One line of text: not empty, no control characters, no white space at
/// either end.
fn is_sentence(s: &str) -> bool {
    let first = s.chars().next();
    let last = s.chars().next_back();
    match (first, last) {
        (Some(a), Some(z)) => {
            !a.is_whitespace() && !z.is_whitespace() && !s.chars().any(char::is_control)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::testing::any_event;
    use proptest::strategy::{Strategy, ValueTree};
    use proptest::test_runner::TestRunner;

    /// "Not before time" includes the same moment: an end or last time equal
    /// to the start is valid.
    #[test]
    fn end_and_last_time_may_equal_the_start() {
        let mut runner = TestRunner::deterministic();
        let mut e = any_event().new_tree(&mut runner).unwrap().current();
        e.count = 2;
        e.last_time = Some(e.time.clone());
        e.end = Some(e.time.clone());
        e.raw_omitted = 0;
        assert_eq!(e.check(), Ok(()));
    }
}

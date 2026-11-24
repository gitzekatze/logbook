//! Stable event IDs (F-C12).

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

/// Something the model refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelError(pub(crate) String);

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ModelError {}

/// An event's ID: `ev-` and 32 lower-case hex digits.
///
/// It is derived, never counted: from the reader, the position of the event's
/// first raw record in its source (never the record's text) and the event's
/// part number within that record. The same record always gives the same ID,
/// so re-deriving keeps every link, report reference and undo valid.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct EventId(String);

const DOMAIN: &[u8] = b"logbook-event-v1";

impl EventId {
    /// `"ev-"` + the first 32 hex digits of
    /// SHA-256(`logbook-event-v1` 0x00 reader 0x00 part (4 bytes, little-endian) position).
    ///
    /// `reader` must match `^[a-z0-9_]+$`: a 0x00 or other separator in it
    /// could make two different records collide.
    pub fn derive(reader: &str, position: &[u8], part: u32) -> Result<EventId, ModelError> {
        if !is_simple_name(reader) {
            return Err(ModelError(format!(
                "reader name {reader:?} isn't of the form [a-z0-9_]+"
            )));
        }
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update([0]);
        hash.update(reader.as_bytes());
        hash.update([0]);
        hash.update(part.to_le_bytes());
        hash.update(position);
        let digest = hash.finalize();
        let mut text = String::with_capacity(35);
        text.push_str("ev-");
        for byte in &digest[..16] {
            text.push(hex_digit(byte >> 4));
            text.push(hex_digit(byte & 0x0f));
        }
        Ok(EventId(text))
    }

    /// The ID as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Accepts an ID read from storage or JSON, if it has the right form.
    pub fn parse(text: &str) -> Result<EventId, ModelError> {
        let digits = text.strip_prefix("ev-").unwrap_or("");
        if digits.len() == 32
            && digits
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            Ok(EventId(text.to_owned()))
        } else {
            Err(ModelError(format!("{text:?} isn't an event ID")))
        }
    }
}

impl<'de> Deserialize<'de> for EventId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        EventId::parse(&text).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `^[a-z0-9_]+$`: reader names.
pub(crate) fn is_simple_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn hex_digit(n: u8) -> char {
    char::from(if n < 10 { b'0' + n } else { b'a' + n - 10 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_errors_print_as_text() {
        let id = EventId::derive("pacman", b"pacman.log:1", 0).unwrap();
        assert_eq!(id.to_string(), id.as_str());
        let e = EventId::derive("Pac Man", b"", 0).unwrap_err();
        assert_eq!(
            e.to_string(),
            "reader name \"Pac Man\" isn't of the form [a-z0-9_]+"
        );
    }
}

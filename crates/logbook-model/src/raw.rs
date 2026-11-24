//! Raw lines (F-D03): kept as text, with bytes that aren't valid UTF-8
//! replaced and marked, never dropped silently.

use std::borrow::Cow;

/// The line as text, with each invalid UTF-8 sequence replaced by U+FFFD.
/// The bool says whether anything was replaced (the event's `raw_lossy`).
pub fn raw_line(bytes: &[u8]) -> (String, bool) {
    match String::from_utf8_lossy(bytes) {
        Cow::Borrowed(text) => (text.to_owned(), false),
        Cow::Owned(text) => (text, true),
    }
}

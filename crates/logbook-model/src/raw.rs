//! Raw lines (F-D03): kept as text, with bytes that aren't valid UTF-8
//! replaced and marked, never dropped silently.

use std::borrow::Cow;

/// The most raw lines an event keeps (F-D03).
pub const MAX_RAW_LINES: usize = 20;

/// The line as text, with each invalid UTF-8 sequence replaced by U+FFFD.
/// The bool says whether anything was replaced (the event's `raw_lossy`).
pub fn raw_line(bytes: &[u8]) -> (String, bool) {
    match String::from_utf8_lossy(bytes) {
        Cow::Borrowed(text) => (text.to_owned(), false),
        Cow::Owned(text) => (text, true),
    }
}

/// The lines an event keeps (F-D03): all of them up to 20, otherwise the
/// first 10 and the last 10. The number returned is how many were left out
/// (the event's `raw_omitted`).
pub fn raw_window(lines: &[String]) -> (Vec<String>, u64) {
    let half = MAX_RAW_LINES / 2;
    if lines.len() <= MAX_RAW_LINES {
        return (lines.to_vec(), 0);
    }
    let mut kept = lines[..half].to_vec();
    kept.extend_from_slice(&lines[lines.len() - half..]);
    (kept, (lines.len() - MAX_RAW_LINES) as u64)
}

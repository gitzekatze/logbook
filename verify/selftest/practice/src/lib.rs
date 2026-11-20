//! Practice crate for the break-list self-test. Not part of Logbook.

/// A90.1: a path is safe only if it stays inside its folder: not absolute,
/// no "..". Tested well.
pub fn is_safe_path(p: &str) -> bool {
    !p.starts_with('/') && !p.split('/').any(|c| c == "..")
}

/// A90.2: names are cut to 8 characters. Tested weakly on purpose: the test
/// checks "at most 8", so cutting to 4 goes unnoticed.
pub fn short_name(s: &str) -> String {
    s.chars().take(8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a90_1_parent_folder_refused() {
        assert!(!is_safe_path("a/../b"));
    }

    #[test]
    fn a90_1_absolute_path_refused() {
        assert!(!is_safe_path("/etc/passwd"));
    }

    #[test]
    fn a90_1_plain_path_allowed() {
        assert!(is_safe_path("a/b"));
    }

    #[test]
    fn a90_2_name_at_most_8() {
        assert!(short_name("abcdefghijk").chars().count() <= 8);
    }
}

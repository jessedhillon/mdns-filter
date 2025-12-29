//! Pattern matching utilities for filter rules.
//!
//! Supports:
//! - Exact match (case-insensitive): `"foo"`
//! - Glob patterns: `"foo*"`, `"*bar*"`, `"foo?bar"`
//! - Regex (wrapped in /): `"/^foo.*bar$/"`
//! - Negation (prefix !): `"!foo*"`

use glob::Pattern as GlobPattern;
use regex::Regex;

use crate::error::{Error, Result};

/// Compiled pattern for efficient repeated matching.
#[derive(Debug, Clone)]
pub enum CompiledPattern {
    /// Exact match (case-insensitive, stored lowercase).
    Exact(String),
    /// Glob pattern.
    Glob(GlobPattern),
    /// Regex pattern.
    Regex(Regex),
}

impl CompiledPattern {
    /// Check if value matches this pattern.
    pub fn is_match(&self, value: &str) -> bool {
        match self {
            CompiledPattern::Exact(pattern) => value.eq_ignore_ascii_case(pattern),
            CompiledPattern::Glob(pattern) => {
                // Glob matching is case-insensitive
                pattern.matches(&value.to_lowercase())
            }
            CompiledPattern::Regex(regex) => regex.is_match(value),
        }
    }
}

/// Utility for pattern matching with glob and regex support.
pub struct PatternMatcher;

impl PatternMatcher {
    /// Compile a pattern string into a CompiledPattern.
    ///
    /// Pattern syntax:
    /// - Regex: `/pattern/` (wrapped in forward slashes)
    /// - Glob: contains `*`, `?`, or `[`
    /// - Exact: anything else (case-insensitive match)
    pub fn compile(pattern: &str) -> Result<CompiledPattern> {
        // Check for regex pattern: /.../
        if pattern.starts_with('/') && pattern.ends_with('/') && pattern.len() > 2 {
            let regex_str = &pattern[1..pattern.len() - 1];
            // Build case-insensitive regex
            let regex = Regex::new(&format!("(?i){}", regex_str)).map_err(|e| {
                Error::InvalidPattern(format!("Invalid regex '{}': {}", regex_str, e))
            })?;
            return Ok(CompiledPattern::Regex(regex));
        }

        // Check for glob pattern
        if pattern.contains('*') || pattern.contains('?') || pattern.contains('[') {
            // Convert to lowercase for case-insensitive matching
            let glob = GlobPattern::new(&pattern.to_lowercase())
                .map_err(|e| Error::InvalidPattern(format!("Invalid glob '{}': {}", pattern, e)))?;
            return Ok(CompiledPattern::Glob(glob));
        }

        // Exact match (case-insensitive)
        Ok(CompiledPattern::Exact(pattern.to_lowercase()))
    }

    /// Check if a value matches a pattern string.
    ///
    /// Handles negation prefix (`!`) automatically.
    pub fn matches(value: Option<&str>, pattern: &str) -> bool {
        let Some(value) = value else {
            return false;
        };

        // Handle negation
        let (negated, pattern) = if let Some(stripped) = pattern.strip_prefix('!') {
            (true, stripped)
        } else {
            (false, pattern)
        };

        // Compile and match
        let result = match Self::compile(pattern) {
            Ok(compiled) => compiled.is_match(value),
            Err(_) => false, // Invalid patterns don't match
        };

        if negated {
            !result
        } else {
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exact match tests
    #[test]
    fn test_exact_match() {
        assert!(PatternMatcher::matches(Some("foo"), "foo"));
        assert!(PatternMatcher::matches(Some("FOO"), "foo"));
        assert!(PatternMatcher::matches(Some("foo"), "FOO"));
        assert!(!PatternMatcher::matches(Some("bar"), "foo"));
    }

    #[test]
    fn test_exact_match_with_special_chars() {
        assert!(PatternMatcher::matches(
            Some("_googlecast._tcp"),
            "_googlecast._tcp"
        ));
        assert!(PatternMatcher::matches(
            Some("Google-Cast-Group"),
            "Google-Cast-Group"
        ));
    }

    // Glob pattern tests
    #[test]
    fn test_glob_wildcard() {
        assert!(PatternMatcher::matches(Some("foobar"), "foo*"));
        assert!(PatternMatcher::matches(Some("foo"), "foo*"));
        assert!(!PatternMatcher::matches(Some("barfoo"), "foo*"));
    }

    #[test]
    fn test_glob_wildcard_middle() {
        assert!(PatternMatcher::matches(Some("fooXXXbar"), "foo*bar"));
        assert!(PatternMatcher::matches(Some("foobar"), "foo*bar"));
        assert!(!PatternMatcher::matches(Some("foobarbaz"), "foo*bar"));
    }

    #[test]
    fn test_glob_any_position() {
        assert!(PatternMatcher::matches(Some("xxxfooyyy"), "*foo*"));
        assert!(PatternMatcher::matches(Some("foo"), "*foo*"));
        assert!(!PatternMatcher::matches(Some("bar"), "*foo*"));
    }

    #[test]
    fn test_glob_question_mark() {
        assert!(PatternMatcher::matches(Some("fooXbar"), "foo?bar"));
        assert!(!PatternMatcher::matches(Some("foobar"), "foo?bar"));
        assert!(!PatternMatcher::matches(Some("fooXXbar"), "foo?bar"));
    }

    #[test]
    fn test_glob_case_insensitive() {
        assert!(PatternMatcher::matches(Some("FOOBAR"), "foo*"));
        assert!(PatternMatcher::matches(Some("FooBar"), "foo*bar"));
    }

    #[test]
    fn test_glob_service_pattern() {
        assert!(PatternMatcher::matches(
            Some("_googlecast._tcp"),
            "_googlecast.*"
        ));
        assert!(PatternMatcher::matches(
            Some("_spotify-connect._tcp"),
            "*spotify*"
        ));
    }

    #[test]
    fn test_glob_instance_pattern() {
        assert!(PatternMatcher::matches(
            Some("Google-Cast-Group-abc123"),
            "Google-Cast-*"
        ));
        assert!(PatternMatcher::matches(Some("WiiM-Pro-12345"), "WiiM-*"));
    }

    // Regex pattern tests
    #[test]
    fn test_regex_basic() {
        assert!(PatternMatcher::matches(Some("foobar"), "/foo.*bar/"));
        assert!(PatternMatcher::matches(Some("foo123bar"), "/foo.*bar/"));
        assert!(!PatternMatcher::matches(Some("barfoo"), "/foo.*bar/"));
    }

    #[test]
    fn test_regex_anchored() {
        assert!(PatternMatcher::matches(Some("foobar"), "/^foo/"));
        assert!(!PatternMatcher::matches(Some("xxxfoo"), "/^foo/"));
        assert!(PatternMatcher::matches(Some("xxxbar"), "/bar$/"));
        assert!(!PatternMatcher::matches(Some("barxxx"), "/bar$/"));
    }

    #[test]
    fn test_regex_case_insensitive() {
        assert!(PatternMatcher::matches(Some("FOOBAR"), "/foo.*bar/"));
        assert!(PatternMatcher::matches(Some("FooBar"), "/foo.*bar/"));
    }

    #[test]
    fn test_regex_character_class() {
        assert!(PatternMatcher::matches(Some("foo1bar"), "/foo[0-9]bar/"));
        assert!(!PatternMatcher::matches(Some("fooXbar"), "/foo[0-9]bar/"));
    }

    // Negation tests
    #[test]
    fn test_negation_exact() {
        assert!(!PatternMatcher::matches(Some("foo"), "!foo"));
        assert!(PatternMatcher::matches(Some("bar"), "!foo"));
    }

    #[test]
    fn test_negation_glob() {
        assert!(!PatternMatcher::matches(Some("foobar"), "!foo*"));
        assert!(PatternMatcher::matches(Some("barfoo"), "!foo*"));
    }

    #[test]
    fn test_negation_regex() {
        assert!(!PatternMatcher::matches(Some("foobar"), "!/foo.*bar/"));
        assert!(PatternMatcher::matches(Some("barbaz"), "!/foo.*bar/"));
    }

    // None value tests
    #[test]
    fn test_none_value() {
        assert!(!PatternMatcher::matches(None, "foo"));
        assert!(!PatternMatcher::matches(None, "*"));
        assert!(!PatternMatcher::matches(None, "!foo"));
    }

    // Edge cases
    #[test]
    fn test_empty_pattern() {
        assert!(PatternMatcher::matches(Some(""), ""));
        assert!(!PatternMatcher::matches(Some("foo"), ""));
    }

    #[test]
    fn test_empty_value() {
        assert!(PatternMatcher::matches(Some(""), ""));
        assert!(PatternMatcher::matches(Some(""), "*"));
        assert!(!PatternMatcher::matches(Some(""), "foo"));
    }

    #[test]
    fn test_compile_caches_pattern() {
        // Just verify compile works and can be reused
        let compiled = PatternMatcher::compile("foo*").unwrap();
        assert!(compiled.is_match("foobar"));
        assert!(compiled.is_match("foo"));
        assert!(!compiled.is_match("barfoo"));
    }
}

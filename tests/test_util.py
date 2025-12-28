"""Tests for mdns_filter.util module."""

from __future__ import annotations

import re as regex
from pathlib import Path

from mdns_filter.util import PatternMatcher, PathType, ClickPath


class TestPatternMatcherCompile:
    """Tests for PatternMatcher.compile_pattern."""

    def test_exact_match_returns_lowercase_string(self) -> None:
        result = PatternMatcher.compile_pattern("FooBar")
        assert result == "foobar"
        assert isinstance(result, str)

    def test_glob_star_returns_regex(self) -> None:
        result = PatternMatcher.compile_pattern("foo*")
        assert isinstance(result, regex.Pattern)

    def test_glob_question_returns_regex(self) -> None:
        result = PatternMatcher.compile_pattern("foo?bar")
        assert isinstance(result, regex.Pattern)

    def test_glob_bracket_returns_regex(self) -> None:
        result = PatternMatcher.compile_pattern("foo[abc]bar")
        assert isinstance(result, regex.Pattern)

    def test_regex_pattern_returns_regex(self) -> None:
        result = PatternMatcher.compile_pattern("/^foo.*bar$/")
        assert isinstance(result, regex.Pattern)

    def test_regex_pattern_strips_slashes(self) -> None:
        result = PatternMatcher.compile_pattern("/test/")
        assert isinstance(result, regex.Pattern)
        assert result.search("test") is not None

    def test_single_slash_treated_as_exact(self) -> None:
        result = PatternMatcher.compile_pattern("/")
        assert result == "/"
        assert isinstance(result, str)

    def test_double_slash_treated_as_exact(self) -> None:
        result = PatternMatcher.compile_pattern("//")
        assert result == "//"
        assert isinstance(result, str)


class TestPatternMatcherMatches:
    """Tests for PatternMatcher.matches."""

    def test_none_value_returns_false(self) -> None:
        assert PatternMatcher.matches(None, "anything") is False

    def test_exact_match_case_insensitive(self) -> None:
        assert PatternMatcher.matches("FooBar", "foobar") is True
        assert PatternMatcher.matches("foobar", "FOOBAR") is True
        assert PatternMatcher.matches("FooBar", "FooBar") is True

    def test_exact_match_no_match(self) -> None:
        assert PatternMatcher.matches("foo", "bar") is False

    def test_glob_star_matches(self) -> None:
        assert PatternMatcher.matches("Google-Cast-abc123", "Google-Cast-*") is True
        assert PatternMatcher.matches("Google-Cast-", "Google-Cast-*") is True
        assert PatternMatcher.matches("Something-Else", "Google-Cast-*") is False

    def test_glob_star_prefix(self) -> None:
        assert PatternMatcher.matches("foo-bar-baz", "*-baz") is True
        assert PatternMatcher.matches("baz", "*-baz") is False

    def test_glob_star_middle(self) -> None:
        assert PatternMatcher.matches("foo-anything-bar", "foo-*-bar") is True
        assert PatternMatcher.matches("foo--bar", "foo-*-bar") is True
        assert PatternMatcher.matches("foo-bar", "foo-*-bar") is False

    def test_glob_question_mark(self) -> None:
        assert PatternMatcher.matches("foo1bar", "foo?bar") is True
        assert PatternMatcher.matches("fooXbar", "foo?bar") is True
        assert PatternMatcher.matches("foobar", "foo?bar") is False
        assert PatternMatcher.matches("foo12bar", "foo?bar") is False

    def test_glob_bracket_class(self) -> None:
        assert PatternMatcher.matches("fooabar", "foo[abc]bar") is True
        assert PatternMatcher.matches("foobbar", "foo[abc]bar") is True
        assert PatternMatcher.matches("foocbar", "foo[abc]bar") is True
        assert PatternMatcher.matches("foodbar", "foo[abc]bar") is False

    def test_glob_case_insensitive(self) -> None:
        assert PatternMatcher.matches("GOOGLE-CAST-ABC", "google-cast-*") is True
        assert PatternMatcher.matches("google-cast-abc", "GOOGLE-CAST-*") is True

    def test_regex_pattern_matches(self) -> None:
        assert PatternMatcher.matches("foobar", "/^foo.*bar$/") is True
        assert PatternMatcher.matches("foo123bar", "/^foo.*bar$/") is True
        assert PatternMatcher.matches("xfoobar", "/^foo.*bar$/") is False

    def test_regex_partial_match(self) -> None:
        assert PatternMatcher.matches("prefix-foo-suffix", "/foo/") is True

    def test_regex_case_insensitive(self) -> None:
        assert PatternMatcher.matches("FOOBAR", "/foobar/") is True
        assert PatternMatcher.matches("foobar", "/FOOBAR/") is True

    def test_negation_exact_match(self) -> None:
        assert PatternMatcher.matches("foo", "!foo") is False
        assert PatternMatcher.matches("bar", "!foo") is True

    def test_negation_glob(self) -> None:
        assert PatternMatcher.matches("Google-Cast-abc", "!Google-Cast-*") is False
        assert PatternMatcher.matches("WiiM-Pro", "!Google-Cast-*") is True

    def test_negation_regex(self) -> None:
        assert PatternMatcher.matches("foobar", "!/foo/") is False
        assert PatternMatcher.matches("bazqux", "!/foo/") is True


class TestPathType:
    """Tests for PathType click parameter."""

    def test_name_is_path(self) -> None:
        pt = PathType()
        assert pt.name == "path"

    def test_convert_string_to_path(self) -> None:
        pt = PathType()
        result = pt.convert("/some/path", None, None)
        assert isinstance(result, Path)
        assert result == Path("/some/path")

    def test_convert_path_returns_same(self) -> None:
        pt = PathType()
        original = Path("/some/path")
        result = pt.convert(original, None, None)
        assert result is original

    def test_click_path_is_instance(self) -> None:
        assert isinstance(ClickPath, PathType)

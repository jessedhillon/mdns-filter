"""Utility classes for mdns-filter."""

from __future__ import annotations

import fnmatch
import re as regex
import typing as t
from pathlib import Path

import click


class PatternMatcher:
    """Utility class for pattern matching with glob and regex support."""

    @staticmethod
    def compile_pattern(pattern: str) -> regex.Pattern[str] | str:
        """
        Compile a pattern for matching.

        Supports:
        - Exact match: "foo"
        - Glob patterns: "foo*", "*bar*"
        - Regex (wrapped in /): "/^foo.*bar$/"
        - Negation (prefix !): "!foo*"
        """
        if pattern.startswith("/") and pattern.endswith("/") and len(pattern) > 2:
            # Regex pattern
            return regex.compile(pattern[1:-1], regex.IGNORECASE)
        elif "*" in pattern or "?" in pattern or "[" in pattern:
            # Glob pattern - convert to regex
            regex_pattern = fnmatch.translate(pattern)
            return regex.compile(regex_pattern, regex.IGNORECASE)
        else:
            # Exact match (case-insensitive)
            return pattern.lower()

    @staticmethod
    def matches(value: str | None, pattern: str) -> bool:
        """Check if a value matches a pattern."""
        if value is None:
            return False

        # Handle negation
        negated = pattern.startswith("!")
        if negated:
            pattern = pattern[1:]

        compiled = PatternMatcher.compile_pattern(pattern)

        if isinstance(compiled, regex.Pattern):
            result = compiled.search(value) is not None
        else:
            result = value.lower() == compiled

        return not result if negated else result


class PathType(click.ParamType):
    """Click parameter type for Path objects."""

    name = "path"

    def convert(self, value: t.Any, param: click.Parameter | None, ctx: click.Context | None) -> Path:
        if isinstance(value, Path):
            return value
        return Path(value)


ClickPath = PathType()

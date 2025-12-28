"""Filter rule definitions and configuration."""

from __future__ import annotations

import ipaddress
import typing as t
from pathlib import Path

import pydantic as p
import yaml

from mdns_filter.const import FilterAction, LogLevel, RecordSection, RecordType
from mdns_filter.util import PatternMatcher
from mdns_filter.mdns import DNSRecord, ParsedMDNSPacket


class FilterMatch(p.BaseModel):
    """Defines matching criteria for a filter rule."""

    model_config = p.ConfigDict(extra="forbid")

    # IP-based matching
    src_ip: t.Annotated[str | None, p.Field(description="Source IP or CIDR")] = None

    # Message-level matching
    is_query: t.Annotated[bool | None, p.Field(description="Match queries (True) or responses (False)")] = None
    is_authoritative: t.Annotated[bool | None, p.Field(description="Match authoritative responses")] = None

    # Record-level matching (patterns support glob and regex)
    service: t.Annotated[
        str | None,
        p.Field(description="Service type pattern, e.g., '_googlecast._tcp'"),
    ] = None
    instance: t.Annotated[
        str | None,
        p.Field(description="Instance name pattern, e.g., 'Google-Cast-*'"),
    ] = None
    name: t.Annotated[
        str | None,
        p.Field(description="Full DNS name pattern"),
    ] = None
    record_type: t.Annotated[
        str | None,
        p.Field(description="Record type: PTR, SRV, TXT, A, AAAA, or *"),
    ] = None
    section: t.Annotated[
        RecordSection | None,
        p.Field(description="Record section: question, answer, authority, additional"),
    ] = None
    txt_contains: t.Annotated[
        str | None,
        p.Field(description="Pattern to match against TXT record content"),
    ] = None

    # Cached compiled network for src_ip
    _compiled_network: ipaddress.IPv4Network | None = None

    @p.field_validator("src_ip")
    @classmethod
    def validate_src_ip(cls, val: str | None) -> str | None:
        """Validate src_ip is a valid IP or CIDR."""
        if val is not None:
            try:
                ipaddress.IPv4Network(val, strict=False)
            except ValueError as err:
                raise ValueError(f"Invalid IP/CIDR: {val}") from err
        return val

    @p.field_validator("record_type")
    @classmethod
    def validate_record_type(cls, val: str | None) -> str | None:
        """Validate record type is known or wildcard."""
        if val is not None:
            val = val.upper()
            valid_types = {"A", "AAAA", "PTR", "SRV", "TXT", "CNAME", "NS", "ANY", "*"}
            if val not in valid_types and not val.startswith("TYPE"):
                # Check if it's a known RecordType
                try:
                    RecordType[val]
                except KeyError as err:
                    raise ValueError(f"Unknown record type: {val}") from err
        return val

    def get_network(self) -> ipaddress.IPv4Network | None:
        """Get compiled IPv4Network for src_ip matching."""
        if self.src_ip is None:
            return None
        if self._compiled_network is None:
            object.__setattr__(
                self,
                "_compiled_network",
                ipaddress.IPv4Network(self.src_ip, strict=False),
            )
        return self._compiled_network

    def matches_record(
        self,
        section: RecordSection,
        record: DNSRecord,
        packet: ParsedMDNSPacket,
    ) -> bool:
        """Check if a record matches all specified criteria."""
        # IP matching
        if self.src_ip is not None and packet.src_ip is not None:
            network = self.get_network()
            if network and packet.src_ip not in network:
                return False

        # Message-level matching
        if self.is_query is not None:
            if self.is_query != (not packet.is_response):
                return False

        if self.is_authoritative is not None:
            if self.is_authoritative != packet.is_authoritative:
                return False

        # Section matching
        if self.section is not None and section != self.section:
            return False

        # Record type matching
        if self.record_type is not None:
            if not record.matches_type(self.record_type):
                return False

        # Service matching
        if self.service is not None:
            if not PatternMatcher.matches(record.service, self.service):
                return False

        # Instance matching
        if self.instance is not None:
            if not PatternMatcher.matches(record.instance, self.instance):
                return False

        # Name matching
        if self.name is not None:
            if not PatternMatcher.matches(record.name, self.name):
                return False

        # TXT record content matching
        if self.txt_contains is not None:
            if record.record_type != RecordType.TXT:
                return False
            # Match against any key or value in TXT records
            matched = False
            for key, value in record.txt_records.items():
                if PatternMatcher.matches(key, self.txt_contains):
                    matched = True
                    break
                if PatternMatcher.matches(value, self.txt_contains):
                    matched = True
                    break
                # Also match "key=value" format
                if PatternMatcher.matches(f"{key}={value}", self.txt_contains):
                    matched = True
                    break
            if not matched:
                return False

        return True


class FilterRule(p.BaseModel):
    """A single filter rule with match criteria and action."""

    model_config = p.ConfigDict(extra="forbid")

    name: t.Annotated[str, p.Field(description="Human-readable rule name")]
    match: t.Annotated[FilterMatch, p.Field(description="Matching criteria")]
    action: t.Annotated[FilterAction, p.Field(description="Action: allow or deny")]
    log: t.Annotated[LogLevel, p.Field(description="Logging level for this rule")] = LogLevel.Off
    match_mode: t.Annotated[
        t.Literal["any", "all"],
        p.Field(description="Match if any record matches, or all records must match"),
    ] = "any"


class FilterConfig(p.BaseModel):
    """Complete filter configuration."""

    model_config = p.ConfigDict(extra="forbid")

    default_action: t.Annotated[
        FilterAction,
        p.Field(description="Action when no rules match"),
    ] = FilterAction.Allow
    rules: t.Annotated[
        list[FilterRule],
        p.Field(description="Ordered list of filter rules (first match wins)"),
    ] = []

    @classmethod
    def from_yaml_file(cls, path: Path) -> "FilterConfig":
        """Load configuration from a YAML file."""
        with open(path) as fh:
            data = yaml.safe_load(fh)
        return cls.model_validate(data)

    @classmethod
    def from_cli_patterns(
        cls,
        allow_patterns: list[str],
        deny_patterns: list[str],
        default_deny: bool = False,
    ) -> "FilterConfig":
        """
        Create configuration from CLI patterns.

        Patterns are in format: "field:pattern" or "field:pattern,field2:pattern2"
        """
        rules: list[FilterRule] = []

        def parse_pattern(pattern: str) -> FilterMatch:
            """Parse a CLI pattern string into FilterMatch."""
            match_dict: dict[str, t.Any] = {}
            for part in pattern.split(","):
                if ":" not in part:
                    raise ValueError(f"Invalid pattern format: {part} (expected field:value)")
                field, _, value = part.partition(":")
                field = field.strip().lower()
                value = value.strip()

                # Map CLI field names to FilterMatch fields
                field_map = {
                    "instance": "instance",
                    "service": "service",
                    "name": "name",
                    "type": "record_type",
                    "record_type": "record_type",
                    "src_ip": "src_ip",
                    "ip": "src_ip",
                    "section": "section",
                    "txt": "txt_contains",
                    "txt_contains": "txt_contains",
                }

                if field not in field_map:
                    raise ValueError(f"Unknown filter field: {field}")

                match_dict[field_map[field]] = value

            return FilterMatch.model_validate(match_dict)

        # Add deny rules first (higher priority)
        for idx, pattern in enumerate(deny_patterns):
            rules.append(
                FilterRule(
                    name=f"cli-deny-{idx}",
                    match=parse_pattern(pattern),
                    action=FilterAction.Deny,
                    log=LogLevel.Debug,
                )
            )

        # Then allow rules
        for idx, pattern in enumerate(allow_patterns):
            rules.append(
                FilterRule(
                    name=f"cli-allow-{idx}",
                    match=parse_pattern(pattern),
                    action=FilterAction.Allow,
                    log=LogLevel.Debug,
                )
            )

        return cls(
            default_action=FilterAction.Deny if default_deny else FilterAction.Allow,
            rules=rules,
        )

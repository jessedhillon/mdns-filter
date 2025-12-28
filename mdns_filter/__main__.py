#!/usr/bin/env python3
"""
mdns-filter - mDNS repeater daemon with content-based filtering

Python rewrite of the [original C version by Darell Tan](https://github.com/geekman/mdns-repeater/),
extended with rule-based filtering that can match on mDNS packet contents.

Copyright (C) 2011 Darell Tan (original C version)
Python rewrite with type hints, Pydantic, Click, and content filtering.

License: GPL v2
"""

from __future__ import annotations

import asyncio
import enum
import fcntl
import fnmatch
import ipaddress
import logging
import re as regex
import signal
import socket
import struct
import sys
import types
import typing as t
from pathlib import Path

import click
import pydantic as p
import yaml

# =============================================================================
# Constants
# =============================================================================

Package = "mdns-filter"
MdnsAddr = "224.0.0.251"
MdnsPort = 5353
PacketSize = 65536


# Socket options that may not be in the socket module
SO_BINDTODEVICE = 25
IP_PKTINFO = 8

logger = logging.getLogger(Package)


# =============================================================================
# DNS Record Types
# =============================================================================


class RecordType(enum.IntEnum):
    """DNS record types relevant to mDNS."""

    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    HINFO = 13
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33
    NSEC = 47
    ANY = 255

    @classmethod
    def from_int(cls, value: int) -> "RecordType | int":
        """Convert int to RecordType, returning int if unknown."""
        try:
            return cls(value)
        except ValueError:
            return value


class RecordSection(enum.StrEnum):
    """Section of DNS message where a record appears."""

    QUESTION = "question"
    ANSWER = "answer"
    AUTHORITY = "authority"
    ADDITIONAL = "additional"


# =============================================================================
# Pydantic Models - mDNS Packet Parsing
# =============================================================================


class DNSRecord(p.BaseModel):
    """Represents a single DNS resource record."""

    model_config = p.ConfigDict(frozen=True)

    name: str
    record_type: int
    record_class: int
    ttl: int = 0
    rdata: bytes = b""

    # Parsed fields for convenience
    instance: str | None = None  # e.g., "Google-Cast-Group-xxx"
    service: str | None = None  # e.g., "_googlecast._tcp"
    domain: str = "local"

    # For TXT records
    txt_records: dict[str, str] = p.Field(default_factory=dict)

    @property
    def type_name(self) -> str:
        """Get human-readable record type name."""
        try:
            return RecordType(self.record_type).name
        except ValueError:
            return f"TYPE{self.record_type}"

    def matches_type(self, type_pattern: str) -> bool:
        """Check if record type matches pattern (e.g., 'PTR', 'TXT', '*')."""
        if type_pattern == "*":
            return True
        return self.type_name.upper() == type_pattern.upper()


class ParsedMDNSPacket(p.BaseModel):
    """Represents a parsed mDNS packet."""

    model_config = p.ConfigDict(frozen=True)

    # Header fields
    transaction_id: int
    flags: int
    is_response: bool
    is_authoritative: bool
    is_truncated: bool

    # Records by section
    questions: tuple[DNSRecord, ...] = ()
    answers: tuple[DNSRecord, ...] = ()
    authorities: tuple[DNSRecord, ...] = ()
    additionals: tuple[DNSRecord, ...] = ()

    # Source information
    src_ip: ipaddress.IPv4Address | None = None

    @property
    def all_records(self) -> list[tuple[RecordSection, DNSRecord]]:
        """Get all records with their sections."""
        result: list[tuple[RecordSection, DNSRecord]] = []
        for rec in self.questions:
            result.append((RecordSection.QUESTION, rec))
        for rec in self.answers:
            result.append((RecordSection.ANSWER, rec))
        for rec in self.authorities:
            result.append((RecordSection.AUTHORITY, rec))
        for rec in self.additionals:
            result.append((RecordSection.ADDITIONAL, rec))
        return result

    @property
    def record_count(self) -> int:
        """Total number of records in the packet."""
        return (
            len(self.questions)
            + len(self.answers)
            + len(self.authorities)
            + len(self.additionals)
        )

    def format_summary(self) -> str:
        """Format packet as a human-readable summary (similar to tcpdump)."""
        parts: list[str] = []

        # Source
        if self.src_ip:
            parts.append(f"from {self.src_ip}")

        # Message type
        if self.is_response:
            flags: list[str] = []
            if self.is_authoritative:
                flags.append("authoritative")
            if self.is_truncated:
                flags.append("truncated")
            flag_str = f" ({', '.join(flags)})" if flags else ""
            parts.append(f"response{flag_str}")
        else:
            parts.append("query")

        # Record counts
        counts: list[str] = []
        if self.questions:
            counts.append(f"{len(self.questions)}q")
        if self.answers:
            counts.append(f"{len(self.answers)}an")
        if self.authorities:
            counts.append(f"{len(self.authorities)}ns")
        if self.additionals:
            counts.append(f"{len(self.additionals)}ar")
        if counts:
            parts.append(f"[{'/'.join(counts)}]")

        # Key records (answers are most interesting)
        record_strs: list[str] = []
        for record in self.answers[:3]:  # Limit to first 3
            type_name = record.type_name
            if record.instance and record.service:
                record_strs.append(f"{type_name} {record.instance}.{record.service}.{record.domain}")
            elif record.service:
                record_strs.append(f"{type_name} {record.service}.{record.domain}")
            else:
                record_strs.append(f"{type_name} {record.name}")

        if not record_strs and self.questions:
            # Fall back to questions if no answers
            for record in self.questions[:3]:
                type_name = record.type_name
                record_strs.append(f"{type_name}? {record.name}")

        if record_strs:
            parts.append(": " + ", ".join(record_strs))
            if len(self.answers) > 3:
                parts.append(f" (+{len(self.answers) - 3} more)")

        return " ".join(parts)

    def format_detailed(self) -> str:
        """Format packet with full details of all records."""
        lines: list[str] = []

        # Header
        lines.append(f"mDNS {'Response' if self.is_response else 'Query'} from {self.src_ip}")
        lines.append(f"  Flags: AA={self.is_authoritative}, TC={self.is_truncated}")

        def format_records(section_name: str, records: tuple[DNSRecord, ...]) -> None:
            if not records:
                return
            lines.append(f"  {section_name}:")
            for record in records:
                type_name = record.type_name
                if record.instance:
                    lines.append(f"    {type_name}: {record.instance}.{record.service}.{record.domain}")
                else:
                    lines.append(f"    {type_name}: {record.name}")
                if record.txt_records:
                    for key, value in record.txt_records.items():
                        lines.append(f"      TXT: {key}={value}")

        format_records("Questions", self.questions)
        format_records("Answers", self.answers)
        format_records("Authority", self.authorities)
        format_records("Additional", self.additionals)

        return "\n".join(lines)


# =============================================================================
# mDNS Packet Parser
# =============================================================================


class MDNSParser:
    """Parser for mDNS/DNS packets."""

    @staticmethod
    def parse_name(data: bytes, offset: int) -> tuple[str, int]:
        """Parse a DNS name from packet data, handling compression."""
        labels: list[str] = []
        original_offset = offset
        jumped = False
        max_jumps = 10  # Prevent infinite loops

        for _ in range(max_jumps):
            if offset >= len(data):
                break

            length = data[offset]

            if length == 0:
                offset += 1
                break

            # Check for compression pointer
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    break
                pointer = ((length & 0x3F) << 8) | data[offset + 1]
                if not jumped:
                    original_offset = offset + 2
                    jumped = True
                offset = pointer
                continue

            offset += 1
            if offset + length > len(data):
                break

            labels.append(data[offset : offset + length].decode("utf-8", errors="replace"))
            offset += length

        name = ".".join(labels)
        return name, original_offset if jumped else offset

    @staticmethod
    def parse_service_name(name: str) -> tuple[str | None, str | None, str]:
        """
        Parse an mDNS service name into instance, service, and domain.

        Examples:
            "Google-Cast-Group-xxx._googlecast._tcp.local"
            -> ("Google-Cast-Group-xxx", "_googlecast._tcp", "local")

            "_googlecast._tcp.local"
            -> (None, "_googlecast._tcp", "local")
        """
        parts = name.split(".")

        # Find service type pattern (_name._tcp or _name._udp)
        service_start = None
        for idx, part in enumerate(parts):
            if part.startswith("_") and idx + 1 < len(parts):
                next_part = parts[idx + 1]
                if next_part in ("_tcp", "_udp"):
                    service_start = idx
                    break

        if service_start is None:
            # No service pattern found
            return None, None, parts[-1] if parts else "local"

        instance = ".".join(parts[:service_start]) if service_start > 0 else None
        service = f"{parts[service_start]}.{parts[service_start + 1]}"
        domain = ".".join(parts[service_start + 2 :]) if service_start + 2 < len(parts) else "local"

        return instance, service, domain

    @staticmethod
    def parse_txt_record(rdata: bytes) -> dict[str, str]:
        """Parse TXT record data into key-value pairs."""
        result: dict[str, str] = {}
        offset = 0

        while offset < len(rdata):
            length = rdata[offset]
            offset += 1

            if length == 0 or offset + length > len(rdata):
                break

            txt = rdata[offset : offset + length].decode("utf-8", errors="replace")
            offset += length

            if "=" in txt:
                key, _, value = txt.partition("=")
                result[key] = value
            else:
                result[txt] = ""

        return result

    @classmethod
    def parse(
        cls, data: bytes, src_ip: ipaddress.IPv4Address | None = None
    ) -> ParsedMDNSPacket | None:
        """Parse an mDNS packet."""
        if len(data) < 12:
            return None

        try:
            # Parse header
            (
                transaction_id,
                flags,
                qdcount,
                ancount,
                nscount,
                arcount,
            ) = struct.unpack("!HHHHHH", data[:12])

            is_response = bool(flags & 0x8000)
            is_authoritative = bool(flags & 0x0400)
            is_truncated = bool(flags & 0x0200)

            offset = 12
            questions: list[DNSRecord] = []
            answers: list[DNSRecord] = []
            authorities: list[DNSRecord] = []
            additionals: list[DNSRecord] = []

            # Parse questions
            for _ in range(qdcount):
                if offset >= len(data):
                    break
                name, offset = cls.parse_name(data, offset)
                if offset + 4 > len(data):
                    break
                qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
                offset += 4

                instance, service, domain = cls.parse_service_name(name)
                questions.append(
                    DNSRecord(
                        name=name,
                        record_type=qtype,
                        record_class=qclass,
                        instance=instance,
                        service=service,
                        domain=domain,
                    )
                )

            # Parse resource records (answers, authorities, additionals)
            def parse_rr(count: int) -> list[DNSRecord]:
                nonlocal offset
                records: list[DNSRecord] = []

                for _ in range(count):
                    if offset >= len(data):
                        break

                    name, offset = cls.parse_name(data, offset)
                    if offset + 10 > len(data):
                        break

                    rtype, rclass, ttl, rdlength = struct.unpack(
                        "!HHIH", data[offset : offset + 10]
                    )
                    offset += 10

                    if offset + rdlength > len(data):
                        break

                    rdata = data[offset : offset + rdlength]
                    offset += rdlength

                    instance, service, domain = cls.parse_service_name(name)

                    # Parse TXT records specially
                    txt_records: dict[str, str] = {}
                    if rtype == RecordType.TXT:
                        txt_records = cls.parse_txt_record(rdata)

                    # For PTR records, also parse the target name for instance/service
                    if rtype == RecordType.PTR and rdata:
                        target_name, _ = cls.parse_name(data, offset - rdlength)
                        ptr_instance, ptr_service, _ = cls.parse_service_name(
                            target_name
                        )
                        # Use target's instance if the name itself doesn't have one
                        if ptr_instance and not instance:
                            instance = ptr_instance
                        if ptr_service and not service:
                            service = ptr_service

                    records.append(
                        DNSRecord(
                            name=name,
                            record_type=rtype,
                            record_class=rclass,
                            ttl=ttl,
                            rdata=rdata,
                            instance=instance,
                            service=service,
                            domain=domain,
                            txt_records=txt_records,
                        )
                    )

                return records

            answers = parse_rr(ancount)
            authorities = parse_rr(nscount)
            additionals = parse_rr(arcount)

            return ParsedMDNSPacket(
                transaction_id=transaction_id,
                flags=flags,
                is_response=is_response,
                is_authoritative=is_authoritative,
                is_truncated=is_truncated,
                questions=tuple(questions),
                answers=tuple(answers),
                authorities=tuple(authorities),
                additionals=tuple(additionals),
                src_ip=src_ip,
            )

        except Exception as err:
            logger.debug("Failed to parse mDNS packet: %s", err)
            return None


# =============================================================================
# Pydantic Models - Filter Configuration
# =============================================================================


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


class FilterAction(enum.StrEnum):
    """Action to take when a filter rule matches."""

    ALLOW = "allow"
    DENY = "deny"


class LogLevel(enum.StrEnum):
    """Log level for filter rule logging."""

    NONE = "none"
    DEBUG = "debug"
    INFO = "info"


class FilterRule(p.BaseModel):
    """A single filter rule with match criteria and action."""

    model_config = p.ConfigDict(extra="forbid")

    name: t.Annotated[str, p.Field(description="Human-readable rule name")]
    match: t.Annotated[FilterMatch, p.Field(description="Matching criteria")]
    action: t.Annotated[FilterAction, p.Field(description="Action: allow or deny")]
    log: t.Annotated[LogLevel, p.Field(description="Logging level for this rule")] = LogLevel.NONE
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
    ] = FilterAction.ALLOW
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
                    action=FilterAction.DENY,
                    log=LogLevel.DEBUG,
                )
            )

        # Then allow rules
        for idx, pattern in enumerate(allow_patterns):
            rules.append(
                FilterRule(
                    name=f"cli-allow-{idx}",
                    match=parse_pattern(pattern),
                    action=FilterAction.ALLOW,
                    log=LogLevel.DEBUG,
                )
            )

        return cls(
            default_action=FilterAction.DENY if default_deny else FilterAction.ALLOW,
            rules=rules,
        )


# =============================================================================
# Filter Engine
# =============================================================================


class FilterEngine:
    """Evaluates filter rules against mDNS packets."""

    def __init__(self, config: FilterConfig) -> None:
        self.config = config

    def evaluate(self, packet: ParsedMDNSPacket) -> tuple[FilterAction, str | None]:
        """
        Evaluate a packet against all rules.

        Returns:
            Tuple of (action, rule_name) where rule_name is None if default action was used.
        """
        all_records = packet.all_records

        if not all_records:
            # Empty packet - use default action
            return self.config.default_action, None

        for rule in self.config.rules:
            matched: bool

            if rule.match_mode == "any":
                # Match if any record matches
                matched = any(
                    rule.match.matches_record(section, record, packet)
                    for section, record in all_records
                )
            else:
                # Match only if all records match
                matched = all(
                    rule.match.matches_record(section, record, packet)
                    for section, record in all_records
                )

            if matched:
                # Log if configured
                if rule.log == LogLevel.DEBUG:
                    logger.debug(
                        "Rule '%s' matched: %s (src=%s)",
                        rule.name,
                        rule.action.value,
                        packet.src_ip,
                    )
                elif rule.log == LogLevel.INFO:
                    logger.info(
                        "Rule '%s' matched: %s (src=%s)",
                        rule.name,
                        rule.action.value,
                        packet.src_ip,
                    )

                return rule.action, rule.name

        # No rule matched - use default action
        return self.config.default_action, None


# =============================================================================
# Pydantic Models - Network Configuration
# =============================================================================


class SubnetConfig(p.BaseModel):
    """Represents a subnet configuration (for legacy IP-based filtering)."""

    model_config = p.ConfigDict(frozen=True)

    network: ipaddress.IPv4Network

    @classmethod
    def from_cidr(cls, cidr: str) -> "SubnetConfig":
        """Parse a CIDR notation string like '192.168.1.0/24'."""
        return cls(network=ipaddress.IPv4Network(cidr, strict=False))

    def contains(self, addr: ipaddress.IPv4Address) -> bool:
        """Check if an address belongs to this subnet."""
        return addr in self.network

    def __str__(self) -> str:
        return str(self.network)


class InterfaceInfo(p.BaseModel):
    """Network interface information (without socket, which can't be serialized)."""

    model_config = p.ConfigDict(frozen=True)

    ifname: str
    addr: ipaddress.IPv4Address
    mask: ipaddress.IPv4Address
    network: ipaddress.IPv4Network

    @classmethod
    def from_interface(cls, ifname: str, addr: ipaddress.IPv4Address, mask: ipaddress.IPv4Address) -> "InterfaceInfo":
        """Create from interface name and address info."""
        prefix_len = bin(int(mask)).count("1")
        network = ipaddress.IPv4Network(f"{addr}/{prefix_len}", strict=False)
        return cls(ifname=ifname, addr=addr, mask=mask, network=network)

    def __str__(self) -> str:
        return f"dev {self.ifname} addr {self.addr} mask {self.mask} net {self.network}"


class InterfaceSocket:
    """Wrapper for interface info with its socket (runtime object)."""

    def __init__(self, info: InterfaceInfo, sockfd: socket.socket) -> None:
        self.info = info
        self.sockfd = sockfd

    @property
    def ifname(self) -> str:
        return self.info.ifname

    @property
    def addr(self) -> ipaddress.IPv4Address:
        return self.info.addr

    @property
    def network(self) -> ipaddress.IPv4Network:
        return self.info.network

    def __str__(self) -> str:
        return str(self.info)


class RepeaterConfig(p.BaseModel):
    """Main configuration for the mDNS repeater."""

    model_config = p.ConfigDict(extra="forbid")

    interfaces: t.Annotated[
        list[str],
        p.Field(min_length=2, description="Network interfaces to bridge"),
    ]
    dry_run: bool = False
    filter_config: FilterConfig = p.Field(default_factory=FilterConfig)

    # Legacy IP-based filtering (still supported)
    blacklist: list[SubnetConfig] = []
    whitelist: list[SubnetConfig] = []

    @p.model_validator(mode="after")
    def validate_lists(self) -> "RepeaterConfig":
        """Ensure blacklist and whitelist aren't both specified."""
        if self.blacklist and self.whitelist:
            raise ValueError("Cannot specify both blacklist and whitelist")
        return self


# =============================================================================
# Network Utilities
# =============================================================================


def get_interface_info(sock: socket.socket, ifname: str) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]:
    """Get IP address and netmask for an interface using ioctl."""
    SIOCGIFADDR = 0x8915
    SIOCGIFNETMASK = 0x891B

    ifreq = struct.pack("256s", ifname.encode("utf-8")[:15])

    try:
        result = fcntl.ioctl(sock.fileno(), SIOCGIFNETMASK, ifreq)
        mask = ipaddress.IPv4Address(socket.inet_ntoa(result[20:24]))
    except OSError as err:
        logger.error("Failed to get netmask for %s: %s", ifname, err)
        raise

    try:
        result = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, ifreq)
        addr = ipaddress.IPv4Address(socket.inet_ntoa(result[20:24]))
    except OSError as err:
        logger.error("Failed to get address for %s: %s", ifname, err)
        raise

    return addr, mask


# =============================================================================
# Main Repeater Class
# =============================================================================


class MDNSRepeater:
    """Main mDNS repeater class."""

    def __init__(self, config: RepeaterConfig) -> None:
        self.config = config
        self.filter_engine = FilterEngine(config.filter_config)

        self.server_socket: socket.socket | None = None
        self.interface_sockets: list[InterfaceSocket] = []
        self.shutdown_flag = False

    def _create_recv_socket(self) -> socket.socket:
        """Create the main receiving socket for mDNS multicast."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                pass

            sock.bind(("", MdnsPort))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

            try:
                sock.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
            except OSError:
                pass

            sock.setblocking(False)
            return sock

        except Exception:
            sock.close()
            raise

    def _create_send_socket(self, recv_sock: socket.socket, ifname: str) -> InterfaceSocket:
        """Create a sending socket bound to a specific interface."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

        try:
            try:
                sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, ifname.encode("utf-8"))
            except OSError as err:
                logger.warning("SO_BINDTODEVICE failed for %s: %s (may need root)", ifname, err)

            addr, mask = get_interface_info(sock, ifname)

            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                pass

            sock.bind((str(addr), MdnsPort))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(str(addr)))

            mreq = struct.pack("4s4s", socket.inet_aton(MdnsAddr), socket.inet_aton(str(addr)))
            recv_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)

            sock.setblocking(False)

            info = InterfaceInfo.from_interface(ifname, addr, mask)
            iface_sock = InterfaceSocket(info, sock)
            logger.info("%s", iface_sock)
            return iface_sock

        except Exception:
            sock.close()
            raise

    def _send_packet(self, sock: socket.socket, data: bytes) -> int:
        """Send a packet to the mDNS multicast address."""
        return sock.sendto(data, (MdnsAddr, MdnsPort))

    def _is_from_our_network(self, from_addr: ipaddress.IPv4Address) -> bool:
        """Check if packet originated from one of our configured networks."""
        return any(from_addr in iface.network for iface in self.interface_sockets)

    def _is_loopback(self, from_addr: ipaddress.IPv4Address) -> bool:
        """Check if packet is from one of our own interface addresses."""
        return any(from_addr == iface.addr for iface in self.interface_sockets)

    def _check_legacy_filters(self, from_addr: ipaddress.IPv4Address) -> bool:
        """Check legacy IP-based whitelist/blacklist. Returns True if allowed."""
        if self.config.whitelist:
            return any(subnet.contains(from_addr) for subnet in self.config.whitelist)

        if self.config.blacklist:
            return not any(subnet.contains(from_addr) for subnet in self.config.blacklist)

        return True

    def _evaluate_packet(
        self, from_addr: ipaddress.IPv4Address, data: bytes
    ) -> tuple[bool, ParsedMDNSPacket | None, str]:
        """
        Evaluate whether a packet should be forwarded.

        Returns:
            Tuple of (should_forward, parsed_packet, reason)
            - should_forward: True if packet should be forwarded
            - parsed_packet: Parsed mDNS packet (if parsing succeeded)
            - reason: Human-readable reason for the decision
        """
        # Basic network checks
        if not self._is_from_our_network(from_addr):
            return False, None, "not from our network"

        if self._is_loopback(from_addr):
            return False, None, "loopback (our own packet)"

        # Legacy IP filtering
        if not self._check_legacy_filters(from_addr):
            return False, None, "blocked by IP filter"

        # Parse the packet
        packet = MDNSParser.parse(data, from_addr)

        # Content-based filtering
        if self.config.filter_config.rules:
            if packet is None:
                action = self.config.filter_config.default_action
                reason = f"parse failed, using default: {action.value}"
            else:
                action, rule_name = self.filter_engine.evaluate(packet)
                if rule_name:
                    reason = f"rule '{rule_name}': {action.value}"
                else:
                    reason = f"no rule matched, default: {action.value}"

            if action == FilterAction.DENY:
                return False, packet, reason
            else:
                return True, packet, reason

        # No content filtering configured - allow
        return True, packet, "allowed (no filters)"

    def _get_source_network(self, from_addr: ipaddress.IPv4Address) -> ipaddress.IPv4Network | None:
        """Get the network from which a packet originated."""
        for iface in self.interface_sockets:
            if from_addr in iface.network:
                return iface.network
        return None

    async def _handle_packet(self, data: bytes, from_addr: tuple[str, int]) -> None:
        """Handle a received mDNS packet."""
        addr = ipaddress.IPv4Address(from_addr[0])

        # Evaluate the packet
        should_forward, packet, reason = self._evaluate_packet(addr, data)

        # Format packet summary for logging
        if packet:
            packet_summary = packet.format_summary()
        else:
            packet_summary = f"{len(data)} bytes from {addr}"

        # Handle denied packets
        if not should_forward:
            logger.info("DENY: %s (%s)", packet_summary, reason)
            return

        # Get target interfaces
        source_net = self._get_source_network(addr)
        target_ifaces = [
            iface for iface in self.interface_sockets
            if iface.network != source_net
        ]
        target_names = [iface.ifname for iface in target_ifaces]

        # Dry run mode - just log what would happen
        if self.config.dry_run:
            logger.info(
                "WOULD FORWARD: %s -> [%s] (%s)",
                packet_summary,
                ", ".join(target_names),
                reason,
            )
            if packet:
                logger.debug("\n%s", packet.format_detailed())
            return

        # Actually forward the packet
        logger.info("FORWARD: %s -> [%s] (%s)", packet_summary, ", ".join(target_names), reason)

        for iface in target_ifaces:
            try:
                sent = self._send_packet(iface.sockfd, data)
                if sent != len(data):
                    logger.error("Partial send to %s: expected %d, sent %d", iface.ifname, len(data), sent)
            except OSError as err:
                logger.error("Send error on %s: %s", iface.ifname, err)

    async def _receive_loop(self) -> None:
        """Main receive loop using asyncio."""
        assert self.server_socket is not None
        loop = asyncio.get_event_loop()

        while not self.shutdown_flag:
            try:
                future = loop.sock_recvfrom(self.server_socket, PacketSize)
                try:
                    data, from_addr = await asyncio.wait_for(future, timeout=10.0)
                    await self._handle_packet(data, from_addr)
                except asyncio.TimeoutError:
                    continue
            except OSError as err:
                if not self.shutdown_flag:
                    logger.error("Receive error: %s", err)
                    await asyncio.sleep(1)

    def _signal_handler(self, signum: int, frame: types.FrameType | None) -> None:
        """Handle shutdown signals."""
        logger.info("Received signal %d, shutting down...", signum)
        self.shutdown_flag = True

    def _setup_logging(self) -> None:
        """Configure logging to stderr."""
        logging.basicConfig(
            level=logging.DEBUG,
            format=f"{Package}: %(message)s",
            stream=sys.stderr,
        )

    def _cleanup(self) -> None:
        """Clean up resources on shutdown."""
        if self.server_socket:
            self.server_socket.close()

        for iface in self.interface_sockets:
            iface.sockfd.close()

        logger.info("Exit.")

    def _log_filter_config(self) -> None:
        """Log the active filter configuration."""
        fc = self.config.filter_config
        logger.info("Filter default action: %s", fc.default_action.value)
        for rule in fc.rules:
            logger.info("  Rule '%s': %s", rule.name, rule.action.value)

    def run(self) -> int:
        """Main entry point."""
        self._setup_logging()

        # Log mode
        if self.config.dry_run:
            logger.info("DRY RUN MODE - packets will not actually be forwarded")

        # Log legacy filters
        for subnet in self.config.whitelist:
            logger.info("Whitelist: %s", subnet)
        for subnet in self.config.blacklist:
            logger.info("Blacklist: %s", subnet)

        # Log content filters
        if self.config.filter_config.rules:
            self._log_filter_config()

        try:
            self.server_socket = self._create_recv_socket()

            for ifname in self.config.interfaces:
                iface_sock = self._create_send_socket(self.server_socket, ifname)
                self.interface_sockets.append(iface_sock)

        except OSError as err:
            logger.error("Failed to create sockets: %s", err)
            self._cleanup()
            return 1

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        try:
            asyncio.run(self._receive_loop())
        except KeyboardInterrupt:
            pass
        finally:
            logger.info("Shutting down...")
            self._cleanup()

        return 0


# =============================================================================
# Click CLI
# =============================================================================


class PathType(click.ParamType):
    """Click parameter type for Path objects."""

    name = "path"

    def convert(
        self, value: t.Any, param: click.Parameter | None, ctx: click.Context | None
    ) -> Path:
        if isinstance(value, Path):
            return value
        return Path(value)


ClickPath = PathType()


@click.command(
    context_settings={"help_option_names": ["-h", "--help"]},
    epilog="""
Examples:

  # Basic usage - repeat between two interfaces
  mdns-filter eth0 wlan0

  # Dry run - see what would be forwarded without actually doing it
  mdns-filter --dry-run eth0 wlan0 \\
    --filter-allow 'instance:Google-Cast-*' \\
    --default-deny

  # Allow only Google Cast groups, deny everything else
  mdns-filter eth0 wlan0 \\
    --filter-allow 'instance:Google-Cast-*' \\
    --default-deny

  # Deny specific devices
  mdns-filter eth0 wlan0 \\
    --filter-deny 'instance:WiiM-*'

  # Use a YAML config file for complex rules
  mdns-filter eth0 wlan0 --filter-config /etc/mdns-filter/filters.yaml

  # Legacy IP-based filtering
  mdns-filter -b 192.168.1.0/24 eth0 eth1
""",
)
@click.argument("interfaces", nargs=-1, required=True)
@click.option(
    "-n",
    "--dry-run",
    is_flag=True,
    help="Don't actually forward packets, just log what would happen.",
)
@click.option(
    "-b",
    "--blacklist",
    "blacklist_cidrs",
    multiple=True,
    metavar="CIDR",
    help="Blacklist subnet (legacy IP filter). Example: 192.168.1.0/24",
)
@click.option(
    "-w",
    "--whitelist",
    "whitelist_cidrs",
    multiple=True,
    metavar="CIDR",
    help="Whitelist subnet (legacy IP filter). Example: 192.168.1.0/24",
)
@click.option(
    "--filter-config",
    type=ClickPath,
    metavar="PATH",
    help="Path to YAML filter configuration file.",
)
@click.option(
    "--filter-allow",
    "filter_allow_patterns",
    multiple=True,
    metavar="PATTERN",
    help="Allow pattern (e.g., 'instance:Google-Cast-*,service:_googlecast._tcp').",
)
@click.option(
    "--filter-deny",
    "filter_deny_patterns",
    multiple=True,
    metavar="PATTERN",
    help="Deny pattern (e.g., 'instance:WiiM-*').",
)
@click.option(
    "--default-deny",
    is_flag=True,
    help="Deny packets that don't match any filter rule (default: allow).",
)
@click.version_option(version="2.0.0", prog_name=Package)
def main(
    interfaces: tuple[str, ...],
    dry_run: bool,
    blacklist_cidrs: tuple[str, ...],
    whitelist_cidrs: tuple[str, ...],
    filter_config: Path | None,
    filter_allow_patterns: tuple[str, ...],
    filter_deny_patterns: tuple[str, ...],
    default_deny: bool,
) -> None:
    """
    mDNS repeater daemon - repeats mDNS packets between network interfaces.

    INTERFACES: Network interfaces to bridge (minimum 2 required).

    Packets received on one interface are repeated to all other specified
    interfaces, enabling mDNS discovery across network segments.
    """
    # Validate interface count
    if len(interfaces) < 2:
        raise click.UsageError("At least 2 interfaces must be specified.")

    # Parse legacy subnet filters
    try:
        blacklist = [SubnetConfig.from_cidr(cidr) for cidr in blacklist_cidrs]
        whitelist = [SubnetConfig.from_cidr(cidr) for cidr in whitelist_cidrs]
    except ValueError as err:
        raise click.UsageError(f"Invalid subnet: {err}") from err

    if blacklist and whitelist:
        raise click.UsageError("Cannot specify both --blacklist and --whitelist.")

    # Build filter configuration
    if filter_config is not None:
        # Load from file
        if filter_allow_patterns or filter_deny_patterns:
            raise click.UsageError(
                "Cannot use --filter-config with --filter-allow or --filter-deny."
            )
        try:
            fc = FilterConfig.from_yaml_file(filter_config)
        except FileNotFoundError as err:
            raise click.UsageError(f"Filter config file not found: {filter_config}") from err
        except yaml.YAMLError as err:
            raise click.UsageError(f"Invalid YAML in filter config: {err}") from err
        except Exception as err:
            raise click.UsageError(f"Error loading filter config: {err}") from err
    elif filter_allow_patterns or filter_deny_patterns:
        # Build from CLI patterns
        try:
            fc = FilterConfig.from_cli_patterns(
                allow_patterns=list(filter_allow_patterns),
                deny_patterns=list(filter_deny_patterns),
                default_deny=default_deny,
            )
        except ValueError as err:
            raise click.UsageError(f"Invalid filter pattern: {err}") from err
    else:
        # No content filtering, just use default
        fc = FilterConfig(
            default_action=FilterAction.DENY if default_deny else FilterAction.ALLOW
        )

    # Build config
    try:
        config = RepeaterConfig(
            interfaces=list(interfaces),
            dry_run=dry_run,
            blacklist=blacklist,
            whitelist=whitelist,
            filter_config=fc,
        )
    except Exception as err:
        raise click.UsageError(f"Configuration error: {err}") from err

    # Run the repeater
    repeater = MDNSRepeater(config)
    sys.exit(repeater.run())


if __name__ == "__main__":
    main()

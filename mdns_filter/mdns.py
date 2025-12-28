"""mDNS packet models."""

from __future__ import annotations

import ipaddress

import pydantic as p

from mdns_filter.const import RecordSection, RecordType


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
            result.append((RecordSection.Question, rec))
        for rec in self.answers:
            result.append((RecordSection.Answer, rec))
        for rec in self.authorities:
            result.append((RecordSection.Authority, rec))
        for rec in self.additionals:
            result.append((RecordSection.Additional, rec))
        return result

    @property
    def record_count(self) -> int:
        """Total number of records in the packet."""
        return len(self.questions) + len(self.answers) + len(self.authorities) + len(self.additionals)

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

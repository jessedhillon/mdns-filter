"""mDNS packet parsing."""

from __future__ import annotations

import ipaddress
import logging
import struct

from mdns_filter import const
from mdns_filter.const import RecordType
from mdns_filter.mdns import DNSRecord, ParsedMDNSPacket

logger = logging.getLogger(const.Package)


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
    def parse(cls, data: bytes, src_ip: ipaddress.IPv4Address | None = None) -> ParsedMDNSPacket | None:
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

                    rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
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
                        ptr_instance, ptr_service, _ = cls.parse_service_name(target_name)
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

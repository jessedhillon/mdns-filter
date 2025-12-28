"""Tests for mdns_filter.mdns module."""

from __future__ import annotations

import ipaddress

from mdns_filter.const import RecordType, RecordSection
from mdns_filter.mdns import DNSRecord, ParsedMDNSPacket


class TestDNSRecord:
    """Tests for DNSRecord model."""

    def test_type_name_known_type(self) -> None:
        record = DNSRecord(name="test.local", record_type=RecordType.PTR, record_class=1)
        assert record.type_name == "PTR"

    def test_type_name_a_record(self) -> None:
        record = DNSRecord(name="test.local", record_type=RecordType.A, record_class=1)
        assert record.type_name == "A"

    def test_type_name_unknown_type(self) -> None:
        record = DNSRecord(name="test.local", record_type=999, record_class=1)
        assert record.type_name == "TYPE999"

    def test_matches_type_exact(self) -> None:
        record = DNSRecord(name="test.local", record_type=RecordType.PTR, record_class=1)
        assert record.matches_type("PTR") is True
        assert record.matches_type("ptr") is True
        assert record.matches_type("TXT") is False

    def test_matches_type_wildcard(self) -> None:
        record = DNSRecord(name="test.local", record_type=RecordType.PTR, record_class=1)
        assert record.matches_type("*") is True

    def test_matches_type_case_insensitive(self) -> None:
        record = DNSRecord(name="test.local", record_type=RecordType.AAAA, record_class=1)
        assert record.matches_type("aaaa") is True
        assert record.matches_type("AAAA") is True
        assert record.matches_type("Aaaa") is True

    def test_frozen_model(self) -> None:
        record = DNSRecord(name="test.local", record_type=RecordType.A, record_class=1)
        # Model should be frozen (immutable)
        try:
            record.name = "other.local"  # type: ignore[misc]
            raise AssertionError("Should have raised an error")
        except Exception:
            pass  # Expected

    def test_default_values(self) -> None:
        record = DNSRecord(name="test.local", record_type=RecordType.A, record_class=1)
        assert record.ttl == 0
        assert record.rdata == b""
        assert record.instance is None
        assert record.service is None
        assert record.domain == "local"
        assert record.txt_records == {}


class TestParsedMDNSPacket:
    """Tests for ParsedMDNSPacket model."""

    def test_all_records_empty_packet(self) -> None:
        packet = ParsedMDNSPacket(
            transaction_id=0,
            flags=0,
            is_response=False,
            is_authoritative=False,
            is_truncated=False,
        )
        assert packet.all_records == []

    def test_all_records_with_sections(self) -> None:
        question = DNSRecord(name="q.local", record_type=RecordType.PTR, record_class=1)
        answer = DNSRecord(name="a.local", record_type=RecordType.PTR, record_class=1)
        authority = DNSRecord(name="ns.local", record_type=RecordType.NS, record_class=1)
        additional = DNSRecord(name="add.local", record_type=RecordType.A, record_class=1)

        packet = ParsedMDNSPacket(
            transaction_id=0,
            flags=0x8400,
            is_response=True,
            is_authoritative=True,
            is_truncated=False,
            questions=(question,),
            answers=(answer,),
            authorities=(authority,),
            additionals=(additional,),
        )

        all_recs = packet.all_records
        assert len(all_recs) == 4
        assert all_recs[0] == (RecordSection.Question, question)
        assert all_recs[1] == (RecordSection.Answer, answer)
        assert all_recs[2] == (RecordSection.Authority, authority)
        assert all_recs[3] == (RecordSection.Additional, additional)

    def test_record_count(self) -> None:
        packet = ParsedMDNSPacket(
            transaction_id=0,
            flags=0,
            is_response=False,
            is_authoritative=False,
            is_truncated=False,
            questions=(
                DNSRecord(name="q1.local", record_type=1, record_class=1),
                DNSRecord(name="q2.local", record_type=1, record_class=1),
            ),
            answers=(DNSRecord(name="a.local", record_type=1, record_class=1),),
        )
        assert packet.record_count == 3

    def test_format_summary_query(self) -> None:
        question = DNSRecord(
            name="_googlecast._tcp.local",
            record_type=RecordType.PTR,
            record_class=1,
        )
        packet = ParsedMDNSPacket(
            transaction_id=0,
            flags=0,
            is_response=False,
            is_authoritative=False,
            is_truncated=False,
            questions=(question,),
            src_ip=ipaddress.IPv4Address("192.168.1.50"),
        )

        summary = packet.format_summary()
        assert "from 192.168.1.50" in summary
        assert "query" in summary
        assert "1q" in summary
        assert "PTR?" in summary

    def test_format_summary_response(self) -> None:
        answer = DNSRecord(
            name="_googlecast._tcp.local",
            record_type=RecordType.PTR,
            record_class=1,
            instance="My-Device",
            service="_googlecast._tcp",
            domain="local",
        )
        packet = ParsedMDNSPacket(
            transaction_id=0,
            flags=0x8400,
            is_response=True,
            is_authoritative=True,
            is_truncated=False,
            answers=(answer,),
            src_ip=ipaddress.IPv4Address("192.168.1.100"),
        )

        summary = packet.format_summary()
        assert "response" in summary
        assert "authoritative" in summary
        assert "1an" in summary
        assert "My-Device" in summary

    def test_format_summary_truncated(self) -> None:
        packet = ParsedMDNSPacket(
            transaction_id=0,
            flags=0x8200,
            is_response=True,
            is_authoritative=False,
            is_truncated=True,
            src_ip=ipaddress.IPv4Address("192.168.1.100"),
        )

        summary = packet.format_summary()
        assert "truncated" in summary

    def test_format_summary_many_answers(self) -> None:
        answers = tuple(DNSRecord(name=f"r{i}.local", record_type=RecordType.A, record_class=1) for i in range(5))
        packet = ParsedMDNSPacket(
            transaction_id=0,
            flags=0x8400,
            is_response=True,
            is_authoritative=True,
            is_truncated=False,
            answers=answers,
        )

        summary = packet.format_summary()
        assert "+2 more" in summary  # 5 answers, shows 3, mentions 2 more

    def test_format_detailed(self) -> None:
        answer = DNSRecord(
            name="Device._googlecast._tcp.local",
            record_type=RecordType.PTR,
            record_class=1,
            instance="Device",
            service="_googlecast._tcp",
            domain="local",
        )
        txt = DNSRecord(
            name="Device._googlecast._tcp.local",
            record_type=RecordType.TXT,
            record_class=1,
            instance="Device",
            txt_records={"fn": "Living Room"},
        )
        packet = ParsedMDNSPacket(
            transaction_id=0,
            flags=0x8400,
            is_response=True,
            is_authoritative=True,
            is_truncated=False,
            answers=(answer, txt),
            src_ip=ipaddress.IPv4Address("192.168.1.100"),
        )

        detailed = packet.format_detailed()
        assert "mDNS Response" in detailed
        assert "192.168.1.100" in detailed
        assert "AA=True" in detailed
        assert "Answers:" in detailed
        assert "PTR:" in detailed
        assert "TXT:" in detailed
        assert "fn=Living Room" in detailed

    def test_format_detailed_query(self) -> None:
        question = DNSRecord(
            name="_googlecast._tcp.local",
            record_type=RecordType.PTR,
            record_class=1,
        )
        packet = ParsedMDNSPacket(
            transaction_id=0,
            flags=0,
            is_response=False,
            is_authoritative=False,
            is_truncated=False,
            questions=(question,),
            src_ip=ipaddress.IPv4Address("192.168.1.50"),
        )

        detailed = packet.format_detailed()
        assert "mDNS Query" in detailed
        assert "Questions:" in detailed

    def test_frozen_model(self) -> None:
        packet = ParsedMDNSPacket(
            transaction_id=0,
            flags=0,
            is_response=False,
            is_authoritative=False,
            is_truncated=False,
        )
        try:
            packet.is_response = True  # type: ignore[misc]
            raise AssertionError("Should have raised an error")
        except Exception:
            pass  # Expected

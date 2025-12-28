"""Tests for mdns_filter.parse module."""

from __future__ import annotations

import ipaddress
import struct

from mdns_filter.const import RecordType
from mdns_filter.parse import MDNSParser


class TestParseName:
    """Tests for MDNSParser.parse_name."""

    def test_simple_single_label(self) -> None:
        # "local" with null terminator
        data = b"\x05local\x00"
        name, offset = MDNSParser.parse_name(data, 0)
        assert name == "local"
        assert offset == 7

    def test_multi_label_name(self) -> None:
        # "_googlecast._tcp.local"
        data = b"\x0b_googlecast\x04_tcp\x05local\x00"
        name, offset = MDNSParser.parse_name(data, 0)
        assert name == "_googlecast._tcp.local"
        assert offset == len(data)

    def test_name_with_instance(self) -> None:
        # "My-Device._googlecast._tcp.local"
        data = b"\x09My-Device\x0b_googlecast\x04_tcp\x05local\x00"
        name, _ = MDNSParser.parse_name(data, 0)
        assert name == "My-Device._googlecast._tcp.local"

    def test_compression_pointer(self) -> None:
        # First name at offset 0: "_googlecast._tcp.local"
        # Second name at offset 23: pointer back to offset 0
        first_name = b"\x0b_googlecast\x04_tcp\x05local\x00"
        pointer = b"\xc0\x00"  # Pointer to offset 0
        data = first_name + pointer

        # Parse the pointer (at offset 23)
        name, offset = MDNSParser.parse_name(data, len(first_name))
        assert name == "_googlecast._tcp.local"
        assert offset == len(data)  # Should advance past the pointer

    def test_partial_compression(self) -> None:
        # "My-Device" followed by pointer to "_googlecast._tcp.local"
        service_part = b"\x0b_googlecast\x04_tcp\x05local\x00"
        instance_with_ptr = b"\x09My-Device\xc0\x00"  # "My-Device" + pointer to offset 0
        data = service_part + instance_with_ptr

        name, _ = MDNSParser.parse_name(data, len(service_part))
        assert name == "My-Device._googlecast._tcp.local"

    def test_empty_name(self) -> None:
        data = b"\x00"
        name, offset = MDNSParser.parse_name(data, 0)
        assert name == ""
        assert offset == 1

    def test_offset_past_data(self) -> None:
        data = b"\x05local\x00"
        name, _ = MDNSParser.parse_name(data, 100)
        assert name == ""

    def test_truncated_label(self) -> None:
        # Label claims 10 bytes but only 5 available
        data = b"\x0ahello"
        name, _ = MDNSParser.parse_name(data, 0)
        assert name == ""


class TestParseServiceName:
    """Tests for MDNSParser.parse_service_name."""

    def test_full_service_name(self) -> None:
        instance, service, domain = MDNSParser.parse_service_name("Google-Cast-Group-abc._googlecast._tcp.local")
        assert instance == "Google-Cast-Group-abc"
        assert service == "_googlecast._tcp"
        assert domain == "local"

    def test_service_without_instance(self) -> None:
        instance, service, domain = MDNSParser.parse_service_name("_googlecast._tcp.local")
        assert instance is None
        assert service == "_googlecast._tcp"
        assert domain == "local"

    def test_udp_service(self) -> None:
        instance, service, domain = MDNSParser.parse_service_name("_spotify-connect._udp.local")
        assert instance is None
        assert service == "_spotify-connect._udp"
        assert domain == "local"

    def test_instance_with_dots(self) -> None:
        # Instance name containing dots
        instance, service, domain = MDNSParser.parse_service_name("My.Device.Name._http._tcp.local")
        assert instance == "My.Device.Name"
        assert service == "_http._tcp"
        assert domain == "local"

    def test_no_service_pattern(self) -> None:
        instance, service, domain = MDNSParser.parse_service_name("hostname.local")
        assert instance is None
        assert service is None
        assert domain == "local"

    def test_plain_hostname(self) -> None:
        instance, service, domain = MDNSParser.parse_service_name("mycomputer")
        assert instance is None
        assert service is None
        assert domain == "mycomputer"

    def test_empty_string(self) -> None:
        instance, service, domain = MDNSParser.parse_service_name("")
        assert instance is None
        assert service is None
        assert domain == ""  # Empty string returns empty domain

    def test_subdomain_after_service(self) -> None:
        instance, service, domain = MDNSParser.parse_service_name("Device._http._tcp.subdomain.local")
        assert instance == "Device"
        assert service == "_http._tcp"
        assert domain == "subdomain.local"


class TestParseTxtRecord:
    """Tests for MDNSParser.parse_txt_record."""

    def test_single_key_value(self) -> None:
        # TXT record: length byte + "key=value"
        rdata = b"\x09key=value"
        result = MDNSParser.parse_txt_record(rdata)
        assert result == {"key": "value"}

    def test_multiple_key_values(self) -> None:
        rdata = b"\x06id=123\x09fn=Living"  # 9 bytes for "fn=Living"
        result = MDNSParser.parse_txt_record(rdata)
        assert result == {"id": "123", "fn": "Living"}

    def test_flag_without_value(self) -> None:
        rdata = b"\x07enabled"
        result = MDNSParser.parse_txt_record(rdata)
        assert result == {"enabled": ""}

    def test_empty_value(self) -> None:
        rdata = b"\x04key="
        result = MDNSParser.parse_txt_record(rdata)
        assert result == {"key": ""}

    def test_empty_rdata(self) -> None:
        result = MDNSParser.parse_txt_record(b"")
        assert result == {}

    def test_zero_length_string(self) -> None:
        rdata = b"\x00"
        result = MDNSParser.parse_txt_record(rdata)
        assert result == {}

    def test_mixed_entries(self) -> None:
        rdata = b"\x05a=one\x04flag\x05b=two"
        result = MDNSParser.parse_txt_record(rdata)
        assert result == {"a": "one", "flag": "", "b": "two"}


class TestParse:
    """Tests for MDNSParser.parse (full packet parsing)."""

    def _build_header(
        self,
        transaction_id: int = 0,
        flags: int = 0,
        qdcount: int = 0,
        ancount: int = 0,
        nscount: int = 0,
        arcount: int = 0,
    ) -> bytes:
        return struct.pack("!HHHHHH", transaction_id, flags, qdcount, ancount, nscount, arcount)

    def _build_question(self, name_bytes: bytes, qtype: int, qclass: int = 1) -> bytes:
        return name_bytes + struct.pack("!HH", qtype, qclass)

    def _build_rr(self, name_bytes: bytes, rtype: int, rclass: int, ttl: int, rdata: bytes) -> bytes:
        return name_bytes + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata

    def test_too_short_returns_none(self) -> None:
        assert MDNSParser.parse(b"short") is None
        assert MDNSParser.parse(b"") is None
        assert MDNSParser.parse(b"12345678901") is None  # 11 bytes, need 12

    def test_header_only_packet(self) -> None:
        data = self._build_header()
        packet = MDNSParser.parse(data)
        assert packet is not None
        assert packet.transaction_id == 0
        assert packet.is_response is False
        assert len(packet.questions) == 0

    def test_query_packet(self) -> None:
        name = b"\x0b_googlecast\x04_tcp\x05local\x00"
        header = self._build_header(qdcount=1)
        question = self._build_question(name, RecordType.PTR)
        data = header + question

        packet = MDNSParser.parse(data)
        assert packet is not None
        assert packet.is_response is False
        assert len(packet.questions) == 1
        assert packet.questions[0].name == "_googlecast._tcp.local"
        assert packet.questions[0].record_type == RecordType.PTR

    def test_response_packet(self) -> None:
        name = b"\x0b_googlecast\x04_tcp\x05local\x00"
        # PTR record pointing to an instance
        ptr_target = b"\x09My-Device\xc0\x00"  # "My-Device" + pointer to offset 12
        header = self._build_header(flags=0x8400, ancount=1)  # Response + Authoritative
        answer = self._build_rr(name, RecordType.PTR, 1, 4500, ptr_target)
        data = header + answer

        packet = MDNSParser.parse(data)
        assert packet is not None
        assert packet.is_response is True
        assert packet.is_authoritative is True
        assert len(packet.answers) == 1

    def test_truncated_flag(self) -> None:
        header = self._build_header(flags=0x8200)  # Response + Truncated
        packet = MDNSParser.parse(header)
        assert packet is not None
        assert packet.is_truncated is True

    def test_txt_record_parsing(self) -> None:
        name = b"\x09My-Device\x0b_googlecast\x04_tcp\x05local\x00"
        txt_rdata = b"\x06id=123\x09fn=Living"
        header = self._build_header(flags=0x8400, ancount=1)
        answer = self._build_rr(name, RecordType.TXT, 1, 4500, txt_rdata)
        data = header + answer

        packet = MDNSParser.parse(data)
        assert packet is not None
        assert len(packet.answers) == 1
        assert packet.answers[0].txt_records == {"id": "123", "fn": "Living"}

    def test_src_ip_included(self) -> None:
        header = self._build_header()
        src = ipaddress.IPv4Address("192.168.1.100")
        packet = MDNSParser.parse(header, src_ip=src)
        assert packet is not None
        assert packet.src_ip == src

    def test_multiple_sections(self) -> None:
        name = b"\x05local\x00"
        header = self._build_header(flags=0x8400, qdcount=1, ancount=1, arcount=1)
        question = self._build_question(name, RecordType.A)
        answer = self._build_rr(name, RecordType.A, 1, 120, b"\xc0\xa8\x01\x64")  # 192.168.1.100
        additional = self._build_rr(name, RecordType.AAAA, 1, 120, b"\x00" * 16)
        data = header + question + answer + additional

        packet = MDNSParser.parse(data)
        assert packet is not None
        assert len(packet.questions) == 1
        assert len(packet.answers) == 1
        assert len(packet.additionals) == 1

    def test_malformed_packet_returns_none(self) -> None:
        # Header claims 1 question but no question data
        header = self._build_header(qdcount=1)
        # Don't add question data, just truncate
        packet = MDNSParser.parse(header)
        # Should still return a packet (just with empty questions due to bounds check)
        assert packet is not None
        assert len(packet.questions) == 0

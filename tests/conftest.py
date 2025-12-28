"""Shared test fixtures for mdns-filter tests."""

from __future__ import annotations

import ipaddress

import pytest

from mdns_filter.const import RecordType, FilterAction, LogLevel
from mdns_filter.mdns import DNSRecord, ParsedMDNSPacket
from mdns_filter.rules import FilterMatch, FilterRule, FilterConfig


@pytest.fixture
def sample_dns_record() -> DNSRecord:
    """A basic DNS PTR record for testing."""
    return DNSRecord(
        name="_googlecast._tcp.local",
        record_type=RecordType.PTR,
        record_class=1,
        ttl=4500,
        instance="Google-Cast-Group-abc123",
        service="_googlecast._tcp",
        domain="local",
    )


@pytest.fixture
def sample_txt_record() -> DNSRecord:
    """A DNS TXT record with key-value pairs."""
    return DNSRecord(
        name="Google-Cast-Group-abc123._googlecast._tcp.local",
        record_type=RecordType.TXT,
        record_class=1,
        ttl=4500,
        instance="Google-Cast-Group-abc123",
        service="_googlecast._tcp",
        domain="local",
        txt_records={"id": "abc123", "fn": "Living Room Speaker", "md": "Google Home"},
    )


@pytest.fixture
def sample_packet(sample_dns_record: DNSRecord) -> ParsedMDNSPacket:
    """A basic mDNS response packet."""
    return ParsedMDNSPacket(
        transaction_id=0,
        flags=0x8400,
        is_response=True,
        is_authoritative=True,
        is_truncated=False,
        answers=(sample_dns_record,),
        src_ip=ipaddress.IPv4Address("192.168.1.100"),
    )


@pytest.fixture
def query_packet() -> ParsedMDNSPacket:
    """A simple mDNS query packet."""
    question = DNSRecord(
        name="_googlecast._tcp.local",
        record_type=RecordType.PTR,
        record_class=1,
    )
    return ParsedMDNSPacket(
        transaction_id=0,
        flags=0,
        is_response=False,
        is_authoritative=False,
        is_truncated=False,
        questions=(question,),
        src_ip=ipaddress.IPv4Address("192.168.1.50"),
    )


@pytest.fixture
def googlecast_response() -> ParsedMDNSPacket:
    """A realistic Google Cast announcement packet."""
    ptr_record = DNSRecord(
        name="_googlecast._tcp.local",
        record_type=RecordType.PTR,
        record_class=1,
        ttl=4500,
        instance="Google-Cast-Group-abc123",
        service="_googlecast._tcp",
        domain="local",
    )
    srv_record = DNSRecord(
        name="Google-Cast-Group-abc123._googlecast._tcp.local",
        record_type=RecordType.SRV,
        record_class=1,
        ttl=120,
        instance="Google-Cast-Group-abc123",
        service="_googlecast._tcp",
        domain="local",
    )
    txt_record = DNSRecord(
        name="Google-Cast-Group-abc123._googlecast._tcp.local",
        record_type=RecordType.TXT,
        record_class=1,
        ttl=4500,
        instance="Google-Cast-Group-abc123",
        service="_googlecast._tcp",
        domain="local",
        txt_records={"id": "abc123", "fn": "Living Room", "md": "Google Home"},
    )
    return ParsedMDNSPacket(
        transaction_id=0,
        flags=0x8400,
        is_response=True,
        is_authoritative=True,
        is_truncated=False,
        answers=(ptr_record, srv_record, txt_record),
        src_ip=ipaddress.IPv4Address("192.168.1.100"),
    )


@pytest.fixture
def sample_filter_config() -> FilterConfig:
    """A basic filter configuration for testing."""
    return FilterConfig(
        default_action=FilterAction.Deny,
        rules=[
            FilterRule(
                name="allow-googlecast",
                match=FilterMatch(instance="Google-Cast-*"),
                action=FilterAction.Allow,
                log=LogLevel.Debug,
            ),
        ],
    )

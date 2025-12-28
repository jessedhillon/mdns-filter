"""Tests for mdns_filter.rules module."""

from __future__ import annotations

import ipaddress
import tempfile
from pathlib import Path

import pytest

from mdns_filter.const import RecordType, RecordSection, FilterAction, LogLevel
from mdns_filter.mdns import DNSRecord, ParsedMDNSPacket
from mdns_filter.rules import FilterMatch, FilterRule, FilterConfig


class TestFilterMatchValidators:
    """Tests for FilterMatch field validators."""

    def test_valid_src_ip_single(self) -> None:
        match = FilterMatch(src_ip="192.168.1.100")
        assert match.src_ip == "192.168.1.100"

    def test_valid_src_ip_cidr(self) -> None:
        match = FilterMatch(src_ip="192.168.1.0/24")
        assert match.src_ip == "192.168.1.0/24"

    def test_invalid_src_ip_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid IP/CIDR"):
            FilterMatch(src_ip="not-an-ip")

    def test_valid_record_type(self) -> None:
        match = FilterMatch(record_type="PTR")
        assert match.record_type == "PTR"

    def test_record_type_uppercase(self) -> None:
        match = FilterMatch(record_type="ptr")
        assert match.record_type == "PTR"

    def test_record_type_wildcard(self) -> None:
        match = FilterMatch(record_type="*")
        assert match.record_type == "*"

    def test_invalid_record_type_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown record type"):
            FilterMatch(record_type="INVALID")


class TestFilterMatchGetNetwork:
    """Tests for FilterMatch.get_network."""

    def test_no_src_ip_returns_none(self) -> None:
        match = FilterMatch()
        assert match.get_network() is None

    def test_single_ip_returns_network(self) -> None:
        match = FilterMatch(src_ip="192.168.1.100")
        network = match.get_network()
        assert network is not None
        assert ipaddress.IPv4Address("192.168.1.100") in network

    def test_cidr_returns_network(self) -> None:
        match = FilterMatch(src_ip="192.168.1.0/24")
        network = match.get_network()
        assert network is not None
        assert ipaddress.IPv4Address("192.168.1.50") in network
        assert ipaddress.IPv4Address("192.168.2.50") not in network

    def test_network_cached(self) -> None:
        match = FilterMatch(src_ip="192.168.1.0/24")
        network1 = match.get_network()
        network2 = match.get_network()
        assert network1 is network2


class TestFilterMatchMatchesRecord:
    """Tests for FilterMatch.matches_record."""

    @pytest.fixture
    def sample_record(self) -> DNSRecord:
        return DNSRecord(
            name="My-Device._googlecast._tcp.local",
            record_type=RecordType.PTR,
            record_class=1,
            instance="My-Device",
            service="_googlecast._tcp",
            domain="local",
        )

    @pytest.fixture
    def sample_packet(self, sample_record: DNSRecord) -> ParsedMDNSPacket:
        return ParsedMDNSPacket(
            transaction_id=0,
            flags=0x8400,
            is_response=True,
            is_authoritative=True,
            is_truncated=False,
            answers=(sample_record,),
            src_ip=ipaddress.IPv4Address("192.168.1.100"),
        )

    def test_empty_match_matches_all(self, sample_record: DNSRecord, sample_packet: ParsedMDNSPacket) -> None:
        match = FilterMatch()
        assert match.matches_record(RecordSection.Answer, sample_record, sample_packet) is True

    def test_src_ip_match(self, sample_record: DNSRecord, sample_packet: ParsedMDNSPacket) -> None:
        match = FilterMatch(src_ip="192.168.1.0/24")
        assert match.matches_record(RecordSection.Answer, sample_record, sample_packet) is True

    def test_src_ip_no_match(self, sample_record: DNSRecord, sample_packet: ParsedMDNSPacket) -> None:
        match = FilterMatch(src_ip="10.0.0.0/8")
        assert match.matches_record(RecordSection.Answer, sample_record, sample_packet) is False

    def test_is_query_match(self, sample_record: DNSRecord) -> None:
        query_packet = ParsedMDNSPacket(
            transaction_id=0,
            flags=0,
            is_response=False,
            is_authoritative=False,
            is_truncated=False,
            questions=(sample_record,),
            src_ip=ipaddress.IPv4Address("192.168.1.50"),
        )
        match = FilterMatch(is_query=True)
        assert match.matches_record(RecordSection.Question, sample_record, query_packet) is True

    def test_is_query_no_match(self, sample_record: DNSRecord, sample_packet: ParsedMDNSPacket) -> None:
        match = FilterMatch(is_query=True)
        assert match.matches_record(RecordSection.Answer, sample_record, sample_packet) is False

    def test_is_authoritative_match(self, sample_record: DNSRecord, sample_packet: ParsedMDNSPacket) -> None:
        match = FilterMatch(is_authoritative=True)
        assert match.matches_record(RecordSection.Answer, sample_record, sample_packet) is True

    def test_section_match(self, sample_record: DNSRecord, sample_packet: ParsedMDNSPacket) -> None:
        match = FilterMatch(section=RecordSection.Answer)
        assert match.matches_record(RecordSection.Answer, sample_record, sample_packet) is True

    def test_section_no_match(self, sample_record: DNSRecord, sample_packet: ParsedMDNSPacket) -> None:
        match = FilterMatch(section=RecordSection.Question)
        assert match.matches_record(RecordSection.Answer, sample_record, sample_packet) is False

    def test_record_type_match(self, sample_record: DNSRecord, sample_packet: ParsedMDNSPacket) -> None:
        match = FilterMatch(record_type="PTR")
        assert match.matches_record(RecordSection.Answer, sample_record, sample_packet) is True

    def test_record_type_no_match(self, sample_record: DNSRecord, sample_packet: ParsedMDNSPacket) -> None:
        match = FilterMatch(record_type="TXT")
        assert match.matches_record(RecordSection.Answer, sample_record, sample_packet) is False

    def test_service_match(self, sample_record: DNSRecord, sample_packet: ParsedMDNSPacket) -> None:
        match = FilterMatch(service="_googlecast._tcp")
        assert match.matches_record(RecordSection.Answer, sample_record, sample_packet) is True

    def test_service_glob_match(self, sample_record: DNSRecord, sample_packet: ParsedMDNSPacket) -> None:
        match = FilterMatch(service="_google*._tcp")
        assert match.matches_record(RecordSection.Answer, sample_record, sample_packet) is True

    def test_instance_match(self, sample_record: DNSRecord, sample_packet: ParsedMDNSPacket) -> None:
        match = FilterMatch(instance="My-Device")
        assert match.matches_record(RecordSection.Answer, sample_record, sample_packet) is True

    def test_instance_glob_match(self, sample_record: DNSRecord, sample_packet: ParsedMDNSPacket) -> None:
        match = FilterMatch(instance="My-*")
        assert match.matches_record(RecordSection.Answer, sample_record, sample_packet) is True

    def test_name_match(self, sample_record: DNSRecord, sample_packet: ParsedMDNSPacket) -> None:
        match = FilterMatch(name="*._googlecast._tcp.local")
        assert match.matches_record(RecordSection.Answer, sample_record, sample_packet) is True

    def test_txt_contains_match(self, sample_packet: ParsedMDNSPacket) -> None:
        txt_record = DNSRecord(
            name="Device._googlecast._tcp.local",
            record_type=RecordType.TXT,
            record_class=1,
            txt_records={"fn": "Living Room", "id": "abc123"},
        )
        match = FilterMatch(txt_contains="fn=Living*")
        assert match.matches_record(RecordSection.Answer, txt_record, sample_packet) is True

    def test_txt_contains_key_match(self, sample_packet: ParsedMDNSPacket) -> None:
        txt_record = DNSRecord(
            name="Device._googlecast._tcp.local",
            record_type=RecordType.TXT,
            record_class=1,
            txt_records={"fn": "Living Room"},
        )
        match = FilterMatch(txt_contains="fn")
        assert match.matches_record(RecordSection.Answer, txt_record, sample_packet) is True

    def test_txt_contains_non_txt_record(self, sample_record: DNSRecord, sample_packet: ParsedMDNSPacket) -> None:
        match = FilterMatch(txt_contains="anything")
        assert match.matches_record(RecordSection.Answer, sample_record, sample_packet) is False

    def test_combined_criteria(self, sample_record: DNSRecord, sample_packet: ParsedMDNSPacket) -> None:
        match = FilterMatch(
            src_ip="192.168.1.0/24",
            service="_googlecast._tcp",
            instance="My-*",
        )
        assert match.matches_record(RecordSection.Answer, sample_record, sample_packet) is True


class TestFilterRule:
    """Tests for FilterRule model."""

    def test_create_rule(self) -> None:
        rule = FilterRule(
            name="test-rule",
            match=FilterMatch(instance="Google-Cast-*"),
            action=FilterAction.Allow,
        )
        assert rule.name == "test-rule"
        assert rule.action == FilterAction.Allow
        assert rule.log == LogLevel.Off
        assert rule.match_mode == "any"

    def test_rule_with_log_level(self) -> None:
        rule = FilterRule(
            name="test-rule",
            match=FilterMatch(),
            action=FilterAction.Deny,
            log=LogLevel.Info,
        )
        assert rule.log == LogLevel.Info

    def test_rule_match_mode_all(self) -> None:
        rule = FilterRule(
            name="test-rule",
            match=FilterMatch(),
            action=FilterAction.Allow,
            match_mode="all",
        )
        assert rule.match_mode == "all"


class TestFilterConfig:
    """Tests for FilterConfig model."""

    def test_default_config(self) -> None:
        config = FilterConfig()
        assert config.default_action == FilterAction.Allow
        assert config.rules == []

    def test_config_with_rules(self) -> None:
        config = FilterConfig(
            default_action=FilterAction.Deny,
            rules=[
                FilterRule(
                    name="rule1",
                    match=FilterMatch(instance="*"),
                    action=FilterAction.Allow,
                ),
            ],
        )
        assert config.default_action == FilterAction.Deny
        assert len(config.rules) == 1


class TestFilterConfigFromYaml:
    """Tests for FilterConfig.from_yaml_file."""

    def test_load_valid_yaml(self) -> None:
        yaml_content = """
default_action: deny
rules:
  - name: allow-googlecast
    match:
      instance: "Google-Cast-*"
    action: allow
    log: debug
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
            fh.write(yaml_content)
            fh.flush()
            config = FilterConfig.from_yaml_file(Path(fh.name))

        assert config.default_action == FilterAction.Deny
        assert len(config.rules) == 1
        assert config.rules[0].name == "allow-googlecast"
        assert config.rules[0].action == FilterAction.Allow

    def test_load_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            FilterConfig.from_yaml_file(Path("/nonexistent/path.yaml"))


class TestFilterConfigFromCliPatterns:
    """Tests for FilterConfig.from_cli_patterns."""

    def test_allow_pattern(self) -> None:
        config = FilterConfig.from_cli_patterns(
            allow_patterns=["instance:Google-Cast-*"],
            deny_patterns=[],
        )
        assert config.default_action == FilterAction.Allow
        assert len(config.rules) == 1
        assert config.rules[0].action == FilterAction.Allow
        assert config.rules[0].match.instance == "Google-Cast-*"

    def test_deny_pattern(self) -> None:
        config = FilterConfig.from_cli_patterns(
            allow_patterns=[],
            deny_patterns=["instance:WiiM-*"],
        )
        assert len(config.rules) == 1
        assert config.rules[0].action == FilterAction.Deny
        assert config.rules[0].match.instance == "WiiM-*"

    def test_deny_before_allow(self) -> None:
        config = FilterConfig.from_cli_patterns(
            allow_patterns=["instance:Allow-*"],
            deny_patterns=["instance:Deny-*"],
        )
        assert len(config.rules) == 2
        assert config.rules[0].action == FilterAction.Deny  # Deny first
        assert config.rules[1].action == FilterAction.Allow

    def test_default_deny_flag(self) -> None:
        config = FilterConfig.from_cli_patterns(
            allow_patterns=["instance:Allow-*"],
            deny_patterns=[],
            default_deny=True,
        )
        assert config.default_action == FilterAction.Deny

    def test_multiple_criteria_pattern(self) -> None:
        config = FilterConfig.from_cli_patterns(
            allow_patterns=["instance:Device,service:_http._tcp"],
            deny_patterns=[],
        )
        assert len(config.rules) == 1
        assert config.rules[0].match.instance == "Device"
        assert config.rules[0].match.service == "_http._tcp"

    def test_field_aliases(self) -> None:
        config = FilterConfig.from_cli_patterns(
            allow_patterns=["type:PTR,ip:192.168.1.0/24,txt:fn=*"],
            deny_patterns=[],
        )
        assert config.rules[0].match.record_type == "PTR"
        assert config.rules[0].match.src_ip == "192.168.1.0/24"
        assert config.rules[0].match.txt_contains == "fn=*"

    def test_invalid_pattern_format(self) -> None:
        with pytest.raises(ValueError, match="Invalid pattern format"):
            FilterConfig.from_cli_patterns(
                allow_patterns=["invalid-pattern"],
                deny_patterns=[],
            )

    def test_unknown_field(self) -> None:
        with pytest.raises(ValueError, match="Unknown filter field"):
            FilterConfig.from_cli_patterns(
                allow_patterns=["unknown_field:value"],
                deny_patterns=[],
            )

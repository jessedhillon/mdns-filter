"""Tests for mdns_filter.filter module."""

from __future__ import annotations

import ipaddress

import pytest

from mdns_filter.const import RecordType, FilterAction
from mdns_filter.filter import FilterEngine
from mdns_filter.mdns import DNSRecord, ParsedMDNSPacket
from mdns_filter.rules import FilterMatch, FilterRule, FilterConfig


class TestFilterEngineEvaluate:
    """Tests for FilterEngine.evaluate."""

    @pytest.fixture
    def googlecast_packet(self) -> ParsedMDNSPacket:
        """A Google Cast announcement packet."""
        return ParsedMDNSPacket(
            transaction_id=0,
            flags=0x8400,
            is_response=True,
            is_authoritative=True,
            is_truncated=False,
            answers=(
                DNSRecord(
                    name="_googlecast._tcp.local",
                    record_type=RecordType.PTR,
                    record_class=1,
                    instance="Google-Cast-abc123",
                    service="_googlecast._tcp",
                    domain="local",
                ),
            ),
            src_ip=ipaddress.IPv4Address("192.168.1.100"),
        )

    @pytest.fixture
    def wiim_packet(self) -> ParsedMDNSPacket:
        """A WiiM device announcement packet."""
        return ParsedMDNSPacket(
            transaction_id=0,
            flags=0x8400,
            is_response=True,
            is_authoritative=True,
            is_truncated=False,
            answers=(
                DNSRecord(
                    name="_spotify-connect._tcp.local",
                    record_type=RecordType.PTR,
                    record_class=1,
                    instance="WiiM-Pro-xyz",
                    service="_spotify-connect._tcp",
                    domain="local",
                ),
            ),
            src_ip=ipaddress.IPv4Address("192.168.1.101"),
        )

    def test_empty_packet_uses_default(self) -> None:
        config = FilterConfig(default_action=FilterAction.Deny)
        engine = FilterEngine(config)

        packet = ParsedMDNSPacket(
            transaction_id=0,
            flags=0,
            is_response=False,
            is_authoritative=False,
            is_truncated=False,
        )

        action, rule_name = engine.evaluate(packet)
        assert action == FilterAction.Deny
        assert rule_name is None

    def test_no_rules_uses_default_allow(self, googlecast_packet: ParsedMDNSPacket) -> None:
        config = FilterConfig(default_action=FilterAction.Allow)
        engine = FilterEngine(config)

        action, rule_name = engine.evaluate(googlecast_packet)
        assert action == FilterAction.Allow
        assert rule_name is None

    def test_no_rules_uses_default_deny(self, googlecast_packet: ParsedMDNSPacket) -> None:
        config = FilterConfig(default_action=FilterAction.Deny)
        engine = FilterEngine(config)

        action, rule_name = engine.evaluate(googlecast_packet)
        assert action == FilterAction.Deny
        assert rule_name is None

    def test_matching_rule_returns_action(self, googlecast_packet: ParsedMDNSPacket) -> None:
        config = FilterConfig(
            default_action=FilterAction.Deny,
            rules=[
                FilterRule(
                    name="allow-googlecast",
                    match=FilterMatch(instance="Google-Cast-*"),
                    action=FilterAction.Allow,
                ),
            ],
        )
        engine = FilterEngine(config)

        action, rule_name = engine.evaluate(googlecast_packet)
        assert action == FilterAction.Allow
        assert rule_name == "allow-googlecast"

    def test_non_matching_rule_uses_default(self, wiim_packet: ParsedMDNSPacket) -> None:
        config = FilterConfig(
            default_action=FilterAction.Allow,
            rules=[
                FilterRule(
                    name="allow-googlecast",
                    match=FilterMatch(instance="Google-Cast-*"),
                    action=FilterAction.Allow,
                ),
            ],
        )
        engine = FilterEngine(config)

        action, rule_name = engine.evaluate(wiim_packet)
        assert action == FilterAction.Allow
        assert rule_name is None

    def test_first_match_wins(self, googlecast_packet: ParsedMDNSPacket) -> None:
        config = FilterConfig(
            default_action=FilterAction.Allow,
            rules=[
                FilterRule(
                    name="deny-all",
                    match=FilterMatch(instance="*"),
                    action=FilterAction.Deny,
                ),
                FilterRule(
                    name="allow-googlecast",
                    match=FilterMatch(instance="Google-Cast-*"),
                    action=FilterAction.Allow,
                ),
            ],
        )
        engine = FilterEngine(config)

        action, rule_name = engine.evaluate(googlecast_packet)
        assert action == FilterAction.Deny
        assert rule_name == "deny-all"

    def test_specific_before_general(self, googlecast_packet: ParsedMDNSPacket) -> None:
        config = FilterConfig(
            default_action=FilterAction.Deny,
            rules=[
                FilterRule(
                    name="allow-googlecast",
                    match=FilterMatch(instance="Google-Cast-*"),
                    action=FilterAction.Allow,
                ),
                FilterRule(
                    name="deny-all",
                    match=FilterMatch(instance="*"),
                    action=FilterAction.Deny,
                ),
            ],
        )
        engine = FilterEngine(config)

        action, rule_name = engine.evaluate(googlecast_packet)
        assert action == FilterAction.Allow
        assert rule_name == "allow-googlecast"

    def test_match_mode_any(self) -> None:
        """With match_mode=any, packet matches if any record matches."""
        packet = ParsedMDNSPacket(
            transaction_id=0,
            flags=0x8400,
            is_response=True,
            is_authoritative=True,
            is_truncated=False,
            answers=(
                DNSRecord(
                    name="rec1.local",
                    record_type=RecordType.PTR,
                    record_class=1,
                    instance="Match-Me",
                    service="_test._tcp",
                ),
                DNSRecord(
                    name="rec2.local",
                    record_type=RecordType.PTR,
                    record_class=1,
                    instance="No-Match",
                    service="_test._tcp",
                ),
            ),
            src_ip=ipaddress.IPv4Address("192.168.1.100"),
        )

        config = FilterConfig(
            default_action=FilterAction.Deny,
            rules=[
                FilterRule(
                    name="allow-match",
                    match=FilterMatch(instance="Match-Me"),
                    action=FilterAction.Allow,
                    match_mode="any",
                ),
            ],
        )
        engine = FilterEngine(config)

        action, rule_name = engine.evaluate(packet)
        assert action == FilterAction.Allow
        assert rule_name == "allow-match"

    def test_match_mode_all(self) -> None:
        """With match_mode=all, packet matches only if all records match."""
        packet = ParsedMDNSPacket(
            transaction_id=0,
            flags=0x8400,
            is_response=True,
            is_authoritative=True,
            is_truncated=False,
            answers=(
                DNSRecord(
                    name="rec1.local",
                    record_type=RecordType.PTR,
                    record_class=1,
                    instance="Match-Me",
                    service="_test._tcp",
                ),
                DNSRecord(
                    name="rec2.local",
                    record_type=RecordType.PTR,
                    record_class=1,
                    instance="No-Match",
                    service="_test._tcp",
                ),
            ),
            src_ip=ipaddress.IPv4Address("192.168.1.100"),
        )

        config = FilterConfig(
            default_action=FilterAction.Allow,
            rules=[
                FilterRule(
                    name="deny-if-all-match",
                    match=FilterMatch(instance="Match-Me"),
                    action=FilterAction.Deny,
                    match_mode="all",
                ),
            ],
        )
        engine = FilterEngine(config)

        # Should NOT match because not all records have instance="Match-Me"
        action, rule_name = engine.evaluate(packet)
        assert action == FilterAction.Allow
        assert rule_name is None

    def test_match_mode_all_succeeds(self) -> None:
        """With match_mode=all, packet matches when all records match."""
        packet = ParsedMDNSPacket(
            transaction_id=0,
            flags=0x8400,
            is_response=True,
            is_authoritative=True,
            is_truncated=False,
            answers=(
                DNSRecord(
                    name="rec1.local",
                    record_type=RecordType.PTR,
                    record_class=1,
                    instance="Match-Me-1",
                    service="_test._tcp",
                ),
                DNSRecord(
                    name="rec2.local",
                    record_type=RecordType.PTR,
                    record_class=1,
                    instance="Match-Me-2",
                    service="_test._tcp",
                ),
            ),
            src_ip=ipaddress.IPv4Address("192.168.1.100"),
        )

        config = FilterConfig(
            default_action=FilterAction.Allow,
            rules=[
                FilterRule(
                    name="deny-test-service",
                    match=FilterMatch(service="_test._tcp"),
                    action=FilterAction.Deny,
                    match_mode="all",
                ),
            ],
        )
        engine = FilterEngine(config)

        # Should match because all records have service="_test._tcp"
        action, rule_name = engine.evaluate(packet)
        assert action == FilterAction.Deny
        assert rule_name == "deny-test-service"

    def test_deny_specific_allow_rest(
        self, googlecast_packet: ParsedMDNSPacket, wiim_packet: ParsedMDNSPacket
    ) -> None:
        """Common pattern: deny specific devices, allow everything else."""
        config = FilterConfig(
            default_action=FilterAction.Allow,
            rules=[
                FilterRule(
                    name="deny-wiim",
                    match=FilterMatch(instance="WiiM-*"),
                    action=FilterAction.Deny,
                ),
            ],
        )
        engine = FilterEngine(config)

        # WiiM should be denied
        action, _ = engine.evaluate(wiim_packet)
        assert action == FilterAction.Deny

        # Google Cast should be allowed (default)
        action, _ = engine.evaluate(googlecast_packet)
        assert action == FilterAction.Allow

    def test_allow_specific_deny_rest(
        self, googlecast_packet: ParsedMDNSPacket, wiim_packet: ParsedMDNSPacket
    ) -> None:
        """Common pattern: allow specific devices, deny everything else."""
        config = FilterConfig(
            default_action=FilterAction.Deny,
            rules=[
                FilterRule(
                    name="allow-googlecast",
                    match=FilterMatch(instance="Google-Cast-*"),
                    action=FilterAction.Allow,
                ),
            ],
        )
        engine = FilterEngine(config)

        # Google Cast should be allowed
        action, _ = engine.evaluate(googlecast_packet)
        assert action == FilterAction.Allow

        # WiiM should be denied (default)
        action, _ = engine.evaluate(wiim_packet)
        assert action == FilterAction.Deny

"""Integration tests for end-to-end packet filtering."""

from __future__ import annotations

import ipaddress
import struct

from mdns_filter.const import RecordType, FilterAction, LogLevel
from mdns_filter.filter import FilterEngine
from mdns_filter.mdns import DNSRecord, ParsedMDNSPacket
from mdns_filter.parse import MDNSParser
from mdns_filter.rules import FilterMatch, FilterRule, FilterConfig


class TestPacketFilteringIntegration:
    """End-to-end tests for packet parsing and filtering."""

    def _build_mdns_response(
        self,
        instance: str,
        service: str,
        src_ip: str,
        record_type: int = RecordType.PTR,
    ) -> bytes:
        """Build a minimal mDNS response packet."""
        # Build the name: instance._service._tcp.local
        service_name, protocol = service.split(".")
        name_parts = [
            instance.encode(),
            service_name.encode(),
            protocol.encode(),
            b"local",
        ]
        name_bytes = b"".join(bytes([len(p)]) + p for p in name_parts) + b"\x00"

        # Header: response with authoritative flag
        header = struct.pack(
            "!HHHHHH",
            0,  # Transaction ID
            0x8400,  # Flags: response + authoritative
            0,  # Questions
            1,  # Answers
            0,  # Authority
            0,  # Additional
        )

        # Answer RR
        rdata = b"\x00"  # Minimal rdata
        answer = name_bytes + struct.pack("!HHIH", record_type, 1, 4500, len(rdata)) + rdata

        return header + answer

    def _build_mdns_query(self, service: str, src_ip: str) -> bytes:
        """Build a minimal mDNS query packet."""
        service_name, protocol = service.split(".")
        name_parts = [service_name.encode(), protocol.encode(), b"local"]
        name_bytes = b"".join(bytes([len(p)]) + p for p in name_parts) + b"\x00"

        header = struct.pack(
            "!HHHHHH",
            0,  # Transaction ID
            0,  # Flags: query
            1,  # Questions
            0,  # Answers
            0,  # Authority
            0,  # Additional
        )

        question = name_bytes + struct.pack("!HH", RecordType.PTR, 1)

        return header + question

    def test_allow_googlecast_deny_others(self) -> None:
        """Integration test: allow Google Cast, deny everything else."""
        config = FilterConfig(
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
        engine = FilterEngine(config)

        # Google Cast packet should be allowed
        googlecast_data = self._build_mdns_response(
            instance="Google-Cast-abc123",
            service="_googlecast._tcp",
            src_ip="192.168.1.100",
        )
        googlecast_packet = MDNSParser.parse(googlecast_data, ipaddress.IPv4Address("192.168.1.100"))
        assert googlecast_packet is not None

        action, rule_name = engine.evaluate(googlecast_packet)
        assert action == FilterAction.Allow
        assert rule_name == "allow-googlecast"

        # WiiM packet should be denied (default)
        wiim_data = self._build_mdns_response(
            instance="WiiM-Pro-xyz",
            service="_spotify-connect._tcp",
            src_ip="192.168.1.101",
        )
        wiim_packet = MDNSParser.parse(wiim_data, ipaddress.IPv4Address("192.168.1.101"))
        assert wiim_packet is not None

        action, rule_name = engine.evaluate(wiim_packet)
        assert action == FilterAction.Deny
        assert rule_name is None

    def test_deny_specific_allow_others(self) -> None:
        """Integration test: deny specific devices, allow everything else."""
        config = FilterConfig(
            default_action=FilterAction.Allow,
            rules=[
                FilterRule(
                    name="deny-wiim",
                    match=FilterMatch(instance="WiiM-*"),
                    action=FilterAction.Deny,
                ),
                FilterRule(
                    name="deny-roku",
                    match=FilterMatch(instance="Roku-*"),
                    action=FilterAction.Deny,
                ),
            ],
        )
        engine = FilterEngine(config)

        # WiiM should be denied
        wiim_data = self._build_mdns_response(
            instance="WiiM-Pro-xyz",
            service="_spotify-connect._tcp",
            src_ip="192.168.1.101",
        )
        wiim_packet = MDNSParser.parse(wiim_data, ipaddress.IPv4Address("192.168.1.101"))
        assert wiim_packet is not None

        action, rule_name = engine.evaluate(wiim_packet)
        assert action == FilterAction.Deny
        assert rule_name == "deny-wiim"

        # Roku should be denied
        roku_data = self._build_mdns_response(
            instance="Roku-abc",
            service="_airplay._tcp",
            src_ip="192.168.1.102",
        )
        roku_packet = MDNSParser.parse(roku_data, ipaddress.IPv4Address("192.168.1.102"))
        assert roku_packet is not None

        action, rule_name = engine.evaluate(roku_packet)
        assert action == FilterAction.Deny
        assert rule_name == "deny-roku"

        # Google Cast should be allowed (default)
        googlecast_data = self._build_mdns_response(
            instance="Google-Cast-abc123",
            service="_googlecast._tcp",
            src_ip="192.168.1.100",
        )
        googlecast_packet = MDNSParser.parse(googlecast_data, ipaddress.IPv4Address("192.168.1.100"))
        assert googlecast_packet is not None

        action, rule_name = engine.evaluate(googlecast_packet)
        assert action == FilterAction.Allow
        assert rule_name is None

    def test_service_based_filtering(self) -> None:
        """Integration test: filter by service type."""
        config = FilterConfig(
            default_action=FilterAction.Deny,
            rules=[
                FilterRule(
                    name="allow-airplay",
                    match=FilterMatch(service="_airplay._tcp"),
                    action=FilterAction.Allow,
                ),
                FilterRule(
                    name="allow-googlecast",
                    match=FilterMatch(service="_googlecast._tcp"),
                    action=FilterAction.Allow,
                ),
            ],
        )
        engine = FilterEngine(config)

        # AirPlay should be allowed
        airplay_data = self._build_mdns_response(
            instance="Apple-TV-abc",
            service="_airplay._tcp",
            src_ip="192.168.1.50",
        )
        airplay_packet = MDNSParser.parse(airplay_data, ipaddress.IPv4Address("192.168.1.50"))
        assert airplay_packet is not None

        action, _ = engine.evaluate(airplay_packet)
        assert action == FilterAction.Allow

        # Spotify Connect should be denied
        spotify_data = self._build_mdns_response(
            instance="Speaker-xyz",
            service="_spotify-connect._tcp",
            src_ip="192.168.1.60",
        )
        spotify_packet = MDNSParser.parse(spotify_data, ipaddress.IPv4Address("192.168.1.60"))
        assert spotify_packet is not None

        action, _ = engine.evaluate(spotify_packet)
        assert action == FilterAction.Deny

    def test_ip_based_filtering(self) -> None:
        """Integration test: filter by source IP."""
        config = FilterConfig(
            default_action=FilterAction.Deny,
            rules=[
                FilterRule(
                    name="allow-trusted-subnet",
                    match=FilterMatch(src_ip="192.168.1.0/24"),
                    action=FilterAction.Allow,
                ),
            ],
        )
        engine = FilterEngine(config)

        # Packet from trusted subnet should be allowed
        trusted_data = self._build_mdns_response(
            instance="Device-abc",
            service="_http._tcp",
            src_ip="192.168.1.50",
        )
        trusted_packet = MDNSParser.parse(trusted_data, ipaddress.IPv4Address("192.168.1.50"))
        assert trusted_packet is not None

        action, rule_name = engine.evaluate(trusted_packet)
        assert action == FilterAction.Allow
        assert rule_name == "allow-trusted-subnet"

        # Packet from other subnet should be denied
        untrusted_data = self._build_mdns_response(
            instance="Device-xyz",
            service="_http._tcp",
            src_ip="10.0.0.50",
        )
        untrusted_packet = MDNSParser.parse(untrusted_data, ipaddress.IPv4Address("10.0.0.50"))
        assert untrusted_packet is not None

        action, rule_name = engine.evaluate(untrusted_packet)
        assert action == FilterAction.Deny
        assert rule_name is None

    def test_query_vs_response_filtering(self) -> None:
        """Integration test: filter queries differently from responses."""
        config = FilterConfig(
            default_action=FilterAction.Allow,
            rules=[
                FilterRule(
                    name="deny-queries",
                    match=FilterMatch(is_query=True),
                    action=FilterAction.Deny,
                ),
            ],
        )
        engine = FilterEngine(config)

        # Query should be denied
        query_data = self._build_mdns_query(service="_googlecast._tcp", src_ip="192.168.1.50")
        query_packet = MDNSParser.parse(query_data, ipaddress.IPv4Address("192.168.1.50"))
        assert query_packet is not None
        assert query_packet.is_response is False

        action, rule_name = engine.evaluate(query_packet)
        assert action == FilterAction.Deny
        assert rule_name == "deny-queries"

        # Response should be allowed
        response_data = self._build_mdns_response(
            instance="Device-abc",
            service="_googlecast._tcp",
            src_ip="192.168.1.100",
        )
        response_packet = MDNSParser.parse(response_data, ipaddress.IPv4Address("192.168.1.100"))
        assert response_packet is not None
        assert response_packet.is_response is True

        action, rule_name = engine.evaluate(response_packet)
        assert action == FilterAction.Allow
        assert rule_name is None

    def test_combined_criteria_filtering(self) -> None:
        """Integration test: filter with multiple criteria combined."""
        config = FilterConfig(
            default_action=FilterAction.Deny,
            rules=[
                FilterRule(
                    name="allow-googlecast-from-trusted",
                    match=FilterMatch(
                        instance="Google-Cast-*",
                        src_ip="192.168.1.0/24",
                    ),
                    action=FilterAction.Allow,
                ),
            ],
        )
        engine = FilterEngine(config)

        # Google Cast from trusted subnet - allowed
        gc_trusted_data = self._build_mdns_response(
            instance="Google-Cast-abc",
            service="_googlecast._tcp",
            src_ip="192.168.1.100",
        )
        gc_trusted_packet = MDNSParser.parse(gc_trusted_data, ipaddress.IPv4Address("192.168.1.100"))
        assert gc_trusted_packet is not None

        action, _ = engine.evaluate(gc_trusted_packet)
        assert action == FilterAction.Allow

        # Google Cast from untrusted subnet - denied
        gc_untrusted_data = self._build_mdns_response(
            instance="Google-Cast-xyz",
            service="_googlecast._tcp",
            src_ip="10.0.0.100",
        )
        gc_untrusted_packet = MDNSParser.parse(gc_untrusted_data, ipaddress.IPv4Address("10.0.0.100"))
        assert gc_untrusted_packet is not None

        action, _ = engine.evaluate(gc_untrusted_packet)
        assert action == FilterAction.Deny

        # Non-Google Cast from trusted subnet - denied
        other_trusted_data = self._build_mdns_response(
            instance="WiiM-abc",
            service="_spotify._tcp",
            src_ip="192.168.1.101",
        )
        other_trusted_packet = MDNSParser.parse(other_trusted_data, ipaddress.IPv4Address("192.168.1.101"))
        assert other_trusted_packet is not None

        action, _ = engine.evaluate(other_trusted_packet)
        assert action == FilterAction.Deny

    def test_rule_order_matters(self) -> None:
        """Integration test: verify first-match-wins behavior."""
        # Rules: deny all Cast, then allow Google Cast - deny should win
        config_deny_first = FilterConfig(
            default_action=FilterAction.Allow,
            rules=[
                FilterRule(
                    name="deny-all-cast",
                    match=FilterMatch(instance="*-Cast-*"),
                    action=FilterAction.Deny,
                ),
                FilterRule(
                    name="allow-googlecast",
                    match=FilterMatch(instance="Google-Cast-*"),
                    action=FilterAction.Allow,
                ),
            ],
        )
        engine_deny_first = FilterEngine(config_deny_first)

        # Rules reversed: allow Google Cast, then deny all Cast - allow should win
        config_allow_first = FilterConfig(
            default_action=FilterAction.Deny,
            rules=[
                FilterRule(
                    name="allow-googlecast",
                    match=FilterMatch(instance="Google-Cast-*"),
                    action=FilterAction.Allow,
                ),
                FilterRule(
                    name="deny-all-cast",
                    match=FilterMatch(instance="*-Cast-*"),
                    action=FilterAction.Deny,
                ),
            ],
        )
        engine_allow_first = FilterEngine(config_allow_first)

        # Same packet
        gc_data = self._build_mdns_response(
            instance="Google-Cast-abc",
            service="_googlecast._tcp",
            src_ip="192.168.1.100",
        )
        gc_packet = MDNSParser.parse(gc_data, ipaddress.IPv4Address("192.168.1.100"))
        assert gc_packet is not None

        # With deny-first config, should be denied
        action, rule_name = engine_deny_first.evaluate(gc_packet)
        assert action == FilterAction.Deny
        assert rule_name == "deny-all-cast"

        # With allow-first config, should be allowed
        action, rule_name = engine_allow_first.evaluate(gc_packet)
        assert action == FilterAction.Allow
        assert rule_name == "allow-googlecast"

    def test_empty_rules_uses_default(self) -> None:
        """Integration test: no rules configured, uses default action."""
        config_allow = FilterConfig(default_action=FilterAction.Allow, rules=[])
        config_deny = FilterConfig(default_action=FilterAction.Deny, rules=[])

        engine_allow = FilterEngine(config_allow)
        engine_deny = FilterEngine(config_deny)

        data = self._build_mdns_response(
            instance="Any-Device",
            service="_http._tcp",
            src_ip="192.168.1.50",
        )
        packet = MDNSParser.parse(data, ipaddress.IPv4Address("192.168.1.50"))
        assert packet is not None

        action, rule_name = engine_allow.evaluate(packet)
        assert action == FilterAction.Allow
        assert rule_name is None

        action, rule_name = engine_deny.evaluate(packet)
        assert action == FilterAction.Deny
        assert rule_name is None


class TestCliPatternIntegration:
    """Integration tests for CLI pattern parsing to filtering."""

    def test_cli_pattern_to_filter_config(self) -> None:
        """Test that CLI patterns create working filter configs."""
        config = FilterConfig.from_cli_patterns(
            allow_patterns=["instance:Google-Cast-*", "service:_airplay._tcp"],
            deny_patterns=["instance:WiiM-*"],
            default_deny=True,
        )

        engine = FilterEngine(config)

        # Verify rule structure
        assert config.default_action == FilterAction.Deny
        assert len(config.rules) == 3
        assert config.rules[0].action == FilterAction.Deny  # Deny rules first
        assert config.rules[1].action == FilterAction.Allow
        assert config.rules[2].action == FilterAction.Allow

        # Test with packets - build using models directly for clarity
        wiim_packet = ParsedMDNSPacket(
            transaction_id=0,
            flags=0x8400,
            is_response=True,
            is_authoritative=True,
            is_truncated=False,
            answers=(
                DNSRecord(
                    name="WiiM-Pro._spotify._tcp.local",
                    record_type=RecordType.PTR,
                    record_class=1,
                    instance="WiiM-Pro",
                    service="_spotify._tcp",
                    domain="local",
                ),
            ),
            src_ip=ipaddress.IPv4Address("192.168.1.101"),
        )

        action, _ = engine.evaluate(wiim_packet)
        assert action == FilterAction.Deny

        googlecast_packet = ParsedMDNSPacket(
            transaction_id=0,
            flags=0x8400,
            is_response=True,
            is_authoritative=True,
            is_truncated=False,
            answers=(
                DNSRecord(
                    name="Google-Cast-abc._googlecast._tcp.local",
                    record_type=RecordType.PTR,
                    record_class=1,
                    instance="Google-Cast-abc",
                    service="_googlecast._tcp",
                    domain="local",
                ),
            ),
            src_ip=ipaddress.IPv4Address("192.168.1.100"),
        )

        action, _ = engine.evaluate(googlecast_packet)
        assert action == FilterAction.Allow

    def test_compound_cli_pattern(self) -> None:
        """Test compound CLI patterns (multiple fields)."""
        config = FilterConfig.from_cli_patterns(
            allow_patterns=["instance:Google-Cast-*,service:_googlecast._tcp"],
            deny_patterns=[],
            default_deny=True,
        )

        engine = FilterEngine(config)

        # Google Cast with correct service - allowed
        gc_correct = ParsedMDNSPacket(
            transaction_id=0,
            flags=0x8400,
            is_response=True,
            is_authoritative=True,
            is_truncated=False,
            answers=(
                DNSRecord(
                    name="Google-Cast-abc._googlecast._tcp.local",
                    record_type=RecordType.PTR,
                    record_class=1,
                    instance="Google-Cast-abc",
                    service="_googlecast._tcp",
                    domain="local",
                ),
            ),
            src_ip=ipaddress.IPv4Address("192.168.1.100"),
        )

        action, _ = engine.evaluate(gc_correct)
        assert action == FilterAction.Allow

        # Google Cast with wrong service - denied (doesn't match compound rule)
        gc_wrong_service = ParsedMDNSPacket(
            transaction_id=0,
            flags=0x8400,
            is_response=True,
            is_authoritative=True,
            is_truncated=False,
            answers=(
                DNSRecord(
                    name="Google-Cast-abc._http._tcp.local",
                    record_type=RecordType.PTR,
                    record_class=1,
                    instance="Google-Cast-abc",
                    service="_http._tcp",
                    domain="local",
                ),
            ),
            src_ip=ipaddress.IPv4Address("192.168.1.100"),
        )

        action, _ = engine.evaluate(gc_wrong_service)
        assert action == FilterAction.Deny

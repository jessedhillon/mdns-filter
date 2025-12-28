"""Filter engine for evaluating packets against rules."""

from __future__ import annotations

import logging

from mdns_filter import const
from mdns_filter.const import FilterAction, LogLevel
from mdns_filter.mdns import ParsedMDNSPacket
from mdns_filter.rules import FilterConfig

logger = logging.getLogger(const.Package)


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
                matched = any(rule.match.matches_record(section, record, packet) for section, record in all_records)
            else:
                # Match only if all records match
                matched = all(rule.match.matches_record(section, record, packet) for section, record in all_records)

            if matched:
                # Log if configured
                if rule.log == LogLevel.Debug:
                    logger.debug(
                        "Rule '%s' matched: %s (src=%s)",
                        rule.name,
                        rule.action.value,
                        packet.src_ip,
                    )
                elif rule.log == LogLevel.Info:
                    logger.info(
                        "Rule '%s' matched: %s (src=%s)",
                        rule.name,
                        rule.action.value,
                        packet.src_ip,
                    )

                return rule.action, rule.name

        # No rule matched - use default action
        return self.config.default_action, None

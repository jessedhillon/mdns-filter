#!/usr/bin/env python3
"""
mdns-filter - mDNS repeater with content-based filtering

CLI entry point.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
import yaml

from mdns_filter import const
from mdns_filter.const import FilterAction
from mdns_filter.util import ClickPath
from mdns_filter.repeater import MDNSRepeater, RepeaterConfig
from mdns_filter.rules import FilterConfig


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
@click.version_option(version="2.0.0", prog_name=const.Package)
def main(
    interfaces: tuple[str, ...],
    dry_run: bool,
    filter_config: Path | None,
    filter_allow_patterns: tuple[str, ...],
    filter_deny_patterns: tuple[str, ...],
    default_deny: bool,
) -> None:
    """
    mDNS repeater - repeats mDNS packets between network interfaces.

    INTERFACES: Network interfaces to bridge (minimum 2 required).

    Packets received on one interface are repeated to all other specified
    interfaces, enabling mDNS discovery across network segments.
    """
    # Validate interface count
    if len(interfaces) < 2:
        raise click.UsageError("At least 2 interfaces must be specified.")

    # Build filter configuration
    if filter_config is not None:
        # Load from file
        if filter_allow_patterns or filter_deny_patterns:
            raise click.UsageError("Cannot use --filter-config with --filter-allow or --filter-deny.")
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
        fc = FilterConfig(default_action=FilterAction.Deny if default_deny else FilterAction.Allow)

    # Build config
    try:
        config = RepeaterConfig(
            interfaces=list(interfaces),
            dry_run=dry_run,
            filter_config=fc,
        )
    except Exception as err:
        raise click.UsageError(f"Configuration error: {err}") from err

    # Run the repeater
    repeater = MDNSRepeater(config)
    sys.exit(repeater.run())


main()

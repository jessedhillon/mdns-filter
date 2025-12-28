"""CLI integration tests for mdns-filter."""

from __future__ import annotations

import tempfile

from click.testing import CliRunner

from mdns_filter.__main__ import main


class TestCliHelp:
    """Tests for CLI help and version."""

    def test_help_option(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "mDNS repeater" in result.output
        assert "--dry-run" in result.output
        assert "--filter-config" in result.output
        assert "--filter-allow" in result.output
        assert "--filter-deny" in result.output
        assert "--default-deny" in result.output

    def test_short_help_option(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["-h"])
        assert result.exit_code == 0
        assert "mDNS repeater" in result.output

    def test_version_option(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "mdns-filter" in result.output
        assert "2.0.0" in result.output


class TestCliValidation:
    """Tests for CLI argument validation."""

    def test_no_interfaces_error(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, [])
        assert result.exit_code != 0
        assert "Missing argument" in result.output or "required" in result.output.lower()

    def test_single_interface_error(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["eth0"])
        assert result.exit_code != 0
        assert "At least 2 interfaces" in result.output

    def test_filter_config_mutual_exclusivity_allow(self) -> None:
        runner = CliRunner()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
            fh.write("default_action: allow\nrules: []\n")
            fh.flush()
            result = runner.invoke(
                main,
                ["eth0", "wlan0", "--filter-config", fh.name, "--filter-allow", "instance:Test"],
            )
        assert result.exit_code != 0
        assert "Cannot use --filter-config with --filter-allow" in result.output

    def test_filter_config_mutual_exclusivity_deny(self) -> None:
        runner = CliRunner()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
            fh.write("default_action: allow\nrules: []\n")
            fh.flush()
            result = runner.invoke(
                main,
                ["eth0", "wlan0", "--filter-config", fh.name, "--filter-deny", "instance:Test"],
            )
        assert result.exit_code != 0
        assert "Cannot use --filter-config with" in result.output

    def test_filter_config_file_not_found(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["eth0", "wlan0", "--filter-config", "/nonexistent/path.yaml"])
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_invalid_filter_pattern_format(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["eth0", "wlan0", "--filter-allow", "invalid-pattern"])
        assert result.exit_code != 0
        assert "Invalid" in result.output

    def test_unknown_filter_field(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["eth0", "wlan0", "--filter-allow", "unknown_field:value"])
        assert result.exit_code != 0
        assert "Unknown filter field" in result.output


class TestCliFilterPatterns:
    """Tests for CLI filter pattern parsing."""

    def test_valid_allow_pattern(self) -> None:
        runner = CliRunner()
        # This will fail at socket creation, but we can check it parses the pattern
        result = runner.invoke(main, ["eth0", "wlan0", "--filter-allow", "instance:Google-Cast-*", "--dry-run"])
        # Should fail at socket creation, not at pattern parsing
        assert "Invalid filter pattern" not in result.output
        assert "Unknown filter field" not in result.output

    def test_valid_deny_pattern(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["eth0", "wlan0", "--filter-deny", "instance:WiiM-*", "--dry-run"])
        assert "Invalid filter pattern" not in result.output
        assert "Unknown filter field" not in result.output

    def test_multiple_patterns(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "eth0",
                "wlan0",
                "--filter-allow",
                "instance:Google-Cast-*",
                "--filter-allow",
                "service:_googlecast._tcp",
                "--filter-deny",
                "instance:WiiM-*",
                "--dry-run",
            ],
        )
        assert "Invalid filter pattern" not in result.output

    def test_compound_pattern(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["eth0", "wlan0", "--filter-allow", "instance:Device,service:_http._tcp,type:PTR", "--dry-run"],
        )
        assert "Invalid filter pattern" not in result.output

    def test_ip_pattern(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["eth0", "wlan0", "--filter-allow", "ip:192.168.1.0/24", "--dry-run"])
        assert "Invalid filter pattern" not in result.output

    def test_src_ip_pattern(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["eth0", "wlan0", "--filter-allow", "src_ip:10.0.0.0/8", "--dry-run"])
        assert "Invalid filter pattern" not in result.output

    def test_txt_pattern(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["eth0", "wlan0", "--filter-allow", "txt:fn=Living*", "--dry-run"])
        assert "Invalid filter pattern" not in result.output


class TestCliFilterConfig:
    """Tests for CLI YAML config loading."""

    def test_valid_yaml_config(self) -> None:
        yaml_content = """
default_action: deny
rules:
  - name: allow-googlecast
    match:
      instance: "Google-Cast-*"
    action: allow
"""
        runner = CliRunner()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
            fh.write(yaml_content)
            fh.flush()
            result = runner.invoke(main, ["eth0", "wlan0", "--filter-config", fh.name, "--dry-run"])
        # Should fail at socket creation, not config parsing
        assert "Invalid YAML" not in result.output
        assert "Error loading filter config" not in result.output

    def test_invalid_yaml_config(self) -> None:
        yaml_content = """
default_action: deny
rules:
  - name: missing-required-fields
"""
        runner = CliRunner()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
            fh.write(yaml_content)
            fh.flush()
            result = runner.invoke(main, ["eth0", "wlan0", "--filter-config", fh.name])
        assert result.exit_code != 0
        assert "Error loading filter config" in result.output

    def test_malformed_yaml(self) -> None:
        yaml_content = """
default_action: deny
rules:
  - name: test
    match
      instance: "Test"  # Missing colon after match
"""
        runner = CliRunner()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
            fh.write(yaml_content)
            fh.flush()
            result = runner.invoke(main, ["eth0", "wlan0", "--filter-config", fh.name])
        assert result.exit_code != 0
        assert "Invalid YAML" in result.output


class TestCliDefaultDeny:
    """Tests for --default-deny flag."""

    def test_default_deny_alone(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["eth0", "wlan0", "--default-deny", "--dry-run"])
        # Should proceed to socket creation (and fail there)
        assert "Invalid" not in result.output

    def test_default_deny_with_allow(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["eth0", "wlan0", "--filter-allow", "instance:Google-Cast-*", "--default-deny", "--dry-run"],
        )
        assert "Invalid" not in result.output


class TestCliDryRun:
    """Tests for --dry-run flag."""

    def test_dry_run_short_option(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["eth0", "wlan0", "-n"])
        # Should proceed to socket creation
        assert "Invalid" not in result.output

    def test_dry_run_long_option(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["eth0", "wlan0", "--dry-run"])
        assert "Invalid" not in result.output

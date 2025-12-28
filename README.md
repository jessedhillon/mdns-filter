# mdns-filter

A mDNS (multicast DNS) repeater daemon with advanced content-based filtering. Bridges mDNS traffic between network interfaces, enabling service discovery across network segments while providing fine-grained control over which services are advertised.

This is a Python rewrite and enhancement of [the original C implementation by Darell Tan](https://github.com/geekman/mdns-repeater/), extended with sophisticated rule-based filtering that can match on mDNS packet contents rather than just IP addresses.

## Features

- Repeat mDNS packets between multiple network interfaces
- Content-based filtering with support for:
  - Source IP matching (CIDR notation)
  - Service type, instance name, and DNS name matching
  - Record type filtering (A, AAAA, PTR, SRV, TXT, etc.)
  - Record section filtering (question, answer, authority, additional)
  - TXT record content matching
  - Query vs response filtering
- Pattern matching with glob, regex, and negation support
- YAML configuration files for complex rule sets
- CLI options for simple filtering scenarios
- Daemonization with PID file management
- Privilege dropping for security
- Dry-run mode for testing configurations

## Requirements

- Python 3.13+
- Linux (uses `SO_BINDTODEVICE` and ioctl for interface management)
- Root privileges or `CAP_NET_RAW` capability (required for `SO_BINDTODEVICE` to bind sockets to specific interfaces)

## Installation

### Using Poetry

```bash
poetry install
```

### Using Nix

```bash
nix develop
```

## Usage

### Basic Usage

Bridge mDNS traffic between two or more interfaces:

```bash
mdns-filter eth0 wlan0
```

### Foreground Mode

Run in foreground for debugging (logs to stderr instead of syslog):

```bash
mdns-filter -f eth0 wlan0
```

### Dry Run

Test your configuration without actually forwarding packets:

```bash
mdns-filter --dry-run -f eth0 wlan0 --filter-config filters.yaml
```

### With Content Filtering

Allow only Chromecast devices, deny everything else:

```bash
mdns-filter eth0 wlan0 \
  --filter-allow 'instance:Google-Cast-*' \
  --default-deny
```

### With YAML Configuration

```bash
mdns-filter eth0 wlan0 --filter-config /etc/mdns-filter/filters.yaml
```

### Legacy IP Filtering

Simple IP-based filtering (blacklist or whitelist, mutually exclusive):

```bash
# Blacklist a subnet
mdns-filter -b 192.168.1.0/24 eth0 wlan0

# Whitelist a subnet
mdns-filter -w 192.168.5.0/24 eth0 wlan0
```

## CLI Reference

```
Usage: mdns-filter [OPTIONS] INTERFACES...

  mDNS filtering repeater daemon with content-based filtering.

Arguments:
  INTERFACES  Network interfaces to bridge (minimum 2 required)

Options:
  -f, --foreground          Run in foreground (don't daemonize)
  -n, --dry-run             Log decisions without forwarding packets
  -p, --pid-file PATH       PID file path [default: /var/run/mdns-filter.pid]
  -u, --user TEXT           Drop privileges to this user after binding sockets
  -b, --blacklist CIDR      Legacy IP blacklist (can be specified multiple times)
  -w, --whitelist CIDR      Legacy IP whitelist (can be specified multiple times)
  --filter-config PATH      Path to YAML filter configuration file
  --filter-allow PATTERN    Allow pattern (can be specified multiple times)
  --filter-deny PATTERN     Deny pattern (can be specified multiple times)
  --default-deny            Deny packets by default (instead of allow)
  --help                    Show this message and exit
```

## Configuration

### YAML Configuration File

The YAML configuration file provides the most flexibility for defining filter rules.

```yaml
# Default action when no rules match: "allow" or "deny"
default_action: allow

rules:
  # Rules are evaluated in order; first match wins

  - name: deny-iot-subnet
    match:
      src_ip: "192.168.10.0/24"
    action: deny

  - name: allow-chromecasts
    match:
      instance: "Google-Cast-*"
    action: allow
    log: info  # Log when this rule matches

  - name: allow-airplay
    match:
      service: "_airplay._tcp"
    action: allow

  - name: deny-printers
    match:
      service: "_ipp._tcp"
    action: deny

  - name: allow-homekit
    match:
      service: "_hap._tcp"
      txt_contains: "md=*Bridge*"
    match_mode: all  # Both conditions must match
    action: allow
```

### Filter Rule Structure

Each rule in the `rules` list has the following structure:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique identifier for the rule (used in logging) |
| `match` | object | Yes | Matching criteria (see below) |
| `action` | string | Yes | Action to take: `allow` or `deny` |
| `match_mode` | string | No | How to match records: `any` (default) or `all` |
| `log` | string | No | Log level when rule matches: `none`, `debug`, or `info` |

### Match Criteria

The `match` object supports the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `src_ip` | string | Source IP address in CIDR notation (e.g., `192.168.1.0/24`) |
| `is_query` | boolean | Match query packets (`true`) or response packets (`false`) |
| `is_authoritative` | boolean | Match authoritative responses |
| `service` | string/list | Service type (e.g., `_googlecast._tcp`, `_airplay._tcp`) |
| `instance` | string/list | Service instance name (e.g., `Living Room TV`) |
| `name` | string/list | Full DNS name |
| `record_type` | string/list | Record type: `A`, `AAAA`, `PTR`, `SRV`, `TXT`, `ANY`, `NSEC` |
| `section` | string/list | Packet section: `question`, `answer`, `authority`, `additional` |
| `txt_contains` | string/list | Match against TXT record key-value content |

### Pattern Matching Syntax

String fields support multiple matching modes:

| Pattern | Description | Example |
|---------|-------------|---------|
| `exact` | Case-insensitive exact match | `Living Room TV` |
| `glob*` | Glob pattern with `*` and `?` wildcards | `Google-Cast-*` |
| `/regex/` | Regular expression (enclosed in `/`) | `/^.*-[0-9]+$/` |
| `!pattern` | Negation (matches if pattern does NOT match) | `!_printer._tcp` |

### Match Modes

- **`any`** (default): The rule matches if at least one record in the packet matches all specified criteria.
- **`all`**: The rule matches only if all records in the packet match the criteria.

### CLI Filter Patterns

When using `--filter-allow` or `--filter-deny`, patterns use the format `field:pattern`:

```bash
# Match by instance name
--filter-allow 'instance:Google-Cast-*'

# Match by service type
--filter-deny 'service:_ipp._tcp'

# Match by source IP
--filter-allow 'src_ip:192.168.5.0/24'

# Match by TXT record content
--filter-allow 'txt_contains:md=*Sonos*'
```

Multiple patterns can be combined:

```bash
mdns-filter eth0 wlan0 \
  --filter-allow 'service:_googlecast._tcp' \
  --filter-allow 'service:_airplay._tcp' \
  --filter-deny 'src_ip:192.168.10.0/24' \
  --default-deny
```

## Examples

### Allow Only Smart Home Devices

```yaml
default_action: deny

rules:
  - name: allow-homekit
    match:
      service: "_hap._tcp"
    action: allow

  - name: allow-airplay
    match:
      service: "_airplay._tcp"
    action: allow

  - name: allow-googlecast
    match:
      service: "_googlecast._tcp"
    action: allow

  - name: allow-spotify-connect
    match:
      service: "_spotify-connect._tcp"
    action: allow
```

### Isolate IoT Network

```yaml
default_action: allow

rules:
  # Deny all mDNS from IoT VLAN
  - name: deny-iot-vlan
    match:
      src_ip: "192.168.100.0/24"
    action: deny
    log: debug

  # Except for specific trusted devices
  - name: allow-trusted-iot
    match:
      src_ip: "192.168.100.10/32"
    action: allow
```

### Debug Mode

Run with verbose logging to see all packet decisions:

```bash
mdns-filter -f --dry-run eth0 wlan0 --filter-config filters.yaml
```

This will log each packet received, the filter rule that matched (if any), and the resulting action without actually forwarding any packets.

## How It Works

1. **Socket Setup**: Creates a UDP socket bound to the mDNS multicast address (224.0.0.251:5353) and joins the multicast group on all specified interfaces.

2. **Packet Reception**: Receives mDNS packets on the multicast socket and determines the source interface based on the sender's IP address.

3. **Packet Parsing**: Fully parses the DNS packet structure including:
   - Header flags (query/response, authoritative, truncated)
   - Question records
   - Answer records
   - Authority records
   - Additional records
   - Compressed name pointers

4. **Filter Evaluation**: Evaluates the parsed packet against configured filter rules in order. The first matching rule determines the action.

5. **Forwarding**: If allowed, forwards the packet to all interfaces except the source interface.

## Daemonization

By default, `mdns-filter` daemonizes (forks to background) and:
- Writes its PID to `/var/run/mdns-filter.pid` (configurable with `-p`)
- Logs to syslog
- Handles SIGTERM and SIGINT for graceful shutdown

Use `-f` to run in foreground for debugging or when managed by a process supervisor.

## Systemd Service

The recommended way to run mdns-filter in production is as a systemd service. This example uses `DynamicUser` to create a transient unprivileged user at runtime, and grants only the required `CAP_NET_RAW` capability.

Create `/etc/systemd/system/mdns-filter.service`:

```ini
[Unit]
Description=mDNS Repeater
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/mdns-filter -f eth0 wlan0 --filter-config /etc/mdns-filter/filters.yaml

# Security: run as a transient unprivileged user
DynamicUser=yes

# Grant only the capability needed for SO_BINDTODEVICE
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW

# Additional hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes

# Allow reading the filter config
ConfigurationDirectory=mdns-filter

# Restart on failure
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Install and start:

```bash
# Copy filter configuration
sudo mkdir -p /etc/mdns-filter
sudo cp filters.yaml /etc/mdns-filter/

# If using Poetry/venv, create a wrapper script or adjust ExecStart path
# For example, with a Poetry-managed install:
# ExecStart=/opt/mdns-filter/.venv/bin/python -m mdns_filter -f eth0 wlan0

# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable mdns-filter
sudo systemctl start mdns-filter

# Check status
sudo systemctl status mdns-filter
sudo journalctl -u mdns-filter -f
```

Note: When using `DynamicUser`, the `-u` flag is not needed since systemd handles user management. The `-f` (foreground) flag is required since systemd manages the process lifecycle.

## Security

- **Privilege Dropping**: Use `-u username` to drop privileges after binding sockets. The daemon will switch to the specified user while retaining the ability to send/receive on already-bound sockets.

- **Network Segmentation**: Content-based filtering enables fine-grained control over which services are visible across network segments, useful for isolating IoT devices or guest networks.

## License

See LICENSE file for details.

## Credits

Based on the [original mdns-repeater by Darell Tan](https://github.com/geekman/mdns-repeater/), with content-based filtering extensions.

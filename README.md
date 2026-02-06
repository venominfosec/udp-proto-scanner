# udp-proto-scanner

UDP service discovery by sending **protocol-specific UDP probes** and reporting targets that reply.

This is a Python 3 port/modernization of the original `udp-proto-scanner.pl` by Mark Lowe (Portcullis). The probe payloads are primarily sourced from tools like `nmap`, `amap`, and `ike-scan`.

## What this tool is (and isn’t)

- **What it does**: sends known UDP probe payloads (DNS, NTP, TFTP, RPC, etc.) to targets and logs any replies.
- **What it doesn’t do**: it is **not** a general UDP port scanner. It won’t enumerate open/closed ports; it’s focused on *discovering specific UDP services* that answer to specific probes.

This is useful during host/service discovery in pentests, especially when targets are heavily firewalled and only expose UDP services.

## Quick start

### Setup

This script uses **only the Python standard library** (no pip dependencies).

1. Clone this repository

```bash
git clone https://github.com/venominfosec/udp-proto-scanner.git
cd udp-proto-scanner
```

### Run

List available probes:

```bash
python udp-proto-scanner.py --list
```

Scan a CIDR with a single probe:

```bash
python udp-proto-scanner.py --probe ntp 10.0.0.0/16
```

Scan targets from a file:

```bash
python udp-proto-scanner.py --probe DNSStatusRequest --file ips.txt
```

Write deduplicated `ip:port` results to disk:

```bash
python udp-proto-scanner.py --probe NTPRequest 127.0.0.1 --output results.txt
```

## Targets input

You can provide targets in either of two ways:

- **`--file`**: one target per line
- **positional `targets`**: provide IPs, hostnames, and/or CIDRs directly on the command line

Each target can be:

- **IPv4 address**: `192.168.1.10`
- **hostname**: `dns01.corp.local` (resolved once per run; cached)
- **CIDR**: `10.0.0.0/16` (expanded to all addresses in that range)

## Probes

Probe definitions are **embedded inside** `udp-proto-scanner.py`. Use `--list` to see the available probe names, and `--probe` to select one or more:

```bash
python udp-proto-scanner.py --probe ntp --probe DNSStatusRequest 10.0.0.0/16
```

If `--probe` is omitted, the tool uses **all probes**.

### Optional external probe config

You can override the embedded probes with `--configfile <path>`. The format is whitespace-separated:

```
<port> <probe_name> <hex_payload>
```

If the file cannot be opened, the tool will also try `/etc/udp-proto-scanner.conf`.

## Output

### Console logging

The tool logs progress and replies in a timestamped format. Replies look like:

```
YYYY-mm-dd HH:MM:SS    [INFO]    Received reply to probe NTPRequest (target port 123) from 192.0.2.10:123: <hex_response>
```

### `--output` file

When `--output <file>` is set, the tool writes **deduplicated** reply endpoints in `ip:port` format (one per line), based on the *source IP/port* of received UDP replies:

```
192.0.2.10:123
198.51.100.5:53
```

### Quiet mode

Use `--quiet` to suppress non-essential progress logs. In quiet mode:

- Reply lines are still printed
- Warnings and errors are still printed
- Startup/progress chatter is suppressed

## Common options

- **`--probe`**: repeatable; choose specific probes (or omit to run all)
- **`--list`**: list probe names and exit
- **`--file`**: read targets from file
- **`--bandwidth`**: cap sending rate (bits/sec). Accepts suffixes `K/M/G` (e.g. `250k`, `1.5M`)
- **`--retries`**: number of probe packets sent per host, per probe type
- **`--output`**: write deduplicated `ip:port` results to a file
- **`--quiet`**: only show replies + warnings/errors
- **`--debug`**: print JSON of parsed CLI args immediately after startup (helpful for troubleshooting)

Run `python udp-proto-scanner.py --help` for the full, argparse-native help output and examples.

## Notes on reliability and limitations

- Some UDP services will not respond unless you already know valid credentials/parameters (e.g., many SNMP configurations).
- A reply indicates “something responded” to the probe; it does not necessarily imply a complete service fingerprint.
- The tool is most efficient on larger target sets. Very small target sets can appear slower due to per-host pacing and retry scheduling.

## Supported probes

The following probe/service types are currently embedded. (Duplicate probe variants for the same service are listed only once.)

| Port | Service |
|---:|---|
| 7 | echo |
| 11 | systat |
| 13 | daytime |
| 19 | chargen |
| 37 | time |
| 53 | dns |
| 69 | tftp |
| 111 | rpc |
| 123 | ntp |
| 137 | nbt |
| 161 | snmp |
| 177 | xdmcp |
| 500 | ike |
| 523 | db2 |
| 1604 | citrix |
| 1434 | ms-sql |
| 2123 | gtpv1 |
| 5405 | net-support |
| 6502 | netop |

## Legal

Use for **authorized** testing only. You are responsible for ensuring you have permission to scan the target networks.

## Credits

- Original concept and implementation: **Mark Lowe** (Portcullis)
- Probe payload sources/inspiration: **`nmap`**, **`amap`**, **`ike-scan`**

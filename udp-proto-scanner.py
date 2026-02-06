#!/usr/bin/env python3
"""
udp-proto-scanner - UDP Service Discovery Tool (Python 3 port)

Original Perl version:
Copyright (C) 2008 Mark Lowe

This port aims to preserve the original tool's CLI and behavior as closely as
possible while running on Python 3.

GPLv2 (or later) applies; see header in original source.
"""

from __future__ import annotations

import argparse
import heapq
import ipaddress
import logging
import json
import math
import socket
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple


VERSION = "2.0"
DEFAULT_BANDWIDTH = "250k"
DEFAULT_MAX_PROBES = 3
PACKET_OVERHEAD_BYTES = 28  # 20 bytes IP header + 8 bytes UDP header

EMBEDDED_PROBE_CONFIG = r"""
# from ike-scan
500	ike	5b5e64c03e99b51100000000000000000110020000000000000001500000013400000001000000010000012801010008030000240101

# These are some probes from amap 5.2
111	rpc	039b65420000000000000002000f4243000000000000000000000000000000000000000000000000
123	ntp	cb0004fa000100000001000000000000000000000000000000000000000000000000000000000000bfbe7099cdb34000
161	snmp-public	3082002f02010004067075626c6963a082002002044c33a756020100020100308200103082000c06082b060102010105000500
1434	ms-sql	02
1434	ms-sql-slam	0A
6502	netop	d6818152000000f3874e01023200a8c000000113c1d904dd037d00000d005448435448435448435448435448432020202020202020202020202020202020023200a8c00000000000000000000000000000000000000000000000000000000000000000000000000000000000
69	tftp	00012f6574632f706173737764006e6574617363696900
523	db2	444232474554414444520053514c3038303230
1604	citrix	1e00013002fda8e300000000000000000000000000000000000000000000

# small services
7	echo	313233
19	chargen	313233
11	systat	313233
13	daytime	313233
37	time	313233

# These are from nmap
111	RPCCheck	72FE1D130000000000000002000186A00001977C0000000000000000000000000000000000000000
53	DNSStatusRequest	000010000000000000000000
53	DNSVersionBindReq	0006010000010000000000000776657273696f6e0462696e640000100003
137	NBTStat	80f00010000100000000000020434b4141414141414141414141414141414141414141414141414141414141410000210001
123	NTPRequest	e30004fa000100000001000000000000000000000000000000000000000000000000000000000000c54f234b71b152f3
161	SNMPv3GetRequest	303a020103300f02024a69020300ffe30401040201030410300e0400020100020100040004000400301204000400a00c020237f00201000201003000
177	xdmcp	0001000200010000

# misc
5405    net-support     01000000000000000000000000000000000080000000000000000000000000000000000000
2123	gtpv1	320100040000000050000000
""".lstrip("\n")


def setup_logging() -> tuple[logging.Logger, logging.Logger]:
    """
    Configure logging in-script (standalone).

    Matches the original config style:
    - All logs go to stdout, timestamped.
    """
    # Keep "WARN" instead of "WARNING".
    logging._levelToName[logging.WARNING] = "WARN"  # type: ignore[attr-defined]

    status_formatter = logging.Formatter(
        "%(asctime)s\t[%(levelname)s]    %(message)s", "%Y-%m-%d %H:%M:%S"
    )
    status_handler = logging.StreamHandler(sys.stdout)
    status_handler.setFormatter(status_formatter)

    logger = logging.getLogger("udp-proto-scanner")
    logger.handlers.clear()
    logger.propagate = False
    logger.addHandler(status_handler)
    logger.setLevel(logging.INFO)

    # Kept for backwards-compat with earlier refactor; route results through logger.
    return logger, logger


logger, results_logger = setup_logging()


def parse_bandwidth_bits(value: str) -> float:
    """
    Parse bandwidth expressed as bits/second.

    Matches the original Perl behavior:
    - pure number => bits
    - number + single-letter suffix => B/K/M/G with 1000 multipliers (K/M/G)
      (B means "bits" and is treated as 1x)
    Examples: "250k", "100000", "1.5M"
    """
    v = value.strip()
    if not v:
        raise ValueError("empty bandwidth")

    # Pure integer (bits/sec)
    if v.isdigit():
        return float(int(v))

    # number + suffix
    suffix = v[-1]
    num = v[:-1]
    try:
        n = float(num)
    except ValueError as e:
        raise ValueError(f"illegal bandwidth specification: {value}") from e

    s = suffix.upper()
    if s == "B":
        mult = 1.0
    elif s == "K":
        mult = 1000.0
    elif s == "M":
        mult = 1_000_000.0
    elif s == "G":
        mult = 1_000_000_000.0
    else:
        raise ValueError(f"illegal bandwidth specification: {value}")

    return n * mult


def string_to_hex(data: bytes) -> str:
    return data.hex()


def parse_probe_config_text(text: str) -> Dict[str, Dict[str, str]]:
    probes: Dict[str, Dict[str, str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        # Accept TAB or whitespace-separated fields.
        parts = line.split(None, 2)
        if len(parts) != 3:
            continue
        port_s, name, payload_hex = parts
        if not port_s.isdigit():
            continue
        payload_hex = payload_hex.strip()
        if not payload_hex or any(c not in "0123456789abcdefABCDEF" for c in payload_hex):
            continue
        probes[name] = {"port": port_s, "payload": payload_hex.lower()}
    return probes


def load_probe_config(config_file: Optional[str]) -> Tuple[str, Dict[str, Dict[str, str]]]:
    """
    Return (config_path_used, probes).

    probes[name] = {"port": "<int>", "payload": "<lowercase hex>"}
    """
    # Default: embedded config (per request).
    if not config_file:
        return "<embedded>", parse_probe_config_text(EMBEDDED_PROBE_CONFIG)

    # Optional override: external file (for customization).
    tried: List[str] = []
    for candidate in (config_file, "/etc/udp-proto-scanner.conf"):
        tried.append(candidate)
        try:
            with open(candidate, "r", encoding="utf-8", errors="replace") as fh:
                return candidate, parse_probe_config_text(fh.read())
        except OSError:
            continue

    raise FileNotFoundError(f"Can't open config file {tried[0]} or /etc/udp-proto-scanner.conf.")


def hex_payload_to_bytes(payload_hex: str) -> bytes:
    return bytes.fromhex(payload_hex)


_RESOLVE_CACHE: Dict[str, Optional[str]] = {}


def resolve_to_ipv4(name_or_ip: str) -> Optional[str]:
    """
    Resolve hostnames to IPv4 (Perl uses gethostbyname + inet_ntoa).
    If it's already an IP, return it unchanged.
    """
    s = name_or_ip.strip()
    if not s:
        return None

    if s in _RESOLVE_CACHE:
        return _RESOLVE_CACHE[s]

    try:
        ipaddress.ip_address(s)
        _RESOLVE_CACHE[s] = s
        return s
    except ValueError:
        pass

    try:
        ip = socket.gethostbyname(s)
        _RESOLVE_CACHE[s] = ip
        return ip
    except OSError:
        logger.warning("%s doesn't resolve", s)
        _RESOLVE_CACHE[s] = None
        return None


def iter_ips_from_token(token: str, resolve_names: bool = True) -> Iterator[str]:
    t = token.strip()
    if not t:
        return

    if "/" in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            # Fall back to hostname handling if it wasn't a valid CIDR.
            if resolve_names:
                ip = resolve_to_ipv4(t)
                if ip is not None:
                    yield ip
            else:
                yield t
            return

        # Match Net::Netmask behavior: include all addresses (network+broadcast too).
        for ip in net:
            yield str(ip)
        return

    if resolve_names:
        ip = resolve_to_ipv4(t)
        if ip is not None:
            yield ip
    else:
        yield t


class TargetSource:
    def __init__(self, *, resolve_names: bool = True):
        self._resolve_names = resolve_names

    def __iter__(self) -> Iterator[str]:
        raise NotImplementedError


class FileTargetSource(TargetSource):
    def __init__(self, path: str, *, resolve_names: bool = True):
        super().__init__(resolve_names=resolve_names)
        self._path = path

    def __iter__(self) -> Iterator[str]:
        try:
            with open(self._path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    s = line.strip()
                    if not s:
                        continue
                    s = s.replace("\r", "").replace("\n", "")
                    for ip in iter_ips_from_token(s, resolve_names=self._resolve_names):
                        yield ip
        except OSError as e:
            raise RuntimeError(f"Cannot open file {self._path}: {e}") from e


class ListTargetSource(TargetSource):
    def __init__(self, targets: List[str], *, resolve_names: bool = True):
        super().__init__(resolve_names=resolve_names)
        self._targets = targets

    def __iter__(self) -> Iterator[str]:
        for t in self._targets:
            for ip in iter_ips_from_token(t, resolve_names=self._resolve_names):
                yield ip


class ResultCollector:
    """
    Collect deduplicated ip:port endpoints (first-seen order).
    """

    def __init__(self) -> None:
        self._seen: set[str] = set()
        self._ordered: list[str] = []

    def add(self, ip: str, port: int) -> None:
        key = f"{ip}:{port}"
        if key in self._seen:
            return
        self._seen.add(key)
        self._ordered.append(key)

    def write(self, path: str) -> None:
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            for item in self._ordered:
                fh.write(item)
                fh.write("\n")


class QuietFilter(logging.Filter):
    """
    In quiet mode, suppress non-essential INFO logs.

    Allowed:
    - WARNING/ERROR/CRITICAL
    - Reply lines marked with extra={"is_reply": True}
    """

    def filter(self, record: logging.LogRecord) -> bool:  # type: ignore[override]
        if record.levelno >= logging.WARNING:
            return True
        return bool(getattr(record, "is_reply", False))


def enable_quiet_logging(log: logging.Logger) -> None:
    qf = QuietFilter()
    for h in log.handlers:
        h.addFilter(qf)


@dataclass(slots=True)
class HostState:
    ip: str
    probes_sent: int = 0
    next_probe_time: float = 0.0
    active: bool = True


class UDPScanner:
    def __init__(self, *, log: logging.Logger, results: ResultCollector) -> None:
        self._log = log
        self._results = results
        self.bandwidth_bits: float = parse_bandwidth_bits("32k")
        self.bandwidth_bytes: float = self.bandwidth_bits / 8.0
        self.max_probes: int = DEFAULT_MAX_PROBES
        self.inter_packet_interval_per_host: float = 0.5
        self.inter_packet_interval: float = 1.0
        self.backoff: float = 1.5
        self.bytes_sent: float = 0.0
        self.host_count: int = 0  # active host states
        self.rtt: float = 1.0
        self.resolve_names: bool = True

        # Target buffering: keep a bounded "active window" of hosts instead of
        # preloading huge lists (the original Perl used 100k high-water marks).
        self.max_active_hosts: int = 2048
        self.low_water_hosts: int = 512
        self._target_count_hint: Optional[int] = None

        self._delays: List[float] = []
        self._recalc_delay()

        self._payload: Optional[bytes] = None
        self._payload_name: Optional[str] = None
        self._target_port: Optional[int] = None
        self._packet_size_bytes: int = 0

        self._targets_iter: Optional[Iterator[str]] = None
        self._heap: List[Tuple[float, int, HostState]] = []
        self._seq: int = 0

        # Allow duplicates (Perl can scan same IP multiple times if present).
        self._states_by_ip: Dict[str, List[HostState]] = {}

    def get_target_count_hint(self) -> Optional[int]:
        return self._target_count_hint

    def _recalc_delay(self) -> None:
        self._delays = []
        for i in range(0, self.max_probes + 1):
            self._delays.append(self.inter_packet_interval_per_host * (self.backoff**i))

    def _recalc_active_window(self) -> None:
        """
        Choose an active-host window that's large enough to keep the sender busy.

        Roughly, we need ~inter_packet_interval_per_host / inter_packet_interval distinct
        hosts to avoid idling due to per-host pacing.
        """
        ipi = max(self.inter_packet_interval, 1e-6)
        needed = int(math.ceil(self.inter_packet_interval_per_host / ipi))
        # Safety margin to account for jitter and backoff.
        target = max(256, min(8192, needed * 2))
        self.max_active_hosts = target
        self.low_water_hosts = max(64, target // 2)

    def add_payload(self, name: str, payload: bytes, port: int) -> None:
        self._payload_name = name
        self._payload = payload
        self._target_port = int(port)
        self._packet_size_bytes = len(payload) + PACKET_OVERHEAD_BYTES

        # Match Perl: inter_packet_interval is min over payload sizes (only one here).
        self.set_bandwidth(self.bandwidth_bits)
        candidate = self._packet_size_bytes / max(self.bandwidth_bytes, 1e-9)
        if candidate < self.inter_packet_interval:
            self.inter_packet_interval = candidate
        self._recalc_active_window()

    def set_bandwidth(self, bandwidth: str | float) -> None:
        if isinstance(bandwidth, str):
            bits = parse_bandwidth_bits(bandwidth)
        else:
            bits = float(bandwidth)

        self.bandwidth_bits = bits
        if self.bandwidth_bits > 1_000_000:
            logger.warning("Scanning at over 1000000 bits/sec is unreliable")
        self.bandwidth_bytes = self.bandwidth_bits / 8.0
        self._recalc_active_window()

    def set_max_probes(self, max_probes: int) -> None:
        self.max_probes = int(max_probes)
        self._recalc_delay()

    def add_target_ips_from_file(self, file_path: str) -> None:
        self._targets_iter = iter(FileTargetSource(file_path, resolve_names=self.resolve_names))
        self._target_count_hint = None
        self._fill_hosts()

    def add_target_ips_from_list(self, targets: List[str]) -> None:
        self._targets_iter = iter(ListTargetSource(targets, resolve_names=self.resolve_names))
        # Best-effort count hint (fast for CIDRs; assumes 1 for hostnames/IPs).
        hint = 0
        for t in targets:
            s = t.strip()
            if not s:
                continue
            if "/" in s:
                try:
                    hint += ipaddress.ip_network(s, strict=False).num_addresses
                    continue
                except ValueError:
                    pass
            hint += 1
        self._target_count_hint = hint
        self._fill_hosts()

    def get_host_count(self) -> int:
        return self.host_count

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _add_host_state(self, ip: str) -> None:
        st = HostState(ip=ip, probes_sent=0, next_probe_time=0.0, active=True)
        heapq.heappush(self._heap, (st.next_probe_time, self._next_seq(), st))
        self._states_by_ip.setdefault(ip, []).append(st)
        self.host_count += 1

    def _fill_hosts(self) -> None:
        if self._targets_iter is None:
            return
        while self.host_count < self.max_active_hosts:
            try:
                ip = next(self._targets_iter)
            except StopIteration:
                self._targets_iter = None
                break
            if ip is None:
                continue
            self._add_host_state(ip)

    def _pop_active_state_for_ip(self, ip: str) -> Optional[HostState]:
        lst = self._states_by_ip.get(ip)
        if not lst:
            return None

        # The list is small unless duplicates were provided.
        while lst and not lst[0].active:
            lst.pop(0)
        if not lst:
            del self._states_by_ip[ip]
            return None

        st = lst.pop(0)
        if not lst:
            del self._states_by_ip[ip]
        return st

    def _deactivate_state(self, st: HostState) -> None:
        if not st.active:
            return
        st.active = False
        self.host_count -= 1

    def _recv_replies(self, sock: socket.socket) -> None:
        # Match Perl: keep reading until socket is empty.
        while True:
            try:
                data, (ip, port) = sock.recvfrom(10000)
            except BlockingIOError:
                return
            except OSError:
                return

            # Remove one matching active state if present (duplicates allowed).
            st = self._pop_active_state_for_ip(ip)
            if st is not None:
                self._deactivate_state(st)

            # Match original output style.
            name = self._payload_name or "unknown"
            sport = self._target_port or 0
            self._results.add(ip, int(port))
            self._log.info(
                "Received reply to probe %s (target port %s) from %s:%s: %s",
                name,
                sport,
                ip,
                port,
                string_to_hex(data),
                extra={"is_reply": True},
            )

    def start_scan(self) -> None:
        if self._payload is None or self._target_port is None:
            raise RuntimeError("Payload and target port must be set before scanning.")

        # Bind to a random-ish local port (Perl chooses random 1024..65535).
        # Python: bind to 0 to let OS select; this is the most portable option.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.bind(("0.0.0.0", 0))

        scan_start = time.monotonic()
        self.bytes_sent = 0.0

        # Main loop: continue while we still have active hosts or more targets to load.
        while True:
            # Refill if we're running low.
            if self.host_count < self.low_water_hosts:
                self._fill_hosts()

            if self.host_count == 0 and self._targets_iter is None:
                break

            now = time.monotonic()
            allowed_bytes = (now - scan_start) * self.bandwidth_bytes

            # Send as many packets as bandwidth budget allows.
            while allowed_bytes > self.bytes_sent:
                # Ensure we have something to send.
                if self.host_count == 0:
                    self._fill_hosts()
                    if self.host_count == 0 and self._targets_iter is None:
                        break
                    if self.host_count == 0:
                        # No active hosts yet, allow loop to progress.
                        break

                # Pop next scheduled host; ignore stale/inactive entries.
                st: Optional[HostState] = None
                due: float = 0.0
                while self._heap:
                    due, _, cand = heapq.heappop(self._heap)
                    if not cand.active:
                        continue
                    if due != cand.next_probe_time:
                        continue
                    st = cand
                    break

                if st is None:
                    # Heap exhausted; try refilling once.
                    self._fill_hosts()
                    if not self._heap and (self.host_count == 0 and self._targets_iter is None):
                        break
                    # Give receive a chance and then loop.
                    self._recv_replies(sock)
                    break

                now = time.monotonic()
                if due > now:
                    # Not yet time for this host; push back and stop trying for now.
                    heapq.heappush(self._heap, (due, self._next_seq(), st))
                    break

                # Send probe.
                try:
                    sock.sendto(self._payload, (st.ip, self._target_port))
                except OSError:
                    # Ignore send errors and treat as "no response".
                    pass

                self.bytes_sent += float(self._packet_size_bytes)

                # Schedule next probe time or mark as complete (max retries).
                old_sent = st.probes_sent
                delay = self._delays[min(old_sent, len(self._delays) - 1)]
                st.probes_sent += 1
                if st.probes_sent >= self.max_probes:
                    self._deactivate_state(st)
                else:
                    st.next_probe_time = time.monotonic() + delay
                    heapq.heappush(self._heap, (st.next_probe_time, self._next_seq(), st))

                # Receive replies opportunistically (mirrors Perl's frequent recv).
                self._recv_replies(sock)

                now = time.monotonic()
                allowed_bytes = (now - scan_start) * self.bandwidth_bytes

            # After we stop sending, receive any queued replies.
            self._recv_replies(sock)

            # If we have no active hosts but can still load more, loop to fill/send.
            if self.host_count == 0 and self._targets_iter is not None:
                continue

            if self.host_count == 0 and self._targets_iter is None:
                break

            # Sleep similarly to Perl's big wait:
            # max(inter_packet_interval, time until next scheduled probe).
            next_due = None
            while self._heap:
                due, _, cand = self._heap[0]
                if not cand.active or due != cand.next_probe_time:
                    heapq.heappop(self._heap)
                    continue
                next_due = due
                break

            now = time.monotonic()
            due_in = 0.0 if next_due is None else max(0.0, next_due - now)
            big_wait = max(self.inter_packet_interval, due_in)
            if big_wait > 0:
                time.sleep(big_wait)

        # Match Perl: wait for RTT after last packet, then recv.
        time.sleep(self.rtt)
        self._recv_replies(sock)


def build_arg_parser(prog: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=prog,
        description=(
            "UDP service discovery via protocol-specific UDP probes.\n\n"
            "This is not a general-purpose UDP port scanner: it sends known probe payloads and\n"
            "reports targets that reply."
        ),
        epilog=(
            "Examples:\n"
            f"  {prog} --list\n"
            f"  {prog} --probe ntp 10.0.0.0/16\n"
            f"  {prog} --probe DNSStatusRequest --file ips.txt\n"
            f"  {prog} --probe NTPRequest 127.0.0.1 --output results.txt\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "-f",
        "--file",
        dest="file",
        help="File containing targets (one per line). Each line may be an IP, hostname, or CIDR.",
    )
    p.add_argument(
        "-p",
        "--probe",
        dest="probes",
        action="append",
        help=(
            "Probe name to use (repeatable). Use 'all' to run all probes (default). "
            "Use --list to see available probe names."
        ),
    )
    p.add_argument(
        "-l",
        "--list",
        dest="list_probes",
        action="store_true",
        help="List all available probe names and exit.",
    )
    p.add_argument(
        "-b",
        "--bandwidth",
        dest="bandwidth",
        default=DEFAULT_BANDWIDTH,
        help="Bandwidth cap in bits/sec. Supports suffixes K/M/G (e.g. 250k, 1.5M).",
    )
    p.add_argument(
        "-c",
        "--configfile",
        dest="configfile",
        help=(
            "Optional external probe config file override. If set, the tool reads probes from that file; "
            "if it cannot be opened, it will also try /etc/udp-proto-scanner.conf. "
            "If omitted, the embedded probe config is used."
        ),
    )
    p.add_argument(
        "-r",
        "--retries",
        dest="retries",
        type=int,
        default=DEFAULT_MAX_PROBES,
        help="Number of probe packets to send per host, per probe type.",
    )
    p.add_argument("--debug", dest="debug", action="store_true", help="Enable debug output")
    p.add_argument(
        "-o",
        "--output",
        dest="output",
        help="Write deduplicated ip:port reply endpoints to this file (one per line).",
    )
    p.add_argument(
        "-q",
        "--quiet",
        dest="quiet",
        action="store_true",
        help="Suppress startup/progress logs; only show replies and warnings/errors.",
    )
    p.add_argument(
        "targets",
        nargs="*",
        help="Targets to scan (IPs, hostnames, and/or CIDRs). Ignored if --file is provided.",
    )
    return p


def main(argv: List[str]) -> int:
    prog = Path(argv[0]).name if argv else "udp-proto-scanner.py"

    parser = build_arg_parser(prog)
    args = parser.parse_args(argv[1:])

    # Apply quiet filtering for scan runs (but don't suppress --list output).
    if args.quiet and not args.list_probes:
        enable_quiet_logging(logger)

    logger.info("Starting udp-proto-scanner v%s", VERSION)
    if args.debug:
        logger.info("%s", json.dumps(vars(args), sort_keys=True))

    try:
        config_used, probes = load_probe_config(args.configfile)
    except FileNotFoundError as e:
        logger.error("%s", str(e))
        return 1

    if args.list_probes:
        names = sorted(probes.keys())
        logger.info(
            "The following probe names (--probe argument) are available from the config source %s:",
            config_used,
        )
        for n in names:
            logger.info("* %s", n)
        return 0

    requested = args.probes or ["all"]
    if any(p == "all" for p in requested):
        probes_to_use = sorted(probes.keys())
    else:
        # Preserve order, drop duplicates.
        seen: set[str] = set()
        probes_to_use = []
        for p in requested:
            if p in seen:
                continue
            seen.add(p)
            probes_to_use.append(p)

        missing = [p for p in probes_to_use if p not in probes]
        if missing:
            logger.error("Probe name(s) %s not in config source %s", ",".join(missing), config_used)
            return 1

    if not args.file:
        if not args.targets:
            parser.error("Supply some hosts to scan. Provide targets or use --file.")

    results = ResultCollector()
    for name in probes_to_use:
        scanner = UDPScanner(log=logger, results=results)
        scanner.add_payload(name, hex_payload_to_bytes(probes[name]["payload"]), int(probes[name]["port"]))
        scanner.set_bandwidth(args.bandwidth)
        scanner.set_max_probes(args.retries)

        if args.file:
            scanner.add_target_ips_from_file(args.file)
        else:
            scanner.add_target_ips_from_list(list(args.targets))

        hint = scanner.get_target_count_hint()
        if hint is None:
            logger.info("Sending %s probes", name)
        else:
            logger.info("Sending %s probes to %s hosts", name, hint)
        scanner.start_scan()

    logger.info("Scan complete at %s", time.ctime())
    if args.output:
        try:
            results.write(args.output)
            logger.info("Wrote %d unique results to %s", len(results._ordered), args.output)
        except OSError as e:
            logger.error("Failed to write output file %s: %s", args.output, e)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))


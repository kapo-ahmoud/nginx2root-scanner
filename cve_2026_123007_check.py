#!/usr/bin/env python3
"""Automatic, bounded HTTP/2 accounting probe.

Usage:
    python cve_2026_123007_check.py HOSTNAME

The tool automatically tries HTTPS on port 443 and cleartext HTTP/2 on port
80. It uses one connection per attempt and writes JSON evidence automatically.

The test is defensive: it does not attempt code execution, authentication
bypass, or data modification. A POSSIBLE_OVER_CREDIT result is evidence for
the tested accounting hypothesis, not independent proof of a CVE.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
MAX_WINDOW = 0x7FFFFFFF
INITIAL_WINDOW = 65535
PING_COUNT = 8000
FOLLOW_UP_UPDATES = ((0, 1), (0, 1), (0, 1), (0, 1))
TIMEOUT_SECONDS = 8.0

DATA = 0x0
HEADERS = 0x1
RST_STREAM = 0x3
SETTINGS = 0x4
PING = 0x6
GOAWAY = 0x7
WINDOW_UPDATE = 0x8

END_STREAM = 0x1
END_HEADERS = 0x4
ACK = 0x1
FLOW_CONTROL_ERROR = 0x3
CANCEL = 0x8

FRAME_NAMES = {
    DATA: "DATA",
    HEADERS: "HEADERS",
    RST_STREAM: "RST_STREAM",
    SETTINGS: "SETTINGS",
    PING: "PING",
    GOAWAY: "GOAWAY",
    WINDOW_UPDATE: "WINDOW_UPDATE",
}


class ProbeError(RuntimeError):
    """A bounded probe failure or incomplete observation."""


@dataclass
class Event:
    direction: str
    kind: str
    flags: int
    stream_id: int
    length: int
    detail: str = ""


@dataclass
class Evidence:
    schema_version: int = 2
    cve_hypothesis: str = "CVE-2026-123007"
    result: str = "INCONCLUSIVE"
    reason: str = ""
    host: str = ""
    port: int = 0
    transport: str = ""
    trace_stream: int = 3
    ping_count: int = PING_COUNT
    follow_up_updates: tuple[tuple[int, int], ...] = FOLLOW_UP_UPDATES
    final_ping_acknowledged: bool = False
    classification: str = "Inconclusive"
    summary_reason: str = ""
    elapsed_seconds: float = 0.0
    events: list[Event] = field(default_factory=list)


def hpack_integer(value: int, prefix_bits: int, prefix_mask: int = 0) -> bytes:
    if value < 0:
        raise ValueError("HPACK integers cannot be negative")
    limit = (1 << prefix_bits) - 1
    if value < limit:
        return bytes((prefix_mask | value,))
    out = bytearray((prefix_mask | limit,))
    value -= limit
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def hpack_indexed_name(index: int, value: str) -> bytes:
    raw = value.encode("ascii")
    return hpack_integer(index, 4) + hpack_integer(len(raw), 7) + raw


def hpack_literal_name(name: str, value: str) -> bytes:
    name_raw = name.encode("ascii")
    value_raw = value.encode("ascii")
    return (
        hpack_integer(0, 4)
        + hpack_integer(len(name_raw), 7)
        + name_raw
        + hpack_integer(len(value_raw), 7)
        + value_raw
    )


def get_headers(authority: str, path: str, scheme: str, method: str = "GET") -> bytes:
    """Build a minimal HPACK request header block."""
    block = bytearray()
    if method == "GET":
        block += b"\x82"  # static :method GET
    else:
        block += hpack_indexed_name(2, method)  # literal :method name, no indexing
    block += b"\x86" if scheme == "http" else b"\x87"  # :scheme
    block += hpack_indexed_name(1, authority)  # :authority
    block += hpack_indexed_name(4, path)  # :path
    return bytes(block)


def frame(kind: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    if not 0 <= stream_id <= MAX_WINDOW:
        raise ValueError("invalid HTTP/2 stream identifier")
    if len(payload) > 0xFFFFFF:
        raise ValueError("HTTP/2 frame payload is too large")
    return (
        len(payload).to_bytes(3, "big")
        + bytes((kind, flags))
        + (stream_id & MAX_WINDOW).to_bytes(4, "big")
        + payload
    )


def settings_initial_window() -> bytes:
    return frame(SETTINGS, 0, 0, b"\x00\x04" + INITIAL_WINDOW.to_bytes(4, "big"))


def window_update(stream_id: int, increment: int) -> bytes:
    if not 1 <= increment <= MAX_WINDOW:
        raise ValueError("WINDOW_UPDATE increment must be 1..2^31-1")
    return frame(WINDOW_UPDATE, 0, stream_id, increment.to_bytes(4, "big"))


def parse_frames(buffer: bytearray, incoming: bytes) -> list[tuple[int, int, int, bytes]]:
    buffer.extend(incoming)
    parsed: list[tuple[int, int, int, bytes]] = []
    while len(buffer) >= 9:
        length = int.from_bytes(buffer[:3], "big")
        if len(buffer) < 9 + length:
            break
        kind, flags = buffer[3], buffer[4]
        stream_id = int.from_bytes(buffer[5:9], "big") & MAX_WINDOW
        payload = bytes(buffer[9 : 9 + length])
        del buffer[: 9 + length]
        parsed.append((kind, flags, stream_id, payload))
    return parsed


def describe_event(direction: str, kind: int, flags: int, stream_id: int, payload: bytes) -> Event:
    detail = ""
    if kind == GOAWAY and len(payload) >= 8:
        detail = (
            f"last_stream={int.from_bytes(payload[:4], 'big') & MAX_WINDOW} "
            f"error_code={int.from_bytes(payload[4:8], 'big')}"
        )
    elif kind == RST_STREAM and len(payload) == 4:
        detail = f"error_code={int.from_bytes(payload, 'big')}"
    elif kind == WINDOW_UPDATE and len(payload) == 4:
        detail = f"increment={int.from_bytes(payload, 'big') & MAX_WINDOW}"
    return Event(direction, FRAME_NAMES.get(kind, f"FRAME_{kind}"), flags, stream_id, len(payload), detail)


class H2Connection:
    def __init__(self, sock: socket.socket, evidence: Evidence, timeout: float) -> None:
        self.sock = sock
        self.evidence = evidence
        self.timeout = timeout
        self.buffer = bytearray()

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def receive(self, duration: float) -> list[tuple[int, int, int, bytes]]:
        frames: list[tuple[int, int, int, bytes]] = []
        deadline = time.monotonic() + duration
        self.sock.settimeout(min(0.25, max(0.01, duration)))
        while time.monotonic() < deadline:
            try:
                data = self.sock.recv(262144)
            except socket.timeout:
                continue
            if not data:
                raise ProbeError("peer closed the TCP connection")
            for item in parse_frames(self.buffer, data):
                frames.append(item)
                self.evidence.events.append(describe_event("in", *item))
        return frames

    def wait_for_stream_end(self, stream_id: int, max_seconds: float) -> int:
        count = 0
        deadline = time.monotonic() + max_seconds
        while time.monotonic() < deadline:
            frames = self.receive(min(0.5, max(0.05, deadline - time.monotonic())))
            for kind, flags, sid, payload in frames:
                if kind == GOAWAY:
                    error = int.from_bytes(payload[4:8], "big") if len(payload) >= 8 else -1
                    raise ProbeError(f"server sent GOAWAY error_code={error}")
                if sid != stream_id:
                    continue
                if kind == DATA:
                    count += len(payload)
                if flags & END_STREAM:
                    return count
        raise ProbeError(f"timed out waiting for END_STREAM on stream {stream_id}")


def normalize_host(host: str) -> str:
    host = host.strip()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    if host.startswith("[") and "]" in host:
        host = host[1 : host.index("]")]
    return host


def authority(host: str, port: int) -> str:
    try:
        address = ipaddress.ip_address(host)
        return f"[{host}]:{port}" if address.version == 6 else f"{host}:{port}"
    except ValueError:
        return f"{host}:{port}"


def connect_target(host: str, port: int, tls: bool, evidence: Evidence) -> H2Connection:
    raw = socket.create_connection((host, port), timeout=TIMEOUT_SECONDS)
    raw.settimeout(TIMEOUT_SECONDS)
    if tls:
        context = ssl.create_default_context()
        context.set_alpn_protocols(["h2"])
        sock = context.wrap_socket(raw, server_hostname=host)
        if sock.selected_alpn_protocol() != "h2":
            sock.close()
            raise ProbeError("TLS completed without negotiating HTTP/2 via ALPN")
        evidence.transport = "h2-tls"
    else:
        sock = raw
        evidence.transport = "h2c"
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    except OSError:
        pass
    return H2Connection(sock, evidence, TIMEOUT_SECONDS)


def probe_once(host: str, port: int, tls: bool) -> Evidence:
    evidence = Evidence(host=host, port=port, transport="h2-tls" if tls else "h2c")
    started = time.monotonic()
    conn: H2Connection | None = None
    try:
        conn = connect_target(host, port, tls, evidence)
        auth = authority(host, port)
        conn.send(PREFACE + settings_initial_window())
        conn.receive(0.5)
        conn.send(frame(SETTINGS, ACK, 0))

        # Raise the peer's connection send window to the maximum legal value,
        # then open TRACE / on a second stream.
        conn.send(window_update(0, MAX_WINDOW - INITIAL_WINDOW))
        conn.send(
            frame(
                HEADERS,
                END_HEADERS | END_STREAM,
                evidence.trace_stream,
                get_headers(auth, "/", "https" if tls else "http", "TRACE"),
            )
        )

        # Send exactly 8,000 PING requests without reading their ACKs.
        for counter in range(PING_COUNT):
            conn.send(frame(PING, 0, 0, counter.to_bytes(8, "big")))

        # Follow-up window updates precede the final PING. These values are
        # explicit so the resulting evidence is reproducible.
        for stream_id, increment in FOLLOW_UP_UPDATES:
            conn.send(window_update(stream_id, increment))
        time.sleep(0.25)

        final_payload = b"FINAL123"
        conn.send(frame(PING, 0, 0, final_payload))

        try:
            post_probe = conn.receive(2.0)
        except ProbeError as exc:
            flow_control_goaway = any(
                event.kind == "GOAWAY" and "error_code=3" in event.detail
                for event in evidence.events
            )
            evidence.result = "PROTECTED" if flow_control_goaway else "PROTECTED_OR_CLOSED"
            evidence.reason = (
                "server sent GOAWAY FLOW_CONTROL_ERROR and then closed"
                if flow_control_goaway
                else str(exc)
            )
            return evidence

        goaways = [item for item in post_probe if item[0] == GOAWAY and len(item[3]) >= 8]
        if goaways:
            error = int.from_bytes(goaways[-1][3][4:8], "big")
            evidence.result = "PROTECTED" if error == FLOW_CONTROL_ERROR else "REJECTED_WITH_GOAWAY"
            evidence.reason = (
                "server rejected the post-cleanup probe with FLOW_CONTROL_ERROR"
                if error == FLOW_CONTROL_ERROR
                else f"server sent GOAWAY error_code={error}"
            )
            return evidence

        ping_payload = b"FINAL123"
        ping_ack = any(
            kind == PING and flags & ACK and sid == 0 and payload == ping_payload
            for kind, flags, sid, payload in post_probe
        )
        evidence.final_ping_acknowledged = ping_ack
        if ping_ack:
            evidence.result = "POSSIBLE_OVER_CREDIT"
            evidence.reason = (
                "final PING was acknowledged after 8,000 queued PING frames and follow-up connection-window updates; confirm the flow-control accounting in server logs/source"
            )
        else:
            evidence.reason = "final PING acknowledgement was not observed"
        return evidence
    except (OSError, ssl.SSLError, ProbeError, ValueError) as exc:
        evidence.reason = str(exc)
        return evidence
    finally:
        evidence.elapsed_seconds = round(time.monotonic() - started, 3)
        if conn is not None:
            try:
                conn.sock.close()
            except OSError:
                pass


def automatic_probe(host: str) -> Evidence:
    host = normalize_host(host)
    attempts: list[str] = []
    last = Evidence(host=host, reason="no automatic probe completed")
    for port, tls in ((443, True), (80, False)):
        attempt = probe_once(host, port, tls)
        attempts.append(f"{attempt.transport}:{port}={attempt.result}")
        if attempt.result in {"PROTECTED", "POSSIBLE_OVER_CREDIT", "REJECTED_WITH_GOAWAY", "PROTECTED_OR_CLOSED"}:
            attempt.reason = f"attempts: {', '.join(attempts)}; {attempt.reason}"
            return attempt
        last = attempt
    last.reason = (
        f"automatic connection flow-control checks did not produce a decisive final-PING result; "
        f"attempts: {', '.join(attempts)}"
    )
    return last


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="authorized hostname or IP address")
    return parser.parse_args(argv)


def evidence_path(host: str) -> Path:
    safe = "".join(ch if ch.isalnum() or ch in ".-_" else "_" for ch in host)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path(f"cve-2026-123007-{safe}-{stamp}.json")


def classify(evidence: Evidence) -> tuple[str, str, str]:
    """Return display label, ANSI color, and concise explanation."""
    if evidence.result == "POSSIBLE_OVER_CREDIT":
        return (
            "Vulnerable",
            "31",
            "The final PING was acknowledged after 8,000 queued PING frames and follow-up connection-window updates, indicating possible over-credit in flow-control accounting.",
        )
    if evidence.result == "PROTECTED":
        return (
            "Not Vulnerable",
            "32",
            "The server rejected the final probe with GOAWAY FLOW_CONTROL_ERROR.",
        )
    if evidence.result == "REJECTED_WITH_GOAWAY":
        return (
            "Not Vulnerable",
            "32",
            "The server rejected the final probe with GOAWAY.",
        )
    if evidence.result == "PROTECTED_OR_CLOSED":
        return (
            "Inconclusive",
            "33",
            "The connection closed before a decisive final response was observed.",
        )
    if evidence.reason.startswith("automatic"):
        reason = "The automatic HTTP/2 test did not complete decisively."
    elif evidence.reason:
        reason = evidence.reason.split(";", 1)[0].strip()
    else:
        reason = "The test did not produce a decisive result."
    return ("Inconclusive", "33", reason[:200])


def enable_windows_ansi() -> None:
    """Enable ANSI colors in supported Windows consoles."""
    if os.name != "nt":
        return
    try:
        import ctypes

        handle = ctypes.windll.kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint()
        if ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            ctypes.windll.kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def colored(text: str, color_code: str) -> str:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return text
    return f"\033[{color_code}m{text}\033[0m"


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    evidence = automatic_probe(args.host)
    label, color_code, summary = classify(evidence)
    evidence.classification = label
    evidence.summary_reason = summary
    output = evidence_path(normalize_host(args.host))
    output.write_text(json.dumps(asdict(evidence), indent=2) + "\n", encoding="utf-8")
    enable_windows_ansi()
    print(colored(label, color_code))
    print(f"Reason: {summary}")
    print(f"Host: {evidence.host}")
    print(f"Evidence written to: {output}")
    return {
        "PROTECTED": 0,
        "PROTECTED_OR_CLOSED": 0,
        "REJECTED_WITH_GOAWAY": 0,
        "POSSIBLE_OVER_CREDIT": 1,
        "INCONCLUSIVE": 2,
    }.get(evidence.result, 2)


if __name__ == "__main__":
    sys.exit(main())

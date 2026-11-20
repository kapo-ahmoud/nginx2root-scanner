#!/usr/bin/env python3
"""Bounded HTTP/2 accounting probe for the CVE-2026-123007 hypothesis.

This is a defensive verification tool.  It does not attempt code execution,
authentication bypass, or data modification.  The probe uses one connection,
one exact-size response fixture, and a bounded stream-pressure phase.  Run it
only against a host you are authorized to test.

Important: the CVE identifier and affected-version boundary are not encoded
as facts here.  A positive result means that the tested server accepted the
post-cleanup flow-control probe and remained alive; that is evidence for the
accounting hypothesis, not independent proof of a CVE.

Recommended fixture setup
-------------------------
Serve a static file whose response body is exactly 65,535 bytes at
--fill-path.  The exact-size fixture makes the connection-window transition
deterministic.  The large body at --body-path should be at least --body-bytes.

Examples
--------
  # TLS, certificate verification enabled:
  python3 cve_2026_123007_check.py \
      --host example.internal --port 443 --tls \
      --fill-path /fixtures/65535.bin --body-path /fixtures/8m.bin \
      --authorize-target "I-AUTHORIZE-THIS-HOST"

  # Re-run after remediation and save machine-readable evidence:
  python3 cve_2026_123007_check.py \
      --host example.internal --port 443 --tls \
      --fill-path /fixtures/65535.bin --body-path /fixtures/8m.bin \
      --authorize-target "I-AUTHORIZE-THIS-HOST" --json after.json

  # Cleartext HTTP/2 on a local lab target:
  python3 cve_2026_123007_check.py \
      --host 127.0.0.1 --port 80 --h2c \
      --fill-path /fixtures/65535.bin --body-path /fixtures/8m.bin \
      --authorize-target "I-AUTHORIZE-THIS-HOST"
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable


PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
MAX_WINDOW = 0x7FFFFFFF

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

NO_ERROR = 0x0
PROTOCOL_ERROR = 0x1
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
    """A bounded probe failure or an incomplete observation."""


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
    schema_version: int = 1
    cve_hypothesis: str = "CVE-2026-123007"
    result: str = "INCONCLUSIVE"
    reason: str = ""
    host: str = ""
    port: int = 0
    transport: str = ""
    fill_path: str = ""
    body_path: str = ""
    fill_bytes_expected: int = 65535
    fill_bytes_observed: int = 0
    body_credit: int = 0
    elapsed_seconds: float = 0.0
    events: list[Event] = field(default_factory=list)


def hpack_integer(value: int, prefix_bits: int, prefix_mask: int = 0) -> bytes:
    """Encode one HPACK integer."""
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
    """Literal header field without indexing, using a static name index."""
    raw = value.encode("ascii")
    return hpack_integer(index, 4) + hpack_integer(len(raw), 7) + raw


def hpack_literal_name(name: str, value: str) -> bytes:
    """Literal header field without indexing, including a literal name."""
    name_raw = name.encode("ascii")
    value_raw = value.encode("ascii")
    return (
        hpack_integer(0, 4)
        + hpack_integer(len(name_raw), 7)
        + name_raw
        + hpack_integer(len(value_raw), 7)
        + value_raw
    )


def get_headers(authority: str, path: str, scheme: str, byte_range: int | None) -> bytes:
    """Build a minimal HPACK header block for a GET request.

    Static-table indexes: :method GET=2, :scheme http=6, https=7,
    :authority=1, and :path=4.  ``range`` is encoded as a literal name;
    it is not a static-table index.
    """
    block = bytearray(b"\x82")
    block += b"\x86" if scheme == "http" else b"\x87"
    block += hpack_indexed_name(1, authority)
    block += hpack_indexed_name(4, path)
    if byte_range is not None:
        if byte_range <= 0:
            raise ValueError("byte_range must be positive")
        block += hpack_literal_name("range", f"bytes=0-{byte_range - 1}")
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


def settings_initial_window(value: int = 65535) -> bytes:
    return frame(SETTINGS, 0, 0, b"\x00\x04" + value.to_bytes(4, "big"))


def window_update(stream_id: int, increment: int) -> bytes:
    if not 1 <= increment <= MAX_WINDOW:
        raise ValueError("WINDOW_UPDATE increment must be 1..2^31-1")
    return frame(WINDOW_UPDATE, 0, stream_id, increment.to_bytes(4, "big"))


def parse_frames(buffer: bytearray, incoming: bytes) -> list[tuple[int, int, int, bytes]]:
    buffer.extend(incoming)
    parsed: list[tuple[int, int, int, bytes]] = []
    while len(buffer) >= 9:
        length = int.from_bytes(buffer[0:3], "big")
        if len(buffer) < 9 + length:
            break
        kind = buffer[3]
        flags = buffer[4]
        stream_id = int.from_bytes(buffer[5:9], "big") & MAX_WINDOW
        payload = bytes(buffer[9 : 9 + length])
        del buffer[: 9 + length]
        parsed.append((kind, flags, stream_id, payload))
    return parsed


def describe_event(direction: str, kind: int, flags: int, stream_id: int, payload: bytes) -> Event:
    detail = ""
    if kind == GOAWAY and len(payload) >= 8:
        last_stream = int.from_bytes(payload[:4], "big") & MAX_WINDOW
        error = int.from_bytes(payload[4:8], "big")
        detail = f"last_stream={last_stream} error_code={error}"
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
        """Read one response and return its DATA byte count."""
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


def is_loopback_host(host: str) -> bool:
    if host.lower() in {"localhost", "ip6-localhost"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    transport = parser.add_mutually_exclusive_group(required=True)
    transport.add_argument("--tls", action="store_true", help="HTTP/2 over TLS with ALPN")
    transport.add_argument("--h2c", action="store_true", help="cleartext HTTP/2")
    parser.add_argument("--server-name", help="TLS SNI/name; defaults to --host")
    parser.add_argument("--insecure-tls", action="store_true", help="disable TLS certificate verification")
    parser.add_argument("--fill-path", required=True, help="path whose response body is exactly --fill-bytes")
    parser.add_argument("--body-path", required=True, help="path for the bounded backpressure phase")
    parser.add_argument("--fill-bytes", type=int, default=65535)
    parser.add_argument("--body-bytes", type=int, default=8 * 1024 * 1024)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--authorize-target", required=True, help="must be I-AUTHORIZE-THIS-HOST")
    parser.add_argument("--allow-remote", action="store_true", help="required for non-loopback targets")
    parser.add_argument("--json", type=Path, help="write JSON evidence")
    args = parser.parse_args(argv)
    if args.authorize_target != "I-AUTHORIZE-THIS-HOST":
        parser.error("explicit target authorization is required")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be 1..65535")
    if args.fill_bytes != 65535:
        parser.error("--fill-bytes must remain 65535 for this accounting probe")
    if not 1 <= args.body_bytes <= 16 * 1024 * 1024:
        parser.error("--body-bytes must be 1..16777216")
    if not is_loopback_host(args.host) and not args.allow_remote:
        parser.error("non-loopback targets require --allow-remote")
    if args.insecure_tls and not args.tls:
        parser.error("--insecure-tls requires --tls")
    return args


def connect(args: argparse.Namespace, evidence: Evidence) -> H2Connection:
    raw = socket.create_connection((args.host, args.port), timeout=args.timeout)
    raw.settimeout(args.timeout)
    if args.tls:
        if args.insecure_tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        else:
            context = ssl.create_default_context()
        context.set_alpn_protocols(["h2"])
        sock = context.wrap_socket(raw, server_hostname=args.server_name or args.host)
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
    return H2Connection(sock, evidence, args.timeout)


def write_evidence(path: Path | None, evidence: Evidence) -> None:
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(evidence), indent=2) + "\n", encoding="utf-8")


def run(args: argparse.Namespace) -> Evidence:
    evidence = Evidence(
        host=args.host,
        port=args.port,
        fill_path=args.fill_path,
        body_path=args.body_path,
        fill_bytes_expected=args.fill_bytes,
        body_credit=args.body_bytes,
    )
    started = time.monotonic()
    conn: H2Connection | None = None
    try:
        conn = connect(args, evidence)
        authority = f"{args.host}:{args.port}"
        scheme = "https" if args.tls else "http"

        # Client preface and a normal initial-window SETTINGS frame.
        conn.send(PREFACE + settings_initial_window())
        conn.receive(0.5)
        conn.send(frame(SETTINGS, ACK, 0))

        # Stage 1: require an exact 65,535-byte DATA response, then replenish
        # the connection-level receive window to its maximum legal value.
        conn.send(
            frame(
                HEADERS,
                END_HEADERS | END_STREAM,
                1,
                get_headers(authority, args.fill_path, scheme, args.fill_bytes),
            )
        )
        fill_observed = conn.wait_for_stream_end(1, args.timeout)
        evidence.fill_bytes_observed = fill_observed
        if fill_observed != args.fill_bytes:
            evidence.reason = (
                f"fill fixture returned {fill_observed} DATA bytes; "
                f"expected exactly {args.fill_bytes}"
            )
            return evidence
        conn.send(window_update(0, MAX_WINDOW))
        conn.receive(0.5)

        # Stage 2: request a bounded large body and grant stream credit while
        # deliberately not reading for a short, fixed interval.  This can
        # create backpressure, but is capped at 16 MiB and one connection.
        conn.send(
            frame(
                HEADERS,
                END_HEADERS | END_STREAM,
                3,
                get_headers(authority, args.body_path, scheme, None),
            )
        )
        conn.send(window_update(3, args.body_bytes))
        time.sleep(min(1.5, args.timeout))

        # Stage 3: exercise the cleanup/refund boundary described by the
        # supplied hypothesis, then send a one-byte connection probe.
        conn.send(window_update(0, 4 * 1024 * 1024))
        conn.receive(0.25)
        conn.send(frame(RST_STREAM, 0, 3, CANCEL.to_bytes(4, "big")))
        conn.receive(0.5)
        conn.send(window_update(0, 1))

        try:
            post_probe = conn.receive(1.5)
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

        goaways = [
            item for item in post_probe
            if item[0] == GOAWAY and len(item[3]) >= 8
        ]
        if goaways:
            error = int.from_bytes(goaways[-1][3][4:8], "big")
            if error == FLOW_CONTROL_ERROR:
                evidence.result = "PROTECTED"
                evidence.reason = "server rejected the post-cleanup probe with FLOW_CONTROL_ERROR"
            else:
                evidence.result = "REJECTED_WITH_GOAWAY"
                evidence.reason = f"server sent GOAWAY error_code={error}"
            return evidence

        # A PING ACK is only a liveness observation.  It makes the result
        # reproducible, but is not itself proof of a flow-control underflow.
        ping_payload = b"CVE123007"
        conn.send(frame(PING, 0, 0, ping_payload))
        ping_frames = conn.receive(1.5)
        ping_ack = any(
            kind == PING and flags & ACK and sid == 0 and payload == ping_payload
            for kind, flags, sid, payload in ping_frames
        )
        if ping_ack:
            evidence.result = "POSSIBLE_OVER_CREDIT"
            evidence.reason = (
                "post-cleanup WINDOW_UPDATE(0,1) was not rejected and the connection "
                "answered a sync PING; confirm with server logs/source and repeat after remediation"
            )
        else:
            evidence.result = "INCONCLUSIVE"
            evidence.reason = "no FLOW_CONTROL_ERROR and no matching post-probe PING acknowledgement"
        return evidence
    except (OSError, ssl.SSLError, ProbeError, ValueError) as exc:
        evidence.result = "INCONCLUSIVE"
        evidence.reason = str(exc)
        return evidence
    finally:
        evidence.elapsed_seconds = round(time.monotonic() - started, 3)
        if conn is not None:
            try:
                conn.sock.close()
            except OSError:
                pass


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    evidence = run(args)
    print(json.dumps(asdict(evidence), indent=2))
    write_evidence(args.json, evidence)
    return {
        "PROTECTED": 0,
        "PROTECTED_OR_CLOSED": 0,
        "REJECTED_WITH_GOAWAY": 0,
        "POSSIBLE_OVER_CREDIT": 1,
        "INCONCLUSIVE": 2,
    }.get(evidence.result, 2)


if __name__ == "__main__":
    sys.exit(main())

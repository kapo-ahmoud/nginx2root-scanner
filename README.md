# CVE-2026-123007 HTTP/2 accounting verifier

This repository contains a bounded, defensive test for the HTTP/2 flow-control
accounting hypothesis described in the accompanying research material.

The tool does **not** attempt code execution, authentication bypass, data
modification, or multi-connection denial of service. It uses one connection,
one bounded PING sequence, and automatic transport detection.

> The CVE identifier and affected-version boundary are intentionally not
> hardcoded as facts. A `POSSIBLE_OVER_CREDIT` result is evidence that the
> tested behavior warrants investigation; it is not independent proof of a
> CVE. Run only against systems you are authorized to test.

## Requirements

- Python 3.10 or newer
- HTTP/2 enabled on the target
- HTTP/2 enabled on the target, either TLS/ALPN on port 443 or h2c on port 80

The script automatically tries HTTPS on port 443 and h2c on port 80, opens
`TRACE /`, sends 8,000 PING requests without reading their acknowledgements,
sends follow-up connection window updates, and sends a final PING. It writes
an evidence file automatically.

## Quick start

Run with only the authorized hostname:

```bash
python3 cve_2026_123007_check.py example.internal
```

The same command is used after remediation. The script creates a timestamped
JSON evidence file in the current directory.

For a local lab:

```bash
python3 cve_2026_123007_check.py 127.0.0.1
```

The automatic TLS check uses normal certificate validation. A self-signed or
misconfigured certificate produces `INCONCLUSIVE`; do not silently disable
certificate validation for production targets.

## Results

The terminal prints a concise, color-coded classification:

| Classification | Color | Exit code | Interpretation |
|---|---|---:|---|
| `Vulnerable` | Red | 1 | The final PING was acknowledged after queued PING frames and follow-up connection-window updates, indicating possible flow-control over-credit. |
| `Not Vulnerable` | Green | 0 | The server rejected the final probe with GOAWAY. |
| `Inconclusive` | Yellow | 2 | The transport or protocol sequence did not complete decisively. |

If color is unavailable, the same labels are printed without ANSI formatting.
Use `NO_COLOR=1` to force plain output.

The script writes timestamped JSON evidence automatically. Preserve the
before-remediation and after-remediation files together with the exact target
build, configuration, and server logs.

## Remediation verification

1. Run `python3 cve_2026_123007_check.py HOSTNAME` before remediation and save
   the generated JSON evidence.
2. Apply the vendor-recommended update or configuration change.
3. Restart or reload the affected service as required.
4. Confirm that the target is running the intended build.
5. Run the identical host-only command again.
6. Require `Not Vulnerable` or a documented vendor-specific rejection. Treat
   `Vulnerable` as a finding requiring further investigation.

Do not use a version number alone as proof of remediation; the verifier does
not encode an unverified affected-version list.

## What the probe does

At a high level, the test:

1. Tries HTTP/2 over TLS/ALPN on port 443, then h2c on port 80.
2. Raises the connection send window to `2^31 - 1`.
3. Opens stream 3 with `TRACE /`.
4. Sends exactly 8,000 PING requests without reading the ACK frames.
5. Sends four follow-up `WINDOW_UPDATE(0, 1)` frames.
6. Sends a final PING and classifies `GOAWAY FLOW_CONTROL_ERROR` versus a
   final PING acknowledgement.

Treat `POSSIBLE_OVER_CREDIT` as a technical finding requiring confirmation
with server logs, source review, or a vendor fix validation.

The probe is not a substitute for source review, vendor advisories, packet
captures, or server-side flow-control logs.

## Development

Run the unit tests without contacting a network target:

```bash
python3 -m unittest discover -v
```

Run the syntax check directly:

```bash
python3 -m py_compile cve_2026_123007_check.py
```

## License

Released under the MIT License. See [LICENSE](LICENSE).

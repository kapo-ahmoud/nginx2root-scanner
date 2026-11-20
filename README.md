# CVE-2026-123007 HTTP/2 accounting verifier

This repository contains a bounded, defensive test for the HTTP/2 flow-control
accounting hypothesis described in the accompanying research material.

The tool does **not** attempt code execution, authentication bypass, data
modification, or multi-connection denial of service. It uses one connection,
one exact-size response fixture, and a bounded stream-pressure phase.

> The CVE identifier and affected-version boundary are intentionally not
> hardcoded as facts. A `POSSIBLE_OVER_CREDIT` result is evidence that the
> tested behavior warrants investigation; it is not independent proof of a
> CVE. Run only against systems you are authorized to test.

## Requirements

- Python 3.10 or newer
- HTTP/2 enabled on the target
- A fixture endpoint returning exactly 65,535 response-body bytes
- A second fixture endpoint returning at least 8 MiB

The exact-size fixture is required because the test transitions the connection
flow-control window from 65,535 bytes to the maximum legal window. If the
fixture is compressed, transformed, truncated, or served with a different
body size, the result is `INCONCLUSIVE`.

## Quick start

Create deterministic local fixtures:

```bash
dd if=/dev/zero of=65535.bin bs=65535 count=1
dd if=/dev/zero of=8m.bin bs=1M count=8
```

Expose those files through the target's HTTP/2 virtual host, then run:

```bash
python3 cve_2026_123007_check.py \
  --host example.internal \
  --port 443 \
  --tls \
  --fill-path /fixtures/65535.bin \
  --body-path /fixtures/8m.bin \
  --authorize-target I-AUTHORIZE-THIS-HOST \
  --json before-remediation.json
```

For cleartext HTTP/2 in a local lab:

```bash
python3 cve_2026_123007_check.py \
  --host 127.0.0.1 \
  --port 80 \
  --h2c \
  --fill-path /fixtures/65535.bin \
  --body-path /fixtures/8m.bin \
  --authorize-target I-AUTHORIZE-THIS-HOST
```

Use `--allow-remote` for a non-loopback target. Use `--insecure-tls` only for
a disposable lab target with a deliberately untrusted certificate.

## Results

| Result | Exit code | Interpretation |
|---|---:|---|
| `PROTECTED` | 0 | The post-cleanup probe produced `GOAWAY FLOW_CONTROL_ERROR`. |
| `POSSIBLE_OVER_CREDIT` | 1 | The probe was not rejected and a sync PING was acknowledged. Confirm with server logs/source. |
| `REJECTED_WITH_GOAWAY` | 0 | The server rejected the probe, but with a GOAWAY code other than `FLOW_CONTROL_ERROR`. |
| `PROTECTED_OR_CLOSED` | 0 | The peer closed without a conclusively observed GOAWAY. |
| `INCONCLUSIVE` | 2 | The transport, fixture, or protocol sequence did not complete. |

The script writes JSON evidence when `--json PATH` is supplied. Preserve the
before-remediation and after-remediation files together with the exact target
build, configuration, fixture hashes, and server logs.

## Remediation verification

1. Run the test before remediation and save JSON evidence.
2. Apply the vendor-recommended update or configuration change.
3. Restart or reload the affected service as required.
4. Confirm that the target is running the intended build.
5. Run the identical command again.
6. Require `PROTECTED` or a documented vendor-specific rejection. Treat
   `POSSIBLE_OVER_CREDIT` as a finding requiring further investigation.

Do not use a version number alone as proof of remediation; the verifier does
not encode an unverified affected-version list.

## What the probe does

At a high level, the test:

1. Negotiates HTTP/2 over TLS/ALPN or h2c.
2. Requests a response containing exactly 65,535 DATA bytes.
3. Raises the connection-level receive window to `2^31 - 1`.
4. Requests a bounded large response and grants bounded stream credit without
   reading for a short interval.
5. Sends a bounded cleanup/refund sequence, resets the stream, and probes with
   `WINDOW_UPDATE(0, 1)`.
6. Classifies a `FLOW_CONTROL_ERROR` rejection separately from a live
   connection. The final PING is only a liveness check.

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

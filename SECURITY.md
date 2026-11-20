# Security policy

## Scope

This project is a defensive HTTP/2 accounting verifier. It is intentionally
bounded, but it can create temporary backpressure on one target connection.

## Safe use

- Test only systems you own or are explicitly authorized to assess.
- Prefer a disposable lab or maintenance window.
- Start with a loopback or isolated target.
- Use the exact fixture sizes documented in the README.
- Do not publish target hostnames, packet captures, or logs containing secrets.
- Stop the test if the service shows resource pressure or unexpected behavior.

## Reporting findings

For a suspected vulnerability, preserve the JSON evidence, target build,
configuration, fixture hashes, and relevant server logs. Report privately to
the vendor or responsible security team before public disclosure.

This repository does not establish the authenticity of a CVE identifier or an
affected-version list. Such claims should be supported by a vendor advisory,
source review, or an authoritative vulnerability database entry.

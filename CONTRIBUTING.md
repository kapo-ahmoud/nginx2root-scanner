# Contributing

Contributions should preserve the tool's defensive and bounded scope.

## Before opening a pull request

```bash
python3 -m unittest discover -v
python3 -m py_compile cve_2026_123007_check.py
```

Do not add tests that contact public hosts. Network tests must use a local mock
server or an explicitly provisioned CI service. Changes that increase the
number of connections, payload size, duration, or concurrency require a clear
security review in the pull request.

Document any change to result classification, evidence fields, or protocol
assumptions in the README and changelog.

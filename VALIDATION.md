# Validation record

Validated during project creation on 2026-09-18 with Python 3.12.14 on Linux.

## Passed

`python3 -m unittest discover -s tests -v`: five tests passed.

- Real loopback TCP and UDP ingestion: 12 expected messages received.
- Octet-counted and newline TCP framing, including a frame split across sends.
- SQLite persistence after closing and reopening the database.
- Both SSH rules on the synthetic sequence, including evidence IDs.
- Expired time windows and unrelated user, host, or application isolation.
- Never-seen and silent source states.
- Priority parsing, legacy format, and unsupported-format fallback.
- Escaping script markup in generated HTML.

A separate actual TCP collection run produced nine events and two findings. Its HTML/JSON output is included in `examples/` using synthetic data only.

## Not verified here

- Docker build/runtime: Docker was unavailable. CI includes a build check, but no CI run is claimed.
- Forwarding from a separate Linux VM or physical network device.
- Windows/macOS execution.
- Browser rendering and filter interaction: HTML and escaping were checked in code; no browser automation was run.
- High load, hostile inputs at scale, packet-loss behavior, or production security.

These are remaining validation tasks, not completed features. Record your own results after running the lab.

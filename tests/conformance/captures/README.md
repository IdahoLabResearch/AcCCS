# Replay corpus — captured sessions

Captured wire bytes from real or veth charging sessions, consumed by the
replay layer (`tests/conformance/replay/`). Each entry is two files:

- `<name>.pcap` (or `<name>.bin`) — the captured bytes.
- `<name>.yaml` — provenance metadata.

The provenance YAML must include the `source` tag:

```yaml
source: veth                 # captured between two AcCCS emulators
# or
source: hw:<device-label>    # captured against a real device (EV or EVSE)
protocol: din70121           # one of: din70121 | iso15118-2 | iso15118-20
energy_mode: dc              # ac | dc | bpt | wpt | acdp
captured_at: 2026-01-15
notes: |
  Free-form context. Hardware identity, lab conditions, anything a future
  reader will want.
```

## Coverage policy

Per ADR-0003:

- **Veth captures** are required for every protocol covered by the suite —
  cheap to author, useful as a regression baseline.
- **Hardware captures** are required *somewhere* in the corpus per
  protocol-and-energy combination — they are the external truth anchor and
  what the major-release real-device-acceptance gate verifies.

This corpus is **empty in Slice 1**. It will be populated by EXPy Slice 4
(#15) — see ADR-0003's per-slice gating table.

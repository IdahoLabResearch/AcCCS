# Scenarios

Forward-driven test inputs for the E2E layer. Each scenario YAML names an
EVCC personality, an SECC personality, optional runtime overrides, and an
expected outcome.

## Schema

```yaml
name: <unique scenario id, kebab-case>
description: <one-line human label>
evcc_personality: <basename under tests/conformance/personalities/>
secc_personality: <basename under tests/conformance/personalities/>
expected_outcome: session_complete    # only value supported in Slice 1
timeout_seconds: 30                   # how long to wait for the session to finish
xfail: false                          # if true, the runner marks the test xfail
xfail_reason: ""                      # required when xfail: true
runtime_overrides:                    # optional; not yet wired in Slice 1
  evcc: {}
  secc: {}
```

ADR-0003 reserves the right to expand `expected_outcome` with a failure-shape
grammar later. Slice 1 only needs `session_complete`.

## Why these three

Per the coverage matrix in ADR-0003 the E2E layer carries one canonical
happy-path scenario per protocol:

- `din-happy.yaml` — DIN 70121, DC. Passes today.
- `iso2-pnc-dc-tls.yaml` — ISO 15118-2, PnC, DC, TLS on. **xfail** until
  personality Slice 3 (#8).
- `iso20-pnc-dc-tls.yaml` — ISO 15118-20, PnC, DC, TLS on. **xfail** until
  personality Slice 4 (#9).

Cross-products (EIM vs PnC, AC vs DC, TLS on/off, BPT, WPT, ACDP) are not
covered at this layer — pushed down to the state-machine and codec layers.

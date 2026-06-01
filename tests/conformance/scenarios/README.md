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

## Coverage

Per the coverage matrix in ADR-0003 the E2E layer carries one PnC and one EIM
happy-path per ISO protocol, plus DIN's happy path and a DIN personality
variant — six scenarios. Each row below is derived from the scenario's YAML:

| Scenario | Protocol | Auth | Energy | TLS |
|---|---|---|---|---|
| `din-happy.yaml` | DIN 70121 | — | DC | off |
| `din-variant.yaml` | DIN 70121 | — | DC | off |
| `iso2-pnc-dc-tls.yaml` | ISO 15118-2 | PnC | DC | on |
| `iso2-eim-dc.yaml` | ISO 15118-2 | EIM | DC | off |
| `iso20-pnc-dc-tls.yaml` | ISO 15118-20 | PnC | DC | on |
| `iso20-eim-dc.yaml` | ISO 15118-20 | EIM | DC | on |

`din-variant` shares `din-happy`'s state-machine shape but advertises altered
power limits, EVSEID, and energy-transfer-mode; it guards against the
personality swap regressing the wire flow. DIN 70121 has no PnC/EIM
contract-auth split, so its auth column is blank.

The remaining cross-products (AC vs DC, BPT, WPT, ACDP) are not covered at this
layer — pushed down to the state-machine and codec layers.

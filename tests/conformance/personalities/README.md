# Test personalities

These are **framework fixtures**, not operational personalities. Each file is
a minimal YAML personality validated by the same Pydantic model the
production loader uses (ADR-0001).

The conformance E2E runner passes a personality path to the spawned
`run_evcc.py` / `run_secc.py` subprocess via `--config <path>`. The runner
also adds `--virtual` so the subprocess never touches the SMBus / I2C relay
hardware (CI / dev boxes don't have it attached).

ADR-0003's F3 step ("swap bootstrap test personalities for YAML once
personality Slice 1 lands") is satisfied — these files are the YAML
replacements. The DIN smoke scenario no longer wears an xfail.

## Risk-based personalities (issue #21)

Most personalities here back the declarative smoke scenarios. The `fallback-*`
files instead back the app-protocol fallback E2E test
(`e2e/test_app_protocol_fallback.py`), which the declarative scenario shape
can't express because it asserts the negotiated protocol mid-session:

| Personality | Role | Offers / supports | Used by |
|---|---|---|---|
| `fallback-evcc-multi` | EVCC | ISO-20 > ISO-2 > DIN (priority order) | SECC-constrained case |
| `fallback-secc-din-only` | SECC | DIN only | SECC-constrained case |
| `fallback-evcc-din-only` | EVCC | DIN only | EVCC-constrained mirror |
| `fallback-secc-multi` | SECC | ISO-2 > DIN | EVCC-constrained mirror |

All four are TLS-off: DIN mandates no transport-layer security (so the EVCC's
SAP builder strips DIN from any TLS offer, [V2G-DC-618]) and a TLS-off SECC is
hard-refused if it lists a -20 protocol. Each file's header comment carries the
full rationale. The ISO-20 envelope and ISO-2 PnC risk-based tests reuse the
existing `iso20-eim-*` and `iso2-*` smoke personalities.

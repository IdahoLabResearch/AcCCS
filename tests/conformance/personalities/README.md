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

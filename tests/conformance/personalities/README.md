# Bootstrap test personalities

These are **framework fixtures**, not operational personalities. Per ADR-0003
Slice F0:

> Bootstrap test personalities authored against the pre-rollout `.env` / JSON
> config so smoke scenarios can run before personality Slice 1 (#6) lands.

They mirror the existing `.env.evcc` / `.env.secc` format because that is the
configuration shape that exists today. Once personality Slice 1 lands (#6)
and the YAML loader is in place, F3 replaces these files with YAML
personalities under the same directory.

The conformance E2E runner reads a personality file, parses each `KEY=VALUE`
line, and passes those values as environment variables to the spawned
`run_evcc.py` / `run_secc.py` subprocess. That keeps the framework decoupled
from the personality format — only the file extension changes when YAML
arrives.

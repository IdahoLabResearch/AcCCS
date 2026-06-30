# Personality YAML as the single configuration artifact

Configuration of AcCCS emulators was previously split across three formats — `.env.evcc` / `.env.secc` (loaded via `environs`), CLI argparse flags with partial overlap, and per-protocol JSON sub-configs under `app/shared/examples/evcc/`. We are consolidating everything that describes "who the emulated device is" (IDs, supported protocols, auth modes, power limits, SOC, cert paths, SLAC timings, TLS posture, etc.) into a single YAML [[personality]] file per role, validated strictly by a Pydantic model on load. Operational/per-invocation knobs (logging level, NMAP toggles, `--virtual`) stay separate in an optional `runtime.yaml`, with CLI flags overriding it.

## Considered Options

- Layered TOML / pydantic-settings with env-var and CLI overrides on the personality fields. Rejected: layering is exactly what we're escaping; multiple sources of truth for the same field hurt reproducibility of test runs.
- JSON file (matching the existing per-protocol sub-config format). Rejected in favor of YAML for comments (these fields are esoteric protocol knobs that benefit from inline docs) and anchors (lets a "Ford Mach-E variant" personality reuse a base block and override two fields).
- Concern-first with per-protocol override blocks (e.g. `power: { max_current: 200, iso15118_20: { max_current: 250 } }`). Rejected for now in favor of flat concern-first sections (single value per field). Graduating to per-protocol overrides is a future change if fuzzing per-protocol encoding divergence becomes important.

## Consequences

- `.env.evcc`, `.env.secc`, and `EVCC_CONFIG_PATH` are removed. Hard cutover — no compat shim.
- CLI for both run scripts shrinks to `--config <personality.yaml>` plus operational flags (`--runtime`, `--log-level`, `--virtual`, `--nmap-args`, …). Personality fields are *not* CLI-overridable.
- Strict Pydantic validation: unknown keys are a hard error. A future "raw protocol-field override" mode (out of scope for this upgrade) will live in a separately-validated `raw_overrides:` section. **Superseded by [ADR-0006](0006-message-field-tree-personality.md):** the raw per-field model is not a separate override layer but *replaces* the structured wire-value sections as a per-message field tree.
- Personality files are searched in this order: explicit `--config` path → `personalities/<name>.yaml` in repo → `~/.acccs/personalities/<name>.yaml` user-local. Lets proprietary device personalities live outside the repo.
- Most personality fields are currently hardcoded inside state machines (`app/evcc/states/`, `app/secc/states/`, controllers) — exposing them is the bulk of the work and is sliced by protocol (DIN → ISO-15118-2 → ISO-15118-20) so each slice is independently end-to-end testable.

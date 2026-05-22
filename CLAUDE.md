# CLAUDE.md

## Agent skills

### Issue tracker

Issues live in GitHub Issues at `IdahoLabResearch/AcCCS` (uses the `gh` CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

Five canonical triage roles using default label strings (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout: `CONTEXT.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.

## Configuration

Emulator configuration follows [ADR-0001](docs/adr/0001-personality-yaml-config.md):

- A **personality** (YAML) describes *who* the emulated device is — IDs,
  supported protocols, power/charging profile, TLS posture, SLAC timings,
  certificates. Loaded once at startup via `--config <name-or-path>`.
- **Runtime** knobs (logging, NMAP toggles, `--virtual`, source port,
  modified-cordset) live in an optional `runtime.yaml` and are
  CLI-overridable. Personality fields are *never* CLI-overridable.
- Personality search order: explicit `--config <path>` →
  `personalities/<name>.yaml` (repo) → `~/.acccs/personalities/<name>.yaml`
  (user-local).
- The Pydantic models live in `app/shared/personality/`; the loader is
  `load_personality` / `load_runtime` / `apply_runtime_overrides`.
- Stock defaults: `personalities/default-evcc.yaml`,
  `personalities/default-secc.yaml`. Regenerate from model defaults via
  `python scripts/regen_personality_defaults.py`. The drift test in
  `tests/personality/test_drift.py` guards against the YAML and the model
  diverging.

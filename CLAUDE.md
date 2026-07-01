# CLAUDE.md

## Agent skills

### Issue tracker

Issues live in GitHub Issues at `IdahoLabResearch/AcCCS` (uses the `gh` CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

Five canonical triage roles using default label strings (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout: `CONTEXT.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.

## Commit conventions

Do **not** add a `Co-Authored-By: Claude ...` trailer (or any other AI
co-author/attribution trailer) to commit messages. This overrides the default
harness behavior. Otherwise mirror the existing log style: an imperative
summary line ending with the issue number in `(#N)` form, plus a body
paragraph explaining the *why*.

## Configuration

Emulator configuration follows [ADR-0001](docs/adr/0001-personality-yaml-config.md)
and [ADR-0006](docs/adr/0006-message-field-tree-personality.md):

- A **personality** (YAML) describes *who* the emulated device is. Per
  ADR-0006 it has two parts: a **`message_field_tree`** — the per-message,
  per-field values the device emits on the wire (keyed by message name and
  field path, DIN-only this slice) — and a **`residual`** section for
  everything with *no* wire representation (`tls`, `slac`, `certificates`,
  `network`, `charge_profile`, and behavioral flags under `behavior`). The
  dividing rule is mechanical: on the wire → tree; not on the wire →
  residual; never duplicated. Dual-purpose fields (e.g. the DIN energy
  transfer mode) are single-sourced from the tree — the
  `WrongEnergyTransferType` reject-gate reads the same
  `ServiceDiscoveryRes → ChargeService → EnergyTransferType` value the SECC
  advertises. The wire-bearing sections that predate the tree (`identity`,
  `capabilities`, `power`, `meter`) still live at the top level until later
  slices migrate them into per-message trees.
- **Layering:** a personality may `extends: <baseline-name>` a per-role
  baseline; the loader deep-merges the device's sparse values over the
  baseline (device leaves win), including individual `message_field_tree`
  leaves. The shipped DIN baselines are
  `personalities/din-{evcc,secc}-baseline.yaml`.
- Loaded once at startup via `--config <name-or-path>`. `--config` is
  optional; when omitted each run script defaults to its per-role DIN file
  (`run_evcc.py` → `din_dc_extended-evcc`, `run_secc.py` →
  `din_dc_extended-secc`) — DIN with the DC_extended energy transfer mode
  that production vehicles request. The symmetric `din_dc_extended.yaml` was
  retired for these per-role files.
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

## Running the virtual two-session demo

Use this to verify end-to-end behaviour after touching the emulator,
codec, transport, or config layers.

Prerequisites (one-time):

1. `bash app/shared/pki/create_certs.sh -v iso-2` — generates PKI certs
   under `app/shared/pki/iso15118_2/certs/`. Stock personalities have TLS
   on, so this is required for the demo to reach SDP/TLS.
2. `sudo ./setup_veth.sh` — creates the `acccs_secc ↔ acccs_evcc` veth
   pair with `fe80::1` / `fe80::2`.

Run (each command needs `sudo` for raw sockets). `sudo` runs with root's
PATH, which does *not* include the activated `AcCCS` conda env — invoke
the env's interpreter by its full path, otherwise `import nmap` (and
every other env-only dep) fails with `ModuleNotFoundError`:

```bash
# Terminal 1
sudo /home/jake-inl/anaconda3/envs/AcCCS/bin/python run_secc.py --config default-secc --virtual

# Terminal 2 (a couple seconds later)
sudo /home/jake-inl/anaconda3/envs/AcCCS/bin/python run_evcc.py --config default-evcc --virtual
```

A clean session walks through: SLAC → SDP/TLS → SessionSetup →
ServiceDiscovery → PowerDelivery → CurrentDemand loop → PowerDelivery →
WeldingDetection → SessionStop, with the EVCC logging
`Going to state A` at the end.

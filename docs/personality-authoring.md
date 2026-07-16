# Authoring a personality

A **personality** is a YAML file that describes *who* an AcCCS-emulated
device is — its identity, supported protocols, power envelope, TLS
posture, SLAC timings, certificates. One file is loaded per process at
startup; nothing in a personality is CLI-overridable. Per
[ADR-0001](adr/0001-personality-yaml-config.md), this is the *only*
place personality fields live: there is no `.env`, no JSON sub-config,
no overlapping CLI flag.

This guide explains what each section means, the personality/runtime
boundary, the file search order, and how to author a new personality
file.

> **Note (ADR-0006):** the wire-value sections described below are being
> replaced by a two-part model — a **`message_field_tree`** (per-message,
> per-field emitted values) plus a **`residual`** section for everything with
> no wire representation (`tls`, `slac`, `certificates`, `network`,
> `charge_profile`, `behavior`). Personalities are now **per role** (separate
> EVCC/SECC files, no shared symmetric file) and can `extends:` a per-role
> baseline. See [ADR-0006](adr/0006-message-field-tree-personality.md) and the
> CLAUDE.md "Configuration" section. The "Sections" narrative here still
> reflects the older concern-first layout for the not-yet-migrated protocols
> and is pending a fuller rewrite.

## Personality vs. runtime

| Concern | Lives in | CLI-overridable? |
|---|---|---|
| Who the device claims to be (IDs, supported protocols, power, TLS) | personality YAML (`personalities/`) | **No** |
| How this invocation is operated (log level, NMAP, `--virtual`) | optional `runtime.yaml` | Yes — see flag table below |

The boundary is intentional: personality is a *contract* about the
emulated device's behaviour. Letting it shift mid-experiment would mean
"who am I running against right now?" no longer has a single answer.
Operational knobs (logging, scanning, virtual veth mode) are per-run and
are CLI-overridable.

### Runtime override flags

| Flag | Overrides |
|---|---|
| `--log-level <LEVEL>` | `runtime.log.console_level` |
| `--file-log-level <LEVEL>` | `runtime.log.file_level` |
| `--virtual` | `runtime.virtual` |
| `--nmap` | `runtime.nmap.enabled` |
| `--nmap-args <ARGS>` | `runtime.nmap.args` |
| `--nmap-ports <SPEC>` | `runtime.nmap.ports` |
| `--source-port <PORT>` | `runtime.source_port` |
| `--modified-cordset` | `runtime.modified_cordset` (SECC only) |
| `--poll-interval <SECONDS>` | `runtime.poll.ongoing_interval_seconds` (EVCC only) |

`--poll-interval` is the cadence at which the EVCC re-sends a request the
SECC answered with `EVSEProcessing=ONGOING` — a real charger holds
ContractAuthentication that way while it waits on external payment
authorization, and an unpaced EVCC re-sends as fast as the charger can
reply (~190 req/s observed in the field). It defaults to 1 s, never delays
the `FINISHED` transition, and accepts `0` to restore the un-paced hot
re-send for probing.

## File search order

`--config` is optional; when omitted each run script defaults to its per-role
DIN file (`run_evcc.py` → `din_dc_extended-evcc`, `run_secc.py` →
`din_dc_extended-secc`). The loader resolves `--config <value>` in this order:

1. **Explicit path** — if `<value>` is a path to an existing file, it
   wins.
2. **Repo-local** — `personalities/<value>.yaml` (and `<value>.yml`) in
   the current working directory.
3. **User-local** — `~/.acccs/personalities/<value>.yaml`.

The user-local tier is the place to keep proprietary device
personalities (a specific OEM's EVSE, an internal test fixture) without
forking AcCCS.

## Sections

Personalities are **concern-first**: the section names group fields by
what they describe, not by which protocol uses them. A single file
shape works for both EVCC and SECC roles — each role only reads the
fields relevant to it.

The Pydantic loader is strict: **unknown keys at any level are a hard
error**. A typo will fail validation at startup rather than silently
falling back to a default.

### `identity`

Wire identifiers the device advertises. `evcc_id` is the EVCCID
(VIN-shaped on the EV side); `evse_id` follows DIN SPEC 91286 /
ISO 15118 EVSEID formatting on the SECC side.

### `network`

Per-deployment topology: the interface name to bind. The role-specific
defaults (`acccs_evcc` / `acccs_secc`) match the bundled veth pair from
`setup_veth.sh`.

### `slac`

HomePlug GreenPHY association: SLAC sound timeout, NID, NMK. These
describe how this device joins the PLC AVLN.

### `tls`

TLS posture:
- `enable_tls_1_3` — if false, ISO 15118-20 sessions are refused.
- `use_tls` — EVCC's hint to the SECC's SDP service.
- `enforce_tls` — if true, refuse non-TLS sessions outright.
- `sdp_retry_cycles` — SDP retries before falling back to PWM signaling.

### `capabilities`

Negotiable items the device announces during session setup:
`supported_protocols`, `supported_auth_modes`, `supported_energy_services`,
`energy_transfer_mode`, plus a handful of session-policy booleans
(`free_charging_service`, `allow_cert_install_service`,
`standby_allowed`, …).

This is the section you tune to **scope a personality to one protocol**
— set `supported_protocols: [DIN_SPEC_70121]` to refuse non-DIN
sessions, etc.

### `power`

The power envelope, split into sub-blocks because the wire shapes
diverge across protocols:

| Sub-block | Used by | Role | What it covers |
|---|---|---|---|
| `evse_dc` | DIN, ISO 15118-2 DC | SECC | DC envelope advertised in CPD/CurrentDemand |
| `ev_dc` | DIN, ISO 15118-2 DC | EVCC | EV-announced DC maxima + start-of-loop targets |
| `evse_ac` | ISO 15118-2 AC | SECC | AC nominal voltage and max current |
| `ev_ac` | ISO 15118-2 AC | EVCC | EV-announced AC envelope and energy ask |
| `evse_dc_v20` | ISO 15118-20 DC + DC-BPT | SECC | RationalNumber DC envelope + BPT discharge |
| `ev_dc_v20` | ISO 15118-20 DC + DC-BPT | EVCC | CPD / PreCharge / scheduled + dynamic loop + BPT |
| `evse_ac_v20` | ISO 15118-20 AC + AC-BPT | SECC | Multiphase AC, ramp limit, BPT |
| `ev_ac_v20` | ISO 15118-20 AC + AC-BPT | EVCC | CPD + scheduled + dynamic + BPT discharge stubs |
| `schedule_exchange_v20` | ISO 15118-20 | EVCC | EV-announced ScheduleExchange (scheduled + dynamic) |
| `evse_schedule_exchange_v20` | ISO 15118-20 | SECC | SECC's schedule envelope (price/tax meta stays hardcoded) |

Each role only consumes its own side. A personality is welcome to fill
in both sides; the unused fields are simply ignored when that role runs.

### `charge_profile`

Charge-loop pacing for the simulated EV: `cycle` (target percent before
welding detection) and `delay_seconds` (between CurrentDemand iterations).

### `certificates`

`pki_path` — where the SECC/EVCC PKI lives — and `max_contract_certs`
(ISO 15118-2 PnC).

### `meter`

SECC-side meter identity advertised in `MeterInfo` blocks
(`meter_id`, `starting_reading_wh`). The per-message reading is
runtime-derived and is *not* a personality field.

## Authoring a new personality

1. Start from the stock dump for your role:
   ```bash
   cp personalities/default-secc.yaml personalities/my-evse.yaml
   ```
   Stock files are a complete materialised dump of every default. Either
   delete fields you don't care to override (defaults will apply) or
   leave them in for documentation.

2. Optionally drop the `role:` field. If present it must match the role
   loading the file; omit it to make the same personality usable by
   both `run_evcc.py` and `run_secc.py`. Most of the bundled examples
   leave it off.

3. Edit. The loader rejects unknown keys, so a typo in a section name
   or field name will fail at startup with a precise Pydantic error.

4. Run:
   ```bash
   python run_secc.py --config my-evse --virtual
   ```
   The `--config` value can be a bare name (looked up under
   `personalities/`) or an explicit file path.

## Bundled examples

The repository ships a starter library under `personalities/`:

| File | Protocol | Notes |
|---|---|---|
| `default-evcc.yaml` / `default-secc.yaml` | All | Materialised model defaults — regenerated from the Pydantic model. |
| `din_dc_extended-evcc.yaml` / `din_dc_extended-secc.yaml` | DIN 70121 | **Default `--config`** (per role). DIN-only, TLS off, `DC_extended` — the mode production vehicles request. Each `extends:` its per-role baseline. |
| `din-evcc-baseline.yaml` / `din-secc-baseline.yaml` | DIN 70121 | Per-role DIN baselines (ADR-0006). The advertised DC energy transfer mode is single-sourced from the SECC baseline's `message_field_tree`. The full ABB/Cadillac trees land here in #73/#74. |
| `din_reference.yaml` | DIN 70121 | DIN-only emulator, TLS off, alternate `energy_transfer_mode` (DC_core, for the personality-swap demo) and a ~3x stock power envelope. |
| `iso2-secc-baseline.yaml` | ISO 15118-2 DC | Per-role ISO-2 **SECC** baseline (ADR-0006 / #96), seeded field-for-field from `HAL+TCP_ISO_2_DC_Example.pcap`. Every SECC-emitted ISO-2 message is tree-sourced; device files `extends:` this. |
| `iso2_eim_dc-secc.yaml` / `iso2_eim_dc-evcc.yaml` | ISO 15118-2 DC | EIM (External Identification Means) auth — no contract certs, no PnC. Per-role split (#96): the SECC side `extends: iso2-secc-baseline` and pins its EVSEID; the EVCC side is still structured (ISO-2 EVCC is pre-tree). |
| `iso2_pnc_dc-secc.yaml` / `iso2_pnc_dc-evcc.yaml` | ISO 15118-2 DC | PnC (Plug-and-Charge) auth — TLS mandatory, contract cert chain required. Per-role split (#96): the SECC side `extends: iso2-secc-baseline`, advertising the Contract payment option with TLS on. |
| `iso20_dc.yaml` | ISO 15118-20 DC | DC energy service over ISO 15118-20 (TLS 1.3 mandatory). |
| `example_iso20_ac_variant.yaml` | ISO 15118-20 AC | AC energy service. |
| `example_iso20_ac_bpt_variant.yaml` | ISO 15118-20 AC-BPT | Bidirectional AC. |
| `example_iso20_dc_bpt_variant.yaml` | ISO 15118-20 DC-BPT | Bidirectional DC. |

Stock defaults are regenerated from the model via
`python scripts/regen_personality_defaults.py`. The drift test
(`tests/personality/test_drift.py`) guards the YAML against the model.

## See also

- [ADR-0001 — Personality YAML as the single configuration artifact](adr/0001-personality-yaml-config.md)
- `app/shared/personality/model.py` — the Pydantic source of truth.
- `app/shared/personality/loader.py` — search order + override merge.

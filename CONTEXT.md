# Glossary

Canonical terminology for the AcCCS project. This file is a glossary only — no implementation details, no decisions, no specs. For decisions see `docs/adr/`.

## Personality

A single configuration artifact (YAML file) that fully describes the identity, capabilities, power/charging profile, security material, network, and timing knobs of either an emulated **EVCC** (vehicle side) or **SECC** (charger side). One personality = "be this specific EV" or "be this specific EVSE" for the duration of a run.

Personalities are loaded once at emulator startup. They are *not* mutated mid-session and they do *not* describe a sequence of behaviors over time — they describe who the device **is**.

A personality covers fields the device chooses or advertises (IDs, supported protocols, max voltage/current, SOC, cert paths, SLAC timings, TLS enforcement, …). Runtime-derived values (session IDs, challenges, signatures, instantaneous measurements during the charge loop) are *not* part of a personality.

Personality is distinct from **runtime config** — per-invocation operator knobs such as logging level, NMAP toggles, and virtual-NIC mode. Runtime config lives in an optional `runtime.yaml` and is overridable by CLI flags; personality fields are never CLI-overridable.

Related: [[evcc]], [[secc]].

## EVCC

Electric Vehicle Communications Controller — the vehicle-side controller in a CCS charging session. In this repo, emulated by the code under `app/evcc/` and launched via `run_evcc.py`. Loads an EVCC-flavored [[personality]].

## SECC

Supply Equipment Communications Controller — the charger-side controller in a CCS charging session. In this repo, emulated by the code under `app/secc/` and launched via `run_secc.py`. Loads an SECC-flavored [[personality]].

## Scenario

A test input artifact (YAML) that names an EVCC [[personality]], an SECC [[personality]], optional runtime overrides, and an expected outcome (clean session completion, specific protocol failure, fallback negotiation result). One scenario = one named end-to-end test case.

Distinct from a [[personality]] (which describes a device's identity, not a test) and from a [[captured-session]] (which is recorded wire traffic used by the replay test layer, not a forward-driven test input).

## Captured session

A recorded artifact (message log or pcap) of an actual charging exchange between an [[EVCC]] and an [[SECC]] — either two AcCCS emulators in veth mode or a real device. Used as input to the replay test layer to verify that the EXI codec and message-parsing layer can faithfully round-trip the messages in the recording.

Distinct from a [[scenario]] (which is a forward-driven test input) — a captured session is backward-driven: bytes go in, equivalence is asserted.

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

## Operator console

The live control channel through which a human operator issues mid-session commands to a *running* emulator — currently realized as an interactive terminal footer. It is the home of the project's only two live, mid-session capabilities: [[stall]] gate releases and [[live-override]] value edits.

The operator console is the deliberate exception to the project's otherwise load-once configuration story: a [[personality]] is immutable and a runtime config is read once at startup, whereas the operator console exists precisely to mutate a device's behaviour and the values it puts on the wire *while the session is in flight*. It carries operator *intent*, not device identity.

## Stall

An operator-controlled behaviour in which an emulated [[EVCC]] or [[SECC]] holds a repeating protocol loop's exit *gate* closed, keeping the peer in that loop indefinitely instead of letting the session advance. Two gates can be stalled:

- the **charge-loop exit gate** — the ISO 15118-2 CurrentDemand loop, the ISO 15118-20 DC/AC ChargeLoop, and the DIN SPEC CurrentDemand loop — normally controlled by the [[EVCC]]'s decision to stop charging; and
- the **authorization gate** — the ISO 15118-2/-20 Authorization loop and the DIN SPEC ContractAuthentication loop — normally controlled by the [[SECC]] declaring processing *finished*.

A stalled gate is released only by an explicit operator action on the [[operator-console]] ("pass the gate"); there is no automatic timeout or cycle cap. Because the protocol assigns control of each gate to one role, the *forceful* stalls are EVCC-over-charge-loop and SECC-over-authorization-gate; the opposite directions are *passive* (e.g. an SECC withholding its stop signal) rather than compelling. Stall mode also relaxes the stalling participants' own protocol timeouts that would otherwise break the hold — e.g. an [[EVCC]] ignores its ongoing-authorization timeout so a stalling [[SECC]] can hold it indefinitely.

Distinct from [[live-override]] (which changes the *values carried in* loop messages, not whether the loop terminates) and from a [[personality]] (which is immutable and never describes behaviour over time).

## Live override

An operator action that replaces, in real time, the current/voltage values an emulated device puts on the wire during the charge loop. Role-aware: on an [[EVCC]] it overrides the EV's *requested target* current/voltage (and present voltage in ISO 15118-20); on an [[SECC]] it overrides the EVSE's *reported present* (delivered) current/voltage. An override takes effect on subsequent loop messages and persists until the operator changes or clears it.

Distinct from a [[personality]]'s power/charging profile: the personality supplies the device's *declared envelope and starting values* (immutable), whereas a live override injects the *instantaneous loop values* that the glossary explicitly excludes from a personality. Issued through the [[operator-console]]. Distinct from [[stall]] (which controls loop termination, not loop values).

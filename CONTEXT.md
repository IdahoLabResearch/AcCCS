# Glossary

Canonical terminology for the AcCCS project. This file is a glossary only — no implementation details, no decisions, no specs. For decisions see `docs/adr/`.

## Personality

A single configuration artifact (YAML file) that fully describes either an emulated **EVCC** (vehicle side) or **SECC** (charger side). One personality = "be this specific EV" or "be this specific EVSE" for the duration of a run. There is one personality file *per role* — EVCC and SECC personalities are separate files, not a shared symmetric file.

A personality has two parts:

- A **[[message field tree]]** — the per-message, per-field values the device emits on the wire, keyed by message name and mirroring the protocol's message models down to each leaf field. This is the device's wire output: *what bytes it puts on the line*.
- A **residual section** — the structured configuration that has *no* wire representation: TLS posture, SLAC layer-2 timings, certificate paths, network interface, and behavioral switches that select code paths (e.g. backend mode). This is *transport and behavior*, not emitted bytes.

The dividing rule is mechanical: **if a value appears on the wire it lives in the message field tree (and any internal decision that needs it reads it from there); if it never appears on the wire it lives in the residual section.** A value is therefore never duplicated across the two parts.

Personalities are loaded once at emulator startup and are *not* mutated mid-session. The message field tree describes wire values per *message type* (one value per repeated message), so a personality still does **not** script a sequence of behaviors over time — instantaneous loop variation comes from computed runtime logic or a [[live-override]], not the personality. Runtime-derived values (session IDs, challenges, signatures, present-voltage/current measurements during the charge loop) are computed at runtime and are *not* baseline tree values unless explicitly overridden.

Personality is distinct from **runtime config** — per-invocation operator knobs such as logging level, NMAP toggles, and virtual-NIC mode. Runtime config lives in an optional `runtime.yaml` and is overridable by CLI flags; personality fields are never CLI-overridable.

Related: [[evcc]], [[secc]], [[message field tree]], [[live-override]].

## Message field tree

The part of a [[personality]] that defines every field the emulated device emits on the wire, keyed by message name and then by nested field path mirroring the protocol's message models (e.g. `ChargeParameterDiscoveryRes → DC_EVSEChargeParameter → DC_EVSEStatus → EVSEIsolationStatus`). It replaces the older concern-first structured wire sections (the flat `power` / per-protocol limit blocks) as the single way to configure emitted bytes.

The tree is **layered**: a baseline tree (shipped per role) supplies the device's full default output, and a device file overrides only the leaves that differ, via YAML anchors; a leaf set nowhere falls back to the message model's own default. Overrides take effect at message *construction* time, so an overridden value flows into both the emitted bytes *and* any internal logic that reads that field.

Validation is **path-strict, value-raw**: a field path must resolve to a real field in the message model (a typo is a hard error), but the value itself is not range- or enum-checked — illegal-but-encodable values are the point (red-team probing), bounded only by what the codec can serialize.

Precedence for a field a [[live-override]] can also set: live-override (runtime) beats the tree, which supplies the declared/start value. Distinct from the residual section of a [[personality]] (non-wire transport/behavior) and from [[live-override]] (mid-session instantaneous values, not load-once config).

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

The console spans the emulator's whole lifetime — it is live from process startup, through every [[session cycle]], and across the [[idle]] gaps between sessions — not just while a session is in flight. It surfaces the current lifecycle phase to the operator and is the only surface that can quit a running emulator.

## Session cycle

One complete run of a charging exchange by an emulated [[EVCC]] or [[SECC]] — from link establishment (SLAC) through SDP/TLS, the protocol state machine, the charge loop, and SessionStop. A single emulator process runs *many* session cycles over its lifetime: after each cycle ends — whether it completes cleanly or fails partway — the side returns to [[idle]] rather than exiting. SLAC is re-performed at the start of every cycle (it is not a one-time startup step).

## Idle

The ready-to-start resting state a side returns to after a [[session cycle]] ends (cleanly or by failure). The device is dropped back to its initial electrical state (EVCC: CP line State A; SECC: proximity open) and waits. From idle, a side is **re-armed** to begin the next cycle: the [[SECC]] re-arms by re-listening for SLAC; the [[EVCC]] re-arms by re-initiating SLAC. Re-arming is operator-driven by default (an *advance* action on the [[operator-console]]) and the [[SECC]] must be re-armed before the [[EVCC]] initiates. A running emulator never leaves idle on its own and never exits on its own — only an explicit operator *quit* terminates the process.

## Auto-rearm

A per-invocation runtime mode (CLI flag plus a live [[operator-console]] toggle, off by default) in which a side re-arms itself the instant a [[session cycle]] ends, skipping the [[idle]] wait for an operator advance. With both sides in auto-rearm, the emulators cycle sessions continuously until quit. Auto-rearm is a runtime knob (per-invocation, CLI-overridable), never a [[personality]] field.

## Stall

An operator-controlled behaviour in which an emulated [[EVCC]] or [[SECC]] holds a repeating protocol loop's exit *gate* closed, keeping the peer in that loop indefinitely instead of letting the session advance. Two gates can be stalled:

- the **charge-loop exit gate** — the ISO 15118-2 CurrentDemand loop, the ISO 15118-20 DC/AC ChargeLoop, and the DIN SPEC CurrentDemand loop — normally controlled by the [[EVCC]]'s decision to stop charging; and
- the **authorization gate** — the ISO 15118-2/-20 Authorization loop and the DIN SPEC ContractAuthentication loop — normally controlled by the [[SECC]] declaring processing *finished*.

A stalled gate is released only by an explicit operator action on the [[operator-console]] ("pass the gate"); there is no automatic timeout or cycle cap. Because the protocol assigns control of each gate to one role, the *forceful* stalls are EVCC-over-charge-loop and SECC-over-authorization-gate; the opposite directions are *passive* (e.g. an SECC withholding its stop signal) rather than compelling. Stall mode also relaxes the stalling participants' own protocol timeouts that would otherwise break the hold — e.g. an [[EVCC]] ignores its ongoing-authorization timeout so a stalling [[SECC]] can hold it indefinitely.

Distinct from [[live-override]] (which changes the *values carried in* loop messages, not whether the loop terminates) and from a [[personality]] (which is immutable and never describes behaviour over time).

## Live override

An operator action that replaces, in real time, the current/voltage values an emulated device puts on the wire during the charge loop. Role-aware: on an [[EVCC]] it overrides the EV's *requested target* current/voltage (and present voltage in ISO 15118-20); on an [[SECC]] it overrides the EVSE's *reported present* (delivered) current/voltage. An override takes effect on subsequent loop messages and persists until the operator changes or clears it.

Distinct from a [[personality]]'s [[message field tree]]: the tree supplies the device's *declared / starting* wire value for a field (immutable, per message type), whereas a live override injects the *instantaneous loop value* at runtime. When both set the same field the live override wins; the tree is the start value it overrides. Issued through the [[operator-console]]. Distinct from [[stall]] (which controls loop termination, not loop values).

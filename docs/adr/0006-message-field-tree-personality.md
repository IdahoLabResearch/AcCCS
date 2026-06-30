# Per-message field tree as the personality's wire-value model

A [[personality]] previously configured emitted wire values through flat, concern-first structured sections (`power.evse_dc.max_voltage_v`, `capabilities.energy_transfer_mode`, …), where one field was hand-mapped to one or more messages inside the state machines and controllers. This is too coarse for the tool's red-team purpose: an operator could not set an arbitrary field of an arbitrary message, and several emitted fields were hardcoded with no config seam at all (e.g. the DIN `DC_EVSEStatus.EVSEIsolationStatus`, pinned to `Valid`, so the emulator could not reproduce the *Invalid → Valid* isolation-monitoring progression a real ABB charger shows across `ChargeParameterDiscoveryRes`/`CableCheckRes`/`PreChargeRes` — see `ABB_Cadillac_Lyric.pcapng`).

We decided to **replace the structured wire-value sections with a [[message field tree]]**: every field the device emits is addressable by message name and nested field path, mirroring the existing Pydantic message models down to each leaf. ADR-0001 reserved a future "raw protocol-field override" `raw_overrides:` section for this; **this ADR supersedes that note** and goes further — the tree is not an override layer bolted onto the structured fields, it *is* the wire-value model, and the structured wire sections are removed.

## Decision

- **Two-part personality.** A personality is a [[message field tree]] (everything emitted on the wire) plus a **residual section** (everything with no wire representation: `tls`, `slac`, `certificates`, `network`, and behavioral path-selecting flags). The dividing rule is mechanical — on the wire → tree; not on the wire → residual — so a value is never duplicated. Dual-purpose fields that are both emitted and consulted internally (`energy_transfer_mode`, `evse_id`, `supported_protocols`, `auth_modes`, `free_charging_service`) live in the tree as a *single* source; the internal decision (e.g. the DIN ChargeParameterDiscovery `WrongEnergyTransferType` reject-gate) reads that same tree entry.

- **Layered baseline + sparse device overrides.** A baseline tree shipped per role supplies the device's full default output; a device file overrides only the leaves that differ, via YAML anchors; a leaf set nowhere falls back to the message model's default.

- **Construction-time substitution.** Overrides are applied where each message is built, so an overridden value flows into both the emitted bytes *and* any internal logic that reads that field (not a wire-only patch at the encode boundary).

- **Path-strict, value-raw validation.** A field path must resolve to a real model field (typo = hard error, preserving ADR-0001 strictness), but the value is not range/enum-checked — illegal-but-encodable values are the point (extends ADR-0004's "send illegal-but-encodable input"), bounded only by codec serializability. Requires a custom path-walker validator and a "lax build" path on the message models so construction-time substitution can emit values the models would normally reject.

- **Precedence and granularity.** For a field a [[live-override]] can also set: live-override > tree > computed. The tree is keyed per *message type* (one value per repeated message), so the personality still does not script behavior over time; instantaneous loop variation comes from computed logic or a live-override.

- **DIN baseline replicates `ABB_Cadillac_Lyric.pcapng`.** The shipped default DIN trees reproduce that capture field-for-field — the SECC tree from the ABB charger's emitted messages, the EVCC tree from the Cadillac Lyriq's — for both roles, in separate per-role files.

- **Sliced DIN → ISO-15118-2 → ISO-15118-20.** Slice 1 builds the full machinery (tree model, path-walker validator, lax build, construction-time wiring, live-override precedence, baseline migration) end-to-end for DIN only (Req + Res), verifiable in the virtual two-session demo and against the pcap. Later slices add ISO-2 then ISO-20 (DC/AC/BPT/WPT/ACDP).

## Considered Options

- **Keep concern-first structured fields and add a `raw_overrides:` layer on top** (ADR-0001's reserved design). Rejected: two sources of truth for the same field, with precedence ambiguity between the structured value and its override.

- **Wire-only patch at the encode choke point.** Rejected in favor of construction-time substitution: an override should be able to flow into the emulator's own internal decisions, not only the outgoing bytes. (The cost is touching every construction site — the bulk of the work, as ADR-0001 anticipated.)

- **Tree-only for dual-purpose fields, no residual section.** Rejected: non-wire config (TLS posture, SLAC L2 timings, cert paths, interface, backend toggles) has no message to live under and cannot be force-fit into a per-message tree.

- **Per-instance / indexed tree values** (a repeated message carries a sequence of values). Rejected: turns the personality into a behavior-over-time script, which the [[personality]] glossary forbids; runtime variation belongs to computed logic and [[live-override]].

- **Allow advertised vs. accepted to diverge for dual-purpose fields** (separate decision copy in the residual section). Rejected: the single-source rule is simpler and the divergence probe (advertise one mode, reject it) was judged not worth a second source of truth. Trade-off accepted: advertised always equals accepted.

- **Path- and value-strict validation through the real models**, or **free-form unvalidated dict**. Both rejected: the former cannot fuzz illegal values (defeats the purpose); the latter loses typo protection and breaks ADR-0001's strict-validation rule.

## Consequences

- The [[personality]] glossary is redefined (it now includes wire values via the tree) and a [[message field tree]] term is added to `CONTEXT.md`. The "concern-first / future `raw_overrides`" notes in [ADR-0001](0001-personality-yaml-config.md) are superseded.
- Large migration: every stock personality is re-expressed as a per-role baseline tree; the drift test (`tests/personality/test_drift.py`) and `scripts/regen_personality_defaults.py` are reworked around the tree; the simulator/state-machine construction sites read from the tree instead of structured fields.
- A new "lax build" seam exists on the message models (value-raw emission); it is exercised only when a tree leaf is set, leaving normal construction validated.
- Default config changes: EVCC and SECC personalities become separate files, and the symmetric `din_dc_extended.yaml` is retired in favor of per-role DIN files seeded from `ABB_Cadillac_Lyric.pcapng`. The run scripts' default `--config` is updated accordingly ([CLAUDE.md](../../CLAUDE.md) "Configuration").
- The emulator can now reproduce real-device wire details it previously hardcoded — notably the DIN isolation-status progression — closing the gap that motivated this work.
- Work is independently end-to-end testable per protocol slice (DIN first).

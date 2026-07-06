# Per-message field tree as the personality's wire-value model

A [[personality]] previously configured emitted wire values through flat, concern-first structured sections (`power.evse_dc.max_voltage_v`, `capabilities.energy_transfer_mode`, …), where one field was hand-mapped to one or more messages inside the state machines and controllers. This is too coarse for the tool's red-team purpose: an operator could not set an arbitrary field of an arbitrary message, and several emitted fields were hardcoded with no config seam at all (e.g. the DIN `DC_EVSEStatus.EVSEIsolationStatus`, pinned to `Valid`, so the emulator could not reproduce the *Invalid → Valid* isolation-monitoring progression a real ABB charger shows across `ChargeParameterDiscoveryRes`/`CableCheckRes`/`PreChargeRes` — see `ABB_Cadillac_Lyric.pcapng`).

We decided to **replace the structured wire-value sections with a [[message field tree]]**: every field the device emits is addressable by message name and nested field path, mirroring the existing Pydantic message models down to each leaf. ADR-0001 reserved a future "raw protocol-field override" `raw_overrides:` section for this; **this ADR supersedes that note** and goes further — the tree is not an override layer bolted onto the structured fields, it *is* the wire-value model, and the structured wire sections are removed.

## Decision

- **Two-part personality.** A personality is a [[message field tree]] (everything emitted on the wire) plus a **residual section** (everything with no wire representation: `tls`, `slac`, `certificates`, `network`, and behavioral path-selecting flags). The dividing rule is mechanical — on the wire → tree; not on the wire → residual — so a value is never duplicated. Dual-purpose fields that are both emitted and consulted internally (`energy_transfer_mode`, `evse_id`, `supported_protocols`, `auth_modes`, `free_charging_service`) live in the tree as a *single* source; the internal decision (e.g. the DIN ChargeParameterDiscovery `WrongEnergyTransferType` reject-gate) reads that same tree entry.

- **Layered baseline + sparse device overrides.** A baseline tree shipped per role supplies the device's full default output; a device file overrides only the leaves that differ, via YAML anchors; a leaf set nowhere falls back to the message model's default.

- **Construction-time substitution.** Overrides are applied where each message is built, so an overridden value flows into both the emitted bytes *and* any internal logic that reads that field (not a wire-only patch at the encode boundary).

- **Path-strict, value-raw validation.** A field path must resolve to a real model field (typo = hard error, preserving ADR-0001 strictness), but the value is not range/enum-checked — illegal-but-encodable values are the point (extends ADR-0004's "send illegal-but-encodable input"), bounded only by codec serializability. Requires a custom path-walker validator and a "lax build" path on the message models so construction-time substitution can emit values the models would normally reject.

  - **Qualification — value-raw is vacuous for enum-restricted wire fields.** "Bounded only by codec serializability" has no reachable effect when the wire field's type is an *enum restriction*: there, *illegal* (fails enum coercion) coincides with *non-encodable* (the DIN EXI codec can only emit declared enum members), so every legal value encodes and round-trips and no non-coercible value is serializable — there is simply no illegal-but-encodable value to honor. Such fields are therefore validated at personality *load*, not honored raw: a mistyped leaf (e.g. the enum *name* `DC_EXTENDED` instead of the wire *value* `DC_extended` on `ServiceDiscoveryRes → ChargeService → EnergyTransferType`) is rejected up front (#76) rather than deferred to a late codec failure. This is a corollary of value-raw, not a contradiction of it. Generalizing this early check to *other* enum-typed tree leaves (which still fail late at the codec) is left as a separate decision.

- **Precedence and granularity.** For a field a [[live-override]] can also set: live-override > tree > computed. The tree is keyed per *message type* (one value per repeated message), so the personality still does not script behavior over time; instantaneous loop variation comes from computed logic or a live-override.

- **DIN baseline replicates `ABB_Cadillac_Lyric.pcapng`.** The shipped default DIN trees reproduce that capture field-for-field — the SECC tree from the ABB charger's emitted messages, the EVCC tree from the Cadillac Lyriq's — for both roles, in separate per-role files.

- **Sliced DIN → ISO-15118-2 → ISO-15118-20.** Slice 1 builds the full machinery (tree model, path-walker validator, lax build, construction-time wiring, live-override precedence, baseline migration) end-to-end for DIN only (Req + Res), verifiable in the virtual two-session demo and against the pcap. Later slices add ISO-2 then ISO-20 (DC/AC/BPT/WPT/ACDP).

## Considered Options

- **Keep concern-first structured fields and add a `raw_overrides:` layer on top** (ADR-0001's reserved design). Rejected: two sources of truth for the same field, with precedence ambiguity between the structured value and its override.

- **Wire-only patch at the encode choke point.** Rejected in favor of construction-time substitution: an override should be able to flow into the emulator's own internal decisions, not only the outgoing bytes. (The cost is touching every construction site — the bulk of the work, as ADR-0001 anticipated.)

- **Tree-only for dual-purpose fields, no residual section.** Rejected: non-wire config (TLS posture, SLAC L2 timings, cert paths, interface, backend toggles) has no message to live under and cannot be force-fit into a per-message tree.

- **Per-instance / indexed tree values *across time*** (the *same message type*, emitted repeatedly through a session, carries a different value on successive emissions — e.g. `CurrentDemandRes` #1 → 30 A, #2 → 25 A). Rejected: turns the personality into a behavior-over-time script, which the [[personality]] glossary forbids; runtime variation belongs to computed logic and [[live-override]]. **Note:** this rejection is about *the emulator scripting its behavior across successive messages* — it does **not** reach a repeated child element *inside a single message* (a list emitted atomically), which is one static wire payload and *is* addressable; see the issue #81 amendment below.

- **Allow advertised vs. accepted to diverge for dual-purpose fields** (separate decision copy in the residual section). Rejected: the single-source rule is simpler and the divergence probe (advertise one mode, reject it) was judged not worth a second source of truth. Trade-off accepted: advertised always equals accepted.

- **Path- and value-strict validation through the real models**, or **free-form unvalidated dict**. Both rejected: the former cannot fuzz illegal values (defeats the purpose); the latter loses typo protection and breaks ADR-0001's strict-validation rule.

## Consequences

- The [[personality]] glossary is redefined (it now includes wire values via the tree) and a [[message field tree]] term is added to `CONTEXT.md`. The "concern-first / future `raw_overrides`" notes in [ADR-0001](0001-personality-yaml-config.md) are superseded.
- Large migration: every stock personality is re-expressed as a per-role baseline tree; the drift test (`tests/personality/test_drift.py`) and `scripts/regen_personality_defaults.py` are reworked around the tree; the simulator/state-machine construction sites read from the tree instead of structured fields.
- A new "lax build" seam exists on the message models (value-raw emission); it is exercised only when a tree leaf is set, leaving normal construction validated.
- Default config changes: EVCC and SECC personalities become separate files, and the symmetric `din_dc_extended.yaml` is retired in favor of per-role DIN files seeded from `ABB_Cadillac_Lyric.pcapng`. The run scripts' default `--config` is updated accordingly ([CLAUDE.md](../../CLAUDE.md) "Configuration").
- The emulator can now reproduce real-device wire details it previously hardcoded — notably the DIN isolation-status progression — closing the gap that motivated this work.
- Work is independently end-to-end testable per protocol slice (DIN first).

## Amendment — list-nested wire fields (issue #81)

The original decision above conflated two things under one "no indexed tree values" rejection. This amendment separates them.

- **Per-instance *across time* — still rejected.** The *same message type*, emitted repeatedly through a session, must not carry a scripted sequence of values across successive emissions. That is a behavior-over-time script and belongs to computed logic / [[live-override]], not the personality. Unchanged.

- **List-nested *within a single message* — now addressable.** A single message may contain a repeated child element — a list emitted **atomically in one message** (the DIN `ChargeParameterDiscoveryRes → SAScheduleList → SAScheduleTuple`, and its nested `PMaxSchedule → PMaxScheduleEntry`). This is one static wire payload that happens to have repeated structure; it has no time dimension in the *emulator's behavior*. The tree addresses it as a nested **YAML list of maps** mirroring the message model down to each element's leaves (the same way scalar lists like `PaymentOption` already work, extended to lists of sub-models).

**The tree declares the whole list, cardinality included.** The tree is the source of truth for the list's *length* as well as its element values — not merely a positional override into a code-built list. This makes list *cardinality* a first-class red-team surface (emit an illegal count, a duplicate `SAScheduleTupleID`, or an empty list), consistent with ADR-0004's "send illegal-but-encodable input." The construction site stops building the list from structured config; the generic tree walker constructs the elements from the tree via the existing lax-build seam.

**Device overrides restate the whole list.** Layered merge keeps the existing `_deep_merge` semantics — a list value is replaced wholesale, not index-merged — so a device file that wants a different schedule spells out the entire `SAScheduleTuple` list. A schedule is a cohesive unit, and wholesale replacement avoids the fragile "what does overriding element [2] mean when the baseline has one" positional-merge trap.

**Guardrail preserving the original concern.** Cardinality and element values are fixed per message *type*, declared once at load; they do **not** vary across successive emissions of that message during a session. So the personality still does not script behavior over time — the amendment widens *what a single message's static payload can express*, not *whether the payload changes over the session*.

**Generic capability, first consumer DIN `SAScheduleList`.** List-walking lands in the generic message-field-tree walker so future repeated wire elements (ISO-15118-2 `SAScheduleList`, `ServiceList`, …) inherit it. The first consumer retires the structured `power.evse_dc.sa_schedule_pmax_w` / `sa_schedule_duration_s` fields (the wire value now lives *only* in the tree, honoring the mechanical dividing rule) and closes two `ABB_Cadillac_Lyric.pcapng` fidelity deltas: `PMaxScheduleID` becomes a tree leaf set to `1` (was hardcoded `0`), and `RelativeTimeInterval.duration` is simply left unset (it is `Optional`, so it is omitted from the wire, matching the ABB capture).

**Split out.** Making a personality *mandatory to run* and adding a *load-time completeness check* for mandatory tree-sourced fields (with the runtime-computed-field exclusion) is a cross-cutting contract change tracked separately in issue #83, not part of this amendment. See the amendment below for its resolved design.

## Amendment — mandatory personality and the load-time completeness check (issue #83)

A [[personality]] is now **mandatory to run**: the personality-less construction path (a bare `SimEVSEController()`) is retired. Production already always loads one, so this only tightens construction ergonomics and the test layer. With a personality guaranteed present, the loader gains a **load-time completeness check**: a *mandatory* wire field (a Pydantic-required leaf — `Field(...)`, no default) that resolves to **no value** in the merged (baseline + device) tree is a **load-time error naming the message and field path**, not a silent gap that crashes deep in message construction. This moves that failure class to startup, consistent with the "fail at load" spirit of #76.

- **Every field stays enumerable.** This check does **not** narrow what a personality may configure. Per the base decision, every field of every message remains addressable and overridable through the tree; the check only governs the *absence* case for required fields. It is a floor on what must be present, never a ceiling on what may be set.

- **The distinction is `absent → error` vs `absent → fallback`, encoded as an explicit optional-field allowlist.** A required field left out of the tree is an error **unless it is on an allowlist of fields the emulator produces on its own at runtime** (a "has-a-live-fallback" list). Fields on the list are *optional* in the tree — omit them and the builder computes them as it does today; **set** them and the configured value is used (the existing construction-time substitution already honors a present leaf and falls back to the computed value for an absent one, so a listed field pinned in the tree is simply a red-team override, extending ADR-0004's "illegal-but-encodable input" to these fields too). Everything required and **not** on the list is mandatory-in-tree by default.

  The DIN allowlist, per role: **SECC** — `ResponseCode`, `EVSEProcessing`, `EVSEPresentVoltage`/`EVSEPresentCurrent`, and the `CurrentDemandRes` `EVSE{Current,Voltage,Power}LimitAchieved` flags. **EVCC** — `EVCCID` (NIC MAC), `EVReady`, `EVErrorCode`, `ChargingComplete`, and the target/present voltage & current that ramp during the session. The list is **leaf-path granular**, not per-sub-model: `DC_EVStatus` is mixed — `EVReady`/`EVErrorCode` are optional-with-fallback while the adjacent required `EVRESSSOC` is config-only (the Cadillac pins 88 %).

- **`SessionID` stays compute-only for now.** It lives on the message *header/envelope*, which the per-message-body tree does not yet address; making it optionally-specifiable would require extending the tree to header fields, out of scope for this slice. It is neither tree-required nor tree-settable until then.

- **The allowlist is standalone, not derived from a baseline.** Deriving "optional" from what a baseline happens to set would let a baseline that *drops* a required leaf silently reclassify it as optional, masking the very regression the check exists to catch. The list is an independent statement of which required fields have a genuine builder fallback, and is **guarded by a test** that builds each listed field from an empty tree and asserts it still populates — so the list cannot lie and thereby merely relocate the mid-session crash.

- **DIN-only this slice**, structured so ISO-15118-2 / ISO-15118-20 add their own allowlist entries as those slices land, matching the protocol-sliced rollout of everything else in this ADR.

- **Scoped to DIN-*exclusive* personalities, per message present.** The check runs only when DIN SPEC 70121 is the personality's *sole* advertised protocol — the shipped DIN baselines and the devices that `extends` them. A multi-protocol personality (the stock `default-*`, the ISO / no-TLS smokes) still drives its DIN wire values through the builders' pre-tree path and carries an empty or partial tree, so demanding a complete DIN tree there would both mis-fire on shipped personalities and forbid the established "set one field of one message" red-team probe. Within a DIN-exclusive personality the check is *per-message-present*: a required leaf is demanded only for a message the merged tree carries an entry for — the same "validate what the tree actually specifies" stance the #76 energy-transfer-mode check takes. Because a DIN device `extends` a baseline that spells out every DIN message, its merged tree carries every message and gets full coverage; the completeness oracle is preserved without conscripting the pre-tree personalities.

### Considered Options (issue #83)

- **Mark computed fields on the message models (a per-field annotation).** Rejected: the message models are shared with the EXI codec and the parsing path and are role/direction-agnostic — "produced at runtime" is true only for the *emitter* of a given message, so the fact belongs to the personality layer, not the wire schema. An explicit allowlist in the personality/completeness layer also keeps leaf-path granularity (needed for mixed sub-models like `DC_EVStatus`) and mirrors the existing per-message `skip_fields` seam.

- **A prohibitive "computed fields may not appear in the tree" rule.** Rejected in favor of the permissive allowlist: forbidding these fields from the tree would remove a red-team surface (pinning a wrong `ResponseCode`, freezing a reported voltage). Optional-and-overridable is strictly more capable and costs nothing extra, since construction-time substitution already prefers a present leaf over the computed value.

- **Derive the optional set from the shipped baseline.** Rejected: circular — a baseline regression that drops a required leaf would be silently absorbed as "optional" instead of caught.

# MIM message relay-boundary taxonomy

The [[MIM]] terminates two real [[V2G]] sessions at once — a full [[SECC]] state machine toward a real [[EVCC]] and a full EVCC state machine toward a real SECC — and passes the application layer end-to-end, editing a field in flight when the operator arms it. For every field of every message, on every hop, the MIM core has to decide one thing: relay the original bytes, or put a different value on the wire. This ADR fixes the classification that decision reads from, across DIN 70121, ISO 15118-2, and ISO 15118-20.

The classification is not per-device configuration. Whether a field must be rewritten to keep the two sessions coherent, and whether it sits under a signature, are properties of the *protocol*, the same in every session — so they belong in code beside the protocol, not in a [[personality]] an operator tunes per run. This is the opposite end of the spectrum from the [[message field tree]], which is per-device wire output; the two share only an addressing scheme.

Two facts shape everything below. First, [ADR-0006](0006-message-field-tree-personality.md) already gives the project one way to name a field — `protocol → message → nested field path` — used by the message field tree and by [[live-override]]. Second, per the ISO-2 and ISO-20 relay research ([#113](https://github.com/IdahoLabResearch/AcCCS/issues/113), [#114](https://github.com/IdahoLabResearch/AcCCS/issues/114)), XMLDSig signatures cover the raw EXI octets, so a decode-then-re-encode of signed content breaks verification: the MIM cannot both keep two legs coherent on a signed field *and* preserve its seal, because it holds no signing key for the peer it is impersonating.

## Considered Options

- **Classify every field into one of three bins — envelope, content, operator-substitutable.** Rejected: the bins overlap, so "exactly one per field" is unrepresentable. The `SessionID` must be rewritten per hop (envelope) *and* is a thing an operator may want to tamper with (substitutable) — one field, two bins. The overlap is not an edge case; it is structural.

- **Enumerate and classify every field of every message by hand.** Rejected as a maintenance liability. It is hundreds of leaves across three protocols, it fights the default-forward policy ([ADR for #118](https://github.com/IdahoLabResearch/AcCCS/issues/118)) by restating "forward" hundreds of times, and it rots silently the moment a message model gains a field.

- **Auto-rewrite a signed field when coherence appears to require it (e.g. regenerate `GenChallenge` per hop, as the single-role emulator does).** Rejected because it cannot work in a relay. `GenChallenge` is the charger's freshness puzzle; the car echoes it back inside a *signed* AuthorizationReq. If the MIM mints its own puzzle toward the car, the car seals *that* puzzle, and the real charger — expecting the echo of *its* puzzle — sees a mismatch the MIM cannot repair without forging the car's signature. The single-role emulator regenerates `GenChallenge` because it *is* an endpoint; a relay is not, and inherits the opposite obligation.

- **Store the classification as tags on the Pydantic message models.** Rejected, narrowly. Tagging each field in its own model definition keeps the fact glued to the field and immune to drift, but it scatters a tiny rulebook — a handful of rewrite fields, a few signed subtrees — across hundreds of model classes, almost none of which carry a tag. The whole rulebook is small enough to read on one screen, and auditing "what does the MIM touch?" should not mean grepping every model.

- **A standalone code table keyed by the ADR-0006 addressing scheme (chosen).** One file is the MIM's rulebook. It lists only the exceptions to default-forward and marks the signed subtrees, named the one way the rest of the project already names fields.

## Decision

- **Each field carries up to four facts.** *Disposition* is `forward` (relay the original bytes) or `rewrite` (the MIM substitutes a value to keep the two legs coherent). A `rewrite` field also has a *style*: `fresh` (a new value every message, no memory — a send-time timestamp) or `mapped` (a held car-side ↔ charger-side correspondence the MIM remembers for the whole session — the `SessionID`). *Substitutable* says the operator may arm an in-flight edit. *Signed* says the field sits under a signature.

- **The default is `forward`.** Relay the original payload byte-for-byte. This is also what preserves signed content for free: a field never decoded is a field never re-encoded.

- **`rewrite` is a short allowlist of unsigned coherence fields only.** DIN: `SessionID` (`mapped`). ISO-2: `SessionID` (`mapped`), `EVSETimeStamp` (`fresh`). ISO-20: `SessionID` (`mapped`), the header timestamp (`fresh`). Everything not on the list forwards.

- **A `signed` field is never auto-rewritten — it forwards, always.** If keeping the legs coherent appears to demand rewriting a signed field, that demand is the signal that both legs must share the one real value, and the field forwards verbatim. `GenChallenge` is `forward` and `signed`, not `rewrite`, for exactly this reason.

- **`substitutable` is orthogonal to disposition and open by default.** The operator may arm an edit on any field, signed or not. Auto-rewrite is what the MIM does on its own for coherence; substitution is what a human does on purpose to probe the peer. Editing a `signed` field is permitted and yields a broken or self-signed signature — which is itself a valid PKI test ("does the peer reject it?"), surfaced to the operator as a warning, never a silent tamper. The cert-attack semantics on top of this live in [#120](https://github.com/IdahoLabResearch/AcCCS/issues/120); the operator console surface in [#122](https://github.com/IdahoLabResearch/AcCCS/issues/122).

- **Addressing reuses the ADR-0006 scheme** (`protocol → message → field path`), so one taxonomy entry, one message-field-tree leaf, and one live-override all name a field the same way. The `rewrite` fields are stamped in the state handlers today and are not message-field-tree leaves — the taxonomy *names* them in the shared scheme without requiring them to be tree-backed.

- **The classification lives in one standalone code table**, the MIM core's rulebook, holding only the departures from default-forward.

## Consequences

- The MIM core's per-hop decision is a single table lookup against a field it already knows how to name. The common path — forward the original bytes — needs no entry at all.
- Signed content is preserved without special-casing: the default-forward path never decodes it. The only way a seal breaks is a deliberate operator substitution, which is reported.
- The ISO-20 header timestamp is listed `fresh`, but *only if it sits outside the header's signed scope*. If ISO-20 seals the timestamp, the signed-field rule reclassifies it to `forward` — the MIM has no 521-bit key to re-sign. This one leaf is unverified against the ISO-20 signature scope and must be confirmed during the ISO-20 slice; the rule decides it either way, so only the fact is pending. The route is DIN-first, so nothing near-term depends on it.
- The table records exceptions only, so a new field in a message model defaults to `forward` with no edit — correct for the overwhelming majority, and a wrong default only for a newly-added coherence or signed field, which is a deliberate addition anyway.
- "What can the MIM touch, and what does it keep intact?" is answerable by reading one file.

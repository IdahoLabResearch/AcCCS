# AcCCS conformance test framework

AcCCS today has no automated tests. Two large concurrent upgrades — the [[personality]] YAML config consolidation (ADR-0001) and the EXPy EXI codec swap (ADR-0002) — touch every state machine and the codec boundary across DIN 70121, ISO 15118-2, and ISO 15118-20. Without a test framework, both upgrades carry unsafe blast radius. This ADR defines the framework that gates them.

## Scope

This framework covers **conformance testing only** — does the emulator hold up its end of a CCS session correctly. It does *not* cover security-tool capability testing (NMAP integration, MIM forwarding, fault-injection probes). A `tests/conformance/capability/` placeholder reserves a home for that future work but contains no tests today.

AcCCS is a security tool whose primary job is to "stay connected long enough to probe a target." But for that probing to produce valid signals, AcCCS must be spec-conformant enough that session failures can be attributed to the device under test, not to AcCCS itself. The framework verifies that conformance bar.

## Test layers

Four layers, each with a distinct seam, oracle, and substrate.

### 1. Codec layer

- **Seam:** pure functions — `EXI.to_exi_*` / `EXI.from_exi_*`.
- **Oracle:** byte-for-byte equality on encode; decoded-Pydantic equality on decode. Fixtures are `(pydantic_model, expected_bytes)` pairs.
- **Substrate:** in-process, no network.
- **Fixture provenance:** Bootstrapped from the current (Exificient) codec during ADR-0002 Slices 1–3. Rebaselined against EXPy at ADR-0002 Slice 5 — see the amendment to ADR-0002.
- **Speed target:** entire layer runs in <5 seconds.

### 2. State-machine layer

- **Seam:** in-process at `process_message()`. One role under test, a scripted peer feeding inbound messages.
- **Oracle:** state-trajectory match — for a given inbound sequence under a given [[personality]], assert the outbound sequence and final state.
- **Substrate:** in-process, no codec round-trip, no socket.
- **Why this seam:** fastest TDD loop for the per-protocol state-machine refactors that personality YAML Slices 2–4 require. Codec interaction is covered separately at the codec layer; full transport is covered at the E2E layer.
- **Speed target:** entire layer runs in <30 seconds.

### 3. End-to-end (E2E) layer

- **Seam:** two real emulator subprocesses talking over the `acccs_secc` ⇄ `acccs_evcc` veth pair (`setup_veth.sh`).
- **Oracle:** clean session termination — both EVCC and SECC observe `SessionStopReq` → `SessionStopRes` with no protocol-level errors raised. Negotiated protocol / auth mode / energy mode may additionally be asserted per [[scenario]].
- **Substrate:** veth-only in CI. The AcCCS-box Raspberry Pi runs the same suite as a pre-merge job on substantial changes (real TCP/IPv6, real `smbus`/PWM/Devolo NIC path).
- **Inputs:** declarative [[scenario]] YAML files (one per protocol, see Coverage). New E2E tests = new YAML files, no Python edits required.
- **Known coverage gap:** HomePlug GreenPHY / SLAC is not exercised — veth is L2-clean Ethernet. SLAC verification depends on hardware-in-the-loop, which is the major-release acceptance gate (below), not routine CI.

### 4. Replay layer

- **Seam:** offline. Captured wire bytes are fed through the current codec; decoded Pydantic objects are asserted to be valid; re-encoded bytes are asserted equivalent to the original.
- **Oracle:** decode-equivalence across the captured corpus.
- **Substrate:** no network, no emulator processes.
- **Capture provenance:** every entry tagged `source: veth` or `source: hw:<device>`. Veth captures are required for every protocol covered by the suite (regression baseline, cheap to author). Hardware captures are required *somewhere* in the corpus per protocol-and-energy combination (external truth anchor). Their absence is what the major-release real-device-acceptance gate verifies.
- **This layer is implemented by ADR-0002 Slice 4 / issue #15.** Sharpening of that issue is required — see the issue update below.

## Coverage matrix

E2E coverage is deliberately narrow — **one canonical happy-path [[scenario]] per protocol**, exercising the most representative real-world configuration:

- `din-happy.yaml` — DIN 70121, DC.
- `iso2-pnc-dc-tls.yaml` — ISO 15118-2, PnC, DC, TLS on.
- `iso20-pnc-dc-tls.yaml` — ISO 15118-20, PnC, DC, TLS on.

Cross-products (EIM vs PnC, AC vs DC, TLS on/off, BPT, WPT, ACDP) are *not* covered at the E2E layer. They are pushed down to:

- **State-machine layer** for per-feature code-path coverage (scripted peers exercise specific transitions).
- **Codec layer** for encoding-specific concerns.
- **Replay corpus** for wire-level variants.

This is a test-pyramid choice: broad coverage at the cheap layers, narrow coverage at the expensive layer.

The three E2E scenarios are a **hard PR gate from day one**. PRs that break the smoke set do not merge. This is enforced even during the personality YAML rollout, where breakage is expected — each personality slice is responsible for updating scenarios as it lands.

Coverage grows in two ways beyond the smoke floor:

- **Slice-tied growth.** Personality YAML Slices 2–4 must add state-machine tests for every newly-surfaced field; EXPy Slices 1–3 must add codec fixtures for each protocol they extend; EXPy Slice 4 must populate the replay corpus.
- **Risk-based augmentation.** Three explicit scenario-authoring tasks for known-fragile areas: ISO-20 envelope strip/synthesize, ISO-2 PnC certificate chains, app-protocol fallback negotiation. These are authored as Python E2E tests (declarative scenarios won't express fault injection cleanly).

## Substrate and gating

| Gate | Substrate | When it runs |
|---|---|---|
| **Codec layer** | In-process | Every PR, every CI run |
| **State-machine layer** | In-process | Every PR, every CI run |
| **E2E layer** | veth in CI | Every PR, every CI run |
| **E2E layer (Pi)** | AcCCS-box Pi as self-hosted runner | Pre-merge on substantial changes (label-triggered) |
| **Replay layer** | Offline | Every PR, every CI run |
| **Real-device acceptance** | Real EV / EVSE in the lab | Manually triggered, gates **major releases only** |

## Tooling

- **Test runner:** `pytest` + `pytest-asyncio` (the codebase is asyncio-heavy).
- **Dependencies** folded into `requirements.txt`: `pytest`, `pytest-asyncio`.
- **Layout:** under `tests/conformance/`. Structure:

```
tests/conformance/
├── README.md                       # framework scope, layers, gating policy
├── conftest.py                     # pytest fixtures: veth setup/teardown, etc.
├── personalities/                  # test personalities (minimal, synthetic; not for operational use)
├── scenarios/                      # E2E scenarios — YAML corpus
├── captures/                       # replay corpus (veth + hw, tagged)
├── codec/                          # codec unit tests + fixtures
├── state_machine/                  # per-role state-machine tests (evcc/, secc/)
├── e2e/                            # parametrized scenario-driven runner
├── replay/                         # replay-layer runner
└── capability/                     # stubbed placeholder; out of scope today
```

Test personalities live under `tests/conformance/personalities/` and are distinct from operational personalities at the repo-root `personalities/` (which is introduced by ADR-0001). Test personalities are framework fixtures — minimal, synthetic, designed to exercise specific code paths.

## Bootstrap ordering

The framework itself lands in slices, interleaved with the in-flight upgrades:

- **F0 — Foundation.** `tests/conformance/` skeleton, pytest wiring, framework README, three smoke scenarios authored as YAML (marked `xfail` until F3), bootstrap test personalities authored against the pre-rollout `.env`/JSON config so smoke scenarios can run before personality Slice 1 lands. **Lands first.**
- **F1 — Codec layer infrastructure.** Fixture-corpus tooling, fixture format, parametrized pytest case. Empty corpus initially; populated by EXPy Slices 1–3. **Lands before EXPy Slice 1 (#12).**
- **F2 — State-machine layer infrastructure.** Scripted-peer harness at the `process_message()` seam. **Lands before personality Slice 2 (#7).**
- **F3 — Migrate smoke scenarios to personality YAML.** Once personality Slice 1 (#6) lands, swap bootstrap test personalities for YAML files under `tests/conformance/personalities/`; remove `xfail`; smoke set becomes hard PR gate.
- **F4 — Replay layer infrastructure.** Folded into EXPy Slice 4 (#15) — same deliverable.
- **F5 — Stubbed capability placeholder.** `tests/conformance/capability/README.md` only. Lowest priority.

## Per-slice gating

| Issue | Gated by |
|---|---|
| #6 Personality Slice 1 — loader + default.yaml | Codec-layer personality loader unit tests; F0+F3 land alongside |
| #7 Personality Slice 2 — DIN field surfacing | State-machine tests per new field; DIN smoke scenario green |
| #8 Personality Slice 3 — ISO-2 field surfacing | State-machine tests per new field; ISO-2 smoke scenario green |
| #9 Personality Slice 4 — ISO-20 field surfacing | State-machine tests per new field; ISO-20 smoke scenario green |
| #10 Personality Slice 5 — cleanup | Full conformance suite green |
| #11 EXPy Slice 0 — install | Install smoke (already in #11's acceptance criteria) |
| #12 EXPy Slice 1 — translation + DIN fixtures | Codec-layer DIN fixture corpus (Exificient-bootstrapped) |
| #13 EXPy Slice 2 — translation + ISO-2 | Codec-layer ISO-2 fixture corpus |
| #14 EXPy Slice 3 — translation + ISO-20 | Codec-layer ISO-20 fixture corpus |
| #15 EXPy Slice 4 — captured-session replay | Replay layer corpus (veth + hw, tagged) green across all three protocols |
| #16 EXPy Slice 5 — the swap | Full conformance suite green; codec fixtures rebaselined per amended ADR-0002 |
| #17 EXPy Slice 6 — cleanup | Docs review only |

## Considered Options

- **Byte-for-byte E2E pcap comparison.** Rejected as the E2E oracle: EXI encodings contain non-deterministic fields (session IDs, timestamps, signatures); the masking overhead outweighs the diagnostic value. Byte equality is used only at the codec layer where inputs are pinned by fixtures.
- **State-trajectory match at the E2E layer.** Rejected: too brittle. Any intentional behavior change would fail the gate; the personality YAML rollout will introduce many such intentional changes. State-trajectory match is used selectively at the state-machine layer where inputs and outputs are tightly scoped.
- **Pure in-process E2E (asyncio.Queue transport shim).** Rejected: would fake the network stack. AcCCS is a network security tool — the IPv6 / TCP / TLS / SDP path is part of what's verified.
- **Full coverage matrix at E2E (30+ scenarios).** Rejected as front-loaded; broad coverage pushed down to faster layers per the test-pyramid principle.
- **Capability tests in the same framework.** Rejected for now; security-tool features (NMAP, MIM) haven't stabilized. Stubbed placeholder reserves the home.

## Consequences

- CI runners need `CAP_NET_ADMIN` to create the veth pair for the E2E layer. GitHub-hosted runners support this; self-hosted runners need explicit configuration. The AcCCS-box Pi must be configured as a self-hosted runner for the pre-merge Pi job.
- HomePlug GreenPHY / SLAC is not covered short of hardware-in-the-loop. This is an accepted gap, documented in the framework README.
- The codec-layer fixture corpus is bootstrapped from the current implementation (Exificient → EXPy). It can only catch *regressions from today's behavior*, not pre-existing bugs. The hardware-tagged replay corpus and the major-release real-device-acceptance gate are the mitigations.
- Veth captures and operational personalities live in distinct directories from their test-fixture counterparts (`captures/` and `personalities/test/` under `tests/conformance/`, vs the repo-root operational locations). This is deliberate: test fixtures and operational artifacts have different audiences and lifecycles.
- Framework tooling deps (`pytest`, `pytest-asyncio`) are folded into `requirements.txt` rather than split into a separate dev requirements file.

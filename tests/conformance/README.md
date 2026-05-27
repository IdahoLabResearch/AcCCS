# AcCCS conformance test framework

This directory holds the conformance test suite for AcCCS — the framework that
verifies the EVCC and SECC emulators hold up their end of a CCS session
correctly. The architecture is defined in
[`docs/adr/0003-conformance-test-framework.md`](../../docs/adr/0003-conformance-test-framework.md);
this README is the operator-facing companion.

## Scope

This suite covers **conformance** only — "does AcCCS speak the protocol
correctly enough that a session failure can be attributed to the device under
test, not to AcCCS itself." It does *not* cover security-tool capability
testing (NMAP integration, MIM forwarding, fault injection). See
[`capability/README.md`](capability/README.md).

## Layers

Four layers, each with a distinct seam, oracle, and substrate.

| Layer | Substrate | Seam | Oracle |
|---|---|---|---|
| [`codec/`](codec/) | in-process | `EXI.to_exi` / `EXI.from_exi` | byte-equal encode, pydantic-equal decode |
| [`state_machine/`](state_machine/) | in-process | `State.process_message()` | state-trajectory match |
| [`e2e/`](e2e/) | veth pair (`acccs_secc` ⇄ `acccs_evcc`) | two emulator subprocesses | clean `SessionStopReq` / `SessionStopRes` |
| [`replay/`](replay/) | offline (captured wire bytes) | codec round-trip | decode-equivalence |

Speed targets: codec layer < 5 s, state-machine layer < 30 s.

## Running

From the repo root:

```
pytest tests/conformance/
```

### Veth requirement

The E2E layer needs the `acccs_secc` ⇄ `acccs_evcc` veth pair from
[`setup_veth.sh`](../../setup_veth.sh). Creating veth interfaces requires
`CAP_NET_ADMIN` (sudo on most Linux distros).

- **Local development:** run `./setup_veth.sh` once per boot; the E2E tests
  reuse the existing pair.
- **GitHub-hosted runners:** have `CAP_NET_ADMIN` by default. The CI workflow
  invokes `setup_veth.sh` as part of the job.
- **Self-hosted runners (incl. the AcCCS-box Pi):** must be configured to allow
  the runner user passwordless `sudo` for `ip link`. See ADR-0003.

If the veth pair is not present, the E2E tests are **skipped** rather than
failing — but those skips will block a merge once F3 lands, because the CI
workflow always provisions the pair.

## Gating policy

The three smoke scenarios (`scenarios/din-happy.yaml`,
`scenarios/iso2-pnc-dc-tls.yaml`, `scenarios/iso20-pnc-dc-tls.yaml`) are a
**hard PR gate from this PR forward**.

All three scenarios run as hard gates — no `xfail` markers. Once the
personality YAML loader (#6) and the ISO-2 / ISO-20 personality slices
(#7, #8, #9) landed, F3 was completed and the smoke set was un-xfailed.

Per ADR-0003: "PRs that break the smoke set do not merge. This is enforced
even during the personality YAML rollout, where breakage is expected — each
personality slice is responsible for updating scenarios as it lands."

## Coverage gaps

### SLAC / HomePlug GreenPHY

veth is L2-clean Ethernet. The PLC association handshake (SLAC) does not run
over it. **SLAC behavior is not exercised by this suite.** It is verified by
the major-release real-device acceptance gate (ADR-0003), not by routine CI.

### Cross-product breadth at the E2E layer

E2E coverage is intentionally one canonical happy-path scenario per protocol.
Cross-products (EIM vs PnC, AC vs DC, TLS on/off, BPT, WPT, ACDP) are pushed
down to the codec, state-machine, and replay layers. This is the
test-pyramid choice documented in ADR-0003.

## Test personalities

`personalities/` holds **minimal, synthetic test personalities** authored
as YAML and validated by the same Pydantic loader (`app.shared.personality`)
the production emulators use.

These are framework fixtures — not operational personalities. The operational
personality directory lives at the repo root (`personalities/`).

## Layout

```
tests/conformance/
├── README.md                  this file
├── conftest.py                pytest fixtures: veth setup, emulator lifecycle
├── pytest.ini                 (rootdir; pytest discovery)
├── personalities/             test personalities (YAML, validated by app.shared.personality)
├── scenarios/                 scenario YAMLs (the E2E corpus)
├── captures/                  replay corpus (veth + hw, tagged) — empty today
├── codec/                     codec layer tests + fixtures
├── state_machine/             scripted-peer state-machine tests (evcc/, secc/)
├── e2e/                       scenario-driven E2E runner
├── replay/                    replay-layer runner — empty today
└── capability/                placeholder; out of scope
```

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
- **AcCCS-box Pi (self-hosted):** does **not** use veth. It has real
  `acccs_evcc` / `acccs_secc` USB-Ethernet NICs (renamed once by the operator's
  `rename_eth.sh`), so the E2E layer runs over them directly and
  `conformance-pi.yml` never calls `setup_veth.sh`. See *Pi runner maintenance*
  below and ADR-0003 § Substrate and gating.

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

## Requesting a Pi run

The hosted `conformance.yml` job runs on every PR but is veth-only on
GitHub-hosted Ubuntu, with `smbus` stripped and the SMBus path stubbed. It
cannot catch Pi-specific breakage — the real `smbus` build/import on ARM, PWM
PCB I/O, or scapy on the Devolo NICs.

The **AcCCS-box Pi** closes that gap. It is registered as a self-hosted runner
and runs the same suite against real Pi hardware via
[`conformance-pi.yml`](../../.github/workflows/conformance-pi.yml). Per ADR-0003
this is a **label-triggered pre-merge gate, not a hard gate on every PR**.

Unlike the hosted job, the Pi runs the E2E layer **non-virtual** (the workflow
sets `ACCCS_E2E_VIRTUAL=0`) over its real `acccs_evcc` / `acccs_secc` USB NICs,
so a Pi run actually exercises the SMBus/I2C relay and PWM path the hosted job
stubs out. That is the whole point of requesting one.

### When to request one

Add the `needs-pi-run` label to a PR when the change is likely to touch
Pi-specific paths — anything under the `smbus`/I2C, PWM, or NIC/scapy layers,
or a dependency bump that affects how those build on ARM. Routine
codec/state-machine/scenario changes do not need it; the hosted job covers them.

### How to request and read the result

1. On the PR, add the **`needs-pi-run`** label. This triggers the
   `Conformance suite (Pi)` workflow on the Pi runner.
2. Watch the **`conformance-pi`** check on the PR. Green = the suite passed on
   real Pi hardware; red = open the check log to see which layer failed.
3. **To re-run** (e.g. after a new commit), remove the `needs-pi-run` label and
   add it again. The workflow keys on the *label-added* event, so a fresh add
   is what re-triggers it; pushing a commit alone does not.

### If the Pi runner is offline

GitHub queues the job against the `acccs-box` runner. If the runner is offline,
the check sits **pending/queued** rather than failing — it will not go red on
its own, and it will pick up and run once the runner reconnects.

- Check runner health: GitHub repo → **Settings → Actions → Runners**. A
  healthy `acccs-box` runner shows **Idle** (green); an offline one shows
  **Offline** (grey).
- If it is offline, restart the runner service (see *Pi runner maintenance*
  below) and the queued job drains automatically.
- If a Pi run is not coming back in time and the change does not actually touch
  Pi-specific paths, a maintainer may remove the `needs-pi-run` label and merge
  on the hosted gate alone — the Pi gate is advisory, not mandatory per ADR-0003.

## Pi runner maintenance

The AcCCS-box Pi is registered as a self-hosted GitHub Actions runner with the
labels **`self-hosted`** and **`acccs-box`** (the workflow's `runs-on` targets
that pair). It runs as a service so it survives reboots and reconnects on its
own. Initial registration and the items below are **operator/maintainer tasks**
— they require shell access to the Pi and repo admin rights.

### Runner prerequisites (provision once)

These must exist on the Pi before the workflow can pass; the workflow does
*not* install them:

- **Python 3.13** with the project's `requirements.txt` installable, exposed on
  the runner service's PATH. The AcCCS-box Pi runs Debian 13 (trixie), whose
  only interpreter is Python 3.13; deps are installed into a venv whose `bin` is
  prepended to the runner's `.path` file (e.g. `~/actions-runner/.path`). The
  systemd runner does **not** source `.bashrc`, so an auto-activated venv is
  invisible to jobs — `.path` is how the job's `python` resolves to it. (System
  Python on trixie is PEP-668 externally-managed and refuses `pip install`, so a
  venv is required.)
- **i2c headers + a C/C++ build toolchain** (CMake ≥3.20, Ninja, a compiler) so
  `smbus` and the EXPy `libcbv2g` extension build during `pip install`.
- **The `cap_net_raw=eip` file capability on the venv interpreter** so the SLAC
  raw socket opens without a per-run `setcap` (the hosted job sets this itself;
  the Pi interpreter carries it persistently).
- **Real `acccs_evcc` / `acccs_secc` USB-Ethernet NICs**, renamed once by the
  operator's `rename_eth.sh` (MAC-matched systemd `.link` files: "PEV" →
  `acccs_evcc`, "EVSE" → `acccs_secc`), with both USB adapters connected and
  coupled. The Pi runs E2E over these real NICs — it does **not** use a veth
  pair, and the workflow must never call `setup_veth.sh` (its teardown would
  `ip link delete` the identically-named real NICs).

The workflow generates TLS/PnC certificates itself (`create_certs.sh -v iso-2`)
each run, so certs are not a provision-once prerequisite.

### Registering / re-registering the runner

From the GitHub repo → **Settings → Actions → Runners → New self-hosted
runner**, copy the `./config.sh` command and registration token, then on the Pi:

```bash
# in the runner install dir (e.g. ~/actions-runner)
./config.sh --url https://github.com/IdahoLabResearch/AcCCS \
            --token <REGISTRATION_TOKEN> \
            --labels acccs-box \
            --name acccs-box
sudo ./svc.sh install     # install as a service
sudo ./svc.sh start       # start it; survives reboot
```

The `--labels acccs-box` is required — the workflow will never schedule onto a
runner that lacks it.

> **GitHub auto-deregisters idle runners.** A self-hosted runner that has not
> connected for a sustained period (~2 weeks; observed pruned after ~10 days
> idle) is removed server-side, so `acccs-box` will silently vanish from
> **Settings → Runners** even though the Pi's service still exists. If the runner
> shows offline/deregistered, re-register: `./config.sh remove --local`, then
> re-run the registration block above with a fresh token, and **re-apply the venv
> `bin` prepend to `.path`** — `config.sh` regenerates `.path` without it, which
> otherwise leaves the job's `python` unable to resolve project deps.

### Rotating the runner token

Registration tokens are short-lived (they expire ~1 hour after issue) and are
only used at `config.sh` time, so there is no long-lived secret to rotate for
normal operation. To re-register (token expired, runner re-imaged, or repo
moved):

```bash
sudo ./svc.sh stop
./config.sh remove --token <REMOVAL_TOKEN>   # token from Settings → Runners
# then re-run the registration block above with a fresh registration token
```

Both the registration and removal tokens come from the same **Settings →
Actions → Runners** page.

### Restarting the service

```bash
sudo ./svc.sh status      # is it running?
sudo ./svc.sh stop
sudo ./svc.sh start
```

After a restart, any job that was queued while the runner was offline drains
automatically.

### Where logs live

- **Live job output:** on the PR's `conformance-pi` check, and in the repo's
  **Actions** tab.
- **Runner service logs (systemd):** `journalctl -u actions.runner.* -f`.
- **Per-job worker diagnostics on the Pi:** the `_diag/` directory inside the
  runner install dir holds `Runner_*.log` and `Worker_*.log` files.

### Security note

A self-hosted runner executes PR code on your own hardware (and the runner has
passwordless `sudo`). `conformance-pi.yml` therefore guards its job with a
head-repo check — `github.event.pull_request.head.repo.full_name ==
github.repository` — so fork-head code can never run on the Pi even if someone
mislabels a fork PR. Keep that guard in place; don't relax the workflow to run
on fork PRs.

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

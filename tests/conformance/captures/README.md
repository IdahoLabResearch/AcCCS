# Replay corpus — captured sessions

Captured wire bytes from real or veth charging sessions, consumed by the
replay layer (`tests/conformance/replay/`). Each entry is two files:

- `<source>/<name>.jsonl` — one record per EXI codec call (encode or
  decode), written by `app/shared/exi_capture.py`. Each line is
  `{ts, dir, ns, model, root, hex}`.
- `<source>/<name>.yaml` — provenance metadata.

## Provenance metadata

```yaml
source: veth                 # captured between two AcCCS emulators
# or
source: hw:<device-label>    # captured against a real device (EV or EVSE)
protocol: din70121           # one of: din70121 | iso15118-2 | iso15118-20
energy_mode: dc              # ac | dc | bpt | wpt | acdp
captured_at: 2026-05-27
secc_personality: din_dc_extended-secc
evcc_personality: din_dc_extended-evcc
messages: 116
notes: |
  Free-form context. Hardware identity, lab conditions, anything a
  future reader will want.
```

## (Re)building the veth corpus

Drive the in-scope personality combos through `setup_veth.sh` then:

```
python scripts/capture_replay_corpus.py
```

The script writes each combo's JSONL + YAML under `veth/`. The capture
tap (`app/shared/exi_capture.py`) is enabled per-process via the
`--capture <path>` flag the script passes to `run_secc.py` /
`run_evcc.py`. CLI args survive `sudo`, where custom env vars do not, so
this replaces the older `/tmp/acccs_exi_capture_path` sentinel
mechanism. With no `--capture` and no `ACCCS_EXI_CAPTURE` env var, the
codec's hot path is zero syscalls — production runs never consult a
sentinel file.

Concurrent appenders (SECC + EVCC root processes writing the same JSONL)
are serialised by `fcntl.LOCK_EX` per record, so a large payload
exceeding `PIPE_BUF` (4096 B) cannot tear across writes. The loader
(`tests/conformance/replay/_corpus.py`) additionally tolerates malformed
JSONL lines: it skips them with a logged warning naming the file and
line, so a re-capture mishap does not crash the replay suite.

## Coverage policy

Per ADR-0003:

- **Veth captures** are required for every protocol covered by the
  suite — cheap to author, useful as a regression baseline. Required.
- **Hardware captures** are required *somewhere* in the corpus per
  protocol-and-energy combination — they are the external truth anchor
  and what the major-release real-device-acceptance gate verifies.

### Veth coverage shipped in Slice 4 (#15)

| Capture            | Protocol     | Energy mode | Personality                       | Records |
|--------------------|--------------|-------------|-----------------------------------|---------|
| `din-dc`           | din70121     | dc          | `din_dc_extended-{secc,evcc}`     | 116     |
| `iso2-eim-dc`      | iso15118-2   | dc          | `iso2_eim_dc-{secc,evcc}`         | 122     |
| `iso2-pnc-dc`      | iso15118-2   | dc          | `iso2_pnc_dc-{secc,evcc}`         | 130     |
| `iso20-ac`         | iso15118-20  | ac          | `iso20_ac-{secc,evcc}`            | 88      |
| `iso20-dc`         | iso15118-20  | dc          | `iso20_dc-{secc,evcc}`            | 136     |

Record counts are the JSONL line count per capture. The deduplicated
replay test count fluctuates by ±a few between re-captures because some
fields are session-randomised (challenges, IDs, nonces) and produce
distinct `(ns, root, hex)` keys each run. The post-#25 re-capture moved
the headline numbers from 167 passed / 24 skipped to **165 passed / 24
skipped** in the replay suite; the delta is a natural consequence of the
session-randomised fields and is not a behavioural regression.

### Known gaps (deferred to follow-up issues)

#### Hardware corpus — entirely deferred

No hardware captures land in Slice 4. The Slice 4 grilling decision
(issue #15) defers them to a dedicated follow-up issue; per ADR-0003 the
hardware corpus is what the major-release real-device-acceptance gate
verifies, and that gate has not been scheduled. Slice 5 ships against
veth alone with the understanding that hardware captures must be added
before the next major release.

#### Protocol-and-energy combinations not capturable today

| Protocol     | Energy mode | Reason                                                                                                            |
|--------------|-------------|-------------------------------------------------------------------------------------------------------------------|
| iso15118-2   | ac          | No ISO-2 AC personality ships in `personalities/` today (only DC variants).                                       |
| iso15118-20  | ac-bpt      | End-to-end path verified (#106); no BPT veth capture shipped yet.                                                 |
| iso15118-20  | dc-bpt      | End-to-end path verified (#106); no BPT veth capture shipped yet.                                                 |
| iso15118-20  | wpt         | Codec fixture covers `WPTPairingReq` alone; no end-to-end state-machine path.                                     |
| iso15118-20  | acdp        | Codec fixture covers `ACDPConnectReq` alone; no end-to-end state-machine path.                                    |

These combinations are surfaced here so subsequent personality / state-machine
slices can pick them up explicitly, and so the Slice 4 human-verification
gate is informed of the deficit.

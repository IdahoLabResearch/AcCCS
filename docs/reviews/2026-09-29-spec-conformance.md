# AcCCS spec-conformance review — 2026-09-29

## 1. Scope and method

**Reviewed:** the `development` working tree at commit `518c26a` ("De-globalize per-leg
TLS/PKI config off shared_settings (#123)") plus the one uncommitted change
(`app/shared/messages/iso15118_2/datatypes.py`: ISO-2 `ServiceName` enum → free string, with its
new test `tests/conformance/codec/test_service_name_free_string.py`).

**Specs (pre-extracted text; PDF page = form-feed count):**
- DIN SPEC 70121:2014 (`[V2G-DC-nnn]`), incl. Annex A XSD (p196) and Annex A/B SLAC (p22-58).
- ISO 15118-2:2014 (`[V2G2-nnn]`), incl. Annex C XSD (p272-276) and Annex K requirement index.
- ISO 15118-20:2022 (`[V2G20-nnnn]`) — the XSD is *not* in the extracted text, so a few enum
  questions carry `verify-XSD`.
- ISO 15118-3:2015 (`[V2G3-…]`) for SLAC / data link.
- IEC 61851-1 and IEC 61851-23 were **not available** (TOC previews only). Anything resting on
  CP-state timing, PWM duty, CP debounce, pre-charge current/voltage tolerance or the emergency
  shutdown reaction is stated from the DIN/ISO text and the public CCS design guide / public plugfest
  deck, and tagged **verify-IEC**.

**Layers covered:** SLAC/data link, SDP, V2GTP, TCP/TLS, SAP, SessionID handling, and the full
application state machines for DIN (both roles), ISO-2 (both roles), ISO-20 DC (both roles),
ISO-20 AC (both roles), the cross-cutting timer and CP-synchronisation obligations, ResponseCode
semantics / error handling / receive tolerance, the message models (pydantic facets vs XSD), the
shipped personalities, and the 2026-09-23 field captures (Charger A, Charger B, Charger C,
Charger D; ISO-2 EIM and DIN, all plaintext).
Charger identities are anonymized as Charger A–D; capture files are referenced by the same letter
prefix (e.g. `A_3 s2`, `C_fail_2`). The mapping to the original pcap file names is kept outside the
repository.

**Not covered:** BPT (AC and DC), WPT, ACDP; ISO-20 side streams (ScheduleRenegotiation,
MeteringConfirmation) beyond noting they crash; ISO-2/-20 certificate-installation cryptography;
TLS 1.3 resumption/OCSP; the operator console; MIM relay code (#111); the Pi's actual working copy
(`/home/pi/AcCCS_private-dash_202`) and its logs — inferred from file mtimes only.

**Method.** Thirteen reviewers (din-evcc, din-secc, iso2-evcc, iso2-secc, iso20-dc-evcc,
iso20-dc-secc, iso20-ac-evcc, iso20-ac-secc, timers-cp-sync, responsecode-tolerance, transport-sap,
slac, pcap-forensics) each walked one slice read-only and produced 263 raw findings. This
aggregator de-duplicated them into the `SC-nnn` findings below, resolved the disagreements
(section 8) against the spec text and code, and then ran:

| Run | Result |
|---|---|
| `pytest tests/ --ignore=tests/conformance/e2e` | **1007 passed, 1 failed** (`test_din_allowlist_fallback_guard.py`, `KeyError: 'acccs_evcc'` — the veth pair did not exist yet). After `setup_veth.sh` that module passes 3/3 → **1008/1008**, 19 s. No test failure relates to any finding. |
| Reviewer repro scripts (`scratchpad/repro/*.py`, `repro_iso20_secc.py`, `din-evcc-work/probe_*.py`, `work/roundtrip.py`) | All reproduce what their authors claimed (details cited per finding as "probe"). |
| Virtual demo **ISO-2** (`default-secc` / `default-evcc`, TLS 1.3, Contract/PnC selected) | Full session SLAC → SDP/TLS → … → SessionStop, EVCC `Going to state A`; EXI capture decoded. |
| Virtual demo **DIN** (per-role defaults, no `--config`, plaintext) | Full session, `Session ended in SessionStop`, `Going to state A`; EXI capture decoded. |
| Virtual demo **ISO-20 DC** (`iso20_dc-secc` / `iso20_dc-evcc`, Scheduled control mode) | Full session; EXI capture decoded. |
| Virtual demo **ISO-20 AC** (`iso20_ac-secc` / `iso20_ac-evcc`, Scheduled) | Full session; EXI capture decoded. |
| Second cycle (SAP list mutation) | Not run live (needs an SECC that flips TLS between cycles); verified offline instead — `EVCCConfig.supported_protocols` and the list `create_sap` mutates are the same object. |

All emulators were stopped afterwards (`pgrep` clean). Demo logs and `--capture` JSONL files are
in the review scratchpad (`demo_{iso2,din,iso20dc,iso20ac}_{secc,evcc}.{log,jsonl}`); the values
quoted below as "demo wire" were decoded from those captures with the project codec.

Severity buckets (from the briefing): **S1** we misbehave against a conformant peer
(session-breaking or wrong wire behaviour); **S2** we reject/abort on a decodable peer value that
should be logged and continued; **S3** defined-but-unenforced timer, missing optional behaviour,
wrong-but-harmless value; **S4** hardware-gated. Confidence: **confirmed** (code path traced end to
end, or reproduced) / **plausible**.

---

## 2. Executive summary

**The field story.** Every field failure on 2026-09-23 is explained by three of our defects and
one personality slip; none is a charger fault except cosmetically:

1. **CableCheck closures (Charger D ×4, Charger C, A_3):** our EVCC never drives CP State C —
   `SimEVController.enable_charging` is `pass` (SC-001). Chargers FAILED/closed 0.5–2 s after
   the first CableCheckReq, exactly the [V2G2-918] / [V2G-DC-547] window. Every run after the
   private copy's 11:27 State-C edit passed CableCheck.
2. **Silent 5 s aborts after ServiceDiscoveryRes (Charger A):** the committed `ServiceName` enum
   rejects `"DC_CHARGING"` (SC-033); fixed by the uncommitted change (verified by replay).
3. **Silent 5 s aborts at SessionSetup (Charger C ISO-2) and CableCheck (Charger C DIN):** ISO-2
   `EVSEID min_length=7` (SC-032) and DIN `NotificationMaxDelay le=65535` although the DIN XSD
   types it `xs:unsignedInt` (SC-002). All three share one mechanism: pydantic rejection →
   `rcv_loop` catch-all → `stop()` sleeps 2+3 s → FIN, nothing sent (SC-031).
4. **Charger A WeldingDetectionRes FAILED ×3:** leaning peer (Charger A samples CP ~60 ms after the
   request instead of waiting up to 1.5 s per [V2G2-920]); our contribution is a ~3 ms
   relay→request gap and `EVReady=true` while stopping (SC-066). Not the State-C bug.
5. **PreCharge:** we end pre-charge after a fixed 5 polls against a 20 kV comparator (SC-067)
   and, as SECC, report a constant 1 V present voltage (SC-029) — the "real vehicles fail at
   PreCharge" ceiling on the SECC side.
6. **Charger C DIN 800 V target vs 410 V EV maximum** is a device-personality inconsistency (SC-068).

**Top ten cross-cutting defects**

| # | ID | Sev | One line |
|---|---|---|---|
| 1 | SC-001 | S1 | EVCC never drives CP State C / never returns to B (all three protocols, DC and AC) — every real DC charger fails us at CableCheck. |
| 2 | SC-031 | S2 | Any decodable-but-out-of-model peer value ends the session silently (5 s FIN, no FAILED, no SessionStopReq) — the umbrella behind SC-002/032/033/034/035/036. |
| 3 | SC-002 | S1/S2 | `NotificationMaxDelay le=65535` on the DIN model although DIN's XSD is `unsignedInt` (schema-legal value rejected); ISO-2 twin should log-and-continue. |
| 4 | SC-003 | S1 | `ChargingComplete` is filled from `continue_charging()` — inverted on the wire (TRUE on PowerDeliveryReq Start) and burns loop cycles / the operator gate as a side effect. |
| 5 | SC-029 | S1 | SECC PreChargeRes/CurrentDemandRes/DC_ChargeLoopRes report a constant 1 V / 1 A; EVSEPresentVoltage never tracks the EV target (all three protocols). |
| 6 | SC-004 | S1 | SECC answers CableCheckRes/PreChargeRes FAILED on any `EVErrorCode != NO_ERROR` — an explicit "shall not influence" in DIN and ISO-2. |
| 7 | SC-005/006 | S1 | ISO-20 WARNING_StandbyNotAllowed terminates the session (SECC); EVSENotification Pause/ExitStandby/MeteringConfirmation/ScheduleRenegotiation raise `NotImplementedError` (EVCC). |
| 8 | SC-024 | S1 | TLS generation is pinned by a flag (1.3-only with client cert, or 1.2-only); ISO-20 offered/selectable over TCP/TLS 1.2; TLS 1.3 curve is P-256 only. Emulator-vs-emulator hides all of it. |
| 9 | SC-060/061 | S3 | Several FAILED templates cannot be EXI-encoded (`evse_id="1234567"`, empty ISO-20 lists) and every FAILED carries a `Notification(ParsingError)` DIN forbids — the SECC goes silent exactly when the spec wants a FAILED. |
| 10 | SC-028 | S1 | SECC SLAC latches the first RunID for the whole cycle and leaves SLAC for good after MATCH.CNF — one lost frame parks the SECC until the operator quits. |

Counts after merge: **S1 30 · S2 19 · S3 33 · S4 3** (85 merged findings from 263 raw).

---

## 3. Findings by severity

Format: ID · title · **Severity** · Confidence (what promoted it) · Protocols/roles · Requirements
(PDF page) · Where · Spec says / Code does · Failure scenario · Evidence · Tags · Fix direction.
Reviewer sections are cited as `[slice F-n]`.

### S1 — we misbehave against a conformant peer

#### SC-001 · EVCC never drives CP State C before CableCheckReq / PowerDeliveryReq(Start) and never returns to State B after the Stop
- **S1** · confirmed (pcap + code) · DIN EVCC, ISO-2 EVCC (DC and AC), ISO-20 EVCC (DC and AC).
- Req: [V2G-DC-501] p169, [V2G-DC-502] p171, [V2G-DC-560] p19; [V2G2-912]/[913]/[914] p189,
  AC [V2G2-846]–[849] p187-188; [V2G20-912]/[913]/[914] p398, AC [V2G20-1617]/[847]/[848] p391.
  SECC-side reactions [V2G2-918]/[922] p189-190, [V2G-DC-547] p175 (1.5 s), [V2G20-918] p399.
- Where: `app/evcc/controller/simulator.py:1273-1275` (`enable_charging` is `pass`);
  `app/evcc/controller/pev.py:196-203, 246-256` (controller built without a CP setter; `setState`
  only ever A/B); call sites `din_spec_states.py:457,725`, `iso15118_2_states.py:842,872,955`,
  `iso15118_20_states.py:979,1052`; `app/shared/relays.py:263-284` already maps `PEVState.C`.
- Spec: C/D after CPDRes (ISO-20: ScheduleExchangeRes Finished) and before CableCheckReq; B after
  PowerDeliveryRes(Stop) before the next request; AC: C ≤250 ms after PDReq(Start), B ≤250 ms
  after PDReq(Stop). Code: the hooks fire at the right points but do nothing; CP stays B all session.
- Failure: conformant DC SECC answers CableCheckRes FAILED / closes within ~1.5 s; AC SECC never
  closes its contactor → FAILED_ContactorError.
- Evidence: Charger D no202_1/no202_2/yes202_1 (SECC FIN +1.51–1.58 s after 1st CableCheckReq, 2nd
  Res still `EVSE_Ready`), A_3 s2 (FAILED +464 ms), C_badStateC_4 (FIN +2.06 s); every
  run after the private copy's 11:27:50 edit passed CableCheck. `[din-evcc F-1] [iso2-evcc F-1/F-2]
  [iso20-dc-evcc F-1] [iso20-ac-evcc F-1] [timers F-1] [pcap F-1]`.
- Tags: already-fixed-in-private-copy (DC correct; AC timing needs adjustment — section 7).
- Fix: port the `cp_state_setter` seam + `enable_charging` body (section 7); add AC send-site hooks.

#### SC-002 · `NotificationMaxDelay` bounded to 65535 — schema-legal DIN values rejected (S1 on DIN), ISO-2 values not logged-and-continued (S2)
- **S1 (DIN) / S2 (ISO-2)** · confirmed (pcap, codec round-trip, pasted box log) · DIN EVCC, ISO-2 EVCC (DC+AC EVSEStatus).
- Req: DIN Table 66 p135 and XSD p196 `<xs:element name="NotificationMaxDelay" type="xs:unsignedInt"/>`;
  [V2G-DC-636] p135 ("the EVCC shall ignore the value"); ISO-2 XSD p272 `unsignedShort`,
  [V2G2-678] p195 (ignore when EVSENotification=None).
- Where: `app/shared/messages/din_spec/datatypes.py:136-139` (comment even says "unsignedShort");
  `app/shared/messages/datatypes.py:578-581` (shared `EVSEStatus`, inherited by ISO-2 `DCEVSEStatus`/`ACEVSEStatus`
  and — via `din_spec/body.py:10-11` — by the DIN responses); failure path SC-031.
- Failure: Charger C DIN CableCheckRes `NotificationMaxDelay=50331648` (3<<24) → EVCC silent, FIN +5.0 s.
- Evidence: C_fail_2 frame 87; `work/roundtrip.py` re-encodes the value to Charger C's exact bytes
  (value is genuinely on the wire; codec is fine); C_full_3 accepted the same bytes only
  because the Pi was hand-patched between 14:03 and 14:14. `[din-evcc F-4] [iso2-evcc F-6] [rc-tol F-3] [pcap F-2]`.
- Tags: hot-patched-on-box (patch in neither tree).
- Fix: DIN class `ge=0, le=4294967295`; ISO-2 class drop `le` (log if > 65535).

#### SC-003 · `ChargingComplete` sourced from `continue_charging()` — inverted value with side effects
- **S1** · confirmed (demo wire ISO-2 and DIN; probe; pcap) · DIN EVCC, ISO-2 EVCC.
- Req: DIN Table 47 p119 / ISO-2 DC_EVPowerDeliveryParameter p139 ("If set to TRUE, the EV indicates
  that full charge (100 % SOC) is complete"); [V2G-DC-421], [V2G2-847].
- Where: `app/evcc/controller/simulator.py:913-930` (`charging_complete=await self.continue_charging()`),
  `:861-885` (`continue_charging` decrements `charging_loop_cycles`, bumps SOC, consumes the operator
  one-shot release); callers `din_spec_states.py:680-690, 838-843`, `iso15118_2_states.py:1453-1462, 1600-1614`.
- Code: PowerDeliveryReq(Start/TRUE) carries `ChargingComplete=TRUE`; the exhausted-loop Stop carries
  `FALSE` with SOC 100; building the Start burns one cycle and `PowerDelivery.process_message` another.
- Evidence: demo wire ISO-2 `PowerDeliveryReq{ChargeProgress:Start, ChargingComplete:1}` then
  `{Stop, ChargingComplete:0, EVRESSSOC:100}`; DIN `{ReadyToChargeState:1, ChargingComplete:1}`;
  DIN demo sent **8** CurrentDemandReq for `charge_loop_cycle: 10`; probe `cycles after PDReq(TRUE)
  build 9 soc 20`; pcap A_1 #363/#573, Charger B #198, Charger C #151. `[din-evcc F-3] [iso2-evcc F-9] [pcap F-8]`.
- Fix: `charging_complete = soc >= 100` (or a controller flag); make `continue_charging()` side-effect-free at build sites.

#### SC-004 · SECC answers CableCheckRes/PreChargeRes FAILED on any `EVErrorCode != NO_ERROR`
- **S1** · confirmed · DIN SECC, ISO-2 SECC.
- Req: [V2G-DC-640] p138 + NOTE ("the EVSE shall not change its behavior based on the value of
  EVErrorCode"); [V2G2-881] p209 (+NOTE 1: the EV signals shutdown by CP State B, not by EVErrorCode).
- Where: `app/secc/states/din_spec_states.py:677-685, 843-851`; `app/secc/states/iso15118_2_states.py:2325-2333, 2460-2468`.
- Code: `NoData`, `Reserved_*`, and every informational FAILED_* code → FAILED response + terminate.
  PowerDelivery/CurrentDemand/WeldingDetection ignore the field, so the SECC is also inconsistent.
- Failure: conformant EV sends `EVErrorCode=NoData` before it has settled its state → session dead.
- Evidence: code only (our EVCC always sends NO_ERROR). `[din-secc F-1] [iso2-secc F-5] [rc-tol F-E]`.
- Fix: log and continue.

#### SC-005 · ISO-20 SECC terminates the session after `WARNING_StandbyNotAllowed`
- **S1** · confirmed (harness repro case B) · ISO-20 SECC (DC and AC).
- Req: [V2G20-1387] p396, [V2G20-1396] p396 (EVCC continues with ChargeLoopReq or renegotiates),
  [V2G20-1700]; 8.6.2 p401 "WARNING … not considered a fatal error. The SECC and EVCC will not terminate".
- Where: `app/secc/states/iso15118_20_states.py:1163-1172` (`stop_state_machine(..., WARN_STANDBY_NOT_ALLOWED)`
  → `Terminate`); default `standby_allowed=False` in `app/shared/personality/model.py:122` (every shipped personality).
- Failure: any conformant EV asking for Standby gets the correct WARNING, then a closing socket.
- Evidence: repro `code WARN_STANDBY_NOT_ALLOWED next_state Terminate`. `[iso20-dc-secc F-1] [iso20-ac-secc F-5] [rc-tol F-C]`.
- Fix: send the WARNING via `create_next_message(None, …)` and stay in PowerDelivery/ChargeLoop.

#### SC-006 · ISO-20 EVCC raises `NotImplementedError` on EVSENotification Pause / ExitStandby / MeteringConfirmation / ScheduleRenegotiation
- **S1** · confirmed · ISO-20 EVCC (DC and AC).
- Req: [V2G20-1850] p413 (Pause), [V2G20-1854] (ExitStandby), [V2G20-1621]/[V2G20-2704] p413/181
  (MeteringConfirmation, PnC only), [V2G20-1954]/[V2G20-1052] (ScheduleRenegotiation), [V2G20-1416] (NotificationMaxDelay); 8.6 p400 "a terminated TCP connection before SessionStopRes is always an error".
- Where: `app/evcc/states/iso15118_20_states.py:1803-1819` (DC), `:1406-1422` (AC); `app/shared/comm_session.py:510-545`.
- Code: crash → TCP close mid-loop; no PowerDeliveryReq(Stop), no SessionStopReq, CP untouched.
- Failure: grid-managed SECC sends `EVSEStatus{Pause, 60}` in a ChargeLoopRes → we die with a traceback.
- `[iso20-dc-evcc F-6] [iso20-ac-evcc F-2] [rc-tol F-D]`.
- Fix (minimum): treat Pause/ScheduleRenegotiation like Terminate (Stop → WeldingDetection → SessionStopReq); ignore MeteringConfirmation under EIM.

#### SC-007 · ISO-20 EVCC sends a ChargeLoopReq after PowerDeliveryReq(Stop) on the GoToPause / scheduled-pause path
- **S1** · confirmed · ISO-20 EVCC (DC and AC).
- Req: [V2G20-1448] p422 (DC: next is DC_WeldingDetectionReq), [V2G20-1623] p430 (AC: next is
  SessionStopReq), [V2G20-2121]–[2123] p162/168 (GoToPause → skip CableCheck/PreCharge, send Stop), [V2G20-459] p402.
- Where: `iso15118_20_states.py:943-958, 1001-1015` (DC discards the computed STOP and runs CableCheck/PreCharge anyway),
  `:979-1000` (AC sends Stop without setting `charging_session_stop_v20`), `:1042-1196` (PowerDelivery falls through to a ChargeLoopReq);
  `simulator.py:694-773` (`process_*_se_params` return STOP when `pause`).
- Failure: SECC with no power sets GoToPause=TRUE → Stop → OK → ChargeLoopReq → FAILED_SequenceError.
- `[iso20-dc-evcc F-2] [iso20-ac-evcc F-3]`. Fix: set the stop marker when the Stop is built; honour GoToPause in the DC branch.

#### SC-008 · ISO-20 EVCC ServiceRenegotiation is broken on both paths
- **S1** · confirmed · ISO-20 EVCC (DC: wrong ChargingSession; both: no ServiceDiscoveryReq).
- Req: [V2G20-1476] p419, [V2G20-1477] p419-420 (ServiceDiscoveryReq after SessionStopRes OK),
  [V2G20-1651]/[1661], [V2G20-1080] p181, SECC [V2G20-1643] p429.
- Where: `iso15118_20_states.py:1913-1925` (`DCWeldingDetection` hard-codes `ChargingSession.TERMINATE`,
  ignoring `charging_session_stop_v20`; the AC branch `:1073-1080` uses it), `:1293-1302` (`SessionStop`
  sets `next_state = ServiceDiscovery` without a message), `app/shared/states.py:81` (`next_msg_timeout` 0)
  → `comm_session.py:252-260` `FaultyStateImplementationError` / `wait_for(read, 0)` TimeoutError.
- Evidence: `tests/conformance/state_machine/evcc/test_iso20_session_stop_routing.py` asserts the routing
  at the `process_message` seam and never sees the driver-level failure. `[iso20-dc-evcc F-5] [iso20-ac-evcc F-4]`.
- Fix: DC WeldingDetection uses the session marker; `SessionStop` must `create_next_message(ServiceDiscovery, ServiceDiscoveryReq, …)` and reset `matched_services_v20`.

#### SC-009 · ISO-20 EVCC treats `AuthorizationRes` WARNING_* + Finished as authorized
- **S1** · confirmed · ISO-20 EVCC (common state, DC and AC).
- Req: [V2G20-1583] p417-418 (WARNING → retry with another cert, switch EIM↔PnC, CertificateInstallationReq, or stop),
  [V2G20-2219] p405 (WARNING_EIMAuthorizationFailure), [V2G20-2201] p402.
- Where: `app/evcc/states/evcc_state.py:232-237` (`"FAILED" in response_code` only); `iso15118_20_states.py:435-459` (TODO acknowledges it).
- Failure: user cancels EIM → SECC `WARNING_EIMAuthorizationFailure, Finished` → we send ServiceDiscoveryReq → FAILED_SequenceError (or a lenient SECC charges an unauthorized EV).
- `[iso20-dc-evcc F-7] [rc-tol F-28]`. Fix: inspect `response_code` in `Authorization`; stop (SessionStopReq) on WARNING under EIM.

#### SC-010 · Scheduled-mode `DC_ChargeLoopReq` carries both EVTargetVoltage and EVTargetCurrent
- **S1** · confirmed (demo wire) · ISO-20 DC EVCC (and DC_BPT scheduled).
- Req: [V2G20-2183] p341 "shall either provide a EVTargetVoltage or EVTargetCurrent … never both".
- Where: `app/evcc/controller/simulator.py:1129-1155, 1202-1211`; `app/shared/messages/iso15118_20/dc.py:109-131`
  (`ScheduledDCChargeLoopReqParams` declares both required, TODO cites 2183 — the model cannot express the conformant form).
- Evidence: demo wire `Scheduled_DC_CLReqControlMode{EVTargetCurrent:200, EVTargetVoltage:20000}` on all 10 loop messages. `[iso20-dc-evcc F-3]`.
- Fix: make both Optional with an exclusive-or validator; builder sends one.

#### SC-011 · ISO-20 EVCC loop/pre-charge magnitudes contradict the announced CPD envelope
- **S1** · confirmed (demo wire) · ISO-20 DC EVCC, ISO-20 AC EVCC.
- Req: DC [V2G20-2180] p198, [V2G20-2198]/[2199] p199, [V2G20-1813] p246, [V2G20-2184] p341; AC [V2G20-1810]/[1812] p182.
- Where: `simulator.py:156-180` (`_EV_DC_V20_SKELETON` 20000 V target/present, 40 V min, 300 kW / 300 kA discharge),
  `:181-191` (`_EV_AC_V20_SKELETON` 300 kW dynamic max, 200 kW present active), `:1021-1046`, `:1242-1271`; baselines pin
  CPD to 800 V/450 V (DC) and 12 kW (AC) but the loop leaves are allowlisted "runtime" values.
- Evidence: demo wire DC `DC_PreChargeReq{EVPresentVoltage:20000, EVTargetVoltage:20000}`; AC `AC_CPDReq EVMaximumChargePower 9000` then
  `AC_ChargeLoopReq EVPresentActivePower 200000`. `[iso20-dc-evcc F-4] [iso20-ac-evcc F-5]`.
- Tags: personality (skeleton constants). Fix: derive loop/pre-charge values from the CPD envelope.

#### SC-012 · ISO-20 AC SECC sends `_L2/_L3` values although the EV sent none
- **S1** · confirmed (demo wire) · ISO-20 AC SECC.
- Req: [V2G20-1209] p307 "SECC shall not send _L2, _L3 values … if it neither received _L2 nor _L3 values in ChargeParameterDiscoveryReq"; [V2G20-1820].
- Where: `app/secc/controller/simulator.py:1033-1058`, `app/secc/controller/interface.py:533-600`; `iso15118_20_states.py:1445-1465` never inspects the Req; `ev_data.py:446-464` records the fact but nobody reads it.
- Evidence: demo wire `AC_CPDRes{EVSEMaximumChargePower_L2/_L3, EVSEMinimumChargePower_L2/_L3, EVSEPresentActivePower_L2/_L3}` and
  `AC_ChargeLoopRes{EVSETargetActivePower_L2/_L3, EVSETargetReactivePower_L2/_L3, …}` after a base-only `AC_CPDReq`. `[iso20-ac-secc F-3]`.
- Tags: baseline-deviation (real-charger baseline capture has no L2/L3). Fix: builder gates phase values on the Req.

#### SC-013 · ISO-20 AC SECC always commands 10 W EVSETargetActive/ReactivePower (Scheduled mode must not; Dynamic value is meaningless)
- **S1** · confirmed (demo wire) · ISO-20 AC SECC.
- Req: [V2G20-1826] p310 (Scheduled: targets only where local grid code mandates ad-hoc interference), [V2G20-1832]; [V2G20-2179] p191 (Dynamic: targets are the command).
- Where: `interface.py:452-679` (`get_ac_charge_loop_params_v20`), `simulator.py:231-310` (`get_evse_context` 10 W session limits), `iso15118_20_states.py:1561-1597`.
- Evidence: demo wire `Scheduled_AC_CLResControlMode{EVSETargetActivePower:10, EVSETargetReactivePower:10, …}` on every loop Res;
  SECC log "Both Max Charge and Discharge power are set … Ignoring Discharge setpoint" ×10. `[iso20-ac-secc F-1] [iso20-ac-secc F-2]`.
- Fix: omit targets in Scheduled mode; derive Dynamic targets from the CPD envelope / personality.

#### SC-014 · ISO-20 SECC schedules are anchored at SECC time 0 (1970)
- **S1** (wire) / plausible (EV impact) · confirmed wire · ISO-20 SECC (AC and DC), mirrored by the EVCC's `EVPowerProfile TimeAnchor 0`.
- Req: [V2G20-1016] p267, Table 112 p266, [V2G20-1811] p269 (power outside the entries is zero), [V2G20-2172] p304, [V2G20-1529]/[1536] p143-144.
- Where: `app/secc/controller/simulator.py:512-519, 569-571, 716-723` (`time_anchor=0`); EVCC `app/evcc/controller/simulator.py:729-741, 762-773`.
- Evidence: demo wire `ScheduleExchangeReq … TimeAnchor:0`, `PowerDeliveryReq … EVPowerProfile{TimeAnchor:0}`. `[iso20-ac-secc F-6] [iso20-dc-evcc F-21] [iso20-ac-evcc F-9]`.
- Fix: anchor at "now" in SECC time (needs SC-050's µs TimeStamp).

#### SC-015 · ISO-20 SECC advertises `CertificateInstallationService=True` but a CertificateInstallationReq crashes with no response
- **S1** · confirmed (repro case I; demo wire) · ISO-20 SECC; EVCC side unimplemented too.
- Req: [V2G20-1970] p428, [V2G20-538]/[736] p427/402, [V2G20-1576] p416; EVCC [V2G20-1578]–[1581], Table 12 payload types.
- Where: `app/secc/states/iso15118_20_states.py:335` (`allow_cert_install_service` default True, `model.py:121`), `:355-375` (`NotImplementedError`);
  EVCC `app/evcc/states/iso15118_20_states.py:303-308` (sent on payload type 0x8001, the SAP type), `:387-407` (`NotImplementedError`).
- Evidence: demo wire `AuthorizationSetupRes{AuthorizationServices:[EIM], CertificateInstallationService:1}` from the EIM-only baseline whose
  header comment claims `false`. `[iso20-dc-secc F-2] [iso20-dc-evcc F-18]`.
- Fix: advertise False until implemented (or answer WARNING_NoCertificateAvailable); EVCC: payload type 0x8002.

#### SC-016 · ISO-20 SECC answers SessionStopReq during DC_PreCharge with FAILED_SequenceError
- **S1** · confirmed (repro case C) · ISO-20 DC SECC.
- Req: [V2G20-2644]/[2645] p413 (SessionStopReq(Terminate) allowed any time before PowerDeliveryReq(Start)), [V2G20-2005]/[2006] p436-437.
- Where: `app/secc/states/iso15118_20_states.py:1839-1843` (`check_msg_v20(message, [DCPreChargeReq, PowerDeliveryReq])`); every other pre-Start state accepts it.
- Failure: EV cannot match voltage within 10 s (which is what happens against us, SC-029) and stops gracefully → we answer FAILED.
- `[iso20-dc-secc F-3]`. Fix: add `SessionStopReq` to the accepted list.

#### SC-017 · ISO-2 SECC DC next-allowed-request gaps (PowerDeliveryReq after Start; CPDReq after Stop; renegotiation forces CableCheck)
- **S1** · confirmed (a, b) / plausible (c) · ISO-2 SECC DC.
- Req: [V2G2-590] p209 ("allowed next request shall be CurrentDemandReq **and PowerDeliveryReq**"), [V2G2-601] p209-210 (after Stop: CPDReq, WeldingDetectionReq, SessionStopReq), Fig 104 p211; [V2G2-813]/[842] p206/187, NOTE 1 p188 (renegotiation keeps the contactor closed).
- Where: `app/secc/states/iso15118_2_states.py:1804-1811, 2549, 2566-2570` (`expect_first=True` forces CurrentDemandReq), `:1696-1704, 1812-1835` (Stop wait list lacks CPDReq), `:1527-1533, 2316` (every DC CPDRes(Finished) → `CableCheck`, which accepts only CableCheckReq).
- Failure: EV aborts right after PDRes(Start) with PDReq(Stop) → FAILED_SequenceError; EV renegotiates then sends PDReq(Start) → FAILED_SequenceError.
- `[iso2-secc F-2] [iso2-secc F-3] [iso2-secc F-4]`. Fix: widen accepted lists; route a renegotiated CPDRes to a wait state accepting PowerDeliveryReq (and CableCheckReq).

#### SC-018 · ISO-2 EVCC: EVSE `StopCharging` via MeteringReceiptRes does not mark the stop; DC loop ignores `ReceiptRequired`
- **S1** · confirmed (a) / plausible (b, PnC/TLS only) · ISO-2 EVCC.
- Req: [V2G2-519]/[520] p199, [V2G2-793]/[619]/[533] p201-202, [V2G2-679]; [V2G2-790] p202, [V2G2-531].
- Where: `iso15118_2_states.py:1077-1089` (Stop built, `charging_session_stop_v2` never set; contrast `:1311-1325`, `:1600-1618`), consumer `:940-1008`; `:1520-1560` (`CurrentDemand` never reads `receipt_required`; AC twin `:1231-1273` does).
- Failure: after the acknowledged Stop we send ChargingStatusReq/CurrentDemandReq → FAILED_SequenceError; DC PnC with ReceiptRequired → FAILED_SequenceError.
- `[iso2-evcc F-7] [iso2-evcc F-8]`.

#### SC-019 · DIN EVCC can send CurrentDemandReq again after PowerDeliveryReq(ReadyToChargeState=FALSE)
- **S1** · confirmed (probe) · DIN EVCC.
- Req: [V2G-DC-427]/[428] p171 (next is WeldingDetectionReq or SessionStopReq), [V2G-DC-645] p166, SECC [V2G-DC-390] p163.
- Where: `din_spec_states.py:713-731` (`PowerDelivery` branches on `continue_charging()` with no memory of which ReadyToChargeState it sent), `:813-815, 835-850`; `simulator.py:861-885`.
- Evidence: probe — after an EVSE-triggered stop with cycles left, `PowerDelivery: continue_charging -> True`; in stall mode the operator's single release is consumed inside `CurrentDemand` and `PowerDelivery` re-arms → CurrentDemandReq. Our own SECC (`secc/din_spec_states.py:1002-1006`) would answer FAILED_SequenceError. `[din-evcc F-2]`.
- Fix: remember the sent ReadyToChargeState (as the ISO-2 path does with `charging_session_stop_v2`).

#### SC-020 · DIN EVCC does not honour `EVSE_Shutdown` before the charge loop
- **S1** · confirmed · DIN EVCC.
- Req: [V2G-DC-650] p167 (+NOTE), [V2G-DC-648], [V2G-DC-673].
- Where: `din_spec_states.py:437-457` (CPD never reads `dc_evse_status`), `:549-561` (CableCheck treats Shutdown as an isolation failure → hard terminate), `:632-665` (PreCharge), `:713-731` (PowerDelivery); only CurrentDemand `:813-815` reacts (then undone by SC-019).
- Failure: customer cancels at the terminal during PreCharge → we keep pre-charging then send PDReq(TRUE) asking to close contactors.
- `[din-evcc F-6] [rc-tol F-26]`.

#### SC-021 · DIN EVCC terminates immediately instead of sending SessionStopReq on pre-CPD FAILED / own non-critical stops
- **S1** · confirmed · DIN EVCC (S4 aspect: 649 vs 652 needs oscillator sensing; conservative default is the opposite of what is implemented).
- Req: [V2G-DC-649] p167, [V2G-DC-648] p166 ("shall send a SessionStopReq message as the next request"), [V2G-DC-652], [V2G-DC-645].
- Where: `evcc_state.py:232-237, 261-274`; `din_spec_states.py:189-216` (ServiceDiscovery own-stop reasons); `comm_session.py:501-506, 373-417`.
- Failure: ContractAuthenticationRes FAILED (auth declined) → conformant EV sends SessionStopReq; ours goes quiet and FINs 5 s later, leaving the SECC to its 60 s sequence timer.
- `[din-evcc F-8] [rc-tol F-26]`.

#### SC-022 · DIN EVCC misapplies the 60 s SECC sequence timeout as an ONGOING abort; V2G_EVCC_ReadyToCharge_Timeout (150 s) never implemented; timer not reset after ContractAuthentication FINISHED
- **S1** · confirmed (code; field likelihood moderate) · DIN EVCC.
- Req: DIN Table 74/75 p152-153 (no EVCC ongoing timer exists), Table 77 p160 (ReadyToCharge 150 s / SECC performance 148 s), [V2G-DC-373]/[375]/[376] p156-157, [V2G-DC-492]/[493] p169.
- Where: `din_spec_states.py:337-350` (ContractAuthentication), `:463-472` (CPD), `:934-942` (WeldingDetection) compare against `TimeoutsShared.V2G_SECC_SEQUENCE_TIMEOUT`; `:360-363` FINISHED branch does not reset `ongoing_timer` (CPD reads the stale start); `din_spec/timeouts.py:17` `V2G_EVCC_READYTOCHARGE_TIMEOUT = 150` never read.
- Failure: RFID/app authorisation taking 61 s (legal within 148 s) → we abort the wrong way (SC-021); CA 45 s + CPD 20 s → abort at CPD.
- Evidence: `test_din_ongoing_timer_defeat.py` pins the 60 s behaviour (needs updating). `[din-evcc F-9] [din-evcc F-10] [timers F-2]`.

#### SC-023 · ISO-2 / ISO-20 SECC answer a REJECTED EIM authorization with `OK`
- **S1** · confirmed (code; latent — the shipped simulator never returns REJECTED) · ISO-2 SECC, ISO-20 SECC.
- Req: [V2G2-458] p191, [V2G2-564] p206, [V2G2-561]; [V2G20-2219] p405, [V2G20-458].
- Where: `iso15118_2_states.py:1264-1323` (`response_code = OK` unless a PnC cert status is set; REJECTED → `stop_state_machine(…, OK)`), `:1063-1108` (PaymentDetails, same); `iso15118_20_states.py:447-520` (REJECTED → `OK` + `FINISHED`, EV proceeds).
- `[rc-tol F-A] [rc-tol F-B]`. Fix: FAILED (ISO-2) / WARNING_EIMAuthorizationFailure (ISO-20).

#### SC-024 · TLS generation is pinned by a personality flag; ISO-20 offered/selectable over TCP or TLS 1.2
- **S1** · confirmed · both roles, ISO-2 and ISO-20.
- Req: [V2G2-067] p35, [V2G2-602] p38; [V2G20-1264] p63, [V2G20-2359], [V2G20-2065]/[2066]/[2067] p88, Table 5 p63; [V2G20-1237] p43 (EVCC shall not offer -20 on TLS 1.2/TCP), [V2G20-2356] (SECC shall not select it), [V2G20-1804]/[1805] p48.
- Where: `app/shared/security.py:154-165, 219-244` (`min=max=TLSv1_3` + `CERT_REQUIRED`, else `min=max=TLSv1_2`; negotiated version never consulted); `app/shared/settings.py:54-57` default `enable_tls_1_3=True`; `app/evcc/comm_session_handler.py:172-217` (`create_sap` strips DIN under TLS but never strips -20 without TLS 1.3); `app/evcc/states/sap_states.py:334-342` (guard uses the config flag, not the socket); `app/secc/states/sap_states.py:111-126`.
- Failure: `iso2_pnc_dc-secc` (1.3-pinned) rejects a conformant ISO-2 vehicle's TLS 1.2 ClientHello; `default-evcc` vs a TLS-1.2 charger fails the handshake with no fallback; `default-evcc` on a plaintext SDP answer still offers `-20:AC` → a conformant SECC answers `Failed_NoNegotiation` although ISO-2 would have worked.
- Evidence: `why_no_work.pcapng` frames 131-137 (TLS 1.2 handshake when the flag was off); `test_app_protocol_fallback.py` docstring institutionalises the -20+DIN plaintext offer. `[transport F-1] [transport F-2]`.
- Fix: one server context accepting 1.2 and 1.3 (per-handshake client-cert requirement via SNI/ALPN or post-handshake check); EVCC filters the SAP offer on the negotiated version.

#### SC-025 · TLS 1.3 key-exchange group restricted to secp256r1; ISO-20 mandates secp521r1 / x448
- **S1** · confirmed · both roles, ISO-20.
- Req: ISO-20 Table 7 p78, [V2G20-1634] p77, [V2G20-1637]/[1639] p78, Table 8 p79, [V2G20-2461].
- Where: `app/shared/security.py:246-247` (`set_ecdh_curve("prime256v1")` for both generations). Certificates are P-521 (`create_certs.sh:159-162`) — fine.
- Failure: conformant -20 EVCC → `handshake_failure`; conformant -20 SECC → HelloRetryRequest we cannot satisfy. Self-pair works because both sides err alike.
- `[transport F-3]`. Fix: `set_ecdh_curve` only for 1.2; for 1.3 leave the default group list (or set secp521r1:x448).

#### SC-026 · ISO-2 static-ECDH cipher suite silently dropped on OpenSSL 3.5
- **S1** · plausible (mechanism confirmed by this aggregator: `set_ciphers('ECDHE-ECDSA-AES128-SHA256:ECDH-ECDSA-AES128-SHA256')` leaves only `['ECDHE-ECDSA-AES128-SHA256']` on OpenSSL 3.5.0) · SECC ISO-2.
- Req: [V2G2-602] p38 (SECC shall support **both** Table 7 suites), [V2G2-603] (EVCC may support just one).
- Where: `app/shared/security.py:195-200`. No log line tells the operator.
- Failure: an EVCC implementing only `TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256` → `handshake_failure`.
- `[transport F-4]`. Fix: log the effective suite list at startup; document the OpenSSL limitation (static ECDH is gone upstream — likely unfixable without a legacy provider).

#### SC-027 · V2GTP is not framed on the TCP stream (`read(7000)` = one message)
- **S1** · plausible (PnC / large-message paths not exercised in the field) · both roles, all protocols.
- Req: [V2G2-088]+NOTE p40, [V2G2-094] p41, Table 9; [V2G20-1229] p92; DIN [V2G-DC-166]/[172] p79-80; [V2G2-784] (12 PMaxScheduleEntries must be accepted).
- Where: `app/shared/comm_session.py:453`, `:185`; `app/shared/messages/v2gtp.py:428-441` (payload length compared to UINT32_MAX only, never to `len(data)-8`).
- Failure: any message > MSS (1440 B on the PLC links) that arrives in two segments — CertificateInstallationRes (~5-6 kB), a CPDRes with 12 entries + SalesTariff, ISO-20 ServiceDetailRes — `EXIDecodingError` → session dead; two coalesced messages decode as one.
- Evidence: all field EIM payloads ≤ 44 B; the Charger A ServiceDiscovery abort is **not** this (single 40 B segment, bytes identical to the accepted run). `[transport F-5] [iso2-evcc F-24]`.
- Fix: read the 8-byte header, then `readexactly(payload_length)`; loop for coalesced messages.

#### SC-028 · SECC SLAC latches the first RunID for the whole cycle and leaves SLAC for good after MATCH.CNF
- **S1** · confirmed (a) / plausible (b, needs a lossy link) · SECC, ISO-3 and DIN SLAC.
- Req: [V2G3-A09-11]/[16] p45-46, [V2G3-A09-123]/[124] p67, Table A.2 (fresh RunID per PARM.REQ); [V2G3-A09-97] p61, [V2G3-A09-103]/[104] p63 (TT_match_join 12 s), [V2G3-A09-118]; DIN [V2G-DC-593]/[598] p48, [V2G-DC-730] p55.
- Where: `app/secc/transport/slac.py:123-125` (filter), `:231` (latch), `:166` (only reset in `start()`); `:241-245` (`stop = True` after one CNF); `app/secc/comm_session_handler.py:350-440` (`await queue.get()` without timeout).
- Failure: EV restarts matching with a new RunID after any lost frame → every run-B frame dropped → SECC parked "Waiting for SLAC" until `q`; lost MATCH.CNF → EV's MATCH.REQ retransmits unanswered.
- Evidence: our own EVCC reuses one RunID per cycle (SC-081), which is why the veth E2E never trips it. `[slac F-1] [slac F-2]`.
- Tags: crosstalk, ADR-0005. Fix direction: proper SLAC state machine (section 10, wayfinder candidate).

#### SC-029 · SECC PreChargeRes / CurrentDemandRes / DC_ChargeLoopRes report a constant 1 V / 1 A
- **S1** (reported value is software) with an **S4** component (a real EV also measures physically) · confirmed (demo wire, all three protocols) · DIN SECC, ISO-2 SECC, ISO-20 DC SECC.
- Req: [V2G2-618]/[528] p201 (EV repeats PreChargeReq until EVSEPresentVoltage meets its threshold; NOTE 2: message value is primary), [V2G2-704]–[706] p185 (7 s); DIN [V2G-DC-421]/[422] p170, [V2G-DC-385]/[386]; ISO-20 8.3.4.5.4.2 p196 ("shall adjust the voltage … reported in EVSEPresentVoltage … to match the EVTargetVoltage"), [V2G20-1400]/[706] (10 s).
- Where: `app/secc/controller/simulator.py:308-309` (`present_current = present_voltage = 1`, never written), `:1205-1212` (`send_charging_command` no-op discards EVTargetVoltage); readers `interface.py:757-806`; emitters `din_spec_states.py:888-915`, `iso15118_2_states.py:2497-2527, 2594-2612`, `iso15118_20_states.py:1861-1881, 2006-2011`.
- Evidence: demo wire DIN/ISO-2 `PreChargeRes EVSEPresentVoltage {Value:1}` ×6, ISO-20 `DC_PreChargeRes {Value:1}` ×4, `DC_ChargeLoopRes present V/I 1/1`; the real chargers ramp 4→34 V (Charger C) / 0→399 V (Charger A). Note: `[din-secc F-3]` says "0 V"; the wire shows 1 V (the sim seeds 1) — finding stands, detail corrected. `[din-secc F-3] [iso2-secc F-1] [iso20-dc-secc F-20]`.
- Fix: `send_charging_command(is_precharge=True)` writes `present_voltage = ev_target_voltage` (or ramps toward it); operator override keeps precedence.

#### SC-030 · ISO-20 EVCC sends PowerDeliveryReq(Stop) without EVPowerProfile (and without ScheduleTupleID in scheduled mode)
- **S1** (mandatory element omitted; low session impact) · confirmed (demo wire) · ISO-20 EVCC DC and AC.
- Req: [V2G20-1546] p171 ("In all control modes the parameter EVPowerProfile … shall be sent if ChargeProgress … is set to Start, Standby, Stop or Pause"), [V2G20-1839] p146.
- Where: `app/evcc/states/evcc_state.py:279-286` (`stop_v20_charging`, also skips `apply_personality_tree`); model validator `common_messages.py:984-1021` waives the profile for STOP.
- Evidence: demo wire `PowerDeliveryReq{ChargeProgress:1(Stop), EVProcessing:0}` with no profile (DC and AC). AcCCS SECC accepts it. `[iso20-dc-evcc F-14] [iso20-ac-evcc F-6]`.

### S2 — we reject/abort on a decodable peer value

#### SC-031 · Umbrella: a decodable-but-out-of-model peer message ends the session silently (no FAILED, no SessionStopReq, 5 s FIN)
- **S2** (EVCC) + **S3** (SECC never answers FAILED to a request that fails validation) · confirmed (pcap ×3, probes) · both roles, all protocols.
- Req: posture; [V2G2-734] p191; DIN [V2G-DC-636]; SECC side [V2G-DC-389] p163, [V2G2-458] p191, [V2G20-458] p402, [V2G2-736].
- Where: `app/shared/comm_session.py:187-201` (re-raise), `:512-546` (generic `except Exception` → `stop()`), `:376-421` (`stop`: `sleep(2)` → `enable_charging(False)` / `update_data_link` → `sleep(3)` → close); `app/shared/exi_codec.py:319-343` (wraps pydantic errors into `V2GMessageValidationError(reason, FAILED, msg_type)` — never consumed); `app/shared/everest_shape.py:604-627` (`_int_to_enum` escapes as a bare `ValueError`).
- Evidence: C_fail_1 (SessionSetupRes RAW → FIN +5.003 s), C_fail_2 (CableCheckRes RAW → FIN +5.003 s), A_1 s0/s1 & A_3 s0 (ServiceDiscoveryRes → FIN +5.04 s). `[rc-tol F-1] [rc-tol F-15] [pcap §0]`.
- Fix direction (framework, section 10): lenient wire-range validators that log and pass the raw value through (`out_of_spec: list[str]` per message), hard only for structural constraints; a `strict` flag re-enables the raise; SECC `rcv_loop` catches `V2GMessageValidationError` and answers `failed_responses_*[exc.message]` with `exc.response_code` (the `stop_state_machine(reason, None, code, message_body_type=…)` overload at `secc_state.py:256-338` already exists and is never called that way).

#### SC-032 · ISO-2 `EVSEID min_length=7` rejects a short EVSEID (Charger C sends one NUL byte)
- **S2** · confirmed (pcap, replay) · ISO-2 EVCC.
- Req: Annex C.6 `evseIDType` minLength 7 / maxLength 37 (p276), Annex H.2.2 p331 — Charger C is non-conformant; posture says log-and-continue; [V2G2-486] p196.
- Where: `app/shared/messages/iso15118_2/body.py:334` (SessionSetupRes), `:385` (ChargingStatusRes), `:607` (CurrentDemandRes).
- Evidence: C_fail_1 frame 47 `charactersLen=1` → EV FIN +5.09 s. `[iso2-evcc F-5] [rc-tol F-2] [pcap F-3]`. Fix: drop `min_length`, keep `max_length`, log.

#### SC-033 · `ServiceName` enum rejects fielded values (`DC_CHARGING`) — fixed for ISO-2 in the working tree, still an enum on DIN
- **S2** · confirmed (replay: HEAD raises `'DC_CHARGING' is not a valid ServiceName`; working tree proceeds to PaymentServiceSelection under every ISO-2 personality) · ISO-2 EVCC (fixed, uncommitted), DIN EVCC (open).
- Req: ISO-2 Annex C.6 `serviceNameType = xs:string maxLength 32` (p275), Table 105 p111; DIN [V2G-DC-628] (sender rule).
- Where: fixed `app/shared/messages/iso15118_2/datatypes.py:154-178`; open `app/shared/messages/din_spec/datatypes.py:102`.
- Evidence: A_1 s0/s1, A_3 s0 — ServiceDiscoveryRes bytes identical to the accepted sessions; local `datatypes.py` edited 12:11, A_1 s2 succeeds 12:16. `[iso2-evcc F-4] [rc-tol F-5/F-6] [pcap F-4]`.
- Tags: already-fixed-in-working-tree (ISO-2), hot-patched-on-box. Fix: commit; apply the same to DIN.

#### SC-034 · ISO-2 `ServiceDetails.service_id` is still the 1..4 IntEnum
- **S2** · confirmed (probe: 60001 in ServiceList and 4660 in ChargeService decode in libcbv2g, rejected by us with a bare `ValueError`) · ISO-2 EVCC.
- Req: Annex C.6 `serviceIDType` unsignedShort; 8.6.3.6 reserves 60001-65535; a third-party DIN charger with ServiceID 4660 broke the DIN EVCC (fixed there).
- Where: `app/shared/messages/iso15118_2/datatypes.py:175` (`service_id: ServiceID`), `ChargeService` inherits `:184`; `everest_shape.py:604-627`.
- `[rc-tol F-4]`. Fix: `service_id: int` (as DIN), keep `ServiceID` for emit.

#### SC-035 · ISO-2 / ISO-20 headers reject a zero-length SessionID (DIN was fixed)
- **S2** · confirmed (probe: `bytesLen: 0` decodes, validator raises `Invalid value '' for SessionID`) · ISO-2 SECC, ISO-20 SECC (and EVCC if echoed).
- Req: [V2G2-746]/[750] p69-70, Annex C.6 `sessionIDType` hexBinary maxLength 8 (length 0 legal); [V2G20-2106] p145; DIN fix `din_spec/header.py:34-49` + `test_din_empty_session_id.py`.
- Where: `app/shared/messages/iso15118_2/header.py:31-51` (`int(value, 16)`), `iso15118_20/common_types.py:57-76`, `iso15118_2/body.py:404-421` (MeteringReceiptReq).
- Failure: the real vehicle that sent an empty SessionID under DIN does it under ISO-2 → no SessionSetupRes at all. `[iso2-secc F-7] [rc-tol F-7] [transport F-7]`. Fix: copy the DIN guard; treat `""` as zero in SessionSetup (see SC-064).

#### SC-036 · ISO-20 EVCC dies on any VAS offer: unknown ServiceIDs raise; any VASList crashes at ServiceDetail
- **S2** · confirmed · ISO-20 EVCC (DC and AC).
- Req: Table 204 p370 (32768-65535 implementation-specific; 65/66 standard VAS), [V2G20-1216], [V2G20-1597], [V2G20-1587] p418, [V2G20-440].
- Where: `iso15118_20_states.py:604-620` (`ServiceV20.get_by_id` → `enums.py:317-338` `cls(service_id)` raises; every VAS appended as `MatchedService(parameter_sets=[])` with no ServiceDetailReq), `:739-751` → `simulator.py:418-434` (`select_vas_services_v20` selects **every** VAS with `parameter_sets[0]` → `IndexError`).
- Failure: SECC offers `VASList=[{65, Internet}]` (or a vendor ID) → TCP close, no SessionStopReq. `[iso20-dc-evcc F-8/F-9] [iso20-ac-evcc F-14] [rc-tol F-8]`.
- Fix: tolerant lookup (skip unknown IDs with a warning); `select_vas_services_v20` returns `[]`.

#### SC-037 · EVCC CableCheck FINISHED requires exactly `EVSE_Ready` + `Valid`; anything else aborts the wrong way
- **S2** · confirmed · DIN EVCC, ISO-2 EVCC.
- Req: DIN [V2G-DC-417] p170, Table 66 p135 (EVSEIsolationStatus optional), [V2G-DC-637] p136 + NOTE (`EVSE_IsolationMonitoringActive` is an expected value), Table 67; ISO-2 [V2G2-701] p184, [V2G2-801]+Table 97 p137 (Warning = below warning level), Table 96, [V2G2-880] p201.
- Where: `din_spec_states.py:545-561`; `iso15118_2_states.py:1361-1376` (`stop_state_machine("Isolation-Level of EVSE is not Valid")`).
- Failure: Finished + `EVSE_IsolationMonitoringActive`, or Finished + Warning / No_IMD / absent → silent abort (DIN wants SessionStopReq for EVSE_Shutdown). `[din-evcc F-5] [iso2-evcc F-13] [rc-tol F-9]`.
- Tags: verify-IEC. Fix: proceed on Valid/Warning (log), log No_IMD/absent, stop only on Fault; EVSE_Shutdown → the SC-020/021 path.

#### SC-038 · DIN EVCC CurrentDemand stops charging on any status code other than `EVSE_Ready`
- **S2** · confirmed · DIN EVCC.
- Req: [V2G-DC-637] p136, [V2G-DC-650] (only EVSE_Shutdown carries an EVCC requirement), p136 NOTE.
- Where: `din_spec_states.py:812-815`. Failure: `EVSE_IsolationMonitoringActive` / `EVSE_UtilityInterruptEvent` during the loop → PowerDeliveryReq(FALSE) (then SC-019). `[din-evcc F-7] [rc-tol F-10]`.

#### SC-039 · SECC PreCharge answers FAILED when `EVTargetCurrent > 2 A`
- **S2** · confirmed (code) / plausible (peer frequency) · DIN SECC, ISO-2 SECC.
- Req: no DIN/ISO-2 requirement — [V2G-DC-458] p176, [V2G2-587]/[588] p209 only say FAILED "if processing is not successful"; the 2 A figure is IEC 61851-23 CC.5.2 inrush guidance on the EVSE **output** (verify-IEC).
- Where: `din_spec_states.py:857-882`; `iso15118_2_states.py:2476-2496` (`present_current` is the 1 A stub anyway).
- Failure: EV requests 3–10 A pre-charge current → session dies at PreCharge. Charger C accepted our 1.5 A with an 800 V target and never rejected. `[din-secc F-2] [iso2-secc F-6] [rc-tol F-11]`. Fix: clamp (no-op in sim) and log.

#### SC-040 · ChargeParameterDiscoveryRes(Finished) without SAScheduleList crashes the EVCC
- **S2** · plausible · DIN EVCC, ISO-2 EVCC.
- Req: DIN Table 39 p109; ISO-2 Table 43 (~p95) / [V2G2-688] (SECC may omit only with Ongoing) — SECC is non-conformant, EVCC only uses it for an optional ChargingProfile.
- Where: `din_spec_states.py:440-442` (`.sa_schedule_list.values`, model `Optional`), `iso15118_2_states.py:835-841` (`.schedule_tuples`). `AttributeError` → SC-031 path.
- `[din-evcc F-16] [iso2-evcc F-14] [rc-tol F-17]`. Fix: default `SAScheduleTupleID=1`, log.

#### SC-041 · ISO-20 SECC rejects PowerDeliveryReq(Renegotiate / Standby) without EVPowerProfile at decode (spec-mandated shape)
- **S2** (also a correctness bug) · confirmed · ISO-20 SECC (validator shared with the EVCC's builder).
- Req: [V2G20-1414] p412 ("If the EVCC sends PowerDeliveryReq with ChargeProgress=Renegotiate it shall not send an EVPowerProfile"), [V2G20-1393] p395, [V2G20-2018] p429, [V2G20-1546].
- Where: `app/shared/messages/iso15118_20/common_messages.py:984-1021` (returns early only for ONGOING or STOP); even if decoded, `iso15118_20_states.py:1193-1215` runs the Start branch and dereferences `ev_power_profile.scheduled_profile`.
- Failure: EV exits standby / renegotiates → `ValueError` → no PowerDeliveryRes, TCP closed. `[iso20-ac-secc F-4] [rc-tol F-12]`. Fix: exempt Renegotiate/Standby; move the "profile required with Start" check into the state (answer FAILED_EVPowerProfileInvalid).

#### SC-042 · ISO-20 decode-time strictness on peer values (MinimumSOC > TargetSOC, MaximumSupportingPoints < 12, MeterID > 32, SOC ranges)
- **S2** · confirmed (validators) / plausible (field) · ISO-20 both roles.
- Req: [V2G20-1640] p262 (an EV-side shall), [V2G20-1202] p167 (minimum supported is 12 — does not forbid sending fewer; verify-XSD), posture.
- Where: `common_messages.py:803-843` (`DynamicScheduleExchangeResParams` raises on MinSOC > TargetSOC), `:820-842`, `:501-503` (`max_supporting_points ge=12`); `common_types.py:352-366` (SOC `ge=0, le=100`), `:248-251` (`meter_id max_length=32`), `:42` (`NumericID ge=1`).
- `[rc-tol F-13] [iso20-ac-evcc F-7] [iso20-dc-secc S2 candidates]`. Fix: lenient tier (SC-031 framework).

#### SC-043 · Other pydantic facets stricter than the wire type (inventory in section 4)
- **S2** · confirmed (each probed by the responsecode reviewer) / plausible (field impact) · all protocols.
- Where/what: `iso15118_2/datatypes.py:102` `SubCertificates max_length=2` (XSD 4; [V2G2-656] is a sender rule); `iso15118_2/datatypes.py:431-432` and `din_spec/datatypes.py:248-249` `RelativeTimeInterval.start le=16777214 / duration le=86400` (XSD unsignedInt); `iso15118_2/datatypes.py:336` `MeterInfo.meter_reading le=999999999` (unsignedLong); `:576-593` `SalesTariffID 1..255` (unsignedByte allows 0); `din_spec/datatypes.py:265-268` `PMaxScheduleEntry max_length=12` ([V2G-DC-329] sender rule, XSD 1024 — 24 entries common in ISO-2-derived firmware); `din_spec/body.py:135` `SessionSetupRes.evse_id min_length=2` (zero-length hexBinary rejected); `app/shared/messages/datatypes.py:83-537` every `PVxxx.unit: Literal[…]`; `iso15118_2/datatypes.py:60` `eMAID constr(14..15)`; `iso15118_2/body.py:493, 336, 387` `sa_schedule_tuple_id ge=1`; DIN `ServiceList` empty model + `extra="forbid"` (`din_spec/datatypes.py:159-160`, `messages/__init__.py:5-10`) rejects a dual-stack charger's ServiceList content.
- `[rc-tol F-16] [din-evcc F-17]`.

#### SC-044 · SECC crashes (no response) on a missing optional sub-element instead of answering FAILED_WrongChargeParameter / FAILED
- **S2** (PowerDeliveryReq) / **S3** (CPDReq variants) · confirmed · DIN SECC, ISO-20 AC SECC.
- Req: DIN [V2G-DC-558] p111 (profile rule; schema-optional), [V2G-DC-665] p172, [V2G-DC-398] p163; ISO-20 [V2G20-1619] p408, [V2G20-2651].
- Where: `din_spec_states.py:980-982` (`dc_ev_power_delivery_parameter.dc_ev_status` on `None`), `:575-577` (`update_dc_charge_parameters(None)`); `iso15118_20_states.py:1466-1479, 1488-1496` (`charge_parameter_valid` stub never called), `ev_data.py:423-425, 443`.
- `[din-secc F-6] [din-secc F-7] [iso20-ac-secc F-14]`.

#### SC-045 · ISO-2 SECC validates the EV's ChargingProfile against an 11 kW SAScheduleTuple PMax while advertising 200 kW / 80 kW
- **S2** (receive) + **S3** (self-inconsistent emission) · plausible · ISO-2 SECC.
- Req: [V2G2-478] p193, [V2G2-673] p195, Table 112 p194.
- Where: `app/secc/controller/simulator.py:182-191` (`iso2_sa_schedule_pmax_w=11000` vs `max_power_w=80000`), `personalities/iso2-secc-baseline.yaml` (EVSEMaximumPowerLimit 200 kW; SAScheduleList builder-computed), `iso15118_2_states.py:1763-1771, 1908-1998`.
- Failure: production-EV-class peer derives its profile from EVSEMaximumPowerLimit → FAILED_ChargingProfileInvalid. `[iso2-secc F-8]`. Tags: personality.

#### SC-046 · SDP response with a port outside 49152-65535 or a reserved Security/Transport byte crashes the EVCC handler
- **S2** · confirmed · EVCC, all protocols.
- Req: [V2G2-078] Table 8 p38, Table 16 p55, [V2G2-800], [V2G2-160]/[161].
- Where: `app/shared/messages/sdp.py:174-179` (`return` without setting attributes), `:220-225` (bare `ValueError`); `app/evcc/comm_session_handler.py:534-538` (only `InvalidSDPResponseError` caught), `:573-578` (`break`).
- Failure: charger answering with port 8000 → `AttributeError`, discovery loop ends. `[transport F-8]`.

#### SC-047 · EVCC SLAC trusts `NumberMSounds` from PARM.CNF; 0 crashes the SLAC thread and leaves a zombie timer
- **S2** · plausible (traced) · EVCC SLAC.
- Req: [V2G3-A09-09] p45 / DIN [V2G-DC-591] p48 (deviating content → ignore).
- Where: `app/evcc/transport/slac.py:240-255, 313-323` (`Countdown = -1` → `struct.error`), `:186-191` (no `try/finally`, cf. SECC `:178-189`), `:198-205`. `[slac F-15]`.

#### SC-048 · ISO-20 `ResponseCode` enum may lack codes the text names (`WARNING_ContractCancelled`, `FAILED_TariffSelectionInvalid`)
- **S2** · plausible (verify-XSD — the ISO-20 XSD is not in the extracted text) · ISO-20 EVCC.
- Req: [V2G20-2210] p404, [V2G20-479] p406 (Table 224 spells it FAILED_ScheduleSelectionInvalid).
- Where: `app/shared/messages/iso15118_20/common_types.py:102-146`. `[iso20-dc-evcc F-22]`.

#### SC-049 · ISO-2 EVCC: no usable PaymentOption → `AttributeError` instead of a clean stop (PnC personality on plaintext)
- **S2** · confirmed (replay: `iso2_pnc_dc-evcc`, `is_tls=False` → `AttributeError: 'NoneType' object has no attribute 'value'`) · ISO-2 EVCC.
- Req: [V2G2-633]/[635] p25, [V2G2-488]/[728] p196-198.
- Where: `iso15118_2_states.py:231-232, 288-308` (`select_auth_mode` calls `stop_state_machine` then line 232 dereferences the result). `[iso2-evcc F-15] [pcap §2 candidate 2]`.

### S3 — defined-but-unenforced timers, missing optional behaviour, wrong-but-harmless values

#### SC-050 · ISO-20 header TimeStamp is UNIX seconds, not microseconds, and not strictly increasing; FAILED templates carry `1`
- **S3** · confirmed (demo wire: `TimeStamp: 1790715848` identical on SessionSetupReq/Res, AuthorizationSetupRes, ServiceDiscoveryRes, ScheduleExchangeReq/Res; `1790715849` on every PreCharge/ChargeLoop message) · ISO-20 both roles.
- Req: [V2G20-1534] p144 ("encoded at microseconds resolution"), [V2G20-1536], [V2G20-1537] (always increase), [V2G20-1538]; DepartureTime offsets [V2G20-2104].
- Where: every `MessageHeader(... timestamp=int(time.time()))` in `app/evcc/states/iso15118_20_states.py` (:200, :360, :445, :1620, :1638, :1866, :1916, :1933) and `sap_states.py:155-157`; `:933-942` re-sends the cached ScheduleExchangeReq (stale TimeStamp); SECC `app/secc/states/iso15118_20_states.py` (:215, :330, :549, :652, :772, :848, :1057, :1139, :1386, :1449, :1568, :1798, :1874, :2000, :2078); `app/secc/failed_responses.py:616` (`timestamp=1`).
- `[iso20-dc-evcc F-13] [iso20-dc-secc F-13] [iso20-ac-secc F-20] [iso20-ac-evcc F-8]`. Fix: `time.time_ns() // 1000`, SECC-time offset on the EVCC from SessionSetupRes; prerequisite for SC-014.

#### SC-051 · SECC waits 20 s (the EVCC's setup budget) for supportedAppProtocolReq instead of V2G_SECC_Sequence_Timeout 60 s; no 18 s CommunicationSetup performance timer
- **S3** · confirmed · SECC, all protocols.
- Req: DIN [V2G-DC-432] p174, Table 75; ISO-2 [V2G2-536] p204, [V2G2-714]/[716] p184 (18 s → [V2G2-034]); ISO-20 [V2G20-2303]/[716] p390.
- Where: `app/secc/comm_session_handler.py:407-411` (`comm_session.start(Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)`), `app/secc/states/sap_states.py:40-41, 136-143` (TODO). Stricter than spec, harmless in practice.
- `[din-secc F-13] [iso2-secc F-10] [transport F-11] [timers F-8]`.

#### SC-052 · ISO-20 SECC charge-loop sequence timeout is 60 s instead of 0.5 s (constants defined, never read)
- **S3** · confirmed (repro case G `timeout used 60`) · ISO-20 SECC AC and DC.
- Req: Table 216/217 p386 (`V2G_SECC_Sequence_Timeout` AC_/DC_ChargeLoopRes 0,5 s), [V2G20-1500]/[1502], [V2G20-2009]/[2010]/[2012]/[2192] p430/437, [V2G20-441]/[443] p385.
- Where: `iso15118_20_states.py:1274-1280` (PowerDelivery), `:1598-1608` (ACChargeLoop), `:1959-1969` (DCChargeLoop) pass `Timeouts.V2G_SECC_SEQUENCE_TIMEOUT`; `iso15118_20/timeouts.py:42,49,58` unused. (Note `Timeouts` is a float Enum, so `V2G_EVCC_ONGOING_TIMEOUT` aliases `V2G_SECC_SEQUENCE_TIMEOUT` = 60 — harmless.)
- Mirror risk: EVCC `charge_profile.delay_seconds ≥ 1` (`simulator.py:228`, integer, cap 50) makes a conformant SECC drop us (`[iso20-dc-evcc F-17] [iso20-ac-evcc F-11]`, personality).
- `[iso20-dc-secc F-5] [iso20-ac-secc F-11] [timers F-9]`.

#### SC-053 · ISO-2 EVCC CurrentDemand loop never uses the 0.25 s message timeout (2 s on entry, 5 s in the loop)
- **S3** · confirmed · ISO-2 EVCC.
- Req: Table 109 p178 (CurrentDemandReq 0,25 s), [V2G2-436]/[438] p181, [V2G2-532].
- Where: `iso15118_2_states.py:1003-1008` (`CHARGING_STATUS_REQ` 2 s), `:1553-1558` (`POWER_DELIVERY_REQ` 5 s); `Timeouts.CURRENT_DEMAND_REQ` only as the cosmetic `__init__` value (`:1432`, `:1518`). DIN (`din_spec_states.py:718,825`) and ISO-20 (0.5 s) are right.
- `[iso2-evcc F-10] [timers F-4] [pcap F-9]`.

#### SC-054 · DIN EVCC re-sent ChargeParameterDiscoveryReq waits 60 s instead of 2 s
- **S3** · confirmed · DIN EVCC. Req: Table 75 p153, [V2G-DC-359]/[361] p155. Where: `din_spec_states.py:480-485` (`TimeoutsShared.V2G_SECC_SEQUENCE_TIMEOUT`; first send `:362-363` uses 2 s). `[din-evcc F-11] [timers F-3]`.

#### SC-055 · V2G_EVCC_CommunicationSetup_Timeout (20 s) never enforced as an aggregate timer; CableCheck/PreCharge timers start one round-trip late
- **S3** · confirmed · EVCC, all protocols.
- Req: DIN [V2G-DC-369]/[371]/[372] p156, [V2G-DC-377]/[382] p157 (start when the first request is *sent*); ISO-2 [V2G2-446]–[448] p183; ISO-20 [V2G20-2298]/[448] p390, [V2G20-700] p392.
- Where: constants `app/shared/messages/timeouts.py:13`, `din_spec/timeouts.py:18`, `iso15118_20/timeouts.py:21`; cosmetic uses `iso15118_2_states.py:163-168`, `iso15118_20_states.py:173-176`; CableCheck/PreCharge armed on the first ONGOING *response* (`din_spec_states.py:563-569, 651-657`, `iso15118_2_states.py:1380-1386, 1472-1478`, `iso15118_20_states.py:1606-1614`). Each leg is separately bounded (SDP 50×250 ms, SAP 2 s, SessionSetup 2 s), so no interop harm.
- `[din-evcc F-12] [iso2-evcc F-19] [iso20-dc-evcc F-15] [timers F-6]`. S4 aspect: the DIN start condition "State B + 5 %" needs CP sensing.

#### SC-056 · ISO-20 EVCC never enforces V2G_EVCC_DC_PreCharge_Timeout (10 s)
- **S3** · confirmed · ISO-20 DC EVCC. Req: Table 223 p392, [V2G20-704]/[706]/[1400]/[1401] p392-393. Where: `iso15118_20_states.py:1650-1710` (no elapsed check), `iso15118_20/timeouts.py:19-20` unused; bounded only by the simulator's 5-poll cap. DIN 7 s and ISO-2 7 s are enforced. `[iso20-dc-evcc F-15] [timers F-10]`.

#### SC-057 · ISO-2 SECC never runs V2G_SECC_Ongoing_Performance_Time (55 s) and never sends the mandated FAILED
- **S3** · confirmed · ISO-2 SECC. Req: [V2G2-712]/[713] p184, Table 109 p179 (ISO-20 [V2G20-2102] is "may"; DIN has none). Where: `iso15118_2_states.py:1252-1360` (Authorization), `:1568`, `:2336-2413`; `grep ongoing_timer app/secc` → none. The operator stall (#30) relies on it; the default non-stalled path should still honour 55 s. `test_iso2_auth_stall.py` asserts the indefinite ONGOING. `[iso2-secc F-10] [timers F-7]`.

#### SC-058 · ISO-2 EVCC applies the 60 s Ongoing timer to `Ongoing_WaitingForCustomerInteraction`
- **S3** · plausible (spec ambiguity) · ISO-2 EVCC. Req: Table 109 p179 / [V2G2-710]/[711] speak of `Ongoing`; [V2G2-845] p187 only says re-send; public CCS design guide: customer wait "could be as long as 2 minutes". Where: `iso15118_2_states.py:753-795`. Evidence: Charger B took 26 s, Charger A up to 19 s. `[iso2-evcc F-20] [timers F-5]`. Tags: verify-interpretation, personality (stall defeat exists).

#### SC-059 · ISO-20 EVCC ScheduleExchange ONGOING loop has no ongoing timer and re-sends a byte-identical cached request
- **S3** · confirmed · ISO-20 EVCC. Req: Table 215 (60 s "may"), [V2G20-1593] p413, [V2G20-2104]. Where: `iso15118_20_states.py:933-941`. `[iso20-ac-evcc F-8]`.

#### SC-060 · Several FAILED templates cannot be EXI-encoded → the SECC goes silent exactly when a FAILED is mandated
- **S3** · confirmed (codec probes) · DIN SECC, ISO-2 SECC, ISO-20 SECC.
- Req: [V2G-DC-390]/[666], [V2G2-459]/[736], [V2G20-464]/[736]/[2222].
- Where: `app/secc/failed_responses.py:320` (`evse_id="1234567"` — 7 hex chars, DIN EVSEID is hexBinary → `non-hexadecimal number found in fromhex() arg at position 7`), same literal `:466, :537, :582` (ISO-2/-20 — a 7-char string is legal there); ISO-20 entries `ServiceDetailRes(service_parameter_list=ServiceParameterList(parameter_sets=[]))` and `ScheduleExchangeRes(… PriceLevelScheduleEntryList(entries=[]))` → libcbv2g rc=-150; the live FAILED_ServiceIDInvalid path `iso15118_20_states.py:763-781` + `simulator.py:619-673` builds the same empty list; `MeteringConfirmationReq/Res` absent from `_ISO20_MSG_CLASSES` (`app/shared/exi_codec.py:99-136`) → `EXIDecodingError` on a peer's MeteringConfirmationReq.
- Failure: any out-of-order SessionSetupReq on DIN, any FAILED ServiceDetailRes/ScheduleExchangeRes on ISO-20 → no response, TCP closed after 5 s. Encodable: 17/17 ISO-2, 10/11 DIN, 15/18 ISO-20.
- `[din-secc F-11] [rc-tol F-20] [rc-tol F-21]`. Fix: `evse_id="00"` for DIN; one minimal parameter set / entry in the ISO-20 templates; a test that round-trips every template.

#### SC-061 · Every FAILED response carries a header `Notification(FaultCode=ParsingError)` — DIN forbids the element; ISO-2 asks for minimal size; the code is wrong for every non-parse error
- **S3** · confirmed (codec probe shows it on the wire) · DIN SECC, ISO-2 SECC.
- Req: [V2G-DC-619] p99 ("the element Notification shall not be used"), 9.5.4 p144; [V2G2-736] p191; 8.5.2.8 FaultCode semantics.
- Where: `app/shared/states.py:247-262` (DIN), `:281-296` / `:301-318` (ISO-2) whenever `stop_reason.successful` is False.
- `[din-secc F-10] [iso2-secc F-11] [rc-tol F-22]`. Fix: omit on DIN; ISO-2 use UnknownError or omit.

#### SC-062 · FAILED_ServiceIDInvalid / FAILED_ServiceSelectionInvalid sent without terminating; ISO-20 body not minimal
- **S3** · confirmed (repro case D `next_state None n_param_sets 3`) · ISO-2 SECC, ISO-20 SECC.
- Req: [V2G2-539] p204, [V2G2-464]; [V2G20-464] p403, [V2G20-736], [V2G20-2222] p427.
- Where: `iso15118_2_states.py:503-521`; `iso15118_20_states.py:756-792` (full AC parameter list for any ServiceID; `get_service_parameter_list` ignores `service_id`), `:1555-1580`, `:1977-2010`.
- `[iso2-secc F-9] [iso20-dc-secc F-9] [iso20-ac-secc F-17] [rc-tol F-23]`. Fix: `stop_state_machine(...)`.

#### SC-063 · Wrong first message before SessionSetup raises instead of FAILED_SequenceError (ISO-2/-20); DIN SessionStopReq-first gets FAILED_UnknownSession
- **S3** · confirmed (repro case A `ValidationError … Invalid value '' for SessionID`) · SECC all protocols.
- Req: [V2G2-538] p204, [V2G2-459]; [V2G20-459] p402, [V2G20-538]; DIN [V2G-DC-664]/[666] p172-173, [V2G-DC-439].
- Where: `secc_state.py:300-359` → `states.py:313-316` (`MessageHeaderV2(session_id="")` raises; ISO-20 `secc_state.py:364` under `validate_assignment`); `din_spec_states.py:189-196, 1234-1236` (`expect_first=False` for SessionStopReq; ID compared against `""`).
- `[iso2-secc F-12] [iso20-dc-secc F-4] [din-secc F-12]`. Fix together with SC-035.

#### SC-064 · Zero-SessionID detection compares against the 1-byte `"00"` only — every own-vs-own ISO session logs "session ID … does not match"
- **S3** · confirmed (demo logs ISO-2 and ISO-20: `EVCC's session ID 000000000000 does not match . New session ID … assigned`) · ISO-2 SECC, ISO-20 SECC.
- Req: [V2G2-750] p70, [V2G2-756]; [V2G20-1243]/[2106]/[2618] p145 (SessionID "consisting only of zeroes", 8 bytes); our EVCC sends 6 zero bytes (`app/evcc/states/sap_states.py:212-218`).
- Where: `iso15118_2_states.py:221`, `iso15118_20_states.py:198-199` (`== bytes(1).hex()`); DIN does `int(x,16)==0` (`din_spec_states.py:207`). Wire outcome (OK_NewSessionEstablished + fresh ID) is conformant; the log and the `ev_session_context` reset are wrong, and the resume branch is unreachable (SC-074).
- `[iso20-dc-secc F-18] [iso20-ac-secc F-13] [rc-tol F-30] [transport F-7]`.

#### SC-065 · Error-path shutdown: CP State B signalled 2 s late, TCP held 5 s, FIN retransmitted, SDP re-run on the same data link
- **S3** (latent for CP until SC-001 is ported; verify-IEC for the emergency-shutdown reaction) · confirmed · both roles, all protocols.
- Req: DIN [V2G-DC-361]/[371]/[375]/[380]/[385] p155-158 and [V2G-DC-402]/[651]–[654]/[656] p167-168 ("without any delay, change to CP State B"); [V2G-DC-366]/[665]/[666] (SECC oscillator off first, then FAILED); ISO-2 [V2G2-720] p28 (D-LINK_ERROR then link re-establishment), [V2G2-025]/[034].
- Where: `app/shared/comm_session.py:373-417` (`stop()`: `sleep(2)` → `enable_charging(False)`/`update_data_link` → `sleep(3)` → close); `evcc_state.py:261-274`; `app/evcc/comm_session_handler.py:600-612` (`restart_sdp(True)` with no data-link reset); `pev.py`/`evse.py` `openProximity()` only after the handler returns.
- Evidence: every `+5.0 s` FIN in the traces; our FIN retransmitted 8-9 times over 30-90 s after charger-initiated closes; one CableCheckReq sent into the half-closed socket during `pace_ongoing_poll()` (reader not consulted while pacing). `[din-evcc F-18] [timers F-15] [pcap F-5] [pcap §7] [transport F-10]`.
- Fix: CP action first (`enable_charging(False)` / oscillator off at the top of `stop()` and in `stop_state_machine`), then the response, then close; drop or shorten the fixed sleeps.

#### SC-066 · WeldingDetectionReq / PowerDeliveryReq(Stop) carry `EVReady=true`; no CP settle time between the State-B relay write and the next request
- **S3** (EVReady) / **S4** (settle) · plausible · DIN EVCC, ISO-2 EVCC (ISO-20 analogue).
- Req: ISO-2 p139 "EVReady: If set to TRUE, the EV is ready to charge"; [V2G2-913], [V2G2-920]–[922] p189-190 (SECC waits up to 1.5 s for B); DIN `T_vald_state_duration` 200-400 ms (Table p46), [V2G-DC-502]/[556].
- Where: `app/evcc/controller/simulator.py:1096-1108` (`ev_ready=True` hard-coded), `iso15118_2_states.py:955-963`, `din_spec_states.py:725-729`.
- Evidence: demo wire `WeldingDetectionReq{DC_EVStatus{EVReady:1, EVRESSSOC:100}}`; Charger A answered WeldingDetectionRes FAILED 59-64 ms after the request in 3/3 sessions (peer did not honour [V2G2-920]); Charger D/Charger B/Charger C accepted the same bytes. Resolution in section 8. `[pcap F-6] [pcap §4]`.
- Fix: `EVReady=false` once stopping; ~200-300 ms settle after the B write (verify-IEC).

#### SC-067 · PreCharge ends on a counter (5 polls) with a 20 kV comparator; WeldingDetection ends after 3 polls; nothing reads EVSEPresentVoltage
- **S3** (logic) / **S4** (needs a real RESS voltage) · confirmed (probe: `is_precharged(4|34|800 V) → False compares against {'value': 20000}`; demo wire 6 PreCharge pairs in DIN/ISO-2, 4 in ISO-20) · EVCC all protocols.
- Req: DIN [V2G-DC-421]/[422] p170, [V2G-DC-386]; ISO-2 [V2G2-705]/[707] p185, [V2G2-618]/[528]; ISO-20 [V2G20-1400]/[1401] p393, [V2G20-1434]/[1435]; welding 9.4.2.5.1 p121-122, [V2G2-620]/[535].
- Where: `simulator.py:900-911` (`is_precharged`), `:1242-1258` (`get_present_voltage` returns `_EV_DC_V20_SKELETON.target_voltage_v` = 20000), `:969-973` (`welding_detection_cycles == 3`); `iso15118_20_states.py:1675-1703` (unpaced PreCharge polls).
- Evidence: field: PDReq(Start) at 0-40 V vs 400/800 V target in every run; Charger A ramped 0→399 V inside the CurrentDemand loop; Charger C reported 269 V during WeldingDetection while we unlocked after 3 polls. `[din-evcc F-13] [din-evcc F-19] [iso2-evcc F-11] [iso2-evcc F-12] [iso20-dc-evcc F-25] [pcap F-10]`.
- Fix: compare against the protocol's own `dc_target_voltage` ± tolerance (IEC 61851-23 order ±20 V, verify-IEC); cycle cap only under `--virtual`.

#### SC-068 · DIN device personality requests EVTargetVoltage 800 V while advertising EVMaximumVoltageLimit 410 V
- **S3** · confirmed (demo wire DIN `PreChargeReq EVTargetVoltage 800`, `CurrentDemandReq EVMaximumVoltageLimit 410`) · DIN EVCC.
- Req: DIN Tables p116/p119/p140; no explicit ordering clause in DIN (IEC 61851-23 caps the EVSE at the EV maximum — verify-IEC).
- Where: `personalities/din_dc_extended-evcc.yaml:22` (`charge_ramp.target_voltage_v: 800.0`) vs `personalities/din-evcc-baseline.yaml:66,90` (410 V); plumbing `evcc_config.py:92`, `simulator.py:273-275`, `din_spec_states.py:585-598, 846-870`. The ISO-2 sibling (`iso2_eim_dc-evcc.yaml:21-24`) is deliberately consistent (400 V under 422 V).
- `[din-evcc F-14] [pcap F-7]`. Tags: personality, verify-IEC.

#### SC-069 · `create_sap` mutates the shared personality protocol list — DIN is never offered again after one TLS cycle
- **S3** · confirmed (offline probe: `alias is cfg.supported_protocols → True`, DIN gone from the config after `.remove`) · EVCC.
- Req: DIN [V2G-DC-618] p90 (the intent is right), [V2G2-167]. Where: `app/evcc/comm_session_handler.py:186-195` (`supported_protocols = self.config.supported_protocols` then `.remove(...)`).
- Failure: multi-protocol personality, first cycle TLS, charger reboots and answers SDP no-TLS → DIN silently missing from the second SAP. `[din-evcc F-20] [transport F-14]`. Fix: `list(...)`.

#### SC-070 · DIN SECC baseline/builder status values: CPDRes pinned to `EVSE_IsolationMonitoringActive` (spec: `EVSE_Ready`); ONGOING CableCheckRes/CPDRes say Valid/EVSE_Ready with an empty tree
- **S3** · confirmed (demo wire DIN `ChargeParameterDiscoveryRes DC_EVSEStatus{EVSEIsolationStatus:0(Invalid), EVSEStatusCode:4(IsolationMonitoringActive)}`) · DIN SECC, ISO-2 SECC.
- Req: [V2G-DC-453] p175, [V2G-DC-498], [V2G-DC-638] p136; [V2G-DC-499] p176, Table 67; ISO-2 8.5.4.1, [V2G2-880].
- Where: `personalities/din-secc-baseline.yaml:57-66` (byte-copy of the real-charger capture) applied at `din_spec_states.py:618-622`; builder defaults `app/secc/controller/simulator.py:1092-1099, 1178-1183` (always Valid/EVSE_Ready even while ONGOING); `personalities/default-secc.yaml:56` (empty tree).
- `[din-secc F-8] [din-secc F-9] [iso2-secc F-18]`. Tags: personality.

#### SC-071 · DIN SECC wrong-but-harmless values: FAILED templates use `EVSENotification=StopCharging` (DIN: always None); `EVSECurrentLimitAchieved` echoes the EV's `ChargingComplete`
- **S3** · confirmed · DIN SECC. Req: [V2G-DC-500]/[636] p135; [V2G-DC-282] Table 48 p121. Where: `app/secc/failed_responses.py:347, 381, 391, 403, 413, 440`; `din_spec_states.py:1111`. `[din-secc F-15] [din-secc F-14]`.

#### SC-072 · DIN SECC missing/unenforced behaviours: PowerDeliveryReq(TRUE) accepted after FALSE; FAILED_ChargingProfileInvalid/TariffSelectionInvalid/ServiceSelectionInvalid(ServiceID)/PowerDeliveryNotApplied never emitted; no SECC-initiated graceful stop; REJECTED authorization never answered; CurrentDemandRes 25 ms performance at risk
- **S3** · confirmed (perf item plausible) · DIN SECC.
- Req: [V2G-DC-459] p176, [V2G-DC-666]; [V2G-DC-266]/[267] p112, [V2G-DC-396]/[399]–[401] p163-164, [V2G-DC-635]; [V2G-DC-662]/[663] p172, Table 68; Table 75 (25 ms), [V2G-DC-358].
- Where: `din_spec_states.py:957-966, 986-998, 1041`; `:398-408` (only empty list checked); `:936-1041`; `:467-473` (REJECTED == ONGOING); `:1138-1142` (three `logger.info` + display params per CurrentDemandRes).
- `[din-secc F-16] [din-secc F-17] [din-secc F-18] [din-secc F-19] [rc-tol F-24] [rc-tol F-25]`.

#### SC-073 · ISO-2 EVCC gaps: EVSENotification=ReNegotiation ignored in the DC loop and EVSEStatus ignored in CPDRes/PowerDeliveryRes; SAP `Failed_NoNegotiation` not recognised (case); charge-loop delay may exceed the 40 s performance time; re-sent AuthorizationReq bypasses the tree
- **S3** · confirmed · ISO-2 EVCC.
- Req: [V2G2-680] p195, [V2G2-686] p202; [V2G2-484]/[172]/[173]; Table 109 (40 s), [V2G2-516]/[531]; [V2G2-684].
- Where: `iso15118_2_states.py:1538-1560` (StopCharging only), `:831-833` (TODO); `evcc_state.py:232` (`"FAILED" in …` is case-sensitive; `sap_states.py:206-210` terminates anyway with a misleading reason); `simulator.py:228` (`min(delay, 50)`), `iso15118_2_states.py:1291-1297` (AC lacks the `delay > 0` guard), `:1541-1550`; `:790-795`.
- `[iso2-evcc F-16] [iso2-evcc F-17] [iso2-evcc F-18] [iso2-evcc F-21] [rc-tol F-27] [rc-tol F-29]`.

#### SC-074 · Pause / resume is not implemented on either role (ISO-2 and ISO-20): EVCC always sends SessionID 0 and `Terminate`; SECC Pause is executed as a data-link TERMINATE; OK_OldSessionJoined unreachable; FAILED_PauseNotAllowed never emitted
- **S3** · confirmed (repro cases E2/A2; demo logs) · ISO-2 both roles, ISO-20 both roles.
- Req: ISO-2 [V2G2-739]–[744] (8.4.2), [V2G2-741]/[753] p70, [V2G2-718]; ISO-20 [V2G20-1540] p146, [V2G20-1541]/[1843]/[2098] p148-150, [V2G20-1777] p50 (D-LINK_PAUSE), [V2G20-463] p403, [V2G20-1195]/[1196] p407, [V2G20-1613]/[2545]/[2623].
- Where: EVCC `iso15118_2_states.py:1323, 1617` (always TERMINATE), `iso15118_20_states.py:1281-1302`, `evcc_state.py:311-314` (TODO), `app/evcc/comm_session_handler.py:241-270` (`save_session_info` logs only), `sap_states.py:359-365` (SessionID always zeros); SECC `iso15118_20_states.py:1354-1364` (Pause → `Terminate`), `app/shared/comm_session.py:389-393` (`update_data_link(TERMINATE)` unless `next_state == Pause`), `app/secc/comm_session_handler.py:147-149, 382-392` (`save_session_info` is `pass`; new session starts with `session_id ""`), `:201-204`.
- The private copy carries a half-built `RESUME_*` global scheme that is never written — do not port. `[iso2-evcc F-23] [transport F-19] [iso20-dc-evcc F-23] [iso20-dc-secc F-8] [iso20-ac-secc F-13] [timers §2.1]`.

#### SC-075 · ISO-2 SECC latent gaps: ONGOING CPDRes builds an empty SAScheduleList instead of omitting it; MeteringReceipt is PnC-only and lacks the DC post-receipt CPDReq path; CertificateUpdateReq not accepted; PnC-only personality on plaintext builds an empty AuthOptionList and crashes
- **S3** · confirmed · ISO-2 SECC.
- Req: [V2G2-688] p206; [V2G2-797] p210, [V2G2-481] p193; [V2G2-551] p205; [V2G2-546] p204.
- Where: `iso15118_2_states.py:1566-1573`; `:2035-2040, 2072-2096`; `:592-603` (no CertificateUpdate state; `failed_responses.py:494` answers FAILED_SequenceError); `:353-367, 437` (`AuthOptionList(auth_options=[])` → ValidationError → no response).
- `[iso2-secc F-13] [iso2-secc F-14] [iso2-secc F-15] [iso2-secc F-16]`.

#### SC-076 · ISO-20 SECC sequence/semantic gaps: ChargeProgress=ScheduleRenegotiation treated as Start; SessionStopReq(ServiceRenegotiation) answered OK not FAILED_NoServiceRenegotiationSupported; Standby (when allowed) processed as Start and loop limits still applied; PowerToleranceAcceptance ignored / EVPowerProfile never validated; side-stream payload types decoded as main stream; SelectedAuthorizationService unchecked; DC_CPDReq never validated; SupportedServiceIDs ignored; EVSEStatus never emitted; FAILED templates carry the wrong control-mode element; after AC Stop still accepts Start / DC_WeldingDetectionReq / SessionStopReq from the loop
- **S3** · confirmed (repro cases E, F, G, J) · ISO-20 SECC DC and AC.
- Req: [V2G20-2018] p435 vs [V2G20-1386]/[1393] p396-397 (self-contradictory); [V2G20-1955] p406, Table 224; [V2G20-1385]/[2118] p395; [V2G20-1944]–[1946] p404, [V2G20-478]/[1070]; [V2G20-1046]/[1047] p441, [V2G20-1084]/[1085] p182; [V2G20-2209]/[2226]/[2227]; [V2G20-2272] p409; Table 38/39 p161; [V2G20-1402]/[1698]/[1959]/[1850]/[1854]; [V2G20-1214]/[1215] p369; [V2G20-1623] p430, [V2G20-2012].
- Where: `iso15118_20_states.py:1193-1264` (no STANDBY/RENEGOTIATION branch), `:1354-1362, 1385-1390`, `:1932-1951`, `:1149-1161, 1262-1264, 1311-1313`, `app/shared/comm_session.py:112-146` (0x8101/0x8102 → Common namespace), `:1520-1521` (TODO), `:448-450`, `:1702-1714` (`charge_parameter_valid` never called), `:622-623, 638-649`, `simulator.py:946-968` (`get_evse_status` → None), `app/secc/failed_responses.py:749-779`, `:1120-1134, 1519-1535`.
- `[iso20-dc-secc F-6/F-7/F-14/F-15/F-16/F-17/F-21/F-23] [iso20-ac-secc F-10/F-12/F-15/F-16/F-18/F-19]`.

#### SC-077 · ISO-20 SECC personality/skeleton emission deviates from the baselines' own provenance: ServiceDetailRes parameter sets ignore ServiceID (EVSENominalVoltage on DC, BPT params missing, Pricing=0 then price schedules); DischargingSchedule +10 kW on plain DC/AC; PowerTolerance announced but never policed; mobility needs regardless of MobilityNeedsMode; EnergyTransferServiceList [2,6] / [1,5] regardless of `supported_energy_services`; EVSEID `PcLoadLetter`; AC_CPDRes MaximumPowerAsymmetry=0 / EVSEPowerRampLimitation=100 / EVSEPresentActivePower=0 not in the real-charger baseline capture
- **S3** · confirmed (repro cases D2/I/J; demo wire `ServiceDiscoveryRes ids [2,6]` (DC) and `[1,5]` (AC), `AC_CPDRes{MaximumPowerAsymmetry:0, EVSEPowerRampLimitation:100, …}`, SECC log "BPT_DC_CPDResEnergyTransferMode is absent … override skipped") · ISO-20 SECC.
- Req: [V2G20-1357] Table 207 p374, [V2G20-1360] Table 208; [V2G20-1035] p248/269; [V2G20-1069] p171, [V2G20-1864]–[1866] p268; Table 109 p262, [V2G20-2660]; [V2G20-1931] p371, Table 204; [V2G20-192]/[2087] (IEC 63119-2 EVSEID, verify-IEC); Table 160 p308-310, [V2G20-1829]–[1831].
- Where: `app/secc/controller/simulator.py:619-691, 483-618, 589-611, 693-732, 734-751, 210-218, 1033-1058, 1292-1352`; `app/secc/secc_settings.py:44-62` (`supported_energy_services` never read); baselines `iso20-dc-secc-baseline.yaml:37-43, 57-59, 75, 80-92`, `iso20-ac-secc-baseline.yaml:28-48, 97-101`.
- `[iso20-dc-secc F-10/F-11/F-12/F-22] [iso20-ac-secc F-7/F-8/F-9]`. Tags: personality, baseline-deviation, bpt-adjacent.

#### SC-078 · ISO-20 EVCC robustness/personality gaps: `supported_auth_modes` not honoured (PnC chosen whenever offered; `FileNotFoundError` without PKI); "no matching energy service" SessionStopReq unbuildable (`ev_termination_code=1` is an int, model wants a URN string); `SessionStop` crashes on `None.lower()` when the stop marker was never set (then SDP is restarted); renegotiation acted on when the SECC said unsupported; `max_supporting_points < 12` loads but crashes at ScheduleExchange; unexpected/stray responses terminate instead of being ignored until the message timer; EVCCID `1FMVAA45B63C47DD58Y6` is not VIN-shaped; scheduled EVEnergyOffer at −10 kW on a charge-only service; MobilityNeedsMode=2 (AckMaxDelay/DepartureTime/SOC updates) ignored; Standby / EVCC-initiated pause / WARNING_* handling absent
- **S3** · confirmed (int termination code reproduced by model instantiation) · ISO-20 EVCC DC and AC.
- Req: [V2G20-2562] p158; [V2G20-2644] p413, Table 50 p180; [V2G20-1463]; [V2G20-1652]/[1480] p414/420; [V2G20-1202]/[1056]; [V2G20-440]/[438]/[1966] p385/414; [V2G20-1062] p154; [V2G20-1034]/[1035] p248, [V2G20-1861]; [V2G20-1368]/[1369] p379, [V2G20-2120]; [V2G20-1390]/[1391]/[1393], [V2G20-2201], [V2G20-1953]/[1954].
- Where: `iso15118_20_states.py:317-356, 578-602, 698-717, 1281-1302, 1815-1819, 554-556, 1038-1046, 1330-1346, 1401-1494`; `evcc_state.py:213-257, 276-314, 303-307`; `evcc_config.py:36, 117-126`; `common_messages.py:501-503, 1123-1128`; `simulator.py:192-209, 344-351, 406-416, 588-658, 694-773`.
- `[iso20-dc-evcc F-10/F-11/F-12/F-16/F-17/F-19/F-20/F-21/F-24] [iso20-ac-evcc F-9/F-10/F-12/F-13] [rc-tol F-28]`.

#### SC-079 · Transport S3 bundle: bad V2GTP header terminates the session instead of "ignore this message" (no DIN payload-type check, no payload-length-vs-buffer check); EVCC SDP client stalls on an unacceptable/undecodable response and can consume a stale one; DIN SDP retry limit 5 (we use 50); EVCC TCP/UDP source ports OS-ephemeral (32768-60999) not 49152-65535; `TCPServer._refresh_port` loop inverted (`!=` should be `==`, so EADDRINUSE retries rebind the same port); SECC restarts its TCP/TLS server on every SDP request (SYN in the gap is RST); SDP server absent for seconds after SLAC match (field cycle 2: 7 unanswered SDP requests); TLS hardening gaps (no `trusted_ca_keys`/OCSP/DC=CPO check, key-log files written unconditionally); DIN-only SECC answers a TLS SDP request with TLS (no `serve_tls` knob)
- **S3** · confirmed (except restart-on-SDP and SDP-absence, plausible) · both roles.
- Req: [V2G2-800] p41, [V2G20-800] p93, DIN [V2G-DC-169]/[171]–[173] p80; [V2G2-126] p53, [V2G2-157]–[161] p56, [V2G2-628], [V2G2-020]; DIN [V2G-DC-216] p91; Table 8 p38, [V2G2-077], Table 15 p53, [V2G2-124]/[138], DIN [V2G-DC-153]/[158]; [V2G2-078]; [V2G2-144] p55, [V2G2-030]/[031] p30, [V2G2-027]; [V2G2-651] p36, [V2G2-070], [V2G2-875] p37, [V2G20-2677]; DIN [V2G-DC-618] p90.
- Where: `app/shared/comm_session.py:185-188, 465-487`; `app/shared/messages/v2gtp.py:372-385, 428-441, 479-482`; `app/evcc/comm_session_handler.py:75, 414-436, 524-532, 549-560`; `app/evcc/transport/udp_client.py:314-332, 434-446`; `app/evcc/transport/tcp_client.py:223-228`; `app/secc/transport/tcp_server.py:173-177` (verified: `while random_port != self.port: random_port = get_tcp_port()`); `app/secc/comm_session_handler.py:436-480`; `app/secc/controller/evse.py:196-211`; `app/shared/security.py:156, 202-217`.
- Evidence: our EVCC's field TCP source ports 37802/43176; `why_no_work.pcapng` cycle 2 (match 412.62 s, SDP 416.97-418.41 s unanswered). `[transport F-6/F-9/F-12/F-13/F-15/F-16/F-17/F-18/F-20] [iso2-evcc F-24]`. Tags: `private_changelog.txt` item 3 fixed the port range in the old .env codebase.

#### SC-080 · SLAC S3 bundle (SECC): ATTEN_CHAR.IND only when the Countdown=0 sound arrives (no TT_EVSE_match_MNBC 600 ms / TT_match_sequence 400 ms fallback, START_ATTEN_CHAR.IND ignored, NumSounds hard-coded 10); CM_ATTEN_CHAR.RSP never processed (no IND retransmit, no TT_EVSE_match_session); NMK a static personality constant (never random, never regenerated after plug-out; NID/NMK unvalidated — defaults verified internally consistent); no leave / D-LINK_TERMINATE at session end; canned ATTEN_PROFILE averages 32.3 dB (> 20 dB EVSE_NOT_FOUND for a literal Table A.3 EV); CM_VALIDATE / CM_AMP_MAP unimplemented; SET_KEY nonce 0xAAAAAAAA and CCo capability 0 on both roles
- **S3** · confirmed · SECC SLAC.
- Req: [V2G3-A09-39]–[47] p52, [V2G3-A09-96] p61; [V2G3-A09-92]/[93] p58, DIN [V2G-DC-574]–[576]/[734]/[735] p28; [V2G3-M09-17]/[18] p33, [V2G3-A09-121] p67, [V2G2-717]; Table A.3 p41, [V2G3-A09-19]/[20]; [V2G3-A09-75]–[90] p57-58, [V2G3-A09-115]/[116]; Table A.8 p63.
- Where: `app/secc/transport/slac.py:216-226, 235-239, 285, 288-348, 389-396, 214-215`; `app/shared/personality/model.py:66-79`; `app/secc/controller/evse.py:73-74, 222-228`; `external_libs/HomePlugPWN/layerscapy/HomePlugGP.py:7-17, 204-215` (no CM_VALIDATE/CM_AMP_MAP/CM_ATTEN_PROFILE layers).
- `[slac F-3/F-4/F-5/F-6/F-12/F-14/F-19]`. Tags: personality, verify-HPGP.

#### SC-081 · SLAC S3 bundle (EVCC): PARM.REQ retry every ~2 s (integer-second timer), unbounded, never FAILED/Unmatched (spec 200 ms × 3, stop after 10 s); one RunID per cycle reused across restarts; ATTEN_CHAR.IND wait 1000 ms vs TT_EV_atten_results 1200 ms and expiry restarts instead of FAILED; retransmitted IND not re-answered; no attenuation decision and RSP/MATCH.REQ addressed to the last PARM.CNF sender; MATCH.REQ not retransmitted on a lost CNF; no link detection / TT_match_join (SDP starts right after SET_KEY); received-MME validation gaps (unicast dst, APPLICATION/SECURITY_TYPE, varfield RunID)
- **S3** · confirmed · EVCC SLAC.
- Req: [V2G3-A09-07]/[08]/[10] p45, [V2G3-A09-122]–[125] p67, Table A.1 p40-41, Table 3 p27; Table A.2 p38; [V2G3-A09-30]/[32]/[34] p51; [V2G3-A09-37]; [V2G3-A09-20]–[22], [V2G3-A09-33]/[36]/[38], [V2G3-A09-100]; [V2G3-A09-94] p61; [V2G3-A09-102]/[117]/[120] p63; DIN [V2G-DC-573] p28, [V2G-DC-589]–[592] p47-48, [V2G-DC-679]/[681] p50, [V2G-DC-727] p55.
- Where: `app/evcc/transport/slac.py:38, 126-132, 164, 198-216, 231-239, 262-278, 333, 349, 359`; `app/evcc/controller/pev.py:86, 190-208`; `app/shared/personality/model.py:77` (`sound_timeout_ms = 1000`).
- Evidence: field note "264 s of unanswered PARM.REQ every 2 s" matches the `int(time.time())` quantisation. `[slac F-7/F-8/F-9/F-10/F-11/F-13/F-16/F-18] [timers F-11]`. Tags: ADR-0005, personality, crosstalk.

#### SC-082 · Duplicate `enable_charging(True)` call in the ISO-2 CPD state; DIN call after `create_next_message` (still before send)
- **S3** (cosmetic; ordering holds) · confirmed · Where: `iso15118_2_states.py:842, 872`; `din_spec_states.py:449-457`. `[pcap §7]`. Fold into the SC-001 port.

### S4 — hardware-gated

#### SC-083 · SECC CP-state gates absent: no C/D gate at CableCheck, no State-B gate for WeldingDetection/SessionStop, no continuous A/E/F/unexpected-B monitoring, `wait_for_state_c_or_d` result only logged; emergency-shutdown / oscillator-off order and V2G_SECC_CPOscillator_Retain_Time only satisfied by the incidental 5 s teardown; SLAC answered regardless of CP state
- **S4** · confirmed (logic absent; `get_cp_state` always `C2`) · SECC all protocols.
- Req: DIN [V2G-DC-661] p172, [V2G-DC-547] p175, [V2G-DC-556] p176, [V2G-DC-667]–[670] p173, [V2G-DC-366]/[665]/[666], [V2G-DC-672] p177, Table 77 p160; ISO-2 [V2G2-916]–[922] p189-190, [V2G2-858]–[866] p188-189, [V2G2-915]; ISO-20 [V2G20-916]–[922] p398-399, [V2G20-858]–[864] p397, [V2G20-1408]; ISO-3 [V2G3-A09-03]/[11]–[13].
- Where: `app/secc/controller/simulator.py:930-944, 1197-1212, 1499-1503`; CableCheck `din_spec_states.py:632-786`, `iso15118_2_states.py:2305-2421`, `iso15118_20_states.py:1717-1815`; `wait_for_state_c_or_d` `iso15118_2_states.py:1878-1907` / `iso15118_20_states.py:1282-1309` (warning only); `din_spec/timeouts.py:21-22` unused; `app/shared/relays.py:285-305` (SECC drives only a CP relay; the 5 % PWM is a fixed TLC555 board; no PWM/duty control in software); `app/shared/comm_session.py:373-417`, `app/secc/controller/evse.py:223-244`.
- Note: when CP sensing arrives, `get_cp_state` alone will not make the SECC conformant — the gates must be added and the PowerDelivery warning turned into FAILED_ContactorError after the performance window. Relay-open ⇒ CP 0 V ≈ State E, not "oscillator off" ⇒ static +12 V (verify-IEC).
- `[din-secc F-4/F-5] [iso2-secc F-17] [iso20-dc-secc F-19] [iso20-ac-secc F-21] [timers F-12/F-13] [rc-tol F-31] [slac F-17]`.

#### SC-084 · EVCC has no CP sensing: State E/F cannot be detected, 5 % PWM cannot be measured before CPDReq / SLAC start, DIN 649-vs-652 (oscillator on/off) undecidable
- **S4** · confirmed · EVCC all protocols.
- Req: [V2G2-737] p187, [V2G-DC-655] p168; [V2G-DC-647]/[656], [V2G2-930]/[V2G20-930]; [V2G3-M06-11]/[13], DIN [V2G-DC-564]/[733] p22, [V2G-DC-588]/[594].
- Where: `app/shared/EmulatorEnum.py` (`PEVState` A/B/C only), no CP read on the EV side; `pev.py:186-190` (SLAC the instant the B relay closes). `[iso2-evcc F-22] [timers §2.1] [slac F-17] [din-evcc F-8 S4 aspect]`.

#### SC-085 · Physical DC stage absent: pre-charge match, welding detection, contactor/isolation behaviour cannot be real (ceiling for real vehicles at PreCharge / CableCheck)
- **S4** · confirmed · both roles. The software-fixable parts are SC-029 (report the target) and SC-067 (compare against the right target). `[din-secc §PreCharge triage] [iso2-secc F-1 S4 part] [iso20-dc-secc F-20]`.

---

## 4. Tolerant-receive inventory (the S2 work list)

Every place a decodable peer value is rejected by a model facet/enum or a state gate. "XSD" is the
wire type; "seen" is a real-device value from the captures or memory notes. All rejections go
through the SC-031 path (silent 5 s close, nothing sent).

| File:line | Field | Current constraint | XSD / spec allows | Seen | SC |
|---|---|---|---|---|---|
| `app/shared/messages/din_spec/datatypes.py:136-139` | DIN `EVSEStatus.NotificationMaxDelay` | `ge=0, le=65535` | `xs:unsignedInt` (DIN p196) | 50331648, 33554432 (Charger C DIN) | SC-002 |
| `app/shared/messages/datatypes.py:578-581` | ISO-2 `EVSEStatus.NotificationMaxDelay` (DC and AC) | `ge=0, le=65535` | `unsignedShort` (p272); [V2G2-678] ignore when None | — | SC-002 |
| `app/shared/messages/iso15118_2/body.py:334, 385, 607` | ISO-2 `EVSEID` (SessionSetupRes, ChargingStatusRes, CurrentDemandRes) | `min_length=7, max_length=37` | minLength 7 (peer non-conformant) | `"\x00"` (Charger C ISO-2) | SC-032 |
| `app/shared/messages/din_spec/datatypes.py:102` | DIN `ServiceDetails.ServiceName` | `Optional[ServiceName]` enum | `xs:string` maxLength 32 | `DC_CHARGING` (Charger A/Charger B on ISO-2) | SC-033 |
| `app/shared/messages/iso15118_2/datatypes.py:154-178` (working tree) | ISO-2 `ServiceName` | fixed → `Optional[str]` | as above | `DC_CHARGING` | SC-033 |
| `app/shared/messages/iso15118_2/datatypes.py:175` | ISO-2 `ServiceDetails.ServiceID` / `ChargeService` | `ServiceID` IntEnum {1..4} | `unsignedShort`, 60001-65535 vendor | 4660 (third-party DIN charger) | SC-034 |
| `app/shared/messages/iso15118_2/header.py:31-51`, `iso15118_20/common_types.py:57-76`, `iso15118_2/body.py:404-421` | SessionID | `int(value,16)` raises on `""` | hexBinary maxLength 8 (length 0 legal) | `bytesLen: 0` (real EV, DIN) | SC-035 |
| `app/shared/messages/enums.py:317-338` via `app/evcc/states/iso15118_20_states.py:604-614` | ISO-20 VAS `ServiceID` | `ServiceV20(id)` raises | Table 204 (32768-65535 vendor) | 4660-class | SC-036 |
| `app/evcc/states/din_spec_states.py:545-561`, `iso15118_2_states.py:1361-1376` | CableCheckRes `EVSEStatusCode` / `EVSEIsolationStatus` on Finished | must be `EVSE_Ready` + `Valid` | any; status codes informational; isolation optional | `EVSE_IsolationMonitoringActive` on Finished (some EVSEs) | SC-037 |
| `app/evcc/states/din_spec_states.py:812-815` | CurrentDemandRes `EVSEStatusCode` | stop unless `EVSE_Ready` | only `EVSE_Shutdown` is normative | — | SC-038 |
| `app/secc/states/din_spec_states.py:677-685, 843-851`; `iso15118_2_states.py:2325-2333, 2460-2468` | `EVErrorCode` | FAILED unless `NO_ERROR` | all values informational ([V2G-DC-640], [V2G2-881]) | — | SC-004 |
| `app/secc/states/din_spec_states.py:857-882`; `iso15118_2_states.py:2476-2496` | PreChargeReq `EVTargetCurrent` | FAILED if > 2 A | no bound (61851-23 output limit) | — | SC-039 |
| `app/evcc/states/din_spec_states.py:440-442`; `iso15118_2_states.py:835-841` | CPDRes `SAScheduleList` on Finished | dereferenced unconditionally | optional in schema | DIN-only chargers omit it | SC-040 |
| `app/shared/messages/iso15118_20/common_messages.py:984-1021` | PowerDeliveryReq `EVPowerProfile` | required unless Ongoing/Stop | must be absent for Renegotiate ([V2G20-1414]) | — | SC-041 |
| `app/shared/messages/iso15118_20/common_messages.py:803-843` | `Dynamic_SEResControlMode` MinimumSOC/TargetSOC | raises if Min > Target | EV-side shall | — | SC-042 |
| `app/shared/messages/iso15118_20/common_messages.py:501-503` | `MaximumSupportingPoints` | `ge=12, le=1024` | 12 is the *minimum supported* (verify-XSD) | — | SC-042 |
| `app/shared/messages/iso15118_20/common_types.py:352-366, 209-233, 248-251, 42` | SOC fields, `MeterID`, `NumericID` | `0..100`, `max_length=32`, `ge=1` | percentValueType 0..100 (likely moot), string, unsignedInt | — | SC-042 |
| `app/shared/messages/iso15118_2/datatypes.py:102` | `SubCertificates.Certificate` | `max_length=2` | 4 ([V2G2-656] sender rule) | — | SC-043 |
| `iso15118_2/datatypes.py:431-432`, `din_spec/datatypes.py:248-249` | `RelativeTimeInterval.start/duration` | `le=16777214` / `le=86400` | `unsignedInt` | — | SC-043 |
| `iso15118_2/datatypes.py:336` | `MeterInfo.MeterReading` | `le=999999999` | `unsignedLong` | — | SC-043 |
| `iso15118_2/datatypes.py:576-593` | `SalesTariffID` | 1..255 | `unsignedByte` (0 allowed) | — | SC-043 |
| `din_spec/datatypes.py:265-268` | `PMaxScheduleEntry` list | `max_length=12` | 1024 ([V2G-DC-329] sender rule) | 24 entries in ISO-2-derived firmware | SC-043 |
| `din_spec/body.py:135` | DIN `SessionSetupRes.EVSEID` | `min_length=2` (hex) | hexBinary maxLength 32 (length 0 possible) | `"00"` accepted | SC-043 |
| `app/shared/messages/datatypes.py:83-537` | every `PVxxx.Unit` | `Literal[…]` | unitSymbolType enum (wrong unit ⇒ log) | Charger D negative present current accepted (fine) | SC-043 |
| `iso15118_2/datatypes.py:60` | `eMAID` | `constr(14..15)` | some MOs embed separators | — | SC-043 |
| `iso15118_2/body.py:493, 336, 387` | `SAScheduleTupleID` | `ge=1` | `unsignedByte` | — | SC-043 |
| `din_spec/datatypes.py:159-160` + `messages/__init__.py:5-10` | DIN `ServiceList` | empty model, `extra="forbid"` | [V2G-DC-549] is a sender rule | dual-stack chargers | SC-043 |
| `app/shared/messages/iso15118_20/common_types.py:102-146` | ISO-20 `ResponseCode` enum | closed set | text names WARNING_ContractCancelled / FAILED_TariffSelectionInvalid (verify-XSD) | — | SC-048 |
| `app/shared/messages/sdp.py:174-179, 220-225` | SDP response port / Security / Transport bytes | out-of-range → attribute-less object / bare `ValueError` | value problem → log, keep discovering | port 8000/15118 class | SC-046 |
| `app/evcc/transport/slac.py:240-255` | PARM.CNF `NUM_SOUNDS` | trusted (0 crashes) | deviating content → ignore frame | — | SC-047 |
| `app/shared/messages/v2gtp.py:372-385, 428-441, 479-482` | V2GTP payload type / length | unknown type → `ValueError` → session stop; no DIN check; no length check | ignore the message ([V2G2-800]) | — | SC-079 |

Verified vacuous (no finding): `SalesTariffEntry.at_least_one_cost_indicator`,
`SalesTariff.check_num_e_price_levels` (pydantic v2 skips validators for unset Optionals);
`PhysicalValue._max_limit` never set, so the "Table 68 max value" check never fires; ISO-20
`EVSEID` (any string ≤ 255) and ISO-20 `NotificationMaxDelay` (unbounded) already tolerant.

---

## 5. Timer conformance table

Enforcement legend: **R** = enforced as the socket receive timeout after the named message
(`comm_session.py:453/508`, the third argument of `create_next_message`); **O** = elapsed-time check
on the ONGOING branch; **cosmetic** = only the value passed to `State.__init__` (logged, never read);
**—** = defined, never read; **n/i** = not implemented.

### 5.1 DIN 70121 (Tables 74/75 p152-153, 76/77 p159-160)

| Spec timer | Spec | Code constant | Enforced where | Verdict |
|---|---|---|---|---|
| V2G_EVCC_Msg_Timeout(SAP) | 2 s | shared `SUPPORTED_APP_PROTOCOL_REQ` 2.0 | R `evcc handler:479` | ok |
| Msg_Timeout(SessionSetup/ServiceDiscovery/ServicePaymentSelection/ContractAuthentication) | 2 s | 2 | R `sap_states.py:197`, `din_spec_states.py:155,228,289,374` | ok |
| Msg_Timeout(ChargeParameterDiscoveryReq) | 2 s | 2 | R `:374` first send; **re-send `:480` uses 60 s** | SC-054 |
| Msg_Timeout(CableCheck/PreCharge/PowerDelivery/WeldingDetection/SessionStop) | 2 s | 2 | R `:449,:577,:553,:660,:643,:845,:726,:957` | ok |
| Msg_Timeout(CurrentDemandReq) | 0.25 s | 0.25 | R `:718,:825` | ok |
| V2G_SECC_Sequence_Timeout (all) | 60 s | `V2G_SECC_SEQUENCE_TIMEOUT` 60 | R every SECC `create_next_message`; initial SAP wait is **20 s** (`secc handler:409`) | SC-051 (stricter, harmless) |
| V2G_EVCC_CommunicationSetup_Timeout | 20 s | `V2G_EVCC_COMMUNICATIONSETUP_TIMEOUT` 20 | cosmetic (SECC SessionSetup init `secc din:173`) | SC-055 |
| V2G_EVCC_ReadyToCharge_Timeout | 150 s | `V2G_EVCC_READYTOCHARGE_TIMEOUT` 150 | — ; replaced by a non-spec 60 s ongoing abort at CA/CPD/WD | SC-022 |
| V2G_EVCC_CableCheck_Timeout | 40 s | 40 | O `din_spec_states.py:563-570` (starts at first ONGOING *response*) | ok, one RTT late (SC-055) |
| V2G_EVCC_PreCharge_Timeout | 7 s | 7 | O `:651-657` | ok, one RTT late |
| V2G_SECC_CPState_Detection_Timeout | 1.5 s | `V2G_SECC_CPState_Detection_Timeout` 1.5 | — (needs CP sensing) | SC-083 |
| V2G_SECC_CPOscillator_Retain_Time | 1.5 s | `V2G_SECC_CPOscillator_Retain_time` 1.5 | — ; incidentally ≥5 s via `stop()` 2+3 s then `openProximity()` | SC-083 |
| Performance times (Msg 25 ms CurrentDemandRes, Setup 18, ReadyToCharge 148, CableCheck 38, PreCharge 5) | perf | none | nothing delays a response; CurrentDemandRes 25 ms unmeasured (three info logs per Res) | SC-072 |

### 5.2 ISO 15118-2 (Tables 108/109 p177-179, 110/111 p182)

| Spec timer | Spec | Code | Enforced where (`app/evcc/states/iso15118_2_states.py` unless noted) | Verdict |
|---|---|---|---|---|
| SAP / SessionSetup / ServiceDiscovery / PaymentServiceSelection / Authorization / CPD / ChargingStatus / MeteringReceipt / CableCheck / PreCharge / WeldingDetection / SessionStop | 2 s | 2 | R (`:193,:258,:400,:523,:690,:747,:994,:1111,:1302,:1261,:863,:1395,:1369,:1481,:960,:1671,:948`); re-sends `:790,:905` = `min(2, 60-elapsed)` | ok |
| ServiceDetail / PaymentDetails / PowerDelivery / CertificateInstallation | 5 s | 5 | R (`:270,:412,:514,:634,:851,:1084,:1098,:1281,:1317,:1463,:1611,:484`) | ok |
| CertificateUpdateReq | 5 s | 5 | n/i (no EVCC state) | out of scope |
| CurrentDemandReq | 0.25 s | 0.25 | **never used**: entry `:1003` 2 s (`CHARGING_STATUS_REQ`), loop `:1553` 5 s (`POWER_DELIVERY_REQ`); 0.25 only cosmetic `:1432,:1518` | SC-053 |
| V2G_SECC_Sequence_Timeout | 60 s | 60 | R every SECC ISO-2 `create_next_message` | ok |
| V2G_EVCC_Ongoing_Timeout | 60 s | shared 60 | O Authorization `:766-777`, CPD `:879-887`, WeldingDetection `:1645-1654` (no EVSEProcessing there — harmless cap); also applied to `Ongoing_WaitingForCustomerInteraction` | SC-058 |
| V2G_SECC_Ongoing_Performance_Time | 55 s | none | n/i (SECC never times its own ONGOING, never sends the mandated FAILED) | SC-057 |
| V2G_EVCC_CommunicationSetup_Timeout | 20 s | shared 20.0 | cosmetic (`:167`) | SC-055 |
| V2G_SECC_CommunicationSetup_Performance_Time | 18 s | 20 (SAP wait) + 60 (SessionSetupReq wait) | R, wrong split (`secc handler:409`, `secc sap_states.py:136`) | SC-051 |
| V2G_EVCC_CableCheck_Timeout | 40 s | 40 | O `:1380-1386` (first ONGOING response) | ok |
| V2G_EVCC_PreCharge_Timeout | 7 s | 7 | O `:1472-1478` | ok |
| V2G_EVCC_Sequence_Performance_Time | 40 s | none | `charge_profile.delay_seconds` ≤ 50 s can exceed it (personality) | SC-073 |
| SDP: ≥250 ms, ≤50 requests | 0.25 / 50 | `Timeouts.SDP_REQ`, `SDP_MAX_REQUEST_COUNTER` 50 | `udp_client.py:175`, `evcc handler:75` | ok (DIN wants 5, SC-079) |

### 5.3 ISO 15118-20 (Tables 214/215 p381-383, 216/217 p386, 220-223 p387-392)

| Spec timer | Spec | Code | Enforced where | Verdict |
|---|---|---|---|---|
| SessionSetup / AuthorizationSetup / Authorization / ServiceDiscovery / ServiceSelection / CPD / ScheduleExchange / PowerDelivery / SessionStop | 2 s | 2 | R `app/evcc/states/iso15118_20_states.py` (`:206,:378,:453,:725,:853,:891,:1340,:1532,:935,:994,:1248,:1081,:595`) | ok |
| CertificateInstallation / ServiceDetail | 5 s | 5 | R `:303` / `:632,:683` | ok |
| AC_ChargeLoopReq | 0.5 s | 0.5 | R `:1143,:1486` | ok |
| DC_CableCheck / DC_PreCharge / DC_WeldingDetection | 2 s | 2 | R `:1009,:1626 / :1599,:1693 / :1065,:1939` | ok |
| DC_ChargeLoopReq | 0.5 s | 0.5 | R `:1187,:1832` | ok |
| MeteringConfirmation, VehicleCheckIn/Out, ACDP_*, WPT_* | 2 s | 2 | n/i (no states) | out of scope |
| V2G_SECC_Sequence_Timeout (non-loop) | 60 s | 60 | R every SECC ISO-20 `create_next_message` | ok |
| V2G_SECC_Sequence_Timeout AC/DC/WPT_ChargeLoopRes | 0.5 s | `V2G_SECC_SEQUENCE_TIMEOUT_{AC,DC,WPT}_CL` 0.5 | **never read**; SECC `:1274-1280,:1602,:1963` use 60 s | SC-052 |
| V2G_EVCC_Ongoing_Timeout ("may") | 60 s | 60 | O Authorization `:475-486`, DCWeldingDetection `:1902-1911`; ScheduleExchange none | SC-059 (allowed) |
| V2G_SECC_Ongoing_Performance_Time ("may") | 55 s | none | n/i | acceptable |
| V2G_EVCC_CommunicationSetup_Timeout | 20 s | 20 | cosmetic (`:176`) | SC-055 |
| V2G_SECC_CommunicationSetup_Performance_Time | 18 s | 20 + 60 | as ISO-2 | SC-051 |
| V2G_EVCC_DC_CableCheck_Timeout | 40 s | 40 | O `:1608-1614` (1 s granularity) | ok |
| V2G_EVCC_DC_PreCharge_Timeout | 10 s | `V2G_EVCC_PRE_CHARGE_TIMEOUT` 10 | **never read** (`:1657-1710`) | SC-056 |
| SDP DiagStatus ongoing | 60 s | — | n/i | out of scope |

### 5.4 ISO 15118-3 SLAC (Table 3 p27, Table A.1 p40-41) and data link

| Spec timer | Spec | Code | Verdict |
|---|---|---|---|
| TP_EV_SLAC_init | ≤10 s | SLAC immediately after State B relay (`pev.py`) | ok (but no 5 % sensing, SC-084) |
| TT_match_response / C_EV_match_retry | 200 ms / 2 | EVCC `timeout = 1` (integer seconds ⇒ ~2 s), restart forever | SC-081 |
| TT_EV_atten_results | 1200 ms | `residual.slac.sound_timeout_ms` 1000 → restart | SC-081 |
| TP_EV_batch_msg_interval / C_EV_start_atten_char_inds / C_EV_match_MNBC | 20-50 ms / 3 / 10 | 20 ms / 3 / NumberMSounds from CNF (0x0A) | ok |
| TT_EVSE_match_MNBC / TP_EVSE_avg_atten_calc | 600 ms / 100 ms | IND only on Countdown==0 sound; no 600 ms fallback | SC-080 |
| TT_match_sequence / TT_EVSE_match_session | 400 ms / 10 s | not enforced; no IND retransmit | SC-080 |
| TT_EVSE_SLAC_init (+T_step_EF) | 20-50 s (4 s) | SECC waits indefinitely; 8 s SET_KEY re-key is not a spec timer | SC-028/SC-083 |
| TT_match_join | 12 s | neither side; EVCC SDP budget (50×250 ms) brackets it by accident | SC-081 |
| TT_matching_repetition / C_conn_max_match / TT_matching_rate | 10 s / 3 / 400 ms | EVCC retries every ~2 s without bound | SC-081 |
| TP_match_leave | 1 s | never leaves the AVLN | SC-080 |
| T_conn_max_comm ([V2G-DC-507]) | 8 s | SECC SLAC listener up before its CP relay closes | ok |

---

## 6. Demo-run wire evidence (what the four self-pair sessions prove)

| Claim | ISO-2 (`default-*`, TLS 1.3, PnC) | DIN (per-role defaults, plaintext) | ISO-20 DC (`iso20_dc-*`) | ISO-20 AC (`iso20_ac-*`) |
|---|---|---|---|---|
| Session completes | yes (SessionStop, State A) | yes | yes | yes |
| `ChargingComplete=TRUE` on PowerDeliveryReq Start (SC-003) | **yes** (`ChargeProgress:0, ChargingComplete:1`) | **yes** (`ReadyToChargeState:1, ChargingComplete:1`) | n/a (DisplayParameters `ChargingComplete:0`) | n/a |
| Loop cycles consumed before the loop (SC-003) | 9 CurrentDemandReq, SOC 20 on the first | **8** CurrentDemandReq for `charge_loop_cycle: 10` | 10 DC_ChargeLoopReq | 10 AC_ChargeLoopReq |
| SECC present voltage constant 1 V (SC-029) | PreChargeRes ×6 = 1 V | PreChargeRes ×6 = 1 V; CurrentDemandRes 1 V / 1 A; WeldingDetectionRes 1 V | DC_PreChargeRes ×4 = 1 V; DC_ChargeLoopRes 1 V / 1 A | n/a |
| PreCharge ends on a counter (SC-067) | 6 pairs | 6 pairs (target 800 V vs 1 V) | 4 pairs (target 20000 V vs 1 V) | n/a |
| Both EVTargetVoltage and EVTargetCurrent in scheduled DC_ChargeLoopReq (SC-010) | — | — | **yes** (200 A + 20000 V, all 10) | — |
| Skeleton magnitudes (SC-011) | — | — | DC_PreChargeReq EVPresentVoltage/EVTargetVoltage 20000 V | AC_CPDReq 9000 W then loop `EVPresentActivePower` 200000 W |
| L2/L3 without EV asymmetry (SC-012) | — | — | — | **yes** in AC_CPDRes and every AC_ChargeLoopRes |
| 10 W targets in Scheduled AC loop (SC-013) | — | — | — | **yes** (`EVSETargetActivePower 10`, reactive 10, L2/L3) |
| TimeStamp seconds, repeated (SC-050) | — | — | `1790715848` on 6 consecutive messages | same pattern |
| TimeAnchor 0 (SC-014) | — | — | ScheduleExchangeReq and EVPowerProfile | — |
| PowerDeliveryReq(Stop) without profile (SC-030) | — | — | **yes** | **yes** |
| CertificateInstallationService advertised (SC-015) | — | — | **yes** (`AuthorizationServices:[EIM], CertificateInstallationService:1`) | — |
| EnergyTransferServiceList vs `supported_energy_services` (SC-077) | — | — | `[2, 6]` | `[1, 5]` |
| Zero-SessionID "does not match" log noise (SC-064) | **yes** | no (DIN compares numerically) | **yes** | **yes** |
| `EVReady=true` while stopping (SC-066) | WeldingDetectionReq ×4 `EVReady:1` | PowerDeliveryReq(FALSE) `EVReady:1` | — | — |
| DIN 800 V target vs 410 V max (SC-068) | — | **yes** | — | — |
| CPDRes pinned `EVSE_IsolationMonitoringActive`/Invalid (SC-070) | — | **yes** (`EVSEStatusCode:4, EVSEIsolationStatus:0`) | — | — |
| DIN removed from SAP under TLS (SC-069 precondition) | log "Removed DIN_SPEC …" | — | — | — |
| Header Notification on FAILED (SC-061) | not exercised (no FAILED in a clean run) | idem | idem | idem |

---

## 7. Private-copy fix assessment (`private_worktree.diff`, 2026-09-23 edits)

**Port (DC is spec-correct):**
- `app/evcc/controller/simulator.py`: `SimEVController.__init__(…, cp_state_setter=None)` and
  `enable_charging(enabled)` → `cp_state_setter(PEVState.C if enabled else PEVState.B)`.
- `app/evcc/controller/pev.py`: pass the setter — but wire it to the ADR-0007 role-scoped
  `EvccRelays.set_state` (`app/shared/relays.py:263-284`), **not** the diff's raw SMBus / whole-register
  writes, which revert #108 and would clobber a co-hosted SECC's relays. `--virtual` stays a no-op
  (`EvccRelays.write` returns early).
- `app/evcc/states/iso15118_2_states.py` ~:874-880: single `enable_charging(True)` before the AC/DC
  branch (removes the duplicate, SC-082); ~:980-994: `enable_charging(False)` before SessionStopReq on
  the AC stop path. DIN (`din_spec_states.py:457,725`) and ISO-20 (`iso15118_20_states.py:979,1052`)
  call sites need no change for DC.
- Timing the DC part satisfies as-is: [V2G-DC-501]/[502], [V2G2-912]/[913]/[914], [V2G20-912]/[913]/[914];
  SECC windows [V2G-DC-547] 1.5 s, [V2G2-917] 1.5 s, [V2G-DC-556] 1.5 s, [V2G2-920] 1.5 s — the relay
  write precedes the request on the wire (relay settle ~10 ms, verify-IEC). Charger A answered FAILED at
  0.46 s (CableCheck) and 60 ms (WeldingDetection), i.e. it samples on arrival: add a **~100-300 ms
  settle** between the relay write and the next request (not spec-mandated; verify-IEC) — SC-066.

**Do not port:**
- The `pev.py` / `evse.py` relay reversions (direct SMBus, whole-register writes) — regression vs ADR-0007 / #108.
- ESDP / "-202" additions and the older settings/relay code (per briefing).
- The half-built `RESUME_*` global pause scheme (never written; SC-074 needs a real design).

**AC timing corrections the reviewers recommend (all three reviewers agree):**
- Start: [V2G2-846]/[V2G20-1617] want State B **when the first PowerDeliveryReq(Start) is sent** and C
  ≤250 ms **after** ([V2G2-847]/[V2G20-847]). The candidate (and the unchanged ISO-20 AC path at
  `iso15118_20_states.py:979`) asserts C before the request; a few microseconds early is
  indistinguishable to an EVSE, but move the C write to after `send()` (a post-send hook in `rcv_loop`)
  to match the letter, and make it conditional on `ChargeProgress=Start` with `EVProcessing=Finished`
  (today it also fires for an Ongoing PDReq and for the GoToPause Stop — SC-007).
- Stop: [V2G2-848]/[V2G20-848] want B ≤250 ms **after sending** PowerDeliveryReq(Stop); the candidate
  waits for the Res (SECC may take 4.5 s ISO-2 / 1.5 s ISO-20). Drive B at the AC Stop build sites
  (`iso15118_2_states.py:1311-1325` ChargingStatus stop, `:1077-1089` MeteringReceipt stop; ISO-20
  `evcc_state.py:279-286`). Keep the DC call where it is (DC must stay in C until the Res, [V2G2-913]).
- Error paths: call `enable_charging(False)` at the top of `stop()` before the 2 s sleep and in
  `stop_state_machine`, so DIN's "without any delay" holds (SC-065).
- Renegotiation: leave untouched (C must persist, [V2G2-849] NOTE 1 / [V2G2-914]).

---

## 8. Disagreements resolved

1. **Charger A WeldingDetectionRes FAILED — State-C gap or peer?** `[iso2-evcc F-2]` and `[timers F-1]`
   cite it as evidence that the EVCC never returns to State B; `[pcap §4]` says ambiguous, leaning peer.
   **Resolution: leaning peer; not evidence for SC-001.** The pcap timeline (private
   `pev.py`/`simulator.py` mtimes 11:27:50; pasted box log `pev (273) - Going to state B`) shows the
   private copy with the State-B drive was running for A_1 s2/s3 and A_2, and all three
   passed CableCheck, so per [V2G2-917] Charger A measured C and a real C→B edge occurred at Stop. Charger A
   answered FAILED 59-64 ms after the request although [V2G2-920] obliges it to "wait for a maximum of
   V2G_SECC_Msg_Performance_Time [1.5 s] to measure CP state B"; Charger D, Charger B and Charger C
   accepted byte-identical requests. In the working tree the bug would have surfaced at CableCheck,
   never at WeldingDetection. Our residual contribution (no settle time, `EVReady=true`) is SC-066 (S3).
2. **NotificationMaxDelay S1 or S2?** `[pcap F-2]` reclassified to S1 because DIN types it
   `unsignedInt`; `[rc-tol F-3]`, `[din-evcc F-4]`, `[iso2-evcc F-6]` said S2. **Resolution: S1 on the
   DIN model, S2 on the ISO-2 model.** Verified in the DIN text: Table p135 "NotificationMaxDelay
   simpleType unsignedInt" and XSD p196 `<xs:element name="NotificationMaxDelay" type="xs:unsignedInt"/>`;
   ISO-2 XSD p272 is `unsignedShort`. Charger C's value is byte-swapped (3<<24) but schema-legal, so
   rejecting it is misbehaving against a conformant DIN message (SC-002).
3. **ChargingComplete severity.** `[iso2-evcc F-9]` S3 vs `[din-evcc F-3]`/`[pcap F-8]` S1.
   **Resolution: S1** — it is a wrong mandatory wire value on every session (demo wire confirms on
   both protocols) with a side effect on the loop budget and the operator gate; the posture treats
   any unintended emit deviation as a bug (SC-003).
4. **ISO-20 PowerDeliveryReq(Stop) without EVPowerProfile.** `[iso20-ac-evcc F-6]` S1 vs
   `[iso20-dc-evcc F-14]` S3. **Resolution: S1 (last in the S1 list)** — [V2G20-1546] is an explicit
   "shall"; impact is low because most SECCs (ours included) tolerate it (SC-030).
5. **Charger A "unexplained" ServiceDiscovery aborts.** `[rc-tol F-17]` proposed `AttributeError` paths
   (`select_auth_mode`, energy-mode mismatch); `[iso2-evcc F-4]` and `[pcap §2]` pinned the
   ServiceName enum by byte-identical replay. **Resolution: ServiceName enum** — the HEAD replay
   (`repro/decode_head_enum.py`) raises `'DC_CHARGING' is not a valid ServiceName`, the working tree
   proceeds under every ISO-2 personality (`repro/delta_sd.py`), and the aborts straddle the 12:11
   local edit. The `AttributeError` path is real but only for `iso2_pnc_dc-evcc` on plaintext (SC-049).
   A_3 s1 (3.44 s) is not the `stop()` signature — most likely an operator quit.
6. **DIN SECC PreChargeRes "0 V".** `[din-secc F-3]` says 0 V (from `evse_data.py` defaults);
   `[iso2-secc F-1]` says 1 V. **Resolution: 1 V on the wire** (DIN demo capture) — the simulator seeds
   `present_voltage = 1`; the finding stands (SC-029).
7. **Static-ECDH cipher suite.** `[transport F-4]` plausible. **Resolution: mechanism confirmed** by this
   aggregator on the env's OpenSSL 3.5.0 (`set_ciphers` with both suites yields only
   `ECDHE-ECDSA-AES128-SHA256`); field impact still plausible (SC-026).
8. **SAP wait 20 s vs 60 s.** Four reviewers, all S3 — no disagreement; merged (SC-051).
9. **ISO-2 SECC renegotiation forces CableCheck** `[iso2-secc F-4]`: the reviewer flagged the SECC-side
   text as ambiguous ([V2G2-582] lists CableCheckReq; NOTE 1 p188 keeps the contactor closed).
   **Resolution: keep S1/plausible** — the EVCC-side [V2G2-842] ("shall set ChargeProgress to Start in
   the next following PowerDeliveryReq") is unambiguous, so a conformant EV will send PowerDeliveryReq
   and we will FAILED_SequenceError it (SC-017 c). Needs a real-EV renegotiation capture.

No finding was rejected outright. Two evidence attributions were corrected (items 1 and 6).

---

## 9. Coverage (condensed per slice)

| Slice | Checked and conformant (highlights) | Not covered |
|---|---|---|
| din-evcc | SAP→SessionSetup ordering, SessionID 0 then echoed, EVCCID = MAC, no Signature/Notification in requests, ServiceDiscoveryReq category, ExternalPayment + single SelectedService, empty ContractAuthenticationReq, identical ONGOING re-sends (paced #88), DC_EVChargeParameter mandatory leaves, CableCheck 40 s / PreCharge 7 s, PDReq always with DC_EVPowerDeliveryParameter, loop → PD(FALSE) → WeldingDetection → SessionStop, FAILED-after-CPD immediate terminate, per-message timeouts (except SC-054), EVSENotification never acted on, State B before SLAC / A at cycle end, DIN dropped under TLS | SLAC/SDP timing, V2GTP framing, DIN codec, SECC reaction, console stall beyond SC-019, IEC 61851 timing |
| din-secc | Full 9.7.4.2.4 sequence acceptance incl. SessionStopReq in every state, FAILED_SequenceError/UnknownSession, SessionSetupRes codes incl. empty SessionID, ServiceDiscoveryRes single-sourced ChargeService, FAILED_PaymentSelectionInvalid, ContractAuthentication Ongoing/Finished + stall, CPDRes WrongEnergyTransferType gate + all Table 72 M leaves, CableCheck Ongoing→Finished with Valid/Ready, PreCharge loop, PDRes TRUE/FALSE with contactor check, CurrentDemandRes M fields + live override, 60 s sequence timer, SAP negotiation codes, no Signature, per-session FAILED templates | Live timing (25 ms), transport/SLAC, IEC 61851-23 CableCheck/PreCharge specifics, ISO-2/-20 templates, OK_OldSessionJoined path |
| iso2-evcc | Figs 101/102 sequence and `check_msg` gating, all Table 109 timeouts except CurrentDemand, Ongoing timers with reset, empty AuthorizationReq / identical CPDReq re-sends, SDP 50×250 ms + security byte + enforce_tls, SAP 2.0, SessionID handling, ChargeService always selected, VAS/PnC only under TLS, PaymentDetails/Authorization signatures, AC ReceiptRequired/ReNegotiation/StopCharging flows, DC PreCharge→PD(Start) with SAScheduleTupleID, Stop→WD→SessionStop, StopCharging honoured in DC, SessionStop → TCP close, Charger B full walk | ISO-2 SECC, private ESDP, relay timing on hardware, TLS/PnC flows against a real charger (SC-018/027 plausible), AC has no field capture |
| iso2-secc | SessionSetup codes/IDs, FAILED_UnknownSession/SequenceError with minimal bodies, ServiceDiscovery/ServiceDetail/PaymentServiceSelection codes, CertificateInstallation + PaymentDetails cert-error mapping, Authorization challenge/signature/Ongoing_WaitingForCustomerInteraction, CPD WrongEnergyTransferMode + 24 h schedule + SalesTariff omission, PowerDelivery TariffSelection/ChargingProfile/Renegotiate/ContactorError, ChargingStatus/CurrentDemand ReceiptRequired=FALSE, CableCheck Ongoing-first, WeldingDetection/SessionStop incl. Pause context, 60 s sequence timer, SAP, tree substitution | CertificateInstallation crypto, SalesTariff signing, profile-validator interval arithmetic, EVSE-initiated renegotiation, transport/SLAC, AC EVSEMaxCurrent derivation |
| iso20-dc-evcc | All Table 215/217 timeouts incl. 0.5 s DC loop, Ongoing 60 s Authorization, CableCheck 40 s, SessionID rules, -20 only with TLS 1.3 flag, happy-path Fig 216 sequence, FAILED* → close, Terminate → Stop→WD→SessionStop, PDReq Ongoing re-send, EIM/PnC exclusivity + PnC signature, ScheduleExchangeReq 1024 points / V2X pairs / DepartureTime, CPDReq envelope |max|>|min|, DC_ChargeLoopReq exactly one control-mode element, WeldingDetection Ongoing…Finished, receive tolerance for EVSEID/NotificationMaxDelay/unknown parameters/WARNING codes | Transport/TLS 1.3 details, CertificateInstallationRes, MeteringConfirmation/VehicleCheckIn/Internet VAS, AC beyond shared states, BPT/WPT/ACDP, data-link termination, 0.5 s loop under real PLC latency |
| iso20-dc-secc | SAP -20 major 1, SessionSetupRes 8-byte ID + codes, FAILED minimal + Terminate + ≥5 s close, AuthorizationSetupRes EIM/PnC modes + GenChallenge, AuthorizationRes EIM/PnC/challenge/stall, ServiceDiscovery DC+DC_BPT, ServiceDetail/Selection codes + MobilityNeedsMode rule, ScheduleExchange Ongoing/Finished + wait-state accepting CableCheck/PowerDelivery/SessionStop, PowerDelivery Ongoing/Start/Stop with contactor/HLC-C + ScheduleTupleID check, CableCheck/PreCharge/ChargeLoop/WeldingDetection/SessionStop routing, model exclusivity validators, RationalNumber ranges | BPT/WPT/ACDP, side streams beyond SC-076, SDP/TLS 1.3/OCSP/PnC WARNING matrix, performance times, AC path, full ISO-20 type validator sweep |
| iso20-ac-evcc | Fig 215 AC flow, 0x8003/0x8002 payload types, Table 215/216 timeouts incl. 0.5 s, `delay_seconds=0` default conformant, FAILED*/ID-mismatch/wrong-type → terminate, AC_CPDReq wire values reproduce the real-charger baseline capture + device override deep-merge, control mode from ServiceDetailRes honoured in SE/PD/loop, 1024 points, V2X pairs, PDReq Ongoing loop, Terminate/ServiceRenegotiation notifications (up to SC-008), tolerant decode of EVSEStatus/AckMaxDelay/MeterInfo, existing tests 12 passed | AC-BPT (negative discharge sign unchecked), WPT, ACDP, common-message depth, EVEnergyOffer/price validity, EXPy facet enforcement on decode, sidestream, no E2E run |
| iso20-ac-secc | AC state chain and next-allowed lists (timeouts excepted), SE Ongoing/Finished + GoToPause omitted, PDReq Ongoing → OK, ScheduleTupleID check, Stop → stop_charger/contactor, AC_ChargeLoopRes MeterInfo iff requested + tree-sourced MeterID, Table 205 parameter sets verified by instantiation, ServiceRenegotiationSupported constant, selection codes, FAILED_SequenceError/UnknownSession templates, SessionStopRes timing, baseline AC_CPDRes leaves reproduce the real-charger baseline capture, MinimumSOC≤TargetSOC, ScheduleTupleID=1, AvailableEnergy | AC_BPT/WPT/ACDP, MeteringConfirmation stream, PnC/CertificateInstallation, EXI-level bytes of AC messages, Ongoing performance under stall, ISO-3 pause mechanics |
| timers-cp-sync | All per-message EVCC timeouts (except SC-053/054), SECC 60 s on every response, timer start/stop semantics (Fig 76/98/212), no retransmission on expiry, Ongoing timers with reset, CableCheck/PreCharge stop conditions, `pace_ongoing_poll` not eating the message timer, SLAC counts/cadence, State B before SLAC, CP change points exactly the spec ones, no CP toggle during renegotiation, EVSE 5 % structurally, `wait_for_state_c_or_d` 0.25 s literal, "response first then close" | ISO-20 VehicleCheckIn/ACDP/WPT/MeteringConfirmation timers, SDP DiagStatus, CertificateUpdate, ISO-2 pause CP behaviour, AC PWM switching, IEC primary text, relay latency measurement, TLS handshake budget |
| responsecode-tolerance | SECC FAILED_SequenceError/UnknownSession all protocols, FAILED templates encode 17/17 ISO-2 · 10/11 DIN · 15/18 ISO-20, SessionSetupRes code selection, ISO-2 PaymentServiceSelection/ServiceDetail/CPD/PowerDelivery/MeteringReceipt/Authorization/PaymentDetails/CertificateInstallation codes, DIN 395/397/451, ISO-20 464/1618/ScheduleSelectionInvalid/SessionStop routing, EVCC stop on wrong type/FAILED* without SessionStopReq (ISO-2/-20 conformant), OK_* as OK, ONGOING loops, ISO-2 AC notifications, ISO-20 Terminate, SAP Failed_NoNegotiation emit, DIN header empty SessionID + int ServiceID, PhysicalValue ranges exactly XSD | CP sequencing around FAILED, ISO-2 CertificateUpdate / ISO-20 CertificateInstallation stubs, WPT/ACDP codes, pause/resume, TLS/PKI codes beyond mapping |
| transport-sap | SDP wire format/addressing/retry, Security/Transport byte semantics + field echo check, V2GTP header on send (all payload types), header check order, TCP port choice + last-SDP-response rule, TLS 1.2 posture (unilateral, chain validation, no hostname) and 1.3 posture (mutual, Table 6 order, P-521 certs), SAP content/selection/minor deviation/Failed_NoNegotiation, SAP timers, SessionID handling both roles, teardown, NMAP off by default; `tests/transport tests/settings` 10 passed | Wireless/ACD-P SDP, TLS 1.3 resumption/0-RTT/OCSP/CRL, IPv6 address selection/DAD, SLAC↔SDP ordering root cause, MIM two-leg TLS (#123), runtime confirmation of SC-026/027 and the SDP restart/absence items |
| slac | Message set/encapsulation/MMTYPEs/MVFLength, Table A.2/A.4/A.7 field values, destination addressing, counts/cadence (3×START_ATTEN, 10 sounds at 20 ms), same-RunID re-answer, SET_KEY before MATCH.CNF, EVCC keys from MATCH.CNF, SECC stops after match, NUM_SOUNDS honoured, RunID filtering on EVCC, default NID = HPGP derivation of default NMK, #90 timer-thread fix, cycle sequencing (ADR-0005) | HomePlug GP spec itself (CCo encoding, ATTEN_PROFILE host delivery, AVLN leave), IEC 61851 CP timing, real PLC loss behaviour (no SLAC frames in the decoded traces), IPv6 NS responder in the SLAC handler, sleep/wake-up |
| pcap-forensics | CableCheckReq 2-4 ms after CPDRes, 1 s ongoing polls + 60 s Ongoing honoured, FAILED handling terminates the spec way, SessionID/EVCCID, SAP single entry, SDP 250 ms/50, DC stop order, ISO-2 NotificationMaxDelay bound correct for ISO-2, DIN ServiceID int + EVSEID "00", codec re-encodes Charger C's frame bit-exactly | Pi working copy and logs (hand-patch inferred), IEC debounce/pre-charge tolerance, unit tests, SECC-side stub behaviour, ISO-20 (no captures) |

---

## 10. Suggested groupings for issue-cutting

| # | Candidate issue | Members | Sev | Size | Wayfinder? |
|---|---|---|---|---|---|
| 1 | Port the EVCC CP-state drive (State C before CableCheck / PD(Start), B after Stop) with the AC send-site hooks, settle delay and immediate-B-on-error | SC-001, SC-066, SC-065 (CP part), SC-082, section 7 | S1 | M (seam exists; three protocols × two roles of call sites; needs a bench run) | No — straight issue, but block on a hardware test slot |
| 2 | Tolerant-receive framework + `strict` flag (lenient validators that log-and-continue; SECC answers FAILED to decode-time rejections) | SC-031 (umbrella), SC-042, SC-043, SC-048 | S2 | L (touches the codec boundary, every model, `rcv_loop`) | **Yes** — design the lenient tier / strict switch / per-message `out_of_spec` first |
| 3 | Quick tolerant-receive fixes that do not need the framework | SC-002 (DIN `le=4294967295`), SC-032, SC-033 (commit + DIN), SC-034, SC-035, SC-040, SC-046, SC-047 | S1/S2 | S each; one PR | No |
| 4 | EVSE status / EVErrorCode / pre-charge-current gates: stop rejecting informational values | SC-004, SC-037, SC-038, SC-039 | S1/S2 | S-M | No |
| 5 | DIN EVCC state-machine fixes | SC-019, SC-020, SC-021, SC-022, SC-054, SC-068 (personality) | S1 | M (`PowerDelivery` stop marker, EVSE_Shutdown per state, SessionStopReq path, ReadyToCharge timer; update `test_din_ongoing_timer_defeat.py`) | No |
| 6 | `ChargingComplete` / `continue_charging()` side effects; PreCharge/WeldingDetection completion against the right target | SC-003, SC-067 | S1 | S-M | No |
| 7 | SECC reported present voltage/current tracks the EV target (all three protocols) | SC-029, SC-070 (builder ONGOING status), SC-071 | S1 | S | No |
| 8 | FAILED-response encodability, header Notification, terminate-after-FAILED, first-message FAILED_SequenceError | SC-060, SC-061, SC-062, SC-063, SC-064, SC-044 | S3 | M (add a round-trip test over every template) | Borderline — a short design note on "how the SECC answers a request it cannot process" (ties to group 2) |
| 9 | ISO-20 EVCC notification/flow handling (Pause, GoToPause, ServiceRenegotiation, WARNING on AuthorizationRes) | SC-006, SC-007, SC-008, SC-009, SC-078 (subset) | S1 | M-L | **Yes** — pause/standby/renegotiation need a state-flow design across both roles (with SC-074) |
| 10 | ISO-20 SECC: Standby WARNING non-fatal, SessionStop during PreCharge, CertificateInstallationService advertisement, charge-loop 0.5 s timeout, Renegotiate/Standby profile validator | SC-005, SC-016, SC-015, SC-052, SC-041, SC-076 (subset) | S1 | M | No |
| 11 | ISO-20 wire values: exclusive DC targets, envelope-derived loop/pre-charge magnitudes, Stop with EVPowerProfile, µs TimeStamp + real TimeAnchor, AC L2/L3 gating and Scheduled targets, baseline/skeleton alignment | SC-010, SC-011, SC-012, SC-013, SC-014, SC-030, SC-050, SC-077 | S1/S3 | L (models + builders + baselines; ADR-0006 provenance) | Borderline — the skeleton-vs-tree single-sourcing question deserves an ADR-0006 follow-up |
| 12 | TLS version negotiation, ISO-20 gating on TLS 1.3, curve/cipher lists | SC-024, SC-025, SC-026 | S1 | M (one context for 1.2 + 1.3; per-handshake client-cert policy; SAP filter on negotiated version) | **Yes** — needs a design (Python `ssl` cannot do per-SNI client-cert requirements easily; may need two listeners or post-handshake checks) |
| 13 | V2GTP stream framing (`readexactly` on payload length; ignore bad headers) | SC-027, SC-079 (V2GTP items) | S1 | S-M | No |
| 14 | SLAC state machine rewrite (RunID per run, re-answer MATCH.REQ, TT_match_join, ATTEN timers, retransmits, leave/re-key, NMK randomisation) | SC-028, SC-080, SC-081, SC-047 | S1/S3 | L | **Yes** — both roles, ADR-0005 lifecycle interaction, needs a lossy two-modem bench |
| 15 | ISO-2 SECC/EVCC sequence gaps (DC next-allowed lists, renegotiation without CableCheck, MeteringReceipt stop marker, ReceiptRequired in DC loop, REJECTED auth → FAILED) | SC-017, SC-018, SC-023, SC-045, SC-049, SC-073, SC-075 | S1/S3 | M | No |
| 16 | Transport/SDP hygiene (port ranges, `_refresh_port`, SDP stall/stale response, server restart per SDP request, DIN retry 5, DIN-only SECC no-TLS knob, key-log files, SAP list aliasing) | SC-069, SC-079 | S3 | S-M | No |
| 17 | Timer cleanup (SAP 60 s, 18 s setup, CurrentDemand 0.25 s, DC PreCharge 10 s, Ongoing 55 s, Ongoing_WaitingForCustomerInteraction, CommunicationSetup aggregate) | SC-051, SC-053, SC-055, SC-056, SC-057, SC-058, SC-059 | S3 | S-M | No |
| 18 | SECC CP sensing + gates (CableCheck C/D, WD/SessionStop B, A/E/F monitoring, FAILED_ContactorError, oscillator-off order) | SC-083, SC-084, SC-085 | S4 | L (hardware + state logic) | **Yes** — hardware design (CP read on the SECC board, PWM control) before the state work |

Suggested order: 3 → 1 → 6/7 → 4 → 5 → 10 → 13 → 15, with the wayfinder sessions (2, 9, 12, 14, 18)
started in parallel because their outputs shape the shape of 8 and 11.

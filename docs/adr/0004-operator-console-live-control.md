# Operator console for live mid-session control

AcCCS is a red-team tool whose value is probing how a real device under test reacts to a misbehaving peer. Two probes its operators want cannot be expressed by the existing configuration story: holding a protocol loop open indefinitely (a [[stall]]) and changing the current/voltage a device puts on the wire *while the charge loop is running* (a [[live-override]]). Both are decisions made *during* a session, in reaction to what the peer is doing — they are not "who the device is."

The codebase is deliberately load-once. A [[personality]] is immutable and, per [ADR-0001](0001-personality-yaml-config.md), never CLI-overridable; `runtime.yaml` is read once at startup. Nothing in the project mutates a device's behaviour after launch, and the entry points (`run_evcc.py` / `run_secc.py`) run headless asyncio event loops with stdlib logging to stdout — no interactive surface exists.

This ADR introduces the **[[operator-console]]**: an opt-out, TTY-detected terminal footer through which an operator issues live commands to a running emulator. It is the single home for the project's only two mid-session mutable capabilities, and the deliberate exception to the load-once rule.

## Considered Options

- **Personality-armed stall / personality-injected values.** Rejected. It directly contradicts the [[personality]] glossary ("not mutated mid-session… does not describe a sequence of behaviours over time") and ADR-0001's "personality fields are never CLI-overridable" — yet stall must be CLI- and footer-toggleable. It also forces two near-identical personality files that differ only in a behaviour flag, and a personality-armed stall run headless would hold its gate forever with nothing to release it. Stall arming therefore lives in `runtime.yaml` (per-invocation, CLI-overridable), not the personality.

- **Command queue between footer and session** (footer pushes command objects onto an `asyncio.Queue`; an applier mutates session state). Rejected for now. Everything runs in one event loop, so there is no thread-safety problem for the queue to solve, and its indirection makes the synchronous, immediate gate-release path harder to reason about. The queue's one real advantage — serializability — only matters if the console ever drives a *remote* emulator (footer and emulator in different processes). If that need arises, the queue is the right seam to revisit; until then a shared in-process object is simpler.

- **curses / always-on TUI.** Rejected. Rerouting stdlib logging into a curses pane fights the current stdout logging model and the E2E runner's stdout-marker scraping. `prompt_toolkit` with `patch_stdout()` keeps existing log lines streaming above a pinned footer with minimal disturbance.

- **Clamping live overrides to the personality's declared envelope.** Rejected. The point of the tool is to send a target illegal-but-encodable input. Overrides are unchecked; only the EXI codec's own encodability bounds apply.

## Decision

- A single shared **`LiveControl`** object is created at startup, injected into the controller and reachable from `comm_session`. It holds role-aware override values (`None` = use the personality value), per-gate stall arm flags, and an `asyncio.Event` release signal per gate. The footer mutates it; controllers and state machines read it each cycle. One source of truth spanning both read sites.

- The console is **opt-out with TTY auto-detection**: active when stdout is a TTY, suppressed by `--no-console`, and silently headless when there is no TTY. This keeps the conformance E2E layer (which spawns the runners as `stdout=PIPE` subprocesses — see [ADR-0003](0003-conformance-test-framework.md)) and the replay/CI paths untouched.

- A [[stall]] holds a loop's exit gate closed until a one-shot manual release; there is no auto-release, timeout, or cycle cap. The forceful directions follow protocol control: EVCC over the charge loop, SECC over the authorization gate. Stall mode also relaxes the holder's own protocol timeouts that would otherwise break the hold (notably the EVCC's ongoing-authorization timer).

## Consequences

- A new mutable-state seam exists in an otherwise immutable-config codebase. It is contained to one object and one delivery surface; the load-once guarantees for [[personality]] and `runtime.yaml` are unchanged.
- `runtime.yaml` gains a `stall` section and a console mode knob; both are CLI-overridable. A [[scenario]]'s existing "runtime overrides" can arm stall without touching either personality.
- `prompt_toolkit` becomes a runtime dependency. Logging output is wrapped in `patch_stdout()` only when the console is active.
- Work is sliced as a tracer bullet (console plumbing + EVCC ISO-2 DC charge-loop stall) then by capability and protocol: live override, SECC auth-stall + EVCC timer-defeat, DIN parity, ISO-20 (DC/AC) parity. Each slice is independently end-to-end testable in the virtual two-session run.
- Remote operator control (footer driving an emulator in another process) is explicitly out of scope; if pursued, the command-queue option above is the seam to reopen.

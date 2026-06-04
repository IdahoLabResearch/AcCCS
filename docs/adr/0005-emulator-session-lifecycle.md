# Long-running emulators: idle-and-re-arm session lifecycle

Until now the emulator processes were one-shot from the operator's point of view: the [[EVCC]] ran a single [[session cycle]] and then `run_evcc.py` exited, while the [[SECC]] looped forever inside its handler as an always-on server. The two halves disagreed, the [[operator-console]] only painted once SLAC had already completed (the peer had to be up before the TUI appeared), and there was no way to start a *second* session against the same running process without relaunching.

We decided to make **both** sides long-running with a single, symmetric lifecycle: a process runs many [[session cycle]]s, and after each one — clean completion *or* failure — the side drops back to [[idle]] (EVCC → CP State A, SECC → proximity open) and waits to be **re-armed**. The governing principle is that **the only thing that exits the process is an operator quit (`q`)**; nothing self-exits. Re-arming re-performs SLAC every cycle. To make the console usable across the pre-session and idle phases it now starts *first* (SLAC moved off the asyncio event loop into an executor) and shows a lifecycle **phase indicator**, extending the console of [ADR-0004](0004-operator-console-live-control.md).

## Considered Options

- **EVCC exits / SECC loops (status quo).** Rejected. The asymmetry is the bug the operator hit: you cannot drive repeated sessions from one process, and the two entry points behave differently for no domain reason.

- **Make the SECC exit after one session too (symmetry by exiting).** This was the original framing of the request and was rejected in favour of symmetry-by-*persisting*. A charging station is naturally a long-running service; exiting after one car is the surprising behaviour, not the looping. The operator wanted to *re-run* sessions, not terminate sooner.

- **Auto-restart loop as the default** (each side immediately begins the next cycle). Rejected as the default, kept as opt-in **[[auto-rearm]]** (`--auto-rearm` flag + `r` toggle key, off by default). A continuous loop is the right behaviour for soak/demo runs but the wrong default for interactive red-teaming, where the operator wants to inspect state between cycles and decide when to go again. Auto-rearm puts a short inter-cycle delay on the EVCC so a fast-failing setup does not hammer in a tight loop and logs stay readable; the SECC just re-listens, so it needs no delay.

- **SECC auto-re-arms; only the EVCC needs an advance.** Rejected in favour of requiring an explicit advance on **both** sides by default (the SECC must be re-armed before the EVCC initiates, or SLAC times out). The auto-re-arm convenience is exactly what [[auto-rearm]] provides when wanted; making it the manual default keeps the operator in control of each cycle and the ordering explicit.

- **Failures still exit the process; only clean SessionStop returns to idle.** Rejected. Returning *failures* to idle as well is what makes the manual model usable: a mis-ordered advance (EVCC before SECC) or a transient error becomes a harmless "press advance again" instead of a process death, and auto-rearm becomes self-healing. The cost — a genuinely broken setup (wrong iface, missing certs) idles-and-retries rather than failing loudly — is mitigated by the phase indicator and the repeated failure logs.

- **A separate one-shot / `--exit-after-session` mode for CI.** Rejected as unnecessary. The conformance E2E runner ([ADR-0003](0003-conformance-test-framework.md)) detects success by scraping stdout log markers and then SIGTERM/SIGKILLs both subprocesses in fixture teardown; it never relied on the processes self-exiting. The console also stays headless under `stdout=PIPE`, so the phase indicator never reaches CI output. The lifecycle change is therefore transparent to the test layer.

## Decision

- Both `run_evcc.py` and `run_secc.py` host a long-running outer **lifecycle loop**: run a [[session cycle]], return to [[idle]], re-arm, repeat. SLAC is re-performed at the start of every cycle for both roles. Neither side exits on its own; a clean SessionStop and any failure (SLAC timeout, SDP failure, mid-session error) both land in idle.

- The [[operator-console]] now spans the full process lifetime. `run_with_console` wraps the lifecycle loop (not a single session coroutine), and `doSLAC()` runs in an executor so the event loop stays free and the TUI paints at startup and stays responsive through idle. The footer gains a **phase indicator** (`Waiting for SLAC` → `Session active` → `Idle — press 'a' to start`, plus the auto-rearm state).

- Three console keys are added/extended, all single-press with no confirmation, consistent with the existing bindings:
  - **`q` — quit:** graceful and unconditional from any phase. Tears down any in-flight session, returns the device to its initial electrical state (EVCC CP State A / SECC proximity open), closes sockets/threads, restores the terminal, exits 0. This is the *only* path that terminates the process.
  - **`a` — advance:** context-dependent on the lifecycle phase shown by the indicator. During an active session with a gate armed it releases the [[stall]] gate once (unchanged from ADR-0004); while [[idle]] it re-arms the side to begin the next [[session cycle]].
  - **`r` — auto-rearm toggle:** flips [[auto-rearm]] on/off live.

- [[auto-rearm]] is a `runtime.yaml` knob (`rearm.auto`, CLI flag `--auto-rearm`, off by default), CLI-overridable like the stall flags and never a [[personality]] field. When on, a side skips the idle wait and re-arms immediately (EVCC with a short inter-cycle delay).

## Consequences

- The run-script contract changes: a bare `run_evcc.py` no longer terminates after one session. Anyone scripting around "the EVCC process exits when done" must now send `q` (or a signal). The conformance E2E layer is unaffected (marker-scrape + teardown-kill).
- `runtime.yaml` gains a `rearm` section; `_CLI_FIELD_MAP` gains `rearm.auto`.
- SLAC must be safely re-runnable per cycle — its sniffer/timeout threads and `stop` flag need clean re-initialization each time, which the prior one-shot code did not exercise. This is the main implementation risk and must hold across ISO 15118-2, ISO 15118-20 (DC/AC), and DIN SPEC, including the -20 renegotiation paths.
- The `a` key now has a phase-dependent meaning; correctness depends on the lifecycle phase being tracked accurately (the same state that drives the phase indicator). `LiveControl` gains a phase field and an advance signal alongside its existing per-gate release events.
- A new `--list-configs` flag on both run scripts (annotated with each personality's source and declared role) is delivered alongside this work; it is independent of the lifecycle change but shares the CLI surface.

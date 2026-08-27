# Role-scoped relay ownership on the shared I2C GPIO expander

Both emulator roles can be live on one AcCCS box at once — [[idle]] re-arm *requires* the [[SECC]] to be listening before the [[EVCC]] initiates ([ADR-0005](0005-emulator-session-lifecycle.md)), so two processes running side by side is the documented normal operating mode, not an exotic case. Both drive the same I2C GPIO expander at `0x20`, each owning a disjoint [[relay bank]]: the EVSE side a control-pilot and a proximity-pilot relay, the EV side two control-pilot relays and proximity pilot.

Every write used to be an absolute whole-register write carrying only the writing role's bits, issued from three separate copies of the wiring (`PEV.__init__`, `EVSE.__init__`, `scripts/evcc_relays.py`). Either role starting up, changing state, or returning to [[idle]] therefore zeroed the other role's relays, and the victim never found out because nothing ever read the expander back. Startup made it worse: the incoming process opened all relays, dwelled five seconds, then re-closed only its own — the other side clobbered twice with a multi-second window in between (issue #108).

## Considered Options

- **A cross-process lock (file lock / semaphore) around each transition.** Rejected. It would have to be held across a bus round-trip on every electrical transition, and a stale lock left by a killed emulator — the ordinary way these processes end, since only an operator quit exits cleanly — would wedge the *other* role's relays. That failure is worse and less diagnosable than the one it prevents.

- **One relay daemon owning the bus, both emulators talking to it.** Rejected as disproportionate. It buys true serialization at the cost of a third process to launch, supervise, and fail — for a device whose entire state is five bits written a handful of times per session cycle.

- **Keep the whole-register writes but have each role re-assert its own bits on a timer.** Rejected. It converts a deterministic clobber into a race whose visible symptom is relays chattering, and it never tells the operator anything went wrong.

- **Read-modify-write per role, unlocked, with a write-verify (chosen).** Each role reads the expander, changes only the bits inside its own mask, and writes back. The remaining lost-update race is accepted rather than locked against, and mitigated by reading the latch back.

- **Read the pin register (`0x09`) for the read-modify-write.** Rejected in favour of the output latch at `0x0A`. A read of the pin register returns pin *levels*, which for a pin still configured as an input is whatever the wire sits at; merging from there would latch a stray high into bits we do not own, and the moment the other role claimed that pin as an output it would drive a relay nobody commanded. The latch only ever holds what was written, and powers up clear.

## Decision

- **One role owns a fixed bit mask and touches nothing else.** Every write to the pin register is a read-modify-write sourced from the output latch and confined to the writing role's mask, so all foreign bits are preserved.

- **The direction register is masked the same way.** A role claims only its own pins as outputs; the other role's direction bits are left as found, and the unused spare pins keep their power-on *input* default instead of being conscripted as outputs by whichever process starts first — so wiring a spare as an input later cannot meet a process already driving it.

- **The cross-process lost-update race is knowingly accepted, with no lock, by deliberate choice.** The mitigation is write-verify: after each write the role reads the latch back and, if its own bits did not stick, logs a warning naming the collision and re-applies **once**. This catches a foreign write that lands before the read-back — the wide half of the window — and misses one that lands after, which survives until the next transition re-asserts our bits. Exactly one retry, never a loop: a disagreement that outlives the re-apply means something else is fighting for the pins, and spinning on the bus would make that harder to see, not easier.

- **All relay behaviour lives in one shared module** (`app/shared/relays.py`). The bus handle, the address, the register numbers, and the bit masks appear there and nowhere else; `PEV`, `EVSE`, and the bench script get the semantic operations (`set_state`, `close_proximity`, `open_proximity`, `toggle_proximity`) from it. The per-role duplication is what let the bug exist, so removing it is part of the fix rather than a tidy-up alongside it.

- **Under `--virtual` no bus is opened and no bus operation is attempted**, while the relay log lines are still emitted, so the virtual two-session demo's log stream matches the hardware one.

## Consequences

- Startup no longer forces every pin to output. A board whose spare pins were implicitly relied on being outputs would change behaviour; nothing in the project drives them.
- The read path now touches `0x0A`, a register the emulator had never read. The rest of the register map (`0x00` direction, `0x09` pins) is the one the emulator has always driven.
- Two bus round-trips replace one per transition (read-modify-write, then the verify read). At a handful of transitions per [[session cycle]] this is immaterial.
- A relay collision is now a visible `WARNING` naming the two masks — the first time the shared-expander contention is observable at all.
- The fake-bus unit tests (`tests/relays/`) cover foreign-bit preservation across every transition for both roles, masked direction writes, the verify-and-re-apply, and virtual mode issuing zero bus operations. Confirming that two live roles keep their relays simultaneously still needs the hardware.
- Recovering a board an orphaned emulator left latched needs the one write the ownership rule forbids: a whole-register clear that ignores the masks. `reset_all_relays`, invoked by the `scripts/reset_relays.py` bench tool (issue #110), is that single sanctioned exception — deliberately wide because the per-role writes are deliberately narrow, and documented to warn that running it against a live emulator clears that session's relays too. It leaves the direction register alone; a reset is not a reconfigure.

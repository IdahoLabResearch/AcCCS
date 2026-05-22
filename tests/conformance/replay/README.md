# Replay layer

Offline runner for the captured-session corpus under
[`../captures/`](../captures/). Feeds captured wire bytes through the current
EXI codec, asserts the decoded Pydantic objects validate, and asserts the
re-encoded bytes are equivalent to the original.

**Empty in Slice 1.** The runner and corpus are delivered by EXPy Slice 4
(#15) — see ADR-0003's per-slice gating table and the F4 entry in the
bootstrap ordering.

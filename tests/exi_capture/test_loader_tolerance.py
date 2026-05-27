"""The replay corpus loader must tolerate malformed JSONL lines.

A single torn / corrupt record (the failure mode the pre-flock writer
could produce, or a re-capture mishap) must not crash the replay test
collection — it skips the bad line with a logged warning and yields the
surrounding valid records.
"""

from __future__ import annotations

import json

import pytest

from tests.conformance.replay._corpus import _load_capture


def _good_record(model: str = "V2G_Message", hex_payload: str = "deadbeef") -> str:
    return json.dumps(
        {
            "ts": 1.0,
            "dir": "encode",
            "ns": "urn:iso:15118:2:2013:MsgDef",
            "model": model,
            "root": "document",
            "hex": hex_payload,
        }
    )


def test_load_capture_skips_malformed_line(tmp_path, caplog):
    p = tmp_path / "torn.jsonl"
    p.write_text(
        "\n".join(
            [
                _good_record("Msg1", "01"),
                "{not valid json",          # malformed
                _good_record("Msg2", "02"),
                "",                          # blank, also tolerated
                _good_record("Msg3", "03"),
            ]
        )
        + "\n"
    )

    with caplog.at_level("WARNING", logger="tests.conformance.replay._corpus"):
        with pytest.warns(RuntimeWarning, match="malformed JSONL line"):
            recs = list(_load_capture(p, meta={"source": "veth"}))

    assert [r.payload.hex() for r in recs] == ["01", "02", "03"]
    # The warning must name the file and the line number so a re-capture
    # mishap is easy to track down.
    assert any(
        "torn.jsonl" in rec.message and ":2" in rec.message
        for rec in caplog.records
    ), f"expected file:line warning, got {caplog.records!r}"


def test_load_capture_skips_blank_trailing_line(tmp_path):
    p = tmp_path / "blanks.jsonl"
    p.write_text(_good_record() + "\n\n")  # trailing blank
    recs = list(_load_capture(p, meta={}))
    assert len(recs) == 1

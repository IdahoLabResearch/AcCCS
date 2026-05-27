"""Slice 0 smoke test: EXPy installs and a DIN document round-trips.

Per ADR-0002, this is the only thing this slice proves — no AcCCS code uses
EXPy yet. If this test fails on a target (dev box or Raspberry Pi), the EXPy
install is broken on that target and downstream slices cannot start.
"""

from expy import EXIProcessor, Namespace
from expy.v2gjson.din import MessageHeaderType, SessionSetupReqType, V2G_Message


def test_din_session_setup_req_round_trips():
    doc = V2G_Message(
        Header=MessageHeaderType(SessionID=bytearray(b"\x00\x00\x00\x00\x00\x00\x00\x00")),
        Body={"SessionSetupReq": SessionSetupReqType(EVCCID=bytearray(b"\xde\xad\xbe\xef\x00\x01"))},
    )
    proc = EXIProcessor(Namespace.DIN)
    encoded = proc.encode(doc)
    assert isinstance(encoded, bytes) and len(encoded) > 0
    decoded = proc.decode(encoded)
    assert decoded == doc

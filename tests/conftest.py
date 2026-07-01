"""Suite-wide fixtures.

The EXI codec is a process-wide singleton (``app.shared.exi_codec.EXI``).
Constructing a communication session handler calls ``EXI().set_exi_codec`` as a
side effect, so any unit test that builds a handler with a throwaway stub codec
would otherwise leak that stub into the global and — depending on pytest
collection order under ``pytest-randomly`` — break later fixture-less wire
round-trip tests that encode/decode through the real codec (issue #77).

Snapshotting the registered codec before every test and restoring it afterward
makes the whole class of leak impossible: no test can hand its codec off to
another. This replaces the per-module defensive re-registration fixture that
#72 added to ``tests/personality/test_message_field_tree.py``.
"""

from __future__ import annotations

import pytest

from app.shared.exi_codec import EXI


@pytest.fixture(autouse=True)
def _preserve_global_exi_codec():
    """Restore the process-wide EXI codec a test may have replaced.

    Reads/writes ``_codec`` directly rather than going through
    ``get_exi_codec``/``set_exi_codec`` so a ``None`` (never-registered) state is
    preserved faithfully — ``get_exi_codec`` would lazily instantiate a real
    codec, and ``set_exi_codec`` cannot represent "nothing registered".
    """
    saved = EXI()._codec
    try:
        yield
    finally:
        EXI()._codec = saved

"""Shared fixtures for the AcCCS conformance suite.

See `tests/conformance/README.md` and `docs/adr/0003-conformance-test-framework.md`.

Three groups of fixtures live here:

1. `exi_codec` — session-scoped EXPy EXI codec, registered on the
   `EXI` singleton. The codec layer and (transitively) state-machine layer
   depend on this.
2. `veth_pair` — verifies that the `acccs_secc` / `acccs_evcc` veth pair
   exists. The E2E layer depends on this; tests that need it skip when it is
   absent so a developer without `CAP_NET_ADMIN` still gets the codec and
   state-machine layers.
3. `launch_emulator` — factory fixture that spawns `run_evcc.py` / `run_secc.py`
   as subprocesses with the requested test personality, then tears them down.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Iterator, Optional

import pytest


# Production code calls `logger.trace(...)` (a custom log level installed by
# `app.shared.logging._init_logger`). The conformance suite does not run that
# initialiser — it would create timestamped log files and load fileConfig from
# an installer-flavoured path — so we install just the trace method here.
if not hasattr(logging.getLoggerClass(), "trace"):
    _TRACE = logging.DEBUG - 5
    logging.addLevelName(_TRACE, "TRACE")
    logging.getLoggerClass().trace = lambda self, *a, **kw: None  # type: ignore[attr-defined]

REPO_ROOT = Path(__file__).resolve().parents[2]
SECC_IFACE = "acccs_secc"
EVCC_IFACE = "acccs_evcc"


# ---------------------------------------------------------------------------
# Codec
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def exi_codec():
    """Initialise the EXPy EXI codec once per test session.

    The codec layer cannot run without a registered codec on the `EXI`
    singleton.
    """
    from app.shared.exi_codec import EXI
    from app.shared.expy_exi_codec import EXPyEXICodec
    from app.shared.settings import load_shared_settings

    # The EXI wrapper consults ``shared_settings`` for log toggles; without
    # this call the wrapper raises KeyError on first use.
    load_shared_settings()
    codec = EXPyEXICodec()
    EXI().set_exi_codec(codec)
    yield codec


# ---------------------------------------------------------------------------
# Veth
# ---------------------------------------------------------------------------


def _iface_exists(name: str) -> bool:
    return Path(f"/sys/class/net/{name}").exists()


@pytest.fixture(scope="session")
def veth_pair() -> Iterator[tuple[str, str]]:
    """Ensure the SECC/EVCC veth pair is up; skip if it is not.

    Slice 1 deliberately does NOT auto-run `setup_veth.sh` from the fixture —
    that script needs `sudo` and there is no portable way to acquire it
    non-interactively. CI environments (and developers) are expected to
    provision the pair before invoking pytest. See README.md.
    """
    if not (_iface_exists(SECC_IFACE) and _iface_exists(EVCC_IFACE)):
        pytest.skip(
            f"veth pair {SECC_IFACE}/{EVCC_IFACE} not present — "
            f"run setup_veth.sh (requires CAP_NET_ADMIN)"
        )
    yield SECC_IFACE, EVCC_IFACE


# ---------------------------------------------------------------------------
# Emulator subprocesses
# ---------------------------------------------------------------------------


@pytest.fixture
def launch_emulator(veth_pair):
    """Factory that spawns `run_evcc.py` or `run_secc.py` with a personality.

    Personality YAML lands in ADR-0001 Slice 1, so this fixture passes
    `--config <path>` to the subprocess rather than a translated env. The
    spawned process is launched in `--virtual` mode (no SMBus / I2C
    relays); CI / dev environments do not have the EV harness PCB attached.

    Returns a callable `(role, personality_path, extra_args=None) -> Popen`.
    All spawned processes are torn down at fixture teardown.
    """
    processes: list[subprocess.Popen] = []

    def _spawn(
        role: str,
        personality_path: Path,
        extra_args: Optional[Iterable[str]] = None,
    ) -> subprocess.Popen:
        if role not in ("evcc", "secc"):
            raise ValueError(f"role must be 'evcc' or 'secc', got {role!r}")

        cmd = [
            sys.executable,
            f"run_{role}.py",
            "--config",
            str(personality_path),
            "--virtual",
            *(list(extra_args) if extra_args else []),
        ]
        proc = subprocess.Popen(
            cmd,
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        processes.append(proc)
        return proc

    yield _spawn

    for proc in processes:
        if proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass


# Pytest-asyncio: each test gets its own event loop unless it opts into a wider
# scope. The default is fine for everything we author in Slice 1.
@pytest.fixture
def event_loop_policy():
    return asyncio.DefaultEventLoopPolicy()

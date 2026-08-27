"""Drive the virtual SECC+EVCC demo for each in-scope personality combo and
write the resulting EXI codec stream to ``tests/conformance/captures/veth/``.

Used to (re)build the veth half of the EXPy Slice 4 replay corpus (#15).
Each entry is two files:

- ``<name>.jsonl`` — one record per ``EXI`` codec call, written by the
  capture tap in ``app/shared/exi_capture.py`` while the demo runs.
- ``<name>.yaml`` — provenance metadata (source, protocol, energy_mode,
  captured_at, notes) per ``tests/conformance/captures/README.md``.

The hardware half of the corpus is **deferred** to a follow-up issue per the
Slice 4 implementation decisions (no hardware access from this session). The
matrix is documented in ``tests/conformance/captures/README.md`` so the gap
is visible to ``/audit-issue`` and Slice 5.

Run as the unprivileged user — the script invokes the emulator
subprocesses through ``sudo`` (the dev-box NOPASSWD entry allows the
specific ``run_secc.py`` / ``run_evcc.py`` command lines). The capture
path is passed via the ``--capture <path>`` runner flag (rather than the
``ACCCS_EXI_CAPTURE`` env var) because the dev box's NOPASSWD sudoers
entry strips custom env vars, but CLI args survive sudo intact:

    /home/jake-inl/anaconda3/envs/AcCCS/bin/python \\
        scripts/capture_replay_corpus.py

The veth pair (``acccs_secc`` ⇄ ``acccs_evcc``) must be present
beforehand — run ``setup_veth.sh`` once per boot.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CAPTURE_DIR = REPO_ROOT / "tests" / "conformance" / "captures" / "veth"
PYTHON = "/home/jake-inl/anaconda3/envs/AcCCS/bin/python"


@dataclasses.dataclass(frozen=True)
class Combo:
    name: str               # capture file base name
    secc_config: str        # personality name passed to --config
    evcc_config: str
    protocol: str           # din70121 | iso15118-2 | iso15118-20
    energy_mode: str        # ac | dc | bpt | wpt | acdp
    notes: str
    timeout_s: int = 90


COMBOS: list[Combo] = [
    Combo(
        name="din-dc",
        secc_config="din_dc_extended-secc",
        evcc_config="din_dc_extended-evcc",
        protocol="din70121",
        energy_mode="dc",
        notes="DIN 70121 DC happy-path session (per-role din_dc_extended-{secc,evcc}, "
        "each tree-backed via its DIN baseline).",
    ),
    Combo(
        name="iso2-eim-dc",
        secc_config="iso2_eim_dc-secc",
        evcc_config="iso2_eim_dc-evcc",
        protocol="iso15118-2",
        energy_mode="dc",
        notes="ISO 15118-2 DC, EIM auth (per-role iso2_eim_dc-{secc,evcc}; the "
        "SECC side is tree-backed via iso2-secc-baseline, #96).",
    ),
    Combo(
        name="iso2-pnc-dc",
        secc_config="iso2_pnc_dc-secc",
        evcc_config="iso2_pnc_dc-evcc",
        protocol="iso15118-2",
        energy_mode="dc",
        notes="ISO 15118-2 DC, PnC auth (per-role iso2_pnc_dc-{secc,evcc}; the "
        "SECC side is tree-backed via iso2-secc-baseline, #96).",
    ),
    Combo(
        name="iso20-ac",
        secc_config="iso20_ac-secc",
        evcc_config="iso20_ac-evcc",
        protocol="iso15118-20",
        energy_mode="ac",
        notes="ISO 15118-20 AC happy-path (per-role iso20_ac-{secc,evcc}, each "
        "tree-backed via its ISO-20 AC baseline).",
    ),
    Combo(
        name="iso20-dc",
        secc_config="iso20_dc-secc",
        evcc_config="iso20_dc-evcc",
        protocol="iso15118-20",
        energy_mode="dc",
        notes="ISO 15118-20 DC happy-path (per-role iso20_dc-{secc,evcc}, each "
        "tree-backed via its ISO-20 DC baseline).",
    ),
]


# Combinations we cannot capture today (no working virtual session or
# personality in-tree). Recorded explicitly so the gap is visible in the
# corpus README.
DEFERRED: list[dict] = [
    {"protocol": "iso15118-2", "energy_mode": "ac", "reason": "No ISO-2 AC personality in-tree (only DC variants ship today)."},
    {"protocol": "iso15118-20", "energy_mode": "ac-bpt", "reason": "ISO-20 AC-BPT end-to-end path verified (#106); no BPT veth capture shipped yet."},
    {"protocol": "iso15118-20", "energy_mode": "dc-bpt", "reason": "ISO-20 DC-BPT end-to-end path verified (#106); no BPT veth capture shipped yet."},
    {"protocol": "iso15118-20", "energy_mode": "wpt", "reason": "ISO-20 WPT — only a single codec fixture (WPTPairingReq); no end-to-end session support."},
    {"protocol": "iso15118-20", "energy_mode": "acdp", "reason": "ISO-20 ACDP — only a single codec fixture (ACDPConnectReq); no end-to-end session support."},
]


def _check_veth_present() -> bool:
    return (
        subprocess.run(["ip", "link", "show", "acccs_secc"], capture_output=True).returncode == 0
        and subprocess.run(["ip", "link", "show", "acccs_evcc"], capture_output=True).returncode == 0
    )


def _spawn(role: str, config: str, capture_path: Path) -> subprocess.Popen:
    runner = "run_secc.py" if role == "secc" else "run_evcc.py"
    log_path = capture_path.with_suffix(f".{role}.log")
    log_fh = open(log_path, "w")
    proc = subprocess.Popen(
        [
            "sudo", "-n", PYTHON, str(REPO_ROOT / runner),
            "--config", config,
            "--virtual",
            "--capture", str(capture_path),
        ],
        cwd=REPO_ROOT,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
    )
    return proc


def _kill_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        # The emulator runs under sudo as root; SIGTERM from this script
        # (running as user) is not deliverable. Reap via the cleanup
        # script which is also NOPASSWD-allowed.
        try:
            subprocess.run(
                ["sudo", "-n", "/usr/bin/bash", str(REPO_ROOT / "scripts" / "cleanup_acccs.sh")],
                check=False,
                timeout=10,
            )
        except subprocess.TimeoutExpired:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def _write_metadata(combo: Combo, capture_path: Path, line_count: int) -> None:
    yaml_path = capture_path.with_suffix(".yaml")
    captured_at = datetime.date.today().isoformat()
    body = (
        f"source: veth\n"
        f"protocol: {combo.protocol}\n"
        f"energy_mode: {combo.energy_mode}\n"
        f"captured_at: {captured_at}\n"
        f"secc_personality: {combo.secc_config}\n"
        f"evcc_personality: {combo.evcc_config}\n"
        f"messages: {line_count}\n"
        f"notes: |\n  {combo.notes}\n"
    )
    yaml_path.write_text(body)


def _run_combo(combo: Combo, *, secc_first_pause: float = 2.0) -> bool:
    capture_path = CAPTURE_DIR / f"{combo.name}.jsonl"
    capture_path.parent.mkdir(parents=True, exist_ok=True)
    if capture_path.exists():
        capture_path.unlink()

    print(f"[capture] {combo.name}: starting SECC", flush=True)
    secc = _spawn("secc", combo.secc_config, capture_path)
    time.sleep(secc_first_pause)
    if secc.poll() is not None:
        print(f"[capture] {combo.name}: SECC exited early (rc={secc.returncode}); see logs", flush=True)
        return False

    print(f"[capture] {combo.name}: starting EVCC", flush=True)
    evcc = _spawn("evcc", combo.evcc_config, capture_path)

    deadline = time.time() + combo.timeout_s
    while time.time() < deadline:
        if evcc.poll() is not None:
            # EVCC naturally terminates after SessionStop.
            break
        time.sleep(1.0)

    _kill_tree(evcc)
    _kill_tree(secc)

    if not capture_path.exists():
        print(f"[capture] {combo.name}: NO capture file written", flush=True)
        return False
    # The JSONL file is chmod-666 by ``app/shared/exi_capture.py`` on
    # first write so this user can re-read/edit it even though it was
    # created by the root-owned emulator process. The per-role .log files
    # remain root-owned; that's fine, they're scratch artefacts.
    line_count = sum(1 for _ in capture_path.open())
    print(f"[capture] {combo.name}: captured {line_count} EXI calls", flush=True)
    _write_metadata(combo, capture_path, line_count)
    return line_count > 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--only",
        nargs="*",
        choices=[c.name for c in COMBOS],
        help="Only capture the named combos (default: all).",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove the existing captures/veth/ directory before capturing.",
    )
    args = parser.parse_args()

    if not _check_veth_present():
        print("acccs_secc/acccs_evcc veth pair not present; run setup_veth.sh first", file=sys.stderr)
        return 2

    if args.clean and CAPTURE_DIR.exists():
        shutil.rmtree(CAPTURE_DIR)

    combos = [c for c in COMBOS if not args.only or c.name in args.only]
    failures: list[str] = []
    for combo in combos:
        if not _run_combo(combo):
            failures.append(combo.name)

    if failures:
        print(f"[capture] FAILED: {failures}", file=sys.stderr)
        return 1
    print("[capture] all combos captured", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

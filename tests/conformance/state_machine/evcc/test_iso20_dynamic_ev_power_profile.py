"""The Dynamic-control-mode ready branch builds a valid `EVPowerProfile` (#104).

`SimEVController.process_dynamic_se_params` gates its "ready" branch on
`random.getrandbits(1)`. That branch used to wrap its entry in an
`EVPowerScheduleEntryList`, but `EVPowerProfile.entry_list` is typed
`EVPowerProfileEntryList` (elements of `PowerScheduleEntry`) — so constructing
the profile raised a Pydantic `ValidationError`, aborting a real
Dynamic-control-mode ISO-20 session at PowerDelivery ~50% of the time.

These tests pin `random.getrandbits` deterministically to exercise both
branches: the ready branch must now build a valid `EVPowerProfile` (regression),
and the not-ready branch must still return `(None, ChargeProgress.START)`.
"""

from __future__ import annotations

import random

import pytest

from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.shared.messages.iso15118_20.common_messages import (
    ChargeProgress,
    DynamicScheduleExchangeResParams,
    EVPowerProfile,
    EVPowerProfileEntryList,
    PowerScheduleEntry,
)
from app.shared.personality.model import EVCCPersonality


def _controller() -> SimEVController:
    return SimEVController(EVCCConfig.from_personality(EVCCPersonality()))


@pytest.mark.asyncio
async def test_dynamic_ready_branch_builds_valid_ev_power_profile(monkeypatch):
    # Pin the readiness gate to the ready branch (getrandbits -> 1).
    monkeypatch.setattr(random, "getrandbits", lambda n: 1)
    controller = _controller()

    profile, charge_progress = await controller.process_dynamic_se_params(
        DynamicScheduleExchangeResParams(), pause=False
    )

    assert isinstance(profile, EVPowerProfile)
    # The bug: entry_list was built from an EVPowerScheduleEntryList; it must be
    # the EVPowerProfileEntryList that EVPowerProfile.entry_list is typed to.
    assert isinstance(profile.entry_list, EVPowerProfileEntryList)
    assert profile.entry_list.entries
    assert all(
        isinstance(entry, PowerScheduleEntry) for entry in profile.entry_list.entries
    )
    assert profile.dynamic_profile is not None
    assert profile.scheduled_profile is None
    assert charge_progress == ChargeProgress.START


@pytest.mark.asyncio
async def test_dynamic_ready_branch_pauses_with_charge_progress_stop(monkeypatch):
    monkeypatch.setattr(random, "getrandbits", lambda n: 1)
    controller = _controller()

    profile, charge_progress = await controller.process_dynamic_se_params(
        DynamicScheduleExchangeResParams(), pause=True
    )

    assert isinstance(profile, EVPowerProfile)
    assert charge_progress == ChargeProgress.STOP


@pytest.mark.asyncio
async def test_dynamic_not_ready_branch_unchanged(monkeypatch):
    # getrandbits -> 0 keeps the not-ready branch; behaviour must be untouched.
    monkeypatch.setattr(random, "getrandbits", lambda n: 0)
    controller = _controller()

    profile, charge_progress = await controller.process_dynamic_se_params(
        DynamicScheduleExchangeResParams(), pause=False
    )

    assert profile is None
    assert charge_progress == ChargeProgress.START

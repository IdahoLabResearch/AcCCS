"""The simulated EV ends welding detection on the charger's reported voltage (#145).

The EVCC used to end welding detection after a fixed three polls without
reading the charger's reported voltage, so it unlocked whatever was still on
the cable. It now finishes once the charger reports a present voltage below
the welding threshold. Only under virtual mode does a poll cap also end it, so
a self-paired demo whose charger never discharges cannot hang; elsewhere the
protocol's welding timer is the only other exit.
"""

from __future__ import annotations

import pytest

from app.evcc.controller.simulator import (
    WELDING_DETECTION_VIRTUAL_POLL_CAP,
    WELDING_DETECTION_VOLTAGE_THRESHOLD_V,
    SimEVController,
)
from app.evcc.evcc_config import EVCCConfig
from app.shared.messages.iso15118_20.common_types import RationalNumber
from app.shared.personality import EVCCPersonality
from tests.evcc.controller.test_is_precharged import PROTOCOL_VOLTAGE


def _controller(virtual: bool = False) -> SimEVController:
    personality = EVCCPersonality.model_validate(
        {"residual": {"charge_ramp": {"target_voltage_v": 800.0}}}
    )
    return SimEVController(EVCCConfig.from_personality(personality), virtual=virtual)


@pytest.mark.parametrize("protocol", PROTOCOL_VOLTAGE)
async def test_welding_detection_finishes_below_the_threshold(protocol):
    voltage = PROTOCOL_VOLTAGE[protocol]
    ctrl = _controller()
    assert not await ctrl.welding_detection_has_finished(voltage(400))
    assert not await ctrl.welding_detection_has_finished(
        voltage(WELDING_DETECTION_VOLTAGE_THRESHOLD_V)
    )
    assert await ctrl.welding_detection_has_finished(
        voltage(WELDING_DETECTION_VOLTAGE_THRESHOLD_V - 1)
    )


async def test_polls_alone_never_finish_welding_detection_outside_virtual_mode():
    ctrl = _controller(virtual=False)
    for _ in range(WELDING_DETECTION_VIRTUAL_POLL_CAP * 3):
        assert not await ctrl.welding_detection_has_finished(
            RationalNumber.get_rational_repr(400)
        )


async def test_virtual_mode_caps_welding_detection_polls():
    ctrl = _controller(virtual=True)
    high = RationalNumber.get_rational_repr(400)
    for _ in range(WELDING_DETECTION_VIRTUAL_POLL_CAP - 1):
        assert not await ctrl.welding_detection_has_finished(high)
    assert await ctrl.welding_detection_has_finished(high)

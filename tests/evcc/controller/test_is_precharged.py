"""The simulated EV completes precharge on the charger's reported voltage (#139).

The EVCC used to declare precharge done after a fixed count of PreChargeRes
polls (counted twice per poll on ISO-20), never reset between sessions, so it
moved on whatever voltage the charger reported. It now waits until the
charger's present voltage is within tolerance of the EV's own precharge target —
the residual ``charge_ramp.target_voltage_v`` seed (or the live override) —
which is also the target the ISO-20 DCPreChargeReq carries.
"""

from __future__ import annotations

import pytest

from app.evcc.controller.simulator import (
    PRECHARGE_VOLTAGE_TOLERANCE_V,
    SimEVController,
)
from app.evcc.evcc_config import EVCCConfig
from app.shared.live_control import LiveControl
from app.shared.messages.datatypes import PVEVSEPresentVoltage, PVEVSEPresentVoltageDin
from app.shared.messages.enums import UnitSymbol
from app.shared.messages.iso15118_20.common_types import RationalNumber
from app.shared.personality import EVCCPersonality


def _controller(live_control: LiveControl | None = None) -> SimEVController:
    personality = EVCCPersonality.model_validate(
        {"residual": {"charge_ramp": {"target_voltage_v": 400.0}}}
    )
    return SimEVController(EVCCConfig.from_personality(personality), live_control)


def _v(volts: float) -> RationalNumber:
    return RationalNumber.get_rational_repr(volts)


# The charger's present voltage as each DC protocol carries it on the wire.
PROTOCOL_VOLTAGE = {
    "DIN": lambda v: PVEVSEPresentVoltageDin(
        multiplier=0, value=int(v), unit=UnitSymbol.VOLTAGE
    ),
    "ISO-2": lambda v: PVEVSEPresentVoltage(
        multiplier=0, value=int(v), unit=UnitSymbol.VOLTAGE
    ),
    "ISO-20": RationalNumber.get_rational_repr,
}


async def test_not_precharged_until_charger_reaches_target():
    ctrl = _controller()
    for volts in (0, 200, 300, 400 - PRECHARGE_VOLTAGE_TOLERANCE_V - 1):
        assert not await ctrl.is_precharged(_v(volts))


async def test_precharged_within_tolerance_of_target():
    ctrl = _controller()
    assert await ctrl.is_precharged(_v(400 - PRECHARGE_VOLTAGE_TOLERANCE_V))
    assert await ctrl.is_precharged(_v(400))


async def test_repeated_polls_never_complete_precharge_on_their_own():
    ctrl = _controller()
    for _ in range(20):
        assert not await ctrl.is_precharged(_v(100))


async def test_live_voltage_override_moves_the_precharge_target():
    lc = LiveControl()
    lc.set_override_voltage(300)
    ctrl = _controller(lc)
    assert await ctrl.is_precharged(_v(300))
    assert not await ctrl.is_precharged(_v(400))


async def test_iso20_precharge_target_is_the_charge_ramp_seed():
    ctrl = _controller()
    assert (await ctrl.get_target_voltage()).get_decimal_value() == 400
    assert (await ctrl.get_present_voltage()).get_decimal_value() == 400


@pytest.mark.parametrize("protocol", PROTOCOL_VOLTAGE)
async def test_precharge_waits_for_an_800_v_target_on_every_dc_protocol(protocol):
    # The 4 V / 34 V readings are the field case (#145): PowerDeliveryReq Start
    # went out at a few volts against a several-hundred-volt target.
    voltage = PROTOCOL_VOLTAGE[protocol]
    personality = EVCCPersonality.model_validate(
        {"residual": {"charge_ramp": {"target_voltage_v": 800.0}}}
    )
    ctrl = SimEVController(EVCCConfig.from_personality(personality))
    assert not await ctrl.is_precharged(voltage(4))
    assert not await ctrl.is_precharged(voltage(34))
    assert await ctrl.is_precharged(voltage(800 - PRECHARGE_VOLTAGE_TOLERANCE_V))
    assert await ctrl.is_precharged(voltage(800))

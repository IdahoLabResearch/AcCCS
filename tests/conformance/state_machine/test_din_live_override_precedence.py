"""Live-override precedence over the message field tree for DIN loop fields (#75).

ADR-0006 fixes the precedence of the DIN charge-loop current/voltage fields both
the operator console and the personality can set:

    live-override  >  message field tree  >  computed

The tree supplies each field's declared / *start* value; a mid-session
[[live-override]] from the operator console still beats it on subsequent loop
messages. Clearing the override falls the field back to the tree, and — tree
unset — to the simulator's computed value.

The fields are role-aware at the read site: on the SECC the reported *present*
V/I of ``CurrentDemandRes`` (``EVSEPresentVoltage`` / ``EVSEPresentCurrent``);
on the EVCC the requested *target* V/I of ``CurrentDemandReq``
(``EVTargetVoltage`` / ``EVTargetCurrent``). Both are exercised here through the
real state graph and EXI round-trip so the assertion is on the emitted wire
value, not an intermediate.

The regression these guard against: the tree is poked onto the built message
*after* construction (``apply_personality_tree``), so before #75 the tree poke
clobbered the already-applied override back to the tree value — inverting the
precedence to tree > override.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.evcc.states.din_spec_states import PowerDelivery as EVCCPowerDelivery
from app.secc.controller.simulator import SimEVSEController
from app.secc.states.din_spec_states import CurrentDemand as SECCCurrentDemand
from app.shared.exi_codec import EXI
from app.shared.live_control import LiveControl
from app.shared.messages.datatypes import (
    DCEVSEStatus,
    PVEVTargetCurrentDin,
    PVEVTargetVoltageDin,
)
from app.shared.messages.din_spec.body import (
    Body,
    CurrentDemandReq,
    PowerDeliveryRes,
)
from app.shared.messages.din_spec.datatypes import (
    DCEVSEStatusCode,
    DCEVStatus,
    EVSENotification,
)
from app.shared.messages.din_spec.header import MessageHeader
from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from app.shared.messages.enums import (
    DCEVErrorCode,
    IsolationLevel,
    Namespace,
    Protocol,
    UnitSymbol,
)
from app.shared.personality.loader import load_personality
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession

PERSONALITIES_DIR = Path(__file__).resolve().parents[3] / "personalities"

# The tree's declared start values and the operator's override — kept distinct
# from each other and from the computed defaults so an assertion pins exactly
# which layer reached the wire.
TREE_VOLTAGE = 222
TREE_CURRENT = 33
OVERRIDE_VOLTAGE = 444.0
OVERRIDE_CURRENT = 55.0


def _decode(result, namespace=Namespace.DIN_MSG_DEF):
    return EXI().from_exi_document(result.outbound_v2gtp.payload, namespace).body.get_message()


def _dc_ev_status() -> DCEVStatus:
    return DCEVStatus(
        ev_ready=True, ev_error_code=DCEVErrorCode.NO_ERROR, ev_ress_soc=42
    )


# ---------------------------------------------------------------------------
# SECC: reported present V/I in CurrentDemandRes
# ---------------------------------------------------------------------------


def _secc_session(*, tree_present: bool, live_control: LiveControl) -> StubCommSession:
    from app.secc.failed_responses import init_failed_responses_din_spec_70121
    from app.secc.secc_settings import Config
    from app.shared.personality.model import Runtime

    personality = load_personality(
        str(PERSONALITIES_DIR / "din-secc-baseline.yaml"), "secc"
    )
    if tree_present:
        # Present V/I is a runtime measurement the baseline deliberately leaves
        # out of the tree; a red-team personality may still pin it, which is the
        # "set in the tree" half of the precedence.
        personality.message_field_tree["CurrentDemandRes"]["EVSEPresentVoltage"] = {
            "Value": TREE_VOLTAGE, "Multiplier": 0, "Unit": "V",
        }
        personality.message_field_tree["CurrentDemandRes"]["EVSEPresentCurrent"] = {
            "Value": TREE_CURRENT, "Multiplier": 0, "Unit": "A",
        }
    session = StubCommSession(
        protocol=Protocol.DIN_SPEC_70121, session_id=bytes(1).hex()
    )
    session.evse_controller = SimEVSEController(
        personality=personality, live_control=live_control
    )
    session.config = Config.from_personality(personality, Runtime())
    session.failed_responses_din_spec = init_failed_responses_din_spec_70121()
    return session


async def _secc_present(session) -> tuple[float, float]:
    req = V2GMessageDINSPEC(
        header=MessageHeader(session_id=session.session_id),
        body=Body(
            current_demand_req=CurrentDemandReq(
                dc_ev_status=_dc_ev_status(),
                ev_target_current=PVEVTargetCurrentDin(
                    multiplier=0, value=60, unit=UnitSymbol.AMPERE
                ),
                ev_target_voltage=PVEVTargetVoltageDin(
                    multiplier=0, value=390, unit=UnitSymbol.VOLTAGE
                ),
                charging_complete=False,
            )
        ),
    )
    res = _decode(await ScriptedPeer(session, SECCCurrentDemand).feed(req))
    return (
        res.evse_present_voltage.get_decimal_value(),
        res.evse_present_current.get_decimal_value(),
    )


@pytest.mark.asyncio
async def test_secc_override_beats_tree(exi_codec):
    lc = LiveControl()
    lc.set_override_voltage(OVERRIDE_VOLTAGE)
    lc.set_override_current(OVERRIDE_CURRENT)
    volt, curr = await _secc_present(_secc_session(tree_present=True, live_control=lc))
    assert volt == OVERRIDE_VOLTAGE
    assert curr == OVERRIDE_CURRENT


@pytest.mark.asyncio
async def test_secc_cleared_override_falls_back_to_tree(exi_codec):
    lc = LiveControl()
    lc.set_override_voltage(OVERRIDE_VOLTAGE)
    lc.set_override_current(OVERRIDE_CURRENT)
    lc.clear_overrides()
    volt, curr = await _secc_present(_secc_session(tree_present=True, live_control=lc))
    assert volt == TREE_VOLTAGE
    assert curr == TREE_CURRENT


@pytest.mark.asyncio
async def test_secc_tree_only_emits_tree(exi_codec):
    volt, curr = await _secc_present(
        _secc_session(tree_present=True, live_control=LiveControl())
    )
    assert volt == TREE_VOLTAGE
    assert curr == TREE_CURRENT


@pytest.mark.asyncio
async def test_secc_neither_is_computed(exi_codec):
    session = _secc_session(tree_present=False, live_control=LiveControl())
    expected_v = (
        await session.evse_controller.get_evse_present_voltage(Protocol.DIN_SPEC_70121)
    ).get_decimal_value()
    expected_c = (
        await session.evse_controller.get_evse_present_current(Protocol.DIN_SPEC_70121)
    ).get_decimal_value()
    volt, curr = await _secc_present(session)
    assert volt == expected_v
    assert curr == expected_c
    assert (volt, curr) != (TREE_VOLTAGE, TREE_CURRENT)


# ---------------------------------------------------------------------------
# EVCC: requested target V/I in CurrentDemandReq
# ---------------------------------------------------------------------------


def _evcc_session(*, tree_target: bool, live_control: LiveControl) -> StubCommSession:
    personality = load_personality(
        str(PERSONALITIES_DIR / "din-evcc-baseline.yaml"), "evcc"
    )
    if tree_target:
        # Target V/I ramps and stays computed in the baseline; a personality may
        # still pin it — the "set in the tree" half of the precedence.
        personality.message_field_tree["CurrentDemandReq"]["EVTargetVoltage"] = {
            "Value": TREE_VOLTAGE, "Multiplier": 0, "Unit": "V",
        }
        personality.message_field_tree["CurrentDemandReq"]["EVTargetCurrent"] = {
            "Value": TREE_CURRENT, "Multiplier": 0, "Unit": "A",
        }
    config = EVCCConfig.from_personality(personality)
    session = StubCommSession(
        protocol=Protocol.DIN_SPEC_70121, session_id=bytes(1).hex()
    )
    session.config = config
    session.ev_controller = SimEVController(config, live_control)
    session.live_control = live_control
    session.selected_energy_mode = None
    return session


async def _evcc_target(session) -> tuple[float, float]:
    res = _decode(
        await ScriptedPeer(session, EVCCPowerDelivery).feed(
            V2GMessageDINSPEC(
                header=MessageHeader(session_id=session.session_id),
                body=Body(
                    power_delivery_res=PowerDeliveryRes(
                        response_code="OK",
                        dc_evse_status=DCEVSEStatus(
                            notification_max_delay=0,
                            evse_notification=EVSENotification.NONE,
                            evse_isolation_status=IsolationLevel.VALID,
                            evse_status_code=DCEVSEStatusCode.EVSE_READY,
                        ),
                    )
                ),
            )
        )
    )
    return (
        res.ev_target_voltage.get_decimal_value(),
        res.ev_target_current.get_decimal_value(),
    )


@pytest.mark.asyncio
async def test_evcc_override_beats_tree(exi_codec):
    lc = LiveControl()
    lc.set_override_voltage(OVERRIDE_VOLTAGE)
    lc.set_override_current(OVERRIDE_CURRENT)
    volt, curr = await _evcc_target(_evcc_session(tree_target=True, live_control=lc))
    assert volt == OVERRIDE_VOLTAGE
    assert curr == OVERRIDE_CURRENT


@pytest.mark.asyncio
async def test_evcc_cleared_override_falls_back_to_tree(exi_codec):
    lc = LiveControl()
    lc.set_override_voltage(OVERRIDE_VOLTAGE)
    lc.set_override_current(OVERRIDE_CURRENT)
    lc.clear_overrides()
    volt, curr = await _evcc_target(_evcc_session(tree_target=True, live_control=lc))
    assert volt == TREE_VOLTAGE
    assert curr == TREE_CURRENT


@pytest.mark.asyncio
async def test_evcc_tree_only_emits_tree(exi_codec):
    volt, curr = await _evcc_target(
        _evcc_session(tree_target=True, live_control=LiveControl())
    )
    assert volt == TREE_VOLTAGE
    assert curr == TREE_CURRENT


@pytest.mark.asyncio
async def test_evcc_neither_is_computed(exi_codec):
    session = _evcc_session(tree_target=False, live_control=LiveControl())
    params = await session.ev_controller.get_dc_charge_params(Protocol.DIN_SPEC_70121)
    expected_v = params.dc_target_voltage.get_decimal_value()
    expected_c = params.dc_target_current.get_decimal_value()
    volt, curr = await _evcc_target(session)
    assert volt == expected_v
    assert curr == expected_c
    assert (volt, curr) != (TREE_VOLTAGE, TREE_CURRENT)

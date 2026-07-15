"""SECC ISO 15118-2 message field tree tracer (issue #95, ADR-0006).

The protocol-keyed slice widens the [[message field tree]] to more than one
protocol and proves the new seams end-to-end through a single ISO 15118-2 field:
``ISO_15118_2 -> ChargeParameterDiscoveryRes -> DC_EVSEChargeParameter ->
DC_EVSEStatus -> EVSEIsolationStatus``. ISO-2 is *not* yet a tree-backed
protocol — it has no shipped baseline and its wire values otherwise come from
the builders' pre-tree path — so this is the tracer: a personality that sets one
ISO-2 leaf must see it on the wire, with the ISO-2 ChargeParameterDiscovery
construction site calling the (now protocol-keyed) apply pass for that one
message.

This drives the real ISO-2 ``ChargeParameterDiscovery`` state through the
ADR-0003 ``process_message()`` seam with a DC ``ChargeParameterDiscoveryReq``,
then asserts the ``ChargeParameterDiscoveryRes`` the SECC built carries the
tree's ``Invalid`` (the simulator hardcodes ``Valid``). The companion
``test_iso2_isolation_absent_falls_back_to_valid`` guards the unset fallback.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.secc.controller.simulator import SimEVSEController
from app.secc.states.iso15118_2_states import ChargeParameterDiscovery
from app.shared.messages.datatypes import (
    PVEVMaxCurrentLimit,
    PVEVMaxVoltageLimit,
)
from app.shared.messages.enums import EnergyTransferModeEnum, IsolationLevel, Protocol
from app.shared.messages.iso15118_2.body import (
    Body,
    ChargeParameterDiscoveryReq,
    ChargeParameterDiscoveryRes,
)
from app.shared.messages.iso15118_2.datatypes import (
    DCEVChargeParameter,
    DCEVStatus,
)
from app.shared.messages.iso15118_2.header import MessageHeader
from app.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from app.shared.personality.model import SECCPersonality
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession


# The one ISO-2 leaf this slice traces, expressed with the XSD aliases the issue
# uses, wrapped under the ISO_15118_2 protocol key.
def _iso2_isolation_tree(value):
    return {
        "ISO_15118_2": {
            "ChargeParameterDiscoveryRes": {
                "DC_EVSEChargeParameter": {
                    "DC_EVSEStatus": {"EVSEIsolationStatus": value}
                }
            }
        }
    }


def _iso2_secc_session(tree) -> StubCommSession:
    """An ISO-2 DC SECC session whose personality carries *tree*.

    The personality advertises only ISO 15118-2, so the DIN completeness gate
    never fires (ISO-2 is not yet tree-backed) and the single partial ISO-2 leaf
    loads fine. The session enters at ``ChargeParameterDiscovery`` directly.
    """
    personality = SECCPersonality.model_validate(
        {
            "capabilities": {"supported_protocols": ["ISO_15118_2"]},
            "message_field_tree": tree,
        }
    )
    from app.secc.secc_settings import Config
    from app.shared.personality.model import Runtime

    controller = SimEVSEController(personality=personality)
    controller.set_selected_protocol(Protocol.ISO_15118_2)
    session = StubCommSession(protocol=Protocol.ISO_15118_2, session_id=bytes(1).hex())
    session.evse_controller = controller
    # The CPD state reads `comm_session.config.free_charging_service` while
    # building the SAScheduleList.
    session.config = Config.from_personality(personality, Runtime())
    # A fresh (unresumed) session: no previously-selected SAScheduleTupleID, so
    # the state builds the schedule from scratch. `sa_schedule_tuple_id = 0` is
    # falsy, matching the initial-session path.
    session.ev_session_context = SimpleNamespace(sa_schedule_tuple_id=0)
    return session


def _dc_charge_parameter_discovery_req(session: StubCommSession) -> V2GMessageV2:
    """A minimal but valid DC ChargeParameterDiscoveryReq.

    DC_extended is what the simulator advertises for ISO 15118-2, so the state
    accepts the mode and enters its DC branch (building the DC_EVSEChargeParameter
    the tracer leaf lives under).
    """
    dc_ev_charge_parameter = DCEVChargeParameter(
        dc_ev_status=DCEVStatus(
            ev_ready=True, ev_error_code="NO_ERROR", ev_ress_soc=50
        ),
        ev_maximum_current_limit=PVEVMaxCurrentLimit(
            multiplier=0, value=200, unit="A"
        ),
        ev_maximum_voltage_limit=PVEVMaxVoltageLimit(
            multiplier=0, value=400, unit="V"
        ),
    )
    return V2GMessageV2(
        header=MessageHeader(session_id=session.session_id),
        body=Body(
            charge_parameter_discovery_req=ChargeParameterDiscoveryReq(
                requested_energy_mode=EnergyTransferModeEnum.DC_EXTENDED,
                dc_ev_charge_parameter=dc_ev_charge_parameter,
            )
        ),
    )


@pytest.mark.asyncio
async def test_iso2_isolation_status_from_message_field_tree(exi_codec):
    """A tree-set ISO-2 EVSEIsolationStatus reaches the built CPDRes.

    Proves the ISO-2 construction site calls the protocol-keyed apply pass: the
    simulator hardcodes ``Valid``, so an emitted ``Invalid`` can only come from
    the ``ISO_15118_2`` subtree.
    """
    session = _iso2_secc_session(_iso2_isolation_tree("Invalid"))
    peer = ScriptedPeer(session, start_state=ChargeParameterDiscovery)

    result = await peer.feed(_dc_charge_parameter_discovery_req(session))

    res = result.outbound_msg.body.charge_parameter_discovery_res
    assert isinstance(res, ChargeParameterDiscoveryRes)
    assert res.dc_charge_parameter is not None
    assert (
        res.dc_charge_parameter.dc_evse_status.evse_isolation_status
        is IsolationLevel.INVALID
    )


@pytest.mark.asyncio
async def test_iso2_isolation_absent_falls_back_to_valid(exi_codec):
    """With no ISO-2 tree leaf the builder's computed ``Valid`` survives.

    The fallback the tracer relies on: an unset leaf leaves the construction
    value untouched, so a personality that trees nothing for this field emits
    the simulator's ``Valid``.
    """
    session = _iso2_secc_session({})
    peer = ScriptedPeer(session, start_state=ChargeParameterDiscovery)

    result = await peer.feed(_dc_charge_parameter_discovery_req(session))

    res = result.outbound_msg.body.charge_parameter_discovery_res
    assert isinstance(res, ChargeParameterDiscoveryRes)
    assert (
        res.dc_charge_parameter.dc_evse_status.evse_isolation_status
        is IsolationLevel.VALID
    )

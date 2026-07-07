"""The DIN EVCC handles a charger that advertises a non-well-known ServiceID.

Regression for a real-charger interop failure: a Tellus Power SECC advertises
``ServiceTag.ServiceID = 4660`` (0x1234) in its ``ServiceDiscoveryRes``. DIN's
``serviceIDType`` is ``xs:unsignedShort`` [0..65535], so that is legal, but the
EVCC used to (a) model ``ServiceID`` as a 4-value enum, so decoding 4660 threw
``Cannot map EVerest enum value 4660 to Pydantic enum ServiceID`` in
``ServiceDiscovery``, and (b) pin ``SelectedServiceList.ServiceID = 1`` in the
personality tree, so even once decoding was fixed it selected an unadvertised
service and the charger rejected ``ServicePaymentSelectionReq`` with
``FAILED_ServiceSelectionInvalid``.

This drives the shipped run default (`din_dc_extended-evcc`, which `extends:`
`din-evcc-baseline`) through SessionSetup -> ServiceDiscovery, feeding a
ServiceDiscoveryRes carrying ServiceID 4660, and asserts the EVCC echoes 4660
back on the wire in ServicePaymentSelectionReq rather than the old pinned 1.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.evcc.states.din_spec_states import ServiceDiscovery, SessionSetup
from app.shared.exi_codec import EXI
from app.shared.messages.din_spec.body import (
    Body,
    ServiceDiscoveryRes,
    SessionSetupRes,
)
from app.shared.messages.din_spec.datatypes import (
    AuthOptionList,
    ChargeService,
    ServiceCategory,
    ServiceDetails,
)
from app.shared.messages.din_spec.header import MessageHeader
from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from app.shared.messages.enums import (
    AuthEnum,
    EnergyTransferModeEnum,
    Namespace,
    Protocol,
)
from app.shared.personality.loader import load_personality
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession

PERSONALITIES_DIR = Path(__file__).resolve().parents[4] / "personalities"

# The value the real Tellus Power charger advertises (0x1234); outside the
# well-known DIN ServiceID enum {CHARGING=1, CERTIFICATE=2, INTERNET=3, CUSTOM=4}.
FOREIGN_SERVICE_ID = 4660


def _run_default_session() -> StubCommSession:
    # The shipped run default for run_evcc.py, not a test-only personality.
    personality = load_personality("din_dc_extended-evcc", "evcc")
    config = EVCCConfig.from_personality(personality)
    session = StubCommSession(
        protocol=Protocol.DIN_SPEC_70121, session_id=bytes(1).hex()
    )
    session.config = config
    session.ev_controller = SimEVController(config)
    session.live_control = None
    session.selected_auth_option = None
    session.selected_services = []
    session.selected_energy_mode = None
    session.selected_schedule = None
    session.ongoing_timer = -1
    return session


def _decode(result):
    payload = result.outbound_v2gtp.payload
    return EXI().from_exi_document(payload, Namespace.DIN_MSG_DEF).body.get_message()


@pytest.mark.asyncio
async def test_evcc_echoes_foreign_service_id(exi_codec):
    session = _run_default_session()
    hdr = lambda: MessageHeader(session_id=session.session_id)  # noqa: E731
    peer = ScriptedPeer(session, SessionSetup)

    # SessionSetupRes -> ServiceDiscoveryReq
    _decode(
        await peer.feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(
                    session_setup_res=SessionSetupRes(response_code="OK", evse_id="00")
                ),
            )
        )
    )

    # ServiceDiscoveryRes (advertising the foreign ServiceID) -> ServicePaymentSelectionReq
    payment_req = _decode(
        await peer.feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(
                    service_discovery_res=ServiceDiscoveryRes(
                        response_code="OK",
                        auth_option_list=AuthOptionList(auth_options=[AuthEnum.EIM_V2]),
                        charge_service=ChargeService(
                            service_tag=ServiceDetails(
                                service_id=FOREIGN_SERVICE_ID,
                                service_category=ServiceCategory.CHARGING,
                            ),
                            free_service=False,
                            energy_transfer_type=EnergyTransferModeEnum.DC_EXTENDED,
                        ),
                    )
                ),
            )
        )
    )

    selected = payment_req.selected_service_list.selected_service
    assert [s.service_id for s in selected] == [FOREIGN_SERVICE_ID], (
        "EVCC must echo the SECC's advertised ServiceID; a static tree pin here "
        "draws FAILED_ServiceSelectionInvalid from a charger that advertises "
        "anything other than 1."
    )
    # Payment option is still the static tree value.
    assert payment_req.selected_payment_option == AuthEnum.EIM_V2

"""ISO 15118-2 ``ServiceName`` is a free string on the wire, not an enum.

Annex C.6 of ISO 15118-2:2014 defines ``serviceNameType`` as
``xs:string`` with ``maxLength=32`` ("Human readable service name"); Table
105 only lists the names the standard itself *assigns* to ServiceIDs 1–4.
Production SECCs advertise other strings (a fielded charger sends
``DC_CHARGING`` for ServiceID 1), and ServiceIDs 60001–65535 are reserved
for implementation-specific services whose names the standard cannot know.

The EVCC previously validated ``ServiceName`` against the Table 105 enum and
aborted ServiceDiscovery with ``'DC_CHARGING' is not a valid ServiceName``.
"""

from __future__ import annotations

import pytest

from app.shared.messages.enums import AuthEnum, EnergyTransferModeEnum, Namespace
from app.shared.messages.iso15118_2.body import Body, ServiceDiscoveryRes
from app.shared.messages.iso15118_2.datatypes import (
    AuthOptionList,
    ChargeService,
    EnergyTransferModeList,
    ResponseCode,
    ServiceCategory,
    ServiceDetails,
    ServiceID,
    ServiceName,
)
from app.shared.messages.iso15118_2.msgdef import V2GMessage
from tests.conformance.codec.fixtures import _iso2_header


def _service_discovery_res(service_name: str) -> V2GMessage:
    return V2GMessage(
        header=_iso2_header(),
        body=Body(
            service_discovery_res=ServiceDiscoveryRes(
                response_code=ResponseCode.OK,
                auth_option_list=AuthOptionList(auth_options=[AuthEnum.EIM_V2]),
                charge_service=ChargeService(
                    service_id=ServiceID.CHARGING,
                    service_name=service_name,
                    service_category=ServiceCategory.CHARGING,
                    free_service=True,
                    supported_energy_transfer_mode=EnergyTransferModeList(
                        energy_modes=[EnergyTransferModeEnum.DC_EXTENDED]
                    ),
                ),
            )
        ),
    )


@pytest.mark.parametrize("service_name", ["DC_CHARGING", "AC_DC_Charging", "x" * 32])
def test_service_name_round_trips_as_free_string(exi_codec, service_name):
    from app.shared.exi_codec import EXI

    message = _service_discovery_res(service_name)
    encoded = EXI().to_exi_document(message, Namespace.ISO_V2_MSG_DEF)
    decoded = EXI().from_exi_document(
        encoded, Namespace.ISO_V2_MSG_DEF, model_cls=V2GMessage
    )

    assert decoded.body.service_discovery_res.charge_service.service_name == service_name
    assert decoded.model_dump(by_alias=True, exclude_none=True) == message.model_dump(
        by_alias=True, exclude_none=True
    )


def test_table_105_enum_members_remain_valid_values():
    """The SECC still emits the Table 105 names via the ``ServiceName`` enum."""
    details = ServiceDetails(
        service_id=ServiceID.CHARGING,
        service_name=ServiceName.CHARGING,
        service_category=ServiceCategory.CHARGING,
        free_service=True,
    )
    assert details.service_name == "AC_DC_Charging"


def test_service_name_longer_than_32_is_rejected():
    with pytest.raises(ValueError):
        ServiceDetails(
            service_id=ServiceID.CHARGING,
            service_name="x" * 33,
            service_category=ServiceCategory.CHARGING,
            free_service=True,
        )

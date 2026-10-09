"""Schema-legal peer values the message model used to reject (issue #124).

Four values hit in the field were legal on the wire but outside our model, so
the EVCC closed the socket instead of continuing (conformance review
SC-002, SC-032, SC-033, SC-034). Each now round-trips through the codec into
the model and is accepted with a single warning-level out-of-spec log line
naming the owning element, the field, the value and the spec bound.

- DIN ``NotificationMaxDelay`` above 65535: DIN types it ``xs:unsignedInt``
  and tells the EVCC to ignore it ([V2G-DC-636]); our bound was ISO-2's.
- ISO-2 ``EVSEID`` shorter than seven characters (Annex C.6 ``evseIDType``
  minLength 7): a real charger sends one NUL byte.
- DIN ``ServiceName`` outside the standard's own names.
- ISO-2 ``ServiceID`` outside 1-4: ``serviceIDType`` is ``xs:unsignedShort``
  and 60001-65535 is reserved for implementation-specific services.
"""

from __future__ import annotations

import logging

import pytest
from pydantic import ValidationError

from app.shared.exi_codec import EXI
from app.shared.messages.datatypes import (
    DCEVSEStatus,
    DCEVSEStatusCode,
    PVEVSEMaxCurrentLimit,
    PVEVSEMaxPowerLimit,
    PVEVSEMaxVoltageLimit,
    PVEVSEPresentCurrent,
    PVEVSEPresentVoltage,
)
from app.shared.messages.enums import (
    AuthEnum,
    EnergyTransferModeEnum,
    EVSEProcessing,
    IsolationLevel,
    Namespace,
)
from app.shared.messages.din_spec.body import Body as BodyDIN
from app.shared.messages.din_spec.body import CableCheckRes as CableCheckResDIN
from app.shared.messages.din_spec.body import ServiceDiscoveryRes as ServiceDiscoveryResDIN
from app.shared.messages.din_spec.datatypes import AuthOptionList as AuthOptionListDIN
from app.shared.messages.din_spec.datatypes import ChargeService as ChargeServiceDIN
from app.shared.messages.din_spec.datatypes import EVSENotification as EVSENotificationDIN
from app.shared.messages.din_spec.datatypes import ResponseCode as ResponseCodeDIN
from app.shared.messages.din_spec.datatypes import ServiceCategory as ServiceCategoryDIN
from app.shared.messages.din_spec.datatypes import ServiceDetails as ServiceDetailsDIN
from app.shared.messages.din_spec.datatypes import ServiceID as ServiceIDDIN
from app.shared.messages.din_spec.datatypes import ServiceName as ServiceNameDIN
from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDIN
from app.shared.messages.iso15118_2.body import Body as BodyISO2
from app.shared.messages.iso15118_2.body import ChargingStatusRes as ChargingStatusResISO2
from app.shared.messages.iso15118_2.body import CurrentDemandRes as CurrentDemandResISO2
from app.shared.messages.iso15118_2.body import ServiceDiscoveryRes as ServiceDiscoveryResISO2
from app.shared.messages.iso15118_2.body import SessionSetupRes as SessionSetupResISO2
from app.shared.messages.iso15118_2.datatypes import AuthOptionList as AuthOptionListISO2
from app.shared.messages.iso15118_2.datatypes import ChargeService as ChargeServiceISO2
from app.shared.messages.iso15118_2.datatypes import EnergyTransferModeList
from app.shared.messages.iso15118_2.datatypes import ResponseCode as ResponseCodeISO2
from app.shared.messages.iso15118_2.datatypes import ServiceCategory as ServiceCategoryISO2
from app.shared.messages.iso15118_2.datatypes import ServiceDetails as ServiceDetailsISO2
from app.shared.messages.iso15118_2.datatypes import ServiceID as ServiceIDISO2
from app.shared.messages.iso15118_2.datatypes import ServiceList as ServiceListISO2
from app.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageISO2
from tests.conformance.out_of_spec_log import (
    OUT_OF_SPEC_LOGGER,
    assert_single_out_of_spec_warning,
    out_of_spec_records,
)
from tests.conformance.codec.fixtures import (
    _din_header,
    _iso2_ac_evse_status,
    _iso2_dc_evse_status,
    _iso2_header,
    _iso2_pv,
)

# What the real DIN charger put on the wire in CableCheckRes (3 << 24).
OVERSIZED_NOTIFICATION_MAX_DELAY = 50331648


def _receive(encoded: bytes, namespace: str, caplog):
    """Decode as the receive path does, capturing only that step's warnings.

    Building the peer's message in the test also ran the validators, so the
    records from construction are dropped first.
    """
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        return EXI().from_exi_document(encoded, namespace)


# ---------------------------------------------------------------------------
# DIN NotificationMaxDelay above 65535 (SC-002)
# ---------------------------------------------------------------------------


def _din_cable_check_res(notification_max_delay: int) -> V2GMessageDIN:
    return V2GMessageDIN(
        header=_din_header(),
        body=BodyDIN(
            cable_check_res=CableCheckResDIN(
                response_code=ResponseCodeDIN.OK,
                dc_evse_status=DCEVSEStatus(
                    notification_max_delay=notification_max_delay,
                    evse_notification=EVSENotificationDIN.NONE,
                    evse_isolation_status=IsolationLevel.VALID,
                    evse_status_code=DCEVSEStatusCode.EVSE_READY,
                ),
                evse_processing=EVSEProcessing.FINISHED,
            )
        ),
    )


def test_din_oversized_notification_max_delay_round_trips(exi_codec, caplog):
    message = _din_cable_check_res(OVERSIZED_NOTIFICATION_MAX_DELAY)
    encoded = EXI().to_exi_document(message, Namespace.DIN_MSG_DEF)

    decoded = _receive(encoded, Namespace.DIN_MSG_DEF, caplog)

    status = decoded.body.cable_check_res.dc_evse_status
    assert status.notification_max_delay == OVERSIZED_NOTIFICATION_MAX_DELAY
    assert decoded.model_dump(by_alias=True, exclude_none=True) == message.model_dump(
        by_alias=True, exclude_none=True
    )
    assert_single_out_of_spec_warning(caplog, "DCEVSEStatus", "NotificationMaxDelay", OVERSIZED_NOTIFICATION_MAX_DELAY, "65535")


# ---------------------------------------------------------------------------
# DIN ServiceName outside the standard's names (SC-033)
# ---------------------------------------------------------------------------

# A name outside ISO 15118-2 Table 105, as a fielded charger advertises.
VENDOR_SERVICE_NAME = "DC_CHARGING"


def _din_service_discovery_res(service_name: str) -> V2GMessageDIN:
    return V2GMessageDIN(
        header=_din_header(),
        body=BodyDIN(
            service_discovery_res=ServiceDiscoveryResDIN(
                response_code=ResponseCodeDIN.OK,
                auth_option_list=AuthOptionListDIN(auth_options=[AuthEnum.EIM_V2]),
                charge_service=ChargeServiceDIN(
                    service_tag=ServiceDetailsDIN(
                        service_id=ServiceIDDIN.CHARGING,
                        service_name=service_name,
                        service_category=ServiceCategoryDIN.CHARGING,
                    ),
                    free_service=True,
                    energy_transfer_type=EnergyTransferModeEnum.DC_EXTENDED,
                ),
            )
        ),
    )


def test_din_vendor_service_name_round_trips(exi_codec, caplog):
    message = _din_service_discovery_res(VENDOR_SERVICE_NAME)
    encoded = EXI().to_exi_document(message, Namespace.DIN_MSG_DEF)

    decoded = _receive(encoded, Namespace.DIN_MSG_DEF, caplog)

    service_tag = decoded.body.service_discovery_res.charge_service.service_tag
    assert service_tag.service_name == VENDOR_SERVICE_NAME
    assert decoded.model_dump(by_alias=True, exclude_none=True) == message.model_dump(
        by_alias=True, exclude_none=True
    )
    assert_single_out_of_spec_warning(caplog, "ServiceDetails", "ServiceName", VENDOR_SERVICE_NAME, "AC_DC_Charging")


def test_din_standard_service_name_is_not_flagged(exi_codec, caplog):
    message = _din_service_discovery_res(ServiceNameDIN.CHARGING)
    encoded = EXI().to_exi_document(message, Namespace.DIN_MSG_DEF)

    decoded = _receive(encoded, Namespace.DIN_MSG_DEF, caplog)

    service_tag = decoded.body.service_discovery_res.charge_service.service_tag
    assert service_tag.service_name == "AC_DC_Charging"
    assert out_of_spec_records(caplog) == []


# ---------------------------------------------------------------------------
# ISO-2 EVSEID shorter than seven characters (SC-032)
# ---------------------------------------------------------------------------

# What the real ISO-2 charger put on the wire in SessionSetupRes: one NUL byte.
ONE_NUL_EVSE_ID = "\x00"
# Annex C.6 evseIDType: minLength 7, maxLength 37.
EVSE_ID_MAX = "A" * 37
EVSE_ID_OVERLONG = "A" * 38


def _iso2_session_setup_res(evse_id: str) -> V2GMessageISO2:
    return V2GMessageISO2(
        header=_iso2_header(),
        body=BodyISO2(
            session_setup_res=SessionSetupResISO2(
                response_code=ResponseCodeISO2.OK_NEW_SESSION_ESTABLISHED,
                evse_id=evse_id,
            )
        ),
    )


@pytest.mark.parametrize(
    "evse_id",
    [
        pytest.param(ONE_NUL_EVSE_ID, id="one-nul-byte-real-charger"),
        pytest.param("A", id="one-character"),
    ],
)
def test_iso2_short_evse_id_round_trips(exi_codec, caplog, evse_id):
    message = _iso2_session_setup_res(evse_id)
    encoded = EXI().to_exi_document(message, Namespace.ISO_V2_MSG_DEF)

    decoded = _receive(encoded, Namespace.ISO_V2_MSG_DEF, caplog)

    assert decoded.body.session_setup_res.evse_id == evse_id
    assert decoded.model_dump(by_alias=True, exclude_none=True) == message.model_dump(
        by_alias=True, exclude_none=True
    )
    assert_single_out_of_spec_warning(caplog, "SessionSetupRes", "EVSEID", repr(evse_id), "minLength 7")


def _iso2_charging_status_res(evse_id: str) -> V2GMessageISO2:
    return V2GMessageISO2(
        header=_iso2_header(),
        body=BodyISO2(
            charging_status_res=ChargingStatusResISO2(
                response_code=ResponseCodeISO2.OK,
                evse_id=evse_id,
                sa_schedule_tuple_id=1,
                ac_evse_status=_iso2_ac_evse_status(),
            )
        ),
    )


def _iso2_current_demand_res(evse_id: str) -> V2GMessageISO2:
    return V2GMessageISO2(
        header=_iso2_header(),
        body=BodyISO2(
            current_demand_res=CurrentDemandResISO2(
                response_code=ResponseCodeISO2.OK,
                dc_evse_status=_iso2_dc_evse_status(),
                evse_present_voltage=_iso2_pv(PVEVSEPresentVoltage, 400),
                evse_present_current=_iso2_pv(PVEVSEPresentCurrent, 10),
                evse_current_limit_achieved=False,
                evse_voltage_limit_achieved=False,
                evse_power_limit_achieved=False,
                evse_max_voltage_limit=_iso2_pv(PVEVSEMaxVoltageLimit, 500),
                evse_max_current_limit=_iso2_pv(PVEVSEMaxCurrentLimit, 200),
                evse_max_power_limit=_iso2_pv(PVEVSEMaxPowerLimit, 80, 3),
                evse_id=evse_id,
                sa_schedule_tuple_id=1,
            )
        ),
    )


@pytest.mark.parametrize(
    ("build", "owner", "body_field"),
    [
        pytest.param(
            _iso2_charging_status_res, "ChargingStatusRes", "charging_status_res",
            id="ChargingStatusRes",
        ),
        pytest.param(
            _iso2_current_demand_res, "CurrentDemandRes", "current_demand_res",
            id="CurrentDemandRes",
        ),
    ],
)
def test_iso2_other_evse_id_bearing_responses_round_trip_short_evse_id(
    exi_codec, caplog, build, owner, body_field
):
    message = build("A")
    encoded = EXI().to_exi_document(message, Namespace.ISO_V2_MSG_DEF)

    decoded = _receive(encoded, Namespace.ISO_V2_MSG_DEF, caplog)

    assert getattr(decoded.body, body_field).evse_id == "A"
    assert decoded.model_dump(by_alias=True, exclude_none=True) == message.model_dump(
        by_alias=True, exclude_none=True
    )
    assert_single_out_of_spec_warning(caplog, owner, "EVSEID", "'A'", "minLength 7")


def test_iso2_evse_id_keeps_schema_maximum(caplog):
    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        assert _iso2_session_setup_res(EVSE_ID_MAX).body.session_setup_res.evse_id == EVSE_ID_MAX
    assert out_of_spec_records(caplog) == []
    with pytest.raises(ValidationError):
        _iso2_session_setup_res(EVSE_ID_OVERLONG)


# ---------------------------------------------------------------------------
# ISO-2 ServiceID outside 1-4 (SC-034)
# ---------------------------------------------------------------------------

# 8.6.3.6 reserves 60001-65535 for implementation-specific services.
VENDOR_SERVICE_ID = 60001
# A third-party DIN charger advertises this (0x1234); nothing stops an ISO-2 one.
FOREIGN_SERVICE_ID = 4660


def _iso2_service_discovery_res(charge_service_id: int, *, vas_id=None) -> V2GMessageISO2:
    service_list = None
    if vas_id is not None:
        service_list = ServiceListISO2(
            services=[
                ServiceDetailsISO2(
                    service_id=vas_id,
                    service_name=VENDOR_SERVICE_NAME,
                    service_category=ServiceCategoryISO2.CUSTOM,
                    free_service=True,
                )
            ]
        )
    return V2GMessageISO2(
        header=_iso2_header(),
        body=BodyISO2(
            service_discovery_res=ServiceDiscoveryResISO2(
                response_code=ResponseCodeISO2.OK,
                auth_option_list=AuthOptionListISO2(auth_options=[AuthEnum.EIM_V2]),
                charge_service=ChargeServiceISO2(
                    service_id=charge_service_id,
                    service_category=ServiceCategoryISO2.CHARGING,
                    free_service=True,
                    supported_energy_transfer_mode=EnergyTransferModeList(
                        energy_modes=[EnergyTransferModeEnum.DC_EXTENDED]
                    ),
                ),
                service_list=service_list,
            )
        ),
    )


@pytest.mark.parametrize(
    "service_id",
    [
        pytest.param(VENDOR_SERVICE_ID, id="60001-implementation-specific"),
        pytest.param(FOREIGN_SERVICE_ID, id="4660-third-party-charger"),
    ],
)
def test_iso2_charge_service_with_vendor_service_id_round_trips(
    exi_codec, caplog, service_id
):
    message = _iso2_service_discovery_res(service_id)
    encoded = EXI().to_exi_document(message, Namespace.ISO_V2_MSG_DEF)

    decoded = _receive(encoded, Namespace.ISO_V2_MSG_DEF, caplog)

    assert decoded.body.service_discovery_res.charge_service.service_id == service_id
    assert decoded.model_dump(by_alias=True, exclude_none=True) == message.model_dump(
        by_alias=True, exclude_none=True
    )
    assert_single_out_of_spec_warning(caplog, "ChargeService", "ServiceID", service_id, "1..4")


def test_iso2_service_list_entry_with_vendor_service_id_round_trips(exi_codec, caplog):
    message = _iso2_service_discovery_res(ServiceIDISO2.CHARGING, vas_id=VENDOR_SERVICE_ID)
    encoded = EXI().to_exi_document(message, Namespace.ISO_V2_MSG_DEF)

    decoded = _receive(encoded, Namespace.ISO_V2_MSG_DEF, caplog)

    [service] = decoded.body.service_discovery_res.service_list.services
    assert service.service_id == VENDOR_SERVICE_ID
    assert service.service_name == VENDOR_SERVICE_NAME
    # ISO-2 ServiceName is already a free string: the only warning is the ID's.
    assert_single_out_of_spec_warning(caplog, "ServiceDetails", "ServiceID", VENDOR_SERVICE_ID, "1..4")


def test_iso2_standard_service_id_is_not_flagged(caplog):
    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        details = ServiceDetailsISO2(
            service_id=ServiceIDISO2.CHARGING,
            service_category=ServiceCategoryISO2.CHARGING,
            free_service=True,
        )
    assert details.service_id == 1
    assert out_of_spec_records(caplog) == []


def test_iso2_service_id_keeps_unsigned_short_bound():
    with pytest.raises(ValidationError):
        ServiceDetailsISO2(
            service_id=65536,
            service_category=ServiceCategoryISO2.CHARGING,
            free_service=True,
        )

"""Message field tree — tracer bullet (issue #71, ADR-0006).

Slice 1 builds the full [[message field tree]] machinery and proves it end to
end through a single field: ``ChargeParameterDiscoveryRes ->
DC_EVSEChargeParameter -> DC_EVSEStatus -> EVSEIsolationStatus`` on the DIN
SECC. These tests pin the issue's acceptance criteria:

* a DIN personality can *carry* a tree entry for that path;
* setting it to ``Invalid`` puts ``Invalid`` on the wire (asserted here via an
  EXI encode/decode round-trip; the virtual demo covers the live state
  machine);
* a misspelled path is a **hard error at load** (path-strict);
* an illegal-but-encodable value is accepted, not range/enum-rejected at the
  tree layer (value-raw);
* an unset leaf falls back to the builder's default.
"""

from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError

from app.shared.exi_codec import EXI
from app.shared.messages.din_spec.body import (
    Body,
    ChargeParameterDiscoveryRes,
)
from app.shared.messages.din_spec.header import MessageHeader
from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from app.shared.messages.enums import EVSEProcessing, IsolationLevel, Namespace
from app.shared.messages.iso15118_2.datatypes import ResponseCode
from app.secc.controller.simulator import SimEVSEController
from app.shared.personality.message_field_tree import (
    MessageFieldTreeError,
    apply_message_field_tree,
)
from app.shared.personality.model import SECCPersonality


@pytest.fixture(autouse=True)
def _real_exi_codec():
    """Guarantee a real EXI codec for the wire round-trip tests below.

    The EXI codec is a process-wide singleton. Another test in the suite can
    register a stub on it — e.g. the session-lifecycle handler tests construct
    a ``CommunicationSessionHandler`` with a ``SimpleNamespace`` codec, and the
    handler's ``__init__`` calls ``EXI().set_exi_codec`` — which would break the
    encode/decode round-trips here. Re-registering the real codec makes these
    tests independent of collection order (pytest-randomly).
    """
    from app.shared.expy_exi_codec import EXPyEXICodec
    from app.shared.settings import load_shared_settings

    load_shared_settings()
    EXI().set_exi_codec(EXPyEXICodec())
    yield


# The one path this slice wires end to end, expressed with the XSD aliases the
# issue uses. A helper keeps the deep nesting out of every test body.
def _isolation_tree(value):
    return {
        "ChargeParameterDiscoveryRes": {
            "DC_EVSEChargeParameter": {
                "DC_EVSEStatus": {"EVSEIsolationStatus": value}
            }
        }
    }


# ---------------------------------------------------------------------------
# Carrying an entry + path-strict validation (criteria 1 and 3)
# ---------------------------------------------------------------------------


def test_personality_carries_isolation_tree_entry():
    p = SECCPersonality.model_validate({"message_field_tree": _isolation_tree("Invalid")})
    leaf = p.message_field_tree["ChargeParameterDiscoveryRes"][
        "DC_EVSEChargeParameter"
    ]["DC_EVSEStatus"]["EVSEIsolationStatus"]
    assert leaf == "Invalid"


def test_default_tree_is_empty():
    assert SECCPersonality().message_field_tree == {}


def test_path_accepts_python_field_names_too():
    # ADR-0006: a segment resolves by field name *or* alias.
    tree = {
        "ChargeParameterDiscoveryRes": {
            "dc_charge_parameter": {
                "dc_evse_status": {"evse_isolation_status": "Warning"}
            }
        }
    }
    SECCPersonality.model_validate({"message_field_tree": tree})


def test_unknown_message_name_is_hard_error():
    with pytest.raises(ValidationError):
        SECCPersonality.model_validate(
            {"message_field_tree": {"ChargeParameterDiscoveryRezz": {}}}
        )


def test_misspelled_leaf_is_hard_error():
    with pytest.raises(ValidationError):
        SECCPersonality.model_validate(
            {
                "message_field_tree": {
                    "ChargeParameterDiscoveryRes": {
                        "DC_EVSEChargeParameter": {
                            "DC_EVSEStatus": {"EVSEIsolationStatuz": "Invalid"}
                        }
                    }
                }
            }
        )


def test_misspelled_mid_path_is_hard_error():
    with pytest.raises(ValidationError):
        SECCPersonality.model_validate(
            {
                "message_field_tree": {
                    "ChargeParameterDiscoveryRes": {
                        "DC_EVSEChargeParametr": {  # typo
                            "DC_EVSEStatus": {"EVSEIsolationStatus": "Invalid"}
                        }
                    }
                }
            }
        )


def test_descending_into_a_leaf_is_hard_error():
    # EVSEProcessing is a scalar leaf; giving it a nested mapping is a path
    # error, not a value the tree should silently accept.
    with pytest.raises(ValidationError):
        SECCPersonality.model_validate(
            {
                "message_field_tree": {
                    "ChargeParameterDiscoveryRes": {"EVSEProcessing": {"x": 1}}
                }
            }
        )


def test_non_mapping_tree_is_hard_error():
    with pytest.raises(ValidationError):
        SECCPersonality.model_validate({"message_field_tree": ["not", "a", "map"]})


def test_validate_helper_raises_message_field_tree_error():
    # The Pydantic layer wraps it, but the raw helper raises the typed error.
    from app.shared.personality.message_field_tree import (
        validate_message_field_tree,
    )

    with pytest.raises(MessageFieldTreeError):
        validate_message_field_tree({"NoSuchMessage": {}})


# ---------------------------------------------------------------------------
# Value-raw: illegal-but-encodable values are not rejected (criterion 4)
# ---------------------------------------------------------------------------


def test_illegal_enum_value_accepted_at_load():
    # 'Bogus' is not an IsolationLevel member — the model would reject it, but
    # the tree layer must not range/enum-check it.
    p = SECCPersonality.model_validate({"message_field_tree": _isolation_tree("Bogus")})
    leaf = p.message_field_tree["ChargeParameterDiscoveryRes"][
        "DC_EVSEChargeParameter"
    ]["DC_EVSEStatus"]["EVSEIsolationStatus"]
    assert leaf == "Bogus"


def test_out_of_range_numeric_leaf_accepted_at_load():
    # NotificationMaxDelay is xs:unsignedShort (le=65535) on the model; the tree
    # layer accepts an out-of-range value (bounded only by codec serializability).
    tree = {
        "ChargeParameterDiscoveryRes": {
            "DC_EVSEChargeParameter": {
                "DC_EVSEStatus": {"NotificationMaxDelay": 999_999}
            }
        }
    }
    p = SECCPersonality.model_validate({"message_field_tree": tree})
    assert (
        p.message_field_tree["ChargeParameterDiscoveryRes"][
            "DC_EVSEChargeParameter"
        ]["DC_EVSEStatus"]["NotificationMaxDelay"]
        == 999_999
    )


# ---------------------------------------------------------------------------
# apply_message_field_tree: lax build + coercion (criteria 2, 4, 5)
# ---------------------------------------------------------------------------


def _built_dc_evse_status():
    """A freshly built DIN DCEVSEStatus with the simulator's Valid default."""
    ctrl = SimEVSEController(personality=SECCPersonality())
    dc = asyncio.run(ctrl.get_dc_charge_parameters_dinspec())
    return ChargeParameterDiscoveryRes(
        response_code=ResponseCode.OK,
        evse_processing=EVSEProcessing.FINISHED,
        dc_charge_parameter=dc,
    )


def test_apply_coerces_valid_value_to_enum():
    msg = _built_dc_evse_status()
    apply_message_field_tree(msg, "ChargeParameterDiscoveryRes", _isolation_tree("Invalid"))
    # A valid string is coerced to the real enum so it encodes normally.
    assert (
        msg.dc_charge_parameter.dc_evse_status.evse_isolation_status
        is IsolationLevel.INVALID
    )


def test_apply_pokes_illegal_value_raw_via_lax_build():
    msg = _built_dc_evse_status()
    apply_message_field_tree(msg, "ChargeParameterDiscoveryRes", _isolation_tree("Bogus"))
    # validate_assignment=True on the model would normally reject 'Bogus'; the
    # lax-build seam poked it raw.
    assert msg.dc_charge_parameter.dc_evse_status.evse_isolation_status == "Bogus"


def test_apply_leaves_unset_leaf_untouched():
    msg = _built_dc_evse_status()
    apply_message_field_tree(msg, "ChargeParameterDiscoveryRes", {})
    assert (
        msg.dc_charge_parameter.dc_evse_status.evse_isolation_status
        is IsolationLevel.VALID
    )


def test_apply_ignores_other_message_entries():
    msg = _built_dc_evse_status()
    # A tree entry for a different message must not touch this one.
    apply_message_field_tree(
        msg,
        "ChargeParameterDiscoveryRes",
        {"CableCheckRes": {"DC_EVSEStatus": {"EVSEIsolationStatus": "Fault"}}},
    )
    assert (
        msg.dc_charge_parameter.dc_evse_status.evse_isolation_status
        is IsolationLevel.VALID
    )


# ---------------------------------------------------------------------------
# End-to-end EXI round-trip (criteria 2 and 5 on the wire)
# ---------------------------------------------------------------------------


def _roundtrip_isolation(tree_value):
    """Build the DIN CPD as the SECC state does, apply the tree, encode+decode.

    Returns the EVSEIsolationStatus recovered from the re-decoded wire bytes,
    so the assertion is on what actually serialized — not just the model.
    """
    from app.shared.settings import load_shared_settings

    load_shared_settings()  # idempotent: the codec reads shared_settings

    tree = _isolation_tree(tree_value) if tree_value is not None else {}
    p = SECCPersonality.model_validate({"message_field_tree": tree})
    ctrl = SimEVSEController(personality=p)
    dc = asyncio.run(ctrl.get_dc_charge_parameters_dinspec())
    msg = ChargeParameterDiscoveryRes(
        response_code=ResponseCode.OK,
        evse_processing=EVSEProcessing.FINISHED,
        dc_charge_parameter=dc,
    )
    if p.message_field_tree:
        apply_message_field_tree(msg, "ChargeParameterDiscoveryRes", p.message_field_tree)

    doc = V2GMessageDINSPEC(
        header=MessageHeader(session_id="00"),
        body=Body(charge_parameter_discovery_res=msg),
    )
    exi = EXI().to_exi_document(doc, Namespace.DIN_MSG_DEF)
    back = EXI().from_exi_document(exi, Namespace.DIN_MSG_DEF)
    return (
        back.body.charge_parameter_discovery_res.dc_charge_parameter.dc_evse_status.evse_isolation_status
    )


def test_wire_unset_falls_back_to_valid():
    assert _roundtrip_isolation(None) is IsolationLevel.VALID


def test_wire_invalid_is_emitted():
    assert _roundtrip_isolation("Invalid") is IsolationLevel.INVALID


def test_wire_warning_is_emitted():
    assert _roundtrip_isolation("Warning") is IsolationLevel.WARNING

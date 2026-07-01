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


# ---------------------------------------------------------------------------
# List-nested wire fields (issue #81, ADR-0006 amendment)
#
# The DIN SAScheduleList is a repeated child element emitted atomically inside
# one ChargeParameterDiscoveryRes. The tree addresses it as a nested list of
# maps and declares the *whole* list (length included); a device file replaces
# it wholesale; path-strict still applies inside each element but the list's
# cardinality/shape is value-raw (a red-team surface).
# ---------------------------------------------------------------------------


def _sa_schedule_tree(tuples):
    return {"ChargeParameterDiscoveryRes": {"SAScheduleList": {"SAScheduleTuple": tuples}}}


def _tuple(tuple_id=1, pmax=24000, schedule_id=1, entries=None):
    return {
        "SAScheduleTupleID": tuple_id,
        "PMaxSchedule": {
            "PMaxScheduleID": schedule_id,
            "PMaxScheduleEntry": entries
            or [{"PMax": pmax, "RelativeTimeInterval": {"start": 0}}],
        },
    }


def _built_cpd_with_scaffold():
    """A DIN CPD carrying the simulator's minimal SAScheduleList scaffold.

    Mirrors what the SECC state builds before construction-time substitution:
    a 1-tuple / 1-entry list the tree then replaces wholesale.
    """
    from app.shared.messages.din_spec.datatypes import (
        PMaxScheduleEntry,
        PMaxScheduleEntryDetails,
        RelativeTimeInterval,
        SAScheduleList,
        SAScheduleTupleEntry,
    )

    scaffold = SAScheduleList(
        values=[
            SAScheduleTupleEntry(
                sa_schedule_tuple_id=1,
                p_max_schedule=PMaxScheduleEntry(
                    p_max_schedule_id=0,
                    entry_details=[
                        PMaxScheduleEntryDetails(
                            p_max=200,
                            time_interval=RelativeTimeInterval(start=0, duration=3600),
                        )
                    ],
                ),
            )
        ]
    )
    return ChargeParameterDiscoveryRes(
        response_code=ResponseCode.OK,
        evse_processing=EVSEProcessing.FINISHED,
        sa_schedule_list=scaffold,
    )


def test_list_element_typo_is_hard_error():
    # Path-strict descends into each list element: a typo inside a repeated
    # element is a hard error at load, exactly like a scalar path typo.
    bad = _sa_schedule_tree(
        [_tuple(entries=[{"PMaxTYPO": 24000, "RelativeTimeInterval": {"start": 0}}])]
    )
    with pytest.raises(ValidationError):
        SECCPersonality.model_validate({"message_field_tree": bad})


def test_list_element_accepts_python_field_names():
    tree = {
        "ChargeParameterDiscoveryRes": {
            "sa_schedule_list": {
                "values": [
                    {
                        "sa_schedule_tuple_id": 1,
                        "p_max_schedule": {
                            "p_max_schedule_id": 1,
                            "entry_details": [
                                {"p_max": 24000, "time_interval": {"start": 0}}
                            ],
                        },
                    }
                ]
            }
        }
    }
    SECCPersonality.model_validate({"message_field_tree": tree})


def test_illegal_cardinality_not_rejected_at_load():
    # Value-raw for the list's *shape*: four tuples (model max_length=3) and
    # thirteen PMax entries (model max_length=12) must load without complaint —
    # cardinality fuzzing is the point (ADR-0004).
    entries = [{"PMax": 100 + i, "RelativeTimeInterval": {"start": 0}} for i in range(13)]
    tree = _sa_schedule_tree(
        [_tuple(tuple_id=i, entries=entries) for i in range(1, 5)]
    )
    SECCPersonality.model_validate({"message_field_tree": tree})


def test_apply_builds_whole_list_from_tree():
    # Element values *and* list length come from the tree: two tuples replace
    # the one-tuple scaffold wholesale, and each element is a real model.
    from app.shared.messages.din_spec.datatypes import SAScheduleTupleEntry

    msg = _built_cpd_with_scaffold()
    tree = _sa_schedule_tree([_tuple(tuple_id=1, pmax=24000), _tuple(tuple_id=2, pmax=5000)])
    apply_message_field_tree(msg, "ChargeParameterDiscoveryRes", tree)

    values = msg.sa_schedule_list.values
    assert len(values) == 2
    assert all(isinstance(v, SAScheduleTupleEntry) for v in values)
    assert values[0].p_max_schedule.p_max_schedule_id == 1
    assert values[0].p_max_schedule.entry_details[0].p_max == 24000
    # duration was omitted in the tree → stays None (Optional, off the wire).
    assert values[0].p_max_schedule.entry_details[0].time_interval.duration is None
    assert values[1].p_max_schedule.entry_details[0].p_max == 5000


def test_apply_empty_list_replaces_scaffold():
    msg = _built_cpd_with_scaffold()
    apply_message_field_tree(msg, "ChargeParameterDiscoveryRes", _sa_schedule_tree([]))
    assert msg.sa_schedule_list.values == []


def test_apply_illegal_leaf_inside_element_survives_as_model():
    # An illegal-but-encodable leaf inside a list element (PMax 99999 > int16
    # max) must survive as a poked-raw attribute on a *real* model instance —
    # not degrade the whole list to un-encodable dicts.
    from app.shared.messages.din_spec.datatypes import SAScheduleTupleEntry

    msg = _built_cpd_with_scaffold()
    apply_message_field_tree(
        msg, "ChargeParameterDiscoveryRes", _sa_schedule_tree([_tuple(pmax=99999)])
    )
    [entry] = msg.sa_schedule_list.values
    assert isinstance(entry, SAScheduleTupleEntry)
    assert entry.p_max_schedule.entry_details[0].p_max == 99999


def test_wire_sa_schedule_list_round_trips():
    # End-to-end: a tree-declared SAScheduleList reaches the wire and decodes
    # back with PMaxScheduleID 1, PMax 24000, start 0, duration omitted.
    from app.shared.settings import load_shared_settings

    load_shared_settings()

    p = SECCPersonality.model_validate(
        {"message_field_tree": _sa_schedule_tree([_tuple(pmax=24000)])}
    )
    msg = _built_cpd_with_scaffold()
    apply_message_field_tree(msg, "ChargeParameterDiscoveryRes", p.message_field_tree)

    doc = V2GMessageDINSPEC(
        header=MessageHeader(session_id="00"),
        body=Body(charge_parameter_discovery_res=msg),
    )
    exi = EXI().to_exi_document(doc, Namespace.DIN_MSG_DEF)
    back = EXI().from_exi_document(exi, Namespace.DIN_MSG_DEF)

    schedule = back.body.charge_parameter_discovery_res.sa_schedule_list
    [tuple_entry] = schedule.values
    assert tuple_entry.sa_schedule_tuple_id == 1
    assert tuple_entry.p_max_schedule.p_max_schedule_id == 1
    [details] = tuple_entry.p_max_schedule.entry_details
    assert details.p_max == 24000
    assert details.time_interval.start == 0
    assert details.time_interval.duration is None


def test_device_override_replaces_list_wholesale():
    # Layered merge: a device file that restates the SAScheduleTuple list
    # replaces the baseline's wholesale (lists do not index-merge). #81 dec. 4.
    from app.shared.personality.loader import _deep_merge

    baseline = _sa_schedule_tree([_tuple(tuple_id=1, pmax=24000), _tuple(tuple_id=2, pmax=5000)])
    device = _sa_schedule_tree([_tuple(tuple_id=1, pmax=32000)])
    merged = _deep_merge(baseline, device)

    tuples = merged["ChargeParameterDiscoveryRes"]["SAScheduleList"]["SAScheduleTuple"]
    assert len(tuples) == 1
    assert tuples[0]["PMaxSchedule"]["PMaxScheduleEntry"][0]["PMax"] == 32000

"""The [[message field tree]] — per-message, per-field emitted wire values.

Per [ADR-0006](../../../docs/adr/0006-message-field-tree-personality.md) a
personality's wire output is a tree keyed by **protocol**, then by message name,
then by nested field path, mirroring the protocol's Pydantic message models down
to each leaf (e.g. ``ISO_15118_2 -> ChargeParameterDiscoveryRes ->
DC_EVSEChargeParameter -> DC_EVSEStatus -> EVSEIsolationStatus``). The protocol
top level (ADR-0006 protocol-keyed amendment) disambiguates a message name that
exists in more than one protocol — ``SessionSetupReq``, ``PowerDeliveryReq``, and
``CableCheckReq`` are each defined by DIN, ISO 15118-2, *and* ISO 15118-20 as
*different* models, and one personality advertises several protocols, so a flat
message-name key would silently bind to whichever registry resolved first. This
module is the *machinery* behind that tree:

* :func:`validate_message_field_tree` — **path-strict, value-raw** validation.
  The top-level key must be a known protocol; every path segment beneath it must
  resolve to a real field (by Python name *or* XSD alias) on the mirrored message
  model *within that protocol's registry*; a typo is a hard error (ADR-0001
  strictness). The leaf *value* is deliberately **not** range/enum-checked —
  illegal-but-encodable values are the red-team point (ADR-0004), bounded only
  by what the codec can serialize.

* :func:`apply_message_field_tree` — **construction-time substitution**. Given a
  freshly-built message model, it pokes each overridden leaf onto the instance
  so the value flows into both the emitted bytes *and* any internal logic that
  reads the field. Valid values are coerced to the field's declared type (so a
  string ``"Invalid"`` becomes ``IsolationLevel.INVALID`` and encodes normally);
  a value the model would reject is set **raw** through the "lax build" seam
  (:func:`_lax_set`), which is why the poke bypasses Pydantic's
  ``validate_assignment``.

The tree's shape is single-sourced from the message models: protocol +
message name → model class comes from each protocol's ``get_msg_type`` (see
:data:`_PROTOCOL_REGISTRIES`), and each path segment is resolved against
``model_fields`` rather than a hand-maintained schema. DIN is the only
*tree-backed* protocol whose values actually flow to the wire today; ISO-2 and
ISO-20 are registered so a personality can tree-source them (the ISO-2 tracer),
with their full baselines landing in later slices.
"""

from __future__ import annotations

import logging
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Tuple,
    Type,
    get_args,
    get_origin,
)

from pydantic import BaseModel, TypeAdapter, ValidationError
from pydantic.fields import FieldInfo

logger = logging.getLogger(__name__)


class MessageFieldTreeError(ValueError):
    """A message field tree path could not be resolved against the models.

    Subclasses :class:`ValueError` so it surfaces through Pydantic validation
    at personality-load time exactly like every other strict-config failure.
    """


# Sentinel distinguishing "the tree does not set this leaf" from a leaf whose
# configured value happens to be ``None``.
UNSET = object()


# ---------------------------------------------------------------------------
# Protocol registries (the tree's top-level key -> message model resolver)
# ---------------------------------------------------------------------------


def _din_registry(message_name: str) -> Optional[Type[BaseModel]]:
    # Imported lazily so this module can be imported from the personality model
    # without dragging the full message package into that import path.
    from app.shared.messages.din_spec.body import get_msg_type

    return get_msg_type(message_name)


def _iso2_registry(message_name: str) -> Optional[Type[BaseModel]]:
    from app.shared.messages.iso15118_2.body import get_msg_type

    return get_msg_type(message_name)


def _iso20_registry(message_name: str) -> Optional[Type[BaseModel]]:
    from app.shared.messages.iso15118_20.registry import get_msg_type

    return get_msg_type(message_name)


# Each advertisable, tree-addressable protocol string maps to its message-name
# registry. The two ISO-20 keys share one registry because ISO-20's common
# messages ride both AC and DC sessions and its variant messages are uniquely
# named (ADR-0006 protocol-keyed amendment). This is the authoritative set of
# *known* protocol keys — a top-level tree key outside it is a hard load error.
_PROTOCOL_REGISTRIES: Dict[str, Callable[[str], Optional[Type[BaseModel]]]] = {
    "DIN_SPEC_70121": _din_registry,
    "ISO_15118_2": _iso2_registry,
    "ISO_15118_20_DC": _iso20_registry,
    "ISO_15118_20_AC": _iso20_registry,
}


def known_protocols() -> Tuple[str, ...]:
    """The protocol strings the tree may be keyed by (a top-level key set)."""
    return tuple(_PROTOCOL_REGISTRIES)


# ---------------------------------------------------------------------------
# Model-shape helpers
# ---------------------------------------------------------------------------


def _message_class(protocol: str, message_name: str) -> Optional[Type[BaseModel]]:
    """Resolve ``(protocol, message name)`` to its mirrored model class.

    The message name is resolved *within* the named protocol's registry, so a
    name defined by several protocols (``SessionSetupReq``) binds to the right
    model. Returns ``None`` when the protocol is unknown or the name is not a
    message of that protocol.
    """
    registry = _PROTOCOL_REGISTRIES.get(protocol)
    if registry is None:
        return None
    return registry(message_name)


def _resolve_field(
    model_cls: Type[BaseModel], segment: str
) -> Optional[Tuple[str, FieldInfo]]:
    """Match one path segment to a field of *model_cls* by name or alias.

    Returns ``(python_field_name, FieldInfo)`` or ``None`` if the segment names
    neither a field nor an alias. Accepting either form honours ADR-0006's
    "resolve to a real model field/alias" — authors use the XSD element names
    (``DC_EVSEStatus``), but the Python attribute names work too.
    """
    for name, field in model_cls.model_fields.items():
        if segment == name or segment == field.alias:
            return name, field
    return None


def _model_in_annotation(annotation: Any) -> Optional[Type[BaseModel]]:
    """Find the first ``BaseModel`` subclass reachable inside an annotation.

    Unwraps ``Optional[...]`` / ``List[...]`` / ``Union[...]`` so an
    intermediate segment typed ``Optional[DCEVSEChargeParameter]`` still yields
    the sub-model to descend into. Returns ``None`` for scalar/leaf fields.
    """
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return annotation
    for arg in get_args(annotation):
        found = _model_in_annotation(arg)
        if found is not None:
            return found
    return None


def _list_element_model(annotation: Any) -> Optional[Type[BaseModel]]:
    """Return the ``BaseModel`` element type of a ``List[...]`` field, else None.

    This is how a *list-nested* wire field is recognised (ADR-0006 issue #81
    amendment): a repeated child element emitted atomically inside one message,
    e.g. ``SAScheduleList -> SAScheduleTuple`` typed ``List[SAScheduleTupleEntry]``.
    Unwraps ``Optional[List[...]]`` so an optional list still resolves. Returns
    ``None`` for a scalar list (``List[AuthEnum]`` — its elements are leaves, not
    sub-models, so it is handled value-raw like any other leaf) and for a
    non-list field.
    """
    for candidate in (annotation, *get_args(annotation)):
        if get_origin(candidate) in (list, List):
            elem_args = get_args(candidate)
            if elem_args:
                return _model_in_annotation(elem_args[0])
    return None


# ---------------------------------------------------------------------------
# Validation (path-strict, value-raw)
# ---------------------------------------------------------------------------


def validate_message_field_tree(tree: Any) -> Dict[str, Any]:
    """Validate a raw message field tree; return it unchanged on success.

    Path-strict at every level: the top-level key must be a known protocol
    (:func:`known_protocols`); each message name beneath it must be a message of
    *that* protocol; and every nested key must resolve to a real field/alias on
    the mirrored model. Value-raw: leaf values are never inspected. Raises
    :class:`MessageFieldTreeError` on the first unresolvable path — an unknown
    protocol key or an unknown message-within-a-protocol included.
    """
    if tree is None:
        return {}
    if not isinstance(tree, Mapping):
        raise MessageFieldTreeError(
            f"message_field_tree must be a mapping of protocol -> message -> "
            f"fields, got {type(tree).__name__}"
        )

    for protocol, messages in tree.items():
        if str(protocol) not in _PROTOCOL_REGISTRIES:
            valid = ", ".join(repr(p) for p in known_protocols())
            raise MessageFieldTreeError(
                f"unknown protocol {protocol!r} at the top of message_field_tree; "
                f"a tree is keyed by protocol first. Use one of: {valid}."
            )
        if not isinstance(messages, Mapping):
            raise MessageFieldTreeError(
                f"message_field_tree[{protocol!r}] must be a mapping of message "
                f"name -> fields, got {type(messages).__name__}"
            )
        for message_name, fields in messages.items():
            model_cls = _message_class(str(protocol), str(message_name))
            if model_cls is None:
                raise MessageFieldTreeError(
                    f"unknown message {message_name!r} under protocol {protocol!r} "
                    f"in message_field_tree (not a {protocol} message name)"
                )
            if not isinstance(fields, Mapping):
                raise MessageFieldTreeError(
                    f"message_field_tree[{protocol!r}][{message_name!r}] must be a "
                    f"mapping of field path -> value, got {type(fields).__name__}"
                )
            _validate_node(model_cls, fields, f"{protocol} -> {message_name}")

    return dict(tree)


def _validate_node(
    model_cls: Type[BaseModel], node: Mapping[str, Any], path: str
) -> None:
    """Recursively check every key of *node* resolves against *model_cls*."""
    for key, value in node.items():
        resolved = _resolve_field(model_cls, str(key))
        if resolved is None:
            raise MessageFieldTreeError(
                f"{path} -> {key}: {key!r} is not a field or alias of "
                f"{model_cls.__name__}"
            )
        _, field = resolved
        elem_cls = _list_element_model(field.annotation)
        if elem_cls is not None:
            # List-nested wire field (ADR-0006 issue #81): a repeated child
            # element emitted atomically in one message. The value must be a
            # *list of maps*; a bare mapping given here would resolve at load
            # (unwrapped as a single element) but crash the SECC at apply time
            # (`list has no attribute model_fields`), so reject it now —
            # symmetric with the leaf-given-a-mapping error below (#84).
            if not isinstance(value, list):
                raise MessageFieldTreeError(
                    f"{path} -> {key}: {key!r} is a list-nested field but was "
                    f"given a {type(value).__name__}; provide a list of maps"
                )
            # Path-strict still applies *inside* each element (a typo in a list
            # element is a hard error), but the list's length/shape is
            # value-raw — cardinality is itself a red-team surface, so no count
            # check here.
            for index, element in enumerate(value):
                if isinstance(element, Mapping):
                    _validate_node(elem_cls, element, f"{path} -> {key}[{index}]")
                # A non-mapping element is value-raw (bounded by the codec).
        elif isinstance(value, Mapping):
            child_cls = _model_in_annotation(field.annotation)
            if child_cls is None:
                raise MessageFieldTreeError(
                    f"{path} -> {key}: {key!r} is a leaf field but was given a "
                    f"nested mapping"
                )
            _validate_node(child_cls, value, f"{path} -> {key}")
        # Leaf (including scalar lists): value-raw — no range/enum/type check.


# ---------------------------------------------------------------------------
# Leaf lookup (single-sourcing dual-purpose fields)
# ---------------------------------------------------------------------------


def resolve_tree_leaf(
    tree: Mapping[str, Any],
    protocol: str,
    message_name: str,
    python_path: Tuple[str, ...],
) -> Any:
    """Return the leaf at ``protocol -> message_name -> python_path``, or UNSET.

    ``python_path`` is the sequence of *Python* field names to walk (e.g.
    ``("charge_service", "energy_transfer_type")``); the tree itself may spell
    each segment as either the Python name or the XSD alias, so this resolves
    each segment against the model like the validator does. Returns
    :data:`UNSET` when the tree carries nothing at that path (including when the
    protocol subtree is absent).

    This is how a *dual-purpose* field (both emitted and consulted internally)
    is single-sourced from the tree per ADR-0006: the internal decision — e.g.
    the DIN ChargeParameterDiscovery ``WrongEnergyTransferType`` reject-gate —
    reads the same tree entry the message builder advertises, so advertised ==
    accepted by construction.
    """
    model_cls = _message_class(protocol, message_name)
    protocol_subtree = tree.get(protocol)
    if model_cls is None or not isinstance(protocol_subtree, Mapping):
        return UNSET
    node: Any = protocol_subtree.get(message_name)
    if not isinstance(node, Mapping):
        return UNSET

    cursor_cls: Optional[Type[BaseModel]] = model_cls
    for depth, py_name in enumerate(python_path):
        if cursor_cls is None:
            return UNSET
        field = cursor_cls.model_fields.get(py_name)
        if field is None:
            return UNSET
        if py_name in node:
            key = py_name
        elif field.alias is not None and field.alias in node:
            key = field.alias
        else:
            return UNSET
        value = node[key]
        if depth == len(python_path) - 1:
            return value
        if not isinstance(value, Mapping):
            return UNSET
        node = value
        cursor_cls = _model_in_annotation(field.annotation)
    return UNSET


# ---------------------------------------------------------------------------
# Construction-time substitution (lax build)
# ---------------------------------------------------------------------------


def apply_message_field_tree(
    model: BaseModel,
    protocol: str,
    message_name: str,
    tree: Mapping[str, Any],
    skip_fields: Optional[Iterable[str]] = None,
) -> None:
    """Substitute a message's tree overrides onto a constructed *model*.

    Applies every leaf the tree sets for *message_name* under *protocol* to the
    already-built *model* instance in place. A leaf set nowhere is left
    untouched, so an unset field keeps whatever the builder computed (the
    fallback the tracer relies on). No-op when the tree carries nothing for this
    protocol/message.

    *skip_fields* names top-level fields of the message (by Python name) to
    leave to the builder's computed value even when the tree sets them — the
    rest of the tree still applies. This is how the DIN CableCheck completing
    (FINISHED) response keeps its computed ``DC_EVSEStatus`` (Valid /
    EVSE_Ready) while every *other* CableCheckRes leaf the tree carries still
    reaches the wire (#82); the tree spells the field as either its Python name
    or its XSD alias, so each node key is resolved to its Python name before
    matching.
    """
    protocol_subtree = tree.get(protocol)
    if not isinstance(protocol_subtree, Mapping):
        return
    fields = protocol_subtree.get(message_name)
    if not fields:
        return
    if skip_fields:
        skip = set(skip_fields)
        model_cls = _message_class(protocol, message_name)
        kept: Dict[str, Any] = {}
        for key, value in fields.items():
            resolved = _resolve_field(model_cls, str(key)) if model_cls else None
            python_name = resolved[0] if resolved else str(key)
            if python_name in skip:
                continue
            kept[key] = value
        fields = kept
        if not fields:
            return
    _apply_node(model, fields, f"{protocol} -> {message_name}")


def _apply_node(instance: BaseModel, node: Mapping[str, Any], path: str) -> None:
    """Recursively poke *node*'s overrides onto the model *instance*."""
    for key, value in node.items():
        resolved = _resolve_field(type(instance), str(key))
        if resolved is None:
            # The tree was path-validated at load, so this should not happen;
            # skip defensively rather than crash a live session.
            logger.warning("message field tree: %s -> %s no longer resolves", path, key)
            continue
        field_name, field = resolved
        elem_cls = _list_element_model(field.annotation)
        if elem_cls is not None:
            # List-nested wire field (ADR-0006 issue #81): the tree declares the
            # *whole* list — its element values and its length — so the built
            # placeholder list is replaced wholesale, not index-merged. Each
            # element is constructed through the same lax-build seam as a scalar
            # leaf (:func:`_build_element`), so an illegal-but-encodable value
            # inside an element survives as a poked raw attribute on a real model
            # instance rather than degrading the whole list to un-encodable dicts.
            if not isinstance(value, list):
                # Load rejects a non-list here (#84), so this is unreachable in
                # practice; guard defensively rather than crash a live session
                # with `list has no attribute model_fields`.
                logger.warning(
                    "message field tree: %s -> %s is a list-nested field but the "
                    "tree value is a %s, not a list; override skipped",
                    path,
                    key,
                    type(value).__name__,
                )
                continue
            built = [
                _build_element(elem_cls, element, f"{path} -> {key}[{index}]")
                if isinstance(element, Mapping)
                else element
                for index, element in enumerate(value)
            ]
            object.__setattr__(instance, field_name, built)
        elif isinstance(value, Mapping):
            child = getattr(instance, field_name, None)
            if child is None:
                # The mirrored sub-message is optional and this build left it
                # unset; there is nothing to poke the override onto.
                logger.warning(
                    "message field tree: %s -> %s is absent on the built "
                    "message; override skipped",
                    path,
                    key,
                )
                continue
            _apply_node(child, value, f"{path} -> {key}")
        else:
            _lax_set(instance, field_name, field, value, f"{path} -> {key}")


def _lax_set(
    instance: BaseModel,
    field_name: str,
    field: FieldInfo,
    value: Any,
    path: str,
) -> None:
    """Set one leaf, coercing to the field's type when possible, else raw.

    The message models run with ``validate_assignment=True``, so a plain
    attribute set would re-reject an illegal-but-encodable value. This is the
    "lax build" seam: coerce a *valid* value to the declared type (so it
    encodes normally) but fall back to the raw value the model would reject,
    poked past Pydantic via ``object.__setattr__``. What survives to the wire
    is then bounded only by codec serializability (ADR-0006).
    """
    try:
        final = TypeAdapter(field.annotation).validate_python(value)
    except ValidationError:
        # Illegal-but-encodable: keep the raw value the model rejects.
        final = value
        logger.debug("message field tree: %s set raw (unvalidated) to %r", path, value)
    object.__setattr__(instance, field_name, final)


def _build_element(
    model_cls: Type[BaseModel], node: Mapping[str, Any], path: str
) -> Any:
    """Construct one list element from a tree map, coercing when possible.

    The model-level analogue of :func:`_lax_set`: a wholly-legal element is
    validated straight to a model instance (so it encodes normally, defaults
    and all); an element that a strict build would reject — because some leaf
    carries an illegal-but-encodable value — is assembled field-by-field and
    stitched together with ``model_construct`` (which bypasses validation),
    poking each rejected leaf raw exactly like the scalar seam. What survives
    to the wire is then bounded only by codec serializability (ADR-0006).
    """
    try:
        return TypeAdapter(model_cls).validate_python(node)
    except ValidationError:
        pass

    assembled: Dict[str, Any] = {}
    for key, value in node.items():
        resolved = _resolve_field(model_cls, str(key))
        if resolved is None:
            # Path-validated at load; skip defensively rather than crash.
            logger.warning("message field tree: %s -> %s no longer resolves", path, key)
            continue
        field_name, field = resolved
        if isinstance(value, Mapping):
            child_cls = _model_in_annotation(field.annotation)
            assembled[field_name] = (
                _build_element(child_cls, value, f"{path} -> {key}")
                if child_cls is not None
                else value
            )
        elif isinstance(value, list) and _list_element_model(field.annotation):
            elem_cls = _list_element_model(field.annotation)
            assembled[field_name] = [
                _build_element(elem_cls, element, f"{path} -> {key}[{index}]")
                if isinstance(element, Mapping)
                else element
                for index, element in enumerate(value)
            ]
        else:
            try:
                assembled[field_name] = TypeAdapter(field.annotation).validate_python(
                    value
                )
            except ValidationError:
                assembled[field_name] = value
                logger.debug(
                    "message field tree: %s -> %s set raw (unvalidated) to %r",
                    path,
                    key,
                    value,
                )
    return model_cls.model_construct(**assembled)

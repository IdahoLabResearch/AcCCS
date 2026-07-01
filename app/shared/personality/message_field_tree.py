"""The [[message field tree]] — per-message, per-field emitted wire values.

Per [ADR-0006](../../../docs/adr/0006-message-field-tree-personality.md) a
personality's wire output is a tree keyed by message name and then by nested
field path, mirroring the protocol's Pydantic message models down to each leaf
(e.g. ``ChargeParameterDiscoveryRes -> DC_EVSEChargeParameter -> DC_EVSEStatus
-> EVSEIsolationStatus``). This module is the *machinery* behind that tree:

* :func:`validate_message_field_tree` — **path-strict, value-raw** validation.
  Every path segment must resolve to a real field (by Python name *or* XSD
  alias) on the mirrored message model; a typo is a hard error (ADR-0001
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

The tree's shape is single-sourced from the message models: message name →
model class comes from :func:`app.shared.messages.din_spec.body.get_msg_type`
(DIN only in this slice; ISO-2 / ISO-20 land in later slices), and each path
segment is resolved against ``model_fields`` rather than a hand-maintained
schema.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Mapping, Optional, Tuple, Type, get_args

from pydantic import BaseModel, TypeAdapter, ValidationError
from pydantic.fields import FieldInfo

logger = logging.getLogger(__name__)


class MessageFieldTreeError(ValueError):
    """A message field tree path could not be resolved against the models.

    Subclasses :class:`ValueError` so it surfaces through Pydantic validation
    at personality-load time exactly like every other strict-config failure.
    """


# ---------------------------------------------------------------------------
# Model-shape helpers
# ---------------------------------------------------------------------------


def _message_class(message_name: str) -> Optional[Type[BaseModel]]:
    """Resolve a top-level message name to its mirrored model class.

    DIN only in this slice — the tree derives its message set from
    :func:`get_msg_type` so the mapping is single-sourced from the DIN body
    module rather than duplicated here.
    """
    # Imported lazily so this module can be imported from the personality model
    # without dragging the full message package into that import path.
    from app.shared.messages.din_spec.body import get_msg_type

    return get_msg_type(message_name)


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


# ---------------------------------------------------------------------------
# Validation (path-strict, value-raw)
# ---------------------------------------------------------------------------


def validate_message_field_tree(tree: Any) -> Dict[str, Any]:
    """Validate a raw message field tree; return it unchanged on success.

    Path-strict: every message name must be a known message and every nested
    key must resolve to a real field/alias on the mirrored model. Value-raw:
    leaf values are never inspected. Raises :class:`MessageFieldTreeError` on
    the first unresolvable path.
    """
    if tree is None:
        return {}
    if not isinstance(tree, Mapping):
        raise MessageFieldTreeError(
            f"message_field_tree must be a mapping of message name -> fields, "
            f"got {type(tree).__name__}"
        )

    for message_name, fields in tree.items():
        model_cls = _message_class(str(message_name))
        if model_cls is None:
            raise MessageFieldTreeError(
                f"unknown message {message_name!r} in message_field_tree "
                f"(not a DIN message name)"
            )
        if not isinstance(fields, Mapping):
            raise MessageFieldTreeError(
                f"message_field_tree[{message_name!r}] must be a mapping of "
                f"field path -> value, got {type(fields).__name__}"
            )
        _validate_node(model_cls, fields, str(message_name))

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
        if isinstance(value, Mapping):
            child_cls = _model_in_annotation(field.annotation)
            if child_cls is None:
                raise MessageFieldTreeError(
                    f"{path} -> {key}: {key!r} is a leaf field but was given a "
                    f"nested mapping"
                )
            _validate_node(child_cls, value, f"{path} -> {key}")
        # Leaf: value-raw — no range/enum/type check (ADR-0006).


# ---------------------------------------------------------------------------
# Construction-time substitution (lax build)
# ---------------------------------------------------------------------------


def apply_message_field_tree(
    model: BaseModel, message_name: str, tree: Mapping[str, Any]
) -> None:
    """Substitute a message's tree overrides onto a constructed *model*.

    Applies every leaf the tree sets for *message_name* to the already-built
    *model* instance in place. A leaf set nowhere is left untouched, so an
    unset field keeps whatever the builder computed (the fallback the tracer
    relies on). No-op when the tree carries nothing for this message.
    """
    fields = tree.get(message_name)
    if not fields:
        return
    _apply_node(model, fields, message_name)


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
        if isinstance(value, Mapping):
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

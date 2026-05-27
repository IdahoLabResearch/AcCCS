"""Pydantic <-> EVerest dict translation for EXPy.

See ADR-0002. EXPy's libcbv2g backend expects EVerest-shaped JSON
(``{"bytes": [...], "bytesLen": N}`` / ``{"characters": [...], "charactersLen": N}``;
optionals signaled by key presence) while AcCCS models messages as Pydantic V2.
This module bridges the two at the codec boundary.

Public entry points:

- :func:`pydantic_to_everest` — Pydantic model → EVerest dict ready for EXPy.
- :func:`everest_to_pydantic` — EVerest dict → Pydantic model instance.

This slice (#12) wires up DIN only. The translation module is **not** plugged
into the production ``EXI`` wrapper yet (that happens in Slice 5).
"""
from __future__ import annotations

import inspect
import typing
from dataclasses import dataclass
from enum import Enum
import types
from typing import Any, Dict, Optional, Tuple, Type, Union, get_args, get_origin


def _is_union(origin: Any) -> bool:
    return origin is Union or origin is types.UnionType

from pydantic import BaseModel

from app.shared.messages.enums import Namespace


class FieldKind(Enum):
    BYTES = "bytes"
    CHARACTERS = "characters"
    SCALAR = "scalar"
    NESTED = "nested"
    LIST = "list"


@dataclass(frozen=True)
class FieldShape:
    """Per-field EVerest shape, derived from a v2gjson type signature."""

    kind: FieldKind
    enum_cls: Optional[Type[Enum]] = None  # for SCALAR enum fields
    list_kind: Optional[FieldKind] = None  # for LIST fields, kind of each element
    list_enum_cls: Optional[Type[Enum]] = None


def _shape_from_annotation(ann: Any) -> FieldShape:
    """Translate a v2gjson parameter annotation into a :class:`FieldShape`."""
    if ann is inspect.Parameter.empty:
        return FieldShape(FieldKind.SCALAR)

    origin = get_origin(ann)
    if _is_union(origin):
        non_none = [a for a in get_args(ann) if a is not type(None)]
        if len(non_none) == 1:
            return _shape_from_annotation(non_none[0])

    if origin is list:
        (inner,) = get_args(ann) or (Any,)
        inner_shape = _shape_from_annotation(inner)
        return FieldShape(
            FieldKind.LIST,
            list_kind=inner_shape.kind,
            list_enum_cls=inner_shape.enum_cls,
        )

    if ann in (bytes, bytearray):
        return FieldShape(FieldKind.BYTES)
    if ann is str:
        return FieldShape(FieldKind.CHARACTERS)
    if isinstance(ann, type) and issubclass(ann, Enum):
        return FieldShape(FieldKind.SCALAR, enum_cls=ann)
    if ann in (int, float, bool):
        return FieldShape(FieldKind.SCALAR)
    if origin is dict or ann is dict:
        return FieldShape(FieldKind.NESTED)

    return FieldShape(FieldKind.SCALAR)


def _build_alias_shape_map(v2gjson_module) -> Dict[str, FieldShape]:
    """Union all ``*Type`` builders in *v2gjson_module* into alias → shape.

    Within a single EVerest namespace, a given field-alias is expected to have
    a single consistent shape (XSD type doesn't depend on parent for the same
    element name). Conflicts would indicate a schema-level ambiguity; we keep
    the first observed shape so the registry is stable across import order.
    """
    shape_map: Dict[str, FieldShape] = {}
    for name, obj in inspect.getmembers(v2gjson_module, inspect.isfunction):
        if not name.endswith("Type"):
            continue
        try:
            sig = inspect.signature(obj)
        except (TypeError, ValueError):
            continue
        for pname, param in sig.parameters.items():
            if pname in shape_map:
                continue
            shape_map[pname] = _shape_from_annotation(param.annotation)
    return shape_map


def _collect_v2gjson_enums(v2gjson_module) -> Dict[str, Type[Enum]]:
    out: Dict[str, Type[Enum]] = {}
    for name, obj in inspect.getmembers(v2gjson_module, inspect.isclass):
        if issubclass(obj, Enum) and obj is not Enum:
            out[name] = obj
    return out


class EnvelopeAdapter:
    """Per-namespace envelope adapter.

    Some EXPy namespaces want a different top-level shape than the Pydantic
    model produces (e.g., ISO-20 strips the ``V2GMessage`` wrapper). DIN/ISO-2
    are identity. The adapter sits between the walker and the EXPy processor;
    override :meth:`wrap` / :meth:`unwrap` for non-identity namespaces.
    """

    def wrap(self, walker: "_Walker", model: BaseModel) -> dict:
        return walker.encode_model(model)

    def unwrap(
        self,
        walker: "_Walker",
        everest: dict,
        model_cls: Type[BaseModel],
    ) -> BaseModel:
        return walker.decode_model(everest, model_cls)


class _IdentityAdapter(EnvelopeAdapter):
    """DIN / ISO-2 identity envelope: Pydantic shape already matches EVerest."""


@dataclass
class _NamespaceConfig:
    adapter: EnvelopeAdapter
    shape_map: Dict[str, FieldShape]
    enum_classes: Dict[str, Type[Enum]]


_REGISTRY: Dict[str, _NamespaceConfig] = {}


def register_namespace(
    namespace: str,
    v2gjson_module,
    adapter: Optional[EnvelopeAdapter] = None,
) -> None:
    """Register a translation namespace.

    *namespace* matches AcCCS's :class:`~app.shared.messages.enums.Namespace`
    string values so callers can route from the same identifier they pass to
    the EXI wrapper.
    """
    _REGISTRY[namespace] = _NamespaceConfig(
        adapter=adapter or _IdentityAdapter(),
        shape_map=_build_alias_shape_map(v2gjson_module),
        enum_classes=_collect_v2gjson_enums(v2gjson_module),
    )


class _Walker:
    """Shared encode/decode walker bound to a single namespace."""

    def __init__(self, config: _NamespaceConfig):
        self._config = config

    # ---- encode (Pydantic -> EVerest) ----

    def encode_model(self, model: BaseModel) -> dict:
        out: Dict[str, Any] = {}
        for field_name, field in type(model).model_fields.items():
            alias = field.alias or field_name
            value = getattr(model, field_name)
            if value is None:
                continue
            out[alias] = self._encode_value(alias, value)
        return out

    def _encode_value(self, alias: str, value: Any) -> Any:
        if isinstance(value, BaseModel):
            return self.encode_model(value)

        shape = self._config.shape_map.get(alias, FieldShape(FieldKind.SCALAR))

        if isinstance(value, list):
            items = [self._encode_list_element(shape, alias, item) for item in value]
            return {"array": items, "arrayLen": len(items)}

        if shape.kind is FieldKind.CHARACTERS and isinstance(value, Enum):
            # Pydantic str-Enum used at a position where libcbv2g expects a
            # plain string (no enum mapping). Emit the XSD string value.
            text = str(value.value)
            data = text.encode("utf-8")
            return {"characters": list(data), "charactersLen": len(data)}

        if isinstance(value, Enum):
            return self._enum_to_int(value, shape.enum_cls)

        if shape.kind is FieldKind.BYTES:
            return self._to_bytes_shape(value)
        if shape.kind is FieldKind.CHARACTERS:
            if isinstance(value, str):
                data = value.encode("utf-8")
                return {"characters": list(data), "charactersLen": len(data)}

        if isinstance(value, bool):
            return int(value)
        return value

    def _encode_list_element(self, shape: FieldShape, alias: str, item: Any) -> Any:
        if isinstance(item, BaseModel):
            return self.encode_model(item)
        if isinstance(item, Enum):
            return self._enum_to_int(item, shape.list_enum_cls)
        if shape.list_kind is FieldKind.BYTES:
            return self._to_bytes_shape(item)
        if shape.list_kind is FieldKind.CHARACTERS and isinstance(item, str):
            data = item.encode("utf-8")
            return {"characters": list(data), "charactersLen": len(data)}
        if isinstance(item, bool):
            return int(item)
        return item

    def _to_bytes_shape(self, value: Any) -> dict:
        if isinstance(value, (bytes, bytearray)):
            data = bytes(value)
        elif isinstance(value, str):
            # AcCCS stores XSD hexBinary fields as hex strings.
            data = bytes.fromhex(value)
        elif isinstance(value, list):
            data = bytes(value)
        else:
            raise TypeError(
                f"Cannot convert value of type {type(value).__name__} to EVerest bytes shape"
            )
        return {"bytes": list(data), "bytesLen": len(data)}

    def _enum_to_int(self, value: Enum, expected: Optional[Type[Enum]]) -> int:
        # Pydantic str-Enums use the XSD enumeration name as ``.value``.
        # v2gjson enums use the same names as member identifiers with int
        # values; v2gjson's codegen appends ``_`` to Python-reserved member
        # names (e.g. ``None`` → ``None_``).
        name = value.value if isinstance(value.value, str) else value.name
        candidates = (name, f"{name}_")
        for candidate in candidates:
            if expected is not None and candidate in expected.__members__:
                return expected[candidate].value
        for cls in self._config.enum_classes.values():
            for candidate in candidates:
                if candidate in cls.__members__:
                    return cls[candidate].value
        if isinstance(value.value, int):
            return value.value
        raise ValueError(
            f"No v2gjson enum member matches Pydantic enum value {value!r}"
        )

    # ---- decode (EVerest -> Pydantic) ----

    def decode_model(self, data: dict, model_cls: Type[BaseModel]) -> BaseModel:
        kwargs: Dict[str, Any] = {}
        for field_name, field in model_cls.model_fields.items():
            alias = field.alias or field_name
            if alias not in data:
                continue
            kwargs[alias] = self._decode_value(field.annotation, alias, data[alias])
        return model_cls.model_validate(kwargs)

    def _decode_value(self, annotation: Any, alias: str, value: Any) -> Any:
        py_type, list_inner = _unwrap_annotation(annotation)

        if list_inner is not None:
            items = value
            if isinstance(value, dict) and "array" in value:
                items = value["array"]
            return [self._decode_value(list_inner, alias, item) for item in items]

        if isinstance(py_type, type) and issubclass(py_type, BaseModel):
            return self.decode_model(value, py_type)

        if isinstance(py_type, type) and issubclass(py_type, Enum):
            if isinstance(value, dict) and "characters" in value:
                value = bytes(value["characters"]).decode("utf-8")
            return self._int_to_enum(value, py_type)

        if isinstance(value, dict) and "bytes" in value:
            data = bytes(value["bytes"])
            if py_type is bytes or py_type is bytearray:
                return data
            return data.hex().upper()

        if isinstance(value, dict) and "characters" in value:
            return bytes(value["characters"]).decode("utf-8")

        if py_type is bool and isinstance(value, int):
            return bool(value)

        return value

    def _int_to_enum(self, value: Any, py_enum: Type[Enum]) -> Enum:
        if isinstance(value, str):
            # Already an XSD-name string; let Pydantic validate it.
            return py_enum(value)
        # IntEnum (or any enum whose values are integers): direct lookup.
        try:
            return py_enum(value)
        except ValueError:
            pass
        # value is the libcbv2g int; resolve via the namespace's v2gjson enums.
        for cls in self._config.enum_classes.values():
            members = {m.value: m.name for m in cls}
            if value in members:
                name = members[value]
                # v2gjson appends ``_`` to reserved Python identifiers
                # (e.g. ``None_``); the Pydantic side keeps the XSD spelling.
                clean = name.rstrip("_")
                for candidate in (name, clean):
                    try:
                        return py_enum(candidate)
                    except ValueError:
                        pass
                    if candidate in py_enum.__members__:
                        return py_enum[candidate]
        raise ValueError(
            f"Cannot map EVerest enum value {value!r} to Pydantic enum {py_enum.__name__}"
        )


def _unwrap_annotation(ann: Any) -> Tuple[Any, Optional[Any]]:
    """Return ``(effective_type, inner_list_type_or_None)``.

    Strips ``Optional``/``Union[..., None]`` and ``Literal[X]``; detects
    ``List[T]`` / ``list[T]`` and returns the inner type as the second tuple
    element.
    """
    origin = get_origin(ann)

    if _is_union(origin):
        non_none = [a for a in get_args(ann) if a is not type(None)]
        if len(non_none) == 1:
            return _unwrap_annotation(non_none[0])

    if origin is typing.Literal:
        # Literal[UnitSymbol.X] -> use type of the first arg
        first = get_args(ann)[0]
        return type(first), None

    if origin in (list,) or ann is list:
        args = get_args(ann)
        inner = args[0] if args else Any
        return list, inner

    return ann, None


# ---- public API ----


def pydantic_to_everest(model: BaseModel, namespace: str) -> dict:
    """Convert a Pydantic V2G message to an EVerest dict (EXPy-ready)."""
    config = _REGISTRY[namespace]
    return config.adapter.wrap(_Walker(config), model)


def everest_to_pydantic(
    data: dict,
    model_cls: Type[BaseModel],
    namespace: str,
) -> BaseModel:
    """Reverse of :func:`pydantic_to_everest`."""
    config = _REGISTRY[namespace]
    return config.adapter.unwrap(_Walker(config), data, model_cls)


# ---- namespace registrations ----

# DIN — identity envelope (V2GMessage Pydantic model already has
# ``Header``/``Body`` keys matching EVerest's top-level shape).
from expy.v2gjson import din as _din_v2gjson  # noqa: E402

register_namespace(Namespace.DIN_MSG_DEF, _din_v2gjson)

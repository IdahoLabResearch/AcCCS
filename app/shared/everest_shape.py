"""Pydantic <-> EVerest dict translation for EXPy.

See ADR-0002. EXPy's libcbv2g backend expects EVerest-shaped JSON
(``{"bytes": [...], "bytesLen": N}`` / ``{"characters": [...], "charactersLen": N}``;
optionals signaled by key presence) while AcCCS models messages as Pydantic V2.
This module bridges the two at the codec boundary.

Public entry points:

- :func:`pydantic_to_everest` — Pydantic model → EVerest dict ready for EXPy.
- :func:`everest_to_pydantic` — EVerest dict → Pydantic model instance.

DIN landed in Slice 1 (#12). Slice 2 (#13) extends coverage to ISO 15118-2 and
adds the Fragment / XmldsigFragment helpers needed for PnC sub-element and
signature payloads. The translation module is **not** plugged into the
production ``EXI`` wrapper yet (that happens in Slice 5).
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

    # ``Annotated[T, ...]`` — used by Pydantic for length/range constraints
    # on bytes/str — has origin ``T`` but isinstance checks need ``T``
    # itself. Strip the metadata.
    if get_origin(ann) is typing.Annotated or hasattr(ann, "__metadata__"):
        args = get_args(ann)
        if args:
            return _shape_from_annotation(args[0])

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


def _build_type_shape_maps(v2gjson_module) -> Dict[str, Dict[str, FieldShape]]:
    """Per-``*Type`` builder shape maps for unambiguous per-context lookup.

    Lookups are case-insensitive on the key, since v2gjson normalises the
    leading character of XSD type names (``eMAIDType`` becomes ``EMAIDType``,
    ``DHpublickeyType`` becomes ``DiffieHellmanPublickeyType``) while the
    Pydantic ``__str__`` overrides preserve the spec spelling.
    """
    out: Dict[str, Dict[str, FieldShape]] = {}
    for name, obj in inspect.getmembers(v2gjson_module, inspect.isfunction):
        if not name.endswith("Type"):
            continue
        try:
            sig = inspect.signature(obj)
        except (TypeError, ValueError):
            continue
        key = name[:-4].lower()
        out[key] = {
            pname: _shape_from_annotation(param.annotation)
            for pname, param in sig.parameters.items()
        }
    return out


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


class _Iso20Adapter(EnvelopeAdapter):
    """ISO 15118-20 envelope: ``{"<MessageName>": <body-dict>}``.

    ISO-20 has no shared ``V2G_Message(Header, Body)`` wrapper — each
    request/response carries its own ``Header`` and libcbv2g expects the
    payload keyed by the XSD element name at the top level. The Pydantic
    side models each message as a :class:`V2GMessage` subclass whose
    ``__str__`` returns the XSD-conformant class name (``SessionSetupReq``,
    ``DC_CableCheckReq``, …), so the strip/synthesize is a single-key wrap.
    """

    def wrap(self, walker: "_Walker", model: BaseModel) -> dict:
        return {str(model): walker.encode_model(model)}

    def unwrap(
        self,
        walker: "_Walker",
        everest: dict,
        model_cls: Type[BaseModel],
    ) -> BaseModel:
        # libcbv2g always emits a single top-level key for ISO-20
        # documents. Strip the wrapper and decode the body against the
        # caller-supplied Pydantic class — the wrapper-key only confirms
        # which message type was decoded, which the caller already knows.
        if len(everest) == 1:
            (body,) = everest.values()
        else:
            body = everest
        return walker.decode_model(body, model_cls)


@dataclass
class _NamespaceConfig:
    adapter: EnvelopeAdapter
    shape_map: Dict[str, FieldShape]
    enum_classes: Dict[str, Type[Enum]]
    alias_renames: Dict[str, str]
    v2gjson_module: Any
    # ``<XSDname>Type`` builders → ``{param: FieldShape}``. Lets the walker
    # resolve shapes per parent model when the global ``shape_map`` is
    # ambiguous (e.g. ``eMAID`` is ``str`` in ``PaymentDetailsReqType`` but
    # a wrapper element in ``CertificateInstallationResType``).
    type_shape_maps: Dict[str, Dict[str, FieldShape]]
    """Encode-side renames: Pydantic alias → v2gjson alias.

    Used for the handful of XSD elements that EVerest's libcbv2g flattens
    into a single ``CONTENT`` parameter alongside attributes (notably
    ``EMAID``, ``ContractSignatureEncryptedPrivateKey``,
    ``DiffieHellmanPublickey``, ``SignatureValue``). AcCCS Pydantic models
    represent the text content as a field aliased ``value``.
    """


_REGISTRY: Dict[str, _NamespaceConfig] = {}


def register_namespace(
    namespace: str,
    v2gjson_module,
    adapter: Optional[EnvelopeAdapter] = None,
    alias_renames: Optional[Dict[str, str]] = None,
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
        alias_renames=dict(alias_renames or {}),
        v2gjson_module=v2gjson_module,
        type_shape_maps=_build_type_shape_maps(v2gjson_module),
    )


class _Walker:
    """Shared encode/decode walker bound to a single namespace."""

    def __init__(self, config: _NamespaceConfig):
        self._config = config

    # ---- encode (Pydantic -> EVerest) ----

    def encode_model(self, model: BaseModel) -> dict:
        # Prefer per-type shape lookup (unambiguous) and fall back to the
        # global alias map for models that don't have a matching v2gjson
        # ``*Type`` builder (e.g. the synthetic ``Body``/``V2GMessage``).
        # ``str(model)`` picks up XSD-element overrides used by message
        # classes (``AC_ChargeParameterDiscoveryReq`` etc.); plain data
        # classes (``RationalNumber``) inherit Pydantic's verbose default
        # ``__str__``, so try the Python class name as a second key.
        type_shape_map = self._config.type_shape_maps.get(
            str(model).lower()
        ) or self._config.type_shape_maps.get(type(model).__name__.lower())
        out: Dict[str, Any] = {}
        for field_name, field in type(model).model_fields.items():
            alias = field.alias or field_name
            value = getattr(model, field_name)
            if value is None:
                continue
            out_alias = self._config.alias_renames.get(alias, alias)
            pydantic_shape = _shape_from_annotation(field.annotation)
            if type_shape_map is not None and out_alias in type_shape_map:
                registry_shape = type_shape_map[out_alias]
            else:
                registry_shape = self._config.shape_map.get(out_alias)
            # The Pydantic annotation drives the kind: it's per-field, not
            # per-alias, so it stays unambiguous when the same alias appears
            # with different shapes in different parent types
            # (``eMAID`` is ``str`` in PaymentDetailsReq but a wrapper element
            # ``EMAIDType`` in CertificateInstallationRes; ``Certificate`` is
            # bytes in CertificateChain but a list of bytes in
            # SubCertificates). The registry contributes enum-class metadata
            # the annotation alone can't supply.
            shape = pydantic_shape
            # The Pydantic annotation gives us the *Pydantic* enum class.
            # ``_encode_value`` needs the v2gjson enum class (whose members
            # carry libcbv2g's integer values) to translate.
            if registry_shape is not None and registry_shape.enum_cls is not None:
                shape = FieldShape(
                    kind=shape.kind,
                    enum_cls=registry_shape.enum_cls,
                    list_kind=shape.list_kind,
                    list_enum_cls=shape.list_enum_cls or registry_shape.list_enum_cls,
                )
            elif registry_shape is not None and registry_shape.list_enum_cls is not None:
                shape = FieldShape(
                    kind=shape.kind,
                    enum_cls=shape.enum_cls,
                    list_kind=shape.list_kind,
                    list_enum_cls=registry_shape.list_enum_cls,
                )
            # Pydantic ``str``-Enums (e.g. ``ServiceName``) and hexBinary
            # ``str`` fields (e.g. ``SessionID``) don't reveal their wire
            # shape on the annotation alone — the registry does. Promote
            # SCALAR / CHARACTERS Pydantic shapes when the registry says
            # BYTES or CHARACTERS.
            if (
                registry_shape is not None
                and registry_shape.kind is FieldKind.NESTED
                and shape.kind is FieldKind.LIST
                and isinstance(value, list)
                and len(value) == 1
            ):
                # v2gjson treats cardinality-1 wrappers as single dicts
                # (``Transforms.Transform``). Unwrap the lone element so the
                # encoder sees the expected shape; the symmetrical decode
                # path re-lists it.
                value = value[0]
                shape = pydantic_shape.list_kind and FieldShape(
                    kind=pydantic_shape.list_kind,
                    enum_cls=pydantic_shape.list_enum_cls,
                ) or FieldShape(FieldKind.SCALAR)
            if registry_shape is not None and registry_shape.kind in (
                FieldKind.BYTES,
                FieldKind.CHARACTERS,
                FieldKind.NESTED,
            ) and shape.kind in (FieldKind.CHARACTERS, FieldKind.SCALAR):
                # NESTED on a Pydantic int means the v2gjson side expects an
                # ``exi_signed_t`` JSON object (``X509SerialNumber``); see
                # :func:`_to_signed_shape`.
                shape = FieldShape(
                    kind=registry_shape.kind,
                    enum_cls=shape.enum_cls,
                    list_kind=shape.list_kind,
                    list_enum_cls=shape.list_enum_cls,
                )
            out[out_alias] = self._encode_value(out_alias, value, shape)
        return out

    def _encode_value(
        self,
        alias: str,
        value: Any,
        shape_override: Optional[FieldShape] = None,
    ) -> Any:
        if isinstance(value, BaseModel):
            # When the surrounding parent's v2gjson signature flattens this
            # element to a simple type (e.g. ``CertificateUpdateReqType.eMAID``
            # is ``str`` while the Pydantic side wraps the value in an EMAID
            # model), extract the text content and re-encode it under the
            # parent's shape.
            if shape_override is not None and shape_override.kind in (
                FieldKind.CHARACTERS,
                FieldKind.BYTES,
            ):
                for field_name, field in type(value).model_fields.items():
                    if (field.alias or field_name) == "value":
                        return self._encode_value(
                            alias, getattr(value, field_name), shape_override
                        )
            return self.encode_model(value)

        shape = shape_override or self._config.shape_map.get(
            alias, FieldShape(FieldKind.SCALAR)
        )

        if isinstance(value, list):
            items = [self._encode_list_element(shape, alias, item) for item in value]
            # A handful of xmldsig fields (notably ``Transforms.Transform``) are
            # modelled as ``List[X]`` on the Pydantic side but appear as a
            # single ``dict`` parameter in v2gjson because cbv2g flattens the
            # cardinality-1 wrapper. Emit the lone element directly so the
            # libcbv2g JSON validator accepts it.
            if shape.kind is not FieldKind.LIST and len(items) == 1:
                return items[0]
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
            # Pydantic-typed string fields (HttpUrl, constrained str) aren't
            # ``str`` subclasses in v2 but render losslessly via ``str()``.
            if not isinstance(value, str):
                value = str(value)
            data = value.encode("utf-8")
            return {"characters": list(data), "charactersLen": len(data)}

        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int) and shape.kind is FieldKind.NESTED:
            # libcbv2g represents ``xs:integer`` (arbitrary-precision) as
            # ``exi_signed_t``, which v2gjson surfaces as a nested ``dict``
            # parameter — currently only ``X509SerialNumber``. Encode via the
            # magnitude-octets-plus-sign shape.
            return _to_signed_shape(value)
        if isinstance(value, (str, int, float)) or value is None:
            return value
        # Pydantic-specific types like ``HttpUrl`` (used in xmldsig Algorithm
        # fields) aren't JSON-serializable. They render losslessly as their
        # string form, which is what libcbv2g expects on the wire.
        return str(value)

    def _encode_list_element(self, shape: FieldShape, alias: str, item: Any) -> Any:
        if isinstance(item, BaseModel):
            return self.encode_model(item)
        if isinstance(item, Enum):
            return self._enum_to_int(item, shape.list_enum_cls)
        # ``shape`` may report a non-LIST kind (e.g. ``Certificate`` in
        # CertificateChain is bytes, but ``SubCertificates.Certificate`` is a
        # list of bytes — the alias→shape map picks one). Fall back to the
        # element-level kind when ``shape.list_kind`` is unset.
        elem_kind = shape.list_kind or shape.kind
        if elem_kind is FieldKind.BYTES:
            return self._to_bytes_shape(item)
        if elem_kind is FieldKind.CHARACTERS and isinstance(item, str):
            data = item.encode("utf-8")
            return {"characters": list(data), "charactersLen": len(data)}
        if isinstance(item, bool):
            return int(item)
        return item

    def _from_signed_shape(self, value: dict) -> int:
        data = value["data"]
        octets = data["octets"]
        magnitude = 0
        for shift, octet in enumerate(octets):
            magnitude |= octet << (8 * shift)
        return -magnitude if value.get("is_negative") else magnitude

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
            data_alias = self._config.alias_renames.get(alias, alias)
            if data_alias not in data:
                continue
            kwargs[alias] = self._decode_value(
                field.annotation, alias, data[data_alias]
            )
        return model_cls.model_validate(kwargs)

    def _decode_value(self, annotation: Any, alias: str, value: Any) -> Any:
        py_type, list_inner = _unwrap_annotation(annotation)

        if (
            isinstance(value, dict)
            and "data" in value
            and isinstance(value["data"], dict)
            and "octets" in value["data"]
        ):
            return self._from_signed_shape(value)

        if list_inner is not None:
            if isinstance(value, dict) and "array" in value:
                items = value["array"]
            elif isinstance(value, list):
                items = value
            else:
                # Pydantic expects List[X] but EVerest gave a single dict
                # (cardinality-1 flattening — e.g. ``Transforms.Transform``).
                items = [value]
            return [self._decode_value(list_inner, alias, item) for item in items]

        if isinstance(py_type, type) and issubclass(py_type, BaseModel):
            # When the v2gjson signature flattens an element to a simple
            # type but the Pydantic model wraps it (the inverse of the
            # encode-side handling for ``CertificateUpdateReq.eMAID``),
            # synthesize the missing wrapper layer so ``model_validate``
            # accepts the flattened value.
            if isinstance(value, dict) and ("bytes" in value or "characters" in value):
                value = {"value": value}
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


def _to_signed_shape(value: int) -> dict:
    """Encode an integer using libcbv2g's ``exi_signed_t`` JSON shape.

    Pydantic models hold ``xs:integer`` fields (currently just
    ``X509SerialNumber``) as plain ``int``. libcbv2g expects them as
    magnitude-octets little-endian plus a sign byte.
    """
    is_negative = 1 if value < 0 else 0
    magnitude = abs(value)
    if magnitude == 0:
        octets = [0]
    else:
        octets = []
        while magnitude:
            octets.append(magnitude & 0xFF)
            magnitude >>= 8
    return {
        "data": {"octets": octets, "octets_count": len(octets)},
        "is_negative": is_negative,
    }


def _unwrap_annotation(ann: Any) -> Tuple[Any, Optional[Any]]:
    if get_origin(ann) is typing.Annotated or hasattr(ann, "__metadata__"):
        args = get_args(ann)
        if args:
            return _unwrap_annotation(args[0])
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


def _fragment_root_name(model: BaseModel, root_name: Optional[str]) -> str:
    if root_name is not None:
        return root_name
    # Fall back to ``str(model)``, which the existing AcCCS codec already
    # relies on (see ``app/shared/exi_codec.py``): sub-element models
    # override ``__str__`` to emit the XSD-conformant element name.
    return str(model)


def pydantic_to_everest_fragment(
    model: BaseModel,
    namespace: str,
    root_name: Optional[str] = None,
) -> dict:
    """Wrap *model* as an EXPy ``encode_fragment``-ready dict.

    Fragment payloads in libcbv2g are encoded as
    ``{"<RootElementName>": <element-body-dict>}``. *root_name* overrides the
    default ``str(model)`` lookup for cases where the same Pydantic class
    surfaces under different XSD element names in different contexts (e.g.
    :class:`CertificateChain` → ``ContractSignatureCertChain`` /
    ``SAProvisioningCertificateChain``).
    """
    config = _REGISTRY[namespace]
    walker = _Walker(config)
    return {_fragment_root_name(model, root_name): walker.encode_model(model)}


def everest_to_pydantic_fragment(
    data: dict,
    model_cls: Type[BaseModel],
    namespace: str,
    root_name: Optional[str] = None,
) -> BaseModel:
    """Reverse of :func:`pydantic_to_everest_fragment`.

    If *root_name* is omitted, the single top-level key of *data* is used.
    """
    config = _REGISTRY[namespace]
    walker = _Walker(config)
    if root_name is None:
        if len(data) != 1:
            raise ValueError(
                "Fragment decode requires either an explicit root_name or "
                f"single-key data; got keys {list(data)!r}"
            )
        (root_name,) = data.keys()
    return walker.decode_model(data[root_name], model_cls)


def pydantic_to_everest_xmldsig(
    model: BaseModel,
    namespace: str,
    root_name: Optional[str] = None,
) -> dict:
    """Wrap *model* as an EXPy ``encode_xmldsig``-ready dict.

    The shape is identical to :func:`pydantic_to_everest_fragment` — a single
    top-level ``{"<RootElementName>": ...}`` pair — but the namespace's
    xmldsig processor is the consumer. Default *root_name* is ``str(model)``
    (which is ``"SignedInfo"`` for :class:`SignedInfo`).
    """
    return pydantic_to_everest_fragment(model, namespace, root_name=root_name)


def everest_to_pydantic_xmldsig(
    data: dict,
    model_cls: Type[BaseModel],
    namespace: str,
    root_name: Optional[str] = None,
) -> BaseModel:
    """Reverse of :func:`pydantic_to_everest_xmldsig`."""
    return everest_to_pydantic_fragment(data, model_cls, namespace, root_name=root_name)


# ---- namespace registrations ----

# DIN — identity envelope (V2GMessage Pydantic model already has
# ``Header``/``Body`` keys matching EVerest's top-level shape).
from expy.v2gjson import din as _din_v2gjson  # noqa: E402

register_namespace(Namespace.DIN_MSG_DEF, _din_v2gjson)

# ISO 15118-2 — identity envelope, same shape contract as DIN. Fragment and
# XmldsigFragment payloads (PnC sub-elements, cert install pieces, SignedInfo)
# go through the dedicated helpers above.
from expy.v2gjson import iso2 as _iso2_v2gjson  # noqa: E402

register_namespace(
    Namespace.ISO_V2_MSG_DEF,
    _iso2_v2gjson,
    alias_renames={
        # libcbv2g flattens simple-typed elements with XML attributes (notably
        # ``eMAID``, ``ContractSignatureEncryptedPrivateKey``,
        # ``DiffieHellmanPublickey``, ``SignatureValue``) into ``CONTENT`` +
        # attributes. Every Pydantic field aliased ``value`` in ISO-2 / xmldsig
        # corresponds to one of these four — see
        # ``app/shared/messages/iso15118_2/datatypes.py`` and ``xmldsig.py``.
        "value": "CONTENT",
    },
)

# ISO 15118-20 — single envelope shape `{"<MessageName>": ...}` for every
# sub-namespace; the body itself carries the per-message ``Header``. Fragment
# and XmldsigFragment helpers reuse the namespace's shape map for signed-
# element payloads (PnC_AReqAuthorizationMode, SignedInfo, …).
from expy.v2gjson import (  # noqa: E402
    iso20_acdp as _iso20_acdp_v2gjson,
    iso20_ac as _iso20_ac_v2gjson,
    iso20_common as _iso20_common_v2gjson,
    iso20_dc as _iso20_dc_v2gjson,
    iso20_wpt as _iso20_wpt_v2gjson,
)

for _ns, _mod in (
    (Namespace.ISO_V20_COMMON_MSG, _iso20_common_v2gjson),
    (Namespace.ISO_V20_AC, _iso20_ac_v2gjson),
    (Namespace.ISO_V20_DC, _iso20_dc_v2gjson),
    (Namespace.ISO_V20_WPT, _iso20_wpt_v2gjson),
    (Namespace.ISO_V20_ACDP, _iso20_acdp_v2gjson),
):
    register_namespace(_ns, _mod, adapter=_Iso20Adapter())

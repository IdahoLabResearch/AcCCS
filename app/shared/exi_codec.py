"""EXI codec wrapper.

Three method pairs cover libcbv2g/EXPy's three roots:

* :meth:`EXI.to_exi_document` / :meth:`EXI.from_exi_document` — full
  V2G messages (DIN, ISO 15118-2, ISO 15118-20) and the SAP
  ``supportedAppProtocolReq``/``Res`` exchange.
* :meth:`EXI.to_exi_fragment` / :meth:`EXI.from_exi_fragment` — signed
  sub-elements (``AuthorizationReq``, ``CertificateInstallationReq``,
  ``SalesTariff``, ISO-2 cert-install components, ISO-20
  ``PnC_AReqAuthorizationMode``).
* :meth:`EXI.to_exi_xmldsig` / :meth:`EXI.from_exi_xmldsig` — the
  ``SignedInfo`` xmldsig fragment that backs every signature
  computation (see :mod:`app.shared.security`).

Pydantic models cross the boundary through
:mod:`app.shared.everest_shape`; bytes cross the boundary through
:class:`~app.shared.expy_exi_codec.EXPyEXICodec`.
"""

from __future__ import annotations

import logging
from typing import Optional, Type, Union

from pydantic import ValidationError

from app.shared.everest_shape import (
    EnvelopeAdapter,
    _NamespaceConfig,
    _REGISTRY,
    _Walker,
    everest_to_pydantic,
    everest_to_pydantic_fragment,
    everest_to_pydantic_xmldsig,
    pydantic_to_everest,
    pydantic_to_everest_fragment,
    pydantic_to_everest_xmldsig,
)
from app.shared.exceptions import (
    EXIDecodingError,
    EXIEncodingError,
    V2GMessageValidationError,
)
from app.shared.exi_capture import record as _exi_capture_record
from app.shared.expy_exi_codec import EXPyEXICodec
from app.shared.messages import BaseModel
from app.shared.messages.app_protocol import (
    SupportedAppProtocolReq,
    SupportedAppProtocolRes,
)
from app.shared.messages.din_spec.body import get_msg_type as get_msg_type_dinspec
from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from app.shared.messages.enums import Namespace
from app.shared.messages.iso15118_2.body import get_msg_type
from app.shared.messages.iso15118_2.datatypes import ResponseCode
from app.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from app.shared.messages.iso15118_20.ac import (
    ACChargeLoopReq,
    ACChargeLoopRes,
    ACChargeParameterDiscoveryReq,
    ACChargeParameterDiscoveryRes,
)
from app.shared.messages.iso15118_20.common_messages import (
    AuthorizationReq as AuthorizationReqV20,
)
from app.shared.messages.iso15118_20.common_messages import (
    AuthorizationRes,
    AuthorizationSetupReq,
    AuthorizationSetupRes,
    CertificateInstallationReq,
    CertificateInstallationRes,
    PowerDeliveryReq,
    PowerDeliveryRes,
    ScheduleExchangeReq,
    ScheduleExchangeRes,
    ServiceDetailReq,
    ServiceDetailRes,
    ServiceDiscoveryReq,
    ServiceDiscoveryRes,
    ServiceSelectionReq,
    ServiceSelectionRes,
    SessionSetupReq,
    SessionSetupRes,
    SessionStopReq,
    SessionStopRes,
)
from app.shared.messages.iso15118_20.common_types import V2GMessage as V2GMessageV20
from app.shared.messages.iso15118_20.dc import (
    DCCableCheckReq,
    DCCableCheckRes,
    DCChargeLoopReq,
    DCChargeLoopRes,
    DCChargeParameterDiscoveryReq,
    DCChargeParameterDiscoveryRes,
    DCPreChargeReq,
    DCPreChargeRes,
    DCWeldingDetectionReq,
    DCWeldingDetectionRes,
)
from app.shared.settings import SettingKey, shared_settings

logger = logging.getLogger(__name__)


# ISO 15118-20 top-level message name → Pydantic class. Used both to
# dispatch decode-side classification and to expose the legacy
# auto-routing of :meth:`from_exi_document` when the caller does not
# pass an explicit ``model_cls``.
_ISO20_MSG_CLASSES: dict[str, Type[V2GMessageV20]] = {
    "SessionSetupReq": SessionSetupReq,
    "SessionSetupRes": SessionSetupRes,
    "AuthorizationSetupReq": AuthorizationSetupReq,
    "AuthorizationSetupRes": AuthorizationSetupRes,
    "CertificateInstallationReq": CertificateInstallationReq,
    "CertificateInstallationRes": CertificateInstallationRes,
    "AuthorizationReq": AuthorizationReqV20,
    "AuthorizationRes": AuthorizationRes,
    "ServiceDiscoveryReq": ServiceDiscoveryReq,
    "ServiceDiscoveryRes": ServiceDiscoveryRes,
    "ServiceDetailReq": ServiceDetailReq,
    "ServiceDetailRes": ServiceDetailRes,
    "ServiceSelectionReq": ServiceSelectionReq,
    "ServiceSelectionRes": ServiceSelectionRes,
    "AC_ChargeParameterDiscoveryReq": ACChargeParameterDiscoveryReq,
    "AC_ChargeParameterDiscoveryRes": ACChargeParameterDiscoveryRes,
    "DC_ChargeParameterDiscoveryReq": DCChargeParameterDiscoveryReq,
    "DC_ChargeParameterDiscoveryRes": DCChargeParameterDiscoveryRes,
    "ScheduleExchangeReq": ScheduleExchangeReq,
    "ScheduleExchangeRes": ScheduleExchangeRes,
    "DC_CableCheckReq": DCCableCheckReq,
    "DC_CableCheckRes": DCCableCheckRes,
    "DC_PreChargeReq": DCPreChargeReq,
    "DC_PreChargeRes": DCPreChargeRes,
    "PowerDeliveryReq": PowerDeliveryReq,
    "PowerDeliveryRes": PowerDeliveryRes,
    "AC_ChargeLoopReq": ACChargeLoopReq,
    "AC_ChargeLoopRes": ACChargeLoopRes,
    "DC_ChargeLoopReq": DCChargeLoopReq,
    "DC_ChargeLoopRes": DCChargeLoopRes,
    "DC_WeldingDetectionReq": DCWeldingDetectionReq,
    "DC_WeldingDetectionRes": DCWeldingDetectionRes,
    "SessionStopReq": SessionStopReq,
    "SessionStopRes": SessionStopRes,
}


# AcCCS-side xmldsig calls pass ``Namespace.XML_DSIG`` (a virtual identifier;
# libcbv2g exposes xmldsig per protocol namespace). For translation lookup we
# route through ISO 15118-2's shape registry, since SignedInfo is shape-
# identical and ISO-2 is the historical anchor — matching the codec-side
# routing in :mod:`app.shared.expy_exi_codec`.
_XMLDSIG_TRANSLATION_NS = Namespace.ISO_V2_MSG_DEF


def _capture(direction: str, namespace: str, model, payload: bytes) -> None:
    try:
        _exi_capture_record(
            direction=direction,
            namespace=namespace,
            model=model,
            payload=payload,
        )
    except Exception:  # capture must never break the session
        logger.exception("EXI capture (%s) failed", direction)


def _wrap_encode_error(exc: Exception, model: BaseModel, namespace: str) -> EXIEncodingError:
    err = EXIEncodingError(
        f"EXIEncodingError for {str(model)} (ns={namespace}): {exc}"
    )
    # Preserve EXPy's structured attributes (``rc``, ``namespace``, ``root``)
    # when available so callers can log the libcbv2g return code.
    for attr in ("rc", "namespace", "root"):
        if hasattr(exc, attr):
            setattr(err, attr, getattr(exc, attr))
    return err


def _wrap_decode_error(exc: Exception, namespace: str) -> EXIDecodingError:
    err = EXIDecodingError(
        f"EXIDecodingError ({exc.__class__.__name__}) ns={namespace}: {exc}"
    )
    for attr in ("rc", "namespace", "root"):
        if hasattr(exc, attr):
            setattr(err, attr, getattr(exc, attr))
    return err


class EXI:
    """Process-wide EXI wrapper (singleton)."""

    _instance: Optional["EXI"] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(EXI, cls).__new__(cls)
            cls._instance._codec = None
        return cls._instance

    def set_exi_codec(self, codec: EXPyEXICodec) -> None:
        logger.info(f"EXI Codec version: {codec.get_version()}")
        self._codec = codec

    def get_exi_codec(self) -> EXPyEXICodec:
        if self._codec is None:
            self._codec = EXPyEXICodec()
        return self._codec

    # ---- document --------------------------------------------------------

    def to_exi_document(self, model: BaseModel, namespace: str) -> bytes:
        if shared_settings[SettingKey.MESSAGE_LOG_JSON]:
            logger.debug(
                f"Message to encode (ns={namespace}, document): {str(model)}"
            )
        try:
            everest = pydantic_to_everest(model, namespace)
            exi_bytes = self.get_exi_codec().encode_document(everest, namespace)
        except Exception as exc:
            logger.error(f"EXIEncodingError (document) ns={namespace}: {exc}")
            raise _wrap_encode_error(exc, model, namespace) from exc
        if shared_settings[SettingKey.MESSAGE_LOG_EXI]:
            logger.debug(f"EXI-encoded document (ns={namespace}): {exi_bytes.hex()}")
        _capture(direction="encode", namespace=namespace, model=model, payload=exi_bytes)
        return exi_bytes

    def from_exi_document(
        self,
        exi_message: bytes,
        namespace: str,
        model_cls: Optional[Type[BaseModel]] = None,
    ) -> Union[
        SupportedAppProtocolReq,
        SupportedAppProtocolRes,
        V2GMessageV2,
        V2GMessageV20,
        V2GMessageDINSPEC,
    ]:
        if shared_settings[SettingKey.MESSAGE_LOG_EXI]:
            logger.debug(
                f"EXI-encoded document (ns={namespace}): {exi_message.hex()}"
            )

        try:
            decoded = self.get_exi_codec().decode_document(exi_message, namespace)
        except Exception as exc:
            raise _wrap_decode_error(exc, namespace) from exc

        if shared_settings[SettingKey.MESSAGE_LOG_JSON]:
            logger.debug(f"Decoded document (ns={namespace}): {decoded}")

        # Resolve target Pydantic class when the caller didn't supply one.
        resolved_cls = model_cls
        envelope_key: Optional[str] = None
        if resolved_cls is None:
            if namespace == Namespace.SAP:
                envelope_key = next(iter(decoded))
                if envelope_key == "supportedAppProtocolReq":
                    resolved_cls = SupportedAppProtocolReq
                elif envelope_key == "supportedAppProtocolRes":
                    resolved_cls = SupportedAppProtocolRes
                else:
                    raise EXIDecodingError(
                        f"Unknown SAP envelope key {envelope_key!r}"
                    )
            elif namespace == Namespace.DIN_MSG_DEF:
                resolved_cls = V2GMessageDINSPEC
            elif namespace == Namespace.ISO_V2_MSG_DEF:
                resolved_cls = V2GMessageV2
            elif namespace.startswith(Namespace.ISO_V20_BASE):
                envelope_key = next(iter(decoded))
                resolved_cls = _ISO20_MSG_CLASSES.get(envelope_key)
                if resolved_cls is None:
                    raise EXIDecodingError(
                        f"Unknown ISO-20 message name {envelope_key!r}"
                    )
            else:
                raise EXIDecodingError(
                    f"Cannot dispatch document decode for namespace {namespace!r}"
                )

        # Record the capture against the decoded model name. For ISO-20 / SAP
        # the envelope key is the natural model name; for DIN / ISO-2 the
        # legacy capture format keys decode records by ``"V2G_Message"``.
        capture_model = envelope_key
        if capture_model is None:
            capture_model = "V2G_Message" if namespace in (
                Namespace.DIN_MSG_DEF,
                Namespace.ISO_V2_MSG_DEF,
            ) else str(resolved_cls.__name__)
        _capture(
            direction="decode",
            namespace=namespace,
            model=capture_model,
            payload=exi_message,
        )

        try:
            return everest_to_pydantic(decoded, resolved_cls, namespace)
        except ValidationError as exc:
            raise self._validation_error(exc, decoded, namespace, resolved_cls) from exc

    # ---- fragment --------------------------------------------------------

    def to_exi_fragment(
        self,
        model: BaseModel,
        namespace: str,
        root_name: Optional[str] = None,
    ) -> bytes:
        translation_ns = (
            _XMLDSIG_TRANSLATION_NS if namespace == Namespace.XML_DSIG else namespace
        )
        try:
            everest = pydantic_to_everest_fragment(
                model, translation_ns, root_name=root_name
            )
            exi_bytes = self.get_exi_codec().encode_fragment(everest, namespace)
        except Exception as exc:
            logger.error(f"EXIEncodingError (fragment) ns={namespace}: {exc}")
            raise _wrap_encode_error(exc, model, namespace) from exc
        if shared_settings[SettingKey.MESSAGE_LOG_EXI]:
            logger.debug(f"EXI-encoded fragment (ns={namespace}): {exi_bytes.hex()}")
        _capture(direction="encode", namespace=namespace, model=model, payload=exi_bytes)
        return exi_bytes

    def from_exi_fragment(
        self,
        exi_message: bytes,
        model_cls: Type[BaseModel],
        namespace: str,
        root_name: Optional[str] = None,
    ) -> BaseModel:
        translation_ns = (
            _XMLDSIG_TRANSLATION_NS if namespace == Namespace.XML_DSIG else namespace
        )
        try:
            decoded = self.get_exi_codec().decode_fragment(exi_message, namespace)
        except Exception as exc:
            raise _wrap_decode_error(exc, namespace) from exc
        _capture(
            direction="decode",
            namespace=namespace,
            model=root_name or model_cls.__name__,
            payload=exi_message,
        )
        try:
            return everest_to_pydantic_fragment(
                decoded, model_cls, translation_ns, root_name=root_name
            )
        except ValidationError as exc:
            raise self._validation_error(exc, decoded, namespace, model_cls) from exc

    # ---- xmldsig ---------------------------------------------------------

    def to_exi_xmldsig(
        self,
        model: BaseModel,
        namespace: str,
        root_name: Optional[str] = None,
    ) -> bytes:
        translation_ns = (
            _XMLDSIG_TRANSLATION_NS if namespace == Namespace.XML_DSIG else namespace
        )
        try:
            everest = pydantic_to_everest_xmldsig(
                model, translation_ns, root_name=root_name
            )
            exi_bytes = self.get_exi_codec().encode_xmldsig(everest, namespace)
        except Exception as exc:
            logger.error(f"EXIEncodingError (xmldsig) ns={namespace}: {exc}")
            raise _wrap_encode_error(exc, model, namespace) from exc
        if shared_settings[SettingKey.MESSAGE_LOG_EXI]:
            logger.debug(f"EXI-encoded xmldsig (ns={namespace}): {exi_bytes.hex()}")
        _capture(direction="encode", namespace=namespace, model=model, payload=exi_bytes)
        return exi_bytes

    def from_exi_xmldsig(
        self,
        exi_message: bytes,
        model_cls: Type[BaseModel],
        namespace: str,
        root_name: Optional[str] = None,
    ) -> BaseModel:
        translation_ns = (
            _XMLDSIG_TRANSLATION_NS if namespace == Namespace.XML_DSIG else namespace
        )
        try:
            decoded = self.get_exi_codec().decode_xmldsig(exi_message, namespace)
        except Exception as exc:
            raise _wrap_decode_error(exc, namespace) from exc
        _capture(
            direction="decode",
            namespace=namespace,
            model=root_name or model_cls.__name__,
            payload=exi_message,
        )
        try:
            return everest_to_pydantic_xmldsig(
                decoded, model_cls, translation_ns, root_name=root_name
            )
        except ValidationError as exc:
            raise self._validation_error(exc, decoded, namespace, model_cls) from exc

    # ---- internal --------------------------------------------------------

    def _validation_error(
        self,
        exc: ValidationError,
        decoded: dict,
        namespace: str,
        model_cls: Type[BaseModel],
    ) -> V2GMessageValidationError:
        msg_type: Optional[Type] = None
        if namespace == Namespace.ISO_V2_MSG_DEF and "Body" in decoded:
            msg_name = next(iter(decoded["Body"]))
            msg_type = get_msg_type(msg_name)
        elif namespace == Namespace.DIN_MSG_DEF and "Body" in decoded:
            msg_name = next(iter(decoded["Body"]))
            msg_type = get_msg_type_dinspec(msg_name)
        elif namespace.startswith(Namespace.ISO_V20_BASE):
            msg_type = model_cls
        elif namespace == Namespace.SAP:
            msg_type = model_cls
        return V2GMessageValidationError(
            f"Validation error: {exc}. \n\nDecoded dict: {decoded}",
            ResponseCode.FAILED,
            msg_type,
        )

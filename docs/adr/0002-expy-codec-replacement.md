# Replace Exificient with EXPy for EXI encoding/decoding

The current EXI codec (`app/shared/exificient_exi_codec.py`) launches a Java subprocess via `py4j.JavaGateway` and calls into `EXICodec.jar` (Siemens Exificient). We are replacing it outright with [EXPy](https://github.com/IdahoLabResearch/EXPy), a Python binding over LF Energy EVerest's `libcbv2g` (C/C++). Motivation: drop the JVM dependency and consolidate on tooling we own and can extend.

This is a **separate, sequential upgrade** that begins only after the [[personality]] YAML config overhaul is fully merged. It is *not* interleaved with that work, because each upgrade individually touches a large surface and we want one merge-conflict story at a time.

## Considered Options

- Hybrid codec, selectable per protocol (keep Exificient for any protocol EXPy didn't yet cover). Rejected: with EXPy v1.0 covering DIN, ISO 15118-2, and all ISO 15118-20 sub-namespaces, there is no transitional gap to bridge.
- Phased migration with both codecs running side-by-side and round-trip-compared on every message. Rejected as overkill for a project of this size; validation is done with fixture-based and captured-session tests at the codec boundary instead.
- Switch AcCCS's in-memory V2G types to EXPy's `expy.v2gjson` typed builders. Rejected: the existing Pydantic models work, carry AcCCS-specific validation, and `v2gjson` carries libcbv2g identifier conventions (`SessionSetupReqType`, `EVSE_NotReady`, `costKindType`) that would leak throughout AcCCS state machines. Pydantic stays as the single in-memory representation; translation happens at the codec boundary.

## EXPy v1.0 capabilities (as of integration)

- Installed via `pip install git+https://github.com/IdahoLabResearch/EXPy@v1.0`. No git submodule.
- Eight `Namespace` selectors covering AcCCS's full namespace surface: `SAP`, `DIN`, `ISO2`, `ISO20_COMMON`, `ISO20_AC`, `ISO20_DC`, `ISO20_WPT`, `ISO20_ACDP`.
- Three root types per Processor, feature-gated: Document (`encode`/`decode`, all eight Namespaces), Fragment (`encode_fragment`/`decode_fragment`, six Namespaces excluding `SAP` and `DIN`), XmldsigFragment (`encode_xmldsig`/`decode_xmldsig`, same six). Direct attribute access raises `AttributeError` on Namespaces lacking a given root.
- EVerest JSON shape on the wire to/from EXPy: bytes fields as `{"bytes": [...], "bytesLen": N}`, character fields as `{"characters": [...], "charactersLen": N}`, optionals signaled by JSON key presence/absence (no `isUsed` marker).
- Top-level envelope shape varies per Namespace: DIN/ISO-2 wrap in `V2G_Message(Header, Body)`; ISO-20 top-level is `{"Body": {"<MessageName>": ...}}` with no `V2G_Message`; `SAP` has its own shape.
- Errors raised as `EncodeError` / `DecodeError` with structured attributes `rc: int`, `namespace: str`, `root: Literal["exiDocument", "exiFragment", "xmldsigFragment"]`.

## Consequences

- The shape mismatch between AcCCS Pydantic models and EXPy's EVerest dict is bridged in a new dedicated module (working name: `app/shared/everest_shape.py`) at the codec boundary. **Not** by rewriting Pydantic model encoders — keeps Pydantic's native JSON shape clean and isolates EVerest's representation choices to one file.
- Translation module shape: a schema-aware Pydantic walker that consults each model's field metadata (`__fields__`) to apply:
  - Bytes fields → `{"bytes": [...], "bytesLen": N}`.
  - String fields → `{"characters": [...], "charactersLen": N}` where the schema demands it.
  - Optionals: omit key when value is `None` (matches EXPy's key-presence semantics natively — no marker injection needed).
  - Per-namespace envelope adapter: identity for DIN/ISO-2 (their Pydantic shape already matches `V2G_Message(Header, Body)`); strip/synthesize `V2GMessage` for ISO-20 since EXPy expects no envelope; namespace-specific shape for SAP.
- The JSON-string round-trip step disappears: today is `pydantic.json() → string → java → bytes`; new flow is `pydantic.dict() → translate-shape → EXPy → bytes`.
- The `EXI` wrapper in `app/shared/exi_codec.py` exposes three distinct method pairs — `to_exi_document` / `from_exi_document`, `to_exi_fragment` / `from_exi_fragment`, `to_exi_xmldsig` / `from_exi_xmldsig` — instead of the current overloaded `to_exi` / `from_exi`. Every existing call site is audited and migrated to the correct variant. Sub-element encodes (e.g. `auth_req.pnc_params`, `cert_install_res.emaid`, `dh_public_key`) become fragment or xmldsig calls; full-message encodes become document calls.
- AcCCS Pydantic models for ISO-20 retain their `V2GMessage` wrapper. The translation module strips it on encode and synthesizes it on decode for ISO-20 namespaces only. This asymmetry is concentrated in the per-namespace envelope adapter.
- EXPy's `EncodeError` / `DecodeError` are mapped to AcCCS's existing `EXIEncodingError` / `EXIDecodingError` / `V2GMessageValidationError` at the codec boundary, preserving structured `rc` / `namespace` / `root` attributes.
- Deployment targets (including Raspberry Pi in the AcCCS box) gain a C/C++ build toolchain requirement (CMake ≥3.20, Ninja ≥1.10) at install time and lose the JVM runtime requirement.
- The XSD schemas under `app/shared/schemas/`, `app/shared/EXICodec.jar`, and the `IEXICodec` ABC are removed in the swap slice. The `EXI` wrapper in `app/shared/exi_codec.py` becomes the test seam.
- Codec-layer test fixtures (generated in Slices 1–3 against the current Exificient codec) are **rebaselined to EXPy at Slice 5**. The Slice 5 PR includes a side-by-side byte-diff of Exificient-output vs EXPy-output across the full fixture corpus; any divergence is explicitly justified in the PR description (either a known EXPy improvement or an unexpected discrepancy requiring investigation). After Slice 5 merges, the Exificient hash snapshot is deleted and the codec-layer regression baseline becomes EXPy's output. The external truth anchor for the codec then shifts to the hardware-tagged captures in the replay corpus (see ADR-0003).

## Implementation plan (revised after EXPy v1.0)

- **Slice 0** — Add `git+https://github.com/IdahoLabResearch/EXPy@v1.0` to `requirements.txt`. Verify install on dev machine and Raspberry Pi (CMake/Ninja prerequisites documented in README). Smoke-test that `from expy import EXIProcessor, Namespace` works and a DIN hello-world document round-trips. No AcCCS code changes beyond `requirements.txt`.
- **Slice 1** — Build the schema-aware Pydantic↔EVerest translation module. Implement bytes-shape, characters-shape, key-presence optionality, and the per-namespace envelope adapter. Unit-test with fixture-pair tests for DIN messages, generated by capturing inputs/outputs from the current Exificient codec on a representative corpus.
- **Slice 2** — Extend translation + fixtures to ISO 15118-2, including fragment and xmldsig payloads (PnC signatures, cert install).
- **Slice 3** — Extend translation + fixtures to ISO 15118-20 (all five sub-namespaces, all energy services), including the `V2GMessage` envelope strip/synthesize and ISO-20 fragment/xmldsig payloads.
- **Slice 4** — Captured-session replay tests for all three protocols. Production code still uses Exificient; tests verify EXPy would produce protocol-equivalent results.
- **Slice 5** — The swap. Add `EXPyEXICodec` and rewrite the `EXI` wrapper in `app/shared/exi_codec.py` to expose the six new methods. Wire the translation module in. Update every call site that uses `to_exi`/`from_exi` to call the appropriate document/fragment/xmldsig variant. Delete `ExificientEXICodec`, `EXICodec.jar`, `app/shared/schemas/`, py4j dependency, the `IEXICodec` ABC, and Java install docs. Map EXPy errors to AcCCS's existing exception types. Gated on all prior slices green.
- **Slice 6** — Cleanup: prune dead imports, update `README.md`, document the EXPy install prerequisite (CMake + Ninja) for new contributors.

Translation module remains unwired from production until Slice 5 — no `use_expy` runtime flag, no parallel production paths. The replay tests in Slice 4 are the integration signal; Slice 5 is the single risky merge.

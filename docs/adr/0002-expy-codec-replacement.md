# Replace Exificient with EXPy for EXI encoding/decoding

The current EXI codec (`app/shared/exificient_exi_codec.py`) launches a Java subprocess via `py4j.JavaGateway` and calls into `EXICodec.jar` (Siemens Exificient). We are replacing it outright with [EXPy](https://github.com/IdahoLabResearch/EXPy), a Python binding over LF Energy EVerest's `libcbv2g` (C/C++). Motivation: drop the JVM dependency and consolidate on tooling we own and can extend; the project owner is contributing the remaining EXPy gaps (DIN test suite, ISO 15118-20 support) in parallel.

This is a **separate, sequential upgrade** that begins only after the [[personality]] YAML config overhaul is fully merged. It is *not* interleaved with that work, because each upgrade individually touches a large surface and we want one merge-conflict story at a time.

## Considered Options

- Hybrid codec, selectable per protocol (keep Exificient for ISO 15118-20 until EXPy supports it; EXPy for DIN + ISO-15118-2 immediately). Rejected: project owner is driving EXPy's -20 implementation; carrying the JVM dependency indefinitely for a transitional case isn't worth the maintenance.
- Phased migration with both codecs running side-by-side and round-trip-compared on every message. Rejected as overkill for a project of this size; validation will be done with a smaller fixture-based test suite at the codec boundary instead.

## Consequences

- AcCCS migration is **gated on EXPy feature parity** for each protocol AcCCS supports (DIN 70121, ISO 15118-2, ISO 15118-20). Until EXPy's ISO 15118-20 lands, AcCCS cannot complete this upgrade.
- The JSON shape produced/consumed by EXPy follows EVerest conventions (`{"bytes": [...], "bytesLen": N}` for byte fields, `"isUsed": true` on optional sub-elements). This differs from the current Pydantic + base64 representation. The shape mismatch is bridged in a new dedicated module (`app/shared/everest_shape.py` or similar) at the codec boundary, **not** by rewriting the Pydantic model encoders — keeps Pydantic's native JSON shape clean and isolates EVerest's representation choices to one file.
- The JSON-string round-trip step disappears: today is `pydantic.json() → string → java → bytes`; new flow is `pydantic.dict() → translate-shape → EXPy → bytes`.
- Deployment targets (including Raspberry Pi in the AcCCS box) gain a C/C++ build toolchain requirement (CMake + Ninja) and lose the JVM requirement.
- The XSD schemas under `app/shared/schemas/` and `app/shared/EXICodec.jar` become unused and are removed in the cleanup slice. The `IEXICodec` abstraction is reviewed for removal at the same time — with only one implementation, it may no longer be earning its keep.
- DIN testing is flagged "not working" in EXPy's README at the time of this decision; the project owner is fixing this and will validate AcCCS's DIN path manually before flipping the codec.

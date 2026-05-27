# Replay layer

Offline runner for the captured-session corpus under
[`../captures/`](../captures/). Per ADR-0003 §"Replay layer" and ADR-0002
Slice 4 (#15), the harness asserts protocol equivalence between the current
Exificient codec and the EXPy + translation module pipeline that will replace
it.

## Equivalence oracle

For every record in the corpus, deduplicated by `(namespace, root, bytes)`:

1. **Bytes-equal.** EXPy re-encode bytes == captured bytes → PASS.
2. **Decode-equivalent through Exificient** *(document records only).*
   Decode both byte strings through the current Exificient codec; compare
   the resulting Pydantic objects. PASS if equal.
3. **EXPy decode-self-consistency fallback.** When Exificient cannot
   decode (DecodeError, schema mismatch), decode both via EXPy and
   compare. This proves EXPy is self-consistent for that byte sequence,
   not that EXPy matches Exificient — the codec layer's
   `expy_authoritative` set is the analogous treatment at the fixture
   level.

The oracle matches the Slice 4 grilling decision recorded on issue #15:
"EXPy-as-cross-decoder fallback (option a)".

## Running

The replay tests run as part of the codec layer in the conformance suite:

```
pytest tests/conformance/replay/
```

The corpus is loaded from JSONL files in `../captures/<source>/<name>.jsonl`,
each accompanied by `<name>.yaml` provenance.

## (Re)building the corpus

To regenerate the veth half of the corpus end-to-end:

```
python scripts/capture_replay_corpus.py
```

The script drives each in-scope personality combo against the
`acccs_secc`/`acccs_evcc` veth pair with the EXI capture tap
(`app/shared/exi_capture.py`) enabled, then writes JSONL + provenance
metadata under `../captures/veth/`. Run `setup_veth.sh` once per boot
beforehand.

The hardware half of the corpus is **deferred** to a follow-up issue;
the script does not produce it. See [`../captures/README.md`](../captures/README.md)
for the coverage matrix and gaps.

## Skipped records

The harness emits explicit skip messages (one per record) rather than
silently passing when the new pipeline cannot reach the bytes:

- **Namespace not registered in translation module.** Today: `SAP`
  (`urn:iso:15118:2:2010:AppProtocol`). Slice 1–3 didn't register SAP;
  Slice 5 picks it up alongside the rebaseline.
- **EXPy encode rejects the EVerest dict.** Surfaces translation-shape
  divergences for messages carrying signed sub-elements
  (`ChargeParameterDiscoveryRes` with `SalesTariff`+`Signature`,
  `PaymentDetailsReq`, `ScheduleExchangeRes`, etc.) and several ISO-20
  paths. Each becomes a rebaseline target at Slice 5.
- **EXPy cannot decode a fragment / xmldsig payload.** The `SignedInfo`
  xmldsig records are encoded by Exificient through the standalone
  XML_DSIG schema; EXPy v1.0 reads only the protocol-rooted xmldsig
  fragment. This is the well-known divergence already documented for
  the codec-layer `iso2-xmldsig-signed-info` /
  `iso20-common-xmldsig-signed-info` fixtures.
- **Translation module rebuild fails Pydantic validation.** Currently:
  empty `ConsumptionCost` arrays surface as `{'arrayLen': 0}` from EXPy
  but the walker reconstructs a single-element with missing required
  fields. Slice 2 follow-up.

Skip ≠ pass. The maintainer human-verification gate on issue #15 reviews
the skip list as part of accepting Slice 4.

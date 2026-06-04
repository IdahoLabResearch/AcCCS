# Replay layer

Offline runner for the captured-session corpus under
[`../captures/`](../captures/). The codec swap (ADR-0002 Slice 5, #16) is
complete: the single production EXI pipeline is
[`EXI`](../../../app/shared/exi_codec.py) over `EXPyEXICodec`. Per ADR-0003
§"Replay layer", the harness now asserts that the EXPy pipeline faithfully
round-trips the captured wire bytes for every record in the corpus.

## Equivalence oracle

For every record in the corpus, deduplicated by `(namespace, root, bytes)`:

1. **Bytes-equal.** EXPy decode → translation → EXPy re-encode produces
   bytes equal to the captured bytes → PASS.
2. **Decode-equivalent fallback.** When the EXPy re-encode produces
   different bytes (acceptable for records captured from a different codec
   implementation), decode both byte strings through EXPy and require the
   resulting Pydantic models to match. This proves EXPy is self-consistent
   for that byte sequence — the codec layer's `expy_authoritative` set is
   the analogous treatment at the fixture level.

This is the post-swap form of the Slice 4 grilling decision recorded on
issue #15 ("EXPy-as-cross-decoder fallback"): with Exificient removed, the
cross-decoder is no longer available, so the fallback compares EXPy against
itself.

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
silently passing when the EXPy pipeline cannot reach the bytes:

- **EXPy cannot decode the captured document/fragment bytes.** The record
  is skipped as a *rebaseline target* — the captured bytes came from a
  different codec implementation and the corpus will be re-captured against
  the EXPy pipeline.
- **EXPy cannot re-encode the decoded model.** Same treatment: skipped as a
  rebaseline target.
- **`XML_DSIG` `SignedInfo` records.** Always skipped. Those bytes
  originate from the historical Exificient standalone XML_DSIG schema;
  EXPy v1.0 reads only the protocol-rooted xmldsig fragment. The corpus
  will be re-captured against the EXPy pipeline.

Skip ≠ pass. The skip list is reviewed as part of the maintainer
human-verification gate (issue #15).

# Compatibility

These tables describe the EWF reader and writer as ebrig/ewf-image left them; in this fork the
writer is behind the `writer` feature. A supported operation does not imply that every producer
variant or consumer has been tested. The README's Validation section gives this fork's comparison
with libewf.

## Reader support

| Area | Status | Notes |
| --- | :---: | --- |
| EWF1 physical `.E01` / EVF | ✓ | Raw/zlib chunks, split segments, metadata, hashes, acquisition errors, sessions, tracks, and table variants. |
| X-Ways encrypted EWF1 | ✓ | Password-aware AES-128/AES-256 CTR reading for compatible Deflate and X-Ways Zstandard images. |
| EWF1 logical `.L01` / LVF | ✓ | Logical single-file catalogs and path lookup. |
| EWF1 SMART `.S01` | ✓ | SMART media profile handling and table-resident chunks. |
| EWF2 physical `.Ex01` | ✓ | Raw, zlib, BZip2, pattern-fill chunks, EWF2 metadata, memory extents, and split segments. |
| EWF2 logical `.Lx01` | ✓ | Logical single-file catalogs and auxiliary single-file tables. |
| Multi-segment discovery | ✓ | EWF1 and EWF2 sibling naming schemes, plus explicit segment lists. |
| Metadata and hashes | ✓ | Typed fields and generic header and hash value maps for compatibility. |
| Stored MD5/SHA1/SHA256 parsing | ✓ | Available with or without default features. |
| Streamed MD5/SHA1/SHA256 verification | ✓ | `Image::verify()` and `VerifyResult`, enabled by the default `verify` feature. |
| EWF2 section integrity checks | ✓ | Available with or without default features. |
| Corruption and encryption probes | ✓ | Lightweight file and segment probes that run without fully opening an image. |
| Logical-file verification/extraction | ✓ | Strict selected-file reads and MD5/SHA1 comparisons; computed SHA256; content-only extraction. |
| Encrypted EWF2 decryption | No | Not implemented. Encrypted images are detected and rejected. |
| Base-plus-overlay delta/shadow images | No | Not implemented. No confirmed public reference is available. |

## Writer support

| Area | Status | Notes |
| --- | :---: | --- |
| EWF1 physical `.E01` | ✓ | Raw/zlib chunks, metadata, hashes, range sections, and segment splitting. |
| EWF1 logical `.L01` | ✓ | Logical single-file catalog output. |
| EWF1 SMART `.S01` | ✓ | SMART profile output. |
| EWF2 physical `.Ex01` | ✓ | Raw, zlib, BZip2, pattern-fill chunks, metadata, memory extents, and segment splitting. |
| EWF2 logical `.Lx01` | ✓ | Logical single-file metadata and auxiliary tables. |
| Metadata and hashes | ✓ | Typed metadata, generic header values, stored MD5/SHA1, and generic hash values; available with or without default features. |
| Acquisition errors, sessions, tracks | ✓ | EWF1 and EWF2 range-style metadata. |
| Streaming physical E01 acquisition | ✓ | Known-size raw/zlib source acquisition, progress/cancellation, checkpoint inspection/resume, and cumulative bad-sector tables; validated with pinned libewf. |
| Sequential EWF1/EWF2 writing | ✓ | Known-length E01/Ex01/Lx01 with segment-bounded payload scratch; no checkpoint resume. Split E01 passed pinned libewf export, info, and verification. CLI raw/zlib output uses 32 KiB chunks. |
| Logical catalog builder | ✓ | `LogicalWriter` supplies file hashes and extents; general L01/Lx01 or sequential Lx01 backend. |
| Incomplete and resumed EWF1 output | ✓ | `finish_incomplete` writes `next`; `resume` appends and rewrites a complete image. |
| Secondary/shadow target mirroring | ✓ | `WriteOptions::secondary_segment_filename` writes a byte-identical secondary segment set for file-backed finishes. |
| Encrypted writing | No | Not implemented for X-Ways EWF1 or EWF2 output. |
| Base-plus-overlay delta/shadow writing | No | Not implemented. A verified reference format or API is required first. |

## Independent-tool coverage

An opt-in regression test over a synthetic corpus covers native WinAcq 20.3 E01
inputs, both compressed and uncompressed with split segments. EnCase 25.3 imports
of EWF and AFF4 output from this project have not been tested.

Evidence is separated by source and direction:

- Synthetic unit fixtures cover malformed inputs, boundary checks, table
  variants, chunk encodings, logical files, metadata, hashes, and writer round
  trips.
- Ignored external corpus tests compare raw stream output, metadata, hash values,
  and verification behavior against external EWF tools.
- Generated fixture tests exercise EWF1 and extended EWF profiles created by
  external tools, plus EWF2 and logical single-file cases created by the writer.
- X-Ways encryption coverage includes AES-128 and AES-256, each with compatible
  Deflate and with X-Ways Zstandard compression. Native uncompressed and
  verifier-less X-Ways fixtures are unavailable. A derived test fixture covers
  the verifier-less fallback behavior. The encrypted split-segment path is
  implemented but has no native split-image oracle.

EWF2 BZip2 support is covered by local tests. Some external tools cannot produce
or export EWF2 BZip2 images, so external oracle coverage for BZip2 is tracked
separately from local read and write behavior.

Independent coverage of split logical writer output includes L01 with the
default 32 KiB chunks and EWF2 logical output with 32 KiB and 8 KiB chunks,
using pinned libewf 20260924. The EWF2 logical writer rejects smaller chunks
because that exporter terminated abnormally on them. An older libewf 20251220
exporter omitted a file from a one-file split image even at 32 KiB. Test a
representative profile with the intended consumer.

## Writer digest semantics

Finalization hashes the complete logical media, including sector padding. The
SHA256 is returned in `WriteResult::computed_sha256`, even without the `verify`
feature. Complete EWF1 output embeds the computed SHA256 in its xhash section
unless an explicit SHA256 reference was supplied. EWF2 output written by this
library has no SHA256 section, so keep the returned digest in an external
acquisition record. Incomplete EWF1 output does not embed final digests.

Explicit MD5, SHA1, and SHA256 references are validated for syntax and for
consistency with each other. Explicit references are not replaced when they
differ from the computed media hash, which supports workflows that record an
intentional mismatch. `create_from_image` and `resume` recompute media digests
and do not copy the source's references. Calling `copy_hash_values_from_*` opts
into preserving those references. Callers that edit the media must then clear or
replace the copied references.

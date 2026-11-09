# Changelog

ys-e01-parser 1.0.0 is Yamato Security's fork of Elijah Brigham's
[ewf-image](https://github.com/ebrig/ewf-image); the versions before it are ewf-image's.

## 1.0.0 (Unreleased)

First version of Yamato Security's EWF reader, the E01 reader of Juntei: ewf-image at `04137ee`,
imported with its history. (@YamatoSecurity)

### Changed

- Images open leniently by default. Damage that the data can still be checked without is gone
  past and reported by `Image::lenient_findings` (and first in `Image::analyze`): truncated
  segments, damaged section descriptors, volume, data and table sections (with their intact
  copies, such as `table2`), and damaged hash, digest and header sections. A chunk that can't be
  verified fails when read. `OpenStrictness::Strict` keeps ewf-image's behaviour. (@YamatoSecurity)
- Writing EWF images and acquiring devices is behind the `writer` feature, off by default.
  (@YamatoSecurity)
- Only the library is kept, without ewf-cli and the experimental AFF4 crate. Named
  `ys-e01-parser` 1.0.0 (library `ewf_image`), on Rust 1.99, under the RPL 1.5 with the Apache
  License 2.0 kept for ewf-image's code. (@YamatoSecurity)
- `tests/oracle.rs` compares the reads of 13 public images with libewf's. (@YamatoSecurity)

### Fixed

- Damaged EWF1/EWF2 table entries could select another intact chunk and return
  its bytes successfully. Reads now reject mappings whose table checksum failed
  unless an intact replacement table exists. Payload checksums alone cannot
  authenticate a chunk's logical position. (@YamatoSecurity)
- Padded raw final chunks now validate the checksum over the entire stored
  payload before returning the media prefix, reject corrupt payloads and
  checksum trailers, and report the dropped padding. (@YamatoSecurity)
- Writer documentation examples respect the optional `writer` feature, so
  default and minimal reader-only doctests compile. (@YamatoSecurity)
- An image whose last chunk decodes to more bytes than the media needs, as some writers store it,
  failed to open; the media's bytes are read and an `OverlongChunk` warning is recorded.
  (@YamatoSecurity)
- EWF2 metadata compressed with a small zlib window was read as text, so an image could lose its
  media size. (@YamatoSecurity)

## ewf-image after 0.6.1 (04137ee)

- Update the experimental AFF4 crate to ZIP 9, propagating filename decoding
  errors and preserving duplicate-name checks and legacy storage discovery.

## 0.6.1 - 2026-10-11

- Keep reader statistics compatible with current Rust warnings while preserving
  the Rust 1.96 minimum and saturating atomic counter updates.

## 0.6.0 - 2026-09-29

### Command-line reliability and performance

- Use the native maximum EWF2 segment capacity by default, reducing segment
  creation and discovery overhead. Bound CLI readers to 32 simultaneous EWF
  segment handles so highly split images leave descriptors available for
  conversion and publication resources.
- Compare embedded EWF source hashes during physical conversion instead of
  decoding the source in a separate preliminary verification pass. Only the
  stored digest algorithms are added to the transfer hasher. Feed the source
  through bounded two-buffer read-ahead to overlap decoding with destination
  hashing and encoding.

### Reader and verification performance

- Let path-backed EWF readers perform native positioned I/O outside the global
  segment-handle pool lock while preserving the configured descriptor ceiling.
  Concurrent misses for the same logical chunk now share one decode.
- Add EWF counters for positioned segment I/O, handle-pool wait time, and
  coalesced chunk-cache misses.
- Let the unpublished `ewf-cli` choose bounded whole-image verification
  parallelism from the host automatically instead of adding a worker-count flag.

### Acquisition and conversion performance

- Encode automatically bounded batches of EWF chunks in parallel during
  healthy acquisition and sequential E01/Ex01 writing while preserving output
  order, progress, cancellation, and resumable segment boundaries.
- Automatically coalesce healthy resumable-acquisition reads across complete
  image chunks, up to 256 KiB, while retaining sector-by-sector fallback after a
  read error and progress or cancellation between accepted chunks.
- Reuse an opened EWF image for destination verification and overlap bounded
  source read-ahead with image encoding. Add phase timings to CLI reports.

## aff4-image 0.2.0 - 2026-09-29

### Reader and verification performance

- Replace AFF4's single decoded-chunk slot with an automatic 128 MiB shared LRU.
  Physical disk readers also coalesce small positioned requests into automatic
  1 MiB read-ahead pages within the same bound, without new reader settings.
- Expose AFF4 cache, decoding, eviction, and read-ahead statistics from
  containers, volume sets, and discovered physical disk readers.
- Read encoded chunks directly from stored ZIP bevies instead of loading each
  complete bevy, while retaining the compatible fallback for ZIP-compressed
  members. Expose counters for the direct range reads.
- Hash paired AFF4 block references in one chunk pass and reuse complete
  verification digests when converting or verifying selected physical disks.
- Fuse AFF4 linear and paired MD5/SHA256 block verification into one decoded
  chunk pass while retaining the existing work budgets, progress callbacks,
  mismatch reporting, and complete verification report.
- Stream identity-mapped ZIP resources and logical conversion input instead of
  retaining complete payloads in memory.
- Record the actual `aff4-image` package version in newly written containers.

### Acquisition and conversion performance

- Encode and block-hash automatically bounded AFF4 chunk batches in parallel,
  retaining deterministic bevy order and cooperative cancellation without a
  writer-tuning option.

## 0.5.0 - 2026-09-28

### Command-line usability

- Add the provisional `ewf-cli` workspace executable. It acquires physical media
  to a single E01, Ex01, AFF4, or raw output, converts decoded physical images
  between formats, and converts logical collections between Lx01 and AFF4 with
  per-file verification and explicit reports of omitted metadata. Remove the
  standalone `ewf-image` and `aff4-image` executables.
- Run the native source adapter and EWF operational runtime inside `ewf-cli`.
  Record physical sector geometry in AFF4 writer metadata.
- Print concise text by default in `ewf-cli`. Add `--json` for
  script-compatible reports that include verification, omission, and publication
  outcomes.
- Shorten help output, group case and image settings, and add `--version`
  output. Add `verify IMAGE ENTRY` and `extract` for logical files. The older
  `verify-file` and `extract-file` commands remain accepted under `ewf-cli ewf`.
- Set AFF4 resource limits in `ewf-cli` from platform capacity instead of
  command-line quota options. Library defaults, structural validation, and
  verification before publication are unchanged.
- Use fallible allocation when growing AFF4 decoded buffers and retained map records.
- Accept a password file or stdin for encrypted EWF1 input in the unified CLI.
  Keep passwords out of command arguments, and allow extraction to restore
  recorded file access and modification times when requested.

### AFF4 integration

- Discover all physical disks and metadata-linked companion containers, with
  independent cursors, bounded shared caches, and identity-checked reopening.
- Add explicit physical-disk selection and an owned `Read`/`Seek` cursor that
  reports the decoded size, volume identity, and declared sector geometry.
- Support reader-only dependencies with `default-features = false`. Acquisition
  and writer dependencies are gated behind the `write` feature. CLI dependencies
  live in the separate `ewf-cli` package.

### EWF library

- Add `AcquisitionWriter` for known-size raw/zlib physical E01 acquisition with
  bounded segment scratch space, sealed-segment checkpoints, binding to the source
  and configuration, progress, cancellation, inspection, and validation. Resume
  validates and rehashes the acquired prefix without rewriting it. Publication
  requires hard links.
- Add retries for seekable sources, stop and zero-fill policies, bounded error
  ranges, and configurable checkpoint intervals. Native bad-sector tables persist
  across resume, and media hashes include substituted bytes. Cumulative error
  ranges from continuation segments are merged without duplication.
- Add `SequentialWriter` for E01/Ex01/Lx01 output of known length and
  `LogicalWriter::create_sequential`, with bounded payload scratch space,
  optional mirroring, and recoverable publication. Sequential output cannot be
  resumed. Use the sequential writer for known-length E01 conversion instead of
  the general writer's full-image spools.
- Add `LogicalWriter` for L01/Lx01 catalogs, with identifiers, extents, per-file
  MD5/SHA1, and cancellation. Add strict streaming, verification, and computed
  SHA256 for selected files.
- Stage file-backed output under a recoverable publication journal with backups.
  Add `EwfWriter::recover_output`. Refuse existing segments unless replacement is
  explicitly enabled, and have `resume()` enable replacement. Detect stale
  continuation segments and validate mirrored namespaces before staging.
- Verify embedded SHA256 and reject malformed or conflicting supported
  references, including xhash identifiers in any letter case. Add
  `computed_sha256` and `sha256_match` to `VerifyResult`. Downstream struct
  literals must be updated.
- Compute SHA256 in the writers and expose `WriteResult::computed_sha256`. Embed
  the digest in complete EWF1 output when no explicit reference was supplied.
  EWF2 callers must record the digest externally. Validate configured references
  while preserving intentional mismatches.
- Write standard numeric logical entry types and complete catalog separators.
  Continue to read the older letter types. Store split EWF2 logical catalogs in
  the final segment. Reject EWF2 logical chunks below 8 KiB because split output
  at smaller chunk sizes crashed the pinned libewf exporter.
- Preserve profile hints from the first segment across sparse headers and
  continuation names, including the rollover from `.EZZ` to `.FAA`. Keep explicit
  metadata consistency checks.
- Store incompressible zlib chunks as raw data with a checksum for libewf
  compatibility.
- Keep logical entry names that contain unpaired UTF-16 surrogates. The new
  `SingleFileEntry::name_utf16` field holds the original UTF-16 units, and `name`
  holds a display string with replacement characters. Writers reject such names
  before publication instead of re-encoding them. Invalid UTF-16 outside entry
  names remains a malformed-catalog error.

### EWF command line

These commands are available as `ewf-cli ewf <command>`.

- Add `acquire`, `resume`, checkpoint inspection and validation, progress,
  source identity, immutable session manifests, JSON schema version 1, and
  verification after publication.
- Add read-only Windows and Linux device sources with discovered geometry, stable
  identity, destination-overlap checks, and aligned uncached reads. Disconnects
  are fatal and never substituted. On Windows, a narrow native module queries the
  opened handle. Device sessions created by the older PowerShell adapter must be
  completed with the original binary.
- Add cancellation and per-request timeouts for source reads, discard late
  results, and request native I/O cancellation on Windows. Discovery, output
  I/O, and drivers that ignore cancellation are not covered by the deadline.
- Persist acquisition history and consolidated reports across resume. Add
  `report` and `report --write`. Keep checkpoints and completed image results
  when logging or report persistence fails. History is a record of past events,
  not a fresh verification.
- Add `info`, strict `export`, bounded `analyze`, logical `files`, `verify-file`,
  and selective `extract-file`. Export and extraction protect existing
  destinations, check supported references, and report substitutions or missing
  references.
- Add `recover` for physical raw/zlib EWF1 images. Recovery produces a bundle
  with raw output, a complete provenance map, output hashes, and a completion
  report. Recovery keeps labeled partial output on failure or cancellation and
  requires opt-in for bytes with suspect checksums.
- Add one-shot `acquire-sequential`, strict directory `collect`, and
  `recover-publication` for EWF2. These commands check sources and verify the
  published media and files. Unresolved publication has an explicit JSON state.
  The commands have no checkpoint resume or mirror option.

### Validation and documentation

- Add Rust CI on Windows, Linux, and macOS, Linux MSRV checks, interoperability
  tests with pinned libewf 20260924, canonical AFF4 references, and producer and
  consumer tests with pinned independent aff4tools. Explicitly requested corpus
  runs fail when inputs are missing or empty.
- Add an opt-in logical corpus test that reads every catalog entry, compares
  stored file MD5 and SHA1 values, and compares complete media SHA256 and size
  with independently computed sidecar files. Add an independent JSON Lines
  manifest comparison for the complete entry tree, names, and file bytes.
- Add process-exit and I/O-failure coverage for acquisition, publication,
  history, export, and recovery. Add Linux loop and device-mapper suites and
  Windows VHDX suites on owned devices, with independent exports, ENOSPC and
  retry, cancellation, and source-preservation checks.
- Extend Windows Ex01/Lx01 NTFS and exFAT acceptance with pinned independent
  oracles. The harness detaches each completed destination before mounting the
  next one.
- Add isolated bounded EWF and AFF4 fuzz targets, reproducible payload, catalog,
  and resume benchmarks, and consumer fixture preparation anchored to source
  hashes. Independent logical EWF coverage includes default 32 KiB split output.
  Split output at 8 KiB and the default 32 KiB passed the pinned libewf
  exporter. An older libewf version still needs separate investigation.
- Reject truncated EWF1 volume flags and non-ASCII logical attribute hex without
  panicking when fuzzing malformed input.
- Add a local acceptance runner with isolated native builds, revision and tool
  provenance, hashed logs and artifacts, and explicit failed, blocked, and
  skipped statuses.
- Consolidate the user guides, writer selection, and migration guidance.

## aff4-image 0.1.0 - 2026-09-28

- Add the separate, experimental `aff4-image` crate. It is versioned and
  packaged independently from `ewf-image`. It reads AFF4 1.0 ImageStreams,
  Maps, and symbolic streams, and logical AFF4-L 1.1 and draft 2.1 containers,
  with resource enumeration and resource limits.
- Add single-volume streaming writers for physical AFF4 1.0 and logical
  AFF4-L 1.1, with source digests, cancellation, and exclusive publication. Draft
  2.1 output, multi-volume writing, and resume are unsupported.
- Add linear and container-wide verification, metadata hashing over exact bytes,
  imported-metadata checks, SHA512 and BLAKE2b, and supported block, map, and
  index integrity checks. Missing references, unsupported constructions, and
  byte coverage are reported explicitly.
- Add physical volume-set reading with per-volume context and
  `verify-set --full`, including foreign references, per-volume metadata, striped
  roots, and aggregate budgets.
- Add logical folders, roots, substreams, case metadata, ImageStreams for large
  files, streaming RDF inventory, directory collection, JSON output, and
  selective extraction.
- Preflight ZIP directory allocation and bound metadata, triples, entries,
  members, chunks, Maps, and verification work. Bound collection discovery and
  account for metadata and entries incrementally. Expose limit overrides and
  structured limit errors.
- Verify the finalized collection staging file before publication. Add the
  opt-in `Writer::finish_verified`, and keep `finish` unverified. Preserve
  diagnostics from failed verification in `Error::VerificationFailed { report }`
  and in CLI JSON.
- Preserve published paths and digests through `Error::PublishedButUnsynced`
  when parent-directory synchronization fails. Report publication and durability
  separately.
- Release finalized writer metadata and serialize reports without a duplicate
  JSON tree, which reduces measured memory use for large catalogs.

## 0.4.0 - 2026-09-12

- Added SHA256 media hashing, external reference comparisons, cancellable
  progress, and optional bounded parallel verification through `VerifyOptions`.
- Verification now bypasses decoded-chunk caches and zero-fill policies, so
  recovery substitutes cannot be accepted as verified media.
- Added typed integrity reports with scan coverage, bounded findings, matching
  EWF1 redundant-table comparison, and optional Serde serialization.
- Added positioned segment sources, bounded subranges, and section summaries
  for EWF1/EWF2 images, preserving table-cache and path-reader handle limits.
- Added a separate physical raw/zlib EWF1 recovery API with redundant-table
  fallback, explicit suspect-data policy, bounded provenance, cancellation,
  output-size controls, and exclusive creation of raw output files.

## 0.3.0 - 2026-08-28

### Breaking Changes

- `CompressionMethod` and `DataChunkEncoding` now expose a `Zstd` variant and
  are non-exhaustive. Downstream matches must include a wildcard arm. See
  [Migrating to 0.3](https://github.com/ebrig/ewf-image/blob/04137ee/docs/migrating-to-0.3.md).

### Added

- Added reader support for X-Ways Forensics 20.9+ EWF1 images that use
  Zstandard-compressed metadata, magicless Zstandard media frames, and the
  X-Ways one-byte zero-chunk marker. Decoding uses a pure-Rust implementation.
- Added password-aware reading for X-Ways EWF1 AES-128 and AES-256 CTR images,
  including `x_encryption` metadata validation, constant-time password
  verifier checks, transparent chunk decryption, and non-secret
  `EncryptionInfo` reporting. Password storage is zeroized on drop.
- Added `Image::open_with_password` and password-aware variants for explicit
  options, segment lists, and caller-supplied readers.
- Verifier-less encrypted images now validate their first mandatory media
  chunk during open, so an incorrect password cannot produce a successful
  image handle before structural validation.

### Fixed

- EWF1 continuation segments may now inherit media geometry from the first
  segment when they omit their own `volume`, `disk`, or `data` section.
  Repeated media sections are checked for consistent geometry.
- Reject unknown or contradictory EWF1 compression markers instead of guessing
  a decoder, and cap Zstandard decoder windows before allocation.

## 0.2.0 - 2026-07-17

### Breaking Changes

- `OpenOptions` fields are now private. Configure reader behavior with the
  `with_*` builders and inspect it with getters. This prevents future reader
  controls from breaking struct-literal callers. See
  [Migrating to 0.2](https://github.com/ebrig/ewf-image/blob/04137ee/docs/migrating-to-0.2.md).

### Added

- Added byte-based decoded-chunk cache sizing and a bounded 4 MiB table-entry
  page cache shared by all clones and cursors from an image. Both limits are
  configurable through `OpenOptions`.
- Added opt-in `ReaderStatistics` snapshots for cache, I/O, parsing, handle,
  checksum, and decompression diagnostics. Collection is disabled by default.
- Added `ReaderCacheInfo` snapshots for the configured chunk/table cache
  capacities and current/peak retained table-page payload bytes.

### Fixed

- Recovered EWF1 chunk offsets that overflow 31 bits in large unsegmented
  images with a zero table base offset, matching FTK-style single-file `.E01`
  output larger than 2 GiB.
- Replaced the per-read linear table-range scan with a binary search so chunk
  lookups stay fast on multi-terabyte images with thousands of chunk tables.
- Cached segment lengths after their first lookup so repeated encoded-chunk and
  table-page reads do not seek to the end of a segment again.
- Table-entry checksums are now validated with a fixed 64 KiB streaming buffer
  instead of allocating the complete table-entry region in memory.
- The EWF1 writer now emits multiple `sectors`/`table`/`table2` groups per
  segment, each with its own 64-bit table base offset, so non-segmented images
  larger than 2 GiB can be written and read back. Groups use the conservative
  16,375-entry compatibility limit documented for FTK Imager and legacy EnCase
  formats; later EnCase versions permit more entries per table. Previously such
  writes failed with a 31-bit offset error.
- EWF1 maximum-segment-size estimation now follows the actual ordered table
  group boundaries, preventing interacting payload and entry limits from
  producing segments slightly larger than the configured maximum.
- Writer segment planning now retains index ranges into the original chunk
  descriptor vector instead of building per-segment descriptor vectors,
  reducing peak memory without writing an additional descriptor index to disk.

### Known Limitations

- Large writes still require temporary space for the raw and encoded media and
  retain one in-memory descriptor per logical chunk, so descriptor memory grows
  with the image's chunk count.

## 0.1.1 - 2026-07-16

### Fixed

- Removed the fixed EWF1 section-chain limit so large unsegmented images can be
  opened, while still rejecting non-advancing and overlapping section chains.
- Corrected raw-chunk checksum failures to report `raw chunk checksum mismatch`.
- Preserved complete fixture paths and underlying errors in external-corpus
  test failures.

## 0.1.0 - 2026-07-09

Initial release.

### Added

- Rust reader for EWF1 physical/logical/SMART and EWF2 physical/logical images.
- Rust writer for EWF1 physical/logical/SMART and EWF2 physical/logical images.
- Multi-segment discovery, positioned reads, `Read + Seek` cursors, and bounded decoded-chunk caching.
- Metadata, stored hash, acquisition error, session, track, memory extent, and logical single-file APIs.
- Raw, zlib, EWF2 BZip2, EWF1 empty-block, and EWF2 pattern-fill chunk support.
- Optional streamed MD5/SHA1 verification through the default `verify` feature.
- External fixture and command-line oracle tests behind the `external-fixtures` feature.
- Secondary/shadow target mirroring for file-backed writer output.

### Known Limitations

- Encrypted EWF2 images are detected and rejected; decryption is not currently
  implemented.
- Encrypted writing and base-plus-overlay delta/shadow behavior are not
  currently implemented.
- EWF2 BZip2 external oracle coverage depends on broader external tool support
  for that path.

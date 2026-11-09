# Verification, analysis, and recovery

Verification checks bytes against references. Analysis reports integrity
findings. Recovery exports damaged media with provenance. Each operation has its
own completion and success criteria.

| Operation | Scope | Result when data is incomplete |
| --- | --- | --- |
| Media verification | Complete decoded media and supported references | Error; no completed verification report |
| Single-file verification | One selected logical file and its file references | Error; does not verify all image media |
| Analysis | Readable media, redundant tables, and integrity findings | Explicit incomplete/unavailable coverage; no whole-media digest |
| Recovery | Supported damaged EWF1 media | Output with explicit recovered, suspect, and substituted provenance |

## Media verification

`Image::verify()` returns MD5, SHA1, and SHA256 results. Verification reads the
backing chunks without using the decoded-chunk cache or the zero-fill recovery
policy, so corrupt media cannot pass verification with cached substitute bytes.

`verify_with_options` and `verify_with_progress` also accept reference digests
supplied by the caller. Recognized SHA256 references embedded in EWF1 xhash
sections are compared as well. Supported digest identifiers are
case-insensitive. Malformed values and conflicting references cause opening to
fail, including in lenient mode. Unknown hash identifiers remain available in the
generic metadata map and are not verified.

`VerificationReport::comparisons` lists embedded and external references
separately. A mismatch is reported as a result, and unreadable media is reported
as an error. `references_match()` returns `None` when no supported reference
exists, so the absence of references is never treated as a match. SHA256 is
computed over the logical media and does not imply any additional EWF stored-hash
section layout.

```rust,no_run
use ewf_image::{Image, VerifyOptions};
use std::ops::ControlFlow;

fn verify(image: &Image, acquisition_sha256: [u8; 32]) -> ewf_image::Result<()> {
    let options = VerifyOptions::default().with_expected_sha256(acquisition_sha256);
    let report = image.verify_with_progress(&options, |progress| {
        println!(
            "{} / {} bytes",
            progress.bytes_verified, progress.bytes_total
        );
        ControlFlow::Continue(())
    })?;
    println!("references match: {:?}", report.references_match());
    Ok(())
}
```

Progress starts at zero and advances in logical chunk order on the calling
thread. Returning `ControlFlow::Break(())` cancels only the current operation.
`Image::signal_abort()` cancels all operations that use the image. Worker reads
already in progress finish before cancellation returns. Callbacks are never
invoked while reader locks are held. Cancellation returns no completed report.

## Parallel scans and memory

The optional `parallel` feature enables more than one worker:

```toml
ewf-image = { version = "0.6", features = ["parallel"] }
```

`VerifyOptions::with_parallelism(4)` selects up to four workers. The default is a
single thread. Each scan owns its worker pool, decompresses bounded batches, and
feeds the hashers in logical order. The decoded batch budget defaults to 8 MiB
and can be changed with `with_chunk_buffer_size_bytes`. At least one chunk is
always processed, so a chunk larger than the budget is processed alone. The batch
size is also capped at twice the worker count. Encoded input buffers, decoder
scratch space, reader caches, and thread stacks use additional memory. Worker
counts outside the range 1 to 64 and zero-byte budgets are rejected before
progress starts.

Verification bypasses the decoded cache without clearing it. The bounded table
cache is shared with normal reads. Images opened by path keep their file pool and
handle limits. Their seek and read operations are serialized, while
decompression can run concurrently. Positioned sources also allow concurrent
backing reads. Throughput depends on compression, storage, chunk size, and
worker count.

## Structured analysis

`Image::analyze` and `analyze_with_progress` collect chunk failures,
disagreements between matching EWF1 `table` and `table2` entries, acquisition
context, and reference hash mismatches. Chunk failures do not stop analysis. An
incomplete pass returns no media hashes or hash comparisons, so omitted or
zero-filled bytes are never represented by a complete media digest.

`IntegrityReport::media_status` distinguishes complete, incomplete, and
unavailable scans. Complete media coverage does not imply that reference hashes
match or that there are no structural findings. `with_maximum_findings` limits
the number of retained records, which defaults to 1,024. Error and warning counts
include findings beyond that limit, and `suppressed_findings` reports how many
were omitted. The optional `serde` feature serializes reports, findings,
progress, recovery records, and section summaries.

`analyze_path` opens the image with the default options, which are lenient:
structural damage that the image can still be checked without (a truncated
segment, a damaged descriptor, media geometry or chunk table with an intact copy
or checkable values, damaged hash or header metadata) is reported as findings
ahead of the media results, and the chunks that cannot be verified are reported
as unreadable. If a table's entries checksum fails and no intact copy exists,
all reads through that table fail: an intact payload checksum does not establish
the chunk's logical position. This also applies to the remaining entries of a
truncated EWF2 table whose checksum was lost. Trusted tables elsewhere in the
image, intact EWF1 `table2` copies, and sequentially verified EWF1 carving remain
usable. Lenient opening never substitutes data. An image that cannot be
opened at all produces one typed finding and unavailable media coverage.
Filesystem errors are returned as errors. Use `analyze_path_with_password` for
encrypted inputs. Open with `OpenStrictness::Strict` and call `Image::analyze`
to treat any structural defect as an opening failure instead.

When analyzing an `Image` that is already open, analysis relies on the checks
performed when the image was opened and does not revalidate every descriptor or
metadata section. The report starts with the defects that lenient opening went
past, which `Image::lenient_findings` also returns.
Table comparison checks only pairs with matching counts and base offsets, and
`table2` ranges that differ are not treated as mirrors. Media progress begins
after table comparison. Table comparison honors `signal_abort`.

## Positioned sources and section inspection

`SegmentReadAt` accepts positioned backings that are owned by the caller and have
a stable length. `SegmentSource` provides memory and file backings and validated
bounded subranges. `Image::open_sources` and its variants with options or
passwords support both EWF1 and EWF2. Supply sources in segment order. Source
names are labels only and are never reopened as filesystem paths.

The image owns all supplied sources for its lifetime. A file handle limit lower
than the number of supplied sources is rejected. Native file backings use
positioned reads on Windows and Unix and fall back to serialized reads on other
platforms. Backings must remain unchanged while the image is open.

```rust,no_run
use ewf_image::{Image, SegmentSource};
use std::fs::File;

fn embedded(container: File, offset: u64, length: u64) -> ewf_image::Result<Image> {
    let source = SegmentSource::from_file(container)?.subrange(offset, length)?;
    Image::open_sources([("embedded.E01", source)])
}
```

`Image::sections()` returns summaries of the accepted descriptors. Each summary
includes segment-relative descriptor and payload locations, the original EWF1
name or EWF2 type ID, and chain links. The summaries describe the structure found
when the image was opened. The summaries are not a fresh integrity verdict and do
not expose payloads or cryptographic material.

## Damaged-image recovery

`EwfRecovery` is a separate library API for physical, unencrypted raw or zlib
EWF1 images with separate sectors sections. Recovery accepts an intact prefix of
the descriptor chain and validated first-segment geometry. Recovery tries the
primary table and any matching redundant table, then writes a logical raw image
with explicit provenance. `EwfRecovery` does not change how images are normally
opened.

```rust,no_run
use ewf_image::{EwfRecovery, RecoveryOptions};

fn recover() -> ewf_image::Result<()> {
    let recovery = EwfRecovery::open("damaged.E01", RecoveryOptions::default())?;
    let report = recovery.recover_to_path("recovered.raw")?;
    println!("{} bytes substituted", report.bytes_zero_filled);
    Ok(())
}
```

`recover_to_path` creates a new file exclusively and refuses existing paths and
source aliases. `recover_to_writer` accepts a destination owned by the caller,
which must be separate from the evidence. After an error or cancellation, the
output written so far remains available for inspection. Recovery does not repair
the source EWF image or prove that recovered data is authentic.

By default, recovery substitutes zeros when neither table provides validated
data. `with_preserve_checksum_suspect(true)` accepts decoded bytes with a bad
raw-data or table-entry checksum, but only when no validated alternative
succeeds. Those chunks are marked as suspect. The primary, redundant, and
zero-filled chunk counts together cover the entire output, and suspect chunks
are a subset of the recovered chunks. Coalesced outcome ranges and structural
notices are each retained up to a limit, with counts of omitted records. The
progress callback reports every outcome and supports cancelling the operation.

`with_maximum_output_bytes` rejects an excessive declared output size before any
output is created. Recovery rejects missing middle segments, incomplete middle
descriptor chains, ambiguous table coverage before later data, invalid geometry,
and unsupported format families. Recovery does not carve lost descriptors or
reconstruct missing table headers. A missing final range is zero-filled when its
position is unambiguous. Recovery does not support EWF2, logical or SMART images,
encryption, X-Ways Zstandard, or table-resident media.

## Password-protected X-Ways EWF1

```rust,no_run
fn main() -> ewf_image::Result<()> {
    let password = ewf_image::EwfPassword::utf8("operator-supplied-password");
    let image = ewf_image::Image::open_with_password("case.E01", &password)?;
    let result = image.verify()?;
    println!("MD5 match: {:?}", result.md5_match);
    Ok(())
}
```

`EwfPassword` zeroizes the password bytes it owns. Use `from_bytes` for
passwords in other encodings. AES-128 accepts at most 16 password bytes, and
AES-256 accepts at most 32. Each open accepts one password. Key material owned by
the library is zeroized and excluded from diagnostics.

A stored verifier checks the password. For images without a verifier, the first
decrypted chunk must pass structural validation. AES-CTR is not authenticated
encryption, so the remaining media still requires integrity verification.
Encrypted EWF2 images are detected and rejected. The CLI accepts a supported
X-Ways EWF1 password from a file or stdin using `--password-file`.

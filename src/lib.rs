// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) 2026 Elijah Brigham
//
// This file is changed from ebrig/ewf-image (https://github.com/ebrig/ewf-image), whose code is
// under the Apache License 2.0 (LICENSE-APACHE).
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

//! Rust library for reading Expert Witness Format forensic images, and with the
//! `writer` feature, writing them.
//!
//! `ewf_image` provides direct Rust APIs for working with Expert Witness Format
//! images. It can open physical, logical, SMART, and EWF2 segment families,
//! expose metadata and stored hashes, read the logical media stream, and walk
//! logical single-file catalogs; with the `writer` feature, it also creates EWF
//! output and acquires devices. Images open leniently by default: damage that
//! the data can still be checked without is gone past and reported by
//! `Image::lenient_findings`, and a chunk that cannot be verified fails when it
//! is read. Juntei mounts the images it reads with ys-vhdx-mount.
//!
//! # Terminology
//!
//! Logical media size is the decoded byte length exposed by [`Image::media_size`]
//! and [`ImageInfo::logical_size`]. Segment set size is the total byte length of
//! the opened EWF container files, as reported by [`Image::segment_set_size`].
//! Chunks are the stored allocation units used by EWF tables. Logical EWF
//! images can also contain a single-file catalog, where each entry describes a
//! file-like object stored inside the image.
//!
//! # Supported container families
//!
//! - EWF1 physical `.E01` / EVF images.
//! - X-Ways AES-128/AES-256 encrypted EWF1 images.
//! - EWF1 logical `.L01` / LVF images.
//! - EWF1 SMART `.S01` images.
//! - EWF2 physical `.Ex01` images.
//! - EWF2 logical `.Lx01` images.
//!
//! # Reading
//!
//! ```no_run
//! use std::io::Read;
//!
//! fn main() -> ewf_image::Result<()> {
//!     let image = ewf_image::Image::open("case.E01")?;
//!     let info = image.info();
//!
//!     println!("{:?}: {} bytes", info.format, info.logical_size);
//!     println!("segments: {}", image.number_of_segments());
//!
//!     let mut sector = vec![0; 512];
//!     image.cursor().read_exact(&mut sector)?;
//!
//!     let mut later_sector = vec![0; 512];
//!     image.read_at(&mut later_sector, 4096)?;
//!
//!     Ok(())
//! }
//! ```
//!
//! Password-protected X-Ways EWF1 images use the same read APIs after a
//! password-aware open:
//!
//! ```no_run
//! fn main() -> ewf_image::Result<()> {
//!     let password = ewf_image::EwfPassword::utf8("operator-supplied-password");
//!     let image = ewf_image::Image::open_with_password("case.E01", &password)?;
//!     println!("{:?}", image.encryption_info());
//!     Ok(())
//! }
//! ```
//!
//! # Metadata and hashes
//!
//! ```no_run
//! fn main() -> ewf_image::Result<()> {
//!     let image = ewf_image::Image::open("case.E01")?;
//!
//!     if let Some(case_number) = image.header_value("case_number") {
//!         println!("case: {case_number}");
//!     }
//!
//!     if let Some(md5) = image.hash_value("MD5") {
//!         println!("stored MD5: {md5}");
//!     }
//!
//!     #[cfg(feature = "verify")]
//!     {
//!         let verification = image.verify()?;
//!         println!("MD5 match: {:?}", verification.md5_match);
//!         println!("SHA1 match: {:?}", verification.sha1_match);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! # Writing
//!
//! ```no_run
//! use std::fs::File;
//!
//! fn main() -> ewf_image::Result<()> {
//!     let mut input = File::open("disk.raw")?;
//!
//!     let mut options = ewf_image::WriteOptions::default();
//!     options.format = ewf_image::WriteFormat::Ewf2Physical;
//!     options.compression = ewf_image::WriteCompression::Zlib;
//!     options.metadata.set_header_value("case_number", "CASE-001");
//!
//!     let mut writer = ewf_image::EwfWriter::create("case.Ex01", options)?;
//!     std::io::copy(&mut input, &mut writer)?;
//!     writer.finish()?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Streaming acquisition
//!
//! `AcquisitionWriter` (with the `writer` feature) seals physical E01 segments as
//! input arrives and can resume sealed checkpoints without rewriting them. It
//! requires a known, sector-aligned source size and a filesystem supporting hard
//! links.
//!
//! ```no_run
//! use std::fs::File;
//! use std::ops::ControlFlow;
//! use ewf_image::{AcquisitionOptions, AcquisitionReadOptions, AcquisitionStatus, AcquisitionWriter};
//!
//! fn continue_acquisition(source_identity: [u8; 32]) -> ewf_image::Result<()> {
//!     let mut input = File::open("disk.raw")?;
//!     let options = AcquisitionOptions::new(input.metadata()?.len());
//!     // Use create instead of resume for the first acquisition session.
//!     // The caller must bind source_identity to a stable source snapshot.
//!     let mut writer = AcquisitionWriter::resume("case.E01", &options, source_identity)?;
//!     let outcome = writer.acquire_with_progress(
//!         &mut input, &AcquisitionReadOptions::default(), |progress| {
//!             println!("{} accepted; {} checkpointed", progress.bytes_written, progress.checkpoint_bytes);
//!             // Return Break(()) when the application's cancellation flag is set.
//!             ControlFlow::Continue(())
//!         }
//!     )?;
//!     if outcome.status == AcquisitionStatus::Complete {
//!         writer.finish()?;
//!     }
//!     Ok(())
//! }
//! ```
//!
//! # Feature flags
//!
//! - `verify` is enabled by default and adds `Image::verify()` plus
//!   `VerifyResult` for streamed MD5/SHA1 verification. Stored hash parsing,
//!   EWF2 section integrity checks, and writer hash support are available
//!   without this feature.
//! - `external-fixtures` enables ignored integration tests that require local
//!   EWF corpora and external EWF tools. It does not change library behavior.
//! - `fuzzing` exposes the logical catalog parser to the isolated fuzz workspace.
//! - `parallel` enables multiple decompression workers for verification and
//!   analysis. It implies `verify`; scans remain single-threaded by default.
//! - `serde` enables serialization of analysis, verification, recovery, and
//!   section-summary results.
//!
//! # Analysis and recovery
//!
//! [`Image::sections`] exposes descriptor locations. [`Image::open_sources`]
//! accepts [`SegmentSource`] backings with independent positioned reads.
//! With `verify`, `verify_with_options` computes SHA256 and compares external
//! references; `analyze` returns typed findings and explicit media coverage.
//! [`EwfRecovery`] separately recovers physical raw/zlib EWF1 data with
//! provenance and exclusive creation of output files.
//!
//! # Limitations
//!
//! X-Ways encrypted EWF1 reading is supported. Encrypted EWF2 images are
//! detected and rejected, and encrypted writing is not implemented.
//! Secondary/shadow target mirroring is supported by the file-backed writer.
//! Base-plus-overlay delta/shadow images are not implemented.

// Without the writer, the helpers only it uses are unused; with --all-features (CI), unused code
// is still an error.
#![cfg_attr(not(feature = "writer"), allow(dead_code))]
#![forbid(unsafe_code)]

mod codepage;
mod date_time;
mod decode;
mod encryption;
mod error;
mod format;
mod hashes;
mod image;
mod index;
#[cfg(feature = "verify")]
mod integrity;
mod lenient;
#[cfg(feature = "verify")]
mod logical_verify;
mod metadata;
mod publication;
mod reader_cache;
mod reader_statistics;
mod sections;
mod segment;
mod signature;
mod single_files;
mod source;
mod types;
#[cfg(feature = "verify")]
mod verify;
#[cfg(feature = "writer")]
mod writer;

pub use encryption::{EncryptionInfo, EncryptionMethod, EwfPassword};
pub use error::{EwfError, Result};
/// Direct catalog parsing for the isolated fuzz workspace.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn parse_single_files_for_fuzzing(data: &[u8], ewf1: bool) -> Result<SingleFilesInfo> {
    if ewf1 {
        single_files::parse_ewf1_single_files_data(data)
    } else {
        single_files::parse_ewf2_single_files_data(data)
    }
}
pub use image::recovery::{
    EwfRecovery, RecoveryNotice, RecoveryOptions, RecoveryProgress, RecoveryRange, RecoveryReport,
    RecoveryStatus,
};
pub use image::{Image, ImageCursor, SegmentReader, SingleFileCursor};
#[cfg(feature = "verify")]
pub use logical_verify::{SingleFileProgress, SingleFileVerification};
pub use reader_statistics::{ReaderCacheInfo, ReaderStatistics};
pub use sections::{SectionInfo, SectionKind};
pub use signature::{
    check_file_corruption, check_file_encryption, check_file_signature,
    check_segment_files_corruption, check_segment_files_encryption,
};
pub use single_files::SINGLE_FILE_PATH_SEPARATOR;
pub use source::{SegmentReadAt, SegmentSource};
pub use types::{
    AcquisitionError, ChunkCacheCapacity, CompressionFlags, CompressionLevel, CompressionMethod,
    CompressionValues, DataChunk, DataChunkEncoding, EncodedDataChunk, EwfMetadata, Format,
    FormatProfile, HeaderCodepage, HeaderDateFormat, ImageInfo, MediaFlags, MediaInfo, MediaType,
    MemoryExtent, OpenOptions, OpenStrictness, SectorRange, SegmentFileVersion,
    SingleFileAttribute, SingleFileEntry, SingleFileEntryType, SingleFileExtent,
    SingleFilePermission, SingleFilePermissionGroup, SingleFileSource, SingleFileSubject,
    SingleFilesAuxTables, SingleFilesInfo, StoredHashes,
};
#[cfg(feature = "writer")]
pub use writer::{
    AcquisitionCheckpoint, AcquisitionOperationPhase, AcquisitionOperationProgress,
    AcquisitionOptions, AcquisitionOutcome, AcquisitionProgress, AcquisitionReadOptions,
    AcquisitionStatus, AcquisitionWriter, EwfWriter, LogicalEntryMetadata, LogicalWriteProgress,
    LogicalWriter, SequentialOptions, SequentialWriter, UnreadableSectorPolicy, WriteCompression,
    WriteCompressionLevel, WriteCompressionValues, WriteFormat, WriteHashes, WriteMediaProfile,
    WriteOptions, WriteResult,
};

#[cfg(feature = "verify")]
pub use integrity::{
    IntegrityFinding, IntegrityFindingKind, IntegrityReport, IntegritySeverity, MediaScanStatus,
    analyze_path, analyze_path_with_password, analyze_path_with_progress,
    analyze_path_with_progress_and_password,
};
#[cfg(feature = "verify")]
pub use types::VerifyResult;
#[cfg(feature = "verify")]
pub use verify::{
    ComputedHashes, HashAlgorithm, HashComparison, HashReference, VerificationReport,
    VerifyOptions, VerifyProgress,
};

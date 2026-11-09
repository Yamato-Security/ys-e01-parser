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

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use bzip2::Compression as Bzip2Compression;
use bzip2::write::BzEncoder;
use flate2::Compression as ZlibCompression;
use flate2::write::ZlibEncoder;
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;
use tempfile::NamedTempFile;

use crate::codepage::encode_header_text;
use crate::date_time::{
    format_ewf1_header_date_value, format_ewf1_header2_date_value, format_xheader_date_value,
};
use crate::decode::{ChunkEncoding, decode_chunk, validate_encoded_size};
use crate::format::{ewf1, ewf2};
use crate::image::Image;
use crate::types::{
    AcquisitionError, CompressionLevel, CompressionMethod, CompressionValues, DataChunk,
    DataChunkEncoding, EncodedDataChunk, EwfMetadata, Format, FormatProfile, HeaderCodepage,
    HeaderDateFormat, ImageInfo, MediaFlags, MediaType, MemoryExtent, SectorRange,
    SingleFileAttribute, SingleFileEntry, SingleFileEntryType, SingleFileExtent,
    SingleFilePermission, SingleFilePermissionGroup, SingleFileSource, SingleFileSubject,
    SingleFilesAuxTables, SingleFilesInfo, StoredHashes,
};
use crate::{EwfError, Result};

mod acquisition;
mod logical;
mod sequential;
pub use acquisition::{
    AcquisitionCheckpoint, AcquisitionOperationPhase, AcquisitionOperationProgress,
    AcquisitionOptions, AcquisitionOutcome, AcquisitionProgress, AcquisitionReadOptions,
    AcquisitionStatus, AcquisitionWriter, UnreadableSectorPolicy,
};
pub use logical::{LogicalEntryMetadata, LogicalWriteProgress, LogicalWriter};
pub use sequential::{SequentialOptions, SequentialWriter};

const VOLUME_DATA_SIZE: usize = 1052;
const EWF1_LTREE_HEADER_SIZE: usize = 48;
const EWF2_DEVICE_INFORMATION_SECTION: u32 = 0x01;
const EWF2_CASE_DATA_SECTION: u32 = 0x02;
const EWF2_SECTOR_DATA_SECTION: u32 = 0x03;
const EWF2_SECTOR_TABLE_SECTION: u32 = 0x04;
const EWF2_ERROR_TABLE_SECTION: u32 = 0x05;
const EWF2_SESSION_TABLE_SECTION: u32 = 0x06;
const EWF2_INCREMENT_DATA_SECTION: u32 = 0x07;
const EWF2_MD5_HASH_SECTION: u32 = 0x08;
const EWF2_SHA1_HASH_SECTION: u32 = 0x09;
const EWF2_RESTART_DATA_SECTION: u32 = 0x0a;
const EWF2_MEMORY_EXTENTS_TABLE_SECTION: u32 = 0x0c;
const EWF2_NEXT_SECTION: u32 = 0x0d;
const EWF2_FINAL_INFORMATION_SECTION: u32 = 0x0e;
const EWF2_DONE_SECTION: u32 = 0x0f;
const EWF2_ANALYTICAL_DATA_SECTION: u32 = 0x10;
const EWF2_SINGLE_FILES_DATA_SECTION: u32 = 0x20;
const EWF2_SINGLE_FILES_TABLE_SECTION: u32 = 0x21;
const EWF2_SINGLE_FILES_MD5_HASH_TABLE_SECTION: u32 = 0x22;
const EWF2_SINGLE_FILES_UNKNOWN_TABLE_SECTION: u32 = 0x23;
const EWF2_TABLE_HEADER_V2_SIZE: usize = 32;
const EWF2_TABLE_FOOTER_SIZE: usize = 16;
// EWF1 table entries hold 31-bit offsets relative to the table base offset, so
// each sectors/table group can address at most 2 GiB of chunk payload. Large
// non-segmented images are written as multiple groups per segment, matching
// EnCase 6 and FTK Imager output.
const EWF1_TABLE_GROUP_MAX_PAYLOAD: u64 = 0x7fff_ffff;
const EWF1_TABLE_GROUP_MAX_ENTRIES: usize = 16_375;
const SIGNED_SECTOR_RANGE_MAX: u64 = i64::MAX as u64;
const EWF2_EXTENDED_ATTRIBUTES_HEADER: &[u8; 37] = &[
    0x00, 0x00, 0x00, 0x00, 0x01, 0x0b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x41, 0x00, 0x74,
    0x00, 0x74, 0x00, 0x72, 0x00, 0x69, 0x00, 0x62, 0x00, 0x75, 0x00, 0x74, 0x00, 0x65, 0x00, 0x73,
    0x00, 0x00, 0x00, 0x00, 0x00,
];

const SINGLE_FILE_ENTRY_TYPES: &[&str] = &[
    "id", "p", "n", "ls", "lo", "po", "du", "src", "sub", "pm", "cid", "opr", "be", "ha", "sha",
    "snh", "cr", "wr", "ac", "mo", "dl", "ea",
];
const SINGLE_FILE_SOURCE_TYPES: &[&str] = &[
    "id", "n", "ev", "loc", "gu", "pgu", "dt", "mfr", "mo", "se", "do", "ip", "ma", "tb", "lo",
    "po", "aq", "ah", "sh",
];
const SINGLE_FILE_SUBJECT_TYPES: &[&str] = &["id", "n"];
const SINGLE_FILE_PERMISSION_TYPES: &[&str] = &["n", "pr", "s", "nta", "nti"];

#[derive(Debug, Clone, PartialEq, Eq)]
/// Configuration used to create an [`EwfWriter`].
pub struct WriteOptions {
    /// Output EWF format.
    pub format: WriteFormat,
    /// Number of sectors represented by each chunk.
    pub sectors_per_chunk: u32,
    /// Bytes in each logical sector.
    pub bytes_per_sector: u32,
    /// Segment set identifier written to output metadata.
    pub set_identifier: Option<[u8; 16]>,
    /// Compression method for newly encoded chunks.
    pub compression: WriteCompression,
    /// Compression level and flags for newly encoded chunks.
    pub compression_values: WriteCompressionValues,
    /// Stored hash values to write.
    pub hashes: WriteHashes,
    /// Maximum output segment size in bytes.
    pub maximum_segment_size: Option<u64>,
    /// Permit replacing existing segment files during file-backed finalization.
    /// Defaults to false. Replacement uses a recoverable publication journal.
    pub overwrite_existing: bool,
    /// First path of the mirrored secondary output segment set.
    pub secondary_segment_filename: Option<PathBuf>,
    /// Declared logical media size in bytes.
    pub media_size: Option<u64>,
    /// Case and acquisition metadata to write.
    pub metadata: EwfMetadata,
    /// Codepage used to encode EWF1 header values.
    pub header_codepage: HeaderCodepage,
    /// Date format used for EWF1 header date values.
    pub header_values_date_format: HeaderDateFormat,
    /// Acquisition error ranges to write.
    pub acquisition_errors: Vec<AcquisitionError>,
    /// Checksum error ranges to write.
    pub checksum_errors: Vec<SectorRange>,
    /// Session sector ranges to write.
    pub sessions: Vec<SectorRange>,
    /// Track sector ranges to write.
    pub tracks: Vec<SectorRange>,
    /// Media type and acquisition flags to write.
    pub media_profile: WriteMediaProfile,
    /// Memory acquisition extents to write.
    pub memory_extents: Vec<MemoryExtent>,
    /// Logical single-file catalog to write.
    pub single_files: Option<SingleFilesInfo>,
    /// Preserved EWF2 single-file auxiliary table data.
    pub ewf2_single_files_tables: SingleFilesAuxTables,
    /// Raw EWF2 increment data sections to write.
    pub ewf2_increment_data: Vec<Vec<u8>>,
    /// Raw EWF2 final information section to write.
    pub ewf2_final_information: Option<Vec<u8>>,
    /// EWF2 restart data text to write.
    pub ewf2_restart_data: Option<String>,
    /// EWF2 analytical data text to write.
    pub ewf2_analytical_data: Option<String>,
}

impl Default for WriteOptions {
    fn default() -> Self {
        Self {
            format: WriteFormat::Ewf1Physical,
            sectors_per_chunk: 64,
            bytes_per_sector: 512,
            set_identifier: None,
            compression: WriteCompression::None,
            compression_values: WriteCompressionValues::default(),
            hashes: WriteHashes::default(),
            maximum_segment_size: None,
            overwrite_existing: false,
            secondary_segment_filename: None,
            media_size: None,
            metadata: EwfMetadata::default(),
            header_codepage: HeaderCodepage::Ascii,
            header_values_date_format: HeaderDateFormat::Ctime,
            acquisition_errors: Vec::new(),
            checksum_errors: Vec::new(),
            sessions: Vec::new(),
            tracks: Vec::new(),
            media_profile: WriteMediaProfile::default(),
            memory_extents: Vec::new(),
            single_files: None,
            ewf2_single_files_tables: SingleFilesAuxTables::default(),
            ewf2_increment_data: Vec::new(),
            ewf2_final_information: None,
            ewf2_restart_data: None,
            ewf2_analytical_data: None,
        }
    }
}

impl WriteOptions {
    /// Copies media geometry and flags from an opened image.
    ///
    /// # Errors
    ///
    /// Returns an error if the source image contains media values that cannot be
    /// represented by writer options.
    pub fn copy_media_values_from_image(&mut self, image: &Image) -> Result<()> {
        self.copy_media_values_from_info(image.info())
    }

    /// Copies media geometry and flags from parsed image metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the source metadata contains media values that cannot
    /// be represented by writer options.
    pub fn copy_media_values_from_info(&mut self, info: &ImageInfo) -> Result<()> {
        let mut candidate = self.clone();
        candidate.format = write_format_from_image_info(info);
        candidate.sectors_per_chunk =
            required_media_u32(info.media.sectors_per_chunk, "sectors per chunk")?;
        candidate.bytes_per_sector =
            required_media_u32(info.media.bytes_per_sector, "bytes per sector")?;
        candidate.set_identifier = info.media.set_identifier;
        candidate.media_size = Some(info.logical_size);
        candidate.media_profile = WriteMediaProfile {
            media_type: info.media.media_type,
            error_granularity: info.media.error_granularity,
            fastbloc: info.media.media_flags.fastbloc,
            tableau: info.media.media_flags.tableau,
        };
        let has_explicit_compression_values =
            info.media.compression_values != CompressionValues::default();
        candidate.compression_values = if has_explicit_compression_values {
            write_compression_values_from_media_values(info.media.compression_values)?
        } else {
            WriteCompressionValues::default()
        };
        if let Some(compression_method) = info.media.compression_method {
            candidate.compression = write_compression_from_media_method(compression_method)?;
        } else if has_explicit_compression_values
            && candidate.compression_values.level != WriteCompressionLevel::None
        {
            candidate.compression = WriteCompression::Zlib;
        } else {
            candidate.compression = WriteCompression::None;
        }
        validate_options(&candidate)?;
        *self = candidate;
        Ok(())
    }

    /// Copies header values from an opened image.
    pub fn copy_header_values_from_image(&mut self, image: &Image) {
        self.copy_header_values_from_info(image.info());
    }

    /// Copies header values from parsed image metadata.
    pub fn copy_header_values_from_info(&mut self, info: &ImageInfo) {
        self.copy_header_values_from_metadata(&info.metadata);
    }

    /// Copies header values from metadata.
    pub fn copy_header_values_from_metadata(&mut self, metadata: &EwfMetadata) {
        self.metadata.copy_header_values_from(metadata);
    }

    /// Copies stored hash values from an opened image.
    pub fn copy_hash_values_from_image(&mut self, image: &Image) {
        self.copy_hash_values_from_info(image.info());
    }

    /// Copies stored hash values from parsed image metadata.
    pub fn copy_hash_values_from_info(&mut self, info: &ImageInfo) {
        self.copy_hash_values_from_stored_hashes(&info.stored_hashes);
    }

    /// Copies stored hash values from a hash collection.
    pub fn copy_hash_values_from_stored_hashes(&mut self, hashes: &StoredHashes) {
        self.hashes.copy_hash_values_from_stored_hashes(hashes);
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
/// Output EWF format selected for writing.
pub enum WriteFormat {
    /// EWF1 physical `.E01` output.
    #[default]
    Ewf1Physical,
    /// EWF1 logical `.L01` output.
    Ewf1Logical,
    /// EWF1 SMART `.S01` output.
    Ewf1Smart,
    /// EWF2 physical `.Ex01` output.
    Ewf2Physical,
    /// EWF2 logical `.Lx01` output.
    Ewf2Logical,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// Hash values configured for writer output.
pub struct WriteHashes {
    /// MD5 hash bytes.
    pub md5: Option<[u8; 16]>,
    /// SHA1 hash bytes.
    pub sha1: Option<[u8; 20]>,
    /// Hash strings keyed by hash identifier.
    pub hash_values: BTreeMap<String, String>,
}

impl WriteHashes {
    /// Copies stored hash values from an image hash collection.
    pub fn copy_hash_values_from_stored_hashes(&mut self, hashes: &StoredHashes) {
        self.md5 = hashes.md5;
        self.sha1 = hashes.sha1;
        self.hash_values = hashes.hash_values.clone();
    }

    /// Returns a hash string by identifier.
    pub fn hash_value(&self, identifier: &str) -> Option<&str> {
        self.hash_values.get(identifier).map(String::as_str)
    }

    /// Sets a hash string by identifier and returns the previous value.
    ///
    /// `MD5` and `SHA1` values are also parsed into typed byte arrays.
    ///
    /// # Errors
    ///
    /// Returns an error if an `MD5`, `SHA1`, or `SHA256` value is not valid hexadecimal of
    /// the required length.
    pub fn set_hash_value(
        &mut self,
        identifier: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Option<String>> {
        let identifier = identifier.into();
        let value = value.into();
        if identifier.eq_ignore_ascii_case("SHA256") {
            crate::hashes::validate_digest(&identifier, &value)?;
        }
        if identifier.eq_ignore_ascii_case("MD5") {
            self.md5 = Some(parse_writer_hash_value("MD5", &value)?);
        } else if identifier.eq_ignore_ascii_case("SHA1") {
            self.sha1 = Some(parse_writer_hash_value("SHA1", &value)?);
        }
        Ok(self.hash_values.insert(identifier, value))
    }

    /// Returns the number of configured hash strings.
    pub fn number_of_hash_values(&self) -> usize {
        self.hash_values.len()
    }

    /// Returns a hash identifier by enumeration index.
    pub fn hash_value_identifier(&self, index: usize) -> Option<&str> {
        self.hash_values.keys().nth(index).map(String::as_str)
    }
}

fn parse_writer_hash_value<const N: usize>(label: &str, value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 {
        return Err(EwfError::Unsupported(format!("invalid {label} hash value")));
    }

    let mut bytes = [0; N];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = writer_hash_nibble(pair[0])
            .ok_or_else(|| EwfError::Unsupported(format!("invalid {label} hash value")))?;
        let low = writer_hash_nibble(pair[1])
            .ok_or_else(|| EwfError::Unsupported(format!("invalid {label} hash value")))?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

fn writer_hash_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
/// Media type and acquisition flags configured for writer output.
pub struct WriteMediaProfile {
    /// Media type to write.
    pub media_type: Option<MediaType>,
    /// Error granularity in sectors.
    pub error_granularity: Option<u64>,
    /// `FastBloc` acquisition flag.
    pub fastbloc: bool,
    /// Tableau acquisition flag.
    pub tableau: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
/// Compression method for writer output.
pub enum WriteCompression {
    /// Store chunks without compression.
    #[default]
    None,
    /// Compress chunks with zlib.
    Zlib,
    /// Compress chunks with `BZip2`.
    Bzip2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Compression settings for writer output.
pub struct WriteCompressionValues {
    /// Compression level.
    pub level: WriteCompressionLevel,
    /// Whether empty-block compression flags should be written.
    pub empty_block: bool,
}

impl Default for WriteCompressionValues {
    fn default() -> Self {
        Self {
            level: WriteCompressionLevel::Default,
            empty_block: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
/// Compression level for writer output.
pub enum WriteCompressionLevel {
    /// Use the compressor default level.
    #[default]
    Default,
    /// Do not compress.
    None,
    /// Prefer faster compression.
    Fast,
    /// Prefer stronger compression.
    Best,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Result returned after finalizing writer output.
pub struct WriteResult {
    /// Output segment paths or labels.
    pub segment_paths: Vec<PathBuf>,
    /// Mirrored secondary output segment paths.
    pub secondary_segment_paths: Vec<PathBuf>,
    /// Logical media size written in bytes.
    pub logical_size: u64,
    /// Logical chunk size written in bytes.
    pub chunk_size: u64,
    /// Number of logical chunks written.
    pub chunk_count: u64,
    /// SHA256 of the written logical media, including sector padding.
    /// EWF1 complete output also embeds it unless a reference was supplied.
    /// EWF2 has no SHA256 section here; retain this value externally.
    pub computed_sha256: [u8; 32],
}

/// Incremental EWF writer.
///
/// The writer buffers media data until [`EwfWriter::finish`] or another finish
/// method is called. Geometry and format options must be configured before
/// media data is written.
pub struct EwfWriter {
    path: PathBuf,
    options: WriteOptions,
    chunk_size: u64,
    chunk_capacity: usize,
    raw: RawSpool,
    encoded_chunks: BTreeMap<u64, RememberedEncodedChunk>,
    current_offset: u64,
    logical_input_size: u64,
    abort_signaled: AtomicBool,
}

struct PreparedWrite {
    path: PathBuf,
    options: WriteOptions,
    chunks: Vec<ChunkDescriptor>,
    spool: ChunkSpool,
    logical_size: u64,
    chunk_size: u64,
    chunk_count: u64,
    chunk_count_u32: u32,
    sector_count: u64,
    computed_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalSection {
    Done,
    Next,
}

impl TerminalSection {
    fn ewf1_type(self) -> &'static [u8; 4] {
        match self {
            Self::Done => b"done",
            Self::Next => b"next",
        }
    }

    fn ewf2_type(self) -> u32 {
        match self {
            Self::Done => EWF2_DONE_SECTION,
            Self::Next => EWF2_NEXT_SECTION,
        }
    }
}

impl std::fmt::Debug for EwfWriter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EwfWriter")
            .field("path", &self.path)
            .field("options", &self.options)
            .field("chunk_size", &self.chunk_size)
            .field("chunk_capacity", &self.chunk_capacity)
            .field("raw", &"<temporary>")
            .field("raw_spooled_bytes", &self.raw.len())
            .field("encoded_chunks", &self.encoded_chunks.len())
            .field("current_offset", &self.current_offset)
            .field("logical_input_size", &self.logical_input_size)
            .field(
                "abort_signaled",
                &self.abort_signaled.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl EwfWriter {
    /// Creates a new writer for a file-backed EWF segment set.
    ///
    /// # Errors
    ///
    /// Returns an error if options are invalid, the secondary segment filename
    /// conflicts with the primary filename, or temporary spool creation fails.
    pub fn create(path: impl AsRef<Path>, mut options: WriteOptions) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        options.maximum_segment_size = normalize_maximum_segment_size(options.maximum_segment_size);
        options.media_size = normalize_media_size(options.media_size);
        validate_options(&options)?;
        validate_secondary_segment_filename(&path, options.secondary_segment_filename.as_deref())?;
        let (chunk_size, chunk_capacity) =
            writer_chunk_geometry(options.sectors_per_chunk, options.bytes_per_sector)?;

        Ok(Self {
            path,
            options,
            chunk_size,
            chunk_capacity,
            raw: RawSpool::new()?,
            encoded_chunks: BTreeMap::new(),
            current_offset: 0,
            logical_input_size: 0,
            abort_signaled: AtomicBool::new(false),
        })
    }

    /// Creates a writer initialized from an existing image and copies its media.
    ///
    /// # Errors
    ///
    /// Returns an error if the source image cannot be represented by the writer,
    /// media copying fails, or writer creation fails.
    pub fn create_from_image(path: impl AsRef<Path>, image: &Image) -> Result<Self> {
        let options = rewrite_options_from_image_info(image.info())?;
        let mut writer = Self::create(path, options)?;
        copy_image_media_to_writer(image, &mut writer)?;
        Ok(writer)
    }

    /// Opens an existing image and prepares a writer that can append or rewrite it.
    ///
    /// # Errors
    ///
    /// Returns an error if the existing image cannot be opened, copied, or
    /// represented by writer options.
    pub fn resume<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        // Resuming rewrites the image in place, so it must not go past damage
        // (and drop the metadata) the way lenient opening does.
        let image = Image::open_with_options(
            &path,
            crate::OpenOptions::default().with_strictness(crate::OpenStrictness::Strict),
        )?;
        let mut writer = Self::create_from_image(&path, &image)?;
        writer.options.media_size = None;
        writer.options.overwrite_existing = true;
        Ok(writer)
    }

    /// Returns the first output segment filename.
    pub fn filename(&self) -> &Path {
        self.path.as_path()
    }

    /// Returns the first output segment filename.
    pub fn segment_filename(&self) -> &Path {
        self.path.as_path()
    }

    /// Sets the first output segment filename.
    pub fn set_segment_filename(&mut self, path: impl AsRef<Path>) {
        self.path = path.as_ref().to_path_buf();
    }

    /// Returns the first mirrored secondary output segment filename.
    pub fn secondary_segment_filename(&self) -> Option<&Path> {
        self.options.secondary_segment_filename.as_deref()
    }

    /// Sets the first mirrored secondary output segment filename.
    ///
    /// # Errors
    ///
    /// Returns an error if the secondary filename conflicts with the primary
    /// output filename.
    pub fn set_secondary_segment_filename(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref().to_path_buf();
        validate_secondary_segment_filename(&self.path, Some(&path))?;
        self.options.secondary_segment_filename = Some(path);
        Ok(())
    }

    /// Clears mirrored secondary output.
    pub fn clear_secondary_segment_filename(&mut self) {
        self.options.secondary_segment_filename = None;
    }

    /// Writes all bytes at the current writer position.
    ///
    /// # Errors
    ///
    /// Returns an error if the writer has been aborted or writing would exceed
    /// configured limits.
    pub fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.ensure_not_aborted()?;
        self.write_to_current(data)?;
        Ok(())
    }

    /// Writes bytes at the current writer position and returns the byte count.
    ///
    /// # Errors
    ///
    /// Returns an error if the writer has been aborted or writing would exceed
    /// configured limits.
    pub fn write_buffer(&mut self, data: &[u8]) -> Result<usize> {
        self.ensure_not_aborted()?;
        self.write_to_current(data)
    }

    /// Writes bytes at an absolute logical byte offset.
    ///
    /// # Errors
    ///
    /// Returns an error if the writer has been aborted or writing would exceed
    /// configured limits.
    pub fn write_at(&mut self, data: &[u8], offset: u64) -> Result<usize> {
        self.ensure_not_aborted()?;
        self.current_offset = offset;
        self.write_to_current(data)
    }

    /// Alias for [`EwfWriter::write_at`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`EwfWriter::write_at`].
    pub fn write_buffer_at_offset(&mut self, data: &[u8], offset: u64) -> Result<usize> {
        self.write_at(data, offset)
    }

    /// Writes a decoded data chunk at the current writer position.
    ///
    /// # Errors
    ///
    /// Returns an error if the chunk metadata is inconsistent, the writer has
    /// been aborted, or writing would exceed configured limits.
    pub fn write_data_chunk(&mut self, chunk: &DataChunk) -> Result<usize> {
        self.ensure_not_aborted()?;
        validate_write_data_chunk(chunk)?;
        self.write_to_current(&chunk.data)
    }

    /// Decodes and writes an encoded data chunk at the current writer position.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded chunk cannot be decoded, the writer has
    /// been aborted, or writing would exceed configured limits.
    pub fn write_encoded_data_chunk(&mut self, chunk: &EncodedDataChunk) -> Result<usize> {
        self.ensure_not_aborted()?;
        let data = decode_write_encoded_data_chunk(chunk)?;
        let offset = self.current_offset;
        let written = self.write_to_current(&data)?;
        self.remember_encoded_data_chunk_at(chunk, offset, data.len());
        Ok(written)
    }

    /// Writes a decoded data chunk at an absolute logical byte offset.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`EwfWriter::write_data_chunk`] and
    /// [`EwfWriter::write_at`].
    pub fn write_data_chunk_at(&mut self, chunk: &DataChunk, offset: u64) -> Result<usize> {
        self.ensure_not_aborted()?;
        validate_write_data_chunk(chunk)?;
        self.write_at(&chunk.data, offset)
    }

    /// Decodes and writes an encoded data chunk at an absolute logical byte offset.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`EwfWriter::write_encoded_data_chunk`] and
    /// [`EwfWriter::write_at`].
    pub fn write_encoded_data_chunk_at(
        &mut self,
        chunk: &EncodedDataChunk,
        offset: u64,
    ) -> Result<usize> {
        self.ensure_not_aborted()?;
        let data = decode_write_encoded_data_chunk(chunk)?;
        self.current_offset = offset;
        let written = self.write_to_current(&data)?;
        self.remember_encoded_data_chunk_at(chunk, offset, data.len());
        Ok(written)
    }

    /// Returns the configured output format.
    pub fn format(&self) -> WriteFormat {
        self.options.format
    }

    /// Sets the output format before media data is written.
    ///
    /// # Errors
    ///
    /// Returns an error if media data has already been written or the new option
    /// combination is unsupported.
    pub fn set_format(&mut self, format: WriteFormat) -> Result<()> {
        self.ensure_configuration_mutable("format")?;
        let mut options = self.options.clone();
        options.format = format;
        validate_options(&options)?;
        self.options = options;
        Ok(())
    }

    /// Returns the current logical byte write position.
    pub fn position(&self) -> u64 {
        self.current_offset
    }

    /// Returns the current logical chunk size in bytes.
    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }

    /// Returns the configured sectors per chunk.
    pub fn sectors_per_chunk(&self) -> u32 {
        self.options.sectors_per_chunk
    }

    /// Sets sectors per chunk before media data is written.
    ///
    /// # Errors
    ///
    /// Returns an error if media data has already been written or the resulting
    /// chunk geometry is invalid.
    pub fn set_sectors_per_chunk(&mut self, sectors_per_chunk: u32) -> Result<()> {
        self.ensure_configuration_mutable("sectors per chunk")?;
        let (chunk_size, chunk_capacity) =
            writer_chunk_geometry(sectors_per_chunk, self.options.bytes_per_sector)?;
        let mut options = self.options.clone();
        options.sectors_per_chunk = sectors_per_chunk;
        validate_options(&options)?;
        self.options = options;
        self.chunk_size = chunk_size;
        self.chunk_capacity = chunk_capacity;
        self.encoded_chunks.clear();
        Ok(())
    }

    /// Returns the configured bytes per sector.
    pub fn bytes_per_sector(&self) -> u32 {
        self.options.bytes_per_sector
    }

    /// Sets bytes per sector before media data is written.
    ///
    /// # Errors
    ///
    /// Returns an error if media data has already been written or the resulting
    /// chunk geometry is invalid.
    pub fn set_bytes_per_sector(&mut self, bytes_per_sector: u32) -> Result<()> {
        self.ensure_configuration_mutable("bytes per sector")?;
        let (chunk_size, chunk_capacity) =
            writer_chunk_geometry(self.options.sectors_per_chunk, bytes_per_sector)?;
        let mut options = self.options.clone();
        options.bytes_per_sector = bytes_per_sector;
        validate_options(&options)?;
        self.options = options;
        self.chunk_size = chunk_size;
        self.chunk_capacity = chunk_capacity;
        self.encoded_chunks.clear();
        Ok(())
    }

    /// Returns the logical size that would be written after sector padding.
    ///
    /// # Errors
    ///
    /// Returns an error if configured sizes overflow or are inconsistent.
    pub fn logical_size(&self) -> Result<u64> {
        padded_logical_size(
            target_media_input_size(self.logical_input_size, self.options.media_size)?,
            self.options.bytes_per_sector,
        )
    }

    /// Alias for [`EwfWriter::logical_size`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`EwfWriter::logical_size`].
    pub fn media_size(&self) -> Result<u64> {
        self.logical_size()
    }

    /// Returns the logical sector count that would be written.
    ///
    /// # Errors
    ///
    /// Returns an error if the logical size cannot be computed.
    pub fn number_of_sectors(&self) -> Result<u64> {
        Ok(self.media_size()? / u64::from(self.options.bytes_per_sector))
    }

    /// Returns the configured maximum segment size in bytes.
    pub fn maximum_segment_size(&self) -> Option<u64> {
        self.options.maximum_segment_size
    }

    /// Sets the maximum segment size before media data is written.
    ///
    /// # Errors
    ///
    /// Returns an error if media data has already been written or the value is
    /// invalid for the current output format.
    pub fn set_maximum_segment_size(&mut self, maximum_segment_size: Option<u64>) -> Result<()> {
        self.ensure_configuration_mutable("maximum segment size")?;
        let mut options = self.options.clone();
        options.maximum_segment_size = normalize_maximum_segment_size(maximum_segment_size);
        validate_options(&options)?;
        self.options = options;
        Ok(())
    }

    /// Sets the declared logical media size before media data is written.
    ///
    /// # Errors
    ///
    /// Returns an error if media data has already been written or the requested
    /// size is smaller than data already written.
    pub fn set_media_size(&mut self, media_size: u64) -> Result<()> {
        self.ensure_configuration_mutable("media size")?;
        let media_size = normalize_media_size(Some(media_size));
        if media_size.is_some_and(|media_size| self.logical_input_size > media_size) {
            return Err(EwfError::Unsupported(
                "writer configured media size is smaller than written data".into(),
            ));
        }
        self.options.media_size = media_size;
        Ok(())
    }

    /// Returns the number of logical chunks that would be written.
    ///
    /// # Errors
    ///
    /// Returns an error if the logical size cannot be computed.
    pub fn number_of_chunks_written(&self) -> Result<u64> {
        Ok(self.logical_size()?.div_ceil(self.chunk_size))
    }

    /// Returns the configured segment set identifier.
    pub fn segment_file_set_identifier(&self) -> Option<[u8; 16]> {
        self.options.set_identifier
    }

    /// Signals future writer operations to abort with [`EwfError::Aborted`].
    pub fn signal_abort(&self) {
        self.abort_signaled.store(true, Ordering::Relaxed);
    }

    /// Sets the segment set identifier before media data is written.
    ///
    /// # Errors
    ///
    /// Returns an error if media data has already been written.
    pub fn set_segment_file_set_identifier(&mut self, set_identifier: [u8; 16]) -> Result<()> {
        self.ensure_configuration_mutable("set identifier")?;
        self.options.set_identifier = Some(set_identifier);
        Ok(())
    }

    /// Returns the configured compression method.
    pub fn compression_method(&self) -> WriteCompression {
        self.options.compression
    }

    /// Sets the compression method before media data is written.
    ///
    /// # Errors
    ///
    /// Returns an error if media data has already been written or `BZip2` is
    /// selected for an EWF1 output format.
    pub fn set_compression_method(&mut self, compression: WriteCompression) -> Result<()> {
        self.ensure_configuration_mutable("compression method")?;
        if matches!(compression, WriteCompression::Bzip2) && !is_ewf2_format(self.options.format) {
            return Err(EwfError::Unsupported(
                "BZip2 writer compression is only supported for EWF2".into(),
            ));
        }
        self.options.compression = compression;
        Ok(())
    }

    /// Returns the configured compression values.
    pub fn compression_values(&self) -> WriteCompressionValues {
        self.options.compression_values
    }

    /// Sets compression values before media data is written.
    ///
    /// # Errors
    ///
    /// Returns an error if media data has already been written.
    pub fn set_compression_values(
        &mut self,
        compression_values: WriteCompressionValues,
    ) -> Result<()> {
        self.ensure_configuration_mutable("compression values")?;
        self.options.compression_values = compression_values;
        Ok(())
    }

    /// Returns the configured media type.
    pub fn media_type(&self) -> Option<MediaType> {
        self.options.media_profile.media_type
    }

    /// Sets the media type before media data is written.
    ///
    /// # Errors
    ///
    /// Returns an error if media data has already been written.
    pub fn set_media_type(&mut self, media_type: Option<MediaType>) -> Result<()> {
        self.ensure_configuration_mutable("media type")?;
        self.options.media_profile.media_type = media_type;
        Ok(())
    }

    /// Returns the configured error granularity in sectors.
    pub fn error_granularity(&self) -> Option<u64> {
        self.options.media_profile.error_granularity
    }

    /// Sets error granularity before media data is written.
    ///
    /// # Errors
    ///
    /// Returns an error if media data has already been written.
    pub fn set_error_granularity(&mut self, error_granularity: Option<u64>) -> Result<()> {
        self.ensure_configuration_mutable("error granularity")?;
        self.options.media_profile.error_granularity = error_granularity;
        Ok(())
    }

    /// Returns media flags derived from format and media profile options.
    pub fn media_flags(&self) -> MediaFlags {
        writer_media_flags(self.options.format, self.options.media_profile)
    }

    /// Sets writable media flags before media data is written.
    ///
    /// The physical flag is controlled by [`WriteFormat`] and cannot be changed
    /// independently.
    ///
    /// # Errors
    ///
    /// Returns an error if media data has already been written or if the
    /// physical flag conflicts with the output format.
    pub fn set_media_flags(&mut self, media_flags: MediaFlags) -> Result<()> {
        self.ensure_configuration_mutable("media flags")?;
        if media_flags.physical != write_format_is_physical(self.options.format) {
            return Err(EwfError::Unsupported(
                "writer physical media flag is controlled by image format".into(),
            ));
        }
        self.options.media_profile.fastbloc = media_flags.fastbloc;
        self.options.media_profile.tableau = media_flags.tableau;
        Ok(())
    }

    /// Copies media geometry and flags from an opened image.
    ///
    /// # Errors
    ///
    /// Returns an error if the source values cannot be represented or conflict
    /// with media data already written.
    pub fn copy_media_values_from_image(&mut self, image: &Image) -> Result<()> {
        self.copy_media_values_from_info(image.info())
    }

    /// Copies media geometry and flags from parsed image metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the source values cannot be represented or conflict
    /// with media data already written.
    pub fn copy_media_values_from_info(&mut self, info: &ImageInfo) -> Result<()> {
        let mut options = self.options.clone();
        options.copy_media_values_from_info(info)?;
        if options
            .media_size
            .is_some_and(|media_size| self.logical_input_size > media_size)
        {
            return Err(EwfError::Unsupported(
                "writer configured media size is smaller than written data".into(),
            ));
        }
        let (chunk_size, chunk_capacity) =
            writer_chunk_geometry(options.sectors_per_chunk, options.bytes_per_sector)?;
        self.options = options;
        self.chunk_size = chunk_size;
        self.chunk_capacity = chunk_capacity;
        Ok(())
    }

    /// Returns a configured header value by EWF identifier.
    pub fn header_value(&self, identifier: &str) -> Option<std::borrow::Cow<'_, str>> {
        self.options
            .metadata
            .header_value_with_date_format(identifier, self.options.header_values_date_format)
    }

    /// Returns the configured header codepage.
    pub fn header_codepage(&self) -> HeaderCodepage {
        self.options.header_codepage
    }

    /// Sets the header codepage.
    pub fn set_header_codepage(&mut self, header_codepage: HeaderCodepage) {
        self.options.header_codepage = header_codepage;
    }

    /// Returns the configured header date format.
    pub fn header_values_date_format(&self) -> HeaderDateFormat {
        self.options.header_values_date_format
    }

    /// Sets the header date format.
    pub fn set_header_values_date_format(&mut self, date_format: HeaderDateFormat) {
        self.options.header_values_date_format = date_format;
    }

    /// Copies header values from an opened image.
    pub fn copy_header_values_from_image(&mut self, image: &Image) {
        self.copy_header_values_from_info(image.info());
    }

    /// Copies header values from parsed image metadata.
    pub fn copy_header_values_from_info(&mut self, info: &ImageInfo) {
        self.copy_header_values_from_metadata(&info.metadata);
    }

    /// Copies header values from metadata.
    pub fn copy_header_values_from_metadata(&mut self, metadata: &EwfMetadata) {
        self.options.copy_header_values_from_metadata(metadata);
    }

    /// Copies stored hash values from an opened image.
    pub fn copy_hash_values_from_image(&mut self, image: &Image) {
        self.copy_hash_values_from_info(image.info());
    }

    /// Copies stored hash values from parsed image metadata.
    pub fn copy_hash_values_from_info(&mut self, info: &ImageInfo) {
        self.copy_hash_values_from_stored_hashes(&info.stored_hashes);
    }

    /// Copies stored hash values from a hash collection.
    pub fn copy_hash_values_from_stored_hashes(&mut self, hashes: &StoredHashes) {
        self.options.copy_hash_values_from_stored_hashes(hashes);
    }

    /// Sets a header value by EWF identifier and returns the previous value.
    pub fn set_header_value(
        &mut self,
        identifier: &str,
        value: impl Into<String>,
    ) -> Option<String> {
        self.options.metadata.set_header_value(identifier, value)
    }

    /// Returns the number of configured header values.
    pub fn number_of_header_values(&self) -> usize {
        self.options.metadata.number_of_header_values()
    }

    /// Returns a configured header value identifier by enumeration index.
    pub fn header_value_identifier(&self, index: usize) -> Option<&str> {
        self.options.metadata.header_value_identifier(index)
    }

    /// Returns a configured hash string by identifier.
    pub fn hash_value(&self, identifier: &str) -> Option<&str> {
        self.options.hashes.hash_value(identifier)
    }

    /// Sets a configured hash string by identifier and returns the previous value.
    ///
    /// # Errors
    ///
    /// Returns an error if an `MD5`, `SHA1`, or `SHA256` value is not valid hexadecimal of
    /// the required length.
    pub fn set_hash_value(
        &mut self,
        identifier: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Option<String>> {
        self.options.hashes.set_hash_value(identifier, value)
    }

    /// Returns the number of configured hash strings.
    pub fn number_of_hash_values(&self) -> usize {
        self.options.hashes.number_of_hash_values()
    }

    /// Returns a configured hash identifier by enumeration index.
    pub fn hash_value_identifier(&self, index: usize) -> Option<&str> {
        self.options.hashes.hash_value_identifier(index)
    }

    /// Returns the configured MD5 hash bytes.
    pub fn md5_hash(&self) -> Option<[u8; 16]> {
        self.options.hashes.md5
    }

    /// Sets the configured MD5 hash bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if an MD5 hash is already configured.
    pub fn set_md5_hash(&mut self, md5: [u8; 16]) -> Result<()> {
        if self.options.hashes.md5.is_some() {
            return Err(EwfError::Unsupported("MD5 hash cannot be changed".into()));
        }
        self.options.hashes.md5 = Some(md5);
        self.options
            .hashes
            .hash_values
            .entry("MD5".to_string())
            .or_insert_with(|| hex_string(&md5));
        Ok(())
    }

    /// Returns the configured SHA1 hash bytes.
    pub fn sha1_hash(&self) -> Option<[u8; 20]> {
        self.options.hashes.sha1
    }

    /// Sets the configured SHA1 hash bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if a SHA1 hash is already configured.
    pub fn set_sha1_hash(&mut self, sha1: [u8; 20]) -> Result<()> {
        if self.options.hashes.sha1.is_some() {
            return Err(EwfError::Unsupported("SHA1 hash cannot be changed".into()));
        }
        self.options.hashes.sha1 = Some(sha1);
        self.options
            .hashes
            .hash_values
            .entry("SHA1".to_string())
            .or_insert_with(|| hex_string(&sha1));
        Ok(())
    }

    /// Returns configured acquisition error ranges.
    pub fn acquisition_errors(&self) -> &[AcquisitionError] {
        &self.options.acquisition_errors
    }

    /// Returns the number of configured acquisition error ranges.
    pub fn number_of_acquisition_errors(&self) -> usize {
        self.options.acquisition_errors.len()
    }

    /// Returns a configured acquisition error range by index.
    pub fn acquisition_error(&self, index: usize) -> Option<&AcquisitionError> {
        self.options.acquisition_errors.get(index)
    }

    /// Appends an acquisition error range.
    ///
    /// # Errors
    ///
    /// This method currently validates no additional constraints and returns
    /// `Ok(())` after appending.
    pub fn append_acquisition_error(&mut self, first_sector: u64, sector_count: u64) -> Result<()> {
        self.options.acquisition_errors.push(AcquisitionError {
            first_sector,
            sector_count,
        });
        Ok(())
    }

    /// Returns configured checksum error ranges.
    pub fn checksum_errors(&self) -> &[SectorRange] {
        &self.options.checksum_errors
    }

    /// Returns the number of configured checksum error ranges.
    pub fn number_of_checksum_errors(&self) -> usize {
        self.options.checksum_errors.len()
    }

    /// Returns a configured checksum error range by index.
    pub fn checksum_error(&self, index: usize) -> Option<&SectorRange> {
        self.options.checksum_errors.get(index)
    }

    /// Appends a checksum error range.
    ///
    /// # Errors
    ///
    /// This method currently validates no additional constraints and returns
    /// `Ok(())` after appending.
    pub fn append_checksum_error(&mut self, first_sector: u64, sector_count: u64) -> Result<()> {
        self.options.checksum_errors.push(SectorRange {
            first_sector,
            sector_count,
        });
        Ok(())
    }

    /// Returns configured session sector ranges.
    pub fn sessions(&self) -> &[SectorRange] {
        &self.options.sessions
    }

    /// Returns the number of configured session sector ranges.
    pub fn number_of_sessions(&self) -> usize {
        self.options.sessions.len()
    }

    /// Returns a configured session sector range by index.
    pub fn session(&self, index: usize) -> Option<&SectorRange> {
        self.options.sessions.get(index)
    }

    /// Appends a session sector range.
    ///
    /// # Errors
    ///
    /// Returns an error if the range values exceed the signed 64-bit range
    /// required by EWF metadata.
    pub fn append_session(&mut self, first_sector: u64, sector_count: u64) -> Result<()> {
        validate_signed_sector_range_value("session", "start sector", first_sector)?;
        validate_signed_sector_range_value("session", "sector count", sector_count)?;
        self.options.sessions.push(SectorRange {
            first_sector,
            sector_count,
        });
        Ok(())
    }

    /// Returns configured track sector ranges.
    pub fn tracks(&self) -> &[SectorRange] {
        &self.options.tracks
    }

    /// Returns the number of configured track sector ranges.
    pub fn number_of_tracks(&self) -> usize {
        self.options.tracks.len()
    }

    /// Returns a configured track sector range by index.
    pub fn track(&self, index: usize) -> Option<&SectorRange> {
        self.options.tracks.get(index)
    }

    /// Appends a track sector range.
    ///
    /// # Errors
    ///
    /// Returns an error if the range values exceed the signed 64-bit range
    /// required by EWF metadata.
    pub fn append_track(&mut self, first_sector: u64, sector_count: u64) -> Result<()> {
        validate_signed_sector_range_value("track", "start sector", first_sector)?;
        validate_signed_sector_range_value("track", "sector count", sector_count)?;
        self.options.tracks.push(SectorRange {
            first_sector,
            sector_count,
        });
        Ok(())
    }

    /// Returns the current logical byte write position.
    pub fn offset(&self) -> u64 {
        self.current_offset
    }

    /// Seeks the writer position and returns the new position.
    ///
    /// # Errors
    ///
    /// Returns an error if the seek would move before the start of the media or
    /// beyond representable bounds.
    pub fn seek_offset(&mut self, position: SeekFrom) -> Result<u64> {
        self.seek_position(position)
    }

    /// Seeks the writer position and returns the new position.
    ///
    /// # Errors
    ///
    /// Returns an error if the seek would move before the start of the media or
    /// beyond representable bounds.
    pub fn seek_position(&mut self, position: SeekFrom) -> Result<u64> {
        let end_size = target_media_input_size(self.logical_input_size, self.options.media_size)?;
        let next = checked_writer_seek(self.current_offset, end_size, position)?;
        self.current_offset = next;
        Ok(next)
    }

    /// Finalizes a complete image and writes a terminal `done` marker.
    ///
    /// # Errors
    ///
    /// Returns an error if output cannot be prepared, encoded, written, flushed,
    /// or mirrored.
    pub fn finish(self) -> Result<WriteResult> {
        self.finish_with_terminal_section(TerminalSection::Done)
    }

    /// Finalizes an incomplete image with a continuation marker.
    ///
    /// # Errors
    ///
    /// Returns an error if output cannot be prepared, encoded, written, flushed,
    /// or mirrored.
    pub fn finish_incomplete(self) -> Result<WriteResult> {
        self.finish_with_terminal_section(TerminalSection::Next)
    }

    /// Recovers an interrupted file-backed publication. Pass the actual first
    /// segment filename and the original secondary first filename, if any.
    /// Uncommitted output is rolled back; committed output is retained. Returns
    /// false if no journal exists. Recovery refuses a currently active writer.
    pub fn recover_output(path: impl AsRef<Path>, secondary: Option<&Path>) -> Result<bool> {
        crate::publication::Publication::recover(path.as_ref(), secondary)
    }

    fn finish_with_terminal_section(self, terminal: TerminalSection) -> Result<WriteResult> {
        let PreparedWrite {
            path,
            options,
            chunks,
            mut spool,
            logical_size,
            chunk_size,
            chunk_count,
            chunk_count_u32,
            sector_count,
            computed_sha256,
        } = self.prepare_write()?;
        let is_v2 = is_ewf2_format(options.format);
        let path_for_segment = if is_v2 {
            ewf2_segment_path
        } else {
            segment_path
        };
        let groups = segment_groups(
            &chunks,
            options.maximum_segment_size,
            &options,
            sector_count,
            u64::from(chunk_count_u32),
        )?;
        let group_count = groups.len();
        let segment_paths = (1..=group_count)
            .map(|index| path_for_segment(&path, index))
            .collect::<Result<Vec<_>>>()?;
        let secondary_segment_paths = if let Some(base) = &options.secondary_segment_filename {
            let paths = (1..=group_count)
                .map(|index| path_for_segment(base, index))
                .collect::<Result<Vec<_>>>()?;
            for secondary in &paths {
                ensure_secondary_segment_path_is_distinct(&segment_paths, secondary)?;
            }
            paths
        } else {
            Vec::new()
        };
        let mut publication = crate::publication::Publication::begin(
            &segment_paths[0],
            secondary_segment_paths.first().map(PathBuf::as_path),
            options.overwrite_existing,
        )?;
        let mut first_chunk = 0_u64;
        for (index, group) in groups.into_iter().enumerate() {
            let group_chunks = &chunks[group];
            let is_last = index + 1 == group_count;
            let staged = publication.stage(0, &segment_paths[index])?;
            let mut file = File::create(&staged)?;
            if is_v2 {
                write_ewf2_segment(
                    &mut file,
                    &mut spool,
                    group_chunks,
                    &options,
                    Ewf2SegmentWriteContext {
                        segment_number: u32::try_from(index + 1).map_err(|_| {
                            EwfError::Unsupported("EWF2 writer segment count exceeds u32".into())
                        })?,
                        first_chunk,
                        total_chunk_count: chunk_count_u32,
                        sector_count,
                        terminal_section_type: if is_last {
                            terminal.ewf2_type()
                        } else {
                            EWF2_NEXT_SECTION
                        },
                    },
                )?;
            } else {
                write_ewf1_segment(
                    &mut file,
                    &mut spool,
                    group_chunks,
                    &options,
                    Ewf1SegmentWriteContext {
                        segment_number: u16::try_from(index + 1).map_err(|_| {
                            EwfError::Unsupported("EWF1 writer segment count exceeds u16".into())
                        })?,
                        chunk_count: chunk_count_u32,
                        sector_count,
                        sections: Ewf1SegmentSections::for_segment(
                            index == 0,
                            is_last && terminal == TerminalSection::Done,
                        ),
                        terminal_section: if is_last {
                            terminal
                        } else {
                            TerminalSection::Done
                        },
                    },
                )?;
            }
            file.sync_all()?;
            drop(file);
            if let Some(secondary) = secondary_segment_paths.get(index) {
                let mirror = publication.stage(1, secondary)?;
                fs::copy(&staged, &mirror)?;
                fs::OpenOptions::new()
                    .write(true)
                    .open(mirror)?
                    .sync_all()?;
            }
            first_chunk += group_chunks.len() as u64;
        }
        let mut destinations = vec![publication_segment_paths(&segment_paths, is_v2)?];
        if !secondary_segment_paths.is_empty() {
            destinations.push(publication_segment_paths(&secondary_segment_paths, is_v2)?);
        }
        publication.publish(&destinations, group_count)?;
        Ok(WriteResult {
            segment_paths,
            secondary_segment_paths,
            logical_size,
            chunk_size,
            chunk_count,
            computed_sha256,
        })
    }

    /// Alias for [`EwfWriter::finish`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`EwfWriter::finish`].
    pub fn write_finalize(self) -> Result<WriteResult> {
        self.finish()
    }

    /// Finalizes the image to one supplied writer.
    ///
    /// # Errors
    ///
    /// Returns an error if the image requires multiple output segments, if
    /// secondary output is configured, or if output preparation/writing fails.
    pub fn finish_to_writer<W: Write>(self, writer: &mut W) -> Result<WriteResult> {
        let path = self.path.clone();
        self.finish_to_segment_writers([(path, writer)])
    }

    /// Finalizes the image to explicitly supplied segment writers.
    ///
    /// The number of supplied writers must match the number of output segments
    /// implied by the current writer configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if secondary output is configured, if the writer count
    /// does not match the computed segment count, or if output
    /// preparation/writing fails.
    pub fn finish_to_segment_writers<P, W, I>(self, segment_writers: I) -> Result<WriteResult>
    where
        P: Into<PathBuf>,
        W: Write,
        I: IntoIterator<Item = (P, W)>,
    {
        let PreparedWrite {
            path: _,
            options,
            chunks,
            mut spool,
            logical_size,
            chunk_size,
            chunk_count,
            chunk_count_u32,
            sector_count,
            computed_sha256,
        } = self.prepare_write()?;
        if options.secondary_segment_filename.is_some() {
            return Err(EwfError::Unsupported(
                "secondary segment output requires file-backed finish".into(),
            ));
        }

        let segment_writers: Vec<_> = segment_writers
            .into_iter()
            .map(|(path, writer)| (path.into(), writer))
            .collect();
        let groups = segment_groups(
            &chunks,
            options.maximum_segment_size,
            &options,
            sector_count,
            u64::from(chunk_count_u32),
        )?;
        if segment_writers.len() != groups.len() {
            return Err(EwfError::Unsupported(
                "finish_to_segment_writers requires exactly one writer per output segment".into(),
            ));
        }
        let group_count = groups.len();
        let mut segment_paths = Vec::with_capacity(group_count);

        if is_ewf2_format(options.format) {
            let mut first_chunk = 0_u64;
            for (index, ((segment_path, mut writer), group)) in
                segment_writers.into_iter().zip(groups).enumerate()
            {
                let group_chunks = &chunks[group];
                let segment_number = u32::try_from(index + 1).map_err(|_| {
                    EwfError::Unsupported("EWF2 writer segment count exceeds u32".into())
                })?;
                let terminal_section_type = if index + 1 == group_count {
                    EWF2_DONE_SECTION
                } else {
                    EWF2_NEXT_SECTION
                };
                write_ewf2_segment(
                    &mut writer,
                    &mut spool,
                    group_chunks,
                    &options,
                    Ewf2SegmentWriteContext {
                        segment_number,
                        first_chunk,
                        total_chunk_count: chunk_count_u32,
                        sector_count,
                        terminal_section_type,
                    },
                )?;
                writer.flush()?;
                first_chunk = first_chunk
                    .checked_add(u64::try_from(group_chunks.len()).expect("usize fits u64"))
                    .ok_or_else(|| {
                        EwfError::Malformed("writer EWF2 first chunk overflow".into())
                    })?;
                segment_paths.push(segment_path);
            }
        } else {
            for (index, ((segment_path, mut writer), group)) in
                segment_writers.into_iter().zip(groups).enumerate()
            {
                let group_chunks = &chunks[group];
                let segment_number = u16::try_from(index + 1).map_err(|_| {
                    EwfError::Unsupported("EWF1 writer segment count exceeds u16".into())
                })?;
                let sections =
                    Ewf1SegmentSections::for_segment(index == 0, index + 1 == group_count);
                write_ewf1_segment(
                    &mut writer,
                    &mut spool,
                    group_chunks,
                    &options,
                    Ewf1SegmentWriteContext {
                        segment_number,
                        chunk_count: chunk_count_u32,
                        sector_count,
                        sections,
                        terminal_section: TerminalSection::Done,
                    },
                )?;
                writer.flush()?;
                segment_paths.push(segment_path);
            }
        }

        Ok(WriteResult {
            segment_paths,
            secondary_segment_paths: Vec::new(),
            logical_size,
            chunk_size,
            chunk_count,
            computed_sha256,
        })
    }

    fn write_to_current(&mut self, data: &[u8]) -> Result<usize> {
        self.ensure_not_aborted()?;
        let data_len = u64::try_from(data.len())
            .map_err(|_| EwfError::Malformed("writer data length does not fit u64".into()))?;
        let end_offset = self
            .current_offset
            .checked_add(data_len)
            .ok_or_else(|| EwfError::Malformed("writer logical input size overflow".into()))?;
        if self
            .options
            .media_size
            .is_some_and(|media_size| end_offset > media_size)
        {
            return Err(EwfError::Unsupported(
                "writer write exceeds configured media size".into(),
            ));
        }
        self.forget_encoded_chunks_in_range(self.current_offset, end_offset);
        self.raw.write_at(self.current_offset, data)?;
        self.current_offset = end_offset;
        self.logical_input_size = self.logical_input_size.max(end_offset);
        Ok(data.len())
    }

    fn prepare_write(self) -> Result<PreparedWrite> {
        self.ensure_not_aborted()?;
        let logical_size = self.logical_size()?;
        let sector_count = logical_size / u64::from(self.options.bytes_per_sector);

        let EwfWriter {
            path,
            mut options,
            chunk_size,
            chunk_capacity,
            mut raw,
            encoded_chunks,
            ..
        } = self;

        let EncodedSpool {
            chunks,
            spool,
            computed_md5,
            computed_sha1,
            computed_sha256,
        } = encode_raw_spool(
            &mut raw,
            encoded_chunks,
            logical_size,
            chunk_capacity,
            chunk_size,
            &options,
        )?;

        options.hashes = effective_write_hashes(
            &options.hashes,
            computed_md5,
            computed_sha1,
            computed_sha256,
        )?;
        validate_session_ranges("sessions", &options.sessions, sector_count)?;
        validate_session_ranges("tracks", &options.tracks, sector_count)?;
        let chunk_count = u64::try_from(chunks.len())
            .map_err(|_| EwfError::Malformed("writer chunk count does not fit u64".into()))?;
        let chunk_count_u32 = u32::try_from(chunk_count)
            .map_err(|_| EwfError::Unsupported("writer chunk count exceeds u32".into()))?;

        Ok(PreparedWrite {
            path,
            options,
            chunks,
            spool,
            logical_size,
            chunk_size,
            chunk_count,
            chunk_count_u32,
            sector_count,
            computed_sha256,
        })
    }

    fn ensure_not_aborted(&self) -> Result<()> {
        if self.abort_signaled.load(Ordering::Relaxed) {
            return Err(EwfError::Aborted);
        }
        Ok(())
    }

    fn ensure_configuration_mutable(&self, label: &str) -> Result<()> {
        if self.logical_input_size == 0 {
            return Ok(());
        }
        Err(EwfError::Unsupported(format!(
            "writer {label} cannot be changed after media data has been written"
        )))
    }

    fn remember_encoded_data_chunk_at(
        &mut self,
        chunk: &EncodedDataChunk,
        offset: u64,
        decoded_len: usize,
    ) {
        let Some(encoded) = remembered_encoded_data_chunk(
            chunk,
            &self.options,
            self.chunk_size,
            offset,
            decoded_len,
        ) else {
            return;
        };
        self.encoded_chunks
            .insert(offset / self.chunk_size, encoded);
    }

    fn forget_encoded_chunks_in_range(&mut self, start_offset: u64, end_offset: u64) {
        if start_offset >= end_offset || self.encoded_chunks.is_empty() {
            return;
        }

        let first_chunk = start_offset / self.chunk_size;
        let last_chunk = (end_offset - 1) / self.chunk_size;
        let keys: Vec<_> = self
            .encoded_chunks
            .range(first_chunk..=last_chunk)
            .map(|(chunk_index, _)| *chunk_index)
            .collect();
        for chunk_index in keys {
            self.encoded_chunks.remove(&chunk_index);
        }
    }
}

fn target_media_input_size(written_size: u64, configured_media_size: Option<u64>) -> Result<u64> {
    match configured_media_size {
        Some(media_size) if written_size > media_size => Err(EwfError::Unsupported(
            "writer configured media size is smaller than written data".into(),
        )),
        Some(media_size) => Ok(media_size),
        None => Ok(written_size),
    }
}

fn padded_logical_size(logical_input_size: u64, bytes_per_sector: u32) -> Result<u64> {
    let bytes_per_sector = u64::from(bytes_per_sector);
    let sector_count = logical_input_size.div_ceil(bytes_per_sector);
    sector_count
        .checked_mul(bytes_per_sector)
        .ok_or_else(|| EwfError::Malformed("writer logical size overflow".into()))
}

fn required_media_u32(value: Option<u64>, label: &str) -> Result<u32> {
    let value = value.ok_or_else(|| {
        EwfError::Unsupported(format!("cannot copy media values without {label}"))
    })?;
    u32::try_from(value)
        .map_err(|_| EwfError::Unsupported(format!("copied {label} does not fit u32")))
}

fn write_format_from_image_info(info: &ImageInfo) -> WriteFormat {
    match info.format {
        Format::Ewf2 if image_info_is_physical(info) => WriteFormat::Ewf2Physical,
        Format::Ewf2 => WriteFormat::Ewf2Logical,
        Format::Ewf1 if info.format_profile == FormatProfile::Smart => WriteFormat::Ewf1Smart,
        Format::Ewf1 if image_info_is_physical(info) => WriteFormat::Ewf1Physical,
        Format::Ewf1 => WriteFormat::Ewf1Logical,
    }
}

fn image_info_is_physical(info: &ImageInfo) -> bool {
    !matches!(info.media.media_type, Some(MediaType::SingleFiles))
        && info.media.media_flags.physical
}

fn write_compression_from_media_method(method: CompressionMethod) -> Result<WriteCompression> {
    match method {
        CompressionMethod::None => Ok(WriteCompression::None),
        CompressionMethod::Zlib => Ok(WriteCompression::Zlib),
        CompressionMethod::Zstd => Err(EwfError::Unsupported(
            "cannot copy X-Ways Zstandard compression settings".into(),
        )),
        CompressionMethod::Bzip2 => Ok(WriteCompression::Bzip2),
        CompressionMethod::Unknown(value) => Err(EwfError::Unsupported(format!(
            "cannot copy unknown compression method {value}"
        ))),
    }
}

fn write_compression_values_from_media_values(
    values: CompressionValues,
) -> Result<WriteCompressionValues> {
    if values.flags.pattern_fill {
        return Err(EwfError::Unsupported(
            "cannot copy pattern fill compression flag".into(),
        ));
    }
    if values.flags.unknown_bits != 0 {
        return Err(EwfError::Unsupported(format!(
            "cannot copy unknown compression flags 0x{:02x}",
            values.flags.unknown_bits
        )));
    }

    Ok(WriteCompressionValues {
        level: write_compression_level_from_media_level(values.level)?,
        empty_block: values.flags.empty_block,
    })
}

fn write_compression_level_from_media_level(
    level: CompressionLevel,
) -> Result<WriteCompressionLevel> {
    match level {
        CompressionLevel::Default => Ok(WriteCompressionLevel::Default),
        CompressionLevel::None => Ok(WriteCompressionLevel::None),
        CompressionLevel::Fast => Ok(WriteCompressionLevel::Fast),
        CompressionLevel::Best => Ok(WriteCompressionLevel::Best),
        CompressionLevel::Unknown(value) => Err(EwfError::Unsupported(format!(
            "cannot copy unknown compression level {value}"
        ))),
    }
}

fn rewrite_options_from_image_info(info: &ImageInfo) -> Result<WriteOptions> {
    let mut options = WriteOptions::default();
    options.copy_media_values_from_info(info)?;
    options.copy_header_values_from_info(info);
    options.header_codepage = info.header_codepage;
    options.header_values_date_format = info.header_values_date_format;
    options
        .acquisition_errors
        .clone_from(&info.acquisition_errors);
    options.sessions.clone_from(&info.sessions);
    options.tracks.clone_from(&info.tracks);
    options.memory_extents.clone_from(&info.memory_extents);
    options.single_files.clone_from(&info.single_files);
    options.ewf2_single_files_tables = info.ewf2_single_files_tables.clone();
    options
        .ewf2_increment_data
        .clone_from(&info.ewf2_increment_data);
    options
        .ewf2_final_information
        .clone_from(&info.ewf2_final_information);
    options
        .ewf2_restart_data
        .clone_from(&info.ewf2_restart_data);
    options
        .ewf2_analytical_data
        .clone_from(&info.ewf2_analytical_data);
    validate_options(&options)?;
    Ok(options)
}

fn copy_image_media_to_writer(image: &Image, writer: &mut EwfWriter) -> Result<()> {
    if let Some(chunk_count) = image.number_of_chunks() {
        for chunk_index in 0..chunk_count {
            let chunk = image.read_encoded_data_chunk(chunk_index)?;
            writer.write_encoded_data_chunk(&chunk)?;
        }
        return Ok(());
    }

    copy_image_media_bytes_to_writer(image, writer)
}

fn copy_image_media_bytes_to_writer(image: &Image, writer: &mut EwfWriter) -> Result<()> {
    let media_size = image.media_size();
    let buffer_size = writer.chunk_capacity.clamp(1, 1024 * 1024);
    let mut buffer = vec![0; buffer_size];
    let mut offset = 0_u64;

    while offset < media_size {
        let remaining = media_size - offset;
        let take = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("source image copy is bounded by buffer length");
        let read = image.read_at(&mut buffer[..take], offset)?;
        if read != take {
            return Err(EwfError::Malformed(format!(
                "source image read returned {read} bytes, expected {take}"
            )));
        }
        writer.write_all(&buffer[..take])?;
        offset = offset
            .checked_add(u64::try_from(take).expect("usize fits u64"))
            .ok_or_else(|| EwfError::Malformed("source image copy offset overflow".into()))?;
    }

    Ok(())
}

impl std::io::Write for EwfWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_all(buf).map_err(std::io::Error::other)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl std::io::Seek for EwfWriter {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.seek_position(pos).map_err(std::io::Error::other)
    }

    fn stream_position(&mut self) -> std::io::Result<u64> {
        Ok(self.current_offset)
    }
}

#[derive(Clone)]
struct WriteHashState {
    md5: Md5,
    sha1: Sha1,
    sha256: Sha256,
}

impl WriteHashState {
    fn new() -> Self {
        Self {
            md5: Md5::new(),
            sha1: Sha1::new(),
            sha256: Sha256::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.md5.update(data);
        self.sha1.update(data);
        self.sha256.update(data);
    }

    fn finalize(self) -> ([u8; 16], [u8; 20], [u8; 32]) {
        (
            self.md5.finalize().into(),
            self.sha1.finalize().into(),
            self.sha256.finalize().into(),
        )
    }
}

fn validate_options(options: &WriteOptions) -> Result<()> {
    validated_write_hashes(&options.hashes)?;
    if options.sectors_per_chunk == 0 {
        return Err(EwfError::Malformed(
            "writer sectors_per_chunk is zero".into(),
        ));
    }
    if options.bytes_per_sector == 0 {
        return Err(EwfError::Malformed(
            "writer bytes_per_sector is zero".into(),
        ));
    }
    if options.format == WriteFormat::Ewf2Logical
        && u64::from(options.sectors_per_chunk) * u64::from(options.bytes_per_sector) < 8192
    {
        return Err(EwfError::Unsupported(
            "EWF2 logical output requires chunks of at least 8192 bytes for libewf interoperability"
                .into(),
        ));
    }
    if matches!(options.compression, WriteCompression::Bzip2) && !is_ewf2_format(options.format) {
        return Err(EwfError::Unsupported(
            "BZip2 writer compression is only supported for EWF2".into(),
        ));
    }
    if matches!(options.compression, WriteCompression::Bzip2)
        && options.compression_values.level == WriteCompressionLevel::None
    {
        return Err(EwfError::Unsupported(
            "BZip2 writer compression does not support none compression level".into(),
        ));
    }
    if options.single_files.is_some()
        && !matches!(
            options.format,
            WriteFormat::Ewf1Logical | WriteFormat::Ewf2Logical
        )
    {
        return Err(EwfError::Unsupported(
            "single files catalog writing is only supported for logical images".into(),
        ));
    }
    if !options.ewf2_single_files_tables.is_empty() && options.format != WriteFormat::Ewf2Logical {
        return Err(EwfError::Unsupported(
            "single files auxiliary table writing is only supported for EWF2 logical images".into(),
        ));
    }
    if !options.memory_extents.is_empty() && !is_ewf2_format(options.format) {
        return Err(EwfError::Unsupported(
            "memory extents writing is only supported for EWF2 images".into(),
        ));
    }
    if (!options.ewf2_increment_data.is_empty() || options.ewf2_final_information.is_some())
        && !is_ewf2_format(options.format)
    {
        return Err(EwfError::Unsupported(
            "opaque EWF2 section writing is only supported for EWF2 images".into(),
        ));
    }
    if (options.ewf2_restart_data.is_some() || options.ewf2_analytical_data.is_some())
        && !is_ewf2_format(options.format)
    {
        return Err(EwfError::Unsupported(
            "EWF2 application data writing is only supported for EWF2 images".into(),
        ));
    }
    Ok(())
}

fn normalize_maximum_segment_size(maximum_segment_size: Option<u64>) -> Option<u64> {
    maximum_segment_size.filter(|size| *size != 0)
}

fn normalize_media_size(media_size: Option<u64>) -> Option<u64> {
    media_size.filter(|size| *size != 0)
}

fn writer_chunk_geometry(sectors_per_chunk: u32, bytes_per_sector: u32) -> Result<(u64, usize)> {
    if sectors_per_chunk == 0 {
        return Err(EwfError::Malformed(
            "writer sectors_per_chunk is zero".into(),
        ));
    }
    if bytes_per_sector == 0 {
        return Err(EwfError::Malformed(
            "writer bytes_per_sector is zero".into(),
        ));
    }

    let chunk_size = u64::from(sectors_per_chunk)
        .checked_mul(u64::from(bytes_per_sector))
        .ok_or_else(|| EwfError::Malformed("writer chunk size overflow".into()))?;
    let chunk_capacity = usize::try_from(chunk_size)
        .map_err(|_| EwfError::Unsupported("writer chunk size does not fit usize".into()))?;
    Ok((chunk_size, chunk_capacity))
}

fn validate_write_data_chunk(chunk: &DataChunk) -> Result<()> {
    if chunk.corrupted {
        return Err(EwfError::Malformed(
            "writer cannot write corrupted data chunk".into(),
        ));
    }
    if chunk.data.len() != chunk.logical_size {
        return Err(EwfError::Malformed(
            "writer data chunk payload length does not match logical size".into(),
        ));
    }

    Ok(())
}

fn decode_write_encoded_data_chunk(chunk: &EncodedDataChunk) -> Result<Vec<u8>> {
    validate_write_encoded_data_chunk(chunk)?;
    decode_chunk(
        &chunk.data,
        encoded_data_chunk_encoding(chunk.encoding),
        chunk.logical_size,
    )
}

fn validate_write_encoded_data_chunk(chunk: &EncodedDataChunk) -> Result<()> {
    if chunk.encoding == DataChunkEncoding::Zstd {
        return Err(EwfError::Unsupported(
            "writer does not support X-Ways Zstandard encoded chunks".into(),
        ));
    }
    let encoded_size = usize::try_from(chunk.encoded_size)
        .map_err(|_| EwfError::Malformed("writer encoded chunk size does not fit usize".into()))?;
    if chunk.data.len() != encoded_size {
        return Err(EwfError::Malformed(
            "writer encoded data chunk payload length does not match encoded size".into(),
        ));
    }

    Ok(())
}

fn encoded_data_chunk_encoding(encoding: DataChunkEncoding) -> ChunkEncoding {
    match encoding {
        DataChunkEncoding::Raw => ChunkEncoding::Raw,
        DataChunkEncoding::Zlib => ChunkEncoding::Zlib,
        DataChunkEncoding::Zstd => ChunkEncoding::Zstd,
        DataChunkEncoding::Bzip2 => ChunkEncoding::Bzip2,
        DataChunkEncoding::PatternFill(pattern) => ChunkEncoding::PatternFill(pattern),
    }
}

fn remembered_encoded_data_chunk(
    chunk: &EncodedDataChunk,
    options: &WriteOptions,
    target_chunk_size: u64,
    offset: u64,
    decoded_len: usize,
) -> Option<RememberedEncodedChunk> {
    if !offset.is_multiple_of(target_chunk_size) || decoded_len != chunk.logical_size {
        return None;
    }
    if u64::try_from(decoded_len).ok()? > target_chunk_size {
        return None;
    }
    if !encoded_data_chunk_encoding_compatible(chunk.encoding, options) {
        return None;
    }
    if validate_encoded_size(
        chunk.encoded_size,
        target_chunk_size,
        encoded_data_chunk_encoding(chunk.encoding),
    )
    .is_err()
    {
        return None;
    }

    let encoded = match chunk.encoding {
        DataChunkEncoding::Raw => {
            if chunk.has_checksum && !raw_encoded_data_chunk_checksum_is_valid(chunk) {
                return None;
            }
            EncodedChunk {
                bytes: chunk.data.clone(),
                compressed: false,
                has_checksum: chunk.has_checksum,
                pattern_fill: None,
            }
        }
        DataChunkEncoding::Zlib | DataChunkEncoding::Bzip2 => EncodedChunk {
            bytes: chunk.data.clone(),
            compressed: true,
            has_checksum: false,
            pattern_fill: None,
        },
        DataChunkEncoding::Zstd => return None,
        DataChunkEncoding::PatternFill(pattern) => EncodedChunk {
            bytes: Vec::new(),
            compressed: true,
            has_checksum: false,
            pattern_fill: Some(pattern),
        },
    };

    Some(RememberedEncodedChunk {
        logical_size: decoded_len,
        encoding: chunk.encoding,
        encoded,
    })
}

fn encoded_data_chunk_encoding_compatible(
    encoding: DataChunkEncoding,
    options: &WriteOptions,
) -> bool {
    match encoding {
        DataChunkEncoding::Raw => true,
        DataChunkEncoding::Zlib => options.compression != WriteCompression::Bzip2,
        DataChunkEncoding::Zstd => false,
        DataChunkEncoding::Bzip2 => {
            is_ewf2_format(options.format) && options.compression == WriteCompression::Bzip2
        }
        DataChunkEncoding::PatternFill(_) => is_ewf2_format(options.format),
    }
}

fn raw_encoded_data_chunk_checksum_is_valid(chunk: &EncodedDataChunk) -> bool {
    let Some(checksum_offset) = chunk.logical_size.checked_add(4) else {
        return false;
    };
    if chunk.data.len() != checksum_offset {
        return false;
    }
    let expected = adler32(&chunk.data[..chunk.logical_size]).to_le_bytes();
    chunk.data[chunk.logical_size..] == expected
}

fn validate_session_ranges(
    label: &str,
    ranges: &[SectorRange],
    media_sector_count: u64,
) -> Result<()> {
    validate_sector_ranges(label, ranges, media_sector_count)?;
    if ranges.is_empty() {
        return Ok(());
    }

    let mut expected_start = 0_u64;
    for range in ranges {
        if range.first_sector != expected_start {
            return Err(EwfError::Unsupported(format!(
                "writer {label} must cover the media contiguously from sector 0"
            )));
        }
        expected_start = range
            .first_sector
            .checked_add(range.sector_count)
            .ok_or_else(|| EwfError::Malformed(format!("writer {label} range overflow")))?;
    }
    if expected_start != media_sector_count {
        return Err(EwfError::Unsupported(format!(
            "writer {label} must end at the media sector count"
        )));
    }

    Ok(())
}

fn validate_sector_ranges(
    label: &str,
    ranges: &[SectorRange],
    media_sector_count: u64,
) -> Result<()> {
    let mut previous_end = 0_u64;
    for range in ranges {
        if range.sector_count == 0 {
            return Err(EwfError::Unsupported(format!(
                "writer {label} cannot contain zero-length ranges"
            )));
        }
        if range.first_sector < previous_end {
            return Err(EwfError::Unsupported(format!(
                "writer {label} ranges must be sorted and non-overlapping"
            )));
        }
        let end = range
            .first_sector
            .checked_add(range.sector_count)
            .ok_or_else(|| EwfError::Malformed(format!("writer {label} range overflow")))?;
        if end > media_sector_count {
            return Err(EwfError::Unsupported(format!(
                "writer {label} range exceeds the media sector count"
            )));
        }
        previous_end = end;
    }

    Ok(())
}

fn validate_signed_sector_range_value(label: &str, field: &str, value: u64) -> Result<()> {
    if value > SIGNED_SECTOR_RANGE_MAX {
        return Err(EwfError::Unsupported(format!(
            "writer {label} {field} exceeds signed 64-bit range"
        )));
    }
    Ok(())
}

fn write_ewf1_segment<W: Write>(
    writer: &mut W,
    spool: &mut ChunkSpool,
    chunks: &[ChunkDescriptor],
    options: &WriteOptions,
    context: Ewf1SegmentWriteContext,
) -> Result<()> {
    u32::try_from(chunks.len())
        .map_err(|_| EwfError::Unsupported("EWF1 writer segment chunk count exceeds u32".into()))?;
    let header = if context.sections.contains(Ewf1SegmentSections::HEADER) {
        header_payload(
            &options.metadata,
            options.header_codepage,
            options.compression_values.level,
        )?
    } else {
        None
    };
    let header2 = if context.sections.contains(Ewf1SegmentSections::HEADER) {
        header2_payload(&options.metadata, options.compression_values.level)?
    } else {
        None
    };
    let xheader = if context.sections.contains(Ewf1SegmentSections::HEADER) {
        xheader_payload(&options.metadata, options.compression_values.level)?
    } else {
        None
    };
    let digest = context
        .sections
        .contains(Ewf1SegmentSections::DIGEST)
        .then(|| digest_payload(&options.hashes))
        .flatten();
    let xhash = if context.sections.contains(Ewf1SegmentSections::DIGEST) {
        xhash_payload(&options.hashes, options.compression_values.level)?
    } else {
        None
    };
    let error2 = if context.sections.contains(Ewf1SegmentSections::ERRORS) {
        ewf1_error2_payload(&options.acquisition_errors)?
    } else {
        None
    };
    let session = if context.sections.contains(Ewf1SegmentSections::SESSIONS) {
        ewf1_session_payload(&options.sessions, &options.tracks)?
    } else {
        None
    };
    let ltree = if context.sections.contains(Ewf1SegmentSections::DIGEST)
        && options.format == WriteFormat::Ewf1Logical
    {
        options
            .single_files
            .as_ref()
            .map(ewf1_ltree_payload)
            .transpose()?
    } else {
        None
    };
    let header_desc_offset = ewf1::FILE_HEADER_SIZE as u64;
    let volume_data_size = volume_data_size(options.format);
    let header2_desc_offset = if let Some(header) = &header {
        header_desc_offset
            .checked_add(ewf1::SECTION_DESCRIPTOR_SIZE as u64)
            .and_then(|value| value.checked_add(u64::try_from(header.len()).ok()?))
            .ok_or_else(|| EwfError::Malformed("writer volume descriptor offset overflow".into()))?
    } else {
        header_desc_offset
    };
    let xheader_desc_offset = if let Some(header2) = &header2 {
        header2_desc_offset
            .checked_add(ewf1::SECTION_DESCRIPTOR_SIZE as u64)
            .and_then(|value| value.checked_add(u64::try_from(header2.len()).ok()?))
            .ok_or_else(|| EwfError::Malformed("writer volume descriptor offset overflow".into()))?
    } else {
        header2_desc_offset
    };
    let volume_desc_offset = if let Some(xheader) = &xheader {
        xheader_desc_offset
            .checked_add(ewf1::SECTION_DESCRIPTOR_SIZE as u64)
            .and_then(|value| value.checked_add(u64::try_from(xheader.len()).ok()?))
            .ok_or_else(|| EwfError::Malformed("writer volume descriptor offset overflow".into()))?
    } else {
        xheader_desc_offset
    };
    let volume_data_offset = volume_desc_offset + ewf1::SECTION_DESCRIPTOR_SIZE as u64;
    let session_desc_offset = volume_data_offset + volume_data_size;
    let sectors_desc_offset = if let Some(session) = &session {
        session_desc_offset
            .checked_add(ewf1::SECTION_DESCRIPTOR_SIZE as u64)
            .and_then(|value| value.checked_add(u64::try_from(session.len()).ok()?))
            .ok_or_else(|| {
                EwfError::Malformed("writer sectors descriptor offset overflow".into())
            })?
    } else {
        session_desc_offset
    };
    let table_footer_bytes = if matches!(options.format, WriteFormat::Ewf1Smart) {
        0
    } else {
        4
    };
    let writes_table2 = matches!(
        options.format,
        WriteFormat::Ewf1Physical | WriteFormat::Ewf1Logical
    );
    let group_layouts = ewf1_table_group_layouts(
        chunks,
        sectors_desc_offset,
        table_footer_bytes,
        writes_table2,
    )?;
    let post_table_desc_offset = group_layouts
        .last()
        .map_or(sectors_desc_offset, |layout| layout.end_offset);
    let ltree_desc_offset = post_table_desc_offset;
    let error2_desc_offset = if let Some(ltree) = &ltree {
        ltree_desc_offset
            .checked_add(ewf1::SECTION_DESCRIPTOR_SIZE as u64)
            .and_then(|value| value.checked_add(u64::try_from(ltree.len()).ok()?))
            .ok_or_else(|| EwfError::Malformed("writer error2 descriptor offset overflow".into()))?
    } else {
        post_table_desc_offset
    };
    let digest_desc_offset = if let Some(error2) = &error2 {
        error2_desc_offset
            .checked_add(ewf1::SECTION_DESCRIPTOR_SIZE as u64)
            .and_then(|value| value.checked_add(u64::try_from(error2.len()).ok()?))
            .ok_or_else(|| EwfError::Malformed("writer digest descriptor offset overflow".into()))?
    } else {
        error2_desc_offset
    };
    let xhash_desc_offset = if let Some(digest) = &digest {
        digest_desc_offset
            .checked_add(ewf1::SECTION_DESCRIPTOR_SIZE as u64)
            .and_then(|value| value.checked_add(u64::try_from(digest.len()).ok()?))
            .ok_or_else(|| EwfError::Malformed("writer xhash descriptor offset overflow".into()))?
    } else {
        digest_desc_offset
    };
    let done_desc_offset = if let Some(xhash) = &xhash {
        xhash_desc_offset
            .checked_add(ewf1::SECTION_DESCRIPTOR_SIZE as u64)
            .and_then(|value| value.checked_add(u64::try_from(xhash.len()).ok()?))
            .ok_or_else(|| EwfError::Malformed("writer done descriptor offset overflow".into()))?
    } else {
        xhash_desc_offset
    };
    let after_tables_desc_offset = if ltree.is_some() {
        ltree_desc_offset
    } else if error2.is_some() {
        error2_desc_offset
    } else if digest.is_some() {
        digest_desc_offset
    } else if xhash.is_some() {
        xhash_desc_offset
    } else {
        done_desc_offset
    };
    let after_ltree_desc_offset = if error2.is_some() {
        error2_desc_offset
    } else if digest.is_some() {
        digest_desc_offset
    } else if xhash.is_some() {
        xhash_desc_offset
    } else {
        done_desc_offset
    };
    let after_error2_desc_offset = if digest.is_some() {
        digest_desc_offset
    } else if xhash.is_some() {
        xhash_desc_offset
    } else {
        done_desc_offset
    };
    let after_digest_desc_offset = if xhash.is_some() {
        xhash_desc_offset
    } else {
        done_desc_offset
    };

    writer.write_all(ewf1_signature(options.format))?;
    writer.write_all(&[1])?;
    writer.write_all(&context.segment_number.to_le_bytes())?;
    writer.write_all(&0_u16.to_le_bytes())?;

    if let Some(header) = &header {
        writer.write_all(&section_desc(
            b"header",
            if header2.is_some() {
                header2_desc_offset
            } else if xheader.is_some() {
                xheader_desc_offset
            } else {
                volume_desc_offset
            },
            ewf1::SECTION_DESCRIPTOR_SIZE as u64
                + u64::try_from(header.len()).expect("usize fits u64"),
        ))?;
        writer.write_all(header)?;
    }

    if let Some(header2) = &header2 {
        writer.write_all(&section_desc(
            b"header2",
            if xheader.is_some() {
                xheader_desc_offset
            } else {
                volume_desc_offset
            },
            ewf1::SECTION_DESCRIPTOR_SIZE as u64
                + u64::try_from(header2.len()).expect("usize fits u64"),
        ))?;
        writer.write_all(header2)?;
    }

    if let Some(xheader) = &xheader {
        writer.write_all(&section_desc(
            b"xheader",
            volume_desc_offset,
            ewf1::SECTION_DESCRIPTOR_SIZE as u64
                + u64::try_from(xheader.len()).expect("usize fits u64"),
        ))?;
        writer.write_all(xheader)?;
    }

    writer.write_all(&section_desc(
        b"volume",
        if session.is_some() {
            session_desc_offset
        } else {
            sectors_desc_offset
        },
        ewf1::SECTION_DESCRIPTOR_SIZE as u64 + volume_data_size,
    ))?;
    writer.write_all(&volume_data(
        options,
        context.chunk_count,
        context.sector_count,
    )?)?;

    if let Some(session) = session {
        writer.write_all(&section_desc(
            b"session",
            sectors_desc_offset,
            ewf1::SECTION_DESCRIPTOR_SIZE as u64
                + u64::try_from(session.len()).expect("usize fits u64"),
        ))?;
        writer.write_all(&session)?;
    }

    for (group_index, layout) in group_layouts.iter().enumerate() {
        let group_chunks = &chunks[layout.first_chunk..layout.end_chunk];
        let group_chunk_count = u32::try_from(group_chunks.len()).map_err(|_| {
            EwfError::Unsupported("EWF1 writer table group chunk count exceeds u32".into())
        })?;
        let next_group_desc_offset = group_layouts
            .get(group_index + 1)
            .map_or(after_tables_desc_offset, |next| next.sectors_desc_offset);

        writer.write_all(&section_desc(
            b"sectors",
            layout.table_desc_offset,
            ewf1::SECTION_DESCRIPTOR_SIZE as u64 + layout.payload_size,
        ))?;
        for chunk in group_chunks {
            spool.copy_chunk_to(chunk, writer)?;
        }

        writer.write_all(&section_desc(
            b"table",
            layout.table2_desc_offset.unwrap_or(next_group_desc_offset),
            ewf1::SECTION_DESCRIPTOR_SIZE as u64 + layout.table_data_size,
        ))?;
        let table_capacity = usize::try_from(layout.table_data_size)
            .map_err(|_| EwfError::Malformed("writer table data size does not fit usize".into()))?;
        let mut table_data = Vec::with_capacity(table_capacity);
        append_ewf1_table_data(
            &mut table_data,
            group_chunk_count,
            layout.sectors_data_offset,
            group_chunks,
            table_footer_bytes != 0,
        )?;
        writer.write_all(&table_data)?;

        if layout.table2_desc_offset.is_some() {
            writer.write_all(&section_desc(
                b"table2",
                next_group_desc_offset,
                ewf1::SECTION_DESCRIPTOR_SIZE as u64 + layout.table_data_size,
            ))?;
            let mut table2_data = Vec::with_capacity(table_capacity);
            append_ewf1_table_data(
                &mut table2_data,
                group_chunk_count,
                layout.sectors_data_offset,
                group_chunks,
                true,
            )?;
            writer.write_all(&table2_data)?;
        }
    }

    if let Some(ltree) = &ltree {
        writer.write_all(&section_desc(
            b"ltree",
            after_ltree_desc_offset,
            ewf1::SECTION_DESCRIPTOR_SIZE as u64
                + u64::try_from(ltree.len()).expect("usize fits u64"),
        ))?;
        writer.write_all(ltree)?;
    }

    if let Some(error2) = error2 {
        writer.write_all(&section_desc(
            b"error2",
            after_error2_desc_offset,
            ewf1::SECTION_DESCRIPTOR_SIZE as u64
                + u64::try_from(error2.len()).expect("usize fits u64"),
        ))?;
        writer.write_all(&error2)?;
    }
    if let Some(digest) = digest {
        writer.write_all(&section_desc(
            b"digest",
            after_digest_desc_offset,
            ewf1::SECTION_DESCRIPTOR_SIZE as u64
                + u64::try_from(digest.len()).expect("usize fits u64"),
        ))?;
        writer.write_all(&digest)?;
    }
    if let Some(xhash) = xhash {
        writer.write_all(&section_desc(
            b"xhash",
            done_desc_offset,
            ewf1::SECTION_DESCRIPTOR_SIZE as u64
                + u64::try_from(xhash.len()).expect("usize fits u64"),
        ))?;
        writer.write_all(&xhash)?;
    }
    writer.write_all(&section_desc(
        context.terminal_section.ewf1_type(),
        done_desc_offset,
        ewf1::SECTION_DESCRIPTOR_SIZE as u64,
    ))?;

    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct Ewf1SegmentWriteContext {
    segment_number: u16,
    chunk_count: u32,
    sector_count: u64,
    sections: Ewf1SegmentSections,
    terminal_section: TerminalSection,
}

#[derive(Debug, Clone, Copy)]
struct Ewf1SegmentSections {
    bits: u8,
}

impl Ewf1SegmentSections {
    const HEADER: u8 = 1 << 0;
    const DIGEST: u8 = 1 << 1;
    const ERRORS: u8 = 1 << 2;
    const SESSIONS: u8 = 1 << 3;

    fn for_segment(is_first: bool, is_last: bool) -> Self {
        let mut bits = 0;
        if is_first {
            bits |= Self::HEADER | Self::ERRORS | Self::SESSIONS;
        }
        if is_last {
            bits |= Self::DIGEST;
        }
        Self { bits }
    }

    fn contains(self, flag: u8) -> bool {
        self.bits & flag != 0
    }
}

fn ewf1_signature(format: WriteFormat) -> &'static [u8; 8] {
    match format {
        WriteFormat::Ewf1Physical | WriteFormat::Ewf1Smart => &ewf1::EVF_SIGNATURE,
        WriteFormat::Ewf1Logical => &ewf1::LVF_SIGNATURE,
        WriteFormat::Ewf2Physical | WriteFormat::Ewf2Logical => {
            unreachable!("EWF2 formats are not EWF1")
        }
    }
}

fn is_ewf2_format(format: WriteFormat) -> bool {
    matches!(format, WriteFormat::Ewf2Physical | WriteFormat::Ewf2Logical)
}

fn write_format_is_physical(format: WriteFormat) -> bool {
    matches!(
        format,
        WriteFormat::Ewf1Physical | WriteFormat::Ewf1Smart | WriteFormat::Ewf2Physical
    )
}

fn writer_media_flags(format: WriteFormat, profile: WriteMediaProfile) -> MediaFlags {
    MediaFlags {
        physical: write_format_is_physical(format),
        fastbloc: profile.fastbloc,
        tableau: profile.tableau,
    }
}

#[derive(Debug, Clone, Copy)]
struct Ewf2SegmentWriteContext {
    segment_number: u32,
    first_chunk: u64,
    total_chunk_count: u32,
    sector_count: u64,
    terminal_section_type: u32,
}

#[derive(Debug, Clone, Copy)]
struct Ewf2SectionPlan {
    data_offset: u64,
    previous_desc_offset: u64,
}

fn plan_ewf2_section(
    current_offset: &mut u64,
    previous_desc_offset: &mut u64,
    data_size: u64,
    label: &str,
) -> Result<Ewf2SectionPlan> {
    let data_offset = *current_offset;
    let desc_offset = checked_add(data_offset, data_size, label)?;
    let section = Ewf2SectionPlan {
        data_offset,
        previous_desc_offset: *previous_desc_offset,
    };
    *current_offset = checked_add(
        desc_offset,
        ewf2::SECTION_DESCRIPTOR_SIZE as u64,
        "EWF2 next section",
    )?;
    *previous_desc_offset = desc_offset;
    Ok(section)
}

fn write_ewf2_section<W: Write>(
    writer: &mut W,
    section_type: u32,
    payload: &[u8],
    section: Ewf2SectionPlan,
) -> Result<()> {
    writer.write_all(payload)?;
    writer.write_all(&ewf2_section_desc(
        section_type,
        u64::try_from(payload.len()).expect("usize fits u64"),
        section.previous_desc_offset,
    ))?;
    Ok(())
}

fn write_ewf2_segment<W: Write>(
    writer: &mut W,
    spool: &mut ChunkSpool,
    chunks: &[ChunkDescriptor],
    options: &WriteOptions,
    context: Ewf2SegmentWriteContext,
) -> Result<()> {
    let local_chunk_count = u32::try_from(chunks.len())
        .map_err(|_| EwfError::Unsupported("EWF2 writer segment chunk count exceeds u32".into()))?;
    let device_information_payload = ewf2_device_information_payload(
        options,
        context.sector_count,
        u64::from(context.total_chunk_count),
    );
    let device_information =
        ewf2_device_information_section_payload(&device_information_payload, options)?;
    let case_data_payload = ewf2_case_data_payload(options, u64::from(context.total_chunk_count));
    let case_data = ewf2_metadata_section_payload(
        &case_data_payload,
        options.compression,
        options.compression_values.level,
    )?;
    let error_table = if context.segment_number == 1 {
        ewf2_error_table_payload(&options.acquisition_errors)?
    } else {
        None
    };
    let session_table = if context.segment_number == 1 {
        ewf2_session_table_payload(&options.sessions, &options.tracks)?
    } else {
        None
    };
    let memory_extents_table = if context.segment_number == 1 {
        ewf2_memory_extents_table_payload(&options.memory_extents)
    } else {
        None
    };
    let increment_data: &[Vec<u8>] = if context.segment_number == 1 {
        &options.ewf2_increment_data
    } else {
        &[]
    };
    // libewf completes the logical catalog while opening this segment and
    // rejects subsequent segments once that catalog exists. Keep all logical
    // catalog sections in the terminal segment, as with EWF1 ltree.
    let writes_hash_sections = context.terminal_section_type == EWF2_DONE_SECTION;
    let single_files_data = if writes_hash_sections {
        options
            .single_files
            .as_ref()
            .map(ewf2_single_files_data_payload)
            .transpose()?
    } else {
        None
    };
    let single_files_table_0x21 = if writes_hash_sections {
        ewf2_single_files_aux_u64_table_payload(
            &options.ewf2_single_files_tables.table_0x21_entries,
        )
    } else {
        None
    };
    let single_files_md5_hash_table = if writes_hash_sections {
        ewf2_single_files_md5_hash_table_payload(&options.ewf2_single_files_tables.md5_hashes)
    } else {
        None
    };
    let single_files_table_0x23 = if writes_hash_sections {
        ewf2_single_files_aux_u64_table_payload(
            &options.ewf2_single_files_tables.table_0x23_entries,
        )
    } else {
        None
    };
    let md5_hash = writes_hash_sections
        .then(|| options.hashes.md5.map(ewf2_hash_payload))
        .flatten();
    let sha1_hash = writes_hash_sections
        .then(|| options.hashes.sha1.map(ewf2_hash_payload))
        .flatten();
    let final_information = if writes_hash_sections {
        options.ewf2_final_information.as_deref()
    } else {
        None
    };
    let analytical_data = if writes_hash_sections {
        options
            .ewf2_analytical_data
            .as_deref()
            .map(|data| {
                ewf2_string_section_payload(
                    data,
                    options.compression,
                    options.compression_values.level,
                )
            })
            .transpose()?
    } else {
        None
    };
    let restart_data = if writes_hash_sections {
        options
            .ewf2_restart_data
            .as_deref()
            .map(|data| {
                ewf2_string_section_payload(
                    data,
                    options.compression,
                    options.compression_values.level,
                )
            })
            .transpose()?
    } else {
        None
    };
    let table_entry_bytes = u64::from(local_chunk_count)
        .checked_mul(ewf2::TABLE_ENTRY_SIZE as u64)
        .ok_or_else(|| EwfError::Malformed("writer EWF2 table entry size overflow".into()))?;
    let table_data_size = (EWF2_TABLE_HEADER_V2_SIZE as u64)
        .checked_add(table_entry_bytes)
        .and_then(|value| value.checked_add(EWF2_TABLE_FOOTER_SIZE as u64))
        .ok_or_else(|| EwfError::Malformed("writer EWF2 table size overflow".into()))?;
    let chunk_payload_size = chunks.iter().try_fold(0_u64, |total, chunk| {
        total
            .checked_add(chunk.data_size)
            .ok_or_else(|| EwfError::Malformed("writer EWF2 chunk payload size overflow".into()))
    })?;

    let mut current_offset = ewf2::FILE_HEADER_SIZE as u64;
    let mut previous_desc_offset = 0_u64;

    let device_section = plan_ewf2_section(
        &mut current_offset,
        &mut previous_desc_offset,
        u64::try_from(device_information.len()).expect("usize fits u64"),
        "EWF2 device information",
    )?;
    let case_section = plan_ewf2_section(
        &mut current_offset,
        &mut previous_desc_offset,
        u64::try_from(case_data.len()).expect("usize fits u64"),
        "EWF2 case data",
    )?;
    let error_section = error_table
        .as_ref()
        .map(|payload| {
            plan_ewf2_section(
                &mut current_offset,
                &mut previous_desc_offset,
                u64::try_from(payload.len()).expect("usize fits u64"),
                "EWF2 error table",
            )
        })
        .transpose()?;
    let session_section = session_table
        .as_ref()
        .map(|payload| {
            plan_ewf2_section(
                &mut current_offset,
                &mut previous_desc_offset,
                u64::try_from(payload.len()).expect("usize fits u64"),
                "EWF2 session table",
            )
        })
        .transpose()?;
    let memory_extents_section = memory_extents_table
        .as_ref()
        .map(|payload| {
            plan_ewf2_section(
                &mut current_offset,
                &mut previous_desc_offset,
                u64::try_from(payload.len()).expect("usize fits u64"),
                "EWF2 memory extents table",
            )
        })
        .transpose()?;

    let mut increment_sections = Vec::with_capacity(increment_data.len());
    for payload in increment_data {
        increment_sections.push(plan_ewf2_section(
            &mut current_offset,
            &mut previous_desc_offset,
            u64::try_from(payload.len()).expect("usize fits u64"),
            "EWF2 increment data",
        )?);
    }

    let single_files_section = single_files_data
        .as_ref()
        .map(|payload| {
            plan_ewf2_section(
                &mut current_offset,
                &mut previous_desc_offset,
                u64::try_from(payload.len()).expect("usize fits u64"),
                "EWF2 single files data",
            )
        })
        .transpose()?;
    let single_files_table_0x21_section = single_files_table_0x21
        .as_ref()
        .map(|payload| {
            plan_ewf2_section(
                &mut current_offset,
                &mut previous_desc_offset,
                u64::try_from(payload.len()).expect("usize fits u64"),
                "EWF2 single files 0x21 table",
            )
        })
        .transpose()?;
    let single_files_md5_hash_table_section = single_files_md5_hash_table
        .as_ref()
        .map(|payload| {
            plan_ewf2_section(
                &mut current_offset,
                &mut previous_desc_offset,
                u64::try_from(payload.len()).expect("usize fits u64"),
                "EWF2 single files MD5 hash table",
            )
        })
        .transpose()?;
    let single_files_table_0x23_section = single_files_table_0x23
        .as_ref()
        .map(|payload| {
            plan_ewf2_section(
                &mut current_offset,
                &mut previous_desc_offset,
                u64::try_from(payload.len()).expect("usize fits u64"),
                "EWF2 single files 0x23 table",
            )
        })
        .transpose()?;

    let sectors_section = plan_ewf2_section(
        &mut current_offset,
        &mut previous_desc_offset,
        chunk_payload_size,
        "EWF2 sector data",
    )?;
    let table_section = plan_ewf2_section(
        &mut current_offset,
        &mut previous_desc_offset,
        table_data_size,
        "EWF2 sector table",
    )?;
    let md5_section = md5_hash
        .as_ref()
        .map(|payload| {
            plan_ewf2_section(
                &mut current_offset,
                &mut previous_desc_offset,
                u64::try_from(payload.len()).expect("usize fits u64"),
                "EWF2 MD5 hash",
            )
        })
        .transpose()?;
    let sha1_section = sha1_hash
        .as_ref()
        .map(|payload| {
            plan_ewf2_section(
                &mut current_offset,
                &mut previous_desc_offset,
                u64::try_from(payload.len()).expect("usize fits u64"),
                "EWF2 SHA1 hash",
            )
        })
        .transpose()?;
    let final_information_section = final_information
        .map(|payload| {
            plan_ewf2_section(
                &mut current_offset,
                &mut previous_desc_offset,
                u64::try_from(payload.len()).expect("usize fits u64"),
                "EWF2 final information",
            )
        })
        .transpose()?;
    let analytical_section = analytical_data
        .as_ref()
        .map(|payload| {
            plan_ewf2_section(
                &mut current_offset,
                &mut previous_desc_offset,
                u64::try_from(payload.len()).expect("usize fits u64"),
                "EWF2 analytical data",
            )
        })
        .transpose()?;
    let restart_section = restart_data
        .as_ref()
        .map(|payload| {
            plan_ewf2_section(
                &mut current_offset,
                &mut previous_desc_offset,
                u64::try_from(payload.len()).expect("usize fits u64"),
                "EWF2 restart data",
            )
        })
        .transpose()?;
    let terminal_section = plan_ewf2_section(
        &mut current_offset,
        &mut previous_desc_offset,
        0,
        "EWF2 terminal",
    )?;

    writer.write_all(ewf2_signature(options.format))?;
    writer.write_all(&[2, 1])?;
    writer.write_all(&ewf2_compression_method(options.compression).to_le_bytes())?;
    writer.write_all(&context.segment_number.to_le_bytes())?;
    writer.write_all(&options.set_identifier.unwrap_or([0; 16]))?;

    write_ewf2_section(
        writer,
        EWF2_DEVICE_INFORMATION_SECTION,
        &device_information,
        device_section,
    )?;

    write_ewf2_section(writer, EWF2_CASE_DATA_SECTION, &case_data, case_section)?;

    if let (Some(error_table), Some(section)) = (&error_table, error_section) {
        write_ewf2_section(writer, EWF2_ERROR_TABLE_SECTION, error_table, section)?;
    }

    if let (Some(session_table), Some(section)) = (&session_table, session_section) {
        write_ewf2_section(writer, EWF2_SESSION_TABLE_SECTION, session_table, section)?;
    }

    if let (Some(memory_extents_table), Some(section)) =
        (&memory_extents_table, memory_extents_section)
    {
        write_ewf2_section(
            writer,
            EWF2_MEMORY_EXTENTS_TABLE_SECTION,
            memory_extents_table,
            section,
        )?;
    }

    for (payload, section) in increment_data.iter().zip(&increment_sections) {
        write_ewf2_section(writer, EWF2_INCREMENT_DATA_SECTION, payload, *section)?;
    }

    if let (Some(single_files_data), Some(section)) = (&single_files_data, single_files_section) {
        write_ewf2_section(
            writer,
            EWF2_SINGLE_FILES_DATA_SECTION,
            single_files_data,
            section,
        )?;
    }

    if let (Some(single_files_table_0x21), Some(section)) =
        (&single_files_table_0x21, single_files_table_0x21_section)
    {
        write_ewf2_section(
            writer,
            EWF2_SINGLE_FILES_TABLE_SECTION,
            single_files_table_0x21,
            section,
        )?;
    }

    if let (Some(single_files_md5_hash_table), Some(section)) = (
        &single_files_md5_hash_table,
        single_files_md5_hash_table_section,
    ) {
        write_ewf2_section(
            writer,
            EWF2_SINGLE_FILES_MD5_HASH_TABLE_SECTION,
            single_files_md5_hash_table,
            section,
        )?;
    }

    if let (Some(single_files_table_0x23), Some(section)) =
        (&single_files_table_0x23, single_files_table_0x23_section)
    {
        write_ewf2_section(
            writer,
            EWF2_SINGLE_FILES_UNKNOWN_TABLE_SECTION,
            single_files_table_0x23,
            section,
        )?;
    }

    for chunk in chunks {
        spool.copy_chunk_to(chunk, writer)?;
    }
    writer.write_all(&ewf2_section_desc(
        EWF2_SECTOR_DATA_SECTION,
        chunk_payload_size,
        sectors_section.previous_desc_offset,
    ))?;

    let table_capacity = usize::try_from(table_data_size)
        .map_err(|_| EwfError::Malformed("writer EWF2 table size does not fit usize".into()))?;
    let mut table_data = Vec::with_capacity(table_capacity);
    table_data.extend_from_slice(&ewf2_table_header(context.first_chunk, local_chunk_count));
    let table_entries_start = table_data.len();
    let mut chunk_offset = sectors_section.data_offset;
    for chunk in chunks {
        let chunk_size = u32::try_from(chunk.data_size)
            .map_err(|_| EwfError::Unsupported("EWF2 writer chunk data size exceeds u32".into()))?;
        table_data.extend_from_slice(&ewf2_table_entry(
            chunk.pattern_fill.unwrap_or(chunk_offset),
            chunk_size,
            chunk.compressed,
            chunk.has_checksum,
            chunk.pattern_fill.is_some(),
        ));
        chunk_offset = checked_add(chunk_offset, chunk.data_size, "EWF2 chunk data offset")?;
    }
    let entries_checksum = adler32(&table_data[table_entries_start..]);
    table_data.extend_from_slice(&entries_checksum.to_le_bytes());
    table_data.extend_from_slice(&[0; EWF2_TABLE_FOOTER_SIZE - 4]);
    write_ewf2_section(
        writer,
        EWF2_SECTOR_TABLE_SECTION,
        &table_data,
        table_section,
    )?;

    if let (Some(md5_hash), Some(section)) = (&md5_hash, md5_section) {
        write_ewf2_section(writer, EWF2_MD5_HASH_SECTION, md5_hash, section)?;
    }
    if let (Some(sha1_hash), Some(section)) = (&sha1_hash, sha1_section) {
        write_ewf2_section(writer, EWF2_SHA1_HASH_SECTION, sha1_hash, section)?;
    }
    if let (Some(final_information), Some(section)) = (final_information, final_information_section)
    {
        write_ewf2_section(
            writer,
            EWF2_FINAL_INFORMATION_SECTION,
            final_information,
            section,
        )?;
    }
    if let (Some(analytical_data), Some(section)) = (&analytical_data, analytical_section) {
        write_ewf2_section(
            writer,
            EWF2_ANALYTICAL_DATA_SECTION,
            analytical_data,
            section,
        )?;
    }
    if let (Some(restart_data), Some(section)) = (&restart_data, restart_section) {
        write_ewf2_section(writer, EWF2_RESTART_DATA_SECTION, restart_data, section)?;
    }
    writer.write_all(&ewf2_section_desc(
        context.terminal_section_type,
        0,
        terminal_section.previous_desc_offset,
    ))?;

    Ok(())
}

fn ewf2_signature(format: WriteFormat) -> &'static [u8; 8] {
    match format {
        WriteFormat::Ewf2Physical => &ewf2::EX01_SIGNATURE,
        WriteFormat::Ewf2Logical => &ewf2::LEF2_SIGNATURE,
        WriteFormat::Ewf1Physical | WriteFormat::Ewf1Logical | WriteFormat::Ewf1Smart => {
            unreachable!("EWF1 formats are not EWF2")
        }
    }
}

fn ewf2_compression_method(compression: WriteCompression) -> u16 {
    match compression {
        // Common EWF readers reject EWF2 segment headers that use COMPRESSION_NONE.
        // Raw chunks are still represented by table flags; the header method must
        // name a supported compression family for the segment.
        WriteCompression::None | WriteCompression::Zlib => 1,
        WriteCompression::Bzip2 => 2,
    }
}

fn zlib_compression(level: WriteCompressionLevel) -> ZlibCompression {
    match level {
        WriteCompressionLevel::Default => ZlibCompression::default(),
        WriteCompressionLevel::None => ZlibCompression::none(),
        WriteCompressionLevel::Fast => ZlibCompression::fast(),
        WriteCompressionLevel::Best => ZlibCompression::best(),
    }
}

fn empty_block_zlib_compression(level: WriteCompressionLevel) -> ZlibCompression {
    match level {
        WriteCompressionLevel::None => ZlibCompression::default(),
        level => zlib_compression(level),
    }
}

fn bzip2_compression(level: WriteCompressionLevel) -> Result<Bzip2Compression> {
    match level {
        WriteCompressionLevel::Default => Ok(Bzip2Compression::default()),
        WriteCompressionLevel::None => Err(EwfError::Unsupported(
            "BZip2 writer compression does not support none compression level".into(),
        )),
        WriteCompressionLevel::Fast => Ok(Bzip2Compression::fast()),
        WriteCompressionLevel::Best => Ok(Bzip2Compression::best()),
    }
}

fn ewf2_metadata_section_payload(
    payload: &[u8],
    compression: WriteCompression,
    compression_level: WriteCompressionLevel,
) -> Result<Vec<u8>> {
    match compression {
        WriteCompression::None | WriteCompression::Zlib => {
            let mut encoder = ZlibEncoder::new(Vec::new(), zlib_compression(compression_level));
            encoder.write_all(payload)?;
            Ok(encoder.finish()?)
        }
        WriteCompression::Bzip2 => {
            let mut encoder = BzEncoder::new(Vec::new(), bzip2_compression(compression_level)?);
            encoder.write_all(payload)?;
            Ok(encoder.finish()?)
        }
    }
}

fn ewf2_device_information_section_payload(
    payload: &[u8],
    options: &WriteOptions,
) -> Result<Vec<u8>> {
    let compression = if matches!(options.compression, WriteCompression::Bzip2) {
        WriteCompression::Zlib
    } else {
        options.compression
    };
    ewf2_metadata_section_payload(payload, compression, options.compression_values.level)
}

fn ewf2_device_information_payload(
    options: &WriteOptions,
    sector_count: u64,
    chunk_count: u64,
) -> Vec<u8> {
    let physical = u8::from(options.format == WriteFormat::Ewf2Physical);
    let mut names = vec![
        "sn", "md", "lb", "ts", "hs", "dc", "dt", "pid", "rs", "ls", "bp", "ph", "sc", "tb",
    ];
    let media_type = options
        .media_profile
        .media_type
        .or(Some(MediaType::Removable))
        .map(ewf2_media_type_value)
        .map(|value| value.to_string())
        .unwrap_or_default();
    let mut values = vec![
        ewf2_device_header_value(&options.metadata, "serial_number", &["sn"]),
        ewf2_device_header_value(&options.metadata, "model", &["md"]),
        ewf2_device_header_value(&options.metadata, "device_label", &["lb", "l"]),
        sector_count.to_string(),
        String::new(),
        String::new(),
        media_type,
        ewf2_device_header_value(&options.metadata, "process_identifier", &["pid"]),
        String::new(),
        String::new(),
        options.bytes_per_sector.to_string(),
        physical.to_string(),
        options.sectors_per_chunk.to_string(),
        chunk_count.to_string(),
    ];
    if let Some(error_granularity) = options.media_profile.error_granularity {
        names.push("gr");
        values.push(error_granularity.to_string());
    }
    let write_blocker_flags =
        u64::from(options.media_profile.fastbloc) | (u64::from(options.media_profile.tableau) << 1);
    if write_blocker_flags != 0 {
        names.push("wb");
        values.push(write_blocker_flags.to_string());
    }

    let text = format!("1\nmain\n{}\n{}\n\n", names.join("\t"), values.join("\t"));
    utf16le_with_bom(&text)
}

fn ewf2_device_header_value(metadata: &EwfMetadata, identifier: &str, aliases: &[&str]) -> String {
    metadata
        .header_value(identifier)
        .or_else(|| {
            aliases
                .iter()
                .find_map(|alias| metadata.header_values.get(*alias).map(String::as_str))
        })
        .map(sanitize_header_value)
        .unwrap_or_default()
}

fn ewf2_media_type_value(media_type: MediaType) -> char {
    match media_type {
        MediaType::Removable => 'r',
        MediaType::Fixed => 'f',
        MediaType::Optical => 'c',
        MediaType::SingleFiles => 'l',
        MediaType::Memory => 'm',
        MediaType::Unknown(value) => char::from(value),
    }
}

fn ewf2_case_data_payload(options: &WriteOptions, chunk_count: u64) -> Vec<u8> {
    let metadata = &options.metadata;
    let write_blocker_flags =
        u64::from(options.media_profile.fastbloc) | (u64::from(options.media_profile.tableau) << 1);
    let compression_method = ewf2_case_data_header_value(metadata, "compression_method", &["cp"]);
    let error_granularity = options.media_profile.error_granularity.map_or_else(
        || {
            ewf2_case_data_header_value(metadata, "error_granularity", &["gr"])
                .unwrap_or_else(|| "0".to_string())
        },
        |value| value.to_string(),
    );
    let write_blocker = if write_blocker_flags != 0 {
        write_blocker_flags.to_string()
    } else {
        ewf2_case_data_header_value(metadata, "write_blocker", &["wb"]).unwrap_or_default()
    };
    let fields = [
        (
            "nm",
            ewf2_case_data_header_value(metadata, "description", &["nm", "de"]).unwrap_or_default(),
        ),
        (
            "cn",
            ewf2_case_data_header_value(metadata, "case_number", &["cn"]).unwrap_or_default(),
        ),
        (
            "en",
            ewf2_case_data_header_value(metadata, "evidence_number", &["en"]).unwrap_or_default(),
        ),
        (
            "ex",
            ewf2_case_data_header_value(metadata, "examiner_name", &["ex"]).unwrap_or_default(),
        ),
        (
            "nt",
            ewf2_case_data_header_value(metadata, "notes", &["nt"]).unwrap_or_default(),
        ),
        (
            "av",
            ewf2_case_data_header_value(metadata, "acquiry_software_version", &["av"])
                .unwrap_or_default(),
        ),
        (
            "os",
            ewf2_case_data_header_value(metadata, "acquiry_operating_system", &["os", "ov"])
                .unwrap_or_default(),
        ),
        (
            "tt",
            ewf2_case_data_header_value(metadata, "system_date", &["tt", "sd"]).unwrap_or_default(),
        ),
        (
            "at",
            ewf2_case_data_header_value(metadata, "acquiry_date", &["at", "ad"])
                .unwrap_or_default(),
        ),
        ("tb", chunk_count.to_string()),
        ("cp", compression_method.unwrap_or_default()),
        ("sb", options.sectors_per_chunk.to_string()),
        ("gr", error_granularity),
        ("wb", write_blocker),
    ];
    let mut names = fields
        .iter()
        .map(|(name, _)| (*name).to_string())
        .collect::<Vec<_>>();
    let mut values = fields
        .into_iter()
        .map(|(_, value)| value)
        .collect::<Vec<_>>();
    if let Some(acquisition_software) = metadata.acquisition_software.as_deref() {
        names.push("acquiry_software".to_string());
        values.push(sanitize_header_value(acquisition_software));
    }
    if let Some(password) = metadata.password.as_deref() {
        names.push("password".to_string());
        values.push(sanitize_header_value(password));
    }
    for (name, value) in &metadata.header_values {
        let tag = ewf2_case_data_tag(name);
        if names.iter().any(|existing| existing == tag) {
            continue;
        }
        names.push(tag.to_string());
        values.push(sanitize_header_value(value));
    }

    let text = format!("1\nmain\n{}\n{}\n\n", names.join("\t"), values.join("\t"));
    utf16le_with_bom(&text)
}

fn ewf2_case_data_header_value(
    metadata: &EwfMetadata,
    identifier: &str,
    aliases: &[&str],
) -> Option<String> {
    metadata
        .header_value(identifier)
        .or_else(|| {
            aliases
                .iter()
                .find_map(|alias| metadata.header_values.get(*alias).map(String::as_str))
        })
        .map(sanitize_header_value)
}

fn ewf2_case_data_tag(identifier: &str) -> &str {
    match identifier {
        "acquiry_date" | "ad" => "at",
        "acquiry_operating_system" | "ov" => "os",
        "acquiry_software_version" => "av",
        "case_number" => "cn",
        "compression_method" => "cp",
        "description" | "de" => "nm",
        "evidence_number" => "en",
        "examiner_name" => "ex",
        "error_granularity" => "gr",
        "notes" => "nt",
        "number_of_chunks" => "tb",
        "sectors_per_chunk" => "sb",
        "system_date" | "sd" => "tt",
        "write_blocker" => "wb",
        _ => identifier,
    }
}

fn ewf2_memory_extents_table_payload(extents: &[MemoryExtent]) -> Option<Vec<u8>> {
    if extents.is_empty() {
        return None;
    }

    let mut payload = Vec::with_capacity(extents.len() * 16);
    for extent in extents {
        payload.extend_from_slice(&extent.start_page.to_le_bytes());
        payload.extend_from_slice(&extent.page_count.to_le_bytes());
    }
    Some(payload)
}

fn ewf2_single_files_aux_u64_table_payload(entries: &[u64]) -> Option<Vec<u8>> {
    if entries.is_empty() {
        return None;
    }

    let mut entry_data = Vec::with_capacity(entries.len() * 8);
    for entry in entries {
        entry_data.extend_from_slice(&entry.to_le_bytes());
    }
    Some(ewf2_single_files_aux_table_payload(
        entries.len(),
        &entry_data,
    ))
}

fn ewf2_single_files_md5_hash_table_payload(hashes: &[[u8; 16]]) -> Option<Vec<u8>> {
    if hashes.is_empty() {
        return None;
    }

    let mut entry_data = Vec::with_capacity(hashes.len() * 16);
    for hash in hashes {
        entry_data.extend_from_slice(hash);
    }
    Some(ewf2_single_files_aux_table_payload(
        hashes.len(),
        &entry_data,
    ))
}

fn ewf2_single_files_aux_table_payload(entry_count: usize, entry_data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(32 + entry_data.len() + 16);
    let entry_count = u32::try_from(entry_count).expect("entry count fits u32");
    payload.extend_from_slice(&entry_count.to_le_bytes());
    payload.extend_from_slice(&[0; 12]);
    let header_checksum = adler32(&payload);
    payload.extend_from_slice(&header_checksum.to_le_bytes());
    payload.extend_from_slice(&[0; 12]);
    payload.extend_from_slice(entry_data);
    let entries_checksum = adler32(entry_data);
    payload.extend_from_slice(&entries_checksum.to_le_bytes());
    payload.extend_from_slice(&[0; 12]);
    payload
}

fn ewf2_string_section_payload(
    text: &str,
    compression: WriteCompression,
    compression_level: WriteCompressionLevel,
) -> Result<Vec<u8>> {
    ewf2_metadata_section_payload(&utf16le_with_bom(text), compression, compression_level)
}

fn ewf1_ltree_payload(info: &SingleFilesInfo) -> Result<Vec<u8>> {
    let single_files_data = ewf2_single_files_data_payload(info)?;
    let mut payload = Vec::with_capacity(EWF1_LTREE_HEADER_SIZE + single_files_data.len());
    let mut hasher = Md5::new();
    hasher.update(&single_files_data);
    payload.extend_from_slice(&hasher.finalize());
    payload.extend_from_slice(
        &u64::try_from(single_files_data.len())
            .expect("usize fits u64")
            .to_le_bytes(),
    );
    payload.extend_from_slice(&0_u32.to_le_bytes());
    payload.extend_from_slice(&[0; 20]);
    let checksum = adler32(&payload[..EWF1_LTREE_HEADER_SIZE]);
    payload[24..28].copy_from_slice(&checksum.to_le_bytes());
    payload.extend_from_slice(&single_files_data);
    Ok(payload)
}

fn ewf2_single_files_data_payload(info: &SingleFilesInfo) -> Result<Vec<u8>> {
    let source_ids = SingleFileSourceIds::new(&info.sources)?;
    let mut lines = Vec::new();
    lines.push("5".to_owned());
    append_single_file_record_category(&mut lines, info)?;
    append_single_file_permission_category(&mut lines, &info.permission_groups);
    append_single_file_source_category(&mut lines, &info.sources)?;
    append_single_file_subject_category(&mut lines, &info.subjects);
    append_single_file_entry_category(&mut lines, &info.root, &source_ids)?;
    // Terminate the final empty category-separator line, as well as the last
    // record line. Streaming consumers must not need to read past the payload.
    lines.push(String::new());
    Ok(utf16le_with_bom(&lines.join("\n")))
}

struct SingleFileSourceIds {
    remapped: BTreeMap<i32, i32>,
}

impl SingleFileSourceIds {
    fn new(sources: &[SingleFileSource]) -> Result<Self> {
        let mut remapped = BTreeMap::new();
        let children = sources.get(1..).unwrap_or(&[]);
        for (index, source) in children.iter().enumerate() {
            if let Some(identifier) = source.identifier {
                remapped
                    .entry(identifier)
                    .or_insert(source_child_identifier(index)?);
            }
        }
        Ok(Self { remapped })
    }

    fn entry_identifier(&self, identifier: Option<i32>) -> Option<i32> {
        match identifier {
            Some(identifier) if identifier > 0 => {
                self.remapped.get(&identifier).copied().or(Some(identifier))
            }
            _ => identifier,
        }
    }
}

fn source_child_identifier(index: usize) -> Result<i32> {
    let identifier = index
        .checked_add(1)
        .ok_or_else(|| EwfError::Malformed("single files source identifier overflow".into()))?;
    i32::try_from(identifier).map_err(|_| {
        EwfError::Unsupported("single files source count exceeds supported identifier range".into())
    })
}

fn append_single_file_record_category(
    lines: &mut Vec<String>,
    info: &SingleFilesInfo,
) -> Result<()> {
    lines.push("rec".to_owned());
    lines.push("tb".to_owned());
    lines.push(single_files_record_data_size(info)?.to_string());
    lines.push(String::new());
    Ok(())
}

fn single_files_record_data_size(info: &SingleFilesInfo) -> Result<u64> {
    Ok(info.data_size.max(single_file_entry_data_size(&info.root)?))
}

fn single_file_entry_data_size(entry: &SingleFileEntry) -> Result<u64> {
    let mut data_size = entry.size.unwrap_or(0);
    for extent in &entry.extents {
        if extent.sparse {
            continue;
        }
        let extent_end = extent
            .data_offset
            .checked_add(extent.data_size)
            .ok_or_else(|| EwfError::Malformed("single files extent end overflow".into()))?;
        data_size = data_size.max(extent_end);
    }
    for child in &entry.children {
        data_size = data_size.max(single_file_entry_data_size(child)?);
    }
    Ok(data_size)
}

fn append_single_file_entry_category(
    lines: &mut Vec<String>,
    root: &SingleFileEntry,
    source_ids: &SingleFileSourceIds,
) -> Result<()> {
    let include_guid = single_file_entry_tree_has_guid(root);
    let entry_types = single_file_entry_types(include_guid);
    lines.push("entry".to_owned());
    lines.push("0\t1".to_owned());
    lines.push(entry_types.join("\t"));
    append_single_file_entry(lines, root, source_ids, include_guid)?;
    lines.push(String::new());
    Ok(())
}

fn single_file_entry_types(include_guid: bool) -> Vec<&'static str> {
    let mut entry_types = SINGLE_FILE_ENTRY_TYPES.to_vec();
    if include_guid {
        entry_types.push("mid");
    }
    entry_types
}

fn single_file_entry_tree_has_guid(entry: &SingleFileEntry) -> bool {
    entry.guid.is_some() || entry.children.iter().any(single_file_entry_tree_has_guid)
}

fn append_single_file_entry(
    lines: &mut Vec<String>,
    entry: &SingleFileEntry,
    source_ids: &SingleFileSourceIds,
    include_guid: bool,
) -> Result<()> {
    lines.push(format!("26\t{}", entry.children.len()));
    lines.push(single_file_entry_row(entry, source_ids, include_guid)?);
    for child in &entry.children {
        append_single_file_entry(lines, child, source_ids, include_guid)?;
    }
    Ok(())
}

fn single_file_entry_row(
    entry: &SingleFileEntry,
    source_ids: &SingleFileSourceIds,
    include_guid: bool,
) -> Result<String> {
    if entry.name_utf16.is_some() {
        return Err(EwfError::Unsupported(
            "writing a single-file name with unpaired UTF-16 units is not supported".into(),
        ));
    }
    let mut values = vec![
        optional_display(entry.identifier),
        single_file_entry_type_value(entry.file_entry_type),
        optional_text(entry.name.as_deref()),
        optional_display(entry.size),
        optional_display(entry.logical_offset),
        optional_display(entry.physical_offset),
        optional_display(entry.duplicate_data_offset),
        optional_display(source_ids.entry_identifier(entry.source_identifier)),
        optional_display(entry.subject_identifier),
        optional_display(entry.permission_group_index),
        optional_display(entry.record_type),
        optional_display(entry.flags),
        single_file_extents_value(&entry.extents),
        optional_text(entry.md5.as_deref()),
        optional_text(entry.sha1.as_deref()),
        single_file_short_name_value(entry.short_name.as_deref()),
        optional_display(entry.creation_time),
        optional_display(entry.modification_time),
        optional_display(entry.access_time),
        optional_display(entry.entry_modification_time),
        optional_display(entry.deletion_time),
        single_file_attributes_value(&entry.attributes)?,
    ];
    if include_guid {
        values.push(optional_text(entry.guid.as_deref()));
    }
    Ok(values.join("\t"))
}

fn append_single_file_source_category(
    lines: &mut Vec<String>,
    sources: &[SingleFileSource],
) -> Result<()> {
    let default_root = SingleFileSource {
        identifier: Some(0),
        ..SingleFileSource::default()
    };
    let (root, children) = sources.split_first().unwrap_or((&default_root, &[]));
    lines.push("srce".to_owned());
    lines.push(format!("{}\t1", children.len()));
    lines.push(SINGLE_FILE_SOURCE_TYPES.join("\t"));
    lines.push(format!("0\t{}", children.len()));
    lines.push(single_file_source_row(root, Some(0)));
    for (index, source) in children.iter().enumerate() {
        lines.push("0\t0".to_owned());
        lines.push(single_file_source_row(
            source,
            Some(source_child_identifier(index)?),
        ));
    }
    lines.push(String::new());
    Ok(())
}

fn single_file_source_row(source: &SingleFileSource, identifier: Option<i32>) -> String {
    vec![
        optional_display(identifier.or(source.identifier)),
        optional_text(source.name.as_deref()),
        optional_text(source.evidence_number.as_deref()),
        optional_text(source.location.as_deref()),
        optional_text(source.device_guid.as_deref()),
        optional_text(source.primary_device_guid.as_deref()),
        source
            .drive_type
            .map(|value| value.to_string())
            .unwrap_or_default(),
        optional_text(source.manufacturer.as_deref()),
        optional_text(source.model.as_deref()),
        optional_text(source.serial_number.as_deref()),
        optional_text(source.domain.as_deref()),
        optional_text(source.ip_address.as_deref()),
        optional_text(source.mac_address.as_deref()),
        optional_display(source.size),
        optional_display(source.logical_offset),
        optional_display(source.physical_offset),
        optional_display(source.acquisition_time),
        optional_text(source.md5.as_deref()),
        optional_text(source.sha1.as_deref()),
    ]
    .join("\t")
}

fn append_single_file_subject_category(lines: &mut Vec<String>, subjects: &[SingleFileSubject]) {
    let default_root = SingleFileSubject {
        identifier: Some(0),
        ..SingleFileSubject::default()
    };
    let (root, children) = subjects.split_first().unwrap_or((&default_root, &[]));
    lines.push("sub".to_owned());
    lines.push(format!("{}\t1", children.len()));
    lines.push(SINGLE_FILE_SUBJECT_TYPES.join("\t"));
    lines.push(format!("0\t{}", children.len()));
    lines.push(single_file_subject_row(root));
    for subject in children {
        lines.push("0\t0".to_owned());
        lines.push(single_file_subject_row(subject));
    }
    lines.push(String::new());
}

fn single_file_subject_row(subject: &SingleFileSubject) -> String {
    [
        optional_display(subject.identifier),
        optional_text(subject.name.as_deref()),
    ]
    .join("\t")
}

fn append_single_file_permission_category(
    lines: &mut Vec<String>,
    groups: &[SingleFilePermissionGroup],
) {
    lines.push("perm".to_owned());
    lines.push(format!("{}\t1", groups.len()));
    lines.push(SINGLE_FILE_PERMISSION_TYPES.join("\t"));
    lines.push(format!("0\t{}", groups.len()));
    lines.push(single_file_permission_root_row());
    for group in groups {
        lines.push(format!("0\t{}", group.permissions.len()));
        lines.push(single_file_permission_group_row(group));
        for permission in &group.permissions {
            lines.push("0\t0".to_owned());
            lines.push(single_file_permission_row(permission));
        }
    }
    lines.push(String::new());
}

fn single_file_permission_root_row() -> String {
    single_file_permission_row(&SingleFilePermission {
        property_type: Some(10),
        ..SingleFilePermission::default()
    })
}

fn single_file_permission_group_row(group: &SingleFilePermissionGroup) -> String {
    [
        optional_text(group.name.as_deref()),
        optional_display(group.property_type.or(Some(10))),
        optional_text(group.identifier.as_deref()),
        optional_display(group.access_mask),
        optional_display(group.ace_flags),
    ]
    .join("\t")
}

fn single_file_permission_row(permission: &SingleFilePermission) -> String {
    [
        optional_text(permission.name.as_deref()),
        optional_display(permission.property_type),
        optional_text(permission.identifier.as_deref()),
        optional_display(permission.access_mask),
        optional_display(permission.ace_flags),
    ]
    .join("\t")
}

fn single_file_entry_type_value(value: Option<SingleFileEntryType>) -> String {
    match value {
        Some(SingleFileEntryType::File) => "0".to_owned(),
        Some(SingleFileEntryType::Directory) => "1".to_owned(),
        Some(SingleFileEntryType::Unknown) => "u".to_owned(),
        None => String::new(),
    }
}

fn single_file_extents_value(extents: &[SingleFileExtent]) -> String {
    if extents.is_empty() {
        return String::new();
    }

    let mut parts = Vec::with_capacity(1 + extents.len() * 3);
    parts.push(format!("{:x}", extents.len()));
    for extent in extents {
        if extent.sparse {
            parts.push("S".to_owned());
        }
        parts.push(format!("{:x}", extent.data_offset));
        parts.push(format!("{:x}", extent.data_size));
    }
    parts.join(" ")
}

fn single_file_attributes_value(attributes: &[SingleFileAttribute]) -> Result<String> {
    if attributes.is_empty() {
        return Ok(String::new());
    }

    let mut data = EWF2_EXTENDED_ATTRIBUTES_HEADER.to_vec();
    for attribute in attributes {
        let name = optional_utf16le_null_terminated(attribute.name.as_deref());
        let value = optional_utf16le_null_terminated(attribute.value.as_deref());
        let name_units = u32::try_from(name.len() / 2).map_err(|_| {
            EwfError::Unsupported("single file attribute name length exceeds u32".into())
        })?;
        let value_units = u32::try_from(value.len() / 2).map_err(|_| {
            EwfError::Unsupported("single file attribute value length exceeds u32".into())
        })?;

        data.extend_from_slice(&[0; 4]);
        data.push(0);
        data.extend_from_slice(&name_units.to_le_bytes());
        data.extend_from_slice(&value_units.to_le_bytes());
        data.extend_from_slice(&name);
        data.extend_from_slice(&value);
    }
    Ok(hex_bytes(&data))
}

fn optional_utf16le_null_terminated(value: Option<&str>) -> Vec<u8> {
    let Some(value) = value else {
        return Vec::new();
    };

    let mut bytes = utf16le(&optional_text(Some(value)));
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes
}

fn optional_text(value: Option<&str>) -> String {
    value.map(sanitize_header_value).unwrap_or_default()
}

fn single_file_short_name_value(value: Option<&str>) -> String {
    let value = optional_text(value);
    if value.is_empty() {
        String::new()
    } else {
        format!("{} {value}", value.len() + 1)
    }
}

fn optional_display<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map(|value| value.to_string()).unwrap_or_default()
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[(byte >> 4) as usize]));
        out.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    out
}

fn ewf2_hash_payload<const N: usize>(hash: [u8; N]) -> [u8; 32] {
    let mut payload = [0; 32];
    payload[..N].copy_from_slice(&hash);
    let checksum = adler32(&payload[..N]);
    payload[N..N + 4].copy_from_slice(&checksum.to_le_bytes());
    payload
}

fn ewf1_error2_payload(errors: &[AcquisitionError]) -> Result<Option<Vec<u8>>> {
    if errors.is_empty() {
        return Ok(None);
    }

    let entry_count = u32::try_from(errors.len()).map_err(|_| {
        EwfError::Unsupported("EWF1 writer acquisition error count exceeds u32".into())
    })?;
    let mut payload = Vec::with_capacity(520 + errors.len() * 8 + 4);
    payload.resize(520, 0);
    payload[0..4].copy_from_slice(&entry_count.to_le_bytes());
    let header_checksum = adler32(&payload[..516]);
    payload[516..520].copy_from_slice(&header_checksum.to_le_bytes());
    let entries_start = payload.len();
    for error in errors {
        let first_sector = u32::try_from(error.first_sector).map_err(|_| {
            EwfError::Unsupported("EWF1 writer acquisition error first sector exceeds u32".into())
        })?;
        let sector_count = u32::try_from(error.sector_count).map_err(|_| {
            EwfError::Unsupported("EWF1 writer acquisition error sector count exceeds u32".into())
        })?;
        payload.extend_from_slice(&first_sector.to_le_bytes());
        payload.extend_from_slice(&sector_count.to_le_bytes());
    }
    let entries_checksum = adler32(&payload[entries_start..]);
    payload.extend_from_slice(&entries_checksum.to_le_bytes());
    Ok(Some(payload))
}

fn ewf2_error_table_payload(errors: &[AcquisitionError]) -> Result<Option<Vec<u8>>> {
    if errors.is_empty() {
        return Ok(None);
    }

    let entry_count = u32::try_from(errors.len()).map_err(|_| {
        EwfError::Unsupported("EWF2 writer acquisition error count exceeds u32".into())
    })?;
    let mut payload = vec![0; 32];
    payload[0..4].copy_from_slice(&entry_count.to_le_bytes());
    let header_checksum = adler32(&payload[..16]);
    payload[16..20].copy_from_slice(&header_checksum.to_le_bytes());
    let entries_start = payload.len();
    for error in errors {
        let sector_count = u32::try_from(error.sector_count).map_err(|_| {
            EwfError::Unsupported("EWF2 writer acquisition error sector count exceeds u32".into())
        })?;
        payload.extend_from_slice(&error.first_sector.to_le_bytes());
        payload.extend_from_slice(&sector_count.to_le_bytes());
        payload.extend_from_slice(&[0; 4]);
    }
    let entries_checksum = adler32(&payload[entries_start..]);
    payload.extend_from_slice(&entries_checksum.to_le_bytes());
    payload.extend_from_slice(&[0; 12]);
    Ok(Some(payload))
}

fn ewf1_session_payload(
    sessions: &[SectorRange],
    tracks: &[SectorRange],
) -> Result<Option<Vec<u8>>> {
    session_payload(1, sessions, tracks)
}

fn ewf2_session_table_payload(
    sessions: &[SectorRange],
    tracks: &[SectorRange],
) -> Result<Option<Vec<u8>>> {
    session_payload(2, sessions, tracks)
}

fn session_payload(
    format_version: u8,
    sessions: &[SectorRange],
    tracks: &[SectorRange],
) -> Result<Option<Vec<u8>>> {
    const AUDIO_TRACK_FLAG: u32 = 0x01;

    if sessions.is_empty() && tracks.is_empty() {
        return Ok(None);
    }

    let mut entries = Vec::with_capacity(sessions.len() + tracks.len());
    entries.extend(sessions.iter().map(|range| (range.first_sector, 0)));
    entries.extend(
        tracks
            .iter()
            .map(|range| (range.first_sector, AUDIO_TRACK_FLAG)),
    );
    entries.sort_by_key(|(start_sector, flags)| (*start_sector, *flags & AUDIO_TRACK_FLAG));

    let entry_count = u32::try_from(entries.len())
        .map_err(|_| EwfError::Unsupported("writer session entry count exceeds u32".into()))?;
    let (header_size, checksum_offset, checksum_data_size, footer_size) = match format_version {
        1 => (36_usize, 32_usize, 32_usize, 4_usize),
        2 => (32_usize, 16_usize, 16_usize, 16_usize),
        _ => unreachable!("writer only emits EWF1 or EWF2 sessions"),
    };
    let mut payload = vec![0; header_size];
    payload[0..4].copy_from_slice(&entry_count.to_le_bytes());
    let header_checksum = adler32(&payload[..checksum_data_size]);
    payload[checksum_offset..checksum_offset + 4].copy_from_slice(&header_checksum.to_le_bytes());

    let entries_start = payload.len();
    for (start_sector, flags) in entries {
        if format_version == 1 {
            let start_sector = u32::try_from(start_sector).map_err(|_| {
                EwfError::Unsupported("EWF1 writer session start sector exceeds u32".into())
            })?;
            payload.extend_from_slice(&flags.to_le_bytes());
            payload.extend_from_slice(&start_sector.to_le_bytes());
            payload.extend_from_slice(&[0; 24]);
        } else {
            payload.extend_from_slice(&start_sector.to_le_bytes());
            payload.extend_from_slice(&flags.to_le_bytes());
            payload.extend_from_slice(&[0; 20]);
        }
    }
    let entries_checksum = adler32(&payload[entries_start..]);
    payload.extend_from_slice(&entries_checksum.to_le_bytes());
    if footer_size > 4 {
        payload.extend_from_slice(&vec![0; footer_size - 4]);
    }

    Ok(Some(payload))
}

fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65_521;
    let mut a = 1_u32;
    let mut b = 0_u32;
    for byte in data {
        a = (a + u32::from(*byte)) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    (b << 16) | a
}

fn utf16le(text: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(text.len() * 2);
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

fn utf16le_with_bom(text: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2 + text.len() * 2);
    bytes.extend_from_slice(&0xfeff_u16.to_le_bytes());
    bytes.extend_from_slice(&utf16le(text));
    bytes
}

fn ewf2_table_header(first_chunk: u64, chunk_count: u32) -> [u8; EWF2_TABLE_HEADER_V2_SIZE] {
    let mut table = [0; EWF2_TABLE_HEADER_V2_SIZE];
    table[0..8].copy_from_slice(&first_chunk.to_le_bytes());
    table[8..12].copy_from_slice(&chunk_count.to_le_bytes());
    let checksum = adler32(&table[..16]);
    table[16..20].copy_from_slice(&checksum.to_le_bytes());
    table
}

fn ewf2_table_entry(
    chunk_offset: u64,
    chunk_size: u32,
    compressed: bool,
    has_checksum: bool,
    pattern_fill: bool,
) -> [u8; ewf2::TABLE_ENTRY_SIZE] {
    let mut entry = [0; ewf2::TABLE_ENTRY_SIZE];
    entry[0..8].copy_from_slice(&chunk_offset.to_le_bytes());
    entry[8..12].copy_from_slice(&chunk_size.to_le_bytes());
    let mut flags = 0_u32;
    if compressed {
        flags |= ewf2::CHUNK_FLAG_COMPRESSED;
    }
    if has_checksum {
        flags |= ewf2::CHUNK_FLAG_HAS_CHECKSUM;
    }
    if pattern_fill {
        flags |= ewf2::CHUNK_FLAG_PATTERN_FILL;
    }
    entry[12..16].copy_from_slice(&flags.to_le_bytes());
    entry
}

fn ewf2_section_desc(
    section_type: u32,
    data_size: u64,
    previous_offset: u64,
) -> [u8; ewf2::SECTION_DESCRIPTOR_SIZE] {
    let mut desc = [0; ewf2::SECTION_DESCRIPTOR_SIZE];
    desc[0..4].copy_from_slice(&section_type.to_le_bytes());
    desc[8..16].copy_from_slice(&previous_offset.to_le_bytes());
    desc[16..24].copy_from_slice(&data_size.to_le_bytes());
    desc[24..28].copy_from_slice(&(ewf2::SECTION_DESCRIPTOR_SIZE as u32).to_le_bytes());
    let checksum = adler32(&desc[..ewf2::SECTION_DESCRIPTOR_SIZE - 4]);
    desc[ewf2::SECTION_DESCRIPTOR_SIZE - 4..].copy_from_slice(&checksum.to_le_bytes());
    desc
}

fn checked_add(left: u64, right: u64, label: &str) -> Result<u64> {
    left.checked_add(right)
        .ok_or_else(|| EwfError::Malformed(format!("writer {label} offset overflow")))
}

fn validated_write_hashes(requested: &WriteHashes) -> Result<WriteHashes> {
    let mut hashes = StoredHashes {
        md5: requested.md5,
        sha1: requested.sha1,
        ..StoredHashes::default()
    };
    for (identifier, value) in &requested.hash_values {
        crate::hashes::insert_stored_hash(&mut hashes, identifier, value)?;
    }
    Ok(WriteHashes {
        md5: hashes.md5,
        sha1: hashes.sha1,
        hash_values: hashes.hash_values,
    })
}

fn effective_write_hashes(
    requested: &WriteHashes,
    computed_md5: [u8; 16],
    computed_sha1: [u8; 20],
    computed_sha256: [u8; 32],
) -> Result<WriteHashes> {
    let mut hashes = validated_write_hashes(requested)?;
    hashes.md5 = hashes.md5.or(Some(computed_md5));
    hashes.sha1 = hashes.sha1.or(Some(computed_sha1));
    hashes
        .hash_values
        .entry("SHA256".into())
        .or_insert_with(|| hex_string(&computed_sha256));
    Ok(hashes)
}

fn checked_writer_seek(
    current_offset: u64,
    logical_input_size: u64,
    position: SeekFrom,
) -> Result<u64> {
    let next = match position {
        SeekFrom::Start(offset) => return Ok(offset),
        SeekFrom::Current(offset) => i128::from(current_offset) + i128::from(offset),
        SeekFrom::End(offset) => i128::from(logical_input_size) + i128::from(offset),
    };
    if next < 0 {
        return Err(EwfError::Malformed(
            "writer seek before start of media".into(),
        ));
    }
    u64::try_from(next)
        .map_err(|_| EwfError::Malformed("writer seek offset does not fit u64".into()))
}

fn encode_raw_spool(
    raw: &mut RawSpool,
    mut encoded_chunks: BTreeMap<u64, RememberedEncodedChunk>,
    logical_size: u64,
    chunk_capacity: usize,
    chunk_size: u64,
    options: &WriteOptions,
) -> Result<EncodedSpool> {
    let mut chunks = Vec::new();
    let mut encoded_spool = ChunkSpool::new()?;
    let mut hash_state = WriteHashState::new();
    let mut offset = 0_u64;
    let is_ewf2 = is_ewf2_format(options.format);

    while offset < logical_size {
        let take = usize::try_from((logical_size - offset).min(chunk_capacity as u64))
            .expect("chunk read is bounded by chunk capacity");
        let mut chunk = vec![0; take];
        raw.read_at_filling_zeroes(offset, &mut chunk)?;
        hash_state.update(&chunk);
        let chunk_index = offset / chunk_size;
        let encoded = if let Some(remembered) = encoded_chunks.remove(&chunk_index) {
            if remembered.logical_size == take
                && encoded_data_chunk_encoding_compatible(remembered.encoding, options)
            {
                remembered.encoded
            } else {
                encode_chunk(
                    chunk,
                    options.compression,
                    options.compression_values,
                    chunk_size,
                    is_ewf2,
                    !is_ewf2 && options.compression_values.empty_block,
                )?
            }
        } else {
            encode_chunk(
                chunk,
                options.compression,
                options.compression_values,
                chunk_size,
                is_ewf2,
                !is_ewf2 && options.compression_values.empty_block,
            )?
        };
        let descriptor = encoded_spool.append(encoded)?;
        chunks.push(descriptor);
        offset = offset
            .checked_add(u64::try_from(take).expect("usize fits u64"))
            .ok_or_else(|| EwfError::Malformed("writer raw spool encode offset overflow".into()))?;
    }

    let (computed_md5, computed_sha1, computed_sha256) = hash_state.finalize();
    Ok(EncodedSpool {
        chunks,
        spool: encoded_spool,
        computed_md5,
        computed_sha1,
        computed_sha256,
    })
}

struct EncodedSpool {
    chunks: Vec<ChunkDescriptor>,
    spool: ChunkSpool,
    computed_md5: [u8; 16],
    computed_sha1: [u8; 20],
    computed_sha256: [u8; 32],
}

struct RememberedEncodedChunk {
    logical_size: usize,
    encoding: DataChunkEncoding,
    encoded: EncodedChunk,
}

#[derive(Debug, Clone, Copy)]
struct ChunkDescriptor {
    data_offset: u64,
    data_size: u64,
    compressed: bool,
    has_checksum: bool,
    pattern_fill: Option<u64>,
}

struct RawSpool {
    file: NamedTempFile,
    len: u64,
}

impl RawSpool {
    fn new() -> Result<Self> {
        Ok(Self {
            file: NamedTempFile::new()?,
            len: 0,
        })
    }

    fn len(&self) -> u64 {
        self.len
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let data_len = u64::try_from(data.len())
            .map_err(|_| EwfError::Malformed("writer data length does not fit u64".into()))?;
        let end_offset = offset
            .checked_add(data_len)
            .ok_or_else(|| EwfError::Malformed("writer raw spool size overflow".into()))?;
        let file = self.file.as_file_mut();
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(data)?;
        self.len = self.len.max(end_offset);
        Ok(())
    }

    fn read_at_filling_zeroes(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        buffer.fill(0);
        if buffer.is_empty() || offset >= self.len {
            return Ok(());
        }

        let available = self.len - offset;
        let take = usize::try_from(available.min(buffer.len() as u64))
            .expect("raw spool read is bounded by buffer length");
        let file = self.file.as_file_mut();
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buffer[..take])?;
        Ok(())
    }
}

struct ChunkSpool {
    file: NamedTempFile,
    len: u64,
    position: u64,
}

impl ChunkSpool {
    fn new() -> Result<Self> {
        Ok(Self {
            file: NamedTempFile::new()?,
            len: 0,
            position: 0,
        })
    }

    fn append(&mut self, encoded: EncodedChunk) -> Result<ChunkDescriptor> {
        let EncodedChunk {
            bytes,
            compressed,
            has_checksum,
            pattern_fill,
        } = encoded;
        let data_offset = self.len;
        let data_size = u64::try_from(bytes.len()).map_err(|_| {
            EwfError::Malformed("writer encoded chunk size does not fit u64".into())
        })?;
        let new_len = self.len.checked_add(data_size).ok_or_else(|| {
            EwfError::Malformed("writer encoded chunk spool size overflow".into())
        })?;
        if data_size > 0 {
            let file = self.file.as_file_mut();
            if self.position != data_offset {
                file.seek(SeekFrom::Start(data_offset))?;
            }
            file.write_all(&bytes)?;
            self.position = new_len;
        }
        self.len = new_len;

        Ok(ChunkDescriptor {
            data_offset,
            data_size,
            compressed,
            has_checksum,
            pattern_fill,
        })
    }

    fn copy_chunk_to<W: Write>(
        &mut self,
        descriptor: &ChunkDescriptor,
        writer: &mut W,
    ) -> Result<()> {
        if descriptor.data_size == 0 {
            return Ok(());
        }

        let mut remaining = descriptor.data_size;
        let mut buffer = vec![0; 64 * 1024];
        let file = self.file.as_file_mut();
        if self.position != descriptor.data_offset {
            file.seek(SeekFrom::Start(descriptor.data_offset))?;
            self.position = descriptor.data_offset;
        }
        while remaining > 0 {
            let take = usize::try_from(remaining.min(buffer.len() as u64))
                .expect("copy chunk is bounded by buffer length");
            file.read_exact(&mut buffer[..take])?;
            writer.write_all(&buffer[..take])?;
            remaining -= u64::try_from(take).expect("usize fits u64");
            self.position += u64::try_from(take).expect("usize fits u64");
        }

        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        self.file.as_file_mut().set_len(0)?;
        self.file.as_file_mut().seek(SeekFrom::Start(0))?;
        self.len = 0;
        self.position = 0;
        Ok(())
    }
}

struct EncodedChunk {
    bytes: Vec<u8>,
    compressed: bool,
    has_checksum: bool,
    pattern_fill: Option<u64>,
}

fn encode_chunk(
    chunk: Vec<u8>,
    compression: WriteCompression,
    compression_values: WriteCompressionValues,
    chunk_size: u64,
    allow_pattern_fill: bool,
    allow_empty_block_compression: bool,
) -> Result<EncodedChunk> {
    if allow_pattern_fill && let Some(pattern) = repeated_ewf2_pattern(&chunk) {
        return Ok(EncodedChunk {
            bytes: Vec::new(),
            compressed: true,
            has_checksum: false,
            pattern_fill: Some(pattern),
        });
    }

    if allow_empty_block_compression && is_full_zero_chunk(&chunk, chunk_size) {
        let mut encoder = ZlibEncoder::new(
            Vec::new(),
            empty_block_zlib_compression(compression_values.level),
        );
        encoder.write_all(&chunk)?;
        return Ok(EncodedChunk {
            bytes: encoder.finish()?,
            compressed: true,
            has_checksum: false,
            pattern_fill: None,
        });
    }

    match compression {
        WriteCompression::None => {
            let checksum = adler32(&chunk);
            let mut bytes = chunk;
            bytes.extend_from_slice(&checksum.to_le_bytes());
            Ok(EncodedChunk {
                bytes,
                compressed: false,
                has_checksum: true,
                pattern_fill: None,
            })
        }
        WriteCompression::Zlib => {
            let mut encoder =
                ZlibEncoder::new(Vec::new(), zlib_compression(compression_values.level));
            encoder.write_all(&chunk)?;
            let bytes = encoder.finish()?;
            // EWF consumers allocate roughly one media chunk plus its checksum.
            // Deflate can expand incompressible data, especially with large
            // chunks. Store those chunks raw with the ordinary Adler checksum.
            if bytes.len() >= chunk.len() {
                return encode_chunk(
                    chunk,
                    WriteCompression::None,
                    compression_values,
                    chunk_size,
                    false,
                    false,
                );
            }
            Ok(EncodedChunk {
                bytes,
                compressed: true,
                has_checksum: false,
                pattern_fill: None,
            })
        }
        WriteCompression::Bzip2 => {
            let mut encoder =
                BzEncoder::new(Vec::new(), bzip2_compression(compression_values.level)?);
            encoder.write_all(&chunk)?;
            Ok(EncodedChunk {
                bytes: encoder.finish()?,
                compressed: true,
                has_checksum: false,
                pattern_fill: None,
            })
        }
    }
}

fn encode_chunks(
    chunks: Vec<Vec<u8>>,
    compression: WriteCompression,
    compression_values: WriteCompressionValues,
    chunk_size: u64,
    allow_pattern_fill: bool,
    allow_empty_block_compression: bool,
) -> Result<Vec<EncodedChunk>> {
    #[cfg(feature = "parallel")]
    if chunks.len() > 1 {
        use rayon::prelude::*;
        return chunks
            .into_par_iter()
            .map(|chunk| {
                encode_chunk(
                    chunk,
                    compression,
                    compression_values,
                    chunk_size,
                    allow_pattern_fill,
                    allow_empty_block_compression,
                )
            })
            .collect();
    }

    chunks
        .into_iter()
        .map(|chunk| {
            encode_chunk(
                chunk,
                compression,
                compression_values,
                chunk_size,
                allow_pattern_fill,
                allow_empty_block_compression,
            )
        })
        .collect()
}

fn automatic_encode_batch_chunks(chunk_size: usize) -> usize {
    #[cfg(feature = "parallel")]
    {
        const MAXIMUM_BATCH_BYTES: usize = 8 * 1024 * 1024;
        let memory_limit = MAXIMUM_BATCH_BYTES
            .checked_div(chunk_size)
            .unwrap_or(0)
            .max(1);
        rayon::current_num_threads()
            .saturating_mul(2)
            .min(memory_limit)
            .max(1)
    }
    #[cfg(not(feature = "parallel"))]
    {
        let _ = chunk_size;
        1
    }
}

fn is_full_zero_chunk(chunk: &[u8], chunk_size: u64) -> bool {
    u64::try_from(chunk.len()).ok() == Some(chunk_size) && chunk.iter().all(|byte| *byte == 0)
}

fn repeated_ewf2_pattern(chunk: &[u8]) -> Option<u64> {
    if chunk.is_empty() {
        return None;
    }

    let mut pattern = [0; 8];
    let seed_size = chunk.len().min(pattern.len());
    pattern[..seed_size].copy_from_slice(&chunk[..seed_size]);
    chunk
        .iter()
        .enumerate()
        .all(|(index, byte)| *byte == pattern[index % pattern.len()])
        .then(|| u64::from_le_bytes(pattern))
}

fn segment_groups(
    chunks: &[ChunkDescriptor],
    maximum_segment_size: Option<u64>,
    options: &WriteOptions,
    sector_count: u64,
    total_chunk_count: u64,
) -> Result<Vec<Range<usize>>> {
    let Some(maximum_segment_size) = maximum_segment_size else {
        return Ok(std::iter::once(0..chunks.len()).collect());
    };

    let mut groups = Vec::new();
    let mut current_start = 0_usize;
    let mut payload_size = 0_u64;
    let is_ewf2 = is_ewf2_format(options.format);
    let mut ewf1_table_group_state = Ewf1TableGroupState::default();
    for (chunk_index, chunk) in chunks.iter().enumerate() {
        let chunk_size = chunk.data_size;
        let proposed_payload_size = payload_size
            .checked_add(chunk_size)
            .ok_or_else(|| EwfError::Malformed("writer segment payload size overflow".into()))?;
        let proposed_ewf1_table_group_state = if is_ewf2 {
            ewf1_table_group_state
        } else {
            ewf1_table_group_state.add_chunk(
                chunk_size,
                EWF1_TABLE_GROUP_MAX_ENTRIES,
                EWF1_TABLE_GROUP_MAX_PAYLOAD,
            )?
        };
        let proposed_size = estimated_segment_size(
            chunk_index - current_start + 1,
            proposed_payload_size,
            proposed_ewf1_table_group_state.group_count.max(1),
            options,
            sector_count,
            total_chunk_count,
        )?;
        if chunk_index > current_start && proposed_size > maximum_segment_size {
            groups.push(current_start..chunk_index);
            current_start = chunk_index;
            payload_size = 0;
            ewf1_table_group_state = if is_ewf2 {
                Ewf1TableGroupState::default()
            } else {
                Ewf1TableGroupState::default().add_chunk(
                    chunk_size,
                    EWF1_TABLE_GROUP_MAX_ENTRIES,
                    EWF1_TABLE_GROUP_MAX_PAYLOAD,
                )?
            };
        } else {
            ewf1_table_group_state = proposed_ewf1_table_group_state;
        }

        payload_size = payload_size
            .checked_add(chunk_size)
            .ok_or_else(|| EwfError::Malformed("writer segment payload size overflow".into()))?;
    }

    groups.push(current_start..chunks.len());
    Ok(groups)
}

fn estimated_segment_size(
    chunk_count: usize,
    chunk_payload_size: u64,
    ewf1_table_group_count: u64,
    options: &WriteOptions,
    sector_count: u64,
    total_chunk_count: u64,
) -> Result<u64> {
    if is_ewf2_format(options.format) {
        return estimated_ewf2_segment_size(
            chunk_count,
            chunk_payload_size,
            options,
            sector_count,
            total_chunk_count,
        );
    }
    estimated_ewf1_segment_size(
        chunk_count,
        chunk_payload_size,
        ewf1_table_group_count,
        options,
    )
}

fn estimated_ewf1_segment_size(
    chunk_count: usize,
    chunk_payload_size: u64,
    table_group_count: u64,
    options: &WriteOptions,
) -> Result<u64> {
    let table_entry_bytes = u64::try_from(chunk_count)
        .map_err(|_| EwfError::Malformed("writer segment chunk count does not fit u64".into()))?
        .checked_mul(4)
        .ok_or_else(|| EwfError::Malformed("writer table entry size overflow".into()))?;
    let table_footer_bytes = if matches!(options.format, WriteFormat::Ewf1Smart) {
        0
    } else {
        4
    };
    let table_group_overhead = (ewf1::SECTION_DESCRIPTOR_SIZE as u64)
        .checked_add(24)
        .and_then(|value| value.checked_add(table_footer_bytes))
        .ok_or_else(|| EwfError::Malformed("writer table group overhead overflow".into()))?;
    let table_sections_size = table_group_count
        .checked_mul(table_group_overhead)
        .and_then(|value| value.checked_add(table_entry_bytes))
        .ok_or_else(|| EwfError::Malformed("writer table sections size overflow".into()))?;
    let sectors_sections_size = table_group_count
        .checked_mul(ewf1::SECTION_DESCRIPTOR_SIZE as u64)
        .and_then(|value| value.checked_add(chunk_payload_size))
        .ok_or_else(|| EwfError::Malformed("writer sectors sections size overflow".into()))?;
    let writes_table2 = matches!(
        options.format,
        WriteFormat::Ewf1Physical | WriteFormat::Ewf1Logical
    );

    let header_size = header_payload(
        &options.metadata,
        options.header_codepage,
        options.compression_values.level,
    )?
    .map(|payload| estimated_ewf1_section_size(payload.len() as u64))
    .transpose()?
    .unwrap_or(0);
    let header2_size = header2_payload(&options.metadata, options.compression_values.level)?
        .map(|payload| estimated_ewf1_section_size(payload.len() as u64))
        .transpose()?
        .unwrap_or(0);
    let xheader_size = xheader_payload(&options.metadata, options.compression_values.level)?
        .map(|payload| estimated_ewf1_section_size(payload.len() as u64))
        .transpose()?
        .unwrap_or(0);
    let session_size = ewf1_session_payload(&options.sessions, &options.tracks)?
        .map(|payload| estimated_ewf1_section_size(payload.len() as u64))
        .transpose()?
        .unwrap_or(0);
    let ltree_size = if matches!(options.format, WriteFormat::Ewf1Logical) {
        options
            .single_files
            .as_ref()
            .map(ewf1_ltree_payload)
            .transpose()?
            .as_ref()
            .map(|payload| estimated_ewf1_section_size(payload.len() as u64))
            .transpose()?
            .unwrap_or(0)
    } else {
        0
    };
    let error2_size = ewf1_error2_payload(&options.acquisition_errors)?
        .map(|payload| estimated_ewf1_section_size(payload.len() as u64))
        .transpose()?
        .unwrap_or(0);
    let digest_size = digest_payload(&options.hashes)
        .map(|payload| estimated_ewf1_section_size(payload.len() as u64))
        .transpose()?
        .unwrap_or(0);
    let xhash_size = xhash_payload(&options.hashes, options.compression_values.level)?
        .map(|payload| estimated_ewf1_section_size(payload.len() as u64))
        .transpose()?
        .unwrap_or(0);

    checked_sum(
        [
            ewf1::FILE_HEADER_SIZE as u64,
            header_size,
            header2_size,
            xheader_size,
            estimated_ewf1_section_size(volume_data_size(options.format))?,
            session_size,
            table_sections_size,
            if writes_table2 {
                table_sections_size
            } else {
                0
            },
            ltree_size,
            sectors_sections_size,
            error2_size,
            digest_size,
            xhash_size,
            ewf1::SECTION_DESCRIPTOR_SIZE as u64,
        ],
        "estimated EWF1 segment size",
    )
}

fn estimated_ewf2_segment_size(
    chunk_count: usize,
    chunk_payload_size: u64,
    options: &WriteOptions,
    sector_count: u64,
    total_chunk_count: u64,
) -> Result<u64> {
    let device_information_payload =
        ewf2_device_information_payload(options, sector_count, total_chunk_count);
    let device_information =
        ewf2_device_information_section_payload(&device_information_payload, options)?;
    let case_data_payload = ewf2_case_data_payload(options, total_chunk_count);
    let case_data = ewf2_metadata_section_payload(
        &case_data_payload,
        options.compression,
        options.compression_values.level,
    )?;
    let error_table = ewf2_error_table_payload(&options.acquisition_errors)?;
    let session_table = ewf2_session_table_payload(&options.sessions, &options.tracks)?;
    let memory_extents_table = ewf2_memory_extents_table_payload(&options.memory_extents);
    let single_files_table_0x21 = ewf2_single_files_aux_u64_table_payload(
        &options.ewf2_single_files_tables.table_0x21_entries,
    );
    let single_files_md5_hash_table =
        ewf2_single_files_md5_hash_table_payload(&options.ewf2_single_files_tables.md5_hashes);
    let single_files_table_0x23 = ewf2_single_files_aux_u64_table_payload(
        &options.ewf2_single_files_tables.table_0x23_entries,
    );
    let increment_data_size =
        options
            .ewf2_increment_data
            .iter()
            .try_fold(0_u64, |total, payload| -> Result<u64> {
                let section_size = estimated_ewf2_section_size(
                    u64::try_from(payload.len()).expect("usize fits u64"),
                )?;
                total.checked_add(section_size).ok_or_else(|| {
                    EwfError::Malformed("writer estimated EWF2 increment data size overflow".into())
                })
            })?;
    let md5_hash = options.hashes.md5.map(ewf2_hash_payload);
    let sha1_hash = options.hashes.sha1.map(ewf2_hash_payload);
    let final_information_size = options
        .ewf2_final_information
        .as_ref()
        .map(|payload| estimated_ewf2_section_size(payload.len() as u64))
        .transpose()?
        .unwrap_or(0);
    let analytical_data = options
        .ewf2_analytical_data
        .as_deref()
        .map(|data| {
            ewf2_string_section_payload(data, options.compression, options.compression_values.level)
        })
        .transpose()?;
    let restart_data = options
        .ewf2_restart_data
        .as_deref()
        .map(|data| {
            ewf2_string_section_payload(data, options.compression, options.compression_values.level)
        })
        .transpose()?;
    let table_entry_bytes = u64::try_from(chunk_count)
        .map_err(|_| EwfError::Malformed("writer segment chunk count does not fit u64".into()))?
        .checked_mul(ewf2::TABLE_ENTRY_SIZE as u64)
        .ok_or_else(|| EwfError::Malformed("writer EWF2 table entry size overflow".into()))?;
    let table_data_size = (EWF2_TABLE_HEADER_V2_SIZE as u64)
        .checked_add(table_entry_bytes)
        .and_then(|value| value.checked_add(EWF2_TABLE_FOOTER_SIZE as u64))
        .ok_or_else(|| EwfError::Malformed("writer EWF2 table size overflow".into()))?;

    checked_sum(
        [
            ewf2::FILE_HEADER_SIZE as u64,
            estimated_ewf2_section_size(device_information.len() as u64)?,
            estimated_ewf2_section_size(case_data.len() as u64)?,
            error_table
                .as_ref()
                .map(|payload| estimated_ewf2_section_size(payload.len() as u64))
                .transpose()?
                .unwrap_or(0),
            session_table
                .as_ref()
                .map(|payload| estimated_ewf2_section_size(payload.len() as u64))
                .transpose()?
                .unwrap_or(0),
            memory_extents_table
                .as_ref()
                .map(|payload| estimated_ewf2_section_size(payload.len() as u64))
                .transpose()?
                .unwrap_or(0),
            increment_data_size,
            single_files_table_0x21
                .as_ref()
                .map(|payload| estimated_ewf2_section_size(payload.len() as u64))
                .transpose()?
                .unwrap_or(0),
            single_files_md5_hash_table
                .as_ref()
                .map(|payload| estimated_ewf2_section_size(payload.len() as u64))
                .transpose()?
                .unwrap_or(0),
            single_files_table_0x23
                .as_ref()
                .map(|payload| estimated_ewf2_section_size(payload.len() as u64))
                .transpose()?
                .unwrap_or(0),
            estimated_ewf2_section_size(table_data_size)?,
            estimated_ewf2_section_size(chunk_payload_size)?,
            md5_hash
                .as_ref()
                .map(|payload| estimated_ewf2_section_size(payload.len() as u64))
                .transpose()?
                .unwrap_or(0),
            sha1_hash
                .as_ref()
                .map(|payload| estimated_ewf2_section_size(payload.len() as u64))
                .transpose()?
                .unwrap_or(0),
            final_information_size,
            analytical_data
                .as_ref()
                .map(|payload| estimated_ewf2_section_size(payload.len() as u64))
                .transpose()?
                .unwrap_or(0),
            restart_data
                .as_ref()
                .map(|payload| estimated_ewf2_section_size(payload.len() as u64))
                .transpose()?
                .unwrap_or(0),
            options
                .single_files
                .as_ref()
                .map(ewf2_single_files_data_payload)
                .transpose()?
                .as_ref()
                .map(|payload| estimated_ewf2_section_size(payload.len() as u64))
                .transpose()?
                .unwrap_or(0),
            ewf2::SECTION_DESCRIPTOR_SIZE as u64,
        ],
        "estimated EWF2 segment size",
    )
}

fn estimated_ewf1_section_size(data_size: u64) -> Result<u64> {
    (ewf1::SECTION_DESCRIPTOR_SIZE as u64)
        .checked_add(data_size)
        .ok_or_else(|| EwfError::Malformed("writer estimated EWF1 section size overflow".into()))
}

fn estimated_ewf2_section_size(data_size: u64) -> Result<u64> {
    (ewf2::SECTION_DESCRIPTOR_SIZE as u64)
        .checked_add(data_size)
        .ok_or_else(|| EwfError::Malformed("writer estimated EWF2 section size overflow".into()))
}

fn checked_sum(parts: impl IntoIterator<Item = u64>, label: &str) -> Result<u64> {
    parts.into_iter().try_fold(0_u64, |total, part| {
        total
            .checked_add(part)
            .ok_or_else(|| EwfError::Malformed(format!("writer {label} overflow")))
    })
}

fn volume_data_size(format: WriteFormat) -> u64 {
    match format {
        WriteFormat::Ewf1Physical | WriteFormat::Ewf1Logical => VOLUME_DATA_SIZE as u64,
        WriteFormat::Ewf1Smart => 94,
        WriteFormat::Ewf2Physical | WriteFormat::Ewf2Logical => {
            unreachable!("EWF2 formats do not use EWF1 volume data")
        }
    }
}

fn segment_path(first_path: &Path, segment_number: usize) -> Result<PathBuf> {
    if segment_number == 1 {
        return Ok(first_path.to_path_buf());
    }
    Ok(first_path.with_extension(v1_segment_extension(first_path, segment_number)?))
}

fn ewf2_segment_path(first_path: &Path, segment_number: usize) -> Result<PathBuf> {
    if segment_number == 1 {
        return Ok(first_path.to_path_buf());
    }
    Ok(first_path.with_extension(v2_segment_extension(first_path, segment_number)?))
}

fn publication_segment_paths(written: &[PathBuf], is_v2: bool) -> Result<Vec<PathBuf>> {
    let first = &written[0];
    let prefix = first
        .extension()
        .and_then(|value| value.to_str())
        .and_then(|value| value.chars().next())
        .unwrap_or('E');
    let mut paths = written.to_vec();
    let existing = written
        .iter()
        .filter_map(|path| path.canonicalize().ok())
        .collect::<Vec<_>>();
    let mut stale = Vec::new();
    for entry in fs::read_dir(crate::segment::segment_dir(first))? {
        let path = entry?.path();
        if path.file_stem() != first.file_stem() {
            continue;
        }
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        if !crate::segment::is_segment_extension(extension, prefix, is_v2) {
            continue;
        }
        if written.contains(&path)
            || path
                .canonicalize()
                .is_ok_and(|path| existing.contains(&path))
        {
            continue;
        }
        stale.push(path);
    }
    stale.sort();
    paths.extend(stale);
    Ok(paths)
}

fn validate_secondary_segment_filename(
    primary_base: &Path,
    secondary_base: Option<&Path>,
) -> Result<()> {
    let Some(secondary_base) = secondary_base else {
        return Ok(());
    };
    if normalized_output_path(primary_base)? == normalized_output_path(secondary_base)? {
        return Err(EwfError::Unsupported(
            "secondary segment filename overlaps primary output".into(),
        ));
    }
    Ok(())
}

fn ensure_secondary_segment_path_is_distinct(
    primary_segment_paths: &[PathBuf],
    secondary_path: &Path,
) -> Result<()> {
    let secondary_path = normalized_output_path(secondary_path)?;
    for primary_path in primary_segment_paths {
        if normalized_output_path(primary_path)? == secondary_path {
            return Err(EwfError::Unsupported(
                "secondary segment filename overlaps primary output".into(),
            ));
        }
    }
    Ok(())
}

fn normalized_output_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
}

fn v1_segment_extension(first_path: &Path, segment_number: usize) -> Result<String> {
    let prefix = first_path
        .extension()
        .and_then(|value| value.to_str())
        .and_then(|value| value.chars().next())
        .unwrap_or('E')
        .to_ascii_uppercase();
    if segment_number <= 99 {
        return Ok(format!("{prefix}{segment_number:02}"));
    }

    let alpha_index = segment_number - 100;
    let prefix_offset = alpha_index / (26 * 26);
    let prefix = char::from_u32(
        (prefix as u32)
            .checked_add(prefix_offset as u32)
            .ok_or_else(|| {
                EwfError::Unsupported("EWF1 writer segment extension prefix overflow".into())
            })?,
    )
    .ok_or_else(|| EwfError::Unsupported("EWF1 writer segment extension prefix overflow".into()))?;
    if !prefix.is_ascii_uppercase() {
        return Err(EwfError::Unsupported(
            "EWF1 writer segment count exceeds supported extensions".into(),
        ));
    }

    let suffix = alpha_index % (26 * 26);
    let first = char::from(b'A' + u8::try_from(suffix / 26).expect("suffix fits u8"));
    let second = char::from(b'A' + u8::try_from(suffix % 26).expect("suffix fits u8"));
    Ok(format!("{prefix}{first}{second}"))
}

fn v2_segment_extension(first_path: &Path, segment_number: usize) -> Result<String> {
    let prefix = first_path
        .extension()
        .and_then(|value| value.to_str())
        .and_then(|value| value.chars().next())
        .unwrap_or('E')
        .to_ascii_uppercase();
    if segment_number <= 99 {
        return Ok(format!("{prefix}x{segment_number:02}"));
    }

    let alpha_index = segment_number - 100;
    let infix_offset = alpha_index / (26 * 26);
    let infix = char::from_u32(u32::from(b'x') + infix_offset as u32)
        .ok_or_else(|| EwfError::Unsupported("EWF2 writer segment extension overflow".into()))?;
    if !matches!(infix, 'x'..='z') {
        return Err(EwfError::Unsupported(
            "EWF2 writer segment count exceeds supported extensions".into(),
        ));
    }

    let suffix = alpha_index % (26 * 26);
    let first = char::from(b'A' + u8::try_from(suffix / 26).expect("suffix fits u8"));
    let second = char::from(b'A' + u8::try_from(suffix % 26).expect("suffix fits u8"));
    Ok(format!("{prefix}{infix}{first}{second}"))
}

fn volume_data(options: &WriteOptions, chunk_count: u32, sector_count: u64) -> Result<Vec<u8>> {
    let mut volume = vec![0; usize::try_from(volume_data_size(options.format)).expect("fits")];
    if options.format == WriteFormat::Ewf1Smart {
        volume[0] = 1;
    } else {
        volume[0] = ewf1_media_type_value(options.format, options.media_profile.media_type);
        volume[36] = ewf1_media_flags_value(options.format, options.media_profile);
    }
    volume[4..8].copy_from_slice(&chunk_count.to_le_bytes());
    volume[8..12].copy_from_slice(&options.sectors_per_chunk.to_le_bytes());
    volume[12..16].copy_from_slice(&options.bytes_per_sector.to_le_bytes());
    volume[52] = ewf1_compression_level_value(options.compression_values.level);
    if options.format == WriteFormat::Ewf1Smart {
        let sector_count = u32::try_from(sector_count)
            .map_err(|_| EwfError::Unsupported("EWF-S01 writer sector count exceeds u32".into()))?;
        volume[16..20].copy_from_slice(&sector_count.to_le_bytes());
        volume[85..90].copy_from_slice(b"SMART");
    } else {
        volume[16..24].copy_from_slice(&sector_count.to_le_bytes());
    }
    if let Some(identifier) = options
        .set_identifier
        .filter(|_| options.format != WriteFormat::Ewf1Smart)
    {
        volume[64..80].copy_from_slice(&identifier);
    }
    if let Some(error_granularity) = options
        .media_profile
        .error_granularity
        .filter(|_| options.format != WriteFormat::Ewf1Smart)
    {
        let error_granularity = u32::try_from(error_granularity).map_err(|_| {
            EwfError::Unsupported("EWF1 writer error granularity exceeds u32".into())
        })?;
        volume[56..60].copy_from_slice(&error_granularity.to_le_bytes());
    }
    let checksum_offset = volume.len() - 4;
    let checksum = adler32(&volume[..checksum_offset]);
    volume[checksum_offset..].copy_from_slice(&checksum.to_le_bytes());
    Ok(volume)
}

fn ewf1_compression_level_value(level: WriteCompressionLevel) -> u8 {
    match level {
        WriteCompressionLevel::Default | WriteCompressionLevel::None => 0,
        WriteCompressionLevel::Fast => 1,
        WriteCompressionLevel::Best => 2,
    }
}

fn ewf1_media_type_value(format: WriteFormat, media_type: Option<MediaType>) -> u8 {
    media_type.map_or_else(
        || match format {
            WriteFormat::Ewf1Logical => 0x0e,
            WriteFormat::Ewf1Physical | WriteFormat::Ewf1Smart => 0x00,
            WriteFormat::Ewf2Physical | WriteFormat::Ewf2Logical => {
                unreachable!("EWF2 formats do not use EWF1 media type values")
            }
        },
        ewf1_media_type_byte,
    )
}

fn ewf1_media_type_byte(media_type: MediaType) -> u8 {
    match media_type {
        MediaType::Removable => 0x00,
        MediaType::Fixed => 0x01,
        MediaType::Optical => 0x03,
        MediaType::SingleFiles => 0x0e,
        MediaType::Memory => 0x10,
        MediaType::Unknown(value) => value,
    }
}

fn ewf1_media_flags_value(format: WriteFormat, profile: WriteMediaProfile) -> u8 {
    let mut flags = 0x01;
    if format == WriteFormat::Ewf1Physical {
        flags |= 0x02;
    }
    if profile.fastbloc {
        flags |= 0x04;
    }
    if profile.tableau {
        flags |= 0x08;
    }
    flags
}

fn table_header(chunk_count: u32, sectors_data_offset: u64) -> [u8; 24] {
    let mut table = [0; 24];
    table[0..4].copy_from_slice(&chunk_count.to_le_bytes());
    table[8..16].copy_from_slice(&sectors_data_offset.to_le_bytes());
    let checksum = adler32(&table[..20]);
    table[20..24].copy_from_slice(&checksum.to_le_bytes());
    table
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ewf1TableGroup {
    first_chunk: usize,
    end_chunk: usize,
    payload_size: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Ewf1TableGroupState {
    group_count: u64,
    current_entry_count: usize,
    current_payload_size: u64,
}

impl Ewf1TableGroupState {
    fn add_chunk(self, data_size: u64, max_entries: usize, max_payload: u64) -> Result<Self> {
        let proposed_payload_size = self
            .current_payload_size
            .checked_add(data_size)
            .ok_or_else(|| EwfError::Malformed("writer table group payload overflow".into()))?;
        if self.current_entry_count != 0
            && (self.current_entry_count >= max_entries || proposed_payload_size > max_payload)
        {
            return Ok(Self {
                group_count: self.group_count.checked_add(1).ok_or_else(|| {
                    EwfError::Malformed("writer table group count overflow".into())
                })?,
                current_entry_count: 1,
                current_payload_size: data_size,
            });
        }

        Ok(Self {
            group_count: self.group_count.max(1),
            current_entry_count: self.current_entry_count.checked_add(1).ok_or_else(|| {
                EwfError::Malformed("writer table group entry count overflow".into())
            })?,
            current_payload_size: proposed_payload_size,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ewf1TableGroupLayout {
    first_chunk: usize,
    end_chunk: usize,
    payload_size: u64,
    sectors_desc_offset: u64,
    sectors_data_offset: u64,
    table_desc_offset: u64,
    table_data_size: u64,
    table2_desc_offset: Option<u64>,
    end_offset: u64,
}

fn ewf1_table_groups(
    chunks: &[ChunkDescriptor],
    max_entries: usize,
    max_payload: u64,
) -> Result<Vec<Ewf1TableGroup>> {
    let mut groups = Vec::new();
    let mut first_chunk = 0_usize;
    let mut state = Ewf1TableGroupState::default();
    for (index, chunk) in chunks.iter().enumerate() {
        let next_state = state.add_chunk(chunk.data_size, max_entries, max_payload)?;
        if next_state.group_count > state.group_count && state.current_entry_count != 0 {
            groups.push(Ewf1TableGroup {
                first_chunk,
                end_chunk: index,
                payload_size: state.current_payload_size,
            });
            first_chunk = index;
        }
        state = next_state;
    }
    groups.push(Ewf1TableGroup {
        first_chunk,
        end_chunk: chunks.len(),
        payload_size: state.current_payload_size,
    });
    Ok(groups)
}

fn ewf1_table_group_layouts(
    chunks: &[ChunkDescriptor],
    first_sectors_desc_offset: u64,
    table_footer_bytes: u64,
    writes_table2: bool,
) -> Result<Vec<Ewf1TableGroupLayout>> {
    let groups = ewf1_table_groups(
        chunks,
        EWF1_TABLE_GROUP_MAX_ENTRIES,
        EWF1_TABLE_GROUP_MAX_PAYLOAD,
    )?;
    let mut layouts = Vec::with_capacity(groups.len());
    let mut cursor = first_sectors_desc_offset;
    for group in groups {
        let table_entry_bytes = u64::try_from(group.end_chunk - group.first_chunk)
            .map_err(|_| EwfError::Malformed("writer table entry count does not fit u64".into()))?
            .checked_mul(4)
            .ok_or_else(|| EwfError::Malformed("writer table entry size overflow".into()))?;
        let table_data_size = 24_u64
            .checked_add(table_entry_bytes)
            .and_then(|value| value.checked_add(table_footer_bytes))
            .ok_or_else(|| EwfError::Malformed("writer table data size overflow".into()))?;
        let sectors_desc_offset = cursor;
        let sectors_data_offset = sectors_desc_offset
            .checked_add(ewf1::SECTION_DESCRIPTOR_SIZE as u64)
            .ok_or_else(|| EwfError::Malformed("writer sectors data offset overflow".into()))?;
        let table_desc_offset = sectors_data_offset
            .checked_add(group.payload_size)
            .ok_or_else(|| EwfError::Malformed("writer table descriptor offset overflow".into()))?;
        let table_end_offset = table_desc_offset
            .checked_add(ewf1::SECTION_DESCRIPTOR_SIZE as u64)
            .and_then(|value| value.checked_add(table_data_size))
            .ok_or_else(|| EwfError::Malformed("writer table section range overflow".into()))?;
        let (table2_desc_offset, end_offset) = if writes_table2 {
            let end_offset = table_end_offset
                .checked_add(ewf1::SECTION_DESCRIPTOR_SIZE as u64)
                .and_then(|value| value.checked_add(table_data_size))
                .ok_or_else(|| {
                    EwfError::Malformed("writer table2 section range overflow".into())
                })?;
            (Some(table_end_offset), end_offset)
        } else {
            (None, table_end_offset)
        };
        layouts.push(Ewf1TableGroupLayout {
            first_chunk: group.first_chunk,
            end_chunk: group.end_chunk,
            payload_size: group.payload_size,
            sectors_desc_offset,
            sectors_data_offset,
            table_desc_offset,
            table_data_size,
            table2_desc_offset,
            end_offset,
        });
        cursor = end_offset;
    }
    Ok(layouts)
}

fn append_ewf1_table_data(
    bytes: &mut Vec<u8>,
    chunk_count: u32,
    sectors_data_offset: u64,
    chunks: &[ChunkDescriptor],
    include_footer: bool,
) -> Result<()> {
    bytes.extend_from_slice(&table_header(chunk_count, sectors_data_offset));
    let table_entries_start = bytes.len();
    let mut relative_offset = 0_u64;
    for chunk in chunks {
        let mut entry = u32::try_from(relative_offset).map_err(|_| {
            EwfError::Unsupported("EWF1 writer raw chunk offset exceeds u32".into())
        })?;
        if entry & 0x8000_0000 != 0 {
            return Err(EwfError::Unsupported(
                "EWF1 writer raw chunk offset exceeds 31 bits".into(),
            ));
        }
        if chunk.compressed {
            entry |= 0x8000_0000;
        }
        bytes.extend_from_slice(&entry.to_le_bytes());
        relative_offset = relative_offset
            .checked_add(chunk.data_size)
            .ok_or_else(|| EwfError::Malformed("writer chunk offset overflow".into()))?;
    }
    if include_footer {
        let entries_checksum = adler32(&bytes[table_entries_start..]);
        bytes.extend_from_slice(&entries_checksum.to_le_bytes());
    }
    Ok(())
}

fn section_desc(section_type: &[u8], next: u64, size: u64) -> [u8; ewf1::SECTION_DESCRIPTOR_SIZE] {
    let mut desc = [0; ewf1::SECTION_DESCRIPTOR_SIZE];
    desc[..section_type.len()].copy_from_slice(section_type);
    desc[16..24].copy_from_slice(&next.to_le_bytes());
    desc[24..32].copy_from_slice(&size.to_le_bytes());
    let checksum = adler32(&desc[..ewf1::SECTION_DESCRIPTOR_SIZE - 4]);
    desc[ewf1::SECTION_DESCRIPTOR_SIZE - 4..].copy_from_slice(&checksum.to_le_bytes());
    desc
}

fn header_payload(
    metadata: &EwfMetadata,
    header_codepage: HeaderCodepage,
    compression_level: WriteCompressionLevel,
) -> Result<Option<Vec<u8>>> {
    ewf1_header_text(metadata, Ewf1HeaderDateStyle::Header)
        .map(|text| {
            zlib_payload(
                &encode_header_text(&text, header_codepage),
                compression_level,
            )
        })
        .transpose()
}

fn header2_payload(
    metadata: &EwfMetadata,
    compression_level: WriteCompressionLevel,
) -> Result<Option<Vec<u8>>> {
    ewf1_header_text(metadata, Ewf1HeaderDateStyle::Header2)
        .map(|text| zlib_payload(&utf16le(&text), compression_level))
        .transpose()
}

fn xheader_payload(
    metadata: &EwfMetadata,
    compression_level: WriteCompressionLevel,
) -> Result<Option<Vec<u8>>> {
    let fields = [
        ("case_number", metadata.case_number.as_deref()),
        ("description", metadata.description.as_deref()),
        ("examiner_name", metadata.examiner.as_deref()),
        ("evidence_number", metadata.evidence_number.as_deref()),
        ("notes", metadata.notes.as_deref()),
        ("acquiry_operating_system", metadata.os_version.as_deref()),
        ("acquiry_date", metadata.acquisition_date.as_deref()),
        ("acquiry_software", metadata.acquisition_software.as_deref()),
        (
            "acquiry_software_version",
            metadata.acquisition_software_version.as_deref(),
        ),
        ("password", metadata.password.as_deref()),
    ];
    if fields.iter().all(|(_, value)| value.is_none()) && metadata.header_values.is_empty() {
        return Ok(None);
    }

    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<xheader>\n");
    for (tag, value) in fields {
        let Some(value) = value else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        xml.push('\t');
        xml.push('<');
        xml.push_str(tag);
        xml.push('>');
        xml.push_str(&escape_xml_text(&xheader_field_value(tag, value)));
        xml.push_str("</");
        xml.push_str(tag);
        xml.push_str(">\n");
    }
    for (tag, value) in &metadata.header_values {
        if fields.iter().any(|(existing_tag, _)| existing_tag == tag) || value.is_empty() {
            continue;
        }
        xml.push('\t');
        xml.push('<');
        xml.push_str(tag);
        xml.push('>');
        xml.push_str(&escape_xml_text(&xheader_field_value(tag, value)));
        xml.push_str("</");
        xml.push_str(tag);
        xml.push_str(">\n");
    }
    xml.push_str("</xheader>\n\n");

    let mut payload = vec![0xef, 0xbb, 0xbf];
    payload.extend_from_slice(xml.as_bytes());
    Ok(Some(zlib_payload(&payload, compression_level)?))
}

fn xheader_field_value<'a>(tag: &str, value: &'a str) -> Cow<'a, str> {
    if tag == "acquiry_date" {
        format_xheader_date_value(value)
    } else {
        Cow::Borrowed(value)
    }
}

fn zlib_payload(payload: &[u8], compression_level: WriteCompressionLevel) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), zlib_compression(compression_level));
    encoder.write_all(payload)?;
    Ok(encoder.finish()?)
}

fn escape_xml_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ewf1HeaderDateStyle {
    Header,
    Header2,
}

fn ewf1_header_text(metadata: &EwfMetadata, date_style: Ewf1HeaderDateStyle) -> Option<String> {
    let fields = [
        ("c", metadata.case_number.as_deref()),
        ("n", metadata.evidence_number.as_deref()),
        ("a", metadata.description.as_deref()),
        ("e", metadata.examiner.as_deref()),
        ("t", metadata.notes.as_deref()),
        ("av", metadata.acquisition_software_version.as_deref()),
        ("ov", metadata.os_version.as_deref()),
        ("m", metadata.acquisition_date.as_deref()),
        ("u", metadata.system_date.as_deref()),
        ("p", metadata.password.as_deref()),
    ];
    if fields.iter().all(|(_, value)| value.is_none()) && metadata.header_values.is_empty() {
        return None;
    }

    let mut names = Vec::new();
    let mut values = Vec::new();
    for (name, value) in fields {
        if let Some(value) = value {
            names.push(name.to_string());
            values.push(sanitize_header_value(&ewf1_header_field_value(
                name, value, date_style,
            )));
        }
    }
    for (name, value) in &metadata.header_values {
        let tag = ewf1_header_tag(name);
        if metadata.password.is_some() && tag == "p" {
            continue;
        }
        if names.iter().any(|existing| existing == tag) {
            continue;
        }
        names.push(tag.to_string());
        values.push(sanitize_header_value(&ewf1_header_field_value(
            tag, value, date_style,
        )));
    }

    let text = format!("1\nmain\n{}\n{}\n", names.join("\t"), values.join("\t"));
    Some(text)
}

fn ewf1_header_tag(identifier: &str) -> &str {
    match identifier {
        "acquiry_date" => "m",
        "acquiry_operating_system" => "ov",
        "acquiry_software_version" => "av",
        "case_number" => "c",
        "compression_level" => "r",
        "description" => "a",
        "device_label" => "l",
        "evidence_number" => "n",
        "examiner_name" => "e",
        "extents" => "ext",
        "model" => "md",
        "notes" => "t",
        "password" => "p",
        "process_identifier" => "pid",
        "serial_number" => "sn",
        "system_date" => "u",
        "unknown_dc" => "dc",
        _ => identifier,
    }
}

fn ewf1_header_field_value<'a>(
    name: &str,
    value: &'a str,
    date_style: Ewf1HeaderDateStyle,
) -> Cow<'a, str> {
    if !matches!(name, "m" | "u" | "acquiry_date" | "system_date") {
        return Cow::Borrowed(value);
    }

    match date_style {
        Ewf1HeaderDateStyle::Header => format_ewf1_header_date_value(value),
        Ewf1HeaderDateStyle::Header2 => format_ewf1_header2_date_value(value),
    }
}

fn sanitize_header_value(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if matches!(ch, '\t' | '\n' | '\r') {
                ' '
            } else {
                ch
            }
        })
        .collect()
}

fn digest_payload(hashes: &WriteHashes) -> Option<[u8; 80]> {
    if hashes.md5.is_none() && hashes.sha1.is_none() {
        return None;
    }

    let mut digest = [0; 80];
    if let Some(md5) = hashes.md5 {
        digest[..16].copy_from_slice(&md5);
    }
    if let Some(sha1) = hashes.sha1 {
        digest[16..36].copy_from_slice(&sha1);
    }
    let checksum = adler32(&digest[..76]);
    digest[76..80].copy_from_slice(&checksum.to_le_bytes());
    Some(digest)
}

fn xhash_payload(
    hashes: &WriteHashes,
    compression_level: WriteCompressionLevel,
) -> Result<Option<Vec<u8>>> {
    if hashes.md5.is_none() && hashes.sha1.is_none() && hashes.hash_values.is_empty() {
        return Ok(None);
    }

    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<xhash>\n");
    if let Some(md5) = hashes.md5 {
        xml.push_str("\t<md5>");
        xml.push_str(&hex_string(&md5));
        xml.push_str("</md5>\n");
    }
    if let Some(sha1) = hashes.sha1 {
        xml.push_str("\t<sha1>");
        xml.push_str(&hex_string(&sha1));
        xml.push_str("</sha1>\n");
    }
    for (tag, value) in &hashes.hash_values {
        if matches!(tag.as_str(), "MD5" | "md5" | "SHA1" | "sha1") || value.is_empty() {
            continue;
        }
        xml.push('\t');
        xml.push('<');
        xml.push_str(tag);
        xml.push('>');
        xml.push_str(&escape_xml_text(value));
        xml.push_str("</");
        xml.push_str(tag);
        xml.push_str(">\n");
    }
    xml.push_str("</xhash>\n\n");

    let mut payload = vec![0xef, 0xbb, 0xbf];
    payload.extend_from_slice(xml.as_bytes());
    Ok(Some(zlib_payload(&payload, compression_level)?))
}

fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[(byte >> 4) as usize]));
        out.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(data_size: u64) -> ChunkDescriptor {
        ChunkDescriptor {
            data_offset: 0,
            data_size,
            compressed: false,
            has_checksum: false,
            pattern_fill: None,
        }
    }

    #[test]
    fn table_groups_split_at_31_bit_payload_cap() {
        let one_gib = 0x4000_0000_u64;
        let chunks = vec![chunk(one_gib), chunk(one_gib), chunk(one_gib)];

        let groups = ewf1_table_groups(
            &chunks,
            EWF1_TABLE_GROUP_MAX_ENTRIES,
            EWF1_TABLE_GROUP_MAX_PAYLOAD,
        )
        .unwrap();

        assert_eq!(groups.len(), 3);
        for group in &groups {
            assert!(group.payload_size <= EWF1_TABLE_GROUP_MAX_PAYLOAD);
        }
    }

    #[test]
    fn table_groups_split_at_entry_cap() {
        let chunks = vec![chunk(512); 5];

        let groups = ewf1_table_groups(&chunks, 2, EWF1_TABLE_GROUP_MAX_PAYLOAD).unwrap();

        assert_eq!(
            groups,
            [
                Ewf1TableGroup {
                    first_chunk: 0,
                    end_chunk: 2,
                    payload_size: 1024
                },
                Ewf1TableGroup {
                    first_chunk: 2,
                    end_chunk: 4,
                    payload_size: 1024
                },
                Ewf1TableGroup {
                    first_chunk: 4,
                    end_chunk: 5,
                    payload_size: 512
                },
            ]
        );
    }

    #[test]
    fn table_group_count_estimate_accounts_for_interacting_limits() {
        let large_chunk_size =
            EWF1_TABLE_GROUP_MAX_PAYLOAD / EWF1_TABLE_GROUP_MAX_ENTRIES as u64 + 1;
        let mut chunks = vec![chunk(1); EWF1_TABLE_GROUP_MAX_ENTRIES];
        chunks.extend(std::iter::repeat_n(
            chunk(large_chunk_size),
            EWF1_TABLE_GROUP_MAX_ENTRIES,
        ));
        let actual_groups = ewf1_table_groups(
            &chunks,
            EWF1_TABLE_GROUP_MAX_ENTRIES,
            EWF1_TABLE_GROUP_MAX_PAYLOAD,
        )
        .unwrap();
        let estimated_state = chunks
            .iter()
            .try_fold(Ewf1TableGroupState::default(), |state, chunk| {
                state.add_chunk(
                    chunk.data_size,
                    EWF1_TABLE_GROUP_MAX_ENTRIES,
                    EWF1_TABLE_GROUP_MAX_PAYLOAD,
                )
            })
            .unwrap();

        assert_eq!(actual_groups.len(), 3);
        assert_eq!(estimated_state.group_count, actual_groups.len() as u64);
    }

    #[test]
    fn segment_groups_respect_maximum_size_when_table_limits_interact() {
        let large_chunk_size =
            EWF1_TABLE_GROUP_MAX_PAYLOAD / EWF1_TABLE_GROUP_MAX_ENTRIES as u64 + 1;
        let mut chunks = vec![chunk(1); EWF1_TABLE_GROUP_MAX_ENTRIES];
        chunks.extend(std::iter::repeat_n(
            chunk(large_chunk_size),
            EWF1_TABLE_GROUP_MAX_ENTRIES,
        ));
        let options = WriteOptions::default();
        let payload_size = chunks.iter().map(|chunk| chunk.data_size).sum();
        let old_aggregate_estimate =
            estimated_ewf1_segment_size(chunks.len(), payload_size, 2, &options).unwrap();

        let segments =
            segment_groups(&chunks, Some(old_aggregate_estimate), &options, 0, 0).unwrap();

        assert!(segments.len() > 1);
        for segment_range in segments {
            let segment = &chunks[segment_range];
            let payload_size = segment.iter().map(|chunk| chunk.data_size).sum();
            let table_group_state = segment
                .iter()
                .try_fold(Ewf1TableGroupState::default(), |state, chunk| {
                    state.add_chunk(
                        chunk.data_size,
                        EWF1_TABLE_GROUP_MAX_ENTRIES,
                        EWF1_TABLE_GROUP_MAX_PAYLOAD,
                    )
                })
                .unwrap();
            let estimated_size = estimated_ewf1_segment_size(
                segment.len(),
                payload_size,
                table_group_state.group_count,
                &options,
            )
            .unwrap();
            assert!(estimated_size <= old_aggregate_estimate);
        }
    }

    #[test]
    fn segment_groups_return_ranges_into_descriptor_slice() {
        let chunks = vec![chunk(512); 3];
        let options = WriteOptions::default();
        let one_chunk_segment_size = estimated_ewf1_segment_size(1, 512, 1, &options).unwrap();

        let groups: Vec<std::ops::Range<usize>> =
            segment_groups(&chunks, Some(one_chunk_segment_size), &options, 0, 0).unwrap();

        assert_eq!(groups, [0..1, 1..2, 2..3]);
    }

    #[test]
    fn table_groups_keep_small_payload_in_one_group() {
        let chunks = vec![chunk(32_768), chunk(32_768)];

        let groups = ewf1_table_groups(
            &chunks,
            EWF1_TABLE_GROUP_MAX_ENTRIES,
            EWF1_TABLE_GROUP_MAX_PAYLOAD,
        )
        .unwrap();

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].payload_size, 65_536);
    }

    #[test]
    fn table_groups_cover_empty_chunk_list_with_one_empty_group() {
        let groups = ewf1_table_groups(
            &[],
            EWF1_TABLE_GROUP_MAX_ENTRIES,
            EWF1_TABLE_GROUP_MAX_PAYLOAD,
        )
        .unwrap();

        assert_eq!(
            groups,
            [Ewf1TableGroup {
                first_chunk: 0,
                end_chunk: 0,
                payload_size: 0
            }]
        );
    }

    #[test]
    fn table_group_layouts_chain_sequential_section_offsets() {
        let chunks = vec![chunk(0x4000_0000), chunk(0x4000_0000), chunk(0x4000_0000)];

        let layouts = ewf1_table_group_layouts(&chunks, 1000, 4, true).unwrap();

        assert_eq!(layouts.len(), 3);
        let mut expected_offset = 1000;
        for (index, layout) in layouts.iter().enumerate() {
            assert_eq!(layout.sectors_desc_offset, expected_offset);
            assert_eq!(layout.sectors_data_offset, expected_offset + 76);
            assert_eq!(
                layout.table_desc_offset,
                layout.sectors_data_offset + 0x4000_0000
            );
            assert_eq!(layout.table_data_size, 24 + 4 + 4);
            assert_eq!(
                layout.table2_desc_offset,
                Some(layout.table_desc_offset + 76 + layout.table_data_size)
            );
            assert_eq!(layout.first_chunk, index);
            assert_eq!(layout.end_chunk, index + 1);
            expected_offset = layout.end_offset;
        }
    }
}

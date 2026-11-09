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
use std::path::PathBuf;

use crate::date_time::format_header_date_value;
use crate::decode::{ChunkEncoding, decode_chunk};
use crate::{EwfError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Top-level EWF container generation.
pub enum Format {
    /// Original EWF/EVF/LVF segment format.
    Ewf1,
    /// EWF2/Ex01/Lx01 segment format.
    Ewf2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
/// Producer/profile inferred from EWF metadata and section layout.
pub enum FormatProfile {
    /// The image profile could not be identified.
    #[default]
    Unknown,
    /// `EnCase` version 1 style EWF1 image.
    EnCase1,
    /// `EnCase` version 2 style EWF1 image.
    EnCase2,
    /// `EnCase` version 3 style EWF1 image.
    EnCase3,
    /// `EnCase` version 4 style EWF1 image.
    EnCase4,
    /// `EnCase` version 5 style EWF1 image.
    EnCase5,
    /// `EnCase` version 6 style EWF1 image.
    EnCase6,
    /// `EnCase` version 7 style EWF1 image.
    EnCase7,
    /// SMART `.S01` style image.
    Smart,
    /// FTK Imager style EWF1 image.
    FtkImager,
    /// Linen version 5 style EWF1 image.
    Linen5,
    /// Linen version 6 style EWF1 image.
    Linen6,
    /// Linen version 7 style EWF1 image.
    Linen7,
    /// `EnCase` 5 logical `.L01` style image.
    LogicalEnCase5,
    /// `EnCase` 6 logical `.L01` style image.
    LogicalEnCase6,
    /// `EnCase` 7 logical `.L01` style image.
    LogicalEnCase7,
    /// `EnCase` 7 EWF2 physical `.Ex01` style image.
    Ewf2EnCase7,
    /// `EnCase` 7 EWF2 logical `.Lx01` style image.
    Ewf2LogicalEnCase7,
    /// Generic EWF-compatible image.
    Ewf,
    /// EWF extended profile.
    Ewfx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
/// Compression method recorded for stored chunks.
pub enum CompressionMethod {
    /// Chunks are stored without compression.
    None,
    /// Chunks use zlib compression.
    Zlib,
    /// Chunks in X-Ways EWF1 images use Zstandard compression.
    Zstd,
    /// Chunks use `BZip2` compression.
    Bzip2,
    /// An unrecognized on-disk compression method value.
    Unknown(u16),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
/// Compression level recorded in EWF metadata.
pub enum CompressionLevel {
    /// Producer default compression level.
    Default,
    /// No compression.
    #[default]
    None,
    /// Fast compression.
    Fast,
    /// Best compression.
    Best,
    /// An unrecognized on-disk compression level value.
    Unknown(i8),
}

impl CompressionLevel {
    /// Returns the EWF metadata numeric representation for this level.
    pub fn as_i8(self) -> i8 {
        match self {
            Self::Default => -1,
            Self::None => 0,
            Self::Fast => 1,
            Self::Best => 2,
            Self::Unknown(value) => value,
        }
    }

    /// Converts an EWF metadata numeric compression level.
    pub fn from_i8(value: i8) -> Self {
        match value {
            -1 => Self::Default,
            0 => Self::None,
            1 => Self::Fast,
            2 => Self::Best,
            value => Self::Unknown(value),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
/// Compression flags recorded in EWF metadata.
pub struct CompressionFlags {
    /// Empty-block compression flag.
    pub empty_block: bool,
    /// Pattern-fill compression flag.
    pub pattern_fill: bool,
    /// Bits not recognized by this crate.
    pub unknown_bits: u8,
}

impl CompressionFlags {
    const EMPTY_BLOCK: u8 = 0x01;
    const PATTERN_FILL: u8 = 0x10;
    const KNOWN_BITS: u8 = Self::EMPTY_BLOCK | Self::PATTERN_FILL;

    /// Decodes a raw EWF compression flags byte.
    pub fn from_bits(bits: u8) -> Self {
        Self {
            empty_block: bits & Self::EMPTY_BLOCK != 0,
            pattern_fill: bits & Self::PATTERN_FILL != 0,
            unknown_bits: bits & !Self::KNOWN_BITS,
        }
    }

    /// Encodes these flags as a raw EWF compression flags byte.
    pub fn bits(self) -> u8 {
        let mut bits = self.unknown_bits;
        if self.empty_block {
            bits |= Self::EMPTY_BLOCK;
        }
        if self.pattern_fill {
            bits |= Self::PATTERN_FILL;
        }
        bits
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
/// Compression level and flags recorded together.
pub struct CompressionValues {
    /// Compression level metadata.
    pub level: CompressionLevel,
    /// Compression flag metadata.
    pub flags: CompressionFlags,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Media type recorded for an image.
pub enum MediaType {
    /// Removable physical media.
    Removable,
    /// Fixed physical media.
    Fixed,
    /// Optical media.
    Optical,
    /// Logical single-file collection.
    SingleFiles,
    /// Memory acquisition.
    Memory,
    /// An unrecognized on-disk media type value.
    Unknown(u8),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
/// Media flags recorded for an image.
pub struct MediaFlags {
    /// The image represents physical media.
    pub physical: bool,
    /// `FastBloc` acquisition flag.
    pub fastbloc: bool,
    /// Tableau acquisition flag.
    pub tableau: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// EWF2 segment file version.
pub struct SegmentFileVersion {
    /// Major version number.
    pub major: u8,
    /// Minor version number.
    pub minor: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// Parsed media geometry and storage metadata.
pub struct MediaInfo {
    /// Number of sectors represented by each chunk, if present.
    pub sectors_per_chunk: Option<u64>,
    /// Bytes in each logical sector, if present.
    pub bytes_per_sector: Option<u64>,
    /// Total logical sector count, if present.
    pub sector_count: Option<u64>,
    /// Total logical chunk count, if present.
    pub chunk_count: Option<u64>,
    /// Error granularity in sectors, if present.
    pub error_granularity: Option<u64>,
    /// Segment set identifier, if present.
    pub set_identifier: Option<[u8; 16]>,
    /// EWF2 segment file version, if present.
    pub ewf2_segment_file_version: Option<SegmentFileVersion>,
    /// Compression method metadata, if present.
    pub compression_method: Option<CompressionMethod>,
    /// Compression level and flags metadata.
    pub compression_values: CompressionValues,
    /// Media type metadata, if present.
    pub media_type: Option<MediaType>,
    /// Media flags metadata.
    pub media_flags: MediaFlags,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Strictness used while opening an image.
///
/// Neither mode substitutes data: a chunk that cannot be located and verified
/// fails when read.
pub enum OpenStrictness {
    /// Treat any structural inconsistency as an error that fails opening.
    Strict,
    /// The default. Go past structural damage that the image can still be
    /// checked without, and fail only the chunks that cannot be verified. Each
    /// defect gone past is recorded and available from `Image::lenient_findings`
    /// and in `Image::analyze` reports (both with the `verify` feature).
    Lenient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Options that control how an image is opened and read.
///
/// Configure values with the `with_*` builders and inspect them with getters.
pub struct OpenOptions {
    /// Structural validation policy; lenient by default.
    strictness: OpenStrictness,
    /// Capacity policy for the decoded-chunk cache.
    chunk_cache_capacity: ChunkCacheCapacity,
    /// Maximum bytes retained for cached table-entry pages.
    table_entry_cache_size_bytes: usize,
    /// Whether cumulative reader statistics are collected.
    reader_statistics: bool,
    /// Return zero-filled chunk data when a chunk checksum fails.
    read_zero_chunk_on_error: bool,
    /// Codepage used to decode EWF1 header values.
    header_codepage: HeaderCodepage,
    /// Date formatting applied when returning header date values.
    header_values_date_format: HeaderDateFormat,
    /// Maximum number of simultaneously open segment handles.
    maximum_open_handles: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Capacity policy for the decoded-chunk cache.
pub enum ChunkCacheCapacity {
    /// Retain at most this many decoded chunks.
    Chunks(usize),
    /// Derive the retained chunk count from this byte target.
    Bytes(usize),
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            strictness: OpenStrictness::Lenient,
            chunk_cache_capacity: ChunkCacheCapacity::Chunks(64),
            table_entry_cache_size_bytes: 4 * 1024 * 1024,
            reader_statistics: false,
            read_zero_chunk_on_error: false,
            header_codepage: HeaderCodepage::Ascii,
            header_values_date_format: HeaderDateFormat::Ctime,
            maximum_open_handles: None,
        }
    }
}

impl OpenOptions {
    /// Returns the structural validation policy.
    pub fn strictness(&self) -> OpenStrictness {
        self.strictness
    }

    /// Sets the structural validation policy. The default is
    /// [`OpenStrictness::Lenient`].
    #[must_use]
    pub fn with_strictness(mut self, strictness: OpenStrictness) -> Self {
        self.strictness = strictness;
        self
    }

    /// Returns the decoded-chunk cache capacity policy.
    pub fn chunk_cache_capacity(&self) -> ChunkCacheCapacity {
        self.chunk_cache_capacity
    }

    /// Configures the decoded-chunk cache by entry count.
    #[must_use]
    pub fn with_chunk_cache_size(mut self, chunk_count: usize) -> Self {
        self.chunk_cache_capacity = ChunkCacheCapacity::Chunks(chunk_count);
        self
    }

    /// Configures the decoded-chunk cache by byte target.
    ///
    /// At least one decoded chunk is retained even when one chunk exceeds the
    /// requested byte target.
    #[must_use]
    pub fn with_chunk_cache_size_bytes(mut self, bytes: usize) -> Self {
        self.chunk_cache_capacity = ChunkCacheCapacity::Bytes(bytes);
        self
    }

    /// Returns the table-entry page-cache byte limit.
    pub fn table_entry_cache_size_bytes(&self) -> usize {
        self.table_entry_cache_size_bytes
    }

    /// Sets the table-entry page-cache byte limit.
    ///
    /// A value of zero disables retention of table-entry pages.
    #[must_use]
    pub fn with_table_entry_cache_size_bytes(mut self, bytes: usize) -> Self {
        self.table_entry_cache_size_bytes = bytes;
        self
    }

    /// Returns whether cumulative reader statistics are collected.
    pub fn reader_statistics_enabled(&self) -> bool {
        self.reader_statistics
    }

    /// Enables or disables cumulative reader statistics collection.
    #[must_use]
    pub fn with_reader_statistics(mut self, enabled: bool) -> Self {
        self.reader_statistics = enabled;
        self
    }

    /// Returns whether malformed chunks are recovered as zero-filled data.
    pub fn read_zero_chunk_on_error(&self) -> bool {
        self.read_zero_chunk_on_error
    }

    /// Enables or disables malformed-chunk recovery as zero-filled data.
    #[must_use]
    pub fn with_read_zero_chunk_on_error(mut self, enabled: bool) -> Self {
        self.read_zero_chunk_on_error = enabled;
        self
    }

    /// Returns the EWF1 header codepage.
    pub fn header_codepage(&self) -> HeaderCodepage {
        self.header_codepage
    }

    /// Sets the EWF1 header codepage.
    #[must_use]
    pub fn with_header_codepage(mut self, codepage: HeaderCodepage) -> Self {
        self.header_codepage = codepage;
        self
    }

    /// Returns the header-value date format.
    pub fn header_values_date_format(&self) -> HeaderDateFormat {
        self.header_values_date_format
    }

    /// Sets the header-value date format.
    #[must_use]
    pub fn with_header_values_date_format(mut self, format: HeaderDateFormat) -> Self {
        self.header_values_date_format = format;
        self
    }

    /// Returns the maximum number of simultaneously open segment handles.
    pub fn maximum_open_handles(&self) -> Option<usize> {
        self.maximum_open_handles
    }

    /// Sets the maximum number of simultaneously open segment handles.
    #[must_use]
    pub fn with_maximum_open_handles(mut self, maximum: Option<usize>) -> Self {
        self.maximum_open_handles = maximum;
        self
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
/// Codepage used for EWF1 textual header values.
pub enum HeaderCodepage {
    /// ASCII header encoding.
    #[default]
    Ascii,
    /// Windows-874 header encoding.
    Windows874,
    /// Windows-932 header encoding.
    Windows932,
    /// Windows-936 header encoding.
    Windows936,
    /// Windows-1250 header encoding.
    Windows1250,
    /// Windows-1251 header encoding.
    Windows1251,
    /// Windows-1252 header encoding.
    Windows1252,
    /// Windows-1253 header encoding.
    Windows1253,
    /// Windows-1254 header encoding.
    Windows1254,
    /// Windows-1255 header encoding.
    Windows1255,
    /// Windows-1256 header encoding.
    Windows1256,
    /// Windows-1257 header encoding.
    Windows1257,
    /// Windows-1258 header encoding.
    Windows1258,
}

impl HeaderCodepage {
    /// Returns the EWF numeric codepage identifier.
    pub fn as_i32(self) -> i32 {
        match self {
            Self::Ascii => 20_127,
            Self::Windows874 => 874,
            Self::Windows932 => 932,
            Self::Windows936 => 936,
            Self::Windows1250 => 1250,
            Self::Windows1251 => 1251,
            Self::Windows1252 => 1252,
            Self::Windows1253 => 1253,
            Self::Windows1254 => 1254,
            Self::Windows1255 => 1255,
            Self::Windows1256 => 1256,
            Self::Windows1257 => 1257,
            Self::Windows1258 => 1258,
        }
    }

    /// Converts an EWF numeric codepage identifier.
    pub fn from_i32(value: i32) -> Option<Self> {
        Some(match value {
            20_127 => Self::Ascii,
            874 => Self::Windows874,
            932 => Self::Windows932,
            936 => Self::Windows936,
            1250 => Self::Windows1250,
            1251 => Self::Windows1251,
            1252 => Self::Windows1252,
            1253 => Self::Windows1253,
            1254 => Self::Windows1254,
            1255 => Self::Windows1255,
            1256 => Self::Windows1256,
            1257 => Self::Windows1257,
            1258 => Self::Windows1258,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
/// Formatting applied when returning parsed EWF header date values.
pub enum HeaderDateFormat {
    /// Day-month date order.
    DayMonth,
    /// Month-day date order.
    MonthDay,
    /// ISO 8601-style date formatting.
    Iso8601,
    /// C `ctime`-style date formatting.
    #[default]
    Ctime,
}

impl HeaderDateFormat {
    /// Returns the numeric date-format identifier used by this crate.
    pub fn as_i32(self) -> i32 {
        match self {
            Self::DayMonth => 1,
            Self::MonthDay => 2,
            Self::Iso8601 => 3,
            Self::Ctime => 4,
        }
    }

    /// Converts a numeric date-format identifier used by this crate.
    pub fn from_i32(value: i32) -> Option<Self> {
        Some(match value {
            1 => Self::DayMonth,
            2 => Self::MonthDay,
            3 => Self::Iso8601,
            4 => Self::Ctime,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// Parsed case and acquisition metadata.
pub struct EwfMetadata {
    /// Case number header value.
    pub case_number: Option<String>,
    /// Evidence number header value.
    pub evidence_number: Option<String>,
    /// Examiner name header value.
    pub examiner: Option<String>,
    /// Case description header value.
    pub description: Option<String>,
    /// Notes header value.
    pub notes: Option<String>,
    /// Acquisition software name.
    pub acquisition_software: Option<String>,
    /// Acquisition software version.
    pub acquisition_software_version: Option<String>,
    /// Acquisition operating system version.
    pub os_version: Option<String>,
    /// Acquisition date header value.
    pub acquisition_date: Option<String>,
    /// System date header value.
    pub system_date: Option<String>,
    /// Password header value, when present in metadata.
    pub password: Option<String>,
    /// Non-standard or otherwise unmapped header values.
    pub header_values: BTreeMap<String, String>,
}

impl EwfMetadata {
    /// Replaces this metadata with another metadata value.
    pub fn copy_header_values_from(&mut self, source: &EwfMetadata) {
        *self = source.clone();
    }

    /// Returns a header value by its EWF identifier.
    pub fn header_value(&self, identifier: &str) -> Option<&str> {
        self.standard_header_value(identifier)
            .or_else(|| self.header_values.get(identifier).map(String::as_str))
    }

    /// Returns a header value, applying date formatting for known date fields.
    pub fn header_value_with_date_format(
        &self,
        identifier: &str,
        date_format: HeaderDateFormat,
    ) -> Option<Cow<'_, str>> {
        let value = self.header_value(identifier)?;
        if matches!(identifier, "acquiry_date" | "system_date") {
            Some(format_header_date_value(value, date_format))
        } else {
            Some(Cow::Borrowed(value))
        }
    }

    /// Sets a header value by its EWF identifier and returns the previous value.
    pub fn set_header_value(
        &mut self,
        identifier: &str,
        value: impl Into<String>,
    ) -> Option<String> {
        let previous = self.header_value(identifier).map(str::to_owned);
        let value = value.into();

        self.header_values.remove(identifier);
        match identifier {
            "case_number" => self.case_number = Some(value),
            "description" => self.description = Some(value),
            "examiner_name" => self.examiner = Some(value),
            "evidence_number" => self.evidence_number = Some(value),
            "notes" => self.notes = Some(value),
            "acquiry_date" => self.acquisition_date = Some(value),
            "system_date" => self.system_date = Some(value),
            "acquiry_operating_system" => self.os_version = Some(value),
            "acquiry_software" => self.acquisition_software = Some(value),
            "acquiry_software_version" => self.acquisition_software_version = Some(value),
            "password" => self.password = Some(value),
            _ => {
                self.header_values.insert(identifier.to_string(), value);
            }
        }

        previous
    }

    /// Returns the number of available header values.
    pub fn number_of_header_values(&self) -> usize {
        let standard_count = STANDARD_HEADER_VALUE_IDENTIFIERS
            .iter()
            .filter(|identifier| self.header_value(identifier).is_some())
            .count();
        let generic_count = self
            .header_values
            .keys()
            .filter(|identifier| !is_standard_header_value_identifier(identifier))
            .count();
        standard_count + generic_count
    }

    /// Returns the header value identifier at a stable enumeration index.
    pub fn header_value_identifier(&self, index: usize) -> Option<&str> {
        let mut remaining = index;
        for identifier in STANDARD_HEADER_VALUE_IDENTIFIERS {
            if self.header_value(identifier).is_some() {
                if remaining == 0 {
                    return Some(identifier);
                }
                remaining -= 1;
            }
        }

        for identifier in self.header_values.keys() {
            if is_standard_header_value_identifier(identifier) {
                continue;
            }
            if remaining == 0 {
                return Some(identifier);
            }
            remaining -= 1;
        }

        None
    }

    fn standard_header_value(&self, identifier: &str) -> Option<&str> {
        match identifier {
            "case_number" => self.case_number.as_deref(),
            "description" => self.description.as_deref(),
            "examiner_name" => self.examiner.as_deref(),
            "evidence_number" => self.evidence_number.as_deref(),
            "notes" => self.notes.as_deref(),
            "acquiry_date" => self.acquisition_date.as_deref(),
            "system_date" => self.system_date.as_deref(),
            "acquiry_operating_system" => self.os_version.as_deref(),
            "acquiry_software" => self.acquisition_software.as_deref(),
            "acquiry_software_version" => self.acquisition_software_version.as_deref(),
            "password" => self.password.as_deref(),
            _ => None,
        }
    }
}

const STANDARD_HEADER_VALUE_IDENTIFIERS: &[&str] = &[
    "case_number",
    "description",
    "examiner_name",
    "evidence_number",
    "notes",
    "acquiry_date",
    "system_date",
    "acquiry_operating_system",
    "acquiry_software",
    "acquiry_software_version",
    "password",
    "compression_level",
    "model",
    "serial_number",
];

fn is_standard_header_value_identifier(identifier: &str) -> bool {
    STANDARD_HEADER_VALUE_IDENTIFIERS.contains(&identifier)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// Stored hash values parsed from an image.
pub struct StoredHashes {
    /// Parsed MD5 hash bytes, if a valid MD5 value was stored.
    pub md5: Option<[u8; 16]>,
    /// Parsed SHA1 hash bytes, if a valid SHA1 value was stored.
    pub sha1: Option<[u8; 20]>,
    /// Stored hash strings keyed by hash identifier.
    pub hash_values: BTreeMap<String, String>,
}

impl StoredHashes {
    /// Returns a stored hash value by identifier.
    pub fn hash_value(&self, identifier: &str) -> Option<&str> {
        self.hash_values.get(identifier).map(String::as_str)
    }

    /// Sets a stored hash value and returns the previous string value.
    pub fn set_hash_value(
        &mut self,
        identifier: impl Into<String>,
        value: impl Into<String>,
    ) -> Option<String> {
        let identifier = identifier.into();
        let value = value.into();
        set_typed_hash_value(&identifier, &value, &mut self.md5, &mut self.sha1);
        self.hash_values.insert(identifier, value)
    }

    /// Returns the number of stored hash values.
    pub fn number_of_hash_values(&self) -> usize {
        self.hash_values.len()
    }

    /// Returns the hash identifier at a stable enumeration index.
    pub fn hash_value_identifier(&self, index: usize) -> Option<&str> {
        self.hash_values.keys().nth(index).map(String::as_str)
    }
}

pub(crate) fn set_typed_hash_value(
    identifier: &str,
    value: &str,
    md5: &mut Option<[u8; 16]>,
    sha1: &mut Option<[u8; 20]>,
) {
    if identifier.eq_ignore_ascii_case("MD5") {
        if let Some(parsed) = parse_hex_array(value) {
            *md5 = Some(parsed);
        }
    } else if identifier.eq_ignore_ascii_case("SHA1")
        && let Some(parsed) = parse_hex_array(value)
    {
        *sha1 = Some(parsed);
    }
}

pub(crate) fn parse_hex_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 {
        return None;
    }

    let mut bytes = [0; N];
    for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes[index] = (high << 4) | low;
    }
    Some(bytes)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Acquisition error range recorded in image metadata.
pub struct AcquisitionError {
    /// First sector affected by the acquisition error.
    pub first_sector: u64,
    /// Number of sectors affected by the acquisition error.
    pub sector_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Inclusive start plus count sector range.
pub struct SectorRange {
    /// First sector in the range.
    pub first_sector: u64,
    /// Number of sectors in the range.
    pub sector_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Memory acquisition extent recorded in pages.
pub struct MemoryExtent {
    /// First memory page in the extent.
    pub start_page: u64,
    /// Number of pages in the extent.
    pub page_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
/// Encoding used for a data chunk payload.
pub enum DataChunkEncoding {
    /// Uncompressed chunk data.
    Raw,
    /// zlib-compressed chunk data.
    Zlib,
    /// X-Ways EWF1 magicless Zstandard data or its one-byte zero marker.
    Zstd,
    /// BZip2-compressed chunk data.
    Bzip2,
    /// Pattern-fill chunk data with the repeated pattern value.
    PatternFill(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Decoded logical data chunk.
pub struct DataChunk {
    /// Zero-based logical chunk index.
    pub chunk_index: u64,
    /// Logical byte offset of the chunk.
    pub logical_offset: u64,
    /// Logical byte size of the decoded chunk.
    pub logical_size: usize,
    /// Encoded byte size as stored in the segment.
    pub encoded_size: u64,
    /// Encoding used by the stored chunk.
    pub encoding: DataChunkEncoding,
    /// Whether the chunk was returned under a corruption-tolerant read policy.
    pub corrupted: bool,
    /// Decoded chunk bytes.
    pub data: Vec<u8>,
}

impl DataChunk {
    /// Returns whether this chunk was marked corrupted while reading.
    pub fn is_corrupted(&self) -> bool {
        self.corrupted
    }

    /// Copies decoded chunk bytes into `buffer`.
    pub fn read_buffer(&self, buffer: &mut [u8]) -> Result<usize> {
        Ok(copy_to_buffer(&self.data, buffer))
    }

    /// Replaces this chunk with raw bytes from `buffer`.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer length does not fit in EWF chunk metadata.
    pub fn write_buffer(&mut self, buffer: &[u8]) -> Result<usize> {
        self.data.clear();
        self.data.extend_from_slice(buffer);
        self.logical_size = buffer.len();
        self.encoded_size = u64::try_from(buffer.len())
            .map_err(|_| EwfError::Malformed("data chunk buffer size overflow".into()))?;
        self.encoding = DataChunkEncoding::Raw;
        self.corrupted = false;
        Ok(buffer.len())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Encoded data chunk as stored in an EWF segment.
pub struct EncodedDataChunk {
    /// Zero-based logical chunk index.
    pub chunk_index: u64,
    /// Logical byte offset of the chunk.
    pub logical_offset: u64,
    /// Logical byte size after decoding.
    pub logical_size: usize,
    /// Encoded byte size stored in the segment.
    pub encoded_size: u64,
    /// Encoding used by the chunk payload.
    pub encoding: DataChunkEncoding,
    /// Whether raw chunk data includes a checksum trailer.
    pub has_checksum: bool,
    /// Encoded chunk bytes.
    pub data: Vec<u8>,
}

impl EncodedDataChunk {
    /// Decodes this chunk and copies logical bytes into `buffer`.
    ///
    /// # Errors
    ///
    /// Returns an error if checksum validation or decompression fails.
    pub fn read_buffer(&self, buffer: &mut [u8]) -> Result<usize> {
        if self.has_checksum && self.encoding == DataChunkEncoding::Raw {
            validate_raw_data_chunk_checksum(&self.data, self.logical_size)?;
        }

        let decoded = decode_chunk(
            &self.data,
            data_chunk_encoding(self.encoding),
            self.logical_size,
        )?;
        Ok(copy_to_buffer(&decoded, buffer))
    }
}

fn copy_to_buffer(data: &[u8], buffer: &mut [u8]) -> usize {
    let read_size = data.len().min(buffer.len());
    buffer[..read_size].copy_from_slice(&data[..read_size]);
    read_size
}

fn data_chunk_encoding(encoding: DataChunkEncoding) -> ChunkEncoding {
    match encoding {
        DataChunkEncoding::Raw => ChunkEncoding::Raw,
        DataChunkEncoding::Zlib => ChunkEncoding::Zlib,
        DataChunkEncoding::Zstd => ChunkEncoding::Zstd,
        DataChunkEncoding::Bzip2 => ChunkEncoding::Bzip2,
        DataChunkEncoding::PatternFill(pattern) => ChunkEncoding::PatternFill(pattern),
    }
}

fn validate_raw_data_chunk_checksum(encoded: &[u8], logical_size: usize) -> Result<()> {
    let checksum_end = logical_size
        .checked_add(4)
        .ok_or_else(|| EwfError::Malformed("raw chunk checksum offset overflow".into()))?;
    if encoded.len() < checksum_end {
        return Err(EwfError::Malformed(
            "raw chunk checksum trailer is missing".into(),
        ));
    }

    let stored = u32::from_le_bytes(
        encoded[logical_size..checksum_end]
            .try_into()
            .expect("raw chunk checksum slice has fixed size"),
    );
    let calculated = adler32(&encoded[..logical_size]);
    if stored != calculated {
        return Err(EwfError::Malformed("raw chunk checksum mismatch".into()));
    }

    Ok(())
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Type of a logical single-file catalog entry.
pub enum SingleFileEntryType {
    /// Regular file entry.
    File,
    /// Directory entry.
    Directory,
    /// Entry type not recognized by this crate.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Data extent for a logical single-file entry.
pub struct SingleFileExtent {
    /// Logical media offset where this extent's data starts.
    pub data_offset: u64,
    /// Number of bytes represented by this extent.
    pub data_size: u64,
    /// Whether the extent is sparse and should read as zeroes.
    pub sparse: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// Source record for logical single-file metadata.
pub struct SingleFileSource {
    /// Source identifier.
    pub identifier: Option<i32>,
    /// Source name.
    pub name: Option<String>,
    /// Evidence number associated with the source.
    pub evidence_number: Option<String>,
    /// Source location.
    pub location: Option<String>,
    /// Source device GUID.
    pub device_guid: Option<String>,
    /// Primary source device GUID.
    pub primary_device_guid: Option<String>,
    /// Source drive type code.
    pub drive_type: Option<char>,
    /// Source manufacturer.
    pub manufacturer: Option<String>,
    /// Source model.
    pub model: Option<String>,
    /// Source serial number.
    pub serial_number: Option<String>,
    /// Source domain.
    pub domain: Option<String>,
    /// Source IP address.
    pub ip_address: Option<String>,
    /// Source MAC address.
    pub mac_address: Option<String>,
    /// Source size in bytes.
    pub size: Option<u64>,
    /// Source logical offset.
    pub logical_offset: Option<i64>,
    /// Source physical offset.
    pub physical_offset: Option<i64>,
    /// Source acquisition timestamp.
    pub acquisition_time: Option<i64>,
    /// Source MD5 hash string.
    pub md5: Option<String>,
    /// Source SHA1 hash string.
    pub sha1: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// Subject record for logical single-file metadata.
pub struct SingleFileSubject {
    /// Subject identifier.
    pub identifier: Option<u32>,
    /// Subject name.
    pub name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// Access-control entry for a logical single-file entry.
pub struct SingleFilePermission {
    /// Permission name.
    pub name: Option<String>,
    /// Security identifier or permission identifier.
    pub identifier: Option<String>,
    /// Permission property type.
    pub property_type: Option<u32>,
    /// Access mask value.
    pub access_mask: Option<u32>,
    /// ACE flags value.
    pub ace_flags: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// Access-control group for logical single-file entries.
pub struct SingleFilePermissionGroup {
    /// Group name.
    pub name: Option<String>,
    /// Security identifier or group identifier.
    pub identifier: Option<String>,
    /// Permission group property type.
    pub property_type: Option<u32>,
    /// Group access mask value.
    pub access_mask: Option<u32>,
    /// Group ACE flags value.
    pub ace_flags: Option<u32>,
    /// Permissions in the group.
    pub permissions: Vec<SingleFilePermission>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// Extended attribute for a logical single-file entry.
pub struct SingleFileAttribute {
    /// Attribute name.
    pub name: Option<String>,
    /// Attribute value.
    pub value: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// Entry in a logical single-file catalog.
pub struct SingleFileEntry {
    /// Entry identifier.
    pub identifier: Option<u64>,
    /// Entry type.
    pub file_entry_type: Option<SingleFileEntryType>,
    /// Raw entry flags.
    pub flags: Option<u32>,
    /// Entry GUID.
    pub guid: Option<String>,
    /// Entry name.
    pub name: Option<String>,
    /// Original UTF-16 units when the entry name contains an unpaired surrogate.
    /// `name` is then a display string with replacement characters; use this
    /// field or the catalog index to distinguish names that display alike.
    pub name_utf16: Option<Vec<u16>>,
    /// Short entry name.
    pub short_name: Option<String>,
    /// Logical file size in bytes.
    pub size: Option<u64>,
    /// Logical media offset for the entry data.
    pub logical_offset: Option<i64>,
    /// Physical source offset for the entry data.
    pub physical_offset: Option<i64>,
    /// Duplicate-data logical media offset.
    pub duplicate_data_offset: Option<i64>,
    /// Identifier of the associated source record.
    pub source_identifier: Option<i32>,
    /// Identifier of the associated subject record.
    pub subject_identifier: Option<u32>,
    /// Index of the associated permission group.
    pub permission_group_index: Option<i32>,
    /// Raw record type.
    pub record_type: Option<u32>,
    /// Creation timestamp.
    pub creation_time: Option<i64>,
    /// Modification timestamp.
    pub modification_time: Option<i64>,
    /// Access timestamp.
    pub access_time: Option<i64>,
    /// Entry metadata modification timestamp.
    pub entry_modification_time: Option<i64>,
    /// Deletion timestamp.
    pub deletion_time: Option<i64>,
    /// Entry MD5 hash string.
    pub md5: Option<String>,
    /// Entry SHA1 hash string.
    pub sha1: Option<String>,
    /// Data extents for the entry.
    pub extents: Vec<SingleFileExtent>,
    /// Extended attributes for the entry.
    pub attributes: Vec<SingleFileAttribute>,
    /// Child entries.
    pub children: Vec<SingleFileEntry>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// Logical single-file catalog metadata.
pub struct SingleFilesInfo {
    /// Byte size of the single-file data section.
    pub data_size: u64,
    /// Root catalog entry.
    pub root: SingleFileEntry,
    /// Source records.
    pub sources: Vec<SingleFileSource>,
    /// Subject records.
    pub subjects: Vec<SingleFileSubject>,
    /// Permission groups.
    pub permission_groups: Vec<SingleFilePermissionGroup>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// Preserved auxiliary EWF2 single-file tables.
pub struct SingleFilesAuxTables {
    /// Raw entries from EWF2 single-files table `0x21`.
    pub table_0x21_entries: Vec<u64>,
    /// MD5 hash table entries.
    pub md5_hashes: Vec<[u8; 16]>,
    /// Raw entries from EWF2 single-files table `0x23`.
    pub table_0x23_entries: Vec<u64>,
}

impl SingleFilesAuxTables {
    /// Returns whether no auxiliary single-file table data is present.
    pub fn is_empty(&self) -> bool {
        self.table_0x21_entries.is_empty()
            && self.md5_hashes.is_empty()
            && self.table_0x23_entries.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Parsed summary of an opened EWF image.
pub struct ImageInfo {
    /// Top-level EWF format generation.
    pub format: Format,
    /// Inferred producer/profile.
    pub format_profile: FormatProfile,
    /// Number of opened segment files.
    pub segment_count: usize,
    /// Segment paths or supplied-reader labels.
    pub segment_paths: Vec<PathBuf>,
    /// Logical chunk size in bytes.
    pub chunk_size: u64,
    /// Logical media size in bytes.
    pub logical_size: u64,
    /// Whether the image has a terminal complete marker.
    pub acquisition_complete: bool,
    /// Header codepage used for decoded EWF1 values.
    pub header_codepage: HeaderCodepage,
    /// Date format used when returning header date values.
    pub header_values_date_format: HeaderDateFormat,
    /// Media geometry and flags.
    pub media: MediaInfo,
    /// Parsed case and acquisition metadata.
    pub metadata: EwfMetadata,
    /// Stored hash values.
    pub stored_hashes: StoredHashes,
    /// Acquisition error ranges.
    pub acquisition_errors: Vec<AcquisitionError>,
    /// Memory acquisition extents.
    pub memory_extents: Vec<MemoryExtent>,
    /// Logical single-file catalog, if present.
    pub single_files: Option<SingleFilesInfo>,
    /// Preserved EWF2 single-file auxiliary table data.
    pub ewf2_single_files_tables: SingleFilesAuxTables,
    /// Raw EWF2 increment data sections.
    pub ewf2_increment_data: Vec<Vec<u8>>,
    /// Raw EWF2 final information section.
    pub ewf2_final_information: Option<Vec<u8>>,
    /// EWF2 restart data text.
    pub ewf2_restart_data: Option<String>,
    /// EWF2 analytical data text.
    pub ewf2_analytical_data: Option<String>,
    /// Session sector ranges.
    pub sessions: Vec<SectorRange>,
    /// Track sector ranges.
    pub tracks: Vec<SectorRange>,
}

#[cfg(feature = "verify")]
#[derive(Debug, Clone, PartialEq, Eq)]
/// Result of streamed logical media hash verification.
pub struct VerifyResult {
    /// MD5 hash computed from the logical media stream.
    pub computed_md5: Option<[u8; 16]>,
    /// SHA1 hash computed from the logical media stream.
    pub computed_sha1: Option<[u8; 20]>,
    /// SHA256 hash computed from the logical media stream.
    pub computed_sha256: Option<[u8; 32]>,
    /// Whether computed MD5 matched the stored MD5, or `None` if no MD5 was stored.
    pub md5_match: Option<bool>,
    /// Whether computed SHA1 matched the stored SHA1, or `None` if no SHA1 was stored.
    pub sha1_match: Option<bool>,
    /// Whether computed SHA256 matched the stored SHA256, or `None` if absent.
    pub sha256_match: Option<bool>,
}

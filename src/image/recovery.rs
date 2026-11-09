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

//! Conservative recovery of physical, unencrypted zlib/raw EWF1 images.
use std::io::Write;
use std::ops::ControlFlow;

use super::{
    Section, decode_ewf1_entry, ewf1, matching_sectors_section, sectors_section_containing_offset,
    validate_present_adler32_checksum, validate_present_ewf1_media_checksum,
    validate_present_table_entries_checksum, validate_raw_chunk_checksum,
};
use crate::decode::{ChunkEncoding, decode_chunk, validate_encoded_size};
use crate::index::{TableRange, TableRangeKind, logical_chunk_count};
use crate::reader_statistics::ReaderStatisticsCollector;
use crate::segment::discover_segments;
use crate::{CompressionMethod, EwfError, Result, SegmentSource};
use std::path::{Path, PathBuf};

/// Controls recovery output size, suspect-data handling, and report retention.
#[derive(Debug, Clone)]
#[must_use]
pub struct RecoveryOptions {
    maximum_output_bytes: Option<u64>,
    preserve_checksum_suspect: bool,
    maximum_records: usize,
}

impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            maximum_output_bytes: None,
            preserve_checksum_suspect: false,
            maximum_records: 1024,
        }
    }
}

impl RecoveryOptions {
    /// Rejects geometry exceeding this output limit before creating output.
    pub fn with_maximum_output_bytes(mut self, bytes: u64) -> Self {
        self.maximum_output_bytes = Some(bytes);
        self
    }
    /// Permits decoded raw bytes with a bad checksum, or bytes addressed by a
    /// checksum-damaged table, only when a validated alternate cannot recover them.
    /// Such bytes are always marked suspect. The default substitutes zeros.
    pub fn with_preserve_checksum_suspect(mut self, preserve: bool) -> Self {
        self.preserve_checksum_suspect = preserve;
        self
    }
    /// Bounds retained notices and outcome ranges independently. Counters and
    /// streaming progress remain complete when records are omitted.
    pub fn with_maximum_records(mut self, count: usize) -> Self {
        self.maximum_records = count;
        self
    }
}

/// Provenance of one recovered logical chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum RecoveryStatus {
    /// Validated bytes addressed by the primary table.
    Primary,
    /// Validated bytes addressed by the redundant table.
    Redundant,
    /// Primary-table bytes retained despite a data or table checksum failure.
    SuspectPrimary,
    /// Redundant-table bytes retained despite a data or table checksum failure.
    SuspectRedundant,
    /// Unrecoverable bytes replaced with zeros.
    ZeroFilled,
}

/// Consecutive chunks sharing the same recovery outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct RecoveryRange {
    /// First logical chunk index.
    pub first_chunk: u64,
    /// Number of consecutive chunks.
    pub chunk_count: u64,
    /// Logical byte offset.
    pub logical_offset: u64,
    /// Logical byte length.
    pub byte_count: u64,
    /// Recovery provenance for this range.
    pub status: RecoveryStatus,
}

/// Structural damage or missing metadata encountered while locating recoverable data.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct RecoveryNotice {
    /// Zero-based source segment index.
    pub segment_index: usize,
    /// Source segment byte offset.
    pub segment_offset: u64,
    /// Diagnostic message.
    pub message: String,
}

/// Streaming recovery progress. The initial event has no last status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct RecoveryProgress {
    /// Number of emitted logical chunks.
    pub chunks_processed: u64,
    /// Total declared logical chunks.
    pub chunks_total: u64,
    /// Logical bytes written, including substituted zeros.
    pub bytes_written: u64,
    /// Declared logical output size.
    pub bytes_total: u64,
    /// Outcome of the most recently emitted chunk.
    pub last_status: Option<RecoveryStatus>,
}

/// Completed recovery accounting. Recovery does not establish image authenticity.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct RecoveryReport {
    /// Declared output size.
    pub logical_size: u64,
    /// Total output chunks.
    pub chunks_total: u64,
    /// Chunks from the primary table, including explicitly retained suspect data.
    pub chunks_primary: u64,
    /// Chunks from the redundant table, including explicitly retained suspect data.
    pub chunks_redundant: u64,
    /// Chunks replaced with zeros.
    pub chunks_zero_filled: u64,
    /// Subset of primary/redundant chunks retained despite checksum failures.
    pub chunks_checksum_suspect: u64,
    /// Bytes read from evidence, including explicitly retained suspect data.
    pub bytes_recovered: u64,
    /// Bytes substituted with zeros.
    pub bytes_zero_filled: u64,
    /// Bounded, coalesced outcome records.
    pub ranges: Vec<RecoveryRange>,
    /// Chunks whose outcome records were omitted due to the retention limit.
    pub omitted_chunk_records: u64,
    /// Bounded structural notices from opening.
    pub notices: Vec<RecoveryNotice>,
    /// Number of omitted structural notices.
    pub omitted_notices: u64,
}

#[derive(Debug)]
struct Candidate {
    range: TableRange,
    data_start: u64,
    trusted_table: bool,
}
#[derive(Debug)]
struct RecoveryGroup {
    first_chunk: u64,
    count: u64,
    primary: Option<Candidate>,
    redundant: Option<Candidate>,
}

/// Read-only recovery plan for physical, unencrypted raw/zlib EWF1 segments.
///
/// Opens a reliable descriptor-chain prefix and requires consistent, validated
/// media geometry. It does not carve lost descriptors, infer missing middle
/// segments, recover encrypted images, or change the normal strict reader.
#[derive(Debug)]
pub struct EwfRecovery {
    sources: Vec<SegmentSource>,
    paths: Vec<PathBuf>,
    groups: Vec<RecoveryGroup>,
    chunk_size: u64,
    logical_size: u64,
    options: RecoveryOptions,
    notices: Vec<RecoveryNotice>,
    omitted_notices: u64,
}

impl EwfRecovery {
    /// Discovers siblings and opens a recovery plan without creating output.
    pub fn open(path: impl AsRef<Path>, options: RecoveryOptions) -> Result<Self> {
        Self::open_segments(discover_segments(path.as_ref())?, options)
    }

    /// Opens explicitly ordered source paths. Numbering gaps are rejected because
    /// EWF1 tables do not provide enough information to place later segments safely.
    pub fn open_segments<P: AsRef<Path>>(
        paths: impl IntoIterator<Item = P>,
        options: RecoveryOptions,
    ) -> Result<Self> {
        let paths: Vec<_> = paths
            .into_iter()
            .map(|path| path.as_ref().to_path_buf())
            .collect();
        if paths.is_empty() {
            return Err(EwfError::NoSegments("empty recovery segment list".into()));
        }
        let mut recovery = Self {
            sources: Vec::new(),
            paths,
            groups: Vec::new(),
            chunk_size: 0,
            logical_size: 0,
            options,
            notices: Vec::new(),
            omitted_notices: 0,
        };
        let mut next_chunk = 0;
        let mut set_identifier = None;
        for index in 0..recovery.paths.len() {
            let source = SegmentSource::from_file(std::fs::File::open(&recovery.paths[index])?)?;
            let mut header_bytes = [0; ewf1::FILE_HEADER_SIZE];
            source.read_exact_at(&mut header_bytes, 0)?;
            if header_bytes[..8] != ewf1::EVF_SIGNATURE || header_bytes[8] != 1 {
                return Err(EwfError::Unsupported(
                    "recovery currently requires physical unencrypted raw/zlib EWF1".into(),
                ));
            }
            let header = ewf1::FileHeader::parse(&header_bytes)?;
            if usize::from(header.segment_number) != index + 1 {
                return Err(EwfError::Malformed(
                    "recovery segment numbering is incomplete or out of order".into(),
                ));
            }
            let sections = recovery.scan_sections(&source, index)?;
            if index + 1 < recovery.paths.len()
                && sections.last().is_none_or(|section| {
                    !matches!(section.desc.section_type.as_str(), "next" | "done")
                })
            {
                return Err(EwfError::Malformed(format!(
                    "cannot place later segments after an incomplete descriptor chain in segment {}",
                    index + 1
                )));
            }
            if super::detect_ewf1_compression_method(header, &sections)? != CompressionMethod::Zlib
            {
                return Err(EwfError::Unsupported(
                    "recovery compression profile is not supported".into(),
                ));
            }
            if sections
                .iter()
                .any(|section| section.desc.section_type == "x_encryption")
            {
                return Err(EwfError::Unsupported(
                    "encrypted recovery is not implemented".into(),
                ));
            }
            if let Some(section) = sections.iter().find(|section| {
                matches!(
                    section.desc.section_type.as_str(),
                    "volume" | "disk" | "data"
                )
            }) {
                if section.data_size > 4096 {
                    return Err(EwfError::Unsupported(
                        "unrecognized recovery media geometry layout".into(),
                    ));
                }
                let bytes = source_bytes(&source, section.data_offset, section.data_size)?;
                validate_present_ewf1_media_checksum(&bytes, &section.desc.section_type)?;
                let volume = ewf1::Volume::parse(&bytes)?;
                if volume.smart {
                    return Err(EwfError::Unsupported(
                        "SMART recovery is not implemented".into(),
                    ));
                }
                let chunk_size = volume.chunk_size()?;
                let logical_size = volume.logical_size()?;
                if chunk_size == 0
                    || chunk_size > super::MAX_CHUNK_SIZE
                    || logical_chunk_count(logical_size, chunk_size)?
                        != u64::from(volume.chunk_count)
                {
                    return Err(EwfError::Malformed(
                        "recovery media geometry is inconsistent".into(),
                    ));
                }
                if index == 0 {
                    recovery.chunk_size = chunk_size;
                    recovery.logical_size = logical_size;
                    set_identifier = volume.set_identifier;
                } else if chunk_size != recovery.chunk_size
                    || logical_size != recovery.logical_size
                    || volume.set_identifier != set_identifier
                {
                    return Err(EwfError::Malformed(
                        "recovery segment media geometry or set identifier differs".into(),
                    ));
                }
            } else if index == 0 {
                return Err(EwfError::Malformed(
                    "recovery requires intact first-segment media geometry".into(),
                ));
            }
            if recovery
                .options
                .maximum_output_bytes
                .is_some_and(|limit| recovery.logical_size > limit)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "recovery exceeds configured output limit",
                )
                .into());
            }
            let before = next_chunk;
            recovery.collect_tables(&source, &sections, index, &mut next_chunk)?;
            if next_chunk == before && index + 1 < recovery.paths.len() {
                return Err(EwfError::Malformed(
                    "cannot position later recovery segments after missing table coverage".into(),
                ));
            }
            recovery.sources.push(source);
        }
        if next_chunk > logical_chunk_count(recovery.logical_size, recovery.chunk_size)? {
            return Err(EwfError::Malformed(
                "recovery tables exceed declared media size".into(),
            ));
        }
        Ok(recovery)
    }

    /// Returns source paths in logical segment order.
    pub fn segment_paths(&self) -> &[PathBuf] {
        &self.paths
    }

    /// Returns the declared size of a recovered raw output.
    pub fn media_size(&self) -> u64 {
        self.logical_size
    }

    /// Creates a new raw output file. Existing paths, including aliases of source
    /// segments, are never overwritten. Errors leave a partial output for inspection.
    pub fn recover_to_path(&self, path: impl AsRef<Path>) -> Result<RecoveryReport> {
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        self.recover_to_writer(&mut output)
    }

    /// Writes recovered raw bytes to a caller-owned destination. The caller must
    /// keep this destination separate from the source evidence.
    pub fn recover_to_writer(&self, output: &mut impl Write) -> Result<RecoveryReport> {
        self.recover_with_progress(output, |_| ControlFlow::Continue(()))
    }

    /// Recovers with one initial event and one event per emitted chunk. Returning
    /// `Break(())` stops with `Aborted`; already-written bytes remain in the output.
    pub fn recover_with_progress(
        &self,
        output: &mut impl Write,
        mut progress: impl FnMut(RecoveryProgress) -> ControlFlow<()>,
    ) -> Result<RecoveryReport> {
        let total = logical_chunk_count(self.logical_size, self.chunk_size)?;
        let mut event = RecoveryProgress {
            chunks_processed: 0,
            chunks_total: total,
            bytes_written: 0,
            bytes_total: self.logical_size,
            last_status: None,
        };
        if progress(event).is_break() {
            return Err(EwfError::Aborted);
        }
        let mut report = RecoveryReport {
            logical_size: self.logical_size,
            chunks_total: total,
            chunks_primary: 0,
            chunks_redundant: 0,
            chunks_zero_filled: 0,
            chunks_checksum_suspect: 0,
            bytes_recovered: 0,
            bytes_zero_filled: 0,
            ranges: Vec::new(),
            omitted_chunk_records: 0,
            notices: self.notices.clone(),
            omitted_notices: self.omitted_notices,
        };
        for id in 0..total {
            let size = self.chunk_size.min(self.logical_size - event.bytes_written) as usize;
            let (bytes, status) = self.recover_chunk(id, size);
            output.write_all(&bytes)?;
            match status {
                RecoveryStatus::Primary | RecoveryStatus::SuspectPrimary => {
                    report.chunks_primary += 1;
                }
                RecoveryStatus::Redundant | RecoveryStatus::SuspectRedundant => {
                    report.chunks_redundant += 1;
                }
                RecoveryStatus::ZeroFilled => report.chunks_zero_filled += 1,
            }
            if matches!(
                status,
                RecoveryStatus::SuspectPrimary | RecoveryStatus::SuspectRedundant
            ) {
                report.chunks_checksum_suspect += 1;
            }
            if status == RecoveryStatus::ZeroFilled {
                report.bytes_zero_filled += size as u64;
            } else {
                report.bytes_recovered += size as u64;
            }
            if let Some(last) = report.ranges.last_mut().filter(|range| {
                range.status == status && range.first_chunk + range.chunk_count == id
            }) {
                last.chunk_count += 1;
                last.byte_count += size as u64;
            } else if report.ranges.len() < self.options.maximum_records {
                report.ranges.push(RecoveryRange {
                    first_chunk: id,
                    chunk_count: 1,
                    logical_offset: event.bytes_written,
                    byte_count: size as u64,
                    status,
                });
            } else {
                report.omitted_chunk_records += 1;
            }
            event.chunks_processed += 1;
            event.bytes_written += size as u64;
            event.last_status = Some(status);
            if progress(event).is_break() {
                return Err(EwfError::Aborted);
            }
        }
        output.flush()?;
        Ok(report)
    }

    fn notice(&mut self, index: usize, offset: u64, message: impl Into<String>) {
        if self.notices.len() < self.options.maximum_records {
            self.notices.push(RecoveryNotice {
                segment_index: index,
                segment_offset: offset,
                message: message.into(),
            });
        } else {
            self.omitted_notices += 1;
        }
    }

    fn scan_sections(&mut self, source: &SegmentSource, index: usize) -> Result<Vec<Section>> {
        let mut sections = Vec::new();
        let mut offset = ewf1::FILE_HEADER_SIZE as u64;
        loop {
            if source.len().saturating_sub(offset) < 76 {
                self.notice(index, offset, "descriptor chain is truncated");
                break;
            }
            let bytes = source_bytes(source, offset, 76)?;
            if let Err(error) =
                validate_present_adler32_checksum(&bytes, 72, 72, "EWF1 section descriptor")
            {
                self.notice(index, offset, error.to_string());
                break;
            }
            let desc = ewf1::SectionDescriptor::parse(&bytes, offset)?;
            let size = match desc.data_size() {
                Ok(size) => size,
                Err(error) => {
                    self.notice(index, offset, error.to_string());
                    break;
                }
            };
            let data_offset = offset + 76;
            let data_size = size.min(source.len() - data_offset);
            let next = desc.next;
            let terminal = matches!(desc.section_type.as_str(), "done" | "next");
            let incomplete = desc.section_type != "done";
            sections.push(Section {
                desc,
                data_offset,
                data_size,
            });
            if size > data_size {
                self.notice(index, offset, "section payload is truncated");
                break;
            }
            if terminal {
                if incomplete && index + 1 == self.paths.len() {
                    self.notice(
                        index,
                        offset,
                        "segment has an incomplete acquisition marker",
                    );
                }
                break;
            }
            if next < data_offset + size || next <= offset {
                self.notice(
                    index,
                    offset,
                    "descriptor chain ends or does not advance beyond the current section",
                );
                break;
            }
            offset = next;
        }
        Ok(sections)
    }

    fn collect_tables(
        &mut self,
        source: &SegmentSource,
        sections: &[Section],
        index: usize,
        next_chunk: &mut u64,
    ) -> Result<()> {
        let first_group = self.groups.len();
        if !sections
            .iter()
            .any(|section| section.desc.section_type == "sectors")
            && sections
                .iter()
                .any(|section| matches!(section.desc.section_type.as_str(), "table" | "table2"))
        {
            return Err(EwfError::Unsupported(
                "recovery requires separate sectors sections".into(),
            ));
        }
        let mut tables = sections
            .iter()
            .filter(|section| matches!(section.desc.section_type.as_str(), "table" | "table2"))
            .peekable();
        while let Some(section) = tables.next() {
            let primary_is_redundant = section.desc.section_type == "table2";
            let first = self.table_candidate(source, sections, section, index);
            let mut second = None;
            if !primary_is_redundant
                && tables
                    .peek()
                    .is_some_and(|next| next.desc.section_type == "table2")
            {
                let mirror = tables.peek().expect("peeked table");
                // Group only matching geometry, or a valid table2 replacing an unreadable header.
                let identity = table_identity(source, section).ok();
                let mirror_identity = table_identity(source, mirror).ok();
                if identity.zip(mirror_identity).is_none_or(|(a, b)| a == b) {
                    second = self.table_candidate(source, sections, mirror, index);
                    tables.next();
                }
            }
            let count = first
                .as_ref()
                .or(second.as_ref())
                .map(|candidate| candidate.range.chunk_count);
            let Some(count) = count else {
                // Without a count, later ranges cannot be positioned safely.
                if tables.peek().is_some() || index + 1 < self.paths.len() {
                    return Err(EwfError::Malformed(
                        "unrecoverable table header prevents placement of later chunks".into(),
                    ));
                }
                break;
            };
            let first_chunk = *next_chunk;
            *next_chunk = next_chunk
                .checked_add(count)
                .ok_or_else(|| EwfError::Malformed("recovery chunk count overflow".into()))?;
            self.groups.push(if primary_is_redundant {
                RecoveryGroup {
                    first_chunk,
                    count,
                    primary: None,
                    redundant: first,
                }
            } else {
                RecoveryGroup {
                    first_chunk,
                    count,
                    primary: first,
                    redundant: second,
                }
            });
        }
        for sectors in sections
            .iter()
            .filter(|section| section.desc.section_type == "sectors" && section.data_size > 0)
        {
            let candidates = || {
                self.groups[first_group..]
                    .iter()
                    .flat_map(|group| group.primary.iter().chain(&group.redundant))
            };
            if !candidates().any(|candidate| candidate.data_start == sectors.data_offset)
                && (index + 1 < self.paths.len()
                    || candidates().any(|candidate| candidate.data_start > sectors.data_offset))
            {
                return Err(EwfError::Malformed(
                    "unindexed sectors prevent placement of later recovery chunks".into(),
                ));
            }
        }
        Ok(())
    }

    fn table_candidate(
        &mut self,
        source: &SegmentSource,
        sections: &[Section],
        section: &Section,
        index: usize,
    ) -> Option<Candidate> {
        match parse_candidate(source, sections, section, index) {
            Ok(candidate) => {
                if !candidate.trusted_table {
                    self.notice(
                        index,
                        section.data_offset,
                        "table entry checksum failed; addresses are suspect",
                    );
                }
                Some(candidate)
            }
            Err(error) => {
                self.notice(index, section.data_offset, error.to_string());
                None
            }
        }
    }

    fn recover_chunk(&self, id: u64, size: usize) -> (Vec<u8>, RecoveryStatus) {
        let index = self
            .groups
            .partition_point(|group| group.first_chunk + group.count <= id);
        let mut suspect = None;
        if let Some(group) = self
            .groups
            .get(index)
            .filter(|group| group.first_chunk <= id)
        {
            for (candidate, clean, damaged) in [
                (
                    &group.primary,
                    RecoveryStatus::Primary,
                    RecoveryStatus::SuspectPrimary,
                ),
                (
                    &group.redundant,
                    RecoveryStatus::Redundant,
                    RecoveryStatus::SuspectRedundant,
                ),
            ] {
                if let Some(candidate) = candidate
                    && let Ok((bytes, checksum_ok)) = read_candidate(
                        &self.sources[candidate.range.segment_index],
                        candidate,
                        id - group.first_chunk,
                        size,
                        self.chunk_size,
                    )
                {
                    if checksum_ok && candidate.trusted_table {
                        return (bytes, clean);
                    }
                    if self.options.preserve_checksum_suspect && suspect.is_none() {
                        suspect = Some((bytes, damaged));
                    }
                }
            }
        }
        suspect.unwrap_or_else(|| (vec![0; size], RecoveryStatus::ZeroFilled))
    }
}

fn source_bytes(source: &SegmentSource, offset: u64, size: u64) -> Result<Vec<u8>> {
    let mut bytes = vec![
        0;
        usize::try_from(size).map_err(|_| EwfError::Malformed(
            "recovery read size exceeds usize".into()
        ))?
    ];
    source.read_exact_at(&mut bytes, offset)?;
    Ok(bytes)
}

fn table_identity(source: &SegmentSource, section: &Section) -> Result<(u64, u64)> {
    if section.data_size < 24 {
        return Err(EwfError::Malformed(
            "recovery table header is truncated".into(),
        ));
    }
    let header = source_bytes(source, section.data_offset, 24)?;
    validate_present_adler32_checksum(&header, 20, 20, "EWF1 table header")?;
    Ok((
        u64::from(u32::from_le_bytes(
            header[..4].try_into().expect("header read"),
        )),
        u64::from_le_bytes(header[8..16].try_into().expect("header read")),
    ))
}

fn parse_candidate(
    source: &SegmentSource,
    sections: &[Section],
    section: &Section,
    segment_index: usize,
) -> Result<Candidate> {
    let (count, base) = table_identity(source, section)?;
    let entries_offset = section.data_offset + 24;
    if count == 0 || count * 4 > section.data_size - 24 {
        return Err(EwfError::Malformed(
            "recovery table entries are missing or truncated".into(),
        ));
    }
    let first = source_bytes(source, entries_offset, 4)?;
    let first_offset = base
        .checked_add(u64::from(
            u32::from_le_bytes(first.try_into().expect("entry read")) & 0x7fff_ffff,
        ))
        .ok_or_else(|| EwfError::Malformed("recovery first chunk offset overflow".into()))?;
    let sectors = matching_sectors_section(sections, base)
        .or_else(|| sectors_section_containing_offset(sections, first_offset))
        .ok_or_else(|| {
            EwfError::Unsupported("recovery requires a separate sectors section".into())
        })?;
    let entries_end = entries_offset + count * 4;
    let trusted_table = if entries_end + 4 <= section.data_offset + section.data_size {
        validate_present_table_entries_checksum(
            &mut source.cursor(),
            entries_offset,
            count * 4,
            entries_end,
            "recovery table",
            &ReaderStatisticsCollector::new(false),
        )
        .is_ok()
    } else {
        true
    };
    Ok(Candidate {
        range: TableRange {
            kind: TableRangeKind::Ewf1,
            segment_index,
            first_chunk: 0,
            chunk_count: count,
            entries_offset,
            base_offset: base,
            data_end: Some(
                sectors
                    .data_offset
                    .checked_add(sectors.desc.data_size()?)
                    .ok_or_else(|| {
                        EwfError::Malformed("recovery sectors extent overflow".into())
                    })?,
            ),
            ewf1_allow_large_compressed_chunks: false,
            ewf1_compression_method: Some(CompressionMethod::Zlib),
            ewf2_compression_method: None,
            entries_verified: trusted_table,
            mapping_unverified: !trusted_table,
            data_start: Some(sectors.data_offset),
        },
        data_start: sectors.data_offset,
        trusted_table,
    })
}

fn read_candidate(
    source: &SegmentSource,
    candidate: &Candidate,
    local: u64,
    size: usize,
    chunk_size: u64,
) -> Result<(Vec<u8>, bool)> {
    let range = &candidate.range;
    let read_entry = |index: u64| -> Result<u32> {
        Ok(u32::from_le_bytes(
            source_bytes(source, range.entries_offset + index * 4, 4)?
                .try_into()
                .expect("entry read"),
        ))
    };
    let raw = read_entry(local)?;
    let next = (local + 1 < range.chunk_count)
        .then(|| read_entry(local + 1))
        .transpose()?;
    let entry = decode_ewf1_entry(range, raw, chunk_size, next, local + 1 == range.chunk_count)?;
    let end = if let Some(raw) = next {
        decode_ewf1_entry(range, raw, chunk_size, None, local + 2 == range.chunk_count)?.offset
    } else {
        range.data_end.expect("recovery candidate has data end")
    };
    if entry.offset < candidate.data_start
        || end > range.data_end.expect("candidate has data end")
        || end <= entry.offset
    {
        return Err(EwfError::Malformed(
            "recovery chunk is outside its sectors section".into(),
        ));
    }
    let encoding = if entry.compressed {
        ChunkEncoding::Zlib
    } else {
        ChunkEncoding::Raw
    };
    validate_encoded_size(end - entry.offset, chunk_size, encoding)?;
    let bytes = source_bytes(source, entry.offset, end - entry.offset)?;
    let checksum_ok = if encoding != ChunkEncoding::Raw {
        true
    } else if bytes.len() == size + 4 || bytes.len() as u64 == chunk_size + 4 {
        validate_raw_chunk_checksum(&bytes, bytes.len() - 4).is_ok()
    } else if bytes.len() == size || bytes.len() as u64 == chunk_size {
        true
    } else {
        return Err(EwfError::Malformed(
            "recovery raw chunk length is not a recognized layout".into(),
        ));
    };
    Ok((decode_chunk(&bytes, encoding, size)?, checksum_ok))
}

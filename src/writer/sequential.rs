// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) 2026 Elijah Brigham
//
// This file is changed from ebrig/ewf-image (https://github.com/ebrig/ewf-image), whose code is
// under the Apache License 2.0 (LICENSE-APACHE).
//
// SPDX-License-Identifier: (RPL-1.5 OR AGPL-3.0-only) AND Apache-2.0
//
// You may instead use this file under the GNU Affero General Public License, version 3 only
// (LICENSE-AGPL-3.0). The notice below is for the RPL.
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

//! Append-only EWF1 physical and EWF2 encoding with bounded payload scratch.

use super::{
    ChunkDescriptor, ChunkSpool, EWF2_DONE_SECTION, EWF2_NEXT_SECTION, Ewf1SegmentSections,
    Ewf1SegmentWriteContext, Ewf2SegmentWriteContext, WriteFormat, WriteHashState, WriteOptions,
    WriteResult, automatic_encode_batch_chunks, effective_write_hashes, encode_chunks,
    estimated_ewf1_segment_size, ewf2_segment_path, is_ewf2_format, normalize_maximum_segment_size,
    normalize_media_size, publication_segment_paths, segment_path, validate_options,
    validate_secondary_segment_filename, validate_session_ranges, write_ewf1_segment,
    write_ewf2_segment, writer_chunk_geometry,
};
use crate::publication::Publication;
use crate::{EwfError, Result};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

/// Settings for a known-length, append-only EWF1 physical or EWF2 write.
#[derive(Debug, Clone)]
pub struct SequentialOptions {
    /// Exact number of source bytes, excluding final sector padding.
    pub source_size: u64,
    /// Chunks per segment, independent of compressed byte size.
    /// The uncompressed segment capacity must not exceed 512 MiB.
    pub chunks_per_segment: u32,
    /// EWF1 physical or EWF2 physical/logical settings. `maximum_segment_size`
    /// is supported for EWF1 physical output only.
    pub write: WriteOptions,
}

impl SequentialOptions {
    /// Creates physical EWF2 settings with 16,375 chunks per segment.
    pub fn new(source_size: u64) -> Self {
        Self {
            source_size,
            chunks_per_segment: 16_375,
            write: WriteOptions {
                format: WriteFormat::Ewf2Physical,
                ..WriteOptions::default()
            },
        }
    }
}

/// Streams EWF1 physical or EWF2 payload into staged native segments without
/// a full raw spool.
///
/// Payload scratch holds one encoded segment, plus an automatically bounded
/// in-memory chunk-encoding batch when the `parallel` feature is enabled.
/// Logical catalogs are written in the final segment.
/// Catalogs and output path lists still grow with entry and segment counts.
/// Input must match the declared size exactly. Final sector padding is zeroed
/// and included in image digests. Errors poison the writer. Dropping it removes
/// uncommitted staging; after process interruption use `EwfWriter::recover_output`.
/// This writer does not support seeking or checkpoint resume.
pub struct SequentialWriter {
    pub(super) options: WriteOptions,
    path: PathBuf,
    source_size: u64,
    position: u64,
    logical_size: u64,
    chunk_size: u64,
    capacity: usize,
    per_segment: usize,
    total_chunks: u32,
    encoded_chunks: u64,
    pending: Vec<u8>,
    current: Group,
    hashes: WriteHashState,
    paths: Vec<PathBuf>,
    mirrors: Vec<PathBuf>,
    poisoned: bool,
    // Drop spools before the publication journal, including on Windows.
    publication: Publication,
}

struct Group {
    spool: ChunkSpool,
    chunks: Vec<ChunkDescriptor>,
}

impl Group {
    fn new(directory: &Path) -> Result<Self> {
        Ok(Self {
            spool: ChunkSpool {
                file: NamedTempFile::new_in(directory)?,
                len: 0,
                position: 0,
            },
            chunks: Vec::new(),
        })
    }
}

impl SequentialWriter {
    /// Starts a publication transaction. Nothing is published until `finish`.
    pub fn create(path: impl AsRef<Path>, settings: SequentialOptions) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let options = settings.write;
        validate_options(&options)?;
        let is_v2 = is_ewf2_format(options.format);
        if !(is_v2 || options.format == WriteFormat::Ewf1Physical)
            || (is_v2 && normalize_maximum_segment_size(options.maximum_segment_size).is_some())
        {
            return Err(EwfError::Unsupported(
                "sequential writing supports EWF1 physical or EWF2 with chunk-count segmentation"
                    .into(),
            ));
        }
        let (chunk_size, capacity) =
            writer_chunk_geometry(options.sectors_per_chunk, options.bytes_per_sector)?;
        if chunk_size > 16 * 1024 * 1024
            || settings.chunks_per_segment == 0
            || chunk_size
                .checked_mul(u64::from(settings.chunks_per_segment))
                .is_none_or(|size| size > 512 * 1024 * 1024)
        {
            return Err(EwfError::Unsupported(
                "sequential writing requires chunks <=16 MiB and segment capacity <=512 MiB".into(),
            ));
        }
        let sector = u64::from(options.bytes_per_sector);
        let logical_size = settings
            .source_size
            .checked_add(sector - 1)
            .map(|size| size / sector * sector)
            .ok_or_else(|| EwfError::Malformed("sequential source size overflow".into()))?;
        if normalize_media_size(options.media_size).is_some_and(|size| size != logical_size) {
            return Err(EwfError::Unsupported(
                "media_size differs from padded source size".into(),
            ));
        }
        let total_chunks = u32::try_from(logical_size.div_ceil(chunk_size))
            .map_err(|_| EwfError::Unsupported("sequential chunk count exceeds u32".into()))?;
        validate_session_ranges("sessions", &options.sessions, logical_size / sector)?;
        validate_session_ranges("tracks", &options.tracks, logical_size / sector)?;
        let per_segment = segment_chunk_limit(&options, chunk_size, settings.chunks_per_segment)?;
        let path_for_segment = if is_v2 {
            ewf2_segment_path
        } else {
            segment_path
        };
        validate_secondary_segment_filename(&path, options.secondary_segment_filename.as_deref())?;
        if let Some(secondary) = &options.secondary_segment_filename {
            validate_namespaces(
                &path,
                secondary,
                (total_chunks as usize).div_ceil(per_segment).max(1),
                path_for_segment,
            )?;
        }
        let publication = Publication::begin(
            &path,
            options.secondary_segment_filename.as_deref(),
            options.overwrite_existing,
        )?;
        let staged = publication.stage(0, &path)?;
        let current = Group::new(staged.parent().expect("staged parent"))?;
        Ok(Self {
            options,
            path,
            source_size: settings.source_size,
            position: 0,
            logical_size,
            chunk_size,
            capacity,
            per_segment,
            total_chunks,
            encoded_chunks: 0,
            pending: Vec::with_capacity(capacity),
            current,
            hashes: WriteHashState::new(),
            paths: Vec::new(),
            mirrors: Vec::new(),
            poisoned: false,
            publication,
        })
    }

    /// Source bytes accepted so far; excludes sector padding.
    pub fn position(&self) -> u64 {
        self.position
    }

    /// Appends bytes. An oversize write poisons the transaction without publishing.
    pub fn write_all(&mut self, mut bytes: &[u8]) -> Result<()> {
        self.healthy()?;
        self.poisoned = true;
        if bytes.len() as u64 > self.source_size - self.position {
            return Err(EwfError::Malformed(
                "sequential input exceeds declared source size".into(),
            ));
        }
        let batch_size = automatic_encode_batch_chunks(self.capacity);
        while !bytes.is_empty() {
            let mut chunks = Vec::with_capacity(batch_size);
            while !bytes.is_empty() && chunks.len() < batch_size {
                let take = bytes.len().min(self.capacity - self.pending.len());
                self.pending.extend_from_slice(&bytes[..take]);
                self.position += take as u64;
                bytes = &bytes[take..];
                if self.pending.len() == self.capacity {
                    chunks.push(std::mem::replace(
                        &mut self.pending,
                        Vec::with_capacity(self.capacity),
                    ));
                }
            }
            self.encode_batch(chunks)?;
        }
        self.poisoned = false;
        Ok(())
    }

    fn healthy(&self) -> Result<()> {
        if self.poisoned {
            return Err(EwfError::Aborted);
        }
        Ok(())
    }

    fn encode_batch(&mut self, chunks: Vec<Vec<u8>>) -> Result<()> {
        for chunk in &chunks {
            self.hashes.update(chunk);
        }
        let encoded = encode_chunks(
            chunks,
            self.options.compression,
            self.options.compression_values,
            self.chunk_size,
            is_ewf2_format(self.options.format),
            !is_ewf2_format(self.options.format) && self.options.compression_values.empty_block,
        )?;
        for chunk in encoded {
            self.current.chunks.push(self.current.spool.append(chunk)?);
            self.encoded_chunks += 1;
            if self.current.chunks.len() == self.per_segment
                && self.encoded_chunks < u64::from(self.total_chunks)
            {
                let staged = self.publication.stage(0, &self.path)?;
                let next = Group::new(staged.parent().expect("staged parent"))?;
                let mut complete = std::mem::replace(&mut self.current, next);
                let number = self.paths.len() + 1;
                self.stage_group(&mut complete, number, false)?;
                self.paths.push(self.segment_path(&self.path, number)?);
            }
        }
        Ok(())
    }

    fn stage_group(&self, group: &mut Group, number: usize, last: bool) -> Result<()> {
        let path = self.segment_path(&self.path, number)?;
        let staged = self.publication.stage(0, &path)?;
        let mut file = File::create(&staged)?;
        let sector_count = self.logical_size / u64::from(self.options.bytes_per_sector);
        if is_ewf2_format(self.options.format) {
            write_ewf2_segment(
                &mut file,
                &mut group.spool,
                &group.chunks,
                &self.options,
                Ewf2SegmentWriteContext {
                    segment_number: u32::try_from(number)
                        .map_err(|_| EwfError::Unsupported("too many segments".into()))?,
                    first_chunk: (number as u64 - 1) * self.per_segment as u64,
                    total_chunk_count: self.total_chunks,
                    sector_count,
                    terminal_section_type: if last {
                        EWF2_DONE_SECTION
                    } else {
                        EWF2_NEXT_SECTION
                    },
                },
            )?;
        } else {
            write_ewf1_segment(
                &mut file,
                &mut group.spool,
                &group.chunks,
                &self.options,
                Ewf1SegmentWriteContext {
                    segment_number: u16::try_from(number)
                        .map_err(|_| EwfError::Unsupported("too many EWF1 segments".into()))?,
                    chunk_count: self.total_chunks,
                    sector_count,
                    sections: Ewf1SegmentSections::for_segment(number == 1, last),
                    terminal_section: super::TerminalSection::Done,
                },
            )?;
            if let Some(limit) = normalize_maximum_segment_size(self.options.maximum_segment_size)
                && group.chunks.len() > 1
                && file.metadata()?.len() > limit
            {
                return Err(EwfError::Unsupported(
                    "sequential EWF1 segment exceeds maximum_segment_size".into(),
                ));
            }
        }
        file.sync_all()?;
        drop(file);
        if let Some(base) = &self.options.secondary_segment_filename {
            let mirror = self.segment_path(base, number)?;
            let destination = self.publication.stage(1, &mirror)?;
            fs::copy(staged, &destination)?;
            fs::OpenOptions::new()
                .write(true)
                .open(destination)?
                .sync_all()?;
        }
        Ok(())
    }

    fn segment_path(&self, base: &Path, number: usize) -> Result<PathBuf> {
        if is_ewf2_format(self.options.format) {
            ewf2_segment_path(base, number)
        } else {
            segment_path(base, number)
        }
    }

    /// Checks the source length, pads the last sector, and publishes all segments.
    pub fn finish(mut self) -> Result<WriteResult> {
        self.healthy()?;
        let is_v2 = is_ewf2_format(self.options.format);
        if self.position != self.source_size {
            return Err(EwfError::Malformed(
                "sequential input is shorter than declared source size".into(),
            ));
        }
        let padding = (self.logical_size - self.source_size) as usize;
        self.pending.resize(self.pending.len() + padding, 0);
        if !self.pending.is_empty() {
            let chunk = std::mem::replace(&mut self.pending, Vec::with_capacity(self.capacity));
            self.encode_batch(vec![chunk])?;
        }
        let (md5, sha1, sha256) = self.hashes.clone().finalize();
        self.options.hashes = effective_write_hashes(&self.options.hashes, md5, sha1, sha256)?;
        let staged = self.publication.stage(0, &self.path)?;
        let empty = Group::new(staged.parent().expect("staged parent"))?;
        let mut last = std::mem::replace(&mut self.current, empty);
        let number = self.paths.len() + 1;
        self.stage_group(&mut last, number, true)?;
        self.paths.push(self.segment_path(&self.path, number)?);
        // Remove scratch handles before publication cleanup on Windows.
        drop(last);
        self.current.spool.file.close()?;
        if let Some(base) = &self.options.secondary_segment_filename {
            for number in 1..=self.paths.len() {
                self.mirrors.push(if is_v2 {
                    ewf2_segment_path(base, number)?
                } else {
                    segment_path(base, number)?
                });
            }
        }
        let mut destinations = vec![publication_segment_paths(&self.paths, is_v2)?];
        if !self.mirrors.is_empty() {
            destinations.push(publication_segment_paths(&self.mirrors, is_v2)?);
        }
        self.publication.publish(&destinations, self.paths.len())?;
        Ok(WriteResult {
            segment_paths: self.paths,
            secondary_segment_paths: self.mirrors,
            logical_size: self.logical_size,
            chunk_size: self.chunk_size,
            chunk_count: u64::from(self.total_chunks),
            computed_sha256: sha256,
        })
    }
}

fn segment_chunk_limit(options: &WriteOptions, chunk_size: u64, requested: u32) -> Result<usize> {
    let Some(maximum_size) = normalize_maximum_segment_size(options.maximum_segment_size) else {
        return Ok(requested as usize);
    };
    if is_ewf2_format(options.format) {
        return Err(EwfError::Unsupported(
            "maximum_segment_size is not supported for sequential EWF2".into(),
        ));
    }
    // Use the largest encoded EWF1 chunk (raw bytes plus Adler32) and include
    // final digest sections on every estimate. This fixes segment boundaries
    // before source data arrives and leaves room for all first/last metadata.
    let mut sizing = options.clone();
    sizing.hashes = effective_write_hashes(&options.hashes, [0; 16], [0; 20], [0; 32])?;
    let encoded_chunk_size = chunk_size
        .checked_add(4)
        .ok_or_else(|| EwfError::Malformed("sequential encoded chunk size overflow".into()))?;
    let mut low = 1_u32;
    let mut high = requested;
    while low < high {
        let candidate = low + (high - low).div_ceil(2);
        let payload_size = encoded_chunk_size
            .checked_mul(u64::from(candidate))
            .ok_or_else(|| EwfError::Malformed("sequential segment size overflow".into()))?;
        let estimate = estimated_ewf1_segment_size(candidate as usize, payload_size, 1, &sizing)?;
        if estimate <= maximum_size {
            low = candidate;
        } else {
            high = candidate - 1;
        }
    }
    Ok(low as usize)
}

// Validate the complete namespace once, before creating a journal or accepting
// source bytes. Resolve parent aliases and use conservative Windows case folding.
// O(n log n) comparisons replace the former per-segment O(n^2) filesystem work.
fn validate_namespaces(
    primary: &Path,
    secondary: &Path,
    count: usize,
    segment_path: fn(&Path, usize) -> Result<PathBuf>,
) -> Result<()> {
    fn key(path: &Path) -> Result<PathBuf> {
        let path = super::normalized_output_path(path)?;
        let parent = path
            .parent()
            .ok_or_else(|| EwfError::Malformed("missing output parent".into()))?;
        let key = parent.canonicalize()?.join(
            path.file_name()
                .ok_or_else(|| EwfError::Malformed("missing output name".into()))?,
        );
        #[cfg(windows)]
        let key = PathBuf::from(key.to_string_lossy().to_lowercase());
        Ok(key)
    }
    let primary: BTreeSet<_> = (1..=count)
        .map(|n| key(&segment_path(primary, n)?))
        .collect::<Result<_>>()?;
    for number in 1..=count {
        if primary.contains(&key(&segment_path(secondary, number)?)?) {
            return Err(EwfError::Unsupported(
                "secondary segment filename overlaps primary output".into(),
            ));
        }
    }
    Ok(())
}

impl Write for SequentialWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        Self::write_all(self, bytes).map_err(std::io::Error::other)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.healthy().map_err(std::io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::{SequentialOptions, SequentialWriter, WriteFormat};
    #[test]
    fn scratch_and_descriptors_do_not_grow_with_completed_segments() {
        for format in [
            WriteFormat::Ewf1Physical,
            WriteFormat::Ewf2Physical,
            WriteFormat::Ewf2Logical,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let sectors_per_chunk = if format == WriteFormat::Ewf2Logical {
                16
            } else {
                1
            };
            let chunk_size = sectors_per_chunk * 512;
            let mut options = SequentialOptions::new(u64::from(chunk_size) * 100);
            options.write.format = format;
            options.write.sectors_per_chunk = sectors_per_chunk;
            options.chunks_per_segment = 3;
            let mut writer = SequentialWriter::create(
                dir.path().join(match format {
                    WriteFormat::Ewf1Physical => "case.E01",
                    WriteFormat::Ewf2Physical => "case.Ex01",
                    WriteFormat::Ewf2Logical => "case.Lx01",
                    _ => unreachable!(),
                }),
                options,
            )
            .unwrap();
            let chunk: Vec<u8> = (0..chunk_size).map(|n| (n % 251) as u8).collect();
            for _ in 0..100 {
                writer.write_all(&chunk).unwrap();
                assert!(writer.current.chunks.len() <= 3);
                assert!(writer.current.spool.len <= u64::from(3 * (chunk_size + 4)));
                assert!(writer.pending.len() < chunk_size as usize);
            }
            writer.finish().unwrap();
        }
    }
}

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

//! Append-only EWF1 acquisition with immutable sealed-segment checkpoints.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use super::{
    ChunkDescriptor, ChunkSpool, EWF1_TABLE_GROUP_MAX_ENTRIES, Ewf1SegmentSections,
    Ewf1SegmentWriteContext, TerminalSection, WriteCompression, WriteHashState, WriteOptions,
    WriteResult, effective_write_hashes, encode_chunk, header_payload, header2_payload,
    publication_segment_paths, segment_path, validate_options, write_ewf1_segment,
    writer_chunk_geometry, xheader_payload,
};
use crate::publication::{OutputLock, acquisition_path, sync_dir};
use crate::{AcquisitionError, EwfError, EwfMetadata, Result};

mod checkpoint;
pub use checkpoint::{
    AcquisitionCheckpoint, AcquisitionOperationPhase, AcquisitionOperationProgress,
};
use checkpoint::{load_checkpoint, operation_progress};
use std::ops::ControlFlow;
mod source;
pub use source::{
    AcquisitionOutcome, AcquisitionProgress, AcquisitionReadOptions, AcquisitionStatus,
    UnreadableSectorPolicy,
};

#[cfg(test)]
mod tests;

/// Configuration for a new, single-destination physical E01 acquisition.
/// The source size must be known, nonzero, and a multiple of the sector size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquisitionOptions {
    /// Exact source size. Acquisition never pads or silently truncates input.
    pub source_size: u64,
    /// Bytes per sector; defaults to 512.
    pub bytes_per_sector: u32,
    /// Sectors per chunk; defaults to 64. Chunks may not exceed 16 MiB.
    pub sectors_per_chunk: u32,
    /// Maximum chunks per sealed segment, from 1 through 16,375.
    /// Defaults to 16,375 (about 512 MiB of raw data at default geometry).
    pub chunks_per_segment: u32,
    /// Raw or zlib compression. `BZip2` is not supported by this EWF1 API.
    pub compression: WriteCompression,
    /// Acquisition metadata, fixed at creation and checked on resume.
    pub metadata: EwfMetadata,
}

impl AcquisitionOptions {
    /// Uses default E01 geometry and zlib compression for the given source size.
    pub fn new(source_size: u64) -> Self {
        Self {
            source_size,
            bytes_per_sector: 512,
            sectors_per_chunk: 64,
            chunks_per_segment: EWF1_TABLE_GROUP_MAX_ENTRIES as u32,
            compression: WriteCompression::Zlib,
            metadata: EwfMetadata::default(),
        }
    }

    fn writer_options(&self) -> Result<WriteOptions> {
        let (chunk_size, _) = writer_chunk_geometry(self.sectors_per_chunk, self.bytes_per_sector)?;
        if self.source_size == 0
            || !self
                .source_size
                .is_multiple_of(u64::from(self.bytes_per_sector))
            || chunk_size > 16 * 1024 * 1024
            || self.chunks_per_segment == 0
            || self.chunks_per_segment as usize > EWF1_TABLE_GROUP_MAX_ENTRIES
            || self.source_size.div_ceil(chunk_size) > u64::from(u32::MAX)
        {
            return Err(EwfError::Unsupported(
                "unsupported acquisition geometry".into(),
            ));
        }
        let options = WriteOptions {
            sectors_per_chunk: self.sectors_per_chunk,
            bytes_per_sector: self.bytes_per_sector,
            compression: self.compression,
            media_size: Some(self.source_size),
            metadata: self.metadata.clone(),
            ..WriteOptions::default()
        };
        validate_options(&options)?;
        Ok(options)
    }
}

/// Append-only physical E01 writer with resumable sealed segments.
///
/// RAM holds a fixed number of chunk buffers and at most `chunks_per_segment` descriptors. Scratch disk
/// holds at most one encoded segment, plus its copy while sealing. Completed
/// native segments accumulate in an adjacent `.ewf-acquisition` directory.
/// [`Self::finish`] publishes them without copying payloads, using hard links;
/// the destination filesystem must support hard links and file locking.
///
/// Drop preserves sealed checkpoints. Resume discards unsealed input, verifies
/// every sealed segment, and rehashes its decoded media to restore digest state.
/// Supply input again starting at [`Self::checkpoint_offset`]. No sealed segment
/// is rewritten. The source identity is a caller-supplied assertion (for example
/// a SHA256 of stable device identifiers); this API cannot detect source changes
/// if the caller reuses an identity. Use a stable source snapshot when needed.
///
/// Flush seals complete chunks. A partial chunk remains uncheckpointed until
/// filled or until the declared source size is reached. Any I/O failure poisons
/// the writer: drop it and resume to discover the last successful checkpoint.
/// Files are synchronized before checkpoint acknowledgement; directory entries
/// are synchronized on Unix. Windows process-crash recovery is supported, but
/// power-loss durability is not certified.
pub struct AcquisitionWriter {
    first: PathBuf,
    state: PathBuf,
    options: WriteOptions,
    source_size: u64,
    chunk_size: usize,
    chunks_per_segment: usize,
    offset: u64,
    pending: Vec<u8>,
    chunks: Vec<ChunkDescriptor>,
    spool: Option<ChunkSpool>,
    hashes: WriteHashState,
    sealed: Vec<Seal>,
    errors: Vec<AcquisitionError>,
    substituted_sectors: u64,
    processing_duration: Duration,
    scratch_write_duration: Duration,
    segment_seal_duration: Duration,
    failed: bool,
    #[cfg(test)]
    fail_seal: bool,
    _lock: OutputLock,
}

#[derive(Clone)]
struct Seal {
    end: u64,
    size: u64,
    digest: [u8; 32],
}

impl AcquisitionWriter {
    /// Creates a new acquisition. Existing E01-family output is never replaced.
    /// The identity and all options must be identical when resuming.
    pub fn create(
        first: impl AsRef<Path>,
        options: &AcquisitionOptions,
        source_identity: [u8; 32],
    ) -> Result<Self> {
        let write_options = options.writer_options()?;
        let first = normalize_first(first.as_ref())?;
        validate_segment_budget(&first, options)?;
        let lock = OutputLock::acquire(&first)?;
        crate::publication::ensure_no_pending(&first)?;
        ensure_output_absent(&first)?;
        let state = acquisition_path(&first)?;
        let init = tempfile::Builder::new()
            .prefix(".ewf-acquisition-init-")
            .tempdir_in(crate::segment::segment_dir(&first))?;
        fs::create_dir(init.path().join("scratch"))?;
        atomic_file(
            init.path(),
            &init.path().join("config"),
            &fingerprint(&first, options, &write_options, source_identity)?,
        )?;
        // Fail before accepting source data on filesystems that cannot perform
        // the eventual copy-free, exclusive publication.
        let probe = init.path().join("hard-link-probe");
        fs::hard_link(init.path().join("config"), &probe)?;
        fs::remove_file(probe)?;
        sync_dir(init.path())?;
        fs::rename(init.path(), &state)?;
        sync_dir(crate::segment::segment_dir(&first))?;
        Self::new(first, state, write_options, options, lock)
    }

    /// Reopens an interrupted acquisition and validates its sealed prefix.
    /// Returns an error for a different identity/configuration, corrupt or missing
    /// sealed data, or a live writer. Work is proportional to checkpointed bytes.
    /// A fully acquired but unpublished set can be resumed and finished directly.
    pub fn resume(
        first: impl AsRef<Path>,
        options: &AcquisitionOptions,
        source_identity: [u8; 32],
    ) -> Result<Self> {
        Self::resume_with_progress(first, options, source_identity, |_| {
            ControlFlow::Continue(())
        })
    }

    /// Resumes with cancellable segment validation and media rehash progress.
    /// Cancellation returns `EwfError::Aborted` and leaves checkpoint files intact.
    pub fn resume_with_progress(
        first: impl AsRef<Path>,
        options: &AcquisitionOptions,
        source_identity: [u8; 32],
        mut on_progress: impl FnMut(AcquisitionOperationProgress) -> ControlFlow<()>,
    ) -> Result<Self> {
        let write_options = options.writer_options()?;
        let first = normalize_first(first.as_ref())?;
        validate_segment_budget(&first, options)?;
        let lock = OutputLock::acquire(&first)?;
        let checkpoint = load_checkpoint(
            &first,
            options,
            &write_options,
            source_identity,
            true,
            &mut on_progress,
        )?;
        let state = checkpoint.state;
        let sealed = checkpoint.sealed;
        let previous = checkpoint.report.checkpoint_bytes;
        let count = sealed.len();
        let errors = checkpoint.report.acquisition_errors;
        let mut hashes = WriteHashState::new();
        if let Some(image) = checkpoint.image {
            let mut progress =
                operation_progress(AcquisitionOperationPhase::RehashingMedia, previous, count);
            checkpoint::notify(progress, &mut on_progress)?;
            let mut cursor = image.cursor();
            let mut buffer = vec![0; image.chunk_size() as usize];
            loop {
                let size = cursor.read(&mut buffer)?;
                if size == 0 {
                    break;
                }
                hashes.update(&buffer[..size]);
                progress.bytes_processed += size as u64;
                progress.segments_processed =
                    sealed.partition_point(|seal| seal.end <= progress.bytes_processed);
                checkpoint::notify(progress, &mut on_progress)?;
            }
        }
        // Validate first; only uncommitted scratch and the possible next segment
        // may be discarded. Sealed segments and their records stay immutable.
        if previous < options.source_size {
            let unsealed = staged_path(&first, &state, count + 1)?;
            match fs::symlink_metadata(&unsealed) {
                Ok(metadata) => {
                    require_file_type(&metadata)?;
                    fs::remove_file(unsealed)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
        }
        for entry in fs::read_dir(state.join("scratch"))? {
            let entry = entry?;
            require_file_type(&fs::symlink_metadata(entry.path())?)?;
            fs::remove_file(entry.path())?;
        }
        let mut writer = Self::new(first, state, write_options, options, lock)?;
        writer.offset = previous;
        writer.hashes = hashes;
        writer.sealed = sealed;
        writer.substituted_sectors = errors.iter().map(|range| range.sector_count).sum();
        writer.errors = errors;
        Ok(writer)
    }

    fn new(
        first: PathBuf,
        state: PathBuf,
        options: WriteOptions,
        acquisition: &AcquisitionOptions,
        lock: OutputLock,
    ) -> Result<Self> {
        let chunk_size =
            (u64::from(options.bytes_per_sector) * u64::from(options.sectors_per_chunk)) as usize;
        let spool = ChunkSpool {
            file: NamedTempFile::new_in(state.join("scratch"))?,
            len: 0,
            position: 0,
        };
        Ok(Self {
            first,
            state,
            options,
            source_size: acquisition.source_size,
            chunk_size,
            chunks_per_segment: acquisition.chunks_per_segment as usize,
            offset: 0,
            pending: Vec::with_capacity(chunk_size),
            chunks: Vec::with_capacity(acquisition.chunks_per_segment as usize),
            spool: Some(spool),
            hashes: WriteHashState::new(),
            sealed: Vec::new(),
            errors: Vec::new(),
            substituted_sectors: 0,
            processing_duration: Duration::ZERO,
            scratch_write_duration: Duration::ZERO,
            segment_seal_duration: Duration::ZERO,
            failed: false,
            #[cfg(test)]
            fail_seal: false,
            _lock: lock,
        })
    }

    /// Number of bytes accepted in this acquisition, including unsealed bytes.
    pub fn position(&self) -> u64 {
        self.offset
    }

    /// Source offset durable at the last acknowledged sealed-segment checkpoint.
    pub fn checkpoint_offset(&self) -> u64 {
        self.sealed.last().map_or(0, |seal| seal.end)
    }

    /// Number of immutable native EWF segments checkpointed so far.
    pub fn sealed_segments(&self) -> usize {
        self.sealed.len()
    }

    /// Time spent hashing and encoding new chunks in this writer instance.
    pub fn processing_duration(&self) -> Duration {
        self.processing_duration
    }

    /// Time spent appending encoded chunks to scratch storage in this instance.
    pub fn scratch_write_duration(&self) -> Duration {
        self.scratch_write_duration
    }

    /// Time spent building, synchronizing, hashing, and checkpointing segments.
    pub fn segment_seal_duration(&self) -> Duration {
        self.segment_seal_duration
    }

    /// Unreadable source sectors replaced with zeroes, including unsealed input.
    /// Checkpointed ranges are recovered from native EWF error sections on resume.
    pub fn acquisition_errors(&self) -> &[AcquisitionError] {
        &self.errors
    }

    /// Seals complete buffered chunks and returns the resumable source offset.
    /// Any partial chunk remains in memory and is not included in this offset.
    pub fn checkpoint(&mut self) -> Result<u64> {
        self.ensure_healthy()?;
        if !self.chunks.is_empty() {
            let result = self.seal(false);
            self.failed = result.is_err();
            result?;
        }
        Ok(self.checkpoint_offset())
    }

    /// Completes and publishes the exact declared source, including MD5, SHA1,
    /// and SHA256 references. Too little input is an error, never an implicit pad.
    /// Before journal retirement, a publication error preserves checkpoints for
    /// `resume(...).finish()`. A cleanup failure after retirement can leave an
    /// already completed image; open the image to check that outcome.
    pub fn finish(self) -> Result<WriteResult> {
        self.finish_with_progress(|_| ControlFlow::Continue(()))
    }

    /// Validates and publishes with cooperative cancellation. Returning `Break`
    /// leaves the acquisition resumable, including after some output links have
    /// been installed. Cancellation is checked before journal retirement; cleanup
    /// after that commit point is not cancellable.
    pub fn finish_with_progress(
        mut self,
        mut on_progress: impl FnMut(AcquisitionOperationProgress) -> ControlFlow<()>,
    ) -> Result<WriteResult> {
        self.ensure_healthy()?;
        if self.checkpoint_offset() != self.source_size {
            return Err(EwfError::Malformed(
                "acquisition source is incomplete".into(),
            ));
        }
        let paths = (1..=self.sealed.len())
            .map(|index| segment_path(&self.first, index))
            .collect::<Result<Vec<_>>>()?;
        let stored_bytes = self
            .sealed
            .iter()
            .try_fold(0_u64, |total, seal| total.checked_add(seal.size))
            .ok_or_else(|| EwfError::Malformed("acquisition stored-size overflow".into()))?;
        let mut progress = operation_progress(
            AcquisitionOperationPhase::ValidatingSegments,
            stored_bytes,
            self.sealed.len(),
        );
        checkpoint::notify(progress, &mut on_progress)?;
        for (index, seal) in self.sealed.iter().enumerate() {
            seal.validate_with_progress(
                &staged_path(&self.first, &self.state, index + 1)?,
                &mut progress,
                &mut on_progress,
            )?;
        }
        let mut progress = operation_progress(
            AcquisitionOperationPhase::Publishing,
            stored_bytes,
            self.sealed.len(),
        );
        checkpoint::notify(progress, &mut on_progress)?;
        let publishing = self.state.join("publishing");
        if !publishing.try_exists()? {
            ensure_output_absent(&self.first)?;
            atomic_file(&self.state.join("scratch"), &publishing, &[])?;
            sync_dir(&self.state)?;
        }
        #[cfg(test)]
        tests::crash_at("publishing", 0);
        if publication_segment_paths(&paths, false)?.len() != paths.len() {
            return Err(EwfError::Malformed(
                "unexpected acquisition output segments".into(),
            ));
        }
        for (index, (path, seal)) in paths.iter().zip(&self.sealed).enumerate() {
            let staged = staged_path(&self.first, &self.state, index + 1)?;
            match fs::hard_link(staged, path) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Existing links can result from interrupted publication.
                    // Revalidate their contents without counting the bytes twice.
                    let mut validation = operation_progress(
                        AcquisitionOperationPhase::ValidatingSegments,
                        seal.size,
                        1,
                    );
                    seal.validate_with_progress(path, &mut validation, &mut on_progress)?;
                }
                Err(error) => return Err(error.into()),
            }
            progress.bytes_processed += seal.size;
            progress.segments_processed += 1;
            checkpoint::notify(progress, &mut on_progress)?;
            #[cfg(test)]
            tests::crash_at("linked", index + 1);
        }
        sync_dir(crate::segment::segment_dir(&self.first))?;
        #[cfg(test)]
        tests::crash_at("published", 0);
        // Retire the entire journal atomically. Interruption during deletion
        // leaves only inert cleanup files, never a half-deleted live checkpoint.
        drop(self.spool.take());
        let cleanup = tempfile::Builder::new()
            .prefix(".ewf-acquisition-cleanup-")
            .tempdir_in(crate::segment::segment_dir(&self.first))?;
        fs::rename(&self.state, cleanup.path().join("retired"))?;
        sync_dir(crate::segment::segment_dir(&self.first))?;
        #[cfg(test)]
        tests::crash_at("retired", 0);
        cleanup.close()?;
        let (_, _, computed_sha256) = self.hashes.finalize();
        Ok(WriteResult {
            segment_paths: paths,
            secondary_segment_paths: Vec::new(),
            logical_size: self.source_size,
            chunk_size: self.chunk_size as u64,
            chunk_count: self.source_size.div_ceil(self.chunk_size as u64),
            computed_sha256,
        })
    }

    fn ensure_healthy(&self) -> Result<()> {
        if self.failed {
            return Err(EwfError::Unsupported(
                "acquisition failed; drop and resume it".into(),
            ));
        }
        Ok(())
    }

    fn append(&mut self, bytes: &[u8]) -> Result<usize> {
        self.ensure_healthy()?;
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.offset == self.source_size {
            return Err(EwfError::Malformed(
                "input exceeds declared acquisition size".into(),
            ));
        }
        let take = bytes
            .len()
            .min(self.chunk_size - self.pending.len())
            .min((self.source_size - self.offset).min(usize::MAX as u64) as usize);
        self.pending.extend_from_slice(&bytes[..take]);
        self.offset += take as u64;
        if self.pending.len() == self.chunk_size || self.offset == self.source_size {
            let processing_started = Instant::now();
            self.hashes.update(&self.pending);
            let data = std::mem::replace(&mut self.pending, Vec::with_capacity(self.chunk_size));
            let encoded = encode_chunk(
                data,
                self.options.compression,
                self.options.compression_values,
                self.chunk_size as u64,
                false,
                false,
            )?;
            self.processing_duration += processing_started.elapsed();
            let scratch_started = Instant::now();
            self.chunks
                .push(self.spool.as_mut().expect("active spool").append(encoded)?);
            self.scratch_write_duration += scratch_started.elapsed();
            if self.chunks.len() == self.chunks_per_segment || self.offset == self.source_size {
                self.seal(self.offset == self.source_size)?;
            }
        }
        Ok(take)
    }

    fn seal(&mut self, final_segment: bool) -> Result<()> {
        let seal_started = Instant::now();
        let index = self.sealed.len() + 1;
        let target = staged_path(&self.first, &self.state, index)?;
        let mut options = self.options.clone();
        let sector_size = u64::from(options.bytes_per_sector);
        let end_sector = (self.offset - self.pending.len() as u64) / sector_size;
        options.acquisition_errors = self
            .errors
            .iter()
            .filter_map(|range| {
                // libewf replaces its error table when a later segment carries
                // error2. Keep each sealed prefix independently resumable and
                // make the last table describe the entire acquired prefix.
                let start = range.first_sector;
                let end = (range.first_sector + range.sector_count).min(end_sector);
                (start < end).then(|| AcquisitionError {
                    first_sector: start,
                    sector_count: end - start,
                })
            })
            .collect();
        let mut sections = Ewf1SegmentSections::for_segment(index == 1, final_segment);
        sections.bits |= Ewf1SegmentSections::ERRORS;
        if final_segment {
            let (md5, sha1, sha256) = self.hashes.clone().finalize();
            options.hashes = effective_write_hashes(&options.hashes, md5, sha1, sha256)?;
        }
        let mut segment = NamedTempFile::new_in(self.state.join("scratch"))?;
        let spool = self.spool.as_mut().expect("active spool");
        write_ewf1_segment(
            segment.as_file_mut(),
            spool,
            &self.chunks,
            &options,
            Ewf1SegmentWriteContext {
                segment_number: u16::try_from(index)
                    .map_err(|_| EwfError::Unsupported("too many acquisition segments".into()))?,
                chunk_count: self.source_size.div_ceil(self.chunk_size as u64) as u32,
                sector_count: self.source_size / u64::from(options.bytes_per_sector),
                sections,
                terminal_section: if final_segment {
                    TerminalSection::Done
                } else {
                    TerminalSection::Next
                },
            },
        )?;
        segment.as_file().sync_all()?;
        #[cfg(test)]
        {
            tests::crash_at("segment-synced", index);
            if self.fail_seal {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::StorageFull,
                    "injected acquisition storage failure",
                )
                .into());
            }
        }
        let size = segment.as_file().metadata()?.len();
        let digest = file_digest(segment.path())?;
        segment
            .persist_noclobber(&target)
            .map_err(|error| error.error)?;
        sync_dir(&self.state)?;
        #[cfg(test)]
        tests::crash_at("segment-installed", index);
        let seal = Seal {
            end: self.offset - self.pending.len() as u64,
            size,
            digest,
        };
        atomic_file(
            &self.state.join("scratch"),
            &checkpoint_path(&self.state, index),
            &seal.bytes(),
        )?;
        #[cfg(test)]
        tests::crash_at("record-installed", index);
        sync_dir(&self.state)?;
        #[cfg(test)]
        tests::crash_at("checkpoint-synced", index);
        self.sealed.push(seal);
        self.chunks.clear();
        spool.reset()?;
        self.segment_seal_duration += seal_started.elapsed();
        Ok(())
    }
}

fn normalize_errors(
    errors: &[AcquisitionError],
    bytes: u64,
    sector_size: u32,
) -> Result<Vec<AcquisitionError>> {
    let mut errors = errors.to_vec();
    errors.sort_unstable_by_key(|range| range.first_sector);
    let mut normalized: Vec<AcquisitionError> = Vec::new();
    for range in errors {
        let end = range
            .first_sector
            .checked_add(range.sector_count)
            .filter(|end| *end <= bytes / u64::from(sector_size))
            .ok_or_else(|| {
                EwfError::Malformed("acquisition error range exceeds checkpoint".into())
            })?;
        if range.sector_count == 0 {
            return Err(EwfError::Malformed("empty acquisition error range".into()));
        }
        if let Some(previous) = normalized.last_mut()
            && range.first_sector <= previous.first_sector + previous.sector_count
        {
            previous.sector_count =
                end.max(previous.first_sector + previous.sector_count) - previous.first_sector;
        } else {
            normalized.push(range);
        }
    }
    Ok(normalized)
}

impl Write for AcquisitionWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let result = self.append(bytes);
        self.failed |= result.is_err();
        result.map_err(std::io::Error::other)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.checkpoint().map(|_| ()).map_err(std::io::Error::other)
    }
}

impl Seal {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(80);
        bytes.extend_from_slice(&self.end.to_le_bytes());
        bytes.extend_from_slice(&self.size.to_le_bytes());
        bytes.extend_from_slice(&self.digest);
        bytes.extend_from_slice(&Sha256::digest(&bytes));
        bytes
    }

    fn read(path: &Path) -> Result<Self> {
        let bytes = read_fixed::<80>(path)?;
        if Sha256::digest(&bytes[..48])[..] != bytes[48..] {
            return Err(EwfError::Malformed("damaged acquisition checkpoint".into()));
        }
        Ok(Self {
            end: u64::from_le_bytes(bytes[..8].try_into().expect("fixed length")),
            size: u64::from_le_bytes(bytes[8..16].try_into().expect("fixed length")),
            digest: bytes[16..48].try_into().expect("fixed length"),
        })
    }

    fn validate_with_progress(
        &self,
        path: &Path,
        progress: &mut AcquisitionOperationProgress,
        callback: &mut impl FnMut(AcquisitionOperationProgress) -> ControlFlow<()>,
    ) -> Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        require_file_type(&metadata)?;
        if metadata.len() != self.size {
            return Err(EwfError::Malformed(
                "sealed acquisition segment changed".into(),
            ));
        }
        let mut file = File::open(path)?;
        let mut hash = Sha256::new();
        let mut buffer = [0; 16 * 1024];
        let mut remaining = self.size;
        while remaining > 0 {
            let take = remaining.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..take])?;
            hash.update(&buffer[..take]);
            remaining -= take as u64;
            progress.bytes_processed += take as u64;
            checkpoint::notify(*progress, callback)?;
        }
        if <[u8; 32]>::from(hash.finalize()) != self.digest {
            return Err(EwfError::Malformed(
                "sealed acquisition segment changed".into(),
            ));
        }
        progress.segments_processed += 1;
        checkpoint::notify(*progress, callback)
    }
}

fn normalize_first(first: &Path) -> Result<PathBuf> {
    if first.extension().and_then(|name| name.to_str()) != Some("E01") {
        return Err(EwfError::Unsupported(
            "acquisition requires an .E01 first segment".into(),
        ));
    }
    Ok(crate::segment::segment_dir(first)
        .canonicalize()?
        .join(first.file_name().expect("E01 filename")))
}

fn validate_segment_budget(first: &Path, options: &AcquisitionOptions) -> Result<()> {
    let chunk_size = u64::from(options.bytes_per_sector) * u64::from(options.sectors_per_chunk);
    let segments = options
        .source_size
        .div_ceil(chunk_size)
        .div_ceil(u64::from(options.chunks_per_segment));
    segment_path(
        first,
        usize::try_from(segments)
            .map_err(|_| EwfError::Unsupported("too many acquisition segments".into()))?,
    )?;
    Ok(())
}

fn fingerprint(
    first: &Path,
    acquisition: &AcquisitionOptions,
    options: &WriteOptions,
    source: [u8; 32],
) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"ewf-image-acquisition-v1");
    hash.update(source);
    hash.update(acquisition.source_size.to_le_bytes());
    hash.update(acquisition.bytes_per_sector.to_le_bytes());
    hash.update(acquisition.sectors_per_chunk.to_le_bytes());
    hash.update(acquisition.chunks_per_segment.to_le_bytes());
    hash.update([u8::from(acquisition.compression == WriteCompression::Zlib)]);
    let path = first.as_os_str().as_encoded_bytes();
    hash.update((path.len() as u64).to_le_bytes());
    hash.update(path);
    for payload in [
        header_payload(
            &options.metadata,
            options.header_codepage,
            options.compression_values.level,
        )?,
        header2_payload(&options.metadata, options.compression_values.level)?,
        xheader_payload(&options.metadata, options.compression_values.level)?,
    ] {
        let payload = payload.unwrap_or_default();
        hash.update((payload.len() as u64).to_le_bytes());
        hash.update(payload);
    }
    Ok(hash.finalize().into())
}

fn staged_path(first: &Path, state: &Path, index: usize) -> Result<PathBuf> {
    Ok(state.join(
        segment_path(first, index)?
            .file_name()
            .expect("segment filename"),
    ))
}

fn checkpoint_path(state: &Path, index: usize) -> PathBuf {
    state.join(format!("checkpoint-{index:05}"))
}

fn checkpoint_count(state: &Path) -> Result<usize> {
    let mut indices = Vec::new();
    for entry in fs::read_dir(state)? {
        let entry = entry?;
        let name = entry.file_name();
        if let Some(index) = name
            .to_str()
            .and_then(|name| name.strip_prefix("checkpoint-"))
        {
            let index = index
                .parse::<u16>()
                .map_err(|_| EwfError::Malformed("invalid acquisition checkpoint name".into()))?;
            if entry.path() != checkpoint_path(state, usize::from(index)) {
                return Err(EwfError::Malformed(
                    "invalid acquisition checkpoint name".into(),
                ));
            }
            indices.push(index);
        }
    }
    indices.sort_unstable();
    if indices
        .iter()
        .enumerate()
        .any(|(index, value)| index + 1 != usize::from(*value))
    {
        return Err(EwfError::Malformed("missing acquisition checkpoint".into()));
    }
    Ok(indices.len())
}

fn atomic_file(scratch: &Path, target: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = NamedTempFile::new_in(scratch)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(target)
        .map_err(|error| error.error)?;
    Ok(())
}

fn read_fixed<const N: usize>(path: &Path) -> Result<[u8; N]> {
    let metadata = fs::symlink_metadata(path)?;
    require_file_type(&metadata)?;
    if metadata.len() != N as u64 {
        return Err(EwfError::Malformed(
            "invalid acquisition record length".into(),
        ));
    }
    let mut bytes = [0; N];
    File::open(path)?.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn require_file_type(metadata: &fs::Metadata) -> Result<()> {
    if !metadata.file_type().is_file() {
        return Err(EwfError::Malformed(
            "acquisition path is not a regular file".into(),
        ));
    }
    Ok(())
}

fn require_directory(path: &Path) -> Result<()> {
    if !fs::symlink_metadata(path)?.file_type().is_dir() {
        return Err(EwfError::Malformed(
            "acquisition path is not a directory".into(),
        ));
    }
    Ok(())
}

fn file_digest(path: &Path) -> Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 16 * 1024];
    loop {
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
    }
    Ok(hash.finalize().into())
}

fn ensure_output_absent(first: &Path) -> Result<()> {
    for path in publication_segment_paths(&[first.to_path_buf()], false)? {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "acquisition output already exists",
                )
                .into());
            }
        }
    }
    Ok(())
}

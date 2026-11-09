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

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::ControlFlow;

use super::super::{encode_chunks, segment_path};
use super::{AcquisitionError, AcquisitionWriter, EwfError, Result};

const AUTOMATIC_BULK_READ_BYTES: usize = 256 * 1024;

/// Treatment of a sector that remains unreadable after its retries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UnreadableSectorPolicy {
    /// Stop without substituting data. Successfully accepted input is retained.
    #[default]
    Stop,
    /// Write a zero sector and record an acquisition-error range in the EWF.
    /// EOF, seek, permission, configuration, timeout, and interrupted-operation errors
    /// always stop; they are never converted to apparently acquired data.
    ZeroFill,
}

/// Source-reading policy; it can be changed between calls or after resume.
/// Previously substituted sectors and their provenance are never rewritten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquisitionReadOptions {
    /// Additional attempts per failed sector, from 0 through 100. Default: 2.
    /// A failed bulk read first falls back to individual sectors; bulk attempts
    /// do not consume a sector's retry allowance.
    pub retries: u32,
    /// Behavior after a sector's attempts are exhausted. Defaults to stopping.
    pub unreadable_sector_policy: UnreadableSectorPolicy,
    /// Maximum disjoint substituted-sector ranges retained in memory.
    /// Defaults to 65,536. Reaching the limit stops before substituting another
    /// disjoint range. Adjacent failed sectors share a range.
    pub maximum_error_ranges: usize,
    /// Optional logical-byte interval for early checkpoints. Must be a positive
    /// multiple of the chunk size. Segment boundaries also checkpoint normally.
    pub checkpoint_interval: Option<u64>,
}

impl Default for AcquisitionReadOptions {
    fn default() -> Self {
        Self {
            retries: 2,
            unreadable_sector_policy: UnreadableSectorPolicy::Stop,
            maximum_error_ranges: 65_536,
            checkpoint_interval: None,
        }
    }
}

/// Source progress delivered synchronously on the acquiring thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AcquisitionProgress {
    /// Declared logical source size.
    pub source_size: u64,
    /// Logical bytes accepted, including substitutions and unsealed input.
    pub bytes_written: u64,
    /// Logical bytes covered by the last acknowledged checkpoint.
    pub checkpoint_bytes: u64,
    /// Total sealed segment count.
    pub sealed_segments: usize,
    /// Total substituted sectors, including those restored by resume.
    pub substituted_sectors: u64,
    /// Bulk and sector attempts started during this call, including retries.
    pub read_attempts: u64,
    /// Additional sector attempts started during this call.
    pub retry_attempts: u64,
    /// Offset of the current or most recent source-read attempt.
    pub read_offset: u64,
    /// Most recent read attempt's error, cleared before a new attempt starts.
    pub read_error: Option<io::ErrorKind>,
}

/// Why a source acquisition call returned successfully.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquisitionStatus {
    /// The declared media range is filled, possibly with recorded substitutions.
    /// Call `finish` to publish it; completion does not imply all sectors were read.
    Complete,
    /// The progress callback requested cancellation. Full chunks were checkpointed.
    Cancelled,
}

/// Source-acquisition outcome. Publication remains an explicit `finish` step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AcquisitionOutcome {
    /// Completed or cancelled.
    pub status: AcquisitionStatus,
    /// Final progress, including the durable and accepted byte offsets.
    pub progress: AcquisitionProgress,
}

impl AcquisitionWriter {
    /// Acquires from a seekable file or caller-opened device using the given policy.
    /// Source position is set explicitly for every attempt, including after resume.
    pub fn acquire_from<R: Read + Seek>(
        &mut self,
        source: &mut R,
        options: &AcquisitionReadOptions,
    ) -> Result<AcquisitionOutcome> {
        self.acquire_with_progress(source, options, |_| ControlFlow::Continue(()))
    }

    /// Acquires with progress and cooperative cancellation. Returning `Break(())`
    /// checkpoints full chunks and returns `Cancelled`; a partial chunk stays in
    /// this writer's memory. Continue with this writer or drop it and resume from
    /// its checkpoint offset. Callbacks run before source I/O and between reads,
    /// retries, and writes. An in-flight OS operation or segment seal cannot be
    /// interrupted. A callback must return promptly and must not panic.
    ///
    /// Healthy reads automatically group complete image chunks into a bounded
    /// buffer. A failed bulk attempt is discarded and retried sector by sector.
    /// Partial failed reads never enter the image.
    /// Source failures checkpoint accepted full chunks and leave the writer usable;
    /// destination failures poison it and require dropping and resuming.
    pub fn acquire_with_progress<R: Read + Seek>(
        &mut self,
        source: &mut R,
        options: &AcquisitionReadOptions,
        mut on_progress: impl FnMut(AcquisitionProgress) -> ControlFlow<()>,
    ) -> Result<AcquisitionOutcome> {
        self.ensure_healthy()?;
        let sector_size = self.options.bytes_per_sector as usize;
        if !self.offset.is_multiple_of(sector_size as u64)
            || options.retries > 100
            || options.maximum_error_ranges == 0
            || self.errors.len() > options.maximum_error_ranges
            || options.checkpoint_interval.is_some_and(|interval| {
                interval == 0 || !interval.is_multiple_of(self.chunk_size as u64)
            })
        {
            return Err(EwfError::Malformed(
                "invalid acquisition read options or unaligned source position".into(),
            ));
        }
        // Early checkpoints consume native segment names too. Reject an
        // impossible interval before starting I/O, rather than after filling
        // the supported E01 segment namespace with a partial acquisition.
        let maximum_segment_bytes = self.chunk_size as u64 * self.chunks_per_segment as u64;
        let interval = options
            .checkpoint_interval
            .unwrap_or(maximum_segment_bytes)
            .min(maximum_segment_bytes);
        let remaining_segments = (self.source_size - self.checkpoint_offset()).div_ceil(interval);
        let final_segment =
            u64::try_from(self.sealed.len()).expect("segment count fits u64") + remaining_segments;
        segment_path(
            &self.first,
            usize::try_from(final_segment)
                .map_err(|_| EwfError::Unsupported("too many acquisition segments".into()))?,
        )?;
        let mut progress = self.source_progress();
        let result = self.acquire_loop(source, options, &mut progress, &mut on_progress);
        let status = match result {
            Ok(()) => AcquisitionStatus::Complete,
            Err(EwfError::Aborted) => AcquisitionStatus::Cancelled,
            Err(error) => {
                if !self.failed {
                    self.checkpoint()?;
                }
                return Err(error);
            }
        };
        self.checkpoint()?;
        self.refresh_source_progress(&mut progress);
        Ok(AcquisitionOutcome { status, progress })
    }

    fn source_progress(&self) -> AcquisitionProgress {
        let mut progress = AcquisitionProgress {
            source_size: self.source_size,
            bytes_written: 0,
            checkpoint_bytes: 0,
            sealed_segments: 0,
            substituted_sectors: 0,
            read_attempts: 0,
            retry_attempts: 0,
            read_offset: self.offset,
            read_error: None,
        };
        self.refresh_source_progress(&mut progress);
        progress
    }

    fn refresh_source_progress(&self, progress: &mut AcquisitionProgress) {
        progress.bytes_written = self.offset;
        progress.checkpoint_bytes = self.checkpoint_offset();
        progress.sealed_segments = self.sealed.len();
        progress.substituted_sectors = self.substituted_sectors;
    }

    fn acquire_loop<R: Read + Seek>(
        &mut self,
        source: &mut R,
        options: &AcquisitionReadOptions,
        progress: &mut AcquisitionProgress,
        callback: &mut impl FnMut(AcquisitionProgress) -> ControlFlow<()>,
    ) -> Result<()> {
        notify(*progress, callback)?;
        let mut buffer = vec![0; automatic_bulk_read_bytes(self.chunk_size)];
        let sector_size = self.options.bytes_per_sector as usize;
        while self.offset < self.source_size {
            let size = (if self.pending.is_empty() {
                buffer.len()
            } else {
                self.chunk_size - self.pending.len()
            })
            .min(buffer.len())
            .min((self.source_size - self.offset).min(usize::MAX as u64) as usize);
            let read = if size > sector_size {
                match read_attempt(source, &mut buffer[..size], self.offset, progress, callback) {
                    Ok(()) => true,
                    Err(AttemptError::Read(error)) if recoverable(&error) => false,
                    Err(error) => return Err(error.into_ewf()),
                }
            } else {
                false
            };
            if read {
                self.append_healthy_batch(&buffer[..size], options, progress, callback)?;
                continue;
            }
            // Re-read the entire failed bulk range by sector; even a successful
            // prefix of the failed attempt may have come from an unstable source.
            for sector in buffer[..size].chunks_mut(sector_size) {
                let mut last_error = None;
                for attempt in 0..=options.retries {
                    if attempt > 0 {
                        progress.retry_attempts += 1;
                    }
                    match read_attempt(source, sector, self.offset, progress, callback) {
                        Ok(()) => {
                            last_error = None;
                            break;
                        }
                        Err(AttemptError::Read(error)) if recoverable(&error) => {
                            last_error = Some(error);
                        }
                        Err(error) => return Err(error.into_ewf()),
                    }
                }
                if let Some(error) = last_error {
                    if options.unreadable_sector_policy == UnreadableSectorPolicy::Stop {
                        return Err(error.into());
                    }
                    self.record_substitution(options.maximum_error_ranges)?;
                    sector.fill(0);
                }
                self.write_all(sector)?;
                self.after_source_write(options, progress, callback)?;
            }
        }
        Ok(())
    }

    fn append_healthy_batch(
        &mut self,
        bytes: &[u8],
        options: &AcquisitionReadOptions,
        progress: &mut AcquisitionProgress,
        callback: &mut impl FnMut(AcquisitionProgress) -> ControlFlow<()>,
    ) -> Result<()> {
        self.ensure_healthy()?;
        if !self.pending.is_empty()
            || bytes.is_empty()
            || bytes.len() as u64 > self.source_size - self.offset
        {
            return Err(EwfError::Malformed(
                "invalid healthy acquisition batch".into(),
            ));
        }

        let processing_started = std::time::Instant::now();
        let mut hash_states = Vec::with_capacity(bytes.len().div_ceil(self.chunk_size));
        let mut hashes = self.hashes.clone();
        let mut lengths = Vec::with_capacity(hash_states.capacity());
        let chunks = bytes
            .chunks(self.chunk_size)
            .map(|chunk| {
                hashes.update(chunk);
                hash_states.push(hashes.clone());
                lengths.push(chunk.len());
                chunk.to_vec()
            })
            .collect();
        let encoded = match encode_chunks(
            chunks,
            self.options.compression,
            self.options.compression_values,
            self.chunk_size as u64,
            false,
            false,
        ) {
            Ok(encoded) => encoded,
            Err(error) => {
                self.failed = true;
                return Err(error);
            }
        };
        self.processing_duration += processing_started.elapsed();

        for ((chunk, length), hashes) in encoded.into_iter().zip(lengths).zip(hash_states) {
            self.offset += length as u64;
            self.hashes = hashes;
            let scratch_started = std::time::Instant::now();
            let descriptor = match self.spool.as_mut().expect("active spool").append(chunk) {
                Ok(descriptor) => descriptor,
                Err(error) => {
                    self.failed = true;
                    return Err(error);
                }
            };
            self.chunks.push(descriptor);
            self.scratch_write_duration += scratch_started.elapsed();
            if (self.chunks.len() == self.chunks_per_segment || self.offset == self.source_size)
                && let Err(error) = self.seal(self.offset == self.source_size)
            {
                self.failed = true;
                return Err(error);
            }
            self.after_source_write(options, progress, callback)?;
        }
        Ok(())
    }

    fn after_source_write(
        &mut self,
        options: &AcquisitionReadOptions,
        progress: &mut AcquisitionProgress,
        callback: &mut impl FnMut(AcquisitionProgress) -> ControlFlow<()>,
    ) -> Result<()> {
        if options
            .checkpoint_interval
            .is_some_and(|interval| self.offset - self.checkpoint_offset() >= interval)
        {
            self.checkpoint()?;
        }
        self.refresh_source_progress(progress);
        notify(*progress, callback)
    }

    fn record_substitution(&mut self, maximum_ranges: usize) -> Result<()> {
        let first_sector = self.offset / u64::from(self.options.bytes_per_sector);
        // The EWF1 error2 representation has 32-bit sector addresses. Never
        // substitute data whose provenance cannot be represented on disk.
        if first_sector > u64::from(u32::MAX) {
            return Err(EwfError::Unsupported(
                "unreadable sector exceeds EWF1 error-table addressing".into(),
            ));
        }
        if let Some(last) = self.errors.last_mut()
            && last.first_sector + last.sector_count == first_sector
            && last.sector_count < u64::from(u32::MAX)
        {
            last.sector_count += 1;
        } else {
            if self.errors.len() >= maximum_ranges {
                return Err(EwfError::Unsupported(
                    "acquisition error-range limit reached".into(),
                ));
            }
            self.errors.push(AcquisitionError {
                first_sector,
                sector_count: 1,
            });
        }
        self.substituted_sectors += 1;
        Ok(())
    }
}

fn automatic_bulk_read_bytes(chunk_size: usize) -> usize {
    (AUTOMATIC_BULK_READ_BYTES / chunk_size).max(1) * chunk_size
}

enum AttemptError {
    Read(io::Error),
    Fatal(EwfError),
}

impl AttemptError {
    fn into_ewf(self) -> EwfError {
        match self {
            Self::Read(error) => error.into(),
            Self::Fatal(error) => error,
        }
    }
}

fn read_attempt<R: Read + Seek>(
    source: &mut R,
    buffer: &mut [u8],
    offset: u64,
    progress: &mut AcquisitionProgress,
    callback: &mut impl FnMut(AcquisitionProgress) -> ControlFlow<()>,
) -> std::result::Result<(), AttemptError> {
    progress.read_offset = offset;
    progress.read_error = None;
    notify(*progress, callback).map_err(AttemptError::Fatal)?;
    let positioned = source
        .seek(SeekFrom::Start(offset))
        .map_err(|error| AttemptError::Fatal(error.into()))?;
    if positioned != offset {
        return Err(AttemptError::Fatal(EwfError::Malformed(
            "source seek returned a different offset".into(),
        )));
    }
    progress.read_attempts += 1;
    let mut filled = 0;
    while filled < buffer.len() {
        let result = source.read(&mut buffer[filled..]);
        let error = match result {
            Ok(0) => Some(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "source ended before declared acquisition size",
            )),
            Ok(size) if size <= buffer.len() - filled => {
                filled += size;
                None
            }
            Ok(_) => Some(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source returned an invalid read length",
            )),
            Err(error) => Some(error),
        };
        if let Some(error) = error {
            progress.read_error = Some(error.kind());
            notify(*progress, callback).map_err(AttemptError::Fatal)?;
            return Err(AttemptError::Read(error));
        }
        notify(*progress, callback).map_err(AttemptError::Fatal)?;
    }
    Ok(())
}

fn recoverable(error: &io::Error) -> bool {
    !matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::Unsupported
            | io::ErrorKind::NotFound
            | io::ErrorKind::Interrupted
            | io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::NotConnected
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
    )
}

fn notify(
    progress: AcquisitionProgress,
    callback: &mut impl FnMut(AcquisitionProgress) -> ControlFlow<()>,
) -> Result<()> {
    if callback(progress).is_break() {
        Err(EwfError::Aborted)
    } else {
        Ok(())
    }
}

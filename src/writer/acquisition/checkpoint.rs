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

use std::fs;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use super::{
    AcquisitionOptions, AcquisitionWriter, Seal, WriteOptions, checkpoint_count, checkpoint_path,
    ensure_output_absent, fingerprint, normalize_errors, normalize_first, read_fixed,
    require_directory, require_file_type, staged_path, validate_segment_budget,
};
use crate::publication::{OutputLock, acquisition_path};
use crate::{AcquisitionError, EwfError, Image, Result};

/// Long-running checkpoint or publication operation currently in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AcquisitionOperationPhase {
    /// Comparing sealed container bytes with checkpointed SHA256 values.
    ValidatingSegments,
    /// Decoding checkpointed media to restore acquisition digest state.
    RehashingMedia,
    /// Installing exclusive output links while retaining the checkpoint journal.
    Publishing,
}

/// Progress for one validation, rehash, or publication phase.
///
/// Counts are local to an operation phase. Revalidation of a previously published
/// link is a separate validation phase with its own byte and segment totals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AcquisitionOperationProgress {
    /// Operation phase.
    pub phase: AcquisitionOperationPhase,
    /// Bytes processed in this phase: encoded bytes for validation/publication,
    /// decoded logical bytes for media rehashing.
    pub bytes_processed: u64,
    /// Total bytes in this phase, using the same units as `bytes_processed`.
    pub bytes_total: u64,
    /// Completed segments in this phase.
    pub segments_processed: usize,
    /// Total segments in this phase.
    pub segments_total: usize,
}

/// Snapshot of a stopped acquisition.
///
/// Inspection never cleans scratch files,
/// rewrites records, rehashes media, or publishes output. It takes the same output
/// lock as a writer; close an active writer first or use its live getters.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AcquisitionCheckpoint {
    /// Declared full source size.
    pub source_size: u64,
    /// Offset at which source input must continue after resume.
    pub checkpoint_bytes: u64,
    /// Logical bytes per chunk.
    pub chunk_size: u64,
    /// Number of sealed native segments.
    pub sealed_segments: usize,
    /// Combined encoded size of sealed segments, excluding scratch and records.
    pub stored_bytes: u64,
    /// All declared source bytes are sealed and the final EWF marker is present.
    pub ready_to_finish: bool,
    /// Publication has started; some output links may already exist.
    pub publication_started: bool,
    /// Every sealed file was checked against its recorded SHA256 in this call.
    /// False for metadata-only inspection; true for `validate_checkpoint`.
    pub segment_hashes_validated: bool,
    /// Normalized substituted-sector ranges wholly inside the sealed prefix.
    pub acquisition_errors: Vec<AcquisitionError>,
    /// Number of substituted sectors in the sealed prefix.
    pub substituted_sectors: u64,
}

pub(super) struct CheckpointData {
    pub(super) state: PathBuf,
    pub(super) sealed: Vec<Seal>,
    pub(super) report: AcquisitionCheckpoint,
    pub(super) image: Option<Image>,
}

impl AcquisitionWriter {
    /// Inspects checkpoint records, segment lengths, and native metadata without
    /// scanning media payloads. Requires the original configuration and identity.
    /// This does not certify segment contents; use `validate_checkpoint` for that.
    pub fn inspect_checkpoint(
        first: impl AsRef<Path>,
        options: &AcquisitionOptions,
        source_identity: [u8; 32],
    ) -> Result<AcquisitionCheckpoint> {
        inspect(first.as_ref(), options, source_identity, false, &mut |_| {
            ControlFlow::Continue(())
        })
    }

    /// Inspects and validates sealed container hashes with cooperative cancellation.
    /// Returning `Break(())` returns `EwfError::Aborted` without changing checkpoint
    /// content. Media decoding/hashing is performed later by `resume`.
    pub fn validate_checkpoint(
        first: impl AsRef<Path>,
        options: &AcquisitionOptions,
        source_identity: [u8; 32],
        mut on_progress: impl FnMut(AcquisitionOperationProgress) -> ControlFlow<()>,
    ) -> Result<AcquisitionCheckpoint> {
        inspect(
            first.as_ref(),
            options,
            source_identity,
            true,
            &mut on_progress,
        )
    }
}

fn inspect(
    first: &Path,
    options: &AcquisitionOptions,
    source_identity: [u8; 32],
    validate: bool,
    callback: &mut impl FnMut(AcquisitionOperationProgress) -> ControlFlow<()>,
) -> Result<AcquisitionCheckpoint> {
    let write_options = options.writer_options()?;
    let first = normalize_first(first)?;
    validate_segment_budget(&first, options)?;
    let _lock = OutputLock::acquire(&first)?;
    Ok(load_checkpoint(
        &first,
        options,
        &write_options,
        source_identity,
        validate,
        callback,
    )?
    .report)
}

pub(super) fn load_checkpoint(
    first: &Path,
    options: &AcquisitionOptions,
    write_options: &WriteOptions,
    source_identity: [u8; 32],
    validate: bool,
    callback: &mut impl FnMut(AcquisitionOperationProgress) -> ControlFlow<()>,
) -> Result<CheckpointData> {
    crate::publication::ensure_no_publication(first)?;
    let state = acquisition_path(first)?;
    require_directory(&state)?;
    require_directory(&state.join("scratch"))?;
    if read_fixed::<32>(&state.join("config"))?
        != fingerprint(first, options, write_options, source_identity)?
    {
        return Err(EwfError::Malformed(
            "acquisition identity or options changed".into(),
        ));
    }
    let count = checkpoint_count(&state)?;
    let mut sealed = Vec::with_capacity(count);
    let mut paths = Vec::with_capacity(count);
    let mut previous = 0;
    let mut stored_bytes = 0_u64;
    let chunk_size = u64::from(options.bytes_per_sector) * u64::from(options.sectors_per_chunk);
    for index in 1..=count {
        let seal = Seal::read(&checkpoint_path(&state, index))?;
        if seal.end <= previous
            || seal.end > options.source_size
            || (seal.end < options.source_size && !seal.end.is_multiple_of(chunk_size))
            || (seal.end - previous).div_ceil(chunk_size) > u64::from(options.chunks_per_segment)
        {
            return Err(EwfError::Malformed(
                "invalid acquisition checkpoint geometry".into(),
            ));
        }
        let path = staged_path(first, &state, index)?;
        let metadata = fs::symlink_metadata(&path)?;
        require_file_type(&metadata)?;
        if metadata.len() != seal.size {
            return Err(EwfError::Malformed(
                "sealed acquisition segment changed".into(),
            ));
        }
        stored_bytes = stored_bytes
            .checked_add(seal.size)
            .ok_or_else(|| EwfError::Malformed("acquisition stored-size overflow".into()))?;
        previous = seal.end;
        paths.push(path);
        sealed.push(seal);
    }
    let publishing = state.join("publishing").try_exists()?;
    if publishing {
        read_fixed::<0>(&state.join("publishing"))?;
        if previous != options.source_size {
            return Err(EwfError::Malformed(
                "incomplete acquisition publication".into(),
            ));
        }
    } else {
        ensure_output_absent(first)?;
    }
    if validate {
        let mut progress = operation_progress(
            AcquisitionOperationPhase::ValidatingSegments,
            stored_bytes,
            count,
        );
        notify(progress, callback)?;
        for (path, seal) in paths.iter().zip(&sealed) {
            seal.validate_with_progress(path, &mut progress, callback)?;
        }
    }
    let (image, errors) = if paths.is_empty() {
        (None, Vec::new())
    } else {
        let image = Image::open_acquisition_prefix(paths, options.source_size, previous)?;
        if image.chunk_size() != chunk_size
            || image.info().acquisition_complete != (previous == options.source_size)
        {
            return Err(EwfError::Malformed(
                "acquisition segment geometry changed".into(),
            ));
        }
        let errors = normalize_errors(
            image.acquisition_errors(),
            previous,
            options.bytes_per_sector,
        )?;
        (Some(image), errors)
    };
    let report = AcquisitionCheckpoint {
        source_size: options.source_size,
        checkpoint_bytes: previous,
        chunk_size,
        sealed_segments: count,
        stored_bytes,
        ready_to_finish: previous == options.source_size,
        publication_started: publishing,
        segment_hashes_validated: validate,
        substituted_sectors: errors.iter().map(|range| range.sector_count).sum(),
        acquisition_errors: errors,
    };
    Ok(CheckpointData {
        state,
        sealed,
        report,
        image,
    })
}

pub(super) fn operation_progress(
    phase: AcquisitionOperationPhase,
    total: u64,
    segments: usize,
) -> AcquisitionOperationProgress {
    AcquisitionOperationProgress {
        phase,
        bytes_processed: 0,
        bytes_total: total,
        segments_processed: 0,
        segments_total: segments,
    }
}

pub(super) fn notify(
    progress: AcquisitionOperationProgress,
    callback: &mut impl FnMut(AcquisitionOperationProgress) -> ControlFlow<()>,
) -> Result<()> {
    if callback(progress).is_break() {
        Err(EwfError::Aborted)
    } else {
        Ok(())
    }
}

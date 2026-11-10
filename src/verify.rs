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

use std::ops::ControlFlow;

use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;

use crate::index::logical_chunk_count;
use crate::{EwfError, Image, Result, VerifyResult};

/// Options shared by verification and media integrity analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct VerifyOptions {
    expected_md5: Option<[u8; 16]>,
    expected_sha1: Option<[u8; 20]>,
    expected_sha256: Option<[u8; 32]>,
    parallelism: usize,
    chunk_buffer_size_bytes: usize,
    maximum_findings: usize,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            expected_md5: None,
            expected_sha1: None,
            expected_sha256: None,
            parallelism: 1,
            chunk_buffer_size_bytes: 8 * 1024 * 1024,
            maximum_findings: 1024,
        }
    }
}

impl VerifyOptions {
    /// Compares media MD5 with an independently supplied reference.
    pub fn with_expected_md5(mut self, expected: [u8; 16]) -> Self {
        self.expected_md5 = Some(expected);
        self
    }

    /// Compares media SHA1 with an independently supplied reference.
    pub fn with_expected_sha1(mut self, expected: [u8; 20]) -> Self {
        self.expected_sha1 = Some(expected);
        self
    }

    /// Compares media SHA256 with an independently supplied reference.
    pub fn with_expected_sha256(mut self, expected: [u8; 32]) -> Self {
        self.expected_sha256 = Some(expected);
        self
    }

    /// Sets the worker limit (1 through 64); values above 1 require `parallel`.
    /// Invalid settings return an error before a scan starts.
    pub fn with_parallelism(mut self, workers: usize) -> Self {
        self.parallelism = workers;
        self
    }

    /// Sets the decoded batch budget. A chunk larger than this budget is
    /// processed alone. Encoded buffers, decoder scratch space, and existing
    /// reader caches are additional memory.
    pub fn with_chunk_buffer_size_bytes(mut self, bytes: usize) -> Self {
        self.chunk_buffer_size_bytes = bytes;
        self
    }

    /// Limits retained analysis findings; suppressed findings are counted.
    /// Scanning continues after this limit is reached. Zero retains no findings.
    pub fn with_maximum_findings(mut self, count: usize) -> Self {
        self.maximum_findings = count;
        self
    }

    /// Returns the requested worker limit.
    pub fn parallelism(&self) -> usize {
        self.parallelism
    }

    /// Returns the decoded batch budget.
    pub fn chunk_buffer_size_bytes(&self) -> usize {
        self.chunk_buffer_size_bytes
    }

    /// Returns the maximum number of retained analysis findings.
    pub fn maximum_findings(&self) -> usize {
        self.maximum_findings
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if !(1..=64).contains(&self.parallelism) || self.chunk_buffer_size_bytes == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "verification requires 1..=64 workers and a nonzero chunk buffer budget",
            )
            .into());
        }
        if self.parallelism > 1 && !cfg!(feature = "parallel") {
            return Err(EwfError::Unsupported("parallel feature is disabled".into()));
        }
        Ok(())
    }
}

/// Hashes over every logical media byte, excluding final-chunk padding.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct ComputedHashes {
    /// Computed MD5 digest.
    pub md5: [u8; 16],
    /// Computed SHA1 digest.
    pub sha1: [u8; 20],
    /// Computed SHA256 digest.
    pub sha256: [u8; 32],
}

/// Digest algorithm used in a comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum HashAlgorithm {
    /// MD5.
    Md5,
    /// SHA1.
    Sha1,
    /// SHA256.
    Sha256,
}

/// Origin of a reference digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum HashReference {
    /// Digest embedded in the EWF image.
    Stored,
    /// Digest supplied independently by the caller.
    External,
}

/// One comparison; external references never replace embedded references.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct HashComparison {
    /// Digest algorithm.
    pub algorithm: HashAlgorithm,
    /// Reference origin.
    pub reference: HashReference,
    /// Expected digest bytes.
    pub expected: Vec<u8>,
    /// Computed digest bytes.
    pub computed: Vec<u8>,
    /// Whether the digests match.
    pub matches: bool,
}

/// Progress delivered on the calling thread, in logical order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct VerifyProgress {
    /// Logical bytes processed, including failed chunks during analysis.
    pub bytes_processed: u64,
    /// Logical bytes successfully decoded and validated.
    pub bytes_verified: u64,
    /// Total logical media size.
    pub bytes_total: u64,
    /// Chunks processed, including failures during analysis.
    pub chunks_processed: u64,
    /// Total logical chunk count.
    pub chunks_total: u64,
}

/// Completed media verification. Mismatches are results, not I/O errors.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct VerificationReport {
    /// Complete media digests.
    pub hashes: ComputedHashes,
    /// Comparisons with every available supported reference digest.
    pub comparisons: Vec<HashComparison>,
    /// Logical bytes verified.
    pub bytes_verified: u64,
}

impl VerificationReport {
    /// Returns `None` without a reference, otherwise whether all references match.
    pub fn references_match(&self) -> Option<bool> {
        (!self.comparisons.is_empty()).then(|| self.comparisons.iter().all(|item| item.matches))
    }
}

pub(crate) struct MediaScan {
    pub(crate) hashes: Option<ComputedHashes>,
    pub(crate) progress: VerifyProgress,
}

impl Image {
    /// Computes MD5, SHA1, and SHA256 hashes and compares embedded references.
    /// Reads backing chunks without using cached or zero-filled recovery data.
    /// Returns an error on corruption, I/O failure, or cancellation.
    pub fn verify(&self) -> Result<VerifyResult> {
        let report = self.verify_with_options(&VerifyOptions::default())?;
        Ok(VerifyResult {
            computed_md5: Some(report.hashes.md5),
            computed_sha1: Some(report.hashes.sha1),
            computed_sha256: Some(report.hashes.sha256),
            md5_match: self.md5_hash().map(|hash| hash == report.hashes.md5),
            sha1_match: self.sha1_hash().map(|hash| hash == report.hashes.sha1),
            sha256_match: report
                .comparisons
                .iter()
                .find(|item| {
                    item.algorithm == HashAlgorithm::Sha256
                        && item.reference == HashReference::Stored
                })
                .map(|item| item.matches),
        })
    }

    /// Computes MD5, SHA1, and SHA256 and compares stored and external references.
    /// Chunk corruption fails verification even if normal reads allow zero-fill.
    pub fn verify_with_options(&self, options: &VerifyOptions) -> Result<VerificationReport> {
        self.verify_with_progress(options, |_| ControlFlow::Continue(()))
    }

    /// Verifies media with an initial event and an event after every processed chunk.
    /// Returning `Break(())` cancels this operation with [`EwfError::Aborted`],
    /// without aborting other readers. Already-running worker reads finish before
    /// the call returns. [`Image::signal_abort`] is also honored.
    pub fn verify_with_progress(
        &self,
        options: &VerifyOptions,
        progress: impl FnMut(VerifyProgress) -> ControlFlow<()>,
    ) -> Result<VerificationReport> {
        let scan = self.scan_media(options, progress, |_, error| Err(error))?;
        let hashes = scan
            .hashes
            .expect("successful verification has complete hashes");
        let comparisons = self.compare_hashes(&hashes, options);
        Ok(VerificationReport {
            hashes,
            comparisons,
            bytes_verified: scan.progress.bytes_verified,
        })
    }

    pub(crate) fn compare_hashes(
        &self,
        hashes: &ComputedHashes,
        options: &VerifyOptions,
    ) -> Vec<HashComparison> {
        let references = [
            (
                HashAlgorithm::Sha256,
                HashReference::Stored,
                self.info()
                    .stored_hashes
                    .hash_value("SHA256")
                    .and_then(crate::types::parse_hex_array::<32>)
                    .map(|v| v.to_vec()),
                hashes.sha256.as_slice(),
            ),
            (
                HashAlgorithm::Md5,
                HashReference::Stored,
                self.md5_hash().map(|v| v.to_vec()),
                hashes.md5.as_slice(),
            ),
            (
                HashAlgorithm::Sha1,
                HashReference::Stored,
                self.sha1_hash().map(|v| v.to_vec()),
                hashes.sha1.as_slice(),
            ),
            (
                HashAlgorithm::Md5,
                HashReference::External,
                options.expected_md5.map(|v| v.to_vec()),
                hashes.md5.as_slice(),
            ),
            (
                HashAlgorithm::Sha1,
                HashReference::External,
                options.expected_sha1.map(|v| v.to_vec()),
                hashes.sha1.as_slice(),
            ),
            (
                HashAlgorithm::Sha256,
                HashReference::External,
                options.expected_sha256.map(|v| v.to_vec()),
                hashes.sha256.as_slice(),
            ),
        ];
        references
            .into_iter()
            .filter_map(|(algorithm, reference, expected, computed)| {
                expected.map(|expected| HashComparison {
                    algorithm,
                    reference,
                    matches: expected == computed,
                    expected,
                    computed: computed.to_vec(),
                })
            })
            .collect()
    }

    pub(crate) fn scan_media(
        &self,
        options: &VerifyOptions,
        mut on_progress: impl FnMut(VerifyProgress) -> ControlFlow<()>,
        mut on_error: impl FnMut(u64, EwfError) -> Result<()>,
    ) -> Result<MediaScan> {
        options.validate()?;
        self.ensure_not_aborted()?;
        let chunk_size = self.chunk_size();
        let count = logical_chunk_count(self.media_size(), chunk_size)?;
        let mut progress = VerifyProgress {
            bytes_processed: 0,
            bytes_verified: 0,
            bytes_total: self.media_size(),
            chunks_processed: 0,
            chunks_total: count,
        };
        report_progress(self, &mut on_progress, progress)?;
        let budget_chunks = (options.chunk_buffer_size_bytes as u64 / chunk_size).max(1);
        let batch_size = budget_chunks.min(options.parallelism as u64 * 2).max(1);
        #[cfg(feature = "parallel")]
        let pool = if options.parallelism > 1 && count > 1 && batch_size > 1 {
            Some(
                rayon::ThreadPoolBuilder::new()
                    .num_threads(options.parallelism.min(batch_size as usize))
                    .build()
                    .map_err(std::io::Error::other)?,
            )
        } else {
            None
        };
        let mut md5 = Md5::new();
        let mut sha1 = Sha1::new();
        let mut sha256 = Sha256::new();
        let mut failed = false;
        let mut start = 0;
        while start < count {
            self.ensure_not_aborted()?;
            let end = start.saturating_add(batch_size).min(count);
            let indices: Vec<u64> = (start..end).collect();
            #[cfg(feature = "parallel")]
            let chunks: Vec<Result<Vec<u8>>> = if let Some(pool) = &pool {
                use rayon::prelude::*;
                pool.install(|| {
                    indices
                        .par_iter()
                        .map(|&id| self.verification_chunk(id))
                        .collect()
                })
            } else {
                indices
                    .iter()
                    .map(|&id| self.verification_chunk(id))
                    .collect()
            };
            #[cfg(not(feature = "parallel"))]
            let chunks: Vec<Result<Vec<u8>>> = indices
                .iter()
                .map(|&id| self.verification_chunk(id))
                .collect();
            for (id, chunk) in indices.into_iter().zip(chunks) {
                self.ensure_not_aborted()?;
                let size = chunk_size.min(self.media_size() - progress.bytes_processed);
                match chunk {
                    Ok(bytes) if bytes.len() as u64 == size => {
                        md5.update(&bytes);
                        sha1.update(&bytes);
                        sha256.update(&bytes);
                        progress.bytes_verified += size;
                    }
                    Ok(_) => {
                        failed = true;
                        on_error(
                            id,
                            EwfError::Malformed(
                                "decoded chunk length differs from logical media range".into(),
                            ),
                        )?;
                    }
                    Err(EwfError::Aborted) => return Err(EwfError::Aborted),
                    Err(error) => {
                        failed = true;
                        on_error(id, error)?;
                    }
                }
                progress.chunks_processed += 1;
                progress.bytes_processed += size;
                report_progress(self, &mut on_progress, progress)?;
            }
            start = end;
        }
        Ok(MediaScan {
            hashes: (!failed).then(|| ComputedHashes {
                md5: md5.finalize().into(),
                sha1: sha1.finalize().into(),
                sha256: sha256.finalize().into(),
            }),
            progress,
        })
    }
}

fn report_progress(
    image: &Image,
    callback: &mut impl FnMut(VerifyProgress) -> ControlFlow<()>,
    progress: VerifyProgress,
) -> Result<()> {
    if callback(progress).is_break() {
        return Err(EwfError::Aborted);
    }
    image.ensure_not_aborted()
}

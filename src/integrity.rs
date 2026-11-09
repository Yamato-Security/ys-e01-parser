use std::ops::ControlFlow;
use std::path::Path;

use crate::lenient::{Defect, DefectKind};
use crate::{
    ComputedHashes, EwfError, EwfPassword, HashAlgorithm, HashComparison, HashReference, Image,
    Result, SectionInfo, SectionKind, VerifyOptions, VerifyProgress,
};

/// Severity of a reported integrity condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum IntegritySeverity {
    /// Context affecting interpretation of evidence.
    Warning,
    /// Invalid structure, unreadable media, or a failed reference comparison.
    Error,
}

/// Stable categories for findings; diagnostic text is not a machine interface.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub enum IntegrityFindingKind {
    /// Opening rejected malformed image structure.
    InvalidStructure,
    /// Input signature was not recognized.
    InvalidSignature,
    /// A required feature is unavailable.
    UnsupportedFeature,
    /// Encrypted input needs a password.
    PasswordRequired,
    /// Supplied password was rejected or decrypted content failed validation.
    DecryptionFailed,
    /// A logical chunk could not be read and validated.
    ChunkUnreadable,
    /// Matching primary and redundant chunk tables contain different entries.
    RedundantTableMismatch,
    /// Redundant-table checking could not complete.
    TableCheckUnavailable,
    /// No supported embedded media hash was found.
    MissingStoredHashes,
    /// Acquisition recorded unreadable source sectors.
    AcquisitionErrors,
    /// Acquisition lacks its completed terminal marker.
    IncompleteAcquisition,
    /// Lenient opening accepted a structural irregularity not covered by a more
    /// specific kind; the message says what was accepted.
    LenientOpen,
    /// A damaged metadata section (header, hash, digest, error, session, or
    /// similar) was ignored, so its values are unavailable.
    MetadataUnavailable,
    /// One complete media digest differs from its reference.
    HashMismatch {
        /// Digest algorithm.
        algorithm: HashAlgorithm,
        /// Reference origin.
        reference: HashReference,
    },
}

/// One finding with optional source and logical locations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct IntegrityFinding {
    /// Typed finding category.
    pub kind: IntegrityFindingKind,
    /// Finding severity.
    pub severity: IntegritySeverity,
    /// Human-readable diagnostic, without passwords or derived keys.
    pub message: String,
    /// Zero-based source segment index, when known.
    pub segment_index: Option<usize>,
    /// Source segment byte offset, when known.
    pub segment_offset: Option<u64>,
    /// Logical chunk index, when known.
    pub chunk_index: Option<u64>,
    /// Logical media byte offset, when known.
    pub logical_offset: Option<u64>,
}

/// Coverage of the logical media pass, separate from the findings' severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum MediaScanStatus {
    /// Every logical byte was decoded and validated; reference hashes may differ.
    Complete,
    /// All chunks were attempted, but some could not be validated.
    Incomplete,
    /// Opening failed before logical media could be scanned.
    Unavailable,
}

/// Bounded integrity findings plus explicit scan coverage.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct IntegrityReport {
    /// Media scan coverage.
    pub media_status: MediaScanStatus,
    /// Successfully validated logical bytes.
    pub bytes_verified: u64,
    /// Declared logical size, when opening succeeded.
    pub bytes_total: Option<u64>,
    /// Complete media digests. Never hashes of a stream with omitted or substituted bytes.
    pub hashes: Option<ComputedHashes>,
    /// Available comparisons; empty if media scanning was incomplete.
    pub comparisons: Vec<HashComparison>,
    /// Retained findings in deterministic check and logical-chunk order.
    pub findings: Vec<IntegrityFinding>,
    /// Number of findings omitted by the caller's retention limit.
    pub suppressed_findings: u64,
    /// Total error findings, including suppressed findings.
    pub error_count: u64,
    /// Total warning findings, including suppressed findings.
    pub warning_count: u64,
}

impl IntegrityReport {
    fn new() -> Self {
        Self {
            media_status: MediaScanStatus::Unavailable,
            bytes_verified: 0,
            bytes_total: None,
            hashes: None,
            comparisons: Vec::new(),
            findings: Vec::new(),
            suppressed_findings: 0,
            error_count: 0,
            warning_count: 0,
        }
    }

    fn push(&mut self, finding: IntegrityFinding, limit: usize) {
        match finding.severity {
            IntegritySeverity::Error => self.error_count += 1,
            IntegritySeverity::Warning => self.warning_count += 1,
        }
        if self.findings.len() < limit {
            self.findings.push(finding);
        } else {
            self.suppressed_findings += 1;
        }
    }
}

fn defect_finding(defect: &Defect, chunk_size: u64) -> IntegrityFinding {
    let (kind, severity) = match defect.kind {
        DefectKind::MetadataUnavailable => (
            IntegrityFindingKind::MetadataUnavailable,
            IntegritySeverity::Error,
        ),
        DefectKind::Irregular => (
            IntegrityFindingKind::LenientOpen,
            IntegritySeverity::Warning,
        ),
    };
    let mut item = finding(kind, severity, defect.message.clone());
    item.segment_index = defect.segment_index;
    item.segment_offset = defect.segment_offset;
    item.chunk_index = defect.chunk_index;
    item.logical_offset = defect
        .chunk_index
        .and_then(|chunk| chunk.checked_mul(chunk_size));
    item
}

fn finding(
    kind: IntegrityFindingKind,
    severity: IntegritySeverity,
    message: impl Into<String>,
) -> IntegrityFinding {
    IntegrityFinding {
        kind,
        severity,
        message: message.into(),
        segment_index: None,
        segment_offset: None,
        chunk_index: None,
        logical_offset: None,
    }
}

/// Opens with the default (lenient) options, then scans media and redundant tables.
///
/// Defects that lenient opening went past are reported as findings ahead of the
/// media scan. An image that cannot be opened at all is returned as one finding
/// with unavailable media coverage. Filesystem I/O errors and invalid scan
/// options remain errors.
pub fn analyze_path(path: impl AsRef<Path>, options: &VerifyOptions) -> Result<IntegrityReport> {
    options.validate()?;
    analyze_open_result(Image::open(path), options)
}

/// Opens with the default (lenient) options and analyzes with cooperative
/// media-scan cancellation.
///
/// Opening and redundant-table inspection precede media progress. Retains at
/// most 16 segment handles and disables the decoded chunk cache. Structural
/// opening failures become findings, as with [`analyze_path`].
pub fn analyze_path_with_progress(
    path: impl AsRef<Path>,
    options: &VerifyOptions,
    progress: impl FnMut(VerifyProgress) -> ControlFlow<()>,
) -> Result<IntegrityReport> {
    options.validate()?;
    let opened = Image::open_with_options(
        path,
        crate::OpenOptions::default()
            .with_chunk_cache_size(0)
            .with_maximum_open_handles(Some(16)),
    );
    analyze_open_with_progress(opened, options, progress)
}

/// Password-aware counterpart to [`analyze_path`]. Password failures are reported
/// without exposing password or key material.
pub fn analyze_path_with_password(
    path: impl AsRef<Path>,
    options: &VerifyOptions,
    password: &EwfPassword,
) -> Result<IntegrityReport> {
    options.validate()?;
    analyze_open_result(Image::open_with_password(path, password), options)
}

/// Password-aware counterpart to [`analyze_path_with_progress`].
pub fn analyze_path_with_progress_and_password(
    path: impl AsRef<Path>,
    options: &VerifyOptions,
    password: &EwfPassword,
    progress: impl FnMut(VerifyProgress) -> ControlFlow<()>,
) -> Result<IntegrityReport> {
    options.validate()?;
    let opened = Image::open_with_options_and_password(
        path,
        crate::OpenOptions::default()
            .with_chunk_cache_size(0)
            .with_maximum_open_handles(Some(16)),
        password,
    );
    analyze_open_with_progress(opened, options, progress)
}

fn analyze_open_result(opened: Result<Image>, options: &VerifyOptions) -> Result<IntegrityReport> {
    analyze_open_with_progress(opened, options, |_| ControlFlow::Continue(()))
}

fn analyze_open_with_progress(
    opened: Result<Image>,
    options: &VerifyOptions,
    progress: impl FnMut(VerifyProgress) -> ControlFlow<()>,
) -> Result<IntegrityReport> {
    match opened {
        Ok(image) => image.analyze_with_progress(options, progress),
        Err(error) => {
            let kind = match &error {
                EwfError::Malformed(_) | EwfError::BufferTooShort { .. } => {
                    IntegrityFindingKind::InvalidStructure
                }
                EwfError::InvalidSignature => IntegrityFindingKind::InvalidSignature,
                EwfError::Unsupported(_) => IntegrityFindingKind::UnsupportedFeature,
                EwfError::PasswordRequired => IntegrityFindingKind::PasswordRequired,
                EwfError::PasswordRejected | EwfError::DecryptionValidationFailed => {
                    IntegrityFindingKind::DecryptionFailed
                }
                EwfError::Io(io) if io.kind() == std::io::ErrorKind::UnexpectedEof => {
                    IntegrityFindingKind::InvalidStructure
                }
                _ => return Err(error),
            };
            let mut report = IntegrityReport::new();
            report.push(
                finding(kind, IntegritySeverity::Error, error.to_string()),
                options.maximum_findings(),
            );
            Ok(report)
        }
    }
}

impl Image {
    /// Structural defects that lenient opening, and reading so far, went past.
    ///
    /// Each entry says what was damaged and what the reader did instead (used an
    /// intact copy, checked the values another way, ignored metadata, or made the
    /// affected chunks fail when read). Lenient opening never substitutes data:
    /// a chunk it cannot verify fails when read. The list is empty for an image
    /// opened with [`crate::OpenStrictness::Strict`] and for an undamaged image.
    pub fn lenient_findings(&self) -> Vec<IntegrityFinding> {
        self.defects()
            .iter()
            .map(|defect| defect_finding(defect, self.chunk_size()))
            .collect()
    }

    /// Collects media failures, redundant-table disagreements, acquisition context,
    /// and digest mismatches. Continues after chunk failures without substituting
    /// zero bytes. Structural validation is the validation performed during open.
    pub fn analyze(&self, options: &VerifyOptions) -> Result<IntegrityReport> {
        self.analyze_with_progress(options, |_| ControlFlow::Continue(()))
    }

    /// Analyzes with media progress and per-operation cancellation. Progress begins
    /// after redundant-table checks. A cancelled scan returns `Aborted`, not a
    /// successful partial report.
    pub fn analyze_with_progress(
        &self,
        options: &VerifyOptions,
        progress: impl FnMut(VerifyProgress) -> ControlFlow<()>,
    ) -> Result<IntegrityReport> {
        options.validate()?;
        self.ensure_not_aborted()?;
        let limit = options.maximum_findings();
        let mut report = IntegrityReport::new();
        report.bytes_total = Some(self.media_size());
        for item in self.lenient_findings() {
            report.push(item, limit);
        }
        if !self.info().acquisition_complete {
            report.push(
                finding(
                    IntegrityFindingKind::IncompleteAcquisition,
                    IntegritySeverity::Warning,
                    "acquisition is incomplete",
                ),
                limit,
            );
        }
        if !self.acquisition_errors().is_empty() {
            report.push(
                finding(
                    IntegrityFindingKind::AcquisitionErrors,
                    IntegritySeverity::Warning,
                    format!(
                        "{} acquisition error ranges are recorded",
                        self.acquisition_errors().len()
                    ),
                ),
                limit,
            );
        }
        if self.md5_hash().is_none()
            && self.sha1_hash().is_none()
            && self.hash_value("SHA256").is_none()
        {
            report.push(
                finding(
                    IntegrityFindingKind::MissingStoredHashes,
                    IntegritySeverity::Warning,
                    "no embedded MD5, SHA1, or SHA256 reference is available",
                ),
                limit,
            );
        }
        self.analyze_redundant_tables(&mut report, limit)?;
        let scan = self.scan_media(options, progress, |id, error| {
            let mut item = finding(
                IntegrityFindingKind::ChunkUnreadable,
                IntegritySeverity::Error,
                error.to_string(),
            );
            item.chunk_index = Some(id);
            item.logical_offset = Some(id * self.chunk_size());
            // Location lookup can itself fail for a damaged table entry.
            item.segment_index = self.segment_filename_for_chunk(id).ok().and_then(|path| {
                self.segment_filenames()
                    .iter()
                    .position(|candidate| candidate == path)
            });
            report.push(item, limit);
            Ok(())
        })?;
        report.bytes_verified = scan.progress.bytes_verified;
        report.media_status = if scan.hashes.is_some() {
            MediaScanStatus::Complete
        } else {
            MediaScanStatus::Incomplete
        };
        if let Some(hashes) = &scan.hashes {
            report.comparisons = self.compare_hashes(hashes, options);
            let mismatches: Vec<_> = report
                .comparisons
                .iter()
                .filter(|item| !item.matches)
                .map(|item| {
                    finding(
                        IntegrityFindingKind::HashMismatch {
                            algorithm: item.algorithm,
                            reference: item.reference,
                        },
                        IntegritySeverity::Error,
                        format!(
                            "{:?} differs from {:?} reference",
                            item.algorithm, item.reference
                        ),
                    )
                })
                .collect();
            for item in mismatches {
                report.push(item, limit);
            }
        }
        report.hashes = scan.hashes;
        Ok(report)
    }

    fn analyze_redundant_tables(&self, report: &mut IntegrityReport, limit: usize) -> Result<()> {
        let mut primary: Option<&SectionInfo> = None;
        for section in self.sections() {
            self.ensure_not_aborted()?;
            match &section.kind {
                SectionKind::Ewf1(name) if name == "table" => primary = Some(section),
                SectionKind::Ewf1(name) if name == "table2" => {
                    if let Some(table) = primary
                        .take()
                        .filter(|table| table.segment_index == section.segment_index)
                    {
                        match self.compare_table_entries(table, section) {
                            Ok(Some(offset)) => {
                                let mut item = finding(
                                    IntegrityFindingKind::RedundantTableMismatch,
                                    IntegritySeverity::Error,
                                    "primary and redundant chunk table entries differ",
                                );
                                item.segment_index = Some(section.segment_index);
                                item.segment_offset = Some(offset);
                                report.push(item, limit);
                            }
                            Err(EwfError::Aborted) => return Err(EwfError::Aborted),
                            Err(error) => {
                                let mut item = finding(
                                    IntegrityFindingKind::TableCheckUnavailable,
                                    IntegritySeverity::Error,
                                    error.to_string(),
                                );
                                item.segment_index = Some(section.segment_index);
                                item.segment_offset = Some(section.descriptor_offset);
                                report.push(item, limit);
                            }
                            Ok(None) => {}
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn compare_table_entries(
        &self,
        primary: &SectionInfo,
        redundant: &SectionInfo,
    ) -> Result<Option<u64>> {
        let left =
            self.read_segment_range(primary.segment_index, primary.data_offset, 24, false)?;
        let right =
            self.read_segment_range(redundant.segment_index, redundant.data_offset, 24, false)?;
        // A table2 with different geometry may be a unique range, not a mirror.
        if left[..4] != right[..4] || left[8..16] != right[8..16] {
            return Ok(None);
        }
        let size = u64::from(u32::from_le_bytes(
            left[..4].try_into().expect("header read"),
        )) * 4;
        if size > primary.data_size.saturating_sub(24)
            || size > redundant.data_size.saturating_sub(24)
        {
            return Err(EwfError::Malformed(
                "redundant table entries exceed section payload".into(),
            ));
        }
        let mut offset = 0;
        while offset < size {
            self.ensure_not_aborted()?;
            let take = (size - offset).min(64 * 1024);
            let a = self.read_segment_range(
                primary.segment_index,
                primary.data_offset + 24 + offset,
                take,
                false,
            )?;
            let b = self.read_segment_range(
                redundant.segment_index,
                redundant.data_offset + 24 + offset,
                take,
                false,
            )?;
            if let Some(difference) = a.iter().zip(&b).position(|(a, b)| a != b) {
                return Ok(Some(
                    redundant.data_offset + 24 + offset + difference as u64,
                ));
            }
            offset += take;
        }
        Ok(None)
    }
}

//! Bookkeeping for structural defects that lenient opening goes past.
//!
//! The reader records each tolerated defect here while opening. With the `verify` feature the records
//! are exposed as [`crate::IntegrityFinding`] values; the internal form keeps the
//! reader independent of that feature.

use crate::{EwfError, OpenStrictness, Result};

/// Category of a tolerated defect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DefectKind {
    /// A damaged metadata section was ignored.
    MetadataUnavailable,
    /// Another irregularity that lenient opening accepted.
    Irregular,
}

/// One tolerated defect with its location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Defect {
    pub(crate) kind: DefectKind,
    pub(crate) message: String,
    pub(crate) segment_index: Option<usize>,
    pub(crate) segment_offset: Option<u64>,
    pub(crate) chunk_index: Option<u64>,
}

/// Open-time policy plus the defects recorded so far.
#[derive(Debug)]
pub(crate) struct Leniency {
    lenient: bool,
    defects: Vec<Defect>,
}

impl Leniency {
    pub(crate) fn new(strictness: OpenStrictness) -> Self {
        Self {
            lenient: strictness == OpenStrictness::Lenient,
            defects: Vec::new(),
        }
    }

    pub(crate) fn is_lenient(&self) -> bool {
        self.lenient
    }

    /// Returns `error` in strict mode. In lenient mode records a structural
    /// error as a defect, with `consequence` describing what the reader does
    /// instead, and returns `Ok`. Other errors (I/O, unsupported features,
    /// passwords) are always returned.
    pub(crate) fn tolerate(
        &mut self,
        error: EwfError,
        kind: DefectKind,
        segment_index: usize,
        segment_offset: u64,
        consequence: &str,
    ) -> Result<()> {
        if !self.lenient
            || !matches!(
                error,
                EwfError::Malformed(_) | EwfError::BufferTooShort { .. }
            )
        {
            return Err(error);
        }
        self.record(
            kind,
            Some(segment_index),
            Some(segment_offset),
            format!("{}; {consequence}", describe(&error)),
        );
        Ok(())
    }

    pub(crate) fn record(
        &mut self,
        kind: DefectKind,
        segment_index: Option<usize>,
        segment_offset: Option<u64>,
        message: impl Into<String>,
    ) {
        self.push(Defect {
            kind,
            message: message.into(),
            segment_index,
            segment_offset,
            chunk_index: None,
        });
    }

    pub(crate) fn push(&mut self, defect: Defect) {
        // Opening reports each defect once; identical repeats add nothing.
        if !self.defects.contains(&defect) {
            self.defects.push(defect);
        }
    }

    pub(crate) fn into_defects(self) -> Vec<Defect> {
        self.defects
    }
}

/// Error text without the generic "malformed EWF image:" prefix.
pub(crate) fn describe(error: &EwfError) -> String {
    match error {
        EwfError::Malformed(message) => message.clone(),
        other => other.to_string(),
    }
}

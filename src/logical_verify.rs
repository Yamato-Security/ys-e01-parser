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

//! Strict logical-file streaming and digest comparisons.

use std::io::Write;
use std::ops::ControlFlow;

use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;

use crate::{
    ComputedHashes, EwfError, HashAlgorithm, HashComparison, HashReference, Image, Result,
    SingleFileEntry, SingleFileEntryType,
};

/// Progress over one file's bytes, including sparse zeroes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct SingleFileProgress {
    /// Bytes successfully read and written.
    pub bytes_processed: u64,
    /// File size; excludes container padding.
    pub bytes_total: u64,
}

/// Completed file-level verification; never certifies the whole container.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct SingleFileVerification {
    /// Hashes of exactly the reconstructed file bytes.
    pub hashes: ComputedHashes,
    /// Comparisons against available entry MD5/SHA1 references.
    pub comparisons: Vec<HashComparison>,
    /// File bytes verified, excluding container padding.
    pub bytes_verified: u64,
}

impl SingleFileVerification {
    /// `None` means no file reference was stored; it does not mean a match.
    pub fn references_match(&self) -> Option<bool> {
        (!self.comparisons.is_empty()).then(|| self.comparisons.iter().all(|c| c.matches))
    }
}

impl Image {
    /// Strictly verifies one regular file against its stored MD5/SHA1 hashes.
    /// Mismatches are results; malformed digests and unreadable data are errors.
    /// The caller should supply an entry from this image's catalog.
    pub fn verify_single_file(&self, entry: &SingleFileEntry) -> Result<SingleFileVerification> {
        self.verify_single_file_with_progress(entry, |_| ControlFlow::Continue(()))
    }

    /// Verifies one file, with cooperative cancellation before and after each buffer.
    pub fn verify_single_file_with_progress(
        &self,
        entry: &SingleFileEntry,
        progress: impl FnMut(SingleFileProgress) -> ControlFlow<()>,
    ) -> Result<SingleFileVerification> {
        self.copy_single_file_with_progress(entry, &mut std::io::sink(), progress)
    }

    /// Copies strictly decoded file bytes and compares stored file hashes.
    /// Uses bounded buffers and bypasses decoded caches and recovery policies.
    /// The caller owns output publication: errors, cancellation, or mismatches
    /// can leave partial or unverified bytes in `output`. No output is flushed
    /// or synchronized here. Missing references return `None`, not success.
    pub fn copy_single_file_with_progress(
        &self,
        entry: &SingleFileEntry,
        output: &mut impl Write,
        mut progress: impl FnMut(SingleFileProgress) -> ControlFlow<()>,
    ) -> Result<SingleFileVerification> {
        if entry.entry_type() != Some(SingleFileEntryType::File) {
            return Err(EwfError::Unsupported(
                "entry is not a regular logical file".into(),
            ));
        }
        // Honor the image-wide abort flag even for an empty file.
        self.read_single_file_at_strict(entry, &mut [], 0)?;
        let references = [
            (HashAlgorithm::Md5, "MD5", entry.md5.as_deref()),
            (HashAlgorithm::Sha1, "SHA1", entry.sha1.as_deref()),
        ];
        for (_, name, value) in references {
            if let Some(value) = value {
                crate::hashes::validate_digest(name, value)?;
            }
        }
        let total = crate::image::single_file_size(entry)?;
        let mut offset = 0;
        let mut buffer = vec![0; 1024 * 1024];
        let mut md5 = Md5::new();
        let mut sha1 = Sha1::new();
        let mut sha256 = Sha256::new();
        loop {
            if progress(SingleFileProgress {
                bytes_processed: offset,
                bytes_total: total,
            })
            .is_break()
            {
                return Err(EwfError::Aborted);
            }
            if offset == total {
                break;
            }
            let length = (total - offset).min(buffer.len() as u64) as usize;
            let read = self.read_single_file_at_strict(entry, &mut buffer[..length], offset)?;
            if read != length {
                return Err(EwfError::Malformed(
                    "logical file read was truncated".into(),
                ));
            }
            output.write_all(&buffer[..read])?;
            md5.update(&buffer[..read]);
            sha1.update(&buffer[..read]);
            sha256.update(&buffer[..read]);
            offset += read as u64;
        }
        let hashes = ComputedHashes {
            md5: md5.finalize().into(),
            sha1: sha1.finalize().into(),
            sha256: sha256.finalize().into(),
        };
        let mut comparisons = Vec::new();
        if let Some(value) = &entry.md5 {
            let expected = crate::types::parse_hex_array::<16>(value).expect("validated digest");
            comparisons.push(HashComparison {
                algorithm: HashAlgorithm::Md5,
                reference: HashReference::Stored,
                expected: expected.to_vec(),
                computed: hashes.md5.to_vec(),
                matches: expected == hashes.md5,
            });
        }
        if let Some(value) = &entry.sha1 {
            let expected = crate::types::parse_hex_array::<20>(value).expect("validated digest");
            comparisons.push(HashComparison {
                algorithm: HashAlgorithm::Sha1,
                reference: HashReference::Stored,
                expected: expected.to_vec(),
                computed: hashes.sha1.to_vec(),
                matches: expected == hashes.sha1,
            });
        }
        Ok(SingleFileVerification {
            hashes,
            comparisons,
            bytes_verified: offset,
        })
    }
}

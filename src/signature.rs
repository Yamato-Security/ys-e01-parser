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

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::format::{ewf1, ewf2};
use crate::image::Image;
use crate::{EwfError, OpenOptions, OpenStrictness, Result};

/// The corruption probes report any structural defect, so they open strictly
/// even though lenient opening is the default.
fn strict_options() -> OpenOptions {
    OpenOptions::default().with_strictness(OpenStrictness::Strict)
}

/// Returns whether a file starts with a recognized EWF segment signature.
///
/// Short files and files with unknown signatures return `false`.
///
/// # Errors
///
/// Returns an error if the file cannot be opened or read.
pub fn check_file_signature(path: impl AsRef<Path>) -> Result<bool> {
    let mut file = File::open(path)?;
    let Some(signature) = read_signature(&mut file)? else {
        return Ok(false);
    };

    Ok(matches!(
        signature,
        ewf1::EVF_SIGNATURE | ewf1::LVF_SIGNATURE | ewf2::EX01_SIGNATURE | ewf2::LEF2_SIGNATURE
    ))
}

/// Returns whether a file appears to be an encrypted EWF segment.
///
/// Plain EWF1 files, short files, and files with unknown signatures return
/// `false`.
///
/// # Errors
///
/// Returns an error if the file cannot be read or if a recognized EWF
/// descriptor chain is malformed while probing for encryption.
pub fn check_file_encryption(path: impl AsRef<Path>) -> Result<bool> {
    let mut file = File::open(path)?;
    let Some(signature) = read_signature(&mut file)? else {
        return Ok(false);
    };

    if matches!(signature, ewf1::EVF_SIGNATURE | ewf1::LVF_SIGNATURE) {
        return ewf1::probe_xways_encryption(&mut file);
    }
    if !matches!(signature, ewf2::EX01_SIGNATURE | ewf2::LEF2_SIGNATURE) {
        return Ok(false);
    }

    check_ewf2_encryption(&mut file)
}

/// Returns whether any segment in a segment set appears to be encrypted.
///
/// Empty segment lists return [`EwfError::NoSegments`]. Segments with unknown
/// signatures are treated as not encrypted.
///
/// # Errors
///
/// Returns an error if a segment cannot be read or if an EWF2 descriptor chain
/// is malformed while probing for encryption.
pub fn check_segment_files_encryption<P, I>(paths: I) -> Result<bool>
where
    P: AsRef<Path>,
    I: IntoIterator<Item = P>,
{
    let paths = segment_path_list(paths)?;
    for path in paths {
        if check_file_encryption(path)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Returns whether a single segment appears corrupt based on structural checks.
///
/// The checks are those of strict opening, so damage that lenient opening goes
/// past still counts as corruption. Files without a recognized EWF signature
/// return `false`. Unsupported but
/// well-formed EWF features also return `false`; this helper is a corruption
/// probe, not a full compatibility probe.
///
/// # Errors
///
/// Returns an error if the file cannot be read or if opening fails for a reason
/// other than a recognized corruption-style malformed-image error.
pub fn check_file_corruption(path: impl AsRef<Path>) -> Result<bool> {
    let path = path.as_ref();
    if !check_file_signature(path)? {
        return Ok(false);
    }

    match Image::open_with_options(path, strict_options()) {
        Err(EwfError::Malformed(message)) => Ok(malformed_error_is_corruption(&message)),
        Ok(_) | Err(EwfError::Unsupported(_) | EwfError::PasswordRequired) => Ok(false),
        Err(err) => Err(err),
    }
}

/// Returns whether a segment set appears corrupt based on structural checks.
///
/// The checks are those of strict opening, as for [`check_file_corruption`].
/// Segment sets with no recognized EWF signatures return `false`.
///
/// # Errors
///
/// Returns [`EwfError::NoSegments`] for an empty segment list, or another error
/// if probing/opening fails for a reason other than a recognized
/// corruption-style malformed-image error.
pub fn check_segment_files_corruption<P, I>(paths: I) -> Result<bool>
where
    P: AsRef<Path>,
    I: IntoIterator<Item = P>,
{
    let paths = segment_path_list(paths)?;
    let mut has_signature = false;
    for path in &paths {
        has_signature |= check_file_signature(path)?;
    }
    if !has_signature {
        return Ok(false);
    }

    match Image::open_segments_with_options(paths, strict_options()) {
        Err(EwfError::Malformed(message)) => Ok(malformed_error_is_corruption(&message)),
        Ok(_) | Err(EwfError::Unsupported(_) | EwfError::PasswordRequired) => Ok(false),
        Err(err) => Err(err),
    }
}

fn segment_path_list<P, I>(paths: I) -> Result<Vec<PathBuf>>
where
    P: AsRef<Path>,
    I: IntoIterator<Item = P>,
{
    let paths: Vec<_> = paths
        .into_iter()
        .map(|path| path.as_ref().to_path_buf())
        .collect();
    if paths.is_empty() {
        return Err(EwfError::NoSegments("empty segment list".into()));
    }
    Ok(paths)
}

fn read_signature(file: &mut File) -> Result<Option<[u8; 8]>> {
    let mut signature = [0; 8];
    let mut read = 0;
    while read < signature.len() {
        let n = file.read(&mut signature[read..])?;
        if n == 0 {
            return Ok(None);
        }
        read += n;
    }
    Ok(Some(signature))
}

fn malformed_error_is_corruption(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("checksum")
        || message.contains("integrity hash")
        || message.contains("corrupt")
}

fn check_ewf2_encryption(file: &mut File) -> Result<bool> {
    let file_len = file.metadata()?.len();
    if file_len < ewf2::FILE_HEADER_SIZE as u64 + ewf2::SECTION_DESCRIPTOR_SIZE as u64 {
        return Ok(false);
    }

    if let Some(encrypted) = check_ewf2_leading_encryption(file, file_len)? {
        return Ok(encrypted);
    }
    check_ewf2_trailing_encryption(file, file_len)
}

fn check_ewf2_leading_encryption(file: &mut File, file_len: u64) -> Result<Option<bool>> {
    let mut offset = ewf2::FILE_HEADER_SIZE as u64;
    let max_sections = ((file_len - ewf2::FILE_HEADER_SIZE as u64)
        / ewf2::SECTION_DESCRIPTOR_SIZE as u64)
        .saturating_add(1);

    for index in 0..max_sections {
        if offset
            .checked_add(ewf2::SECTION_DESCRIPTOR_SIZE as u64)
            .is_none_or(|end| end > file_len)
        {
            return if index == 0 {
                Ok(None)
            } else {
                Err(EwfError::Malformed(
                    "EWF2 leading section descriptor exceeds file".into(),
                ))
            };
        }

        let desc = match read_ewf2_descriptor(file, offset) {
            Ok(desc) if is_probe_ewf2_descriptor(desc) => desc,
            _ if index == 0 => return Ok(None),
            _ => {
                return Err(EwfError::Malformed(
                    "EWF2 leading section descriptor is invalid".into(),
                ));
            }
        };

        if ewf2_descriptor_is_encrypted(desc) {
            return Ok(Some(true));
        }
        if is_terminal_ewf2_section(desc.section_type) {
            return Ok(Some(false));
        }

        let data_offset = offset
            .checked_add(u64::from(desc.descriptor_size))
            .ok_or_else(|| EwfError::Malformed("EWF2 section data offset overflow".into()))?;
        let next_offset = data_offset
            .checked_add(desc.data_size)
            .ok_or_else(|| EwfError::Malformed("EWF2 section advance overflow".into()))?;
        let next_offset = next_offset
            .checked_add(ewf2_section_padding_size(desc)?)
            .ok_or_else(|| EwfError::Malformed("EWF2 section padding overflow".into()))?;
        if next_offset > file_len {
            return Err(EwfError::Malformed(
                "EWF2 section padding exceeds file".into(),
            ));
        }
        if next_offset <= offset {
            return Err(EwfError::Malformed(
                "EWF2 leading section chain does not advance".into(),
            ));
        }
        offset = next_offset;
    }

    Err(EwfError::Malformed(
        "EWF2 leading section descriptor chain is too long".into(),
    ))
}

fn check_ewf2_trailing_encryption(file: &mut File, file_len: u64) -> Result<bool> {
    let header_size = ewf2::FILE_HEADER_SIZE as u64;
    let descriptor_size = ewf2::SECTION_DESCRIPTOR_SIZE as u64;
    let mut offset = file_len
        .checked_sub(descriptor_size)
        .ok_or_else(|| EwfError::Malformed("EWF2 file is too short".into()))?;
    let max_sections = ((file_len - header_size) / descriptor_size).saturating_add(1);

    for _ in 0..max_sections {
        let desc = read_ewf2_descriptor(file, offset)?;
        if !is_probe_ewf2_descriptor(desc) {
            return Err(EwfError::Malformed(
                "EWF2 trailing section descriptor is invalid".into(),
            ));
        }
        if ewf2_descriptor_is_encrypted(desc) {
            return Ok(true);
        }
        if desc.previous_offset == 0 {
            return Ok(false);
        }
        if desc.previous_offset >= desc.offset {
            return Err(EwfError::Malformed(
                "EWF2 previous section offset is not before current section".into(),
            ));
        }
        offset = desc.previous_offset;
    }

    Err(EwfError::Malformed(
        "EWF2 trailing section descriptor chain is too long".into(),
    ))
}

fn read_ewf2_descriptor(file: &mut File, offset: u64) -> Result<ewf2::SectionDescriptor> {
    let mut buf = [0; ewf2::SECTION_DESCRIPTOR_SIZE];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut buf)?;
    ewf2::SectionDescriptor::parse(&buf, offset)
}

fn is_probe_ewf2_descriptor(desc: ewf2::SectionDescriptor) -> bool {
    desc.descriptor_size == ewf2::SECTION_DESCRIPTOR_SIZE as u32
}

fn ewf2_section_padding_size(desc: ewf2::SectionDescriptor) -> Result<u64> {
    let padding_size = u64::from(desc.padding_size);
    if padding_size > desc.data_size {
        return Err(EwfError::Malformed(
            "EWF2 section padding size exceeds data size".into(),
        ));
    }
    Ok(padding_size)
}

fn ewf2_descriptor_is_encrypted(desc: ewf2::SectionDescriptor) -> bool {
    desc.encrypted || desc.section_type == ewf2::SectionType::EncryptionKeys
}

fn is_terminal_ewf2_section(section_type: ewf2::SectionType) -> bool {
    matches!(
        section_type,
        ewf2::SectionType::Done | ewf2::SectionType::Next
    )
}

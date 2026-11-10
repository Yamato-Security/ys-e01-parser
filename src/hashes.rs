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

//! Validation shared by stored digest readers and writers.

use crate::types::{StoredHashes, parse_hex_array};
use crate::{EwfError, Result};

pub(crate) fn canonical_identifier(identifier: &str) -> Option<&'static str> {
    ["MD5", "SHA1", "SHA256"]
        .into_iter()
        .find(|candidate| identifier.eq_ignore_ascii_case(candidate))
}

pub(crate) fn validate_digest(identifier: &str, value: &str) -> Result<()> {
    let valid = match canonical_identifier(identifier) {
        Some("MD5") => parse_hex_array::<16>(value).is_some(),
        Some("SHA1") => parse_hex_array::<20>(value).is_some(),
        Some("SHA256") => parse_hex_array::<32>(value).is_some(),
        _ => true,
    };
    if !valid {
        return Err(EwfError::Malformed(format!(
            "invalid {identifier} digest: expected hexadecimal of the required length"
        )));
    }
    Ok(())
}

pub(crate) fn insert_stored_hash(
    hashes: &mut StoredHashes,
    identifier: &str,
    value: &str,
) -> Result<()> {
    let Some(identifier) = canonical_identifier(identifier) else {
        hashes
            .hash_values
            .entry(identifier.into())
            .or_insert_with(|| value.into());
        return Ok(());
    };
    validate_digest(identifier, value)?;
    if hashes
        .hash_values
        .get(identifier)
        .is_some_and(|old| !old.eq_ignore_ascii_case(value))
    {
        return Err(EwfError::Malformed(format!(
            "conflicting stored {identifier} digests"
        )));
    }
    match identifier {
        "MD5" => merge_typed(&mut hashes.md5, parse_hex_array(value), identifier)?,
        "SHA1" => merge_typed(&mut hashes.sha1, parse_hex_array(value), identifier)?,
        _ => {}
    }
    hashes
        .hash_values
        .entry(identifier.into())
        .or_insert_with(|| value.into());
    Ok(())
}

fn merge_typed<const N: usize>(
    target: &mut Option<[u8; N]>,
    source: Option<[u8; N]>,
    identifier: &str,
) -> Result<()> {
    if target.is_some() && *target != source {
        return Err(EwfError::Malformed(format!(
            "conflicting stored {identifier} digests"
        )));
    }
    *target = source;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::parse_xhash_data;

    #[test]
    fn supported_xhashes_reject_invalid_empty_and_conflicting_values() {
        for value in ["", "abc", &"g".repeat(64)] {
            let xml = format!("<xhash><SHA256>{value}</SHA256></xhash>");
            assert!(parse_xhash_data(xml.as_bytes(), &mut StoredHashes::default()).is_err());
        }
        let xml = format!(
            "<xhash><Sha256>{}</Sha256><sHa256>{}</sHa256></xhash>",
            "a".repeat(64),
            "b".repeat(64)
        );
        assert!(parse_xhash_data(xml.as_bytes(), &mut StoredHashes::default()).is_err());
    }

    #[test]
    fn equivalent_references_are_accepted_and_binary_conflicts_rejected() {
        let mut hashes = StoredHashes {
            md5: Some([0xaa; 16]),
            ..StoredHashes::default()
        };
        insert_stored_hash(&mut hashes, "mD5", &"AA".repeat(16)).unwrap();
        insert_stored_hash(&mut hashes, "MD5", &"aa".repeat(16)).unwrap();
        assert!(insert_stored_hash(&mut hashes, "MD5", &"bb".repeat(16)).is_err());
        assert_eq!(hashes.md5, Some([0xaa; 16]));
        let mut typed_only = StoredHashes {
            sha1: Some([0xaa; 20]),
            ..StoredHashes::default()
        };
        assert!(insert_stored_hash(&mut typed_only, "SHA1", &"bb".repeat(20)).is_err());
    }
}

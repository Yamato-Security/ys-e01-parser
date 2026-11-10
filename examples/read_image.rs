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

//! Prints basic metadata and the first sector from an EWF image.

use std::env;
use std::io::{Error, ErrorKind};

fn main() -> ewf_image::Result<()> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "read_image".to_string());
    let Some(image_path) = args.next() else {
        return Err(
            Error::new(ErrorKind::InvalidInput, format!("usage: {program} <image>")).into(),
        );
    };

    let image = ewf_image::Image::open(&image_path)?;
    let info = image.info();

    println!("file: {}", image.filename().display());
    println!("format: {:?}", info.format);
    println!("profile: {:?}", info.format_profile);
    println!("logical size: {}", info.logical_size);
    println!("chunk size: {}", info.chunk_size);
    println!("segments: {}", info.segment_count);
    println!("acquisition complete: {}", info.acquisition_complete);

    if let Some(case_number) = image.header_value("case_number") {
        println!("case number: {case_number}");
    }
    if let Some(evidence_number) = image.header_value("evidence_number") {
        println!("evidence number: {evidence_number}");
    }
    if let Some(examiner) = image.header_value("examiner_name") {
        println!("examiner: {examiner}");
    }

    for index in 0..image.number_of_hash_values() {
        if let Some(identifier) = image.hash_value_identifier(index)
            && let Some(value) = image.hash_value(identifier)
        {
            println!("hash {identifier}: {value}");
        }
    }

    #[cfg(feature = "verify")]
    {
        let verification = image.verify()?;
        println!("MD5 match: {:?}", verification.md5_match);
        println!("SHA1 match: {:?}", verification.sha1_match);
    }

    Ok(())
}

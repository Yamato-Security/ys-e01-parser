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

//! Exports the logical media stream from an EWF image to a raw file.

use std::env;
use std::fs::File;
use std::io::{self, Error, ErrorKind};

fn main() -> ewf_image::Result<()> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "export_raw".to_string());
    let (Some(image_path), Some(raw_path)) = (args.next(), args.next()) else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("usage: {program} <image> <output.raw>"),
        )
        .into());
    };

    let image = ewf_image::Image::open(&image_path)?;
    let mut cursor = image.cursor();
    let mut output = File::create(&raw_path)?;
    let bytes = io::copy(&mut cursor, &mut output)?;

    println!("wrote {bytes} bytes to {raw_path}");
    Ok(())
}

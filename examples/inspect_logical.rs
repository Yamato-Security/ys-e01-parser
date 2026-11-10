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

//! Prints the logical single-file catalog from an EWF image.

use std::env;
use std::io::{Error, ErrorKind};

fn main() -> ewf_image::Result<()> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "inspect_logical".to_string());
    let Some(image_path) = args.next() else {
        return Err(
            Error::new(ErrorKind::InvalidInput, format!("usage: {program} <image>")).into(),
        );
    };

    let image = ewf_image::Image::open(&image_path)?;
    let Some(root) = image.root_file_entry() else {
        println!("no logical single-file catalog");
        return Ok(());
    };

    print_entry(root, 0);
    Ok(())
}

fn print_entry(entry: &ewf_image::SingleFileEntry, depth: usize) {
    let indent = "  ".repeat(depth);
    let name = entry.name().unwrap_or("<root>");
    let size = entry.size().unwrap_or(0);
    let entry_type = entry.entry_type();

    println!("{indent}{name} {entry_type:?} {size} bytes");

    for child in &entry.children {
        print_entry(child, depth + 1);
    }
}

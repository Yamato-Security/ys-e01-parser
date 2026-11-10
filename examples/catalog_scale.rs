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

//! Measure sequential logical writing with a synthetic large catalog.
use ewf_image::{Image, LogicalEntryMetadata, LogicalWriter, SequentialOptions, WriteFormat};
use std::io::{Cursor, Read};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .ok_or("usage: catalog_scale OUTPUT FILE_COUNT")?;
    let count: u32 = args.next().ok_or("missing file count")?.parse()?;
    if count == 0 || count > 100_000 {
        return Err("file count must be 1 through 100000".into());
    }
    let mut settings = SequentialOptions::new(u64::from(count) * 1024);
    settings.write.format = WriteFormat::Ewf2Logical;
    settings.chunks_per_segment = 128;
    let mut writer = LogicalWriter::create_sequential(&path, settings)?;
    let data: Vec<u8> = (0..1024).map(|n| (n % 251) as u8).collect();
    for index in 0..count {
        writer.add_file(
            1,
            LogicalEntryMetadata {
                name: format!("file-{index:06}"),
                ..Default::default()
            },
            1024,
            &mut Cursor::new(&data),
        )?;
    }
    writer.finish()?;
    let image = Image::open(path)?;
    let root = image.root_file_entry().ok_or("missing catalog")?;
    if root.children.len() != count as usize {
        return Err("catalog count mismatch".into());
    }
    for entry in &root.children {
        let mut decoded = Vec::new();
        image.single_file_cursor(entry).read_to_end(&mut decoded)?;
        if decoded != data {
            return Err("logical file mismatch".into());
        }
    }
    println!("{count} files reopened and compared byte-for-byte");
    Ok(())
}

// Copyright (C) 2026 Shirofune Security Co., Ltd.
//
// SPDX-License-Identifier: RPL-1.5 OR AGPL-3.0-only
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

//! The EWF1 volume section says whether the chunks are compressed, as `EnCase` writes it.
#![cfg(feature = "writer")]
use ewf_image::{EwfWriter, WriteCompression, WriteCompressionLevel, WriteFormat, WriteOptions};
use std::path::Path;

/// The compression level byte of the first segment's `volume` section.
fn volume_compression_level(path: &Path) -> u8 {
    let data = std::fs::read(path).unwrap();
    let mut offset = 13;
    loop {
        let kind = &data[offset..offset + 16];
        if kind.starts_with(b"volume\0") || kind.starts_with(b"disk\0") {
            return data[offset + 76 + 52];
        }
        let next = usize::try_from(u64::from_le_bytes(
            data[offset + 16..offset + 24].try_into().unwrap(),
        ))
        .unwrap();
        assert!(next > offset, "no volume section");
        offset = next;
    }
}

#[test]
fn volume_section_records_the_compression_level_like_encase() {
    for (compression, level, expected) in [
        (WriteCompression::None, WriteCompressionLevel::Default, 0),
        (WriteCompression::None, WriteCompressionLevel::Best, 0),
        (WriteCompression::Zlib, WriteCompressionLevel::None, 0),
        (WriteCompression::Zlib, WriteCompressionLevel::Default, 1),
        (WriteCompression::Zlib, WriteCompressionLevel::Fast, 1),
        (WriteCompression::Zlib, WriteCompressionLevel::Best, 2),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("level.E01");
        let mut options = WriteOptions {
            format: WriteFormat::Ewf1Physical,
            compression,
            ..WriteOptions::default()
        };
        options.compression_values.level = level;
        let mut writer = EwfWriter::create(&path, options).unwrap();
        writer.write_all(&[7u8; 4096]).unwrap();
        writer.finish().unwrap();
        assert_eq!(
            volume_compression_level(&path),
            expected,
            "{compression:?} {level:?}"
        );
    }
}

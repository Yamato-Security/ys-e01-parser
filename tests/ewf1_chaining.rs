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

//! Intermediate EWF1 files must continue with `next`, not terminate with `done`.
#![cfg(feature = "writer")]
use ewf_image::{
    EwfWriter, Image, SequentialOptions, SequentialWriter, WriteCompression, WriteFormat,
    WriteOptions,
};
use std::io::Read;

#[test]
fn physical_segments_continue_until_the_last_file() {
    for streaming in [false, true] {
        for compression in [WriteCompression::None, WriteCompression::Zlib] {
            let dir = tempfile::tempdir().unwrap();
            let first = dir.path().join("test.E01");
            let source: Vec<u8> = (0..16_384)
                .map(|i| ((i * 71 + i / 257) % 251) as u8)
                .collect();
            let options = WriteOptions {
                format: WriteFormat::Ewf1Physical,
                compression,
                sectors_per_chunk: 1,
                maximum_segment_size: Some(4096),
                ..WriteOptions::default()
            };
            let result = if streaming {
                let mut settings = SequentialOptions::new(source.len() as u64);
                settings.write = options;
                settings.chunks_per_segment = 3;
                let mut writer = SequentialWriter::create(&first, settings).unwrap();
                writer.write_all(&source).unwrap();
                writer.finish().unwrap()
            } else {
                let mut writer = EwfWriter::create(&first, options).unwrap();
                writer.write_all(&source).unwrap();
                writer.finish().unwrap()
            };
            assert!(result.segment_paths.len() > 1);
            for (i, path) in result.segment_paths.iter().enumerate() {
                let data = std::fs::read(path).unwrap();
                let terminal = &data[data.len() - 76..data.len() - 72];
                assert_eq!(
                    terminal,
                    if i + 1 == result.segment_paths.len() {
                        b"done"
                    } else {
                        b"next"
                    },
                    "streaming={streaming}, segment={i}"
                );
            }
            let image = Image::open(&first).unwrap();
            let mut decoded = Vec::new();
            image.cursor().read_to_end(&mut decoded).unwrap();
            assert_eq!(decoded, source);
            if let Some(tool) = std::env::var_os("EWF_VERIFY_TOOL") {
                let output = std::process::Command::new(tool)
                    .arg("-q")
                    .arg(&first)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }
}

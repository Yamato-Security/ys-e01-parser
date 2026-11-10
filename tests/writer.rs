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

//! Writer integration tests.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Read, Seek, SeekFrom, Write as IoWrite};

use flate2::read::ZlibDecoder;
use tempfile::tempdir;

use ewf_image::{
    AcquisitionError, CompressionMethod, DataChunk, DataChunkEncoding, EwfMetadata, EwfWriter,
    Format, HeaderCodepage, HeaderDateFormat, MediaFlags, MediaType, MemoryExtent, SectorRange,
    SegmentFileVersion, SingleFileAttribute, SingleFileEntry, SingleFileEntryType,
    SingleFileExtent, SingleFilePermission, SingleFilePermissionGroup, SingleFileSource,
    SingleFileSubject, SingleFilesAuxTables, SingleFilesInfo, WriteCompression,
    WriteCompressionLevel, WriteCompressionValues, WriteFormat, WriteHashes, WriteMediaProfile,
    WriteOptions,
};
use md5::{Digest, Md5};
use sha1::Sha1;

#[test]
fn ewf2_logical_writer_rejects_sub_8k_chunks_before_output() {
    use ewf_image::{LogicalWriter, SequentialOptions};

    let dir = tempdir().unwrap();
    let path = dir.path().join("small.Lx01");
    let mut options = SequentialOptions::new(4096);
    options.write.format = WriteFormat::Ewf2Logical;
    options.write.sectors_per_chunk = 8;
    assert!(LogicalWriter::create_sequential(&path, options).is_err());
    assert!(!path.exists());

    let path = dir.path().join("config.Lx01");
    let mut writer = EwfWriter::create(
        &path,
        WriteOptions {
            format: WriteFormat::Ewf2Logical,
            ..WriteOptions::default()
        },
    )
    .unwrap();
    assert!(writer.set_sectors_per_chunk(8).is_err());
    assert_eq!(writer.sectors_per_chunk(), 64);
    assert!(writer.set_bytes_per_sector(64).is_err());
    assert_eq!(writer.bytes_per_sector(), 512);
    assert!(!path.exists());
}

#[test]
fn logical_builder_assigns_offsets_hashes_and_preserves_metadata() {
    use ewf_image::{LogicalEntryMetadata, LogicalWriter};
    for (name, format) in [
        ("case.L01", WriteFormat::Ewf1Logical),
        ("case.Lx01", WriteFormat::Ewf2Logical),
    ] {
        let dir = tempdir().unwrap();
        let path = dir.path().join(name);
        let mut writer = LogicalWriter::create(
            &path,
            WriteOptions {
                format,
                compression: WriteCompression::Zlib,
                maximum_segment_size: Some(65536),
                ..WriteOptions::default()
            },
        )
        .unwrap();
        assert!(
            writer
                .add_directory(
                    1,
                    LogicalEntryMetadata {
                        name: "bad\nname".into(),
                        ..LogicalEntryMetadata::default()
                    }
                )
                .is_err()
        );
        let folder = writer
            .add_directory(
                1,
                LogicalEntryMetadata {
                    name: "Evidence".into(),
                    ..LogicalEntryMetadata::default()
                },
            )
            .unwrap();
        for (name, bytes) in [
            ("first", b"abc".as_slice()),
            ("empty", b"".as_slice()),
            ("last", b"defgh".as_slice()),
        ] {
            writer
                .add_file(
                    folder,
                    LogicalEntryMetadata {
                        name: name.into(),
                        modification_time: Some(1_700_000_000),
                        ..LogicalEntryMetadata::default()
                    },
                    bytes.len() as u64,
                    &mut Cursor::new(bytes),
                )
                .unwrap();
        }
        let result = writer.finish().unwrap();
        let image = ewf_image::Image::open(&result.segment_paths[0]).unwrap();
        for (name, bytes) in [
            ("first", b"abc".as_slice()),
            ("empty", b"".as_slice()),
            ("last", b"defgh".as_slice()),
        ] {
            let entry = image
                .file_entry_by_path(&format!("Evidence\t{name}"))
                .unwrap()
                .unwrap();
            assert_eq!(entry.modification_time, Some(1_700_000_000));
            let mut read = Vec::new();
            image
                .single_file_cursor(entry)
                .read_to_end(&mut read)
                .unwrap();
            assert_eq!(read, bytes);
            assert_eq!(
                entry.md5.as_deref(),
                Some(hex_string(&Md5::digest(bytes)).as_str())
            );
            #[cfg(feature = "verify")]
            assert_eq!(
                image.verify_single_file(entry).unwrap().references_match(),
                Some(true)
            );
        }
    }
}

#[test]
fn logical_builder_failed_input_or_cancel_cannot_publish() {
    use ewf_image::{LogicalEntryMetadata, LogicalWriter};
    use std::ops::ControlFlow;
    for cancel in [false, true] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("case.L01");
        let mut writer = LogicalWriter::create(
            &path,
            WriteOptions {
                format: WriteFormat::Ewf1Logical,
                ..WriteOptions::default()
            },
        )
        .unwrap();
        assert!(
            writer
                .add_file_with_progress(
                    1,
                    LogicalEntryMetadata {
                        name: "short".into(),
                        ..LogicalEntryMetadata::default()
                    },
                    10,
                    &mut Cursor::new(b"abc"),
                    |_| if cancel {
                        ControlFlow::Break(())
                    } else {
                        ControlFlow::Continue(())
                    }
                )
                .is_err()
        );
        assert!(writer.finish().is_err());
        assert!(!path.exists());
    }
}

fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65_521;
    let mut a = 1_u32;
    let mut b = 0_u32;
    for byte in data {
        a = (a + u32::from(*byte)) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    (b << 16) | a
}

fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[(byte >> 4) as usize]));
        out.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    out
}

fn ewf1_section_data<'a>(bytes: &'a [u8], section_type: &[u8]) -> &'a [u8] {
    let mut offset = 13;
    loop {
        let desc = bytes
            .get(offset..offset + 76)
            .expect("EWF1 section descriptor exists");
        let current_type = desc[..16]
            .split(|byte| *byte == 0)
            .next()
            .expect("section type prefix exists");
        let next = u64::from_le_bytes(desc[16..24].try_into().unwrap()) as usize;
        let section_size = u64::from_le_bytes(desc[24..32].try_into().unwrap()) as usize;
        let data_offset = offset + 76;
        let data_end = offset + section_size;

        if current_type == section_type {
            return &bytes[data_offset..data_end];
        }
        assert!(
            !(next == 0 || current_type == b"done"),
            "EWF1 section {} not found",
            String::from_utf8_lossy(section_type)
        );

        offset = next;
    }
}

fn ewf1_section_types(bytes: &[u8]) -> Vec<String> {
    let mut offset = 13;
    let mut section_types = Vec::new();
    loop {
        let desc = bytes
            .get(offset..offset + 76)
            .expect("EWF1 section descriptor exists");
        let current_type = desc[..16]
            .split(|byte| *byte == 0)
            .next()
            .expect("section type prefix exists");
        let next = u64::from_le_bytes(desc[16..24].try_into().unwrap()) as usize;

        section_types.push(String::from_utf8_lossy(current_type).into_owned());

        if next == 0 || matches!(current_type, b"done" | b"next") {
            return section_types;
        }
        offset = next;
    }
}

#[derive(Debug, Clone, Copy)]
struct Ewf2TestSection {
    section_type: u32,
    data_offset: usize,
    data_size: usize,
    desc_offset: usize,
}

fn ewf2_test_sections(bytes: &[u8]) -> Vec<Ewf2TestSection> {
    ewf2_leading_test_sections(bytes).unwrap_or_else(|| ewf2_trailing_test_sections(bytes))
}

fn ewf2_leading_test_sections(bytes: &[u8]) -> Option<Vec<Ewf2TestSection>> {
    let mut offset = 32;
    let mut sections = Vec::new();

    loop {
        let desc = bytes.get(offset..offset + 64)?;
        if u32::from_le_bytes(desc[60..64].try_into().unwrap()) != adler32(&desc[..60]) {
            return None;
        }
        let section_type = u32::from_le_bytes(desc[0..4].try_into().unwrap());
        let data_size = u64::from_le_bytes(desc[16..24].try_into().unwrap()) as usize;
        let descriptor_size = u32::from_le_bytes(desc[24..28].try_into().unwrap()) as usize;
        let padding_size = u32::from_le_bytes(desc[28..32].try_into().unwrap()) as usize;
        if descriptor_size != 64 {
            return None;
        }
        let data_offset = offset.checked_add(descriptor_size)?;
        let data_end = data_offset.checked_add(data_size)?;
        bytes.get(data_offset..data_end)?;
        sections.push(Ewf2TestSection {
            section_type,
            data_offset,
            data_size,
            desc_offset: offset,
        });
        if matches!(section_type, 0x0d | 0x0f) {
            return Some(sections);
        }

        offset = data_end.checked_add(padding_size)?;
    }
}

fn ewf2_trailing_test_sections(bytes: &[u8]) -> Vec<Ewf2TestSection> {
    let mut offset = bytes
        .len()
        .checked_sub(64)
        .expect("EWF2 terminal descriptor exists");
    let mut sections = Vec::new();

    loop {
        let desc = bytes
            .get(offset..offset + 64)
            .expect("EWF2 trailing section descriptor exists");
        assert_eq!(
            u32::from_le_bytes(desc[60..64].try_into().unwrap()),
            adler32(&desc[..60])
        );
        let section_type = u32::from_le_bytes(desc[0..4].try_into().unwrap());
        let previous_offset = u64::from_le_bytes(desc[8..16].try_into().unwrap()) as usize;
        let data_size = u64::from_le_bytes(desc[16..24].try_into().unwrap()) as usize;
        let descriptor_size = u32::from_le_bytes(desc[24..28].try_into().unwrap()) as usize;
        assert_eq!(descriptor_size, 64);
        let data_offset = offset
            .checked_sub(data_size)
            .expect("EWF2 trailing data precedes descriptor");
        bytes
            .get(data_offset..offset)
            .expect("EWF2 trailing section data exists");
        sections.push(Ewf2TestSection {
            section_type,
            data_offset,
            data_size,
            desc_offset: offset,
        });
        if previous_offset == 0 {
            sections.reverse();
            return sections;
        }
        offset = previous_offset;
    }
}

fn ewf2_section_data(bytes: &[u8], section_type: u32) -> &[u8] {
    ewf2_test_sections(bytes)
        .into_iter()
        .find(|section| section.section_type == section_type)
        .map_or_else(
            || panic!("EWF2 section {section_type:#x} not found"),
            |section| &bytes[section.data_offset..section.data_offset + section.data_size],
        )
}

fn utf16le_string(data: &[u8]) -> String {
    assert_eq!(data.len() % 2, 0);
    let mut units = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u16::from_le_bytes(*chunk))
        .collect::<Vec<_>>();
    if units.first() == Some(&0xfeff) {
        units.remove(0);
    }
    String::from_utf16(&units).unwrap()
}

fn ewf2_sections_data(bytes: &[u8], section_type: u32) -> Vec<&[u8]> {
    ewf2_test_sections(bytes)
        .into_iter()
        .filter(|section| section.section_type == section_type)
        .map(|section| &bytes[section.data_offset..section.data_offset + section.data_size])
        .collect()
}

fn ewf2_trailing_section_types(bytes: &[u8]) -> Vec<u32> {
    let mut offset = bytes
        .len()
        .checked_sub(64)
        .expect("EWF2 terminal descriptor exists");
    let mut section_types = Vec::new();

    loop {
        let desc = bytes
            .get(offset..offset + 64)
            .expect("EWF2 trailing section descriptor exists");
        section_types.push(u32::from_le_bytes(desc[0..4].try_into().unwrap()));
        let previous_offset = u64::from_le_bytes(desc[8..16].try_into().unwrap()) as usize;
        if previous_offset == 0 {
            section_types.reverse();
            return section_types;
        }
        offset = previous_offset;
    }
}

fn ewf2_has_section(bytes: &[u8], section_type: u32) -> bool {
    ewf2_test_sections(bytes)
        .iter()
        .any(|section| section.section_type == section_type)
}

fn ewf2_u64_aux_table_entries(table: &[u8]) -> Vec<u64> {
    let entry_count = u32::from_le_bytes(table[0..4].try_into().unwrap()) as usize;
    assert_eq!(
        u32::from_le_bytes(table[16..20].try_into().unwrap()),
        adler32(&table[..16])
    );
    let entries_offset = 32;
    let entries_end = entries_offset + entry_count * 8;
    assert_eq!(
        u32::from_le_bytes(table[entries_end..entries_end + 4].try_into().unwrap()),
        adler32(&table[entries_offset..entries_end])
    );
    table[entries_offset..entries_end]
        .as_chunks::<8>()
        .0
        .iter()
        .map(|entry| u64::from_le_bytes(*entry))
        .collect()
}

fn ewf2_md5_aux_table_hashes(table: &[u8]) -> Vec<[u8; 16]> {
    let entry_count = u32::from_le_bytes(table[0..4].try_into().unwrap()) as usize;
    assert_eq!(
        u32::from_le_bytes(table[16..20].try_into().unwrap()),
        adler32(&table[..16])
    );
    let entries_offset = 32;
    let entries_end = entries_offset + entry_count * 16;
    assert_eq!(
        u32::from_le_bytes(table[entries_end..entries_end + 4].try_into().unwrap()),
        adler32(&table[entries_offset..entries_end])
    );
    table[entries_offset..entries_end]
        .as_chunks::<16>()
        .0
        .to_vec()
}

fn assert_ewf1_descriptor_checksums(bytes: &[u8]) {
    let mut offset = 13;
    loop {
        let desc = bytes
            .get(offset..offset + 76)
            .expect("EWF1 section descriptor exists");
        assert_eq!(
            u32::from_le_bytes(desc[72..76].try_into().unwrap()),
            adler32(&desc[..72])
        );

        let current_type = desc[..16]
            .split(|byte| *byte == 0)
            .next()
            .expect("section type prefix exists");
        let next = u64::from_le_bytes(desc[16..24].try_into().unwrap()) as usize;
        if next == 0 || current_type == b"done" {
            break;
        }
        offset = next;
    }
}

fn assert_ewf2_descriptor_checksums(bytes: &[u8]) {
    for section in ewf2_test_sections(bytes) {
        let desc = bytes
            .get(section.desc_offset..section.desc_offset + 64)
            .expect("EWF2 section descriptor exists");
        assert_eq!(
            u32::from_le_bytes(desc[60..64].try_into().unwrap()),
            adler32(&desc[..60])
        );
    }
}

fn assert_ewf1_table_checksums(table: &[u8], entries_footer: bool) {
    assert!(table.len() >= 24);
    assert_eq!(
        u32::from_le_bytes(table[20..24].try_into().unwrap()),
        adler32(&table[..20])
    );

    let entry_count = u32::from_le_bytes(table[0..4].try_into().unwrap()) as usize;
    let entries_start = 24;
    let entries_end = entries_start + entry_count * 4;
    assert!(table.len() >= entries_end);
    if entries_footer {
        assert!(table.len() >= entries_end + 4);
        assert_eq!(
            u32::from_le_bytes(table[entries_end..entries_end + 4].try_into().unwrap()),
            adler32(&table[entries_start..entries_end])
        );
    }
}

fn assert_ewf2_table_checksums(table: &[u8]) {
    assert!(table.len() >= 32);
    assert_eq!(
        u32::from_le_bytes(table[16..20].try_into().unwrap()),
        adler32(&table[..16])
    );

    let entry_count = u32::from_le_bytes(table[8..12].try_into().unwrap()) as usize;
    let entries_start = 32;
    let entries_end = entries_start + entry_count * 16;
    assert!(table.len() >= entries_end + 16);
    assert_eq!(
        u32::from_le_bytes(table[entries_end..entries_end + 4].try_into().unwrap()),
        adler32(&table[entries_start..entries_end])
    );
}

fn assert_raw_chunk_checksum(encoded: &[u8], logical: &[u8]) {
    assert_eq!(encoded.len(), logical.len() + 4);
    assert_eq!(&encoded[..logical.len()], logical);
    assert_eq!(
        u32::from_le_bytes(
            encoded[logical.len()..logical.len() + 4]
                .try_into()
                .unwrap()
        ),
        adler32(logical)
    );
}

fn padded_hashes(data: &[u8], logical_size: usize) -> ([u8; 16], [u8; 20]) {
    let mut logical = data.to_vec();
    logical.resize(logical_size, 0);

    let mut md5 = Md5::new();
    md5.update(&logical);
    let md5: [u8; 16] = md5.finalize().into();

    let mut sha1 = Sha1::new();
    sha1.update(&logical);
    let sha1: [u8; 20] = sha1.finalize().into();

    (md5, sha1)
}

#[test]
fn writer_creates_readable_single_segment_e01() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("case.E01");
    let data = vec![0x5a; 4096];

    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();
    writer.write_all(&data).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.segment_paths, vec![path.clone()]);
    assert_eq!(result.logical_size, data.len() as u64);
    assert!(fs::metadata(&path).unwrap().len() > data.len() as u64);

    let image = ewf_image::Image::open(&path).unwrap();
    assert_eq!(image.info().format, Format::Ewf1);
    assert_eq!(
        image.info().format_profile,
        ewf_image::FormatProfile::EnCase2
    );
    assert_eq!(image.info().logical_size, data.len() as u64);
    assert_eq!(image.info().chunk_size, 32_768);
    assert_eq!(image.info().segment_paths, vec![path.clone()]);

    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);

    let bytes = fs::read(&path).unwrap();
    assert_ewf1_descriptor_checksums(&bytes);
    let volume = ewf1_section_data(&bytes, b"volume");
    assert_eq!(
        u32::from_le_bytes(volume[volume.len() - 4..].try_into().unwrap()),
        adler32(&volume[..volume.len() - 4])
    );
    assert_ewf1_table_checksums(ewf1_section_data(&bytes, b"table"), true);
    assert_ewf1_table_checksums(ewf1_section_data(&bytes, b"table2"), true);
    assert_raw_chunk_checksum(ewf1_section_data(&bytes, b"sectors"), &data);
}

#[test]
fn writer_finish_incomplete_writes_next_terminal_section() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("incomplete.E01");
    let data = vec![0x3c; 32_768];

    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();
    writer.write_all(&data).unwrap();
    let result = writer.finish_incomplete().unwrap();

    assert_eq!(result.segment_paths, vec![path.clone()]);
    assert_eq!(result.logical_size, data.len() as u64);

    let bytes = fs::read(&path).unwrap();
    let sections = ewf1_section_types(&bytes);
    assert_eq!(sections.last().map(String::as_str), Some("next"));
    assert!(!sections.iter().any(|section| section == "digest"));

    let image = ewf_image::Image::open(&path).unwrap();
    assert!(!image.info().acquisition_complete);
    let mut decoded = vec![0; data.len()];
    assert_eq!(image.read_at(&mut decoded, 0).unwrap(), data.len());
    assert_eq!(decoded, data);
}

#[test]
fn writer_resumes_incomplete_e01_and_finishes_readable_image() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("resume.E01");
    let first = vec![0x41; 32_768];
    let second = vec![0x42; 32_768];

    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();
    writer.write_all(&first).unwrap();
    writer.finish_incomplete().unwrap();

    let mut writer = EwfWriter::resume(&path).unwrap();
    assert_eq!(writer.position(), first.len() as u64);
    writer.write_all(&second).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.logical_size, (first.len() + second.len()) as u64);

    let image = ewf_image::Image::open(&path).unwrap();
    assert!(image.info().acquisition_complete);
    let mut decoded = vec![0; first.len() + second.len()];
    assert_eq!(image.read_at(&mut decoded, 0).unwrap(), decoded.len());
    assert_eq!(&decoded[..first.len()], first.as_slice());
    assert_eq!(&decoded[first.len()..], second.as_slice());
}

#[test]
fn writer_exposes_compatibility_style_write_finalize_alias() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("write-finalize.E01");
    let data = b"finalized through alias";

    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();
    writer.write_buffer(data).unwrap();
    let result = writer.write_finalize().unwrap();

    assert_eq!(result.segment_paths, vec![path.clone()]);
    assert_eq!(result.logical_size, 512);

    let image = ewf_image::Image::open(&path).unwrap();
    assert_eq!(image.info().logical_size, 512);
    let mut decoded = vec![0; data.len()];
    assert_eq!(image.read_at(&mut decoded, 0).unwrap(), data.len());
    assert_eq!(&decoded, data);
}

#[test]
fn writer_finishes_single_segment_e01_to_supplied_writer() {
    let path = std::path::PathBuf::from("streamed.E01");
    let data = vec![0x4d; 4096];
    let mut output = Vec::new();

    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();
    writer.write_all(&data).unwrap();
    let result = writer.finish_to_writer(&mut output).unwrap();

    assert_eq!(result.segment_paths, vec![path.clone()]);
    assert_eq!(result.logical_size, data.len() as u64);
    assert!(output.len() > data.len());

    let image = ewf_image::Image::open_readers([(path.clone(), Cursor::new(output))]).unwrap();
    assert_eq!(image.info().format, Format::Ewf1);
    assert_eq!(image.info().segment_paths, vec![path]);

    let mut decoded = vec![0; data.len()];
    assert_eq!(image.read_at(&mut decoded, 0).unwrap(), data.len());
    assert_eq!(decoded, data);
}

#[test]
fn writer_orders_ewf1_chunks_before_tables_for_common_readers() {
    let dir = tempdir().unwrap();
    let e01_path = dir.path().join("ordered.E01");
    let l01_path = dir.path().join("ordered.L01");
    let data = vec![0x5a; 4096];

    let mut e01_writer = EwfWriter::create(&e01_path, WriteOptions::default()).unwrap();
    e01_writer.write_all(&data).unwrap();
    e01_writer.finish().unwrap();

    let l01_options = WriteOptions {
        format: WriteFormat::Ewf1Logical,
        ..WriteOptions::default()
    };
    let mut l01_writer = EwfWriter::create(&l01_path, l01_options).unwrap();
    l01_writer.write_all(&data).unwrap();
    l01_writer.finish().unwrap();

    assert_eq!(
        ewf1_section_types(&fs::read(&e01_path).unwrap()),
        [
            "volume", "sectors", "table", "table2", "digest", "xhash", "done"
        ]
    );
    assert_eq!(
        ewf1_section_types(&fs::read(&l01_path).unwrap()),
        [
            "volume", "sectors", "table", "table2", "digest", "xhash", "done"
        ]
    );
}

#[test]
fn writer_implements_std_io_write_for_streaming_input() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("stdio-write.E01");
    let data = b"written through std::io::Write";

    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();
    IoWrite::write_all(&mut writer, &data[..9]).unwrap();
    IoWrite::write_all(&mut writer, &data[9..]).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);
}

#[test]
fn writer_reports_pending_media_and_chunk_state() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("pending-state.E01");
    let options = WriteOptions {
        sectors_per_chunk: 2,
        bytes_per_sector: 256,
        ..WriteOptions::default()
    };
    let mut writer = EwfWriter::create(&path, options).unwrap();

    assert_eq!(writer.chunk_size(), 512);
    assert_eq!(writer.logical_size().unwrap(), 0);
    assert_eq!(writer.media_size().unwrap(), 0);
    assert_eq!(writer.number_of_chunks_written().unwrap(), 0);

    writer.write_all(b"abc").unwrap();
    assert_eq!(writer.position(), 3);
    assert_eq!(writer.logical_size().unwrap(), 256);
    assert_eq!(writer.media_size().unwrap(), 256);
    assert_eq!(writer.number_of_chunks_written().unwrap(), 1);

    writer.write_at(b"tail", 512).unwrap();
    assert_eq!(writer.logical_size().unwrap(), 768);
    assert_eq!(writer.media_size().unwrap(), 768);
    assert_eq!(writer.number_of_chunks_written().unwrap(), 2);

    let result = writer.finish().unwrap();
    assert_eq!(result.logical_size, 768);
    assert_eq!(result.chunk_size, 512);
    assert_eq!(result.chunk_count, 2);
}

#[test]
fn writer_exposes_compatibility_style_media_configuration_setters() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("media-setters.Ex01");
    let mut writer = EwfWriter::create(
        &path,
        WriteOptions {
            format: WriteFormat::Ewf2Physical,
            ..WriteOptions::default()
        },
    )
    .unwrap();

    assert_eq!(writer.sectors_per_chunk(), 64);
    assert_eq!(writer.bytes_per_sector(), 512);
    assert_eq!(writer.segment_file_set_identifier(), None);
    assert_eq!(writer.compression_method(), WriteCompression::None);
    assert_eq!(
        writer.compression_values(),
        WriteCompressionValues::default()
    );
    assert_eq!(writer.media_type(), None);
    assert_eq!(writer.error_granularity(), None);
    assert_eq!(
        writer.media_flags(),
        MediaFlags {
            physical: true,
            fastbloc: false,
            tableau: false,
        }
    );

    writer.set_sectors_per_chunk(4).unwrap();
    writer.set_bytes_per_sector(256).unwrap();
    writer.set_segment_file_set_identifier([0x42; 16]).unwrap();
    writer
        .set_compression_method(WriteCompression::Zlib)
        .unwrap();
    writer
        .set_compression_values(WriteCompressionValues {
            level: WriteCompressionLevel::Best,
            empty_block: false,
        })
        .unwrap();
    writer.set_media_type(Some(MediaType::Fixed)).unwrap();
    writer.set_error_granularity(Some(2)).unwrap();
    writer
        .set_media_flags(MediaFlags {
            physical: true,
            fastbloc: true,
            tableau: true,
        })
        .unwrap();

    assert_eq!(writer.sectors_per_chunk(), 4);
    assert_eq!(writer.bytes_per_sector(), 256);
    assert_eq!(writer.chunk_size(), 1024);
    assert_eq!(writer.segment_file_set_identifier(), Some([0x42; 16]));
    assert_eq!(writer.compression_method(), WriteCompression::Zlib);
    assert_eq!(
        writer.compression_values(),
        WriteCompressionValues {
            level: WriteCompressionLevel::Best,
            empty_block: false,
        }
    );
    assert_eq!(writer.media_type(), Some(MediaType::Fixed));
    assert_eq!(writer.error_granularity(), Some(2));
    assert_eq!(
        writer.media_flags(),
        MediaFlags {
            physical: true,
            fastbloc: true,
            tableau: true,
        }
    );

    writer.write_all(&vec![0x5a; 1500]).unwrap();
    assert_eq!(writer.media_size().unwrap(), 1536);
    assert_eq!(writer.number_of_sectors().unwrap(), 6);
    assert_eq!(writer.number_of_chunks_written().unwrap(), 2);
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    assert_eq!(image.sectors_per_chunk(), Some(4));
    assert_eq!(image.bytes_per_sector(), Some(256));
    assert_eq!(image.number_of_sectors(), Some(6));
    assert_eq!(image.number_of_chunks(), Some(2));
    assert_eq!(image.segment_file_set_identifier(), Some([0x42; 16]));
    assert_eq!(image.compression_method(), Some(CompressionMethod::Zlib));
    assert_eq!(image.media_type(), Some(MediaType::Fixed));
    assert_eq!(image.error_granularity(), Some(2));
    assert_eq!(
        image.media_flags(),
        MediaFlags {
            physical: true,
            fastbloc: true,
            tableau: true,
        }
    );
}

#[test]
fn writer_rejects_layout_configuration_changes_after_writes_start() {
    fn assert_locked(err: ewf_image::EwfError) {
        assert!(
            matches!(err, ewf_image::EwfError::Unsupported(message) if message.contains("cannot be changed after media data has been written"))
        );
    }

    let dir = tempdir().unwrap();
    let mut writer_index = 0;
    let mut writer_after_data = || {
        writer_index += 1;
        let path = dir.path().join(format!("locked-config-{writer_index}.E01"));
        let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();
        writer.write_all(b"data").unwrap();
        writer
    };

    assert_locked(
        writer_after_data()
            .set_format(WriteFormat::Ewf2Physical)
            .unwrap_err(),
    );
    assert_locked(writer_after_data().set_sectors_per_chunk(8).unwrap_err());
    assert_locked(writer_after_data().set_bytes_per_sector(1024).unwrap_err());
    assert_locked(
        writer_after_data()
            .set_maximum_segment_size(Some(34_500))
            .unwrap_err(),
    );
    assert_locked(writer_after_data().set_media_size(2048).unwrap_err());
    assert_locked(
        writer_after_data()
            .set_compression_method(WriteCompression::Zlib)
            .unwrap_err(),
    );
    assert_locked(
        writer_after_data()
            .set_segment_file_set_identifier([0x42; 16])
            .unwrap_err(),
    );
    assert_locked(
        writer_after_data()
            .set_compression_values(WriteCompressionValues {
                level: WriteCompressionLevel::Best,
                empty_block: false,
            })
            .unwrap_err(),
    );
    assert_locked(
        writer_after_data()
            .set_media_type(Some(MediaType::Fixed))
            .unwrap_err(),
    );
    assert_locked(
        writer_after_data()
            .set_error_granularity(Some(2))
            .unwrap_err(),
    );
    assert_locked(
        writer_after_data()
            .set_media_flags(MediaFlags {
                physical: true,
                fastbloc: true,
                tableau: true,
            })
            .unwrap_err(),
    );
}

#[test]
fn writer_records_ewf1_compression_level_in_volume_data() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("compression-level.E01");
    let mut writer = EwfWriter::create(
        &path,
        WriteOptions {
            compression: WriteCompression::Zlib,
            compression_values: WriteCompressionValues {
                level: WriteCompressionLevel::Best,
                empty_block: true,
            },
            ..WriteOptions::default()
        },
    )
    .unwrap();

    writer.write_all(&vec![0x34; 4096]).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    assert_eq!(
        image.compression_values().level,
        ewf_image::CompressionLevel::Best
    );
}

#[test]
fn writer_copies_ewf1_compression_values_from_source_image() {
    let dir = tempdir().unwrap();
    let source_path = dir.path().join("source-compression.E01");
    let target_path = dir.path().join("target-compression.E01");
    let data = vec![0x35; 4096];
    let source_options = WriteOptions {
        compression: WriteCompression::Zlib,
        compression_values: WriteCompressionValues {
            level: WriteCompressionLevel::Best,
            empty_block: false,
        },
        ..WriteOptions::default()
    };

    let mut source_writer = EwfWriter::create(&source_path, source_options).unwrap();
    source_writer.write_all(&data).unwrap();
    source_writer.finish().unwrap();
    let source = ewf_image::Image::open(&source_path).unwrap();

    let mut copied_options = WriteOptions::default();
    copied_options
        .copy_media_values_from_info(source.info())
        .unwrap();

    assert_eq!(copied_options.compression, WriteCompression::Zlib);
    assert_eq!(
        copied_options.compression_values,
        WriteCompressionValues {
            level: WriteCompressionLevel::Best,
            empty_block: false,
        }
    );

    let mut target_writer = EwfWriter::create(&target_path, WriteOptions::default()).unwrap();
    target_writer.copy_media_values_from_image(&source).unwrap();
    assert_eq!(
        target_writer.compression_values(),
        WriteCompressionValues {
            level: WriteCompressionLevel::Best,
            empty_block: false,
        }
    );
    target_writer.write_all(&data).unwrap();
    target_writer.finish().unwrap();

    let target = ewf_image::Image::open(&target_path).unwrap();
    assert_eq!(
        target.compression_values().level,
        ewf_image::CompressionLevel::Best
    );
}

#[test]
fn writer_rejects_copying_xways_zstd_media_settings() {
    let dir = tempdir().unwrap();
    let source_path = dir.path().join("source.E01");
    let mut source_writer = EwfWriter::create(&source_path, WriteOptions::default()).unwrap();
    source_writer.write_all(b"source media").unwrap();
    source_writer.finish().unwrap();
    let source = ewf_image::Image::open(&source_path).unwrap();
    let mut source_info = source.info().clone();
    source_info.media.compression_method = Some(CompressionMethod::Zstd);
    let mut options = WriteOptions::default();

    let err = options
        .copy_media_values_from_info(&source_info)
        .unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Unsupported(message)
            if message.contains("X-Ways Zstandard")
    ));
}

#[test]
fn writer_copies_compatibility_style_media_values_from_source_image() {
    let dir = tempdir().unwrap();
    let source_path = dir.path().join("source.Ex01");
    let target_path = dir.path().join("target.Ex01");
    let data = vec![0x5b; 1500];
    let source_options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        sectors_per_chunk: 4,
        bytes_per_sector: 256,
        set_identifier: Some([0x77; 16]),
        compression: WriteCompression::Bzip2,
        media_profile: WriteMediaProfile {
            media_type: Some(MediaType::Fixed),
            error_granularity: Some(2),
            fastbloc: true,
            tableau: true,
        },
        ..WriteOptions::default()
    };

    let mut source_writer = EwfWriter::create(&source_path, source_options).unwrap();
    source_writer.write_all(&data).unwrap();
    source_writer.finish().unwrap();
    let source = ewf_image::Image::open(&source_path).unwrap();

    let mut copied_options = WriteOptions::default();
    copied_options
        .copy_media_values_from_info(source.info())
        .unwrap();

    assert_eq!(copied_options.format, WriteFormat::Ewf2Physical);
    assert_eq!(copied_options.sectors_per_chunk, 4);
    assert_eq!(copied_options.bytes_per_sector, 256);
    assert_eq!(copied_options.set_identifier, Some([0x77; 16]));
    assert_eq!(copied_options.compression, WriteCompression::Bzip2);
    assert_eq!(copied_options.media_size, Some(1536));
    assert_eq!(
        copied_options.media_profile,
        WriteMediaProfile {
            media_type: Some(MediaType::Fixed),
            error_granularity: Some(2),
            fastbloc: true,
            tableau: true,
        }
    );

    let mut target_writer = EwfWriter::create(&target_path, WriteOptions::default()).unwrap();
    target_writer.copy_media_values_from_image(&source).unwrap();

    assert_eq!(target_writer.format(), WriteFormat::Ewf2Physical);
    assert_eq!(target_writer.sectors_per_chunk(), 4);
    assert_eq!(target_writer.bytes_per_sector(), 256);
    assert_eq!(target_writer.chunk_size(), 1024);
    assert_eq!(
        target_writer.segment_file_set_identifier(),
        Some([0x77; 16])
    );
    assert_eq!(target_writer.compression_method(), WriteCompression::Bzip2);
    assert_eq!(target_writer.media_size().unwrap(), 1536);
    assert_eq!(target_writer.media_type(), Some(MediaType::Fixed));
    assert_eq!(target_writer.error_granularity(), Some(2));
    assert_eq!(
        target_writer.media_flags(),
        MediaFlags {
            physical: true,
            fastbloc: true,
            tableau: true,
        }
    );

    target_writer.write_all(&data).unwrap();
    target_writer.finish().unwrap();

    let target = ewf_image::Image::open(&target_path).unwrap();
    assert_eq!(target.format(), Format::Ewf2);
    assert_eq!(target.sectors_per_chunk(), Some(4));
    assert_eq!(target.bytes_per_sector(), Some(256));
    assert_eq!(target.media_size(), 1536);
    assert_eq!(target.number_of_sectors(), Some(6));
    assert_eq!(target.number_of_chunks(), Some(2));
    assert_eq!(target.segment_file_set_identifier(), Some([0x77; 16]));
    assert_eq!(target.compression_method(), Some(CompressionMethod::Bzip2));
    assert_eq!(target.media_type(), Some(MediaType::Fixed));
    assert_eq!(target.error_granularity(), Some(2));
    assert_eq!(
        target.media_flags(),
        MediaFlags {
            physical: true,
            fastbloc: true,
            tableau: true,
        }
    );
}

#[test]
fn writer_creates_patchable_writer_from_source_image() {
    let dir = tempdir().unwrap();
    let source_path = dir.path().join("source-update.Ex01");
    let target_path = dir.path().join("target-update.Ex01");
    let data = b"abcdefghijklmnopqrstuvwxyz012345".repeat(32);
    let acquisition_errors = vec![AcquisitionError {
        first_sector: 2,
        sector_count: 1,
    }];
    let sessions = vec![SectorRange {
        first_sector: 0,
        sector_count: 4,
    }];
    let tracks = vec![SectorRange {
        first_sector: 0,
        sector_count: 4,
    }];
    let memory_extents = vec![MemoryExtent {
        start_page: 7,
        page_count: 3,
    }];
    let source_options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        sectors_per_chunk: 2,
        bytes_per_sector: 256,
        set_identifier: Some([0x53; 16]),
        compression: WriteCompression::Zlib,
        metadata: EwfMetadata {
            case_number: Some("CASE-UPDATE".to_string()),
            examiner: Some("Analyst".to_string()),
            ..EwfMetadata::default()
        },
        acquisition_errors: acquisition_errors.clone(),
        sessions: sessions.clone(),
        tracks: tracks.clone(),
        memory_extents: memory_extents.clone(),
        media_profile: WriteMediaProfile {
            media_type: Some(MediaType::Fixed),
            error_granularity: Some(1),
            fastbloc: true,
            tableau: false,
        },
        ..WriteOptions::default()
    };

    let mut source_writer = EwfWriter::create(&source_path, source_options).unwrap();
    source_writer.write_all(&data).unwrap();
    source_writer.finish().unwrap();
    let source = ewf_image::Image::open(&source_path).unwrap();

    let mut writer = EwfWriter::create_from_image(&target_path, &source).unwrap();
    assert_eq!(writer.position(), source.media_size());
    assert_eq!(writer.media_size().unwrap(), source.media_size());

    writer.write_at(b"PATCHED", 10).unwrap();
    writer.finish().unwrap();

    let mut expected = data;
    expected[10..17].copy_from_slice(b"PATCHED");
    let (expected_md5, expected_sha1) = padded_hashes(&expected, expected.len());

    let target = ewf_image::Image::open(&target_path).unwrap();
    let mut decoded = vec![0; expected.len()];
    assert_eq!(target.read_at(&mut decoded, 0).unwrap(), expected.len());
    assert_eq!(decoded, expected);
    assert_eq!(target.format(), Format::Ewf2);
    assert_eq!(target.sectors_per_chunk(), Some(2));
    assert_eq!(target.bytes_per_sector(), Some(256));
    assert_eq!(target.segment_file_set_identifier(), Some([0x53; 16]));
    assert_eq!(target.compression_method(), Some(CompressionMethod::Zlib));
    assert_eq!(target.media_type(), Some(MediaType::Fixed));
    assert_eq!(target.error_granularity(), Some(1));
    assert_eq!(
        target.header_value("case_number").as_deref(),
        Some("CASE-UPDATE")
    );
    assert_eq!(
        target.header_value("examiner_name").as_deref(),
        Some("Analyst")
    );
    assert_eq!(target.info().acquisition_errors, acquisition_errors);
    assert_eq!(target.info().sessions, sessions);
    assert_eq!(target.info().tracks, tracks);
    assert_eq!(target.info().memory_extents, memory_extents);
    assert_eq!(target.md5_hash(), Some(expected_md5));
    assert_eq!(target.sha1_hash(), Some(expected_sha1));
}

#[test]
fn writer_from_source_image_preserves_unchanged_encoded_chunks() {
    let dir = tempdir().unwrap();
    let source_path = dir.path().join("source-encoded-update.Ex01");
    let target_path = dir.path().join("target-encoded-update.Ex01");
    let data: Vec<u8> = (0..65_536)
        .map(|index| ((index * 17 + index / 251) % 251) as u8)
        .collect();
    let source_options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        compression: WriteCompression::Zlib,
        compression_values: WriteCompressionValues {
            level: WriteCompressionLevel::Best,
            ..WriteCompressionValues::default()
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&source_path, source_options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let source = ewf_image::Image::open(&source_path).unwrap();
    let source_first = source.read_encoded_data_chunk(0).unwrap();

    let writer = EwfWriter::create_from_image(&target_path, &source).unwrap();
    writer.finish().unwrap();

    let target = ewf_image::Image::open(&target_path).unwrap();
    let target_first = target.read_encoded_data_chunk(0).unwrap();

    assert_eq!(target_first.encoding, source_first.encoding);
    assert_eq!(target_first.data, source_first.data);
}

#[test]
fn writer_copies_compatibility_style_hash_values_from_source_image() {
    let dir = tempdir().unwrap();
    let source_path = dir.path().join("source-hashes.E01");
    let target_path = dir.path().join("target-hashes.E01");
    let data = vec![0x49; 4096];
    let md5 = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let sha1 = [
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23,
        0x01, 0xaa, 0xbb, 0xcc, 0xdd,
    ];
    let sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let mut hashes = WriteHashes::default();
    hashes.set_hash_value("SHA256", sha256).unwrap();
    hashes
        .set_hash_value("MD5", "0123456789abcdeffedcba9876543210")
        .unwrap();
    hashes
        .set_hash_value("SHA1", "1032547698badcfeefcdab8967452301aabbccdd")
        .unwrap();
    let source_options = WriteOptions {
        hashes,
        ..WriteOptions::default()
    };

    let mut source_writer = EwfWriter::create(&source_path, source_options).unwrap();
    source_writer.write_all(&data).unwrap();
    source_writer.finish().unwrap();
    let source = ewf_image::Image::open(&source_path).unwrap();

    let mut copied_options = WriteOptions::default();
    copied_options.copy_hash_values_from_info(source.info());

    assert_eq!(copied_options.hashes.md5, Some(md5));
    assert_eq!(copied_options.hashes.sha1, Some(sha1));
    assert_eq!(
        copied_options.hashes.hash_value("MD5"),
        Some("0123456789abcdeffedcba9876543210")
    );
    assert_eq!(
        copied_options.hashes.hash_value("SHA1"),
        Some("1032547698badcfeefcdab8967452301aabbccdd")
    );
    assert_eq!(copied_options.hashes.hash_value("SHA256"), Some(sha256));

    let mut target_writer = EwfWriter::create(&target_path, WriteOptions::default()).unwrap();
    target_writer.copy_hash_values_from_image(&source);
    target_writer.write_all(&data).unwrap();
    target_writer.finish().unwrap();

    let target = ewf_image::Image::open(&target_path).unwrap();
    let hashes = &target.info().stored_hashes;

    assert_eq!(hashes.md5, Some(md5));
    assert_eq!(hashes.sha1, Some(sha1));
    assert_eq!(
        hashes.hash_value("MD5"),
        Some("0123456789abcdeffedcba9876543210")
    );
    assert_eq!(
        hashes.hash_value("SHA1"),
        Some("1032547698badcfeefcdab8967452301aabbccdd")
    );
    assert_eq!(hashes.hash_value("SHA256"), Some(sha256));
}

#[test]
fn writer_exposes_compatibility_style_format_and_segment_size_setters() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("format-setters.Ex01");
    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();

    assert_eq!(writer.format(), WriteFormat::Ewf1Physical);
    assert_eq!(writer.maximum_segment_size(), None);
    assert_eq!(
        writer.media_flags(),
        MediaFlags {
            physical: true,
            fastbloc: false,
            tableau: false,
        }
    );

    writer.set_format(WriteFormat::Ewf2Physical).unwrap();
    writer.set_maximum_segment_size(Some(34_500)).unwrap();
    writer
        .set_compression_method(WriteCompression::Bzip2)
        .unwrap();

    assert_eq!(writer.format(), WriteFormat::Ewf2Physical);
    assert_eq!(writer.maximum_segment_size(), Some(34_500));
    assert_eq!(
        writer.media_flags(),
        MediaFlags {
            physical: true,
            fastbloc: false,
            tableau: false,
        }
    );

    let err = writer.set_format(WriteFormat::Ewf1Physical).unwrap_err();
    assert!(matches!(err, ewf_image::EwfError::Unsupported(_)));
    assert_eq!(writer.format(), WriteFormat::Ewf2Physical);

    writer
        .set_compression_method(WriteCompression::Zlib)
        .unwrap();
    writer.set_format(WriteFormat::Ewf2Logical).unwrap();
    writer.set_maximum_segment_size(None).unwrap();

    assert_eq!(writer.format(), WriteFormat::Ewf2Logical);
    assert_eq!(writer.maximum_segment_size(), None);
    assert_eq!(
        writer.media_flags(),
        MediaFlags {
            physical: false,
            fastbloc: false,
            tableau: false,
        }
    );

    writer.write_all(&vec![0x61; 1500]).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    assert_eq!(image.format(), Format::Ewf2);
    assert_eq!(
        image.format_profile(),
        ewf_image::FormatProfile::Ewf2LogicalEnCase7
    );
    assert!(!image.media_flags().physical);
}

#[test]
fn writer_treats_zero_maximum_segment_size_as_format_maximum() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("zero-segment-size.E01");
    let options = WriteOptions {
        maximum_segment_size: Some(0),
        ..WriteOptions::default()
    };
    let mut writer = EwfWriter::create(&path, options).unwrap();

    assert_eq!(writer.maximum_segment_size(), None);

    writer.set_maximum_segment_size(Some(34_500)).unwrap();
    assert_eq!(writer.maximum_segment_size(), Some(34_500));
    writer.set_maximum_segment_size(Some(0)).unwrap();
    assert_eq!(writer.maximum_segment_size(), None);
}

#[test]
fn writer_and_image_expose_compatibility_style_segment_filenames() {
    let dir = tempdir().unwrap();
    let original = dir.path().join("original.E01");
    let retargeted = dir.path().join("retargeted.E01");
    let data = b"filename getter data";
    let mut writer = EwfWriter::create(&original, WriteOptions::default()).unwrap();

    assert_eq!(writer.filename(), original.as_path());
    assert_eq!(writer.segment_filename(), original.as_path());

    writer.set_segment_filename(&retargeted);

    assert_eq!(writer.filename(), retargeted.as_path());
    assert_eq!(writer.segment_filename(), retargeted.as_path());

    writer.write_all(data).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.segment_paths, vec![retargeted.clone()]);
    assert!(!original.exists());
    assert!(retargeted.exists());

    let image = ewf_image::Image::open(&retargeted).unwrap();

    assert_eq!(image.number_of_segments(), 1);
    assert_eq!(image.filename(), retargeted.as_path());
    assert_eq!(image.segment_filename(0), Some(retargeted.as_path()));
    assert_eq!(image.segment_filename(1), None);
    assert_eq!(image.segment_filenames(), std::slice::from_ref(&retargeted));
}

#[test]
fn writer_creates_secondary_shadow_e01_segment_set_matching_primary_output() {
    let dir = tempdir().unwrap();
    let primary_first = dir.path().join("primary.E01");
    let primary_second = dir.path().join("primary.E02");
    let shadow_first = dir.path().join("shadow.E01");
    let shadow_second = dir.path().join("shadow.E02");
    let data: Vec<u8> = (0..65_536).map(|index| (index % 193) as u8).collect();
    let options = WriteOptions {
        maximum_segment_size: Some(34_500),
        secondary_segment_filename: Some(shadow_first.clone()),
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&primary_first, options).unwrap();
    writer.write_all(&data).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(
        result.segment_paths,
        vec![primary_first.clone(), primary_second.clone()]
    );
    assert_eq!(
        result.secondary_segment_paths,
        vec![shadow_first.clone(), shadow_second.clone()]
    );
    assert_eq!(
        fs::read(&shadow_first).unwrap(),
        fs::read(&primary_first).unwrap()
    );
    assert_eq!(
        fs::read(&shadow_second).unwrap(),
        fs::read(&primary_second).unwrap()
    );

    let image = ewf_image::Image::open(&shadow_first).unwrap();
    assert_eq!(image.info().segment_paths, result.secondary_segment_paths);
    assert_eq!(image.info().logical_size, data.len() as u64);

    let mut decoded = vec![0; data.len()];
    assert_eq!(image.read_at(&mut decoded, 0).unwrap(), data.len());
    assert_eq!(decoded, data);
}

#[test]
fn writer_creates_secondary_shadow_ex01_segment_set_matching_primary_output() {
    let dir = tempdir().unwrap();
    let primary_first = dir.path().join("primary.Ex01");
    let primary_second = dir.path().join("primary.Ex02");
    let shadow_first = dir.path().join("shadow.Ex01");
    let shadow_second = dir.path().join("shadow.Ex02");
    let data: Vec<u8> = (0..65_536).map(|index| (index % 197) as u8).collect();
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        maximum_segment_size: Some(34_500),
        secondary_segment_filename: Some(shadow_first.clone()),
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&primary_first, options).unwrap();
    writer.write_all(&data).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(
        result.segment_paths,
        vec![primary_first.clone(), primary_second.clone()]
    );
    assert_eq!(
        result.secondary_segment_paths,
        vec![shadow_first.clone(), shadow_second.clone()]
    );
    assert_eq!(
        fs::read(&shadow_first).unwrap(),
        fs::read(&primary_first).unwrap()
    );
    assert_eq!(
        fs::read(&shadow_second).unwrap(),
        fs::read(&primary_second).unwrap()
    );

    let image = ewf_image::Image::open(&shadow_first).unwrap();
    assert_eq!(image.info().format, Format::Ewf2);
    assert_eq!(image.info().segment_paths, result.secondary_segment_paths);
    assert_eq!(image.info().logical_size, data.len() as u64);

    let mut decoded = vec![0; data.len()];
    assert_eq!(image.read_at(&mut decoded, 0).unwrap(), data.len());
    assert_eq!(decoded, data);
}

#[test]
fn writer_rejects_secondary_shadow_output_that_overlaps_primary_output() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("overlap.E01");
    let options = WriteOptions {
        secondary_segment_filename: Some(path.clone()),
        ..WriteOptions::default()
    };

    let err = EwfWriter::create(&path, options).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Unsupported(message)
            if message.contains("secondary segment filename overlaps primary output")
    ));
}

#[test]
fn writer_write_at_overwrites_existing_bytes_before_finish() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("write-at-overwrite.E01");
    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();

    writer.write_all(b"abcdef").unwrap();
    let written = writer.write_at(b"XY", 2).unwrap();
    assert_eq!(written, 2);
    assert_eq!(writer.position(), 4);
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    let mut decoded = vec![0; 6];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, 6);
    assert_eq!(&decoded, b"abXYef");
}

#[test]
fn writer_write_at_creates_zero_filled_gap_for_forward_offsets() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("write-at-gap.Ex01");
    let mut writer = EwfWriter::create(
        &path,
        WriteOptions {
            format: WriteFormat::Ewf2Physical,
            ..WriteOptions::default()
        },
    )
    .unwrap();

    writer.write_all(b"head").unwrap();
    let written = writer.write_at(b"tail", 512).unwrap();
    assert_eq!(written, 4);
    assert_eq!(writer.position(), 516);
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    assert_eq!(image.info().logical_size, 1024);
    let mut decoded = vec![0xff; 516];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, 516);
    assert_eq!(&decoded[..4], b"head");
    assert!(decoded[4..512].iter().all(|byte| *byte == 0));
    assert_eq!(&decoded[512..516], b"tail");
}

#[test]
fn writer_pads_to_configured_media_size() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("media-size.E01");
    let data = b"declared media prefix";
    let options = WriteOptions {
        media_size: Some(2048),
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(data).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.logical_size, 2048);

    let image = ewf_image::Image::open(&path).unwrap();
    assert_eq!(image.info().logical_size, 2048);
    assert_eq!(image.info().media.sector_count, Some(4));

    let mut decoded = vec![0xff; 2048];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, decoded.len());
    assert_eq!(&decoded[..data.len()], data);
    assert!(decoded[data.len()..].iter().all(|byte| *byte == 0));
}

#[test]
fn writer_set_media_size_controls_final_size() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("set-media-size.E01");
    let data = b"set by method";
    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();

    writer.set_media_size(1024).unwrap();
    writer.write_all(data).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.logical_size, 1024);

    let image = ewf_image::Image::open(&path).unwrap();
    let mut decoded = vec![0xff; 1024];
    image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(&decoded[..data.len()], data);
    assert!(decoded[data.len()..].iter().all(|byte| *byte == 0));
}

#[test]
fn writer_treats_zero_media_size_as_streamed_size() {
    let dir = tempdir().unwrap();
    let options_path = dir.path().join("zero-media-size-options.E01");
    let setter_path = dir.path().join("zero-media-size-setter.E01");
    let data = b"stream-sized media";
    let options = WriteOptions {
        media_size: Some(0),
        ..WriteOptions::default()
    };
    let mut options_writer = EwfWriter::create(&options_path, options).unwrap();

    options_writer.write_all(data).unwrap();
    let options_result = options_writer.finish().unwrap();

    assert_eq!(options_result.logical_size, 512);
    let options_image = ewf_image::Image::open(&options_path).unwrap();
    let mut options_decoded = vec![0; data.len()];
    assert_eq!(
        options_image.read_at(&mut options_decoded, 0).unwrap(),
        data.len()
    );
    assert_eq!(&options_decoded, data);

    let mut setter_writer = EwfWriter::create(&setter_path, WriteOptions::default()).unwrap();
    setter_writer.set_media_size(1024).unwrap();
    setter_writer.set_media_size(0).unwrap();
    setter_writer.write_all(data).unwrap();
    let setter_result = setter_writer.finish().unwrap();

    assert_eq!(setter_result.logical_size, 512);
}

#[test]
fn writer_seek_from_end_uses_configured_media_size() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("media-size-seek-end.E01");
    let options = WriteOptions {
        media_size: Some(1024),
        ..WriteOptions::default()
    };
    let mut writer = EwfWriter::create(&path, options).unwrap();

    assert_eq!(writer.seek(SeekFrom::End(-4)).unwrap(), 1020);
    writer.write_all(b"tail").unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    let mut decoded = vec![0xff; 1024];
    image.read_at(&mut decoded, 0).unwrap();

    assert!(decoded[..1020].iter().all(|byte| *byte == 0));
    assert_eq!(&decoded[1020..], b"tail");
}

#[test]
fn writer_exposes_compatibility_style_offset_helpers() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("offset-helpers.E01");
    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();

    assert_eq!(writer.offset(), 0);
    writer.write_buffer(b"0123456789").unwrap();
    assert_eq!(writer.offset(), 10);
    assert_eq!(writer.seek_offset(SeekFrom::Start(4)).unwrap(), 4);
    assert_eq!(writer.offset(), 4);
    assert_eq!(writer.write_buffer(b"AB").unwrap(), 2);
    assert_eq!(writer.offset(), 6);
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    let mut decoded = [0; 10];
    assert_eq!(image.read_at(&mut decoded, 0).unwrap(), 10);
    assert_eq!(&decoded, b"0123AB6789");
}

#[test]
fn writer_rejects_writes_past_configured_media_size() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("media-size-bounds.E01");
    let options = WriteOptions {
        media_size: Some(4),
        ..WriteOptions::default()
    };
    let mut writer = EwfWriter::create(&path, options).unwrap();

    let err = writer.write_all(b"12345").unwrap_err();

    assert!(
        matches!(err, ewf_image::EwfError::Unsupported(message) if message.contains("configured media size"))
    );
}

#[test]
fn writer_exposes_compatibility_style_write_buffer_aliases() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("write-buffer-aliases.E01");
    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();

    assert_eq!(writer.write_buffer(b"hello world").unwrap(), 11);
    assert_eq!(writer.write_buffer_at_offset(b"EWF", 6).unwrap(), 3);
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    let mut decoded = [0; 11];
    assert_eq!(image.read_at(&mut decoded, 0).unwrap(), 11);
    assert_eq!(&decoded, b"hello EWFld");
}

#[test]
fn writer_signal_abort_stops_subsequent_writes_and_finish() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("abort-writer.E01");
    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();
    let decoded = DataChunk {
        chunk_index: 0,
        logical_offset: 0,
        logical_size: 4,
        encoded_size: 4,
        encoding: DataChunkEncoding::Raw,
        corrupted: false,
        data: b"data".to_vec(),
    };
    let encoded = ewf_image::EncodedDataChunk {
        chunk_index: 0,
        logical_offset: 0,
        logical_size: 4,
        encoded_size: 4,
        encoding: DataChunkEncoding::Raw,
        has_checksum: false,
        data: b"data".to_vec(),
    };

    writer.write_all(b"seed").unwrap();
    writer.signal_abort();

    assert!(matches!(
        writer.write_all(b"after").unwrap_err(),
        ewf_image::EwfError::Aborted
    ));
    assert!(matches!(
        writer.write_at(b"after", 0).unwrap_err(),
        ewf_image::EwfError::Aborted
    ));
    assert!(matches!(
        writer.write_data_chunk(&decoded).unwrap_err(),
        ewf_image::EwfError::Aborted
    ));
    assert!(matches!(
        writer.write_encoded_data_chunk(&encoded).unwrap_err(),
        ewf_image::EwfError::Aborted
    ));
    assert!(matches!(
        writer.finish().unwrap_err(),
        ewf_image::EwfError::Aborted
    ));
}

#[test]
fn writer_seek_updates_position_for_subsequent_writes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("seek-write.E01");
    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();

    writer.write_all(b"abcdef").unwrap();
    assert_eq!(writer.seek(SeekFrom::Start(1)).unwrap(), 1);
    IoWrite::write_all(&mut writer, b"ZZ").unwrap();
    assert_eq!(writer.seek(SeekFrom::Current(1)).unwrap(), 4);
    IoWrite::write_all(&mut writer, b"Q").unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    let mut decoded = vec![0; 6];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, 6);
    assert_eq!(&decoded, b"aZZdQf");
}

#[test]
fn writer_debug_redacts_spooled_input_bytes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("debug-redacted.E01");
    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();

    writer.write_all(b"secret evidence bytes").unwrap();
    let debug = format!("{writer:?}");

    assert!(!debug.contains("[115, 101, 99, 114, 101, 116"));
    assert!(!debug.contains("secret evidence bytes"));
    assert!(debug.contains("raw_spooled_bytes"));
}

#[test]
fn writer_spools_full_chunks_as_raw_input_before_finish() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("flushed-full-chunk.E01");
    let data = vec![0x5c; 32_768];
    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();

    writer.write_all(&data).unwrap();
    let debug = format!("{writer:?}");

    assert!(
        debug.contains("raw_spooled_bytes: 32768"),
        "writer should spool completed raw input before finish: {debug}"
    );

    let result = writer.finish().unwrap();
    assert_eq!(result.logical_size, data.len() as u64);

    let image = ewf_image::Image::open(&path).unwrap();
    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);
}

#[test]
fn writer_defers_encoded_chunks_until_finish() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("spooled-full-chunk.E01");
    let data = vec![0x37; 32_768];
    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();

    writer.write_all(&data).unwrap();
    let debug = format!("{writer:?}");

    assert!(
        debug.contains("encoded_chunks: 0"),
        "writer should not retain encoded payloads before finish: {debug}"
    );
    assert!(
        debug.contains("raw_spooled_bytes: 32768"),
        "writer should spool raw input before finish: {debug}"
    );

    let result = writer.finish().unwrap();
    assert_eq!(result.logical_size, data.len() as u64);

    let image = ewf_image::Image::open(&path).unwrap();
    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);
}

#[test]
fn writer_computes_default_e01_digest_hashes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("computed.E01");
    let data = (0_u16..1000).map(|value| value as u8).collect::<Vec<_>>();
    let (md5, sha1) = padded_hashes(&data, 1024);

    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();
    writer.write_all(&data).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.logical_size, 1024);

    let image = ewf_image::Image::open(&path).unwrap();

    assert_eq!(image.info().stored_hashes.md5, Some(md5));
    assert_eq!(image.info().stored_hashes.sha1, Some(sha1));
}

#[test]
fn writer_creates_readable_empty_e01() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("empty.E01");

    let writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.segment_paths, vec![path.clone()]);
    assert_eq!(result.logical_size, 0);
    assert_eq!(result.chunk_count, 0);

    let image = ewf_image::Image::open(&path).unwrap();
    let mut buf = [0; 16];
    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(image.info().logical_size, 0);
    assert_eq!(read, 0);
}

#[test]
fn writer_creates_readable_e01_with_multiple_raw_chunks() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("case.E01");
    let data: Vec<u8> = (0..33_280).map(|index| (index % 251) as u8).collect();

    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();
    writer.write_all(&data[..1024]).unwrap();
    writer.write_all(&data[1024..]).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.logical_size, data.len() as u64);

    let image = ewf_image::Image::open(&path).unwrap();
    assert_eq!(image.info().logical_size, data.len() as u64);
    assert_eq!(image.info().media.chunk_count, Some(2));

    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);

    let bytes = fs::read(&path).unwrap();
    let volume = ewf1_section_data(&bytes, b"volume");
    assert_eq!(
        u32::from_le_bytes(volume[volume.len() - 4..].try_into().unwrap()),
        adler32(&volume[..volume.len() - 4])
    );
    assert_ewf1_table_checksums(ewf1_section_data(&bytes, b"table"), true);
}

#[test]
fn image_reads_decoded_raw_data_chunk_with_metadata() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("data-chunk.E01");
    let data: Vec<u8> = (0..32_768).map(|index| (index % 251) as u8).collect();

    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    let chunk = image.read_data_chunk(0).unwrap();

    assert_eq!(chunk.chunk_index, 0);
    assert_eq!(chunk.logical_offset, 0);
    assert_eq!(chunk.logical_size, data.len());
    assert_eq!(chunk.encoded_size, data.len() as u64 + 4);
    assert_eq!(chunk.encoding, DataChunkEncoding::Raw);
    assert!(!chunk.corrupted);
    assert_eq!(chunk.data, data);
}

#[test]
fn image_reads_decoded_compressed_data_chunk_with_metadata() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("compressed-data-chunk.Ex01");
    let mut data = Vec::with_capacity(32_768);
    for index in 0..32_768 {
        data.push(((index * 17 + index / 251) % 251) as u8);
    }
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        compression: WriteCompression::Zlib,
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    let chunk = image.read_data_chunk(0).unwrap();

    assert_eq!(chunk.logical_size, data.len());
    assert_eq!(chunk.encoding, DataChunkEncoding::Zlib);
    assert!(chunk.encoded_size < data.len() as u64);
    assert_eq!(chunk.data, data);
}

#[test]
fn image_reads_encoded_compressed_data_chunk_with_metadata() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("encoded-data-chunk.Ex01");
    let mut data = Vec::with_capacity(32_768);
    for index in 0..32_768 {
        data.push(((index * 17 + index / 251) % 251) as u8);
    }
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        compression: WriteCompression::Zlib,
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    let decoded = image.read_data_chunk(0).unwrap();
    let encoded = image.read_encoded_data_chunk(0).unwrap();

    assert_eq!(encoded.chunk_index, decoded.chunk_index);
    assert_eq!(encoded.logical_offset, decoded.logical_offset);
    assert_eq!(encoded.logical_size, decoded.logical_size);
    assert_eq!(encoded.encoded_size, decoded.encoded_size);
    assert_eq!(encoded.encoding, DataChunkEncoding::Zlib);
    assert!(!encoded.has_checksum);
    assert_eq!(encoded.data.len(), encoded.encoded_size as usize);
    assert!(encoded.data.len() < decoded.data.len());
    assert_ne!(encoded.data, decoded.data);
}

#[test]
fn image_cursor_reads_data_chunks_at_current_offset() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("cursor-data-chunks.Ex01");
    let data: Vec<u8> = (0..65_536)
        .map(|index| ((index * 29 + index / 251) % 251) as u8)
        .collect();
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        compression: WriteCompression::Zlib,
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    let mut cursor = image.cursor();

    let first = cursor.read_data_chunk().unwrap().unwrap();
    assert_eq!(first.chunk_index, 0);
    assert_eq!(first.logical_offset, 0);
    assert_eq!(first.logical_size, 32_768);
    assert_eq!(first.data, data[..32_768]);
    assert_eq!(cursor.position(), 32_768);

    cursor.seek(SeekFrom::Start(32_769)).unwrap();
    let second = cursor.read_encoded_data_chunk().unwrap().unwrap();
    assert_eq!(second.chunk_index, 1);
    assert_eq!(second.logical_offset, 32_768);
    assert_eq!(second.logical_size, 32_768);
    assert_eq!(second.encoding, DataChunkEncoding::Zlib);
    assert_eq!(cursor.position(), 65_536);

    assert!(cursor.read_data_chunk().unwrap().is_none());
    assert_eq!(cursor.position(), 65_536);
}

#[test]
fn image_reads_pattern_fill_data_chunk_with_metadata() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("pattern-data-chunk.Ex01");
    let pattern = 0x1122_3344_5566_7788_u64;
    let data = pattern.to_le_bytes().repeat(4096);
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    let chunk = image.read_data_chunk(0).unwrap();

    assert_eq!(chunk.logical_size, data.len());
    assert_eq!(chunk.encoded_size, 0);
    assert_eq!(chunk.encoding, DataChunkEncoding::PatternFill(pattern));
    assert_eq!(chunk.data, data);
}

#[test]
fn writer_writes_data_chunks_from_reader_values() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("chunk-source.E01");
    let target = dir.path().join("chunk-target.E01");
    let data: Vec<u8> = (0..65_536).map(|index| (index % 251) as u8).collect();

    let mut writer = EwfWriter::create(&source, WriteOptions::default()).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&source).unwrap();
    let first = image.read_data_chunk(0).unwrap();
    let second = image.read_data_chunk(1).unwrap();

    let mut writer = EwfWriter::create(&target, WriteOptions::default()).unwrap();
    assert_eq!(writer.write_data_chunk(&first).unwrap(), first.logical_size);
    assert_eq!(
        writer.write_data_chunk(&second).unwrap(),
        second.logical_size
    );
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&target).unwrap();
    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);
}

#[test]
fn writer_writes_encoded_data_chunks_from_reader_values() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("encoded-chunk-source.Ex01");
    let target = dir.path().join("encoded-chunk-target.Ex01");
    let data: Vec<u8> = (0..65_536)
        .map(|index| ((index * 19 + index / 251) % 251) as u8)
        .collect();
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        compression: WriteCompression::Zlib,
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&source, options.clone()).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&source).unwrap();
    let first = image.read_encoded_data_chunk(0).unwrap();
    let second = image.read_encoded_data_chunk(1).unwrap();

    let mut writer = EwfWriter::create(&target, options).unwrap();
    assert_eq!(
        writer.write_encoded_data_chunk(&first).unwrap(),
        first.logical_size
    );
    assert_eq!(
        writer.write_encoded_data_chunk(&second).unwrap(),
        second.logical_size
    );
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&target).unwrap();
    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);
}

#[test]
fn writer_preserves_compatible_encoded_data_chunk_payloads() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("encoded-preserve-source.Ex01");
    let target = dir.path().join("encoded-preserve-target.Ex01");
    let data: Vec<u8> = (0..65_536)
        .map(|index| ((index * 17 + index / 251) % 251) as u8)
        .collect();
    let source_options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        compression: WriteCompression::Zlib,
        compression_values: WriteCompressionValues {
            level: WriteCompressionLevel::Best,
            ..WriteCompressionValues::default()
        },
        ..WriteOptions::default()
    };
    let target_options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        compression: WriteCompression::Zlib,
        compression_values: WriteCompressionValues {
            level: WriteCompressionLevel::Fast,
            ..WriteCompressionValues::default()
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&source, source_options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&source).unwrap();
    let first = image.read_encoded_data_chunk(0).unwrap();
    let second = image.read_encoded_data_chunk(1).unwrap();

    let mut writer = EwfWriter::create(&target, target_options).unwrap();
    assert_eq!(
        writer.write_encoded_data_chunk(&first).unwrap(),
        first.logical_size
    );
    assert_eq!(
        writer.write_encoded_data_chunk(&second).unwrap(),
        second.logical_size
    );
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&target).unwrap();
    let target_first = image.read_encoded_data_chunk(0).unwrap();
    let target_second = image.read_encoded_data_chunk(1).unwrap();

    assert_eq!(target_first.encoding, first.encoding);
    assert_eq!(target_second.encoding, second.encoding);
    assert_eq!(target_first.data, first.data);
    assert_eq!(target_second.data, second.data);

    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();
    assert_eq!(read, data.len());
    assert_eq!(decoded, data);
}

#[test]
fn writer_writes_data_chunk_at_explicit_offsets() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("chunk-at-source.Ex01");
    let target = dir.path().join("chunk-at-target.Ex01");
    let data: Vec<u8> = (0..65_536)
        .map(|index| ((index * 19) % 251) as u8)
        .collect();
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        compression: WriteCompression::Zlib,
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&source, options.clone()).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&source).unwrap();
    let first = image.read_data_chunk(0).unwrap();
    let second = image.read_data_chunk(1).unwrap();

    let mut writer = EwfWriter::create(&target, options).unwrap();
    assert_eq!(
        writer
            .write_data_chunk_at(&second, second.logical_offset)
            .unwrap(),
        second.logical_size
    );
    assert_eq!(
        writer
            .write_data_chunk_at(&first, first.logical_offset)
            .unwrap(),
        first.logical_size
    );
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&target).unwrap();
    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);
}

#[test]
fn writer_writes_encoded_data_chunk_at_explicit_offsets() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("encoded-chunk-at-source.Ex01");
    let target = dir.path().join("encoded-chunk-at-target.Ex01");
    let data: Vec<u8> = (0..65_536)
        .map(|index| ((index * 23 + index / 251) % 251) as u8)
        .collect();
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        compression: WriteCompression::Zlib,
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&source, options.clone()).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&source).unwrap();
    let first = image.read_encoded_data_chunk(0).unwrap();
    let second = image.read_encoded_data_chunk(1).unwrap();

    let mut writer = EwfWriter::create(&target, options).unwrap();
    assert_eq!(
        writer
            .write_encoded_data_chunk_at(&second, second.logical_offset)
            .unwrap(),
        second.logical_size
    );
    assert_eq!(
        writer
            .write_encoded_data_chunk_at(&first, first.logical_offset)
            .unwrap(),
        first.logical_size
    );
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&target).unwrap();
    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);
}

#[test]
fn writer_rejects_invalid_data_chunks() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("invalid-chunk.E01");
    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();
    let chunk = DataChunk {
        chunk_index: 0,
        logical_offset: 0,
        logical_size: 4,
        encoded_size: 4,
        encoding: DataChunkEncoding::Raw,
        corrupted: true,
        data: vec![1, 2, 3, 4],
    };

    let err = writer.write_data_chunk(&chunk).unwrap_err();
    assert!(err.to_string().contains("corrupted data chunk"));

    let chunk = DataChunk {
        corrupted: false,
        logical_size: 5,
        ..chunk
    };
    let err = writer.write_data_chunk(&chunk).unwrap_err();
    assert!(err.to_string().contains("payload length"));
}

#[test]
fn writer_rejects_xways_zstd_encoded_chunks() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("xways-zstd-chunk.E01");
    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();
    let chunk = ewf_image::EncodedDataChunk {
        chunk_index: 0,
        logical_offset: 0,
        logical_size: 32_768,
        encoded_size: 1,
        encoding: DataChunkEncoding::Zstd,
        has_checksum: false,
        data: vec![0],
    };

    let err = writer.write_encoded_data_chunk(&chunk).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Unsupported(message)
            if message.contains("X-Ways Zstandard")
    ));
}

#[test]
fn writer_uses_ewf1_empty_block_compression_for_full_zero_chunks() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("empty-block.E01");
    let data = vec![0; 32_768];

    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();
    writer.write_all(&data).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.logical_size, data.len() as u64);

    let image = ewf_image::Image::open(&path).unwrap();
    let mut decoded = vec![0xff; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);

    let bytes = fs::read(&path).unwrap();
    let table = ewf1_section_data(&bytes, b"table");
    assert_ewf1_table_checksums(table, true);
    let first_entry = u32::from_le_bytes(table[24..28].try_into().unwrap());
    assert_ne!(first_entry & 0x8000_0000, 0);

    let sectors = ewf1_section_data(&bytes, b"sectors");
    assert!(sectors.len() < data.len());
    assert_eq!(sectors.first(), Some(&0x78));
}

#[test]
fn writer_can_disable_empty_block_compression_for_zero_chunks() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("no-empty-block.E01");
    let data = vec![0; 32_768];
    let options = WriteOptions {
        compression_values: WriteCompressionValues {
            empty_block: false,
            ..WriteCompressionValues::default()
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    let mut decoded = vec![0xff; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);

    let bytes = fs::read(&path).unwrap();
    let table = ewf1_section_data(&bytes, b"table");
    assert_ewf1_table_checksums(table, true);
    let first_entry = u32::from_le_bytes(table[24..28].try_into().unwrap());
    assert_eq!(first_entry & 0x8000_0000, 0);

    let sectors = ewf1_section_data(&bytes, b"sectors");
    assert_eq!(sectors.len(), data.len() + 4);
    assert_eq!(
        u32::from_le_bytes(sectors[data.len()..data.len() + 4].try_into().unwrap()),
        adler32(&data)
    );
}

#[test]
fn writer_creates_readable_logical_l01() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("logical.L01");
    let data = vec![0x4c; 512];
    let options = WriteOptions {
        format: WriteFormat::Ewf1Logical,
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.segment_paths, vec![path.clone()]);

    let image = ewf_image::Image::open(&path).unwrap();
    assert_eq!(image.info().format, Format::Ewf1);
    assert!(!image.info().media.media_flags.physical);
    assert_eq!(image.info().logical_size, data.len() as u64);

    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);

    let bytes = fs::read(&path).unwrap();
    let volume = ewf1_section_data(&bytes, b"volume");
    assert_eq!(
        u32::from_le_bytes(volume[volume.len() - 4..].try_into().unwrap()),
        adler32(&volume[..volume.len() - 4])
    );
    assert_ewf1_table_checksums(ewf1_section_data(&bytes, b"table"), true);
}

#[test]
fn writer_creates_readable_logical_l01_single_files_catalog() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("logical-single-files.L01");
    let data = b"l01 payload".to_vec();
    let single_files = SingleFilesInfo {
        root: SingleFileEntry {
            identifier: Some(1),
            file_entry_type: Some(SingleFileEntryType::Directory),
            name: Some("root".to_owned()),
            children: vec![SingleFileEntry {
                identifier: Some(2),
                file_entry_type: Some(SingleFileEntryType::File),
                name: Some("payload.bin".to_owned()),
                size: Some(data.len() as u64),
                extents: vec![SingleFileExtent {
                    data_offset: 0,
                    data_size: data.len() as u64,
                    sparse: false,
                }],
                ..SingleFileEntry::default()
            }],
            ..SingleFileEntry::default()
        },
        ..SingleFilesInfo::default()
    };
    let options = WriteOptions {
        format: WriteFormat::Ewf1Logical,
        media_profile: WriteMediaProfile {
            media_type: Some(MediaType::SingleFiles),
            ..WriteMediaProfile::default()
        },
        single_files: Some(single_files),
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let bytes = fs::read(&path).unwrap();
    let ltree = ewf1_section_data(&bytes, b"ltree");
    let ltree_data = &ltree[48..];
    assert!(utf16le_string(ltree_data).ends_with("\n\n"));
    let mut hasher = Md5::new();
    hasher.update(ltree_data);
    assert_eq!(&ltree[0..16], hasher.finalize().as_slice());
    assert_eq!(
        u64::from_le_bytes(ltree[16..24].try_into().unwrap()),
        ltree_data.len() as u64
    );
    let mut header = ltree[..48].to_vec();
    header[24..28].fill(0);
    assert_eq!(
        u32::from_le_bytes(ltree[24..28].try_into().unwrap()),
        adler32(&header)
    );

    let image = ewf_image::Image::open(&path).unwrap();
    let single_files = image.info().single_files.as_ref().unwrap();
    let child = single_files.entry_by_path("payload.bin").unwrap().unwrap();
    let mut decoded = vec![0; data.len()];
    let read = image.read_single_file_at(child, &mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);
}

#[test]
fn writer_rejects_unpaired_utf16_entry_name_without_reencoding_it() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("unpaired.L01");
    let single_files = SingleFilesInfo {
        root: SingleFileEntry {
            file_entry_type: Some(SingleFileEntryType::Directory),
            name: Some("root".to_owned()),
            children: vec![SingleFileEntry {
                file_entry_type: Some(SingleFileEntryType::File),
                name: Some("�".to_owned()),
                name_utf16: Some(vec![0xd800]),
                size: Some(1),
                extents: vec![SingleFileExtent {
                    data_offset: 0,
                    data_size: 1,
                    sparse: false,
                }],
                ..SingleFileEntry::default()
            }],
            ..SingleFileEntry::default()
        },
        ..SingleFilesInfo::default()
    };
    let options = WriteOptions {
        format: WriteFormat::Ewf1Logical,
        single_files: Some(single_files),
        ..WriteOptions::default()
    };
    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(b"x").unwrap();

    let error = writer.finish().unwrap_err();
    assert!(error.to_string().contains("unpaired UTF-16"));
    assert!(!path.exists());
}

#[test]
fn writer_creates_readable_smart_s01() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("smart.s01");
    let data = vec![0x53; 32_768];
    let options = WriteOptions {
        format: WriteFormat::Ewf1Smart,
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.segment_paths, vec![path.clone()]);

    let image = ewf_image::Image::open(&path).unwrap();
    assert_eq!(image.info().format, Format::Ewf1);
    assert_eq!(image.info().media.media_type, Some(MediaType::Removable));
    assert!(!image.info().media.media_flags.physical);
    assert_eq!(image.info().logical_size, data.len() as u64);

    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);

    let bytes = fs::read(&path).unwrap();
    let volume = ewf1_section_data(&bytes, b"volume");
    assert_eq!(
        u32::from_le_bytes(volume[volume.len() - 4..].try_into().unwrap()),
        adler32(&volume[..volume.len() - 4])
    );
    assert_ewf1_table_checksums(ewf1_section_data(&bytes, b"table"), false);
}

#[test]
fn writer_computes_default_ewf2_hash_sections() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("computed.Ex01");
    let data = (0_u16..1000)
        .map(|value| value.wrapping_mul(7) as u8)
        .collect::<Vec<_>>();
    let (md5, sha1) = padded_hashes(&data, 1024);
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.logical_size, 1024);

    let image = ewf_image::Image::open(&path).unwrap();

    assert_eq!(image.info().stored_hashes.md5, Some(md5));
    assert_eq!(image.info().stored_hashes.sha1, Some(sha1));
    assert_eq!(
        &ewf2_section_data(&fs::read(&path).unwrap(), 0x08)[..16],
        &md5
    );
}

#[test]
fn writer_creates_readable_ewf2_ex01() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("case.Ex01");
    let data = (0_u16..4096)
        .map(|value| (value.wrapping_mul(31) ^ (value >> 3)) as u8)
        .collect::<Vec<_>>();
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        set_identifier: Some([0x9a; 16]),
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.segment_paths, vec![path.clone()]);

    let image = ewf_image::Image::open(&path).unwrap();
    assert_eq!(image.info().format, Format::Ewf2);
    assert!(image.info().media.media_flags.physical);
    assert_eq!(image.info().media.sectors_per_chunk, Some(64));
    assert_eq!(image.info().media.bytes_per_sector, Some(512));
    assert_eq!(image.info().media.sector_count, Some(8));
    assert_eq!(image.info().media.chunk_count, Some(1));
    assert_eq!(image.info().media.set_identifier, Some([0x9a; 16]));
    assert_eq!(
        image.info().media.ewf2_segment_file_version,
        Some(SegmentFileVersion { major: 2, minor: 1 })
    );
    assert_eq!(
        image.info().media.compression_method,
        Some(CompressionMethod::Zlib)
    );
    assert_eq!(image.info().logical_size, data.len() as u64);

    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);

    let bytes = fs::read(&path).unwrap();
    assert_ewf2_descriptor_checksums(&bytes);
    assert_eq!(ewf2_section_data(&bytes, 0x01).first(), Some(&0x78));
    let table = ewf2_section_data(&bytes, 0x04);
    assert_ewf2_table_checksums(table);
    assert_eq!(
        u32::from_le_bytes(table[44..48].try_into().unwrap()),
        0x0000_0002
    );
    assert_raw_chunk_checksum(ewf2_section_data(&bytes, 0x03), &data);
}

#[test]
fn writer_uses_trailing_ewf2_descriptors_for_common_readers() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("trailing.Ex01");
    let data = vec![0x5a; 4096];
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let bytes = fs::read(&path).unwrap();

    assert_ne!(
        u32::from_le_bytes(bytes[32..36].try_into().unwrap()),
        0x01,
        "EWF2 payload should precede the first section descriptor"
    );
    assert_eq!(
        ewf2_trailing_section_types(&bytes),
        [0x01, 0x02, 0x03, 0x04, 0x08, 0x09, 0x0f]
    );
}

#[test]
fn writer_emits_ewf2_pattern_fill_chunks_for_repeated_data() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("pattern.Ex01");
    let pattern = 0x1122_3344_5566_7788_u64;
    let data = pattern.to_le_bytes().repeat(512);
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.logical_size, data.len() as u64);

    let image = ewf_image::Image::open(&path).unwrap();
    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);

    let bytes = fs::read(&path).unwrap();
    let table = ewf2_section_data(&bytes, 0x04);
    assert_ewf2_table_checksums(table);
    assert_eq!(
        u64::from_le_bytes(table[32..40].try_into().unwrap()),
        pattern
    );
    assert_eq!(u32::from_le_bytes(table[40..44].try_into().unwrap()), 0);
    assert_eq!(
        u32::from_le_bytes(table[44..48].try_into().unwrap()),
        0x0000_0005
    );
    assert_eq!(ewf2_section_data(&bytes, 0x03), []);
}

#[test]
fn writer_creates_readable_empty_ewf2_ex01() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("empty.Ex01");
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        ..WriteOptions::default()
    };

    let writer = EwfWriter::create(&path, options).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.segment_paths, vec![path.clone()]);
    assert_eq!(result.logical_size, 0);
    assert_eq!(result.chunk_count, 0);

    let image = ewf_image::Image::open(&path).unwrap();
    let mut buf = [0; 16];
    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(image.info().format, Format::Ewf2);
    assert_eq!(image.info().logical_size, 0);
    assert_eq!(read, 0);
}

#[test]
fn writer_creates_readable_ewf2_lx01() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("logical.Lx01");
    let data = vec![0x6c; 512];
    let options = WriteOptions {
        format: WriteFormat::Ewf2Logical,
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    assert_eq!(image.info().format, Format::Ewf2);
    assert!(!image.info().media.media_flags.physical);
    assert_eq!(image.info().logical_size, data.len() as u64);

    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);
}

#[test]
fn writer_creates_readable_ewf2_lx01_single_files_catalog() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("logical-single-files.Lx01");
    let data = b"hello world".to_vec();
    let single_files = SingleFilesInfo {
        root: SingleFileEntry {
            identifier: Some(1),
            file_entry_type: Some(SingleFileEntryType::Directory),
            name: Some("root".to_owned()),
            children: vec![SingleFileEntry {
                identifier: Some(2),
                file_entry_type: Some(SingleFileEntryType::File),
                guid: Some("00112233445566778899aabbccddeeff".to_owned()),
                name: Some("report.txt".to_owned()),
                short_name: Some("REPORT~1.TXT".to_owned()),
                size: Some(data.len() as u64),
                source_identifier: Some(7),
                subject_identifier: Some(3),
                permission_group_index: Some(0),
                extents: vec![SingleFileExtent {
                    data_offset: 0,
                    data_size: data.len() as u64,
                    sparse: false,
                }],
                attributes: vec![SingleFileAttribute {
                    name: Some("Zone.Identifier".to_owned()),
                    value: Some("ZoneId=3".to_owned()),
                }],
                ..SingleFileEntry::default()
            }],
            ..SingleFileEntry::default()
        },
        sources: vec![
            SingleFileSource {
                identifier: Some(0),
                name: Some("root-source".to_owned()),
                ..SingleFileSource::default()
            },
            SingleFileSource {
                identifier: Some(7),
                name: Some("acquired-folder".to_owned()),
                evidence_number: Some("EV-7".to_owned()),
                ..SingleFileSource::default()
            },
        ],
        subjects: vec![
            SingleFileSubject {
                identifier: Some(0),
                name: Some("root-subject".to_owned()),
            },
            SingleFileSubject {
                identifier: Some(3),
                name: Some("desktop-user".to_owned()),
            },
        ],
        permission_groups: vec![SingleFilePermissionGroup {
            name: Some("acl".to_owned()),
            identifier: Some("S-1-5-32-544".to_owned()),
            permissions: vec![SingleFilePermission {
                name: Some("Administrators".to_owned()),
                identifier: Some("S-1-5-32-544".to_owned()),
                access_mask: Some(0x0012_0089),
                ace_flags: Some(0),
                ..SingleFilePermission::default()
            }],
            ..SingleFilePermissionGroup::default()
        }],
        ..SingleFilesInfo::default()
    };
    let options = WriteOptions {
        format: WriteFormat::Ewf2Logical,
        media_profile: WriteMediaProfile {
            media_type: Some(MediaType::SingleFiles),
            ..WriteMediaProfile::default()
        },
        single_files: Some(single_files),
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let bytes = fs::read(&path).unwrap();
    let single_files_data = utf16le_string(ewf2_section_data(&bytes, 0x20));
    assert!(single_files_data.ends_with("\n\n"));
    let category_headers = single_files_data
        .lines()
        .filter(|line| matches!(*line, "5" | "rec" | "perm" | "srce" | "sub" | "entry"))
        .collect::<Vec<_>>();
    assert_eq!(
        category_headers,
        ["5", "rec", "perm", "srce", "sub", "entry"]
    );
    assert!(single_files_data.contains("rec\ntb\n11\n\nperm\n"));
    assert!(single_files_data.contains("n\tpr\ts\tnta\tnti\n"));
    assert!(single_files_data.contains("acl\t10\tS-1-5-32-544"));
    assert!(single_files_data.contains("\n1\tacquired-folder\tEV-7"));
    assert!(single_files_data.contains("mid"));
    assert!(single_files_data.contains("00112233445566778899aabbccddeeff"));
    assert!(single_files_data.contains("13 REPORT~1.TXT"));

    let image = ewf_image::Image::open(&path).unwrap();
    let single_files = image.info().single_files.as_ref().unwrap();
    let child = single_files.entry_by_path("report.txt").unwrap().unwrap();
    let mut decoded = vec![0; data.len()];
    let read = image.read_single_file_at(child, &mut decoded, 0).unwrap();

    assert_eq!(child.file_entry_type, Some(SingleFileEntryType::File));
    assert_eq!(
        child.guid.as_deref(),
        Some("00112233445566778899aabbccddeeff")
    );
    assert_eq!(child.short_name.as_deref(), Some("REPORT~1.TXT"));
    assert_eq!(child.size, Some(data.len() as u64));
    assert_eq!(child.extents.len(), 1);
    assert_eq!(
        child.attributes,
        vec![SingleFileAttribute {
            name: Some("Zone.Identifier".to_owned()),
            value: Some("ZoneId=3".to_owned()),
        }]
    );
    assert_eq!(
        single_files
            .source_for_entry(child)
            .unwrap()
            .name
            .as_deref(),
        Some("acquired-folder")
    );
    assert_eq!(
        image.source_for_file_entry(child).unwrap().name.as_deref(),
        Some("acquired-folder")
    );
    assert_eq!(
        single_files
            .subject_for_entry(child)
            .unwrap()
            .name
            .as_deref(),
        Some("desktop-user")
    );
    assert_eq!(
        image.subject_for_file_entry(child).unwrap().name.as_deref(),
        Some("desktop-user")
    );
    assert_eq!(
        single_files.access_control_entries_for_entry(child)[0]
            .name
            .as_deref(),
        Some("Administrators")
    );
    assert_eq!(
        image.number_of_access_control_entries_for_file_entry(child),
        1
    );
    assert_eq!(
        image
            .access_control_entry_for_file_entry(child, 0)
            .unwrap()
            .name
            .as_deref(),
        Some("Administrators")
    );
    assert!(image.source_for_file_entry(&single_files.root).is_none());
    assert_eq!(read, data.len());
    assert_eq!(decoded, data);
}

#[test]
fn writer_creates_ewf2_lx01_single_files_aux_tables() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("logical-single-files-tables.Lx01");
    let data = b"aux table data".to_vec();
    let single_files_tables = SingleFilesAuxTables {
        table_0x21_entries: vec![0x10, 0x20],
        md5_hashes: vec![[0x11; 16], [0x22; 16]],
        table_0x23_entries: vec![0x30],
    };
    let options = WriteOptions {
        format: WriteFormat::Ewf2Logical,
        ewf2_single_files_tables: single_files_tables.clone(),
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let bytes = fs::read(&path).unwrap();
    assert_eq!(
        ewf2_u64_aux_table_entries(ewf2_section_data(&bytes, 0x21)),
        single_files_tables.table_0x21_entries
    );
    assert_eq!(
        ewf2_md5_aux_table_hashes(ewf2_section_data(&bytes, 0x22)),
        single_files_tables.md5_hashes
    );
    assert_eq!(
        ewf2_u64_aux_table_entries(ewf2_section_data(&bytes, 0x23)),
        single_files_tables.table_0x23_entries
    );

    let image = ewf_image::Image::open(&path).unwrap();

    assert_eq!(image.info().ewf2_single_files_tables, single_files_tables);
}

#[test]
fn writer_creates_readable_ewf2_with_zlib_chunks() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("compressed.Ex01");
    let data = (0..32_768)
        .map(|index| (index % 17) as u8)
        .collect::<Vec<_>>();
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        compression: WriteCompression::Zlib,
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.logical_size, data.len() as u64);
    assert!(fs::metadata(&path).unwrap().len() < data.len() as u64);

    let image = ewf_image::Image::open(&path).unwrap();
    assert_eq!(image.info().format, Format::Ewf2);
    assert_eq!(
        image.info().media.compression_method,
        Some(CompressionMethod::Zlib)
    );

    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);

    let bytes = fs::read(&path).unwrap();
    let table = ewf2_section_data(&bytes, 0x04);
    assert_ewf2_table_checksums(table);
    assert_eq!(
        u32::from_le_bytes(table[44..48].try_into().unwrap()),
        0x0000_0001
    );
    assert_eq!(ewf2_section_data(&bytes, 0x03).first(), Some(&0x78));
}

#[test]
fn writer_uses_configured_zlib_best_level_for_ewf1_chunks() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("zlib-best.E01");
    let data = (0..32_768)
        .map(|index| ((index * 13 + index / 17) % 251) as u8)
        .collect::<Vec<_>>();
    let options = WriteOptions {
        compression: WriteCompression::Zlib,
        compression_values: WriteCompressionValues {
            level: WriteCompressionLevel::Best,
            ..WriteCompressionValues::default()
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);

    let bytes = fs::read(&path).unwrap();
    let sectors = ewf1_section_data(&bytes, b"sectors");
    assert_eq!(&sectors[..2], &[0x78, 0xda]);
}

#[test]
fn writer_uses_configured_zlib_none_level_for_ewf2_chunks() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("zlib-none.Ex01");
    let data = (0..32_768)
        .map(|index| ((index * 29 + 7) % 251) as u8)
        .collect::<Vec<_>>();
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        compression: WriteCompression::Zlib,
        compression_values: WriteCompressionValues {
            level: WriteCompressionLevel::None,
            ..WriteCompressionValues::default()
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);

    let bytes = fs::read(&path).unwrap();
    let sector_data = ewf2_section_data(&bytes, 0x03);
    assert!(sector_data.len() > data.len());
    assert!(
        sector_data
            .windows(128)
            .any(|window| window == &data[..128])
    );
}

#[test]
fn writer_compresses_ewf2_zlib_metadata_sections() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("zlib-metadata.Ex01");
    let data = vec![0x7a; 32_768];
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        compression: WriteCompression::Zlib,
        metadata: EwfMetadata {
            case_number: Some("CASE-ZLIB".to_string()),
            ..EwfMetadata::default()
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let bytes = fs::read(&path).unwrap();
    assert_eq!(ewf2_section_data(&bytes, 0x01).first(), Some(&0x78));
    assert_eq!(ewf2_section_data(&bytes, 0x02).first(), Some(&0x78));

    let image = ewf_image::Image::open(&path).unwrap();

    assert_eq!(
        image.info().metadata.case_number.as_deref(),
        Some("CASE-ZLIB")
    );
}

#[test]
fn writer_creates_ewf2_with_restart_and_analytical_data() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("application-data.Ex01");
    let data = vec![0x61; 4096];
    let analytical_data = "1\nmain\ntps\n123\n\n".to_owned();
    let restart_data = "1\t1\np\td\tsr\tsp\n0\t1\n\n0\t0\n0\t0\t8\t15\n".to_owned();
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        compression: WriteCompression::Zlib,
        ewf2_analytical_data: Some(analytical_data.clone()),
        ewf2_restart_data: Some(restart_data.clone()),
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let bytes = fs::read(&path).unwrap();
    assert_eq!(ewf2_section_data(&bytes, 0x10).first(), Some(&0x78));
    assert_eq!(ewf2_section_data(&bytes, 0x0a).first(), Some(&0x78));

    let image = ewf_image::Image::open(&path).unwrap();

    assert_eq!(
        image.info().ewf2_analytical_data.as_deref(),
        Some(analytical_data.as_str())
    );
    assert_eq!(
        image.info().ewf2_restart_data.as_deref(),
        Some(restart_data.as_str())
    );
    assert_eq!(image.ewf2_analytical_data(), Some(analytical_data.as_str()));
    assert_eq!(image.ewf2_restart_data(), Some(restart_data.as_str()));
}

#[test]
fn writer_creates_ewf2_with_opaque_increment_and_final_information() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("opaque-sections.Ex01");
    let data = vec![0x51; 4096];
    let increment_data = vec![
        b"increment section one".to_vec(),
        b"increment section two".to_vec(),
    ];
    let final_information = b"final information bytes".to_vec();
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        ewf2_increment_data: increment_data.clone(),
        ewf2_final_information: Some(final_information.clone()),
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let bytes = fs::read(&path).unwrap();
    assert_eq!(
        ewf2_sections_data(&bytes, 0x07),
        vec![increment_data[0].as_slice(), increment_data[1].as_slice()]
    );
    assert_eq!(ewf2_section_data(&bytes, 0x0e), final_information);

    let image = ewf_image::Image::open(&path).unwrap();

    assert_eq!(image.info().ewf2_increment_data, increment_data);
    assert_eq!(
        image.info().ewf2_final_information.as_deref(),
        Some(final_information.as_slice())
    );
    assert_eq!(image.number_of_ewf2_increment_data_sections(), 2);
    assert_eq!(image.ewf2_increment_data(), increment_data);
    assert_eq!(
        image.ewf2_increment_data_section(1),
        Some(increment_data[1].as_slice())
    );
    assert_eq!(image.ewf2_increment_data_section(2), None);
    assert_eq!(
        image.ewf2_final_information(),
        Some(final_information.as_slice())
    );
}

#[test]
fn writer_creates_readable_ewf2_with_bzip2_chunks() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("bzip2.Ex01");
    let data = (0..32_768)
        .map(|index| (index % 19) as u8)
        .collect::<Vec<_>>();
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        compression: WriteCompression::Bzip2,
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.logical_size, data.len() as u64);
    assert!(fs::metadata(&path).unwrap().len() < data.len() as u64);

    let image = ewf_image::Image::open(&path).unwrap();
    assert_eq!(image.info().format, Format::Ewf2);
    assert_eq!(
        image.info().media.compression_method,
        Some(CompressionMethod::Bzip2)
    );

    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);

    let bytes = fs::read(&path).unwrap();
    let table = ewf2_section_data(&bytes, 0x04);
    assert_ewf2_table_checksums(table);
    assert_eq!(
        u32::from_le_bytes(table[44..48].try_into().unwrap()),
        0x0000_0001
    );
    assert!(ewf2_section_data(&bytes, 0x03).starts_with(b"BZh"));
}

#[test]
fn writer_uses_configured_bzip2_best_level_for_ewf2_chunks() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("bzip2-best.Ex01");
    let data = (0..32_768)
        .map(|index| ((index * 31 + index / 19) % 251) as u8)
        .collect::<Vec<_>>();
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        compression: WriteCompression::Bzip2,
        compression_values: WriteCompressionValues {
            level: WriteCompressionLevel::Best,
            ..WriteCompressionValues::default()
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);

    let bytes = fs::read(&path).unwrap();
    assert_eq!(&ewf2_section_data(&bytes, 0x03)[..4], b"BZh9");
}

#[test]
fn writer_compresses_ewf2_bzip2_metadata_sections_with_device_info_compatibility() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("bzip2-metadata.Ex01");
    let data = vec![0x62; 32_768];
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        compression: WriteCompression::Bzip2,
        metadata: EwfMetadata {
            case_number: Some("CASE-BZIP2".to_string()),
            ..EwfMetadata::default()
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let bytes = fs::read(&path).unwrap();
    assert_eq!(ewf2_section_data(&bytes, 0x01).first(), Some(&0x78));
    assert!(ewf2_section_data(&bytes, 0x02).starts_with(b"BZh"));

    let image = ewf_image::Image::open(&path).unwrap();

    assert_eq!(
        image.info().metadata.case_number.as_deref(),
        Some("CASE-BZIP2")
    );
}

#[test]
fn writer_rejects_bzip2_for_ewf1() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("bzip2.E01");
    let options = WriteOptions {
        compression: WriteCompression::Bzip2,
        ..WriteOptions::default()
    };

    let err = EwfWriter::create(&path, options).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Unsupported(_)));
}

#[test]
fn writer_rejects_bzip2_none_compression_level() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("bzip2-none.Ex01");
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        compression: WriteCompression::Bzip2,
        compression_values: WriteCompressionValues {
            level: WriteCompressionLevel::None,
            ..WriteCompressionValues::default()
        },
        ..WriteOptions::default()
    };

    let err = EwfWriter::create(&path, options).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Unsupported(_)));
}

#[test]
fn writer_rejects_memory_extents_for_ewf1() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("memory.E01");
    let options = WriteOptions {
        memory_extents: vec![MemoryExtent {
            start_page: 0x1000,
            page_count: 1,
        }],
        ..WriteOptions::default()
    };

    let err = EwfWriter::create(&path, options).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Unsupported(_)));
}

#[test]
fn writer_rejects_ewf2_application_data_for_ewf1() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("application-data.E01");
    let options = WriteOptions {
        ewf2_restart_data: Some("restart".to_owned()),
        ewf2_analytical_data: Some("analytical".to_owned()),
        ..WriteOptions::default()
    };

    let err = EwfWriter::create(&path, options).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Unsupported(_)));
}

#[test]
fn writer_rejects_opaque_ewf2_sections_for_ewf1() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("opaque-sections.E01");
    let options = WriteOptions {
        ewf2_increment_data: vec![b"increment".to_vec()],
        ewf2_final_information: Some(b"final".to_vec()),
        ..WriteOptions::default()
    };

    let err = EwfWriter::create(&path, options).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Unsupported(_)));
}

#[test]
fn writer_rejects_single_files_aux_tables_for_non_lx01() {
    for (format, extension) in [
        (WriteFormat::Ewf1Physical, "E01"),
        (WriteFormat::Ewf2Physical, "Ex01"),
    ] {
        let dir = tempdir().unwrap();
        let path = dir.path().join(format!("single-files-table.{extension}"));
        let options = WriteOptions {
            format,
            ewf2_single_files_tables: SingleFilesAuxTables {
                md5_hashes: vec![[0xaa; 16]],
                ..SingleFilesAuxTables::default()
            },
            ..WriteOptions::default()
        };

        let err = EwfWriter::create(&path, options).unwrap_err();

        assert!(matches!(err, ewf_image::EwfError::Unsupported(_)));
    }
}

#[test]
fn writer_splits_ewf2_output_by_maximum_segment_size() {
    let dir = tempdir().unwrap();
    let first = dir.path().join("split.Ex01");
    let second = dir.path().join("split.Ex02");
    let data: Vec<u8> = (0..65_536).map(|index| (index % 197) as u8).collect();
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        maximum_segment_size: Some(34_500),
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&first, options).unwrap();
    writer.write_all(&data).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.segment_paths, vec![first.clone(), second.clone()]);
    assert_eq!(result.logical_size, data.len() as u64);
    assert_eq!(result.chunk_count, 2);
    assert!(first.exists());
    assert!(second.exists());
    assert!(fs::metadata(&first).unwrap().len() <= 34_500);
    assert!(fs::metadata(&second).unwrap().len() <= 34_500);

    let image = ewf_image::Image::open(&first).unwrap();
    assert_eq!(image.info().format, Format::Ewf2);
    assert_eq!(image.info().segment_count, 2);
    assert_eq!(image.info().segment_paths, result.segment_paths);
    assert_eq!(image.info().logical_size, data.len() as u64);
    assert_eq!(
        image.segment_filename_for_chunk(0).unwrap(),
        first.as_path()
    );
    assert_eq!(
        image.segment_filename_for_offset(1).unwrap(),
        Some(first.as_path())
    );
    assert_eq!(
        image.segment_filename_for_chunk(1).unwrap(),
        second.as_path()
    );
    assert_eq!(
        image.segment_filename_for_offset(32_768).unwrap(),
        Some(second.as_path())
    );

    let mut cursor = image.cursor();
    assert_eq!(cursor.segment_filename().unwrap(), Some(first.as_path()));
    cursor.seek(SeekFrom::Start(32_768)).unwrap();
    assert_eq!(cursor.segment_filename().unwrap(), Some(second.as_path()));
    cursor.seek(SeekFrom::End(0)).unwrap();
    assert_eq!(cursor.segment_filename().unwrap(), None);

    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);

    let first_bytes = fs::read(&first).unwrap();
    let second_bytes = fs::read(&second).unwrap();
    assert!(!ewf2_has_section(&first_bytes, 0x08));
    assert!(!ewf2_has_section(&first_bytes, 0x09));
    assert!(ewf2_has_section(&second_bytes, 0x08));
    assert!(ewf2_has_section(&second_bytes, 0x09));
}

#[test]
fn image_opens_explicit_segment_path_list() {
    let dir = tempdir().unwrap();
    let first = dir.path().join("explicit.Ex01");
    let second = dir.path().join("explicit.Ex02");
    let data: Vec<u8> = (0..65_536).map(|index| (index % 251) as u8).collect();
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        maximum_segment_size: Some(34_500),
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&first, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    fs::write(
        dir.path().join("explicit.Ex03"),
        [
            &[0x45, 0x56, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00][..],
            b"not a real segment",
        ]
        .concat(),
    )
    .unwrap();

    let image = ewf_image::Image::open_segments([first.clone(), second.clone()]).unwrap();

    assert_eq!(image.info().segment_paths, vec![first, second]);
    assert_eq!(image.info().logical_size, data.len() as u64);

    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);
}

#[test]
fn writer_removes_stale_ewf2_segments_when_replacing_existing_output() {
    let dir = tempdir().unwrap();
    let first = dir.path().join("replace.Ex01");
    let second = dir.path().join("replace.Ex02");
    let large: Vec<u8> = (0..65_536).map(|index| (index % 197) as u8).collect();
    let small = b"replacement ewf2 data";
    let split_options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        maximum_segment_size: Some(34_500),
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&first, split_options).unwrap();
    writer.write_all(&large).unwrap();
    writer.finish().unwrap();
    assert!(second.exists());

    let mut writer = EwfWriter::create(
        &first,
        WriteOptions {
            format: WriteFormat::Ewf2Physical,
            overwrite_existing: true,
            ..WriteOptions::default()
        },
    )
    .unwrap();
    writer.write_all(small).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.segment_paths, vec![first.clone()]);
    assert!(!second.exists());

    let image = ewf_image::Image::open(&first).unwrap();
    assert_eq!(image.info().segment_count, 1);
    let mut decoded = vec![0; small.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();
    assert_eq!(read, small.len());
    assert_eq!(decoded, small);
}

#[test]
fn writer_creates_ewf2_with_stored_hashes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("hashed.Ex01");
    let data = vec![0x58; 4096];
    let md5 = [
        0x19, 0xb8, 0xbb, 0xe1, 0xf3, 0x2b, 0x02, 0x5b, 0xd7, 0xd6, 0x3b, 0x08, 0xad, 0x16, 0x07,
        0x7a,
    ];
    let sha1 = [
        0x65, 0x00, 0x95, 0x13, 0x23, 0xa9, 0x03, 0x37, 0xec, 0x3b, 0x08, 0xc0, 0x92, 0x8a, 0xf4,
        0x4f, 0xa0, 0x9d, 0x73, 0xeb,
    ];
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        hashes: WriteHashes {
            md5: Some(md5),
            sha1: Some(sha1),
            ..WriteHashes::default()
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();

    assert_eq!(image.info().stored_hashes.md5, Some(md5));
    assert_eq!(image.info().stored_hashes.sha1, Some(sha1));
    assert_eq!(image.md5_hash(), Some(md5));
    assert_eq!(image.sha1_hash(), Some(sha1));

    let bytes = fs::read(&path).unwrap();
    let md5_section = ewf2_section_data(&bytes, 0x08);
    let sha1_section = ewf2_section_data(&bytes, 0x09);
    assert_eq!(
        u32::from_le_bytes(md5_section[16..20].try_into().unwrap()),
        adler32(&md5_section[..16])
    );
    assert_eq!(
        u32::from_le_bytes(sha1_section[20..24].try_into().unwrap()),
        adler32(&sha1_section[..20])
    );
}

#[test]
fn writer_sets_stored_hashes_after_create() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("set-hashes.Ex01");
    let data = vec![0x59; 4096];
    let md5 = [0x12; 16];
    let sha1 = [0x34; 20];
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();

    assert_eq!(writer.md5_hash(), None);
    assert_eq!(writer.sha1_hash(), None);

    writer.set_md5_hash(md5).unwrap();
    writer.set_sha1_hash(sha1).unwrap();

    assert_eq!(writer.md5_hash(), Some(md5));
    assert_eq!(writer.sha1_hash(), Some(sha1));
    assert_eq!(
        writer.hash_value("MD5"),
        Some("12121212121212121212121212121212")
    );
    assert_eq!(
        writer.hash_value("SHA1"),
        Some("3434343434343434343434343434343434343434")
    );

    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();

    assert_eq!(image.md5_hash(), Some(md5));
    assert_eq!(image.sha1_hash(), Some(sha1));
    assert_eq!(
        image.hash_value("MD5"),
        Some("12121212121212121212121212121212")
    );
    assert_eq!(
        image.hash_value("SHA1"),
        Some("3434343434343434343434343434343434343434")
    );
}

#[test]
fn writer_rejects_changing_direct_hashes_once_set() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("duplicate-direct-hashes.Ex01");
    let first_md5 = [0x12; 16];
    let second_md5 = [0x56; 16];
    let first_sha1 = [0x34; 20];
    let second_sha1 = [0x78; 20];
    let mut writer = EwfWriter::create(
        &path,
        WriteOptions {
            format: WriteFormat::Ewf2Physical,
            ..WriteOptions::default()
        },
    )
    .unwrap();

    writer.set_md5_hash(first_md5).unwrap();
    writer.set_sha1_hash(first_sha1).unwrap();

    assert!(matches!(
        writer.set_md5_hash(second_md5).unwrap_err(),
        ewf_image::EwfError::Unsupported(message) if message.contains("MD5 hash cannot be changed")
    ));
    assert!(matches!(
        writer.set_sha1_hash(second_sha1).unwrap_err(),
        ewf_image::EwfError::Unsupported(message) if message.contains("SHA1 hash cannot be changed")
    ));
    assert_eq!(writer.md5_hash(), Some(first_md5));
    assert_eq!(writer.sha1_hash(), Some(first_sha1));
    assert_eq!(
        writer.hash_value("MD5"),
        Some("12121212121212121212121212121212")
    );
    assert_eq!(
        writer.hash_value("SHA1"),
        Some("3434343434343434343434343434343434343434")
    );
}

#[test]
fn writer_sets_header_and_hash_values_after_create() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("direct-values.E01");
    let data = vec![0x76; 4096];
    let md5 = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();

    assert_eq!(writer.number_of_header_values(), 0);
    assert_eq!(writer.header_value_identifier(0), None);
    assert_eq!(writer.header_value("case_number"), None);
    assert_eq!(writer.number_of_hash_values(), 0);
    assert_eq!(writer.hash_value_identifier(0), None);
    assert_eq!(writer.hash_value("MD5"), None);

    assert_eq!(writer.set_header_value("case_number", "CASE-DIRECT"), None);
    assert_eq!(
        writer.set_header_value("custom_field", "custom value"),
        None
    );
    assert_eq!(writer.set_hash_value("SHA256", sha256).unwrap(), None);
    assert_eq!(
        writer
            .set_hash_value("MD5", "0123456789abcdeffedcba9876543210")
            .unwrap(),
        None
    );

    assert_eq!(writer.number_of_header_values(), 2);
    assert_eq!(writer.header_value_identifier(0), Some("case_number"));
    assert_eq!(writer.header_value_identifier(1), Some("custom_field"));
    assert_eq!(writer.header_value_identifier(2), None);
    assert_eq!(
        writer.header_value("case_number").as_deref(),
        Some("CASE-DIRECT")
    );
    assert_eq!(
        writer.header_value("custom_field").as_deref(),
        Some("custom value")
    );
    assert_eq!(writer.number_of_hash_values(), 2);
    assert_eq!(writer.hash_value_identifier(0), Some("MD5"));
    assert_eq!(writer.hash_value_identifier(1), Some("SHA256"));
    assert_eq!(writer.hash_value_identifier(2), None);
    assert_eq!(
        writer.hash_value("MD5"),
        Some("0123456789abcdeffedcba9876543210")
    );
    assert_eq!(writer.hash_value("SHA256"), Some(sha256));
    assert_eq!(writer.md5_hash(), Some(md5));

    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    let metadata = &image.info().metadata;
    let hashes = &image.info().stored_hashes;

    assert_eq!(metadata.header_value("case_number"), Some("CASE-DIRECT"));
    assert_eq!(metadata.header_value("custom_field"), Some("custom value"));
    assert_eq!(hashes.md5, Some(md5));
    assert_eq!(
        hashes.hash_value("MD5"),
        Some("0123456789abcdeffedcba9876543210")
    );
    assert_eq!(hashes.hash_value("SHA256"), Some(sha256));
}

#[test]
fn writer_exposes_compatibility_style_header_encoding_controls() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("header-controls.E01");
    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();

    assert_eq!(writer.header_codepage(), HeaderCodepage::Ascii);
    assert_eq!(writer.header_values_date_format(), HeaderDateFormat::Ctime);

    writer.set_header_codepage(HeaderCodepage::Windows1252);
    writer.set_header_values_date_format(HeaderDateFormat::Iso8601);

    assert_eq!(writer.header_codepage(), HeaderCodepage::Windows1252);
    assert_eq!(
        writer.header_values_date_format(),
        HeaderDateFormat::Iso8601
    );

    writer.write_all(&vec![0x7a; 1024]).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open_with_options(
        &path,
        ewf_image::OpenOptions::default()
            .with_header_codepage(HeaderCodepage::Windows1252)
            .with_header_values_date_format(HeaderDateFormat::Iso8601),
    )
    .unwrap();

    assert_eq!(image.info().header_codepage, HeaderCodepage::Windows1252);
    assert_eq!(
        image.info().header_values_date_format,
        HeaderDateFormat::Iso8601
    );
    assert_eq!(image.header_codepage(), HeaderCodepage::Windows1252);
    assert_eq!(image.header_values_date_format(), HeaderDateFormat::Iso8601);
}

#[test]
fn reader_applies_configured_header_date_format_to_legacy_dates() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("header-date-format.E01");
    let options = WriteOptions {
        metadata: EwfMetadata {
            acquisition_date: Some("2026 06 27 14 05 06".to_string()),
            system_date: Some("2026 06 27 15 06 07".to_string()),
            ..EwfMetadata::default()
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&vec![0x48; 1024]).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open_with_options(
        &path,
        ewf_image::OpenOptions::default()
            .with_header_values_date_format(HeaderDateFormat::DayMonth),
    )
    .unwrap();

    assert_eq!(
        image.header_value("acquiry_date").as_deref(),
        Some("27/06/2026 14:05:06")
    );
    assert_eq!(
        image.header_value("system_date").as_deref(),
        Some("27/06/2026 15:06:07")
    );
}

#[test]
fn writer_applies_configured_header_date_format_to_header_value_getters() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("writer-date-format.E01");
    let options = WriteOptions {
        header_values_date_format: HeaderDateFormat::Iso8601,
        metadata: EwfMetadata {
            acquisition_date: Some("2026 06 27 14 05 06".to_string()),
            system_date: Some("2026 06 27 15 06 07".to_string()),
            ..EwfMetadata::default()
        },
        ..WriteOptions::default()
    };
    let writer = EwfWriter::create(&path, options).unwrap();

    assert_eq!(
        writer.header_value("acquiry_date").as_deref(),
        Some("2026-06-27T14:05:06")
    );
    assert_eq!(
        writer.header_value("system_date").as_deref(),
        Some("2026-06-27T15:06:07")
    );

    let mut writer = writer;
    writer.set_header_values_date_format(HeaderDateFormat::MonthDay);
    assert_eq!(
        writer.header_value("acquiry_date").as_deref(),
        Some("06/27/2026 14:05:06")
    );

    writer.set_header_values_date_format(HeaderDateFormat::Ctime);
    assert_eq!(
        writer.header_value("acquiry_date").as_deref(),
        Some("Sat Jun 27 14:05:06 2026")
    );
}

#[test]
fn writer_copies_compatibility_style_header_values_from_source_image() {
    let dir = tempdir().unwrap();
    let source_path = dir.path().join("source-headers.E01");
    let target_path = dir.path().join("target-headers.E01");
    let data = vec![0x31; 4096];
    let mut source_header_values = BTreeMap::new();
    source_header_values.insert("custom_field".to_string(), "source custom".to_string());
    source_header_values.insert("model".to_string(), "Source Model".to_string());
    let source_options = WriteOptions {
        metadata: EwfMetadata {
            case_number: Some("CASE-SOURCE".to_string()),
            examiner: Some("Source Examiner".to_string()),
            acquisition_software: Some("source tool".to_string()),
            header_values: source_header_values,
            ..EwfMetadata::default()
        },
        ..WriteOptions::default()
    };

    let mut source_writer = EwfWriter::create(&source_path, source_options).unwrap();
    source_writer.write_all(&data).unwrap();
    source_writer.finish().unwrap();
    let source = ewf_image::Image::open(&source_path).unwrap();

    let mut stale_options = WriteOptions {
        metadata: EwfMetadata {
            case_number: Some("CASE-STALE".to_string()),
            examiner: Some("Stale Examiner".to_string()),
            notes: Some("remove me".to_string()),
            ..EwfMetadata::default()
        },
        ..WriteOptions::default()
    };
    stale_options
        .metadata
        .set_header_value("stale_field", "stale value");

    stale_options.copy_header_values_from_info(source.info());

    assert_eq!(
        stale_options.metadata.header_value("case_number"),
        Some("CASE-SOURCE")
    );
    assert_eq!(
        stale_options.metadata.header_value("examiner_name"),
        Some("Source Examiner")
    );
    assert_eq!(
        stale_options.metadata.header_value("acquiry_software"),
        Some("source tool")
    );
    assert_eq!(
        stale_options.metadata.header_value("custom_field"),
        Some("source custom")
    );
    assert_eq!(
        stale_options.metadata.header_value("model"),
        Some("Source Model")
    );
    assert_eq!(stale_options.metadata.header_value("notes"), None);
    assert_eq!(stale_options.metadata.header_value("stale_field"), None);

    let mut target_writer = EwfWriter::create(&target_path, WriteOptions::default()).unwrap();
    target_writer.set_header_value("case_number", "CASE-STALE");
    target_writer.set_header_value("stale_field", "stale value");
    target_writer.copy_header_values_from_image(&source);

    assert_eq!(
        target_writer.header_value("case_number").as_deref(),
        Some("CASE-SOURCE")
    );
    assert_eq!(
        target_writer.header_value("examiner_name").as_deref(),
        Some("Source Examiner")
    );
    assert_eq!(
        target_writer.header_value("custom_field").as_deref(),
        Some("source custom")
    );
    assert_eq!(target_writer.header_value("stale_field"), None);

    target_writer.write_all(&data).unwrap();
    target_writer.finish().unwrap();

    let target = ewf_image::Image::open(&target_path).unwrap();
    assert_eq!(
        target.header_value("case_number").as_deref(),
        Some("CASE-SOURCE")
    );
    assert_eq!(
        target.header_value("examiner_name").as_deref(),
        Some("Source Examiner")
    );
    assert_eq!(
        target.header_value("custom_field").as_deref(),
        Some("source custom")
    );
    assert_eq!(
        target.header_value("model").as_deref(),
        Some("Source Model")
    );
    assert_eq!(target.header_value("stale_field"), None);
}

#[test]
fn writer_creates_ewf2_with_case_metadata() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("metadata.Ex01");
    let data = vec![0x63; 4096];
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        metadata: EwfMetadata {
            case_number: Some("CASE-EWF2".to_string()),
            evidence_number: Some("EVID-EWF2".to_string()),
            examiner: Some("Examiner Two".to_string()),
            description: Some("EWF2 disk image".to_string()),
            notes: Some("EWF2 metadata test".to_string()),
            acquisition_software: Some("ewf crate".to_string()),
            acquisition_software_version: Some("0.1.0".to_string()),
            os_version: Some("Linux".to_string()),
            acquisition_date: Some("2026-06-27T14:00:00Z".to_string()),
            system_date: Some("2026-06-27T14:30:00Z".to_string()),
            password: Some("typed-secret".to_string()),
            ..EwfMetadata::default()
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    let metadata = &image.info().metadata;

    assert_eq!(metadata.case_number.as_deref(), Some("CASE-EWF2"));
    assert_eq!(metadata.evidence_number.as_deref(), Some("EVID-EWF2"));
    assert_eq!(metadata.examiner.as_deref(), Some("Examiner Two"));
    assert_eq!(metadata.description.as_deref(), Some("EWF2 disk image"));
    assert_eq!(metadata.notes.as_deref(), Some("EWF2 metadata test"));
    assert_eq!(metadata.acquisition_software.as_deref(), Some("ewf crate"));
    assert_eq!(
        metadata.acquisition_software_version.as_deref(),
        Some("0.1.0")
    );
    assert_eq!(metadata.os_version.as_deref(), Some("Linux"));
    assert_eq!(metadata.password.as_deref(), Some("typed-secret"));
    assert_eq!(
        metadata
            .header_values
            .get("case_number")
            .map(String::as_str),
        Some("CASE-EWF2")
    );
}

#[test]
fn writer_uses_case_data_tags_for_ewf2_metadata() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("case-tags.Ex01");
    let data = vec![0x64; 4096];
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        metadata: EwfMetadata {
            description: Some("Canonical case data".to_string()),
            case_number: Some("CASE-TAGS".to_string()),
            evidence_number: Some("EVID-TAGS".to_string()),
            examiner: Some("Case Examiner".to_string()),
            notes: Some("Case notes".to_string()),
            acquisition_software_version: Some("1.2.3".to_string()),
            os_version: Some("Linux".to_string()),
            acquisition_date: Some("2026-06-27T14:00:00Z".to_string()),
            system_date: Some("2026-06-27T14:30:00Z".to_string()),
            ..EwfMetadata::default()
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let bytes = fs::read(&path).unwrap();
    let mut decoded = Vec::new();
    ZlibDecoder::new(ewf2_section_data(&bytes, 0x02))
        .read_to_end(&mut decoded)
        .unwrap();
    let case_data = utf16le_string(&decoded);
    let tags = case_data
        .lines()
        .nth(2)
        .unwrap()
        .split('\t')
        .collect::<Vec<_>>();

    for expected in ["nm", "cn", "en", "ex", "nt", "av", "os", "tt", "at"] {
        assert!(
            tags.contains(&expected),
            "missing EWF2 case data tag {expected}"
        );
    }
    for unexpected in ["de", "ov", "ad", "sd", "description", "system_date"] {
        assert!(
            !tags.contains(&unexpected),
            "wrote non-canonical EWF2 case data tag {unexpected}"
        );
    }
}

#[test]
fn writer_uses_case_data_object_count_for_ewf2_metadata() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("case-object-count.Ex01");
    let data = vec![0x66; 4096];
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        metadata: EwfMetadata {
            case_number: Some("CASE-OBJECT".to_string()),
            ..EwfMetadata::default()
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let bytes = fs::read(&path).unwrap();
    let mut decoded = Vec::new();
    ZlibDecoder::new(ewf2_section_data(&bytes, 0x02))
        .read_to_end(&mut decoded)
        .unwrap();
    let case_data = utf16le_string(&decoded);
    let lines = case_data.lines().collect::<Vec<_>>();

    assert_eq!(lines.first().copied(), Some("1"));
    assert_eq!(lines.get(1).copied(), Some("main"));
}

#[test]
fn writer_uses_case_data_media_fields_for_ewf2_metadata() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("case-media-fields.Ex01");
    let data = vec![0x67; 4096];
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        sectors_per_chunk: 4,
        media_profile: WriteMediaProfile {
            error_granularity: Some(8),
            fastbloc: true,
            tableau: true,
            ..WriteMediaProfile::default()
        },
        metadata: EwfMetadata {
            case_number: Some("CASE-MEDIA".to_string()),
            ..EwfMetadata::default()
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let bytes = fs::read(&path).unwrap();
    let mut decoded = Vec::new();
    ZlibDecoder::new(ewf2_section_data(&bytes, 0x02))
        .read_to_end(&mut decoded)
        .unwrap();
    let case_data = utf16le_string(&decoded);
    let lines = case_data.lines().collect::<Vec<_>>();
    let tags = lines[2].split('\t').collect::<Vec<_>>();
    let values = lines[3].split('\t').collect::<Vec<_>>();
    let value_for = |tag: &str| {
        tags.iter()
            .position(|candidate| *candidate == tag)
            .and_then(|index| values.get(index))
            .copied()
    };

    assert_eq!(value_for("tb"), Some("2"));
    assert_eq!(value_for("sb"), Some("4"));
    assert_eq!(value_for("gr"), Some("8"));
    assert_eq!(value_for("wb"), Some("3"));
}

#[test]
fn writer_emits_ewf2_case_data_without_user_metadata() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("default-case-data.Ex01");
    let data = vec![0x68; 4096];
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let bytes = fs::read(&path).unwrap();
    let mut decoded = Vec::new();
    ZlibDecoder::new(ewf2_section_data(&bytes, 0x02))
        .read_to_end(&mut decoded)
        .unwrap();
    let case_data = utf16le_string(&decoded);
    let lines = case_data.lines().collect::<Vec<_>>();
    let tags = lines[2].split('\t').collect::<Vec<_>>();
    let values = lines[3].split('\t').collect::<Vec<_>>();
    let value_for = |tag: &str| {
        tags.iter()
            .position(|candidate| *candidate == tag)
            .and_then(|index| values.get(index))
            .copied()
    };

    assert_eq!(lines.first().copied(), Some("1"));
    assert_eq!(lines.get(1).copied(), Some("main"));
    assert_eq!(
        tags,
        [
            "nm", "cn", "en", "ex", "nt", "av", "os", "tt", "at", "tb", "cp", "sb", "gr", "wb"
        ]
    );
    assert_eq!(value_for("tb"), Some("1"));
    assert_eq!(value_for("cp"), Some(""));
    assert_eq!(value_for("sb"), Some("64"));
    assert_eq!(value_for("gr"), Some("0"));
    assert_eq!(value_for("wb"), Some(""));
}

#[test]
fn writer_uses_device_information_tags_for_ewf2_metadata() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("device-tags.Ex01");
    let data = vec![0x65; 4096];
    let header_values = BTreeMap::from([
        ("device_label".to_string(), "Disk Label".to_string()),
        ("model".to_string(), "Model X".to_string()),
        ("process_identifier".to_string(), "4242".to_string()),
        ("serial_number".to_string(), "SN-001".to_string()),
    ]);
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        metadata: EwfMetadata {
            header_values,
            ..EwfMetadata::default()
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let bytes = fs::read(&path).unwrap();
    let mut decoded = Vec::new();
    ZlibDecoder::new(ewf2_section_data(&bytes, 0x01))
        .read_to_end(&mut decoded)
        .unwrap();
    let device_information = utf16le_string(&decoded);
    let lines = device_information.lines().collect::<Vec<_>>();
    assert_eq!(lines.first().copied(), Some("1"));
    let tags = lines[2].split('\t').collect::<Vec<_>>();
    let values = lines[3].split('\t').collect::<Vec<_>>();

    for expected in ["sn", "md", "lb", "ts", "dt", "pid", "bp", "ph"] {
        assert!(
            tags.contains(&expected),
            "missing EWF2 device information tag {expected}"
        );
    }
    for unexpected in [
        "serial_number",
        "model",
        "device_label",
        "process_identifier",
    ] {
        assert!(
            !tags.contains(&unexpected),
            "wrote reserved identifier {unexpected} as an EWF2 device information tag"
        );
    }

    let value_for = |tag: &str| {
        tags.iter()
            .position(|candidate| *candidate == tag)
            .and_then(|index| values.get(index))
            .copied()
    };
    assert_eq!(value_for("sn"), Some("SN-001"));
    assert_eq!(value_for("md"), Some("Model X"));
    assert_eq!(value_for("lb"), Some("Disk Label"));
    assert_eq!(value_for("pid"), Some("4242"));
}

#[test]
fn writer_uses_default_drive_type_for_ewf2_device_information() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("default-drive-type.Ex01");
    let data = vec![0x69; 4096];
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let bytes = fs::read(&path).unwrap();
    let mut decoded = Vec::new();
    ZlibDecoder::new(ewf2_section_data(&bytes, 0x01))
        .read_to_end(&mut decoded)
        .unwrap();
    let device_information = utf16le_string(&decoded);
    let lines = device_information.lines().collect::<Vec<_>>();
    let tags = lines[2].split('\t').collect::<Vec<_>>();
    let values = lines[3].split('\t').collect::<Vec<_>>();
    let value_for = |tag: &str| {
        tags.iter()
            .position(|candidate| *candidate == tag)
            .and_then(|index| values.get(index))
            .copied()
    };

    assert_eq!(value_for("dt"), Some("r"));

    let image = ewf_image::Image::open(&path).unwrap();
    assert_eq!(image.media_type(), Some(MediaType::Removable));
}

#[test]
fn writer_creates_e01_with_acquisition_errors() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("errors.E01");
    let data = vec![0x3e; 4096];
    let errors = vec![AcquisitionError {
        first_sector: 42,
        sector_count: 7,
    }];
    let options = WriteOptions {
        acquisition_errors: errors.clone(),
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();

    assert_eq!(image.info().acquisition_errors, errors);
    assert_eq!(image.acquisition_errors(), errors.as_slice());
    assert_eq!(image.number_of_acquisition_errors(), 1);
    assert_eq!(image.acquisition_error(0), Some(&errors[0]));
    assert_eq!(image.acquisition_error(1), None);

    let bytes = fs::read(&path).unwrap();
    let error2 = ewf1_section_data(&bytes, b"error2");
    let entries_start = 520;
    let entries_end = entries_start + errors.len() * 8;
    assert_eq!(error2.len(), entries_end + 4);
    assert_eq!(
        u32::from_le_bytes(error2[516..520].try_into().unwrap()),
        adler32(&error2[..516])
    );
    assert_eq!(
        u32::from_le_bytes(error2[entries_end..entries_end + 4].try_into().unwrap()),
        adler32(&error2[entries_start..entries_end])
    );
}

#[test]
fn writer_creates_ewf2_with_acquisition_errors() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("errors.Ex01");
    let data = vec![0x3f; 4096];
    let errors = vec![AcquisitionError {
        first_sector: 0x1_0000_002a,
        sector_count: 7,
    }];
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        acquisition_errors: errors.clone(),
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();

    assert_eq!(image.info().acquisition_errors, errors);

    let bytes = fs::read(&path).unwrap();
    let error_table = ewf2_section_data(&bytes, 0x05);
    let entries_start = 32;
    let entries_end = entries_start + errors.len() * 16;
    assert_eq!(error_table.len(), entries_end + 16);
    assert_eq!(
        u32::from_le_bytes(error_table[16..20].try_into().unwrap()),
        adler32(&error_table[..16])
    );
    assert_eq!(
        u32::from_le_bytes(
            error_table[entries_end..entries_end + 4]
                .try_into()
                .unwrap()
        ),
        adler32(&error_table[entries_start..entries_end])
    );
}

#[test]
fn writer_appends_acquisition_errors_sessions_and_tracks() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("appended-ranges.Ex01");
    let data = vec![0x48; 4096];
    let errors = vec![AcquisitionError {
        first_sector: 2,
        sector_count: 1,
    }];
    let sessions = vec![
        SectorRange {
            first_sector: 0,
            sector_count: 4,
        },
        SectorRange {
            first_sector: 4,
            sector_count: 4,
        },
    ];
    let tracks = vec![
        SectorRange {
            first_sector: 0,
            sector_count: 4,
        },
        SectorRange {
            first_sector: 4,
            sector_count: 4,
        },
    ];
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.append_acquisition_error(2, 1).unwrap();
    writer.append_session(0, 4).unwrap();
    writer.append_session(4, 4).unwrap();
    writer.append_track(0, 4).unwrap();
    writer.append_track(4, 4).unwrap();

    assert_eq!(writer.acquisition_errors(), errors.as_slice());
    assert_eq!(writer.number_of_acquisition_errors(), 1);
    assert_eq!(writer.acquisition_error(0), Some(&errors[0]));
    assert_eq!(writer.acquisition_error(1), None);
    assert_eq!(writer.sessions(), sessions.as_slice());
    assert_eq!(writer.number_of_sessions(), 2);
    assert_eq!(writer.session(1), Some(&sessions[1]));
    assert_eq!(writer.tracks(), tracks.as_slice());
    assert_eq!(writer.number_of_tracks(), 2);
    assert_eq!(writer.track(1), Some(&tracks[1]));

    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();

    assert_eq!(image.info().acquisition_errors, errors);
    assert_eq!(image.info().sessions, sessions);
    assert_eq!(image.info().tracks, tracks);
}

#[test]
fn writer_rejects_session_and_track_values_above_signed_64_bit_range() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("oversized-ranges.Ex01");
    let too_large = i64::MAX as u64 + 1;
    let mut writer = EwfWriter::create(
        &path,
        WriteOptions {
            format: WriteFormat::Ewf2Physical,
            ..WriteOptions::default()
        },
    )
    .unwrap();

    assert!(matches!(
        writer.append_session(too_large, 1).unwrap_err(),
        ewf_image::EwfError::Unsupported(message) if message.contains("session start sector exceeds signed 64-bit range")
    ));
    assert!(matches!(
        writer.append_session(0, too_large).unwrap_err(),
        ewf_image::EwfError::Unsupported(message) if message.contains("session sector count exceeds signed 64-bit range")
    ));
    assert!(matches!(
        writer.append_track(too_large, 1).unwrap_err(),
        ewf_image::EwfError::Unsupported(message) if message.contains("track start sector exceeds signed 64-bit range")
    ));
    assert!(matches!(
        writer.append_track(0, too_large).unwrap_err(),
        ewf_image::EwfError::Unsupported(message) if message.contains("track sector count exceeds signed 64-bit range")
    ));
    assert_eq!(writer.sessions(), []);
    assert_eq!(writer.tracks(), []);
}

#[test]
fn writer_tracks_configured_checksum_errors() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("configured-checksum-errors.E01");
    let checksum_errors = vec![
        SectorRange {
            first_sector: 3,
            sector_count: 2,
        },
        SectorRange {
            first_sector: 9,
            sector_count: 1,
        },
    ];
    let options = WriteOptions {
        checksum_errors: checksum_errors.clone(),
        ..WriteOptions::default()
    };

    let writer = EwfWriter::create(&path, options).unwrap();

    assert_eq!(writer.checksum_errors(), checksum_errors.as_slice());
    assert_eq!(writer.number_of_checksum_errors(), 2);
    assert_eq!(writer.checksum_error(0), Some(&checksum_errors[0]));
    assert_eq!(writer.checksum_error(1), Some(&checksum_errors[1]));
    assert_eq!(writer.checksum_error(2), None);
}

#[test]
fn writer_appends_checksum_errors_without_authored_acquisition_errors() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("appended-checksum-errors.E01");
    let data = vec![0x49; 4096];
    let checksum_errors = vec![SectorRange {
        first_sector: 4,
        sector_count: 2,
    }];

    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();
    writer.append_checksum_error(4, 2).unwrap();

    assert_eq!(writer.checksum_errors(), checksum_errors.as_slice());
    assert_eq!(writer.number_of_checksum_errors(), 1);
    assert_eq!(writer.checksum_error(0), Some(&checksum_errors[0]));
    assert_eq!(writer.checksum_error(1), None);

    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();

    assert_eq!(image.info().acquisition_errors, []);
    assert_eq!(image.number_of_checksum_errors().unwrap(), 0);
}

#[test]
fn writer_creates_ewf2_with_sessions() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("sessions.Ex01");
    let data = vec![0x51; 4096];
    let sessions = vec![
        SectorRange {
            first_sector: 0,
            sector_count: 4,
        },
        SectorRange {
            first_sector: 4,
            sector_count: 4,
        },
    ];
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        sessions: sessions.clone(),
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    let bytes = fs::read(&path).unwrap();

    assert_eq!(image.info().sessions, sessions);
    assert_eq!(image.info().tracks, []);
    assert_eq!(image.sessions(), sessions.as_slice());
    assert_eq!(image.number_of_sessions(), 2);
    assert_eq!(image.session(1), Some(&sessions[1]));
    assert_eq!(image.session(2), None);
    assert_eq!(image.tracks(), []);
    assert_eq!(image.number_of_tracks(), 0);
    assert_eq!(image.track(0), None);
    assert_eq!(ewf2_section_data(&bytes, 0x06).len(), 32 + 2 * 32 + 16);
}

#[test]
fn writer_creates_e01_with_sessions() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("sessions.E01");
    let data = vec![0x31; 4096];
    let sessions = vec![
        SectorRange {
            first_sector: 0,
            sector_count: 4,
        },
        SectorRange {
            first_sector: 4,
            sector_count: 4,
        },
    ];
    let options = WriteOptions {
        sessions: sessions.clone(),
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();

    assert_eq!(image.info().sessions, sessions);
    assert_eq!(image.info().tracks, []);
}

#[test]
fn writer_creates_e01_with_sessions_and_tracks() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("sessions-and-tracks.E01");
    let data = vec![0x32; 4096];
    let sessions = vec![
        SectorRange {
            first_sector: 0,
            sector_count: 4,
        },
        SectorRange {
            first_sector: 4,
            sector_count: 4,
        },
    ];
    let tracks = vec![
        SectorRange {
            first_sector: 0,
            sector_count: 4,
        },
        SectorRange {
            first_sector: 4,
            sector_count: 4,
        },
    ];
    let options = WriteOptions {
        sessions: sessions.clone(),
        tracks: tracks.clone(),
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();

    assert_eq!(image.info().sessions, sessions);
    assert_eq!(image.info().tracks, tracks);
}

#[test]
fn writer_rejects_non_contiguous_tracks() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("tracks.Ex01");
    let data = vec![0x74; 4096];
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        tracks: vec![SectorRange {
            first_sector: 4,
            sector_count: 4,
        }],
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();

    let err = writer.finish().unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Unsupported(_)));
}

#[test]
fn writer_creates_ewf2_with_tracks() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("tracks.Ex01");
    let data = vec![0x72; 4096];
    let tracks = vec![
        SectorRange {
            first_sector: 0,
            sector_count: 4,
        },
        SectorRange {
            first_sector: 4,
            sector_count: 4,
        },
    ];
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        tracks: tracks.clone(),
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();

    assert_eq!(image.info().tracks, tracks);
    assert_eq!(image.tracks(), tracks.as_slice());
    assert_eq!(image.number_of_tracks(), 2);
    assert_eq!(image.track(1), Some(&tracks[1]));
    assert_eq!(image.track(2), None);
    assert_eq!(
        image.info().sessions,
        [SectorRange {
            first_sector: 0,
            sector_count: 8,
        }]
    );
    assert_eq!(image.number_of_sessions(), 1);
}

#[test]
fn writer_creates_ewf2_with_sessions_and_tracks() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("sessions-and-tracks.Ex01");
    let data = vec![0x73; 4096];
    let sessions = vec![
        SectorRange {
            first_sector: 0,
            sector_count: 4,
        },
        SectorRange {
            first_sector: 4,
            sector_count: 4,
        },
    ];
    let tracks = vec![
        SectorRange {
            first_sector: 0,
            sector_count: 4,
        },
        SectorRange {
            first_sector: 4,
            sector_count: 4,
        },
    ];
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        sessions: sessions.clone(),
        tracks: tracks.clone(),
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();

    assert_eq!(image.info().sessions, sessions);
    assert_eq!(image.info().tracks, tracks);
}

#[test]
fn writer_creates_ewf2_with_media_profile() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("profile.Ex01");
    let data = vec![0x70; 4096];
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        media_profile: WriteMediaProfile {
            media_type: Some(MediaType::Fixed),
            error_granularity: Some(8),
            fastbloc: true,
            tableau: true,
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    let media = &image.info().media;

    assert_eq!(media.media_type, Some(MediaType::Fixed));
    assert_eq!(media.error_granularity, Some(8));
    assert_eq!(
        media.media_flags,
        MediaFlags {
            physical: true,
            fastbloc: true,
            tableau: true,
        }
    );
}

#[test]
fn writer_creates_ewf2_with_memory_extents() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("memory.Ex01");
    let data = vec![0x6d; 4096];
    let memory_extents = vec![
        MemoryExtent {
            start_page: 0x1000,
            page_count: 7,
        },
        MemoryExtent {
            start_page: 0x2000,
            page_count: 11,
        },
    ];
    let options = WriteOptions {
        format: WriteFormat::Ewf2Physical,
        media_profile: WriteMediaProfile {
            media_type: Some(MediaType::Memory),
            ..WriteMediaProfile::default()
        },
        memory_extents: memory_extents.clone(),
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let bytes = fs::read(&path).unwrap();
    assert_eq!(ewf2_section_data(&bytes, 0x0c).len(), 32);

    let image = ewf_image::Image::open(&path).unwrap();
    assert_eq!(image.info().media.media_type, Some(MediaType::Memory));
    assert_eq!(image.info().memory_extents, memory_extents);
}

#[test]
fn writer_creates_e01_with_media_profile() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("profile.E01");
    let data = vec![0x71; 4096];
    let options = WriteOptions {
        media_profile: WriteMediaProfile {
            media_type: Some(MediaType::Fixed),
            error_granularity: Some(8),
            fastbloc: true,
            tableau: true,
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    let media = &image.info().media;

    assert_eq!(media.media_type, Some(MediaType::Fixed));
    assert_eq!(media.error_granularity, Some(8));
    assert_eq!(
        media.media_flags,
        MediaFlags {
            physical: true,
            fastbloc: true,
            tableau: true,
        }
    );
}

#[test]
fn writer_splits_e01_output_by_maximum_segment_size() {
    let dir = tempdir().unwrap();
    let first = dir.path().join("split.E01");
    let second = dir.path().join("split.E02");
    let data: Vec<u8> = (0..65_536).map(|index| (index % 193) as u8).collect();
    let options = WriteOptions {
        maximum_segment_size: Some(34_500),
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&first, options).unwrap();
    writer.write_all(&data).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.segment_paths, vec![first.clone(), second.clone()]);
    assert_eq!(result.logical_size, data.len() as u64);
    assert_eq!(result.chunk_count, 2);
    assert!(first.exists());
    assert!(second.exists());

    let image = ewf_image::Image::open(&first).unwrap();
    assert_eq!(image.info().segment_count, 2);
    assert_eq!(image.info().segment_paths, result.segment_paths);
    assert_eq!(image.info().logical_size, data.len() as u64);

    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);
}

#[test]
fn writer_emits_multiple_table_groups_in_one_e01_segment() {
    // FTK-style non-segmented images store many sectors/table groups in one
    // segment file. Force multiple groups by exceeding the per-table entry cap
    // (16375) with small chunks instead of writing multi-gigabyte payloads.
    let dir = tempdir().unwrap();
    let first = dir.path().join("groups.E01");
    let chunk_count = 16_380_usize;
    let data: Vec<u8> = (0..chunk_count * 512)
        .map(|index| (index % 251) as u8)
        .collect();
    let options = WriteOptions {
        sectors_per_chunk: 1,
        bytes_per_sector: 512,
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&first, options).unwrap();
    writer.write_all(&data).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.segment_paths, vec![first.clone()]);
    assert_eq!(result.chunk_count, chunk_count as u64);

    let bytes = fs::read(&first).unwrap();
    let section_types = ewf1_section_types(&bytes);
    let table_count = section_types
        .iter()
        .filter(|section| section.as_str() == "table")
        .count();
    let sectors_count = section_types
        .iter()
        .filter(|section| section.as_str() == "sectors")
        .count();
    assert_eq!(table_count, 2);
    assert_eq!(sectors_count, 2);

    let image = ewf_image::Image::open(&first).unwrap();
    assert_eq!(image.info().segment_count, 1);
    assert_eq!(image.info().logical_size, data.len() as u64);

    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);
}

#[test]
fn writer_finishes_split_e01_to_supplied_segment_writers() {
    let first = std::path::PathBuf::from("streamed-split.E01");
    let second = std::path::PathBuf::from("streamed-split.E02");
    let data: Vec<u8> = (0..65_536).map(|index| (index % 193) as u8).collect();
    let options = WriteOptions {
        maximum_segment_size: Some(34_500),
        ..WriteOptions::default()
    };
    let mut first_output = Vec::new();
    let mut second_output = Vec::new();

    let mut writer = EwfWriter::create(&first, options).unwrap();
    writer.write_all(&data).unwrap();
    let result = writer
        .finish_to_segment_writers([
            (first.clone(), Cursor::new(&mut first_output)),
            (second.clone(), Cursor::new(&mut second_output)),
        ])
        .unwrap();

    assert_eq!(result.segment_paths, vec![first.clone(), second.clone()]);
    assert_eq!(result.logical_size, data.len() as u64);
    assert_eq!(result.chunk_count, 2);
    assert_ne!(first_output, []);
    assert_ne!(second_output, []);
    let expected_segment_set_size = u64::try_from(first_output.len() + second_output.len())
        .expect("segment output sizes fit u64");

    let image = ewf_image::Image::open_readers([
        (first, Cursor::new(first_output)),
        (second, Cursor::new(second_output)),
    ])
    .unwrap();
    assert_eq!(image.info().segment_count, 2);
    assert_eq!(image.info().logical_size, data.len() as u64);
    assert_eq!(image.segment_set_size().unwrap(), expected_segment_set_size);

    let mut decoded = vec![0; data.len()];
    assert_eq!(image.read_at(&mut decoded, 0).unwrap(), data.len());
    assert_eq!(decoded, data);
}

#[test]
fn writer_removes_stale_e01_segments_when_replacing_existing_output() {
    let dir = tempdir().unwrap();
    let first = dir.path().join("replace.E01");
    let second = dir.path().join("replace.E02");
    let large: Vec<u8> = (0..65_536).map(|index| (index % 193) as u8).collect();
    let small = b"replacement e01 data";
    let split_options = WriteOptions {
        maximum_segment_size: Some(34_500),
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&first, split_options).unwrap();
    writer.write_all(&large).unwrap();
    writer.finish().unwrap();
    assert!(second.exists());

    let mut writer = EwfWriter::create(
        &first,
        WriteOptions {
            overwrite_existing: true,
            ..WriteOptions::default()
        },
    )
    .unwrap();
    writer.write_all(small).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.segment_paths, vec![first.clone()]);
    assert!(!second.exists());

    let image = ewf_image::Image::open(&first).unwrap();
    assert_eq!(image.info().segment_count, 1);
    let mut decoded = vec![0; small.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();
    assert_eq!(read, small.len());
    assert_eq!(decoded, small);
}

#[test]
fn writer_splits_e01_when_digest_would_exceed_maximum_segment_size() {
    let dir = tempdir().unwrap();
    let first = dir.path().join("digest-split.E01");
    let data: Vec<u8> = (0..65_536).map(|index| (index % 191) as u8).collect();
    let options = WriteOptions {
        maximum_segment_size: Some(67_000),
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&first, options).unwrap();
    writer.write_all(&data).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.segment_paths.len(), 2);
    for path in &result.segment_paths {
        assert!(
            fs::metadata(path).unwrap().len() <= 67_000,
            "{} exceeded maximum segment size",
            path.display()
        );
    }

    let image = ewf_image::Image::open(&first).unwrap();
    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);
}

#[test]
fn writer_creates_readable_e01_with_zlib_chunks() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("compressed.E01");
    let data = vec![0x7d; 32_768];
    let options = WriteOptions {
        compression: WriteCompression::Zlib,
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    let result = writer.finish().unwrap();

    assert_eq!(result.logical_size, data.len() as u64);
    assert!(fs::metadata(&path).unwrap().len() < data.len() as u64);

    let image = ewf_image::Image::open(&path).unwrap();
    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0).unwrap();

    assert_eq!(read, data.len());
    assert_eq!(decoded, data);
}

#[test]
fn writer_creates_e01_with_stored_digest_hashes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("hashed.E01");
    let data = vec![0x42; 4096];
    let md5 = [
        0xc1, 0x4c, 0xa9, 0x70, 0x91, 0x5e, 0x64, 0x22, 0xb9, 0x4f, 0xaa, 0xf8, 0x95, 0xfa, 0xb3,
        0xaa,
    ];
    let sha1 = [
        0x59, 0x68, 0x2b, 0xdd, 0xd4, 0xb2, 0xa3, 0x1b, 0x08, 0xbc, 0x69, 0x77, 0x16, 0x96, 0x91,
        0xc1, 0x0d, 0xb7, 0xa5, 0x01,
    ];
    let options = WriteOptions {
        hashes: WriteHashes {
            md5: Some(md5),
            sha1: Some(sha1),
            ..WriteHashes::default()
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();

    assert_eq!(image.info().stored_hashes.md5, Some(md5));
    assert_eq!(image.info().stored_hashes.sha1, Some(sha1));

    let bytes = fs::read(&path).unwrap();
    let digest = ewf1_section_data(&bytes, b"digest");
    assert_eq!(
        u32::from_le_bytes(digest[76..80].try_into().unwrap()),
        adler32(&digest[..76])
    );

    let xhash = ewf1_section_data(&bytes, b"xhash");
    assert_eq!(xhash.first(), Some(&0x78));
    let mut xhash_xml = String::new();
    ZlibDecoder::new(xhash)
        .read_to_string(&mut xhash_xml)
        .unwrap();
    assert!(xhash_xml.contains(&format!("<md5>{}</md5>", hex_string(&md5))));
    assert!(xhash_xml.contains(&format!("<sha1>{}</sha1>", hex_string(&sha1))));
}

#[test]
fn write_hashes_expose_compatibility_style_hash_values() {
    let mut hashes = WriteHashes::default();

    assert_eq!(hashes.number_of_hash_values(), 0);
    assert_eq!(hashes.hash_value_identifier(0), None);
    assert_eq!(hashes.hash_value("MD5"), None);

    assert_eq!(
        hashes.set_hash_value("SHA256", "aa".repeat(32)).unwrap(),
        None
    );
    assert_eq!(
        hashes.set_hash_value("SHA512", "sha512-value").unwrap(),
        None
    );
    assert_eq!(
        hashes.set_hash_value("SHA256", "bb".repeat(32)).unwrap(),
        Some("aa".repeat(32))
    );

    assert_eq!(hashes.number_of_hash_values(), 2);
    assert_eq!(hashes.hash_value_identifier(0), Some("SHA256"));
    assert_eq!(hashes.hash_value_identifier(1), Some("SHA512"));
    assert_eq!(hashes.hash_value_identifier(2), None);
    assert_eq!(hashes.hash_value("SHA256"), Some("bb".repeat(32).as_str()));
    assert_eq!(hashes.hash_value("SHA512"), Some("sha512-value"));
}

#[test]
fn write_hashes_set_typed_hashes_from_hex_values() {
    let mut hashes = WriteHashes::default();
    let md5 = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let sha1 = [
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23,
        0x01, 0xaa, 0xbb, 0xcc, 0xdd,
    ];

    hashes
        .set_hash_value("MD5", "0123456789abcdeffedcba9876543210")
        .unwrap();
    hashes
        .set_hash_value("SHA1", "1032547698badcfeefcdab8967452301aabbccdd")
        .unwrap();

    assert_eq!(hashes.md5, Some(md5));
    assert_eq!(hashes.sha1, Some(sha1));
}

#[test]
fn write_hashes_reject_invalid_typed_hash_values() {
    let mut hashes = WriteHashes::default();

    assert!(matches!(
        hashes.set_hash_value("MD5", "md5-value").unwrap_err(),
        ewf_image::EwfError::Unsupported(message) if message.contains("invalid MD5 hash value")
    ));
    assert!(matches!(
        hashes.set_hash_value("SHA1", "sha1-value").unwrap_err(),
        ewf_image::EwfError::Unsupported(message) if message.contains("invalid SHA1 hash value")
    ));
    assert_eq!(hashes.md5, None);
    assert_eq!(hashes.sha1, None);
    assert_eq!(hashes.number_of_hash_values(), 0);
    assert!(hashes.set_hash_value("SHA256", "not-a-digest").is_err());
    assert_eq!(hashes.number_of_hash_values(), 0);
}

#[test]
fn writer_sha256_covers_sector_padding_and_is_returned_for_ewf2() {
    use sha2::{Digest as _, Sha256};
    for format in [WriteFormat::Ewf1Physical, WriteFormat::Ewf2Physical] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hash.E01");
        let mut writer = EwfWriter::create(
            &path,
            WriteOptions {
                format,
                ..WriteOptions::default()
            },
        )
        .unwrap();
        writer.write_all(b"abc").unwrap();
        let result = writer.finish().unwrap();
        let mut padded = vec![0; 512];
        padded[..3].copy_from_slice(b"abc");
        let expected: [u8; 32] = Sha256::digest(&padded).into();
        assert_eq!(result.computed_sha256, expected);
        let image = ewf_image::Image::open(&result.segment_paths[0]).unwrap();
        if format == WriteFormat::Ewf1Physical {
            assert_eq!(
                image.hash_value("SHA256"),
                Some(hex_string(&expected).as_str())
            );
        } else {
            assert_eq!(image.hash_value("SHA256"), None);
        }
    }
}

#[test]
fn writer_rejects_conflicting_reference_maps_before_creating_output() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("conflicting.E01");
    let mut options = WriteOptions::default();
    options.hashes.md5 = Some([0xaa; 16]);
    options
        .hashes
        .hash_values
        .insert("mD5".into(), "bb".repeat(16));
    assert!(EwfWriter::create(&path, options).is_err());
    assert!(!path.exists());
}

#[test]
fn writer_refuses_existing_outputs_by_default_and_preserves_both_destinations() {
    let dir = tempdir().unwrap();
    let primary = dir.path().join("primary.E01");
    let secondary = dir.path().join("secondary.E01");
    std::fs::write(&secondary, b"existing evidence").unwrap();
    let mut writer = EwfWriter::create(
        &primary,
        WriteOptions {
            secondary_segment_filename: Some(secondary.clone()),
            ..WriteOptions::default()
        },
    )
    .unwrap();
    writer.write_all(b"replacement").unwrap();
    assert!(writer.finish().is_err());
    assert!(!primary.exists());
    assert_eq!(std::fs::read(&secondary).unwrap(), b"existing evidence");
    assert!(!EwfWriter::recover_output(&primary, Some(&secondary)).unwrap());
}

#[test]
fn replacement_removes_stale_segments_beyond_a_numbering_gap() {
    let dir = tempdir().unwrap();
    let primary = dir.path().join("gap.E01");
    let stale = primary.with_extension("E04");
    std::fs::write(&stale, b"old segment").unwrap();
    let mut writer = EwfWriter::create(
        &primary,
        WriteOptions {
            overwrite_existing: true,
            ..WriteOptions::default()
        },
    )
    .unwrap();
    writer.write_all(b"replacement").unwrap();
    writer.finish().unwrap();
    assert!(!stale.exists());
    assert_eq!(
        ewf_image::Image::open(primary)
            .unwrap()
            .info()
            .segment_count,
        1
    );
}

#[test]
fn resumed_media_gets_a_new_sha256_instead_of_the_old_reference() {
    use sha2::{Digest as _, Sha256};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("resume-hash.E01");
    let mut writer = EwfWriter::create(
        &path,
        WriteOptions {
            bytes_per_sector: 1,
            ..WriteOptions::default()
        },
    )
    .unwrap();
    writer.write_all(b"ab").unwrap();
    writer.finish_incomplete().unwrap();
    let mut writer = EwfWriter::resume(&path).unwrap();
    writer.write_all(b"c").unwrap();
    let result = writer.finish().unwrap();
    let expected: [u8; 32] = Sha256::digest(b"abc").into();
    assert_eq!(result.computed_sha256, expected);
    assert_eq!(
        ewf_image::Image::open(path).unwrap().hash_value("SHA256"),
        Some(hex_string(&expected).as_str())
    );
}

#[test]
fn writer_rejects_invalid_typed_hash_values() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("invalid-generic-hashes.E01");
    let mut writer = EwfWriter::create(&path, WriteOptions::default()).unwrap();

    assert!(matches!(
        writer.set_hash_value("MD5", "md5-value").unwrap_err(),
        ewf_image::EwfError::Unsupported(message) if message.contains("invalid MD5 hash value")
    ));
    assert!(matches!(
        writer.set_hash_value("SHA1", "sha1-value").unwrap_err(),
        ewf_image::EwfError::Unsupported(message) if message.contains("invalid SHA1 hash value")
    ));
    assert_eq!(writer.md5_hash(), None);
    assert_eq!(writer.sha1_hash(), None);
    assert_eq!(writer.number_of_hash_values(), 0);
}

#[test]
fn writer_uses_hash_values_set_from_hex_as_stored_hashes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("generic-hash-setter.E01");
    let data = vec![0x52; 4096];
    let md5 = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let sha1 = [
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23,
        0x01, 0xaa, 0xbb, 0xcc, 0xdd,
    ];
    let mut hashes = WriteHashes::default();
    hashes
        .set_hash_value("MD5", "0123456789abcdeffedcba9876543210")
        .unwrap();
    hashes
        .set_hash_value("SHA1", "1032547698badcfeefcdab8967452301aabbccdd")
        .unwrap();
    let options = WriteOptions {
        hashes,
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();

    assert_eq!(image.info().stored_hashes.md5, Some(md5));
    assert_eq!(image.info().stored_hashes.sha1, Some(sha1));
}

#[test]
fn writer_creates_e01_with_generic_xhash_values() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("generic-hash.E01");
    let data = vec![0x51; 4096];
    let mut hash_values = BTreeMap::new();
    hash_values.insert(
        "SHA256".to_string(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
    );
    let options = WriteOptions {
        hashes: WriteHashes {
            md5: None,
            sha1: None,
            hash_values,
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();

    assert_eq!(
        image
            .info()
            .stored_hashes
            .hash_values
            .get("SHA256")
            .map(String::as_str),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
}

#[test]
fn writer_creates_e01_with_header_metadata() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("metadata.E01");
    let data = vec![0x33; 4096];
    let options = WriteOptions {
        metadata: EwfMetadata {
            case_number: Some("CASE-001".to_string()),
            evidence_number: Some("EVID-002".to_string()),
            examiner: Some("Examiner".to_string()),
            description: Some("Disk image".to_string()),
            notes: Some("Acquired for tests".to_string()),
            acquisition_software: Some("ewf crate".to_string()),
            acquisition_software_version: Some("0.1.0".to_string()),
            os_version: Some("Linux".to_string()),
            acquisition_date: Some("2026-06-27T12:00:00Z".to_string()),
            system_date: Some("2026-06-27T12:30:00Z".to_string()),
            password: Some("typed-secret".to_string()),
            ..EwfMetadata::default()
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let image = ewf_image::Image::open(&path).unwrap();
    let metadata = &image.info().metadata;

    assert_eq!(metadata.case_number.as_deref(), Some("CASE-001"));
    assert_eq!(metadata.evidence_number.as_deref(), Some("EVID-002"));
    assert_eq!(metadata.examiner.as_deref(), Some("Examiner"));
    assert_eq!(metadata.description.as_deref(), Some("Disk image"));
    assert_eq!(metadata.notes.as_deref(), Some("Acquired for tests"));
    assert_eq!(metadata.acquisition_software.as_deref(), Some("ewf crate"));
    assert_eq!(
        metadata.acquisition_software_version.as_deref(),
        Some("0.1.0")
    );
    assert_eq!(metadata.os_version.as_deref(), Some("Linux"));
    assert_eq!(metadata.password.as_deref(), Some("typed-secret"));
    assert_eq!(
        metadata
            .header_values
            .get("case_number")
            .map(String::as_str),
        Some("CASE-001")
    );

    let bytes = fs::read(&path).unwrap();
    let header = ewf1_section_data(&bytes, b"header");
    assert_eq!(header.first(), Some(&0x78));
    let mut header_text = String::new();
    ZlibDecoder::new(header)
        .read_to_string(&mut header_text)
        .unwrap();
    assert!(header_text.contains("CASE-001"));
    assert!(header_text.contains("typed-secret"));

    let header2 = ewf1_section_data(&bytes, b"header2");
    assert_eq!(header2.first(), Some(&0x78));
    let mut header2_decoded = Vec::new();
    ZlibDecoder::new(header2)
        .read_to_end(&mut header2_decoded)
        .unwrap();
    let case_number_utf16le = "CASE-001"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    assert!(
        header2_decoded
            .windows(case_number_utf16le.len())
            .any(|window| window == case_number_utf16le)
    );

    let xheader = ewf1_section_data(&bytes, b"xheader");
    assert_eq!(xheader.first(), Some(&0x78));
    let mut xheader_xml = String::new();
    ZlibDecoder::new(xheader)
        .read_to_string(&mut xheader_xml)
        .unwrap();
    assert!(xheader_xml.contains("<case_number>CASE-001</case_number>"));
    assert!(xheader_xml.contains("<examiner_name>Examiner</examiner_name>"));
    assert!(xheader_xml.contains("<acquiry_software>ewf crate</acquiry_software>"));
    assert!(xheader_xml.contains("<acquiry_software_version>0.1.0</acquiry_software_version>"));
    assert!(xheader_xml.contains("<password>typed-secret</password>"));
}

#[test]
fn writer_maps_header_value_identifiers_to_ewf1_tags() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("mapped-header-tags.E01");
    let data = vec![0x41; 4096];
    let header_values = BTreeMap::from([
        ("compression_level".to_string(), "best".to_string()),
        ("device_label".to_string(), "disk-label".to_string()),
        ("extents".to_string(), "1 S 0 4096".to_string()),
        ("model".to_string(), "Model X".to_string()),
        ("process_identifier".to_string(), "12345".to_string()),
        ("serial_number".to_string(), "SN-001".to_string()),
        ("unknown_dc".to_string(), "dc-value".to_string()),
    ]);
    let options = WriteOptions {
        metadata: EwfMetadata {
            header_values,
            ..EwfMetadata::default()
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let bytes = fs::read(&path).unwrap();
    let header = ewf1_section_data(&bytes, b"header");
    let mut header_text = String::new();
    ZlibDecoder::new(header)
        .read_to_string(&mut header_text)
        .unwrap();
    let names = header_text.lines().nth(2).unwrap();
    let tags = names.split('\t').collect::<Vec<_>>();

    for expected in ["r", "l", "ext", "md", "pid", "sn", "dc"] {
        assert!(
            tags.contains(&expected),
            "missing EWF1 header tag {expected}"
        );
    }
    for unexpected in [
        "compression_level",
        "device_label",
        "model",
        "process_identifier",
        "serial_number",
        "unknown_dc",
    ] {
        assert!(
            !tags.contains(&unexpected),
            "wrote reserved identifier {unexpected} as an EWF1 header tag"
        );
    }
}

#[test]
fn writer_normalizes_recognized_dates_for_ewf1_header_sections() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("normalized-header-dates.E01");
    let data = vec![0x37; 4096];
    let options = WriteOptions {
        metadata: EwfMetadata {
            acquisition_date: Some("2026-06-27T12:34:56Z".to_string()),
            system_date: Some("Sat Jun 27 13:35:57 2026".to_string()),
            ..EwfMetadata::default()
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let bytes = fs::read(&path).unwrap();
    let header = ewf1_section_data(&bytes, b"header");
    let mut header_text = String::new();
    ZlibDecoder::new(header)
        .read_to_string(&mut header_text)
        .unwrap();
    assert!(header_text.contains("2026 6 27 12 34 56"));
    assert!(header_text.contains("2026 6 27 13 35 57"));
    assert!(!header_text.contains("2026-06-27T12:34:56Z"));

    let header2 = ewf1_section_data(&bytes, b"header2");
    let mut header2_decoded = Vec::new();
    ZlibDecoder::new(header2)
        .read_to_end(&mut header2_decoded)
        .unwrap();
    let header2_text = utf16le_string(&header2_decoded);
    assert!(header2_text.contains("1782563696"));
    assert!(header2_text.contains("1782567357"));
    assert!(!header2_text.contains("2026-06-27T12:34:56Z"));
}

#[test]
fn writer_normalizes_recognized_dates_for_ewf1_xheader() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("normalized-xheader-date.E01");
    let data = vec![0x38; 4096];
    let options = WriteOptions {
        metadata: EwfMetadata {
            acquisition_date: Some("2026-06-27T12:34:56Z".to_string()),
            ..EwfMetadata::default()
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let bytes = fs::read(&path).unwrap();
    let xheader = ewf1_section_data(&bytes, b"xheader");
    let mut xheader_xml = String::new();
    ZlibDecoder::new(xheader)
        .read_to_string(&mut xheader_xml)
        .unwrap();

    assert!(xheader_xml.contains("<acquiry_date>Sat Jun 27 12:34:56 2026</acquiry_date>"));
    assert!(!xheader_xml.contains("2026-06-27T12:34:56Z"));
}

#[test]
fn writer_uses_configured_windows1252_header_codepage_for_legacy_header() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("windows1252-header.E01");
    let data = vec![0x34; 4096];
    let options = WriteOptions {
        header_codepage: HeaderCodepage::Windows1252,
        metadata: EwfMetadata {
            case_number: Some("CASE-\u{e9}".to_string()),
            description: Some("Description-\u{201c}quoted\u{201d}".to_string()),
            ..EwfMetadata::default()
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let bytes = fs::read(&path).unwrap();
    let header = ewf1_section_data(&bytes, b"header");
    let mut header_decoded = Vec::new();
    ZlibDecoder::new(header)
        .read_to_end(&mut header_decoded)
        .unwrap();

    assert!(
        header_decoded
            .windows(b"CASE-\xe9".len())
            .any(|window| window == b"CASE-\xe9")
    );
    assert!(
        header_decoded
            .windows(b"Description-\x93quoted\x94".len())
            .any(|window| window == b"Description-\x93quoted\x94")
    );
    assert!(
        !header_decoded
            .windows(b"CASE-\xc3\xa9".len())
            .any(|window| window == b"CASE-\xc3\xa9")
    );

    let image = ewf_image::Image::open_with_options(
        &path,
        ewf_image::OpenOptions::default().with_header_codepage(HeaderCodepage::Windows1252),
    )
    .unwrap();
    assert_eq!(
        image.header_value("case_number").as_deref(),
        Some("CASE-\u{e9}")
    );
    assert_eq!(
        image.header_value("description").as_deref(),
        Some("Description-\u{201c}quoted\u{201d}")
    );
}

#[test]
fn writer_creates_e01_xheader_with_generic_metadata_values() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("generic-xheader.E01");
    let data = vec![0x34; 4096];
    let mut header_values = BTreeMap::new();
    header_values.insert("custom_field".to_string(), "custom & <value>".to_string());
    let options = WriteOptions {
        metadata: EwfMetadata {
            case_number: Some("CASE-X".to_string()),
            header_values,
            ..EwfMetadata::default()
        },
        ..WriteOptions::default()
    };

    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    let bytes = fs::read(&path).unwrap();
    let xheader = ewf1_section_data(&bytes, b"xheader");
    let mut xheader_xml = String::new();
    ZlibDecoder::new(xheader)
        .read_to_string(&mut xheader_xml)
        .unwrap();

    assert!(xheader_xml.contains("<custom_field>custom &amp; &lt;value&gt;</custom_field>"));
}

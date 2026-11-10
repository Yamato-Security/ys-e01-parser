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

//! Recovery provenance, fallback, truncation, and output safety.
use std::ops::ControlFlow;

use ewf_image::{
    EwfError, EwfRecovery, EwfWriter, Image, RecoveryOptions, RecoveryStatus, SectionKind,
    WriteCompression, WriteFormat, WriteOptions,
};

fn fixture(compression: WriteCompression) -> (tempfile::TempDir, std::path::PathBuf, Vec<u8>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("recover.E01");
    let data: Vec<u8> = (0..32768 * 3 + 17).map(|i| (i % 239) as u8).collect();
    let mut writer = EwfWriter::create(
        &path,
        WriteOptions {
            compression,
            bytes_per_sector: 1,
            ..WriteOptions::default()
        },
    )
    .unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();
    (dir, path, data)
}

fn adler32(bytes: &[u8]) -> u32 {
    let (mut a, mut b) = (1_u32, 0_u32);
    for byte in bytes {
        a = (a + u32::from(*byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

fn break_primary_pointer(path: &std::path::Path) {
    let image = Image::open(path).unwrap();
    let table = image
        .sections()
        .iter()
        .find(|section| section.kind == SectionKind::Ewf1("table".into()))
        .unwrap();
    let mut bytes = std::fs::read(path).unwrap();
    let start = table.data_offset as usize;
    let count = u32::from_le_bytes(bytes[start..start + 4].try_into().unwrap()) as usize;
    bytes[start + 24..start + 28].copy_from_slice(&0x7fff_fff0_u32.to_le_bytes());
    let checksum = adler32(&bytes[start + 24..start + 24 + count * 4]);
    bytes[start + 24 + count * 4..start + 28 + count * 4].copy_from_slice(&checksum.to_le_bytes());
    drop(image);
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn healthy_raw_and_zlib_recover_identically() {
    for compression in [WriteCompression::None, WriteCompression::Zlib] {
        let (_dir, path, data) = fixture(compression);
        let recovery = EwfRecovery::open(path, RecoveryOptions::default()).unwrap();
        let mut output = Vec::new();
        let report = recovery.recover_to_writer(&mut output).unwrap();
        assert_eq!(output, data);
        assert_eq!(report.chunks_primary, report.chunks_total);
        assert_eq!(report.bytes_recovered, data.len() as u64);
        assert_eq!(report.chunks_zero_filled, 0);
        assert_eq!(report.ranges.len(), 1);
    }
}

#[test]
fn redundant_table_recovers_a_bad_primary_pointer_and_reports_provenance() {
    let (_dir, path, data) = fixture(WriteCompression::Zlib);
    break_primary_pointer(&path);
    let recovery = EwfRecovery::open(&path, RecoveryOptions::default()).unwrap();
    let mut output = Vec::new();
    let report = recovery.recover_to_writer(&mut output).unwrap();
    assert_eq!(output, data);
    assert!(report.chunks_redundant > 0);
    assert_eq!(report.chunks_zero_filled, 0);
    assert_eq!(
        report.chunks_primary + report.chunks_redundant,
        report.chunks_total
    );
    assert_eq!(report.ranges[0].status, RecoveryStatus::Redundant);
    #[cfg(feature = "verify")]
    {
        let image = Image::open(path).unwrap();
        let analysis = image.analyze(&ewf_image::VerifyOptions::default()).unwrap();
        assert!(
            analysis
                .findings
                .iter()
                .any(|item| item.kind == ewf_image::IntegrityFindingKind::RedundantTableMismatch)
        );
    }
}

#[test]
fn suspect_raw_bytes_require_opt_in_and_have_complete_accounting() {
    let (_dir, path, data) = fixture(WriteCompression::None);
    let image = Image::open(&path).unwrap();
    let offset = image
        .sections()
        .iter()
        .find(|section| section.kind == SectionKind::Ewf1("sectors".into()))
        .unwrap()
        .data_offset as usize;
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[offset] ^= 0xff;
    drop(image);
    std::fs::write(&path, bytes).unwrap();
    let recovery =
        EwfRecovery::open(&path, RecoveryOptions::default().with_maximum_records(1)).unwrap();
    let mut output = Vec::new();
    let report = recovery.recover_to_writer(&mut output).unwrap();
    assert!(output[..64].iter().all(|byte| *byte == 0));
    assert_eq!(&output[64..], &data[64..]);
    assert_eq!(report.chunks_zero_filled, 1);
    assert_eq!(
        report.bytes_recovered + report.bytes_zero_filled,
        data.len() as u64
    );
    assert!(report.omitted_chunk_records > 0);
    let mut output = Vec::new();
    let recovery = EwfRecovery::open(
        &path,
        RecoveryOptions::default().with_preserve_checksum_suspect(true),
    )
    .unwrap();
    let report = recovery.recover_to_writer(&mut output).unwrap();
    assert_eq!(report.chunks_checksum_suspect, 1);
    assert_eq!(report.chunks_zero_filled, 0);
    assert_eq!(output[0], data[0] ^ 0xff);
    assert_eq!(report.ranges[0].status, RecoveryStatus::SuspectPrimary);
}

#[test]
fn missing_terminal_descriptor_is_recoverable() {
    let (_dir, path, data) = fixture(WriteCompression::Zlib);
    let image = Image::open(&path).unwrap();
    let end = image.sections().last().unwrap().descriptor_offset;
    drop(image);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(end + 10)
        .unwrap();
    let strict =
        ewf_image::OpenOptions::default().with_strictness(ewf_image::OpenStrictness::Strict);
    assert!(Image::open_with_options(&path, strict).is_err());
    // Lenient opening keeps the complete sections, which include the tables.
    let lenient = Image::open(&path).unwrap();
    let mut read = vec![0; data.len()];
    assert_eq!(lenient.read_at(&mut read, 0).unwrap(), data.len());
    assert_eq!(read, data);
    drop(lenient);
    let recovery = EwfRecovery::open(path, RecoveryOptions::default()).unwrap();
    let mut output = Vec::new();
    let report = recovery.recover_to_writer(&mut output).unwrap();
    assert_eq!(output, data);
    assert_ne!(report.notices, []);
}

#[test]
fn damaged_first_geometry_and_oversized_output_are_rejected() {
    let (_dir, path, _) = fixture(WriteCompression::None);
    assert!(
        EwfRecovery::open(
            &path,
            RecoveryOptions::default().with_maximum_output_bytes(1)
        )
        .is_err()
    );
    let image = Image::open(&path).unwrap();
    let volume = image
        .sections()
        .iter()
        .find(|section| section.kind == SectionKind::Ewf1("volume".into()))
        .unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[volume.data_offset as usize + 12] ^= 1;
    drop(image);
    std::fs::write(&path, bytes).unwrap();
    assert!(EwfRecovery::open(path, RecoveryOptions::default()).is_err());
}

#[test]
fn existing_output_and_source_aliases_are_not_overwritten() {
    let (dir, path, _) = fixture(WriteCompression::None);
    let original = std::fs::read(&path).unwrap();
    let recovery = EwfRecovery::open(&path, RecoveryOptions::default()).unwrap();
    assert!(recovery.recover_to_path(&path).is_err());
    let alias = dir.path().join("alias.raw");
    std::fs::hard_link(&path, &alias).unwrap();
    assert!(recovery.recover_to_path(alias).is_err());
    assert_eq!(std::fs::read(path).unwrap(), original);
    let output = dir.path().join("new.raw");
    recovery.recover_to_path(&output).unwrap();
    assert_eq!(
        std::fs::metadata(output).unwrap().len(),
        recovery.media_size()
    );
}

#[test]
fn cancelled_recovery_keeps_partial_output_and_can_be_restarted() {
    let (_dir, path, data) = fixture(WriteCompression::None);
    let recovery = EwfRecovery::open(path, RecoveryOptions::default()).unwrap();
    let mut output = Vec::new();
    assert!(matches!(
        recovery.recover_with_progress(&mut output, |event| {
            if event.chunks_processed == 1 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        }),
        Err(EwfError::Aborted)
    ));
    assert_eq!(output.len(), 64);
    output.clear();
    recovery.recover_to_writer(&mut output).unwrap();
    assert_eq!(output, data);
}

#[test]
fn unsupported_recovery_family_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image.Ex01");
    let mut writer = EwfWriter::create(
        &path,
        WriteOptions {
            format: WriteFormat::Ewf2Physical,
            ..WriteOptions::default()
        },
    )
    .unwrap();
    writer.write_all(b"test").unwrap();
    writer.finish().unwrap();
    assert!(matches!(
        EwfRecovery::open(path, RecoveryOptions::default()),
        Err(EwfError::Unsupported(_))
    ));
}

#[test]
fn split_recovery_rejects_numbering_gaps_and_incomplete_middle_chains() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("split.E01");
    let data = vec![0x51; 32768 * 3];
    let mut writer = EwfWriter::create(
        &path,
        WriteOptions {
            maximum_segment_size: Some(34_500),
            ..WriteOptions::default()
        },
    )
    .unwrap();
    writer.write_all(&data).unwrap();
    let written = writer.finish().unwrap();
    assert_eq!(written.segment_paths.len(), 3);
    let recovery = EwfRecovery::open(&path, RecoveryOptions::default()).unwrap();
    let mut output = Vec::new();
    recovery.recover_to_writer(&mut output).unwrap();
    assert_eq!(output, data);
    assert!(
        EwfRecovery::open_segments(
            [&written.segment_paths[0], &written.segment_paths[2]],
            RecoveryOptions::default()
        )
        .is_err()
    );
    let first_len = std::fs::metadata(&path).unwrap().len();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(first_len - 10)
        .unwrap();
    assert!(EwfRecovery::open(path, RecoveryOptions::default()).is_err());
}

#[test]
fn missing_middle_table_group_is_rejected_but_missing_tail_is_zero_filled() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("groups.E01");
    let data = vec![0x43; 16_380];
    let mut writer = EwfWriter::create(
        &path,
        WriteOptions {
            sectors_per_chunk: 1,
            bytes_per_sector: 1,
            ..WriteOptions::default()
        },
    )
    .unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();
    let image = Image::open(&path).unwrap();
    let tables: Vec<_> = image.sections().iter().filter(|section| matches!(&section.kind, SectionKind::Ewf1(name) if name == "table" || name == "table2")).cloned().collect();
    assert_eq!(tables.len(), 4);
    let original = std::fs::read(&path).unwrap();
    drop(image);
    for group in [0, 1] {
        let mut bytes = original.clone();
        for section in &tables[group * 2..group * 2 + 2] {
            let offset = section.descriptor_offset as usize;
            bytes[offset..offset + 16].fill(0);
            bytes[offset..offset + 7].copy_from_slice(b"unknown");
            let checksum = adler32(&bytes[offset..offset + 72]);
            bytes[offset + 72..offset + 76].copy_from_slice(&checksum.to_le_bytes());
        }
        std::fs::write(&path, bytes).unwrap();
        let opened = EwfRecovery::open(&path, RecoveryOptions::default());
        if group == 0 {
            assert!(opened.is_err());
        } else {
            let mut output = Vec::new();
            let report = opened.unwrap().recover_to_writer(&mut output).unwrap();
            assert_eq!(report.chunks_zero_filled, 5);
            assert_eq!(&output[..16_375], &data[..16_375]);
            assert_eq!(&output[16_375..], &[0; 5]);
        }
    }
}

#[cfg(feature = "external-fixtures")]
#[test]
#[ignore = "requires ewfacquirestream and ewfexport"]
fn external_acquisition_and_truncated_recovery_match_ewfexport() {
    use std::process::{Command, Stdio};
    let dir = tempfile::tempdir().unwrap();
    let data: Vec<u8> = (0..512 * 257).map(|i| (i * 31 % 251) as u8).collect();
    let raw = dir.path().join("source.raw");
    std::fs::write(&raw, &data).unwrap();
    for compression in ["none", "fast"] {
        let target = dir.path().join(compression);
        let acquire = Command::new(
            std::env::var_os("EWFACQUIRESTREAM").unwrap_or_else(|| "ewfacquirestream".into()),
        )
        .args(["-q", "-B"])
        .arg(data.len().to_string())
        .args([
            "-f",
            "encase6",
            "-c",
            compression,
            "-m",
            "fixed",
            "-M",
            "physical",
            "-t",
        ])
        .arg(&target)
        .stdin(std::fs::File::open(&raw).unwrap())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
        assert!(
            acquire.status.success(),
            "{}",
            String::from_utf8_lossy(&acquire.stderr)
        );
        let path = target.with_extension("E01");
        let exported =
            Command::new(std::env::var_os("EWFEXPORT").unwrap_or_else(|| "ewfexport".into()))
                .args(["-q", "-f", "raw", "-t", "-", "-u"])
                .arg(&path)
                .output()
                .unwrap();
        assert!(
            exported.status.success(),
            "{}",
            String::from_utf8_lossy(&exported.stderr)
        );
        assert_eq!(exported.stdout, data);
        let image = Image::open(&path).unwrap();
        #[cfg(feature = "verify")]
        assert_eq!(image.verify().unwrap().md5_match, Some(true));
        let last_descriptor = image.sections().last().unwrap().descriptor_offset;
        drop(image);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(last_descriptor)
            .unwrap();
        let mut recovered = Vec::new();
        let report = EwfRecovery::open(&path, RecoveryOptions::default())
            .unwrap()
            .recover_to_writer(&mut recovered)
            .unwrap();
        assert_eq!(recovered, exported.stdout);
        assert_eq!(report.chunks_zero_filled, 0);
        assert_ne!(report.notices, []);
    }
}

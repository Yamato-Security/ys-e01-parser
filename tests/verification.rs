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

//! Verification and integrity report regressions.
#![cfg(feature = "verify")]

use std::io::{Seek, SeekFrom, Write};
use std::ops::ControlFlow;

use ewf_image::{
    EwfError, EwfWriter, HashReference, Image, IntegrityFindingKind, MediaScanStatus, OpenOptions,
    SectionKind, VerifyOptions, WriteCompression, WriteFormat, WriteOptions,
};
use sha2::{Digest, Sha256};

#[test]
fn logical_verification_handles_sparse_duplicates_references_and_cancellation() {
    use ewf_image::{SingleFileEntry, SingleFileEntryType, SingleFileExtent};
    let (_dir, path) = fixture(b"abc", WriteFormat::Ewf1Physical, WriteCompression::None);
    let image = Image::open(path).unwrap();
    let mut entry = SingleFileEntry {
        file_entry_type: Some(SingleFileEntryType::File),
        size: Some(3),
        duplicate_data_offset: Some(0),
        md5: Some("900150983CD24FB0D6963F7D28E17F72".into()),
        sha1: Some("a9993e364706816aba3e25717850c26c9cd0d89d".into()),
        ..SingleFileEntry::default()
    };
    let verified = image.verify_single_file(&entry).unwrap();
    assert_eq!(verified.references_match(), Some(true));
    assert_eq!(verified.bytes_verified, 3);
    assert!(matches!(
        image.verify_single_file_with_progress(&entry, |_| ControlFlow::Break(())),
        Err(EwfError::Aborted)
    ));
    entry.md5 = Some("00".repeat(16));
    assert_eq!(
        image.verify_single_file(&entry).unwrap().references_match(),
        Some(false)
    );
    entry.md5 = Some("malformed".into());
    assert!(image.verify_single_file(&entry).is_err());
    entry.md5 = None;
    entry.sha1 = None;
    entry.size = Some(5);
    entry.extents = vec![
        SingleFileExtent {
            data_offset: 0,
            data_size: 3,
            sparse: false,
        },
        SingleFileExtent {
            data_offset: u64::MAX,
            data_size: 2,
            sparse: true,
        },
    ];
    let mut output = Vec::new();
    let verified = image
        .copy_single_file_with_progress(&entry, &mut output, |_| ControlFlow::Continue(()))
        .unwrap();
    assert_eq!(output, b"abc\0\0");
    assert_eq!(verified.references_match(), None);
    assert_eq!(
        verified.hashes.sha256.as_slice(),
        Sha256::digest(&output).as_slice()
    );
    entry.size = Some(6);
    assert!(image.verify_single_file(&entry).is_err());
    entry.size = Some(0);
    assert_eq!(image.verify_single_file(&entry).unwrap().bytes_verified, 0);
    entry.file_entry_type = Some(SingleFileEntryType::Directory);
    assert!(image.verify_single_file(&entry).is_err());
    entry.file_entry_type = Some(SingleFileEntryType::File);
    image.signal_abort();
    assert!(matches!(
        image.verify_single_file(&entry),
        Err(EwfError::Aborted)
    ));
}

#[test]
fn logical_verification_bypasses_cached_and_substituted_chunks() {
    use ewf_image::{SingleFileEntry, SingleFileEntryType};
    let (_dir, path) = fixture(b"abc", WriteFormat::Ewf1Physical, WriteCompression::None);
    let image = Image::open(&path).unwrap();
    let entry = SingleFileEntry {
        file_entry_type: Some(SingleFileEntryType::File),
        size: Some(3),
        duplicate_data_offset: Some(0),
        ..SingleFileEntry::default()
    };
    image.read_single_file_at(&entry, &mut [0; 3], 0).unwrap();
    let offset = image
        .sections()
        .iter()
        .find(|s| s.kind == SectionKind::Ewf1("sectors".into()))
        .unwrap()
        .data_offset;
    let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(b"z").unwrap();
    file.sync_all().unwrap();
    image.set_read_zero_chunk_on_error(true);
    assert!(image.verify_single_file(&entry).is_err());
    let image = Image::open(&path).unwrap();
    image.set_read_zero_chunk_on_error(true);
    image.read_single_file_at(&entry, &mut [0; 3], 0).unwrap();
    assert!(image.verify_single_file(&entry).is_err());
}

fn fixture(
    data: &[u8],
    format: WriteFormat,
    compression: WriteCompression,
) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image.E01");
    let options = WriteOptions {
        format,
        compression,
        bytes_per_sector: 1,
        sectors_per_chunk: 32768,
        ..WriteOptions::default()
    };
    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(data).unwrap();
    writer.finish().unwrap();
    (dir, path)
}

#[test]
fn known_sha256_vector_and_independent_reference_mismatch() {
    let (_dir, path) = fixture(b"abc", WriteFormat::Ewf1Physical, WriteCompression::Zlib);
    let image = Image::open(path).unwrap();
    let expected = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    let options = VerifyOptions::default()
        .with_expected_sha256(expected)
        .with_expected_md5([0; 16]);
    let report = image.verify_with_options(&options).unwrap();
    assert_eq!(report.hashes.sha256, expected);
    assert_eq!(report.bytes_verified, 3);
    assert_eq!(report.references_match(), Some(false));
    assert!(
        report
            .comparisons
            .iter()
            .any(|item| item.reference == HashReference::Stored && item.matches)
    );
    assert!(
        report
            .comparisons
            .iter()
            .any(|item| item.reference == HashReference::External && !item.matches)
    );
    let analysis = image.analyze(&options).unwrap();
    assert_eq!(analysis.media_status, MediaScanStatus::Complete);
    assert!(analysis.findings.iter().any(|item| matches!(
        item.kind,
        IntegrityFindingKind::HashMismatch {
            reference: HashReference::External,
            ..
        }
    )));
}

#[test]
fn embedded_sha256_is_compared_by_both_verification_interfaces() {
    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    for (reference, matches) in [(ABC_SHA256.to_uppercase(), true), ("00".repeat(32), false)] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sha256.E01");
        let mut options = WriteOptions {
            bytes_per_sector: 1,
            ..WriteOptions::default()
        };
        options.hashes.set_hash_value("sHa256", reference).unwrap();
        let mut writer = EwfWriter::create(&path, options).unwrap();
        writer.write_all(b"abc").unwrap();
        writer.finish().unwrap();
        let image = Image::open(path).unwrap();
        let report = image
            .verify_with_options(&VerifyOptions::default())
            .unwrap();
        assert_eq!(report.references_match(), Some(matches));
        let legacy = image.verify().unwrap();
        assert_eq!(legacy.sha256_match, Some(matches));
        assert_eq!(legacy.computed_sha256, Some(report.hashes.sha256));
        let analysis = image.analyze(&VerifyOptions::default()).unwrap();
        assert_eq!(
            analysis.findings.iter().any(|finding| matches!(
                finding.kind,
                IntegrityFindingKind::HashMismatch {
                    algorithm: ewf_image::HashAlgorithm::Sha256,
                    reference: HashReference::Stored
                }
            )),
            !matches
        );
    }
}

#[test]
fn progress_is_ordered_exact_and_locally_cancellable() {
    let data = vec![0x57; 32768 * 3 + 7];
    let (_dir, path) = fixture(&data, WriteFormat::Ewf1Physical, WriteCompression::Zlib);
    let image = Image::open(path).unwrap();
    let mut events = Vec::new();
    let report = image
        .verify_with_progress(&VerifyOptions::default(), |event| {
            events.push(event);
            ControlFlow::Continue(())
        })
        .unwrap();
    assert_eq!(events.len(), 5);
    assert_eq!(events[0].bytes_processed, 0);
    assert_eq!(events[4].bytes_processed, data.len() as u64);
    assert_eq!(events[4].bytes_verified, data.len() as u64);
    assert_eq!(
        report.hashes.sha256.as_slice(),
        Sha256::digest(&data).as_slice()
    );
    for pair in events.windows(2) {
        assert_eq!(pair[1].chunks_processed, pair[0].chunks_processed + 1);
    }
    let error = image
        .verify_with_progress(&VerifyOptions::default(), |event| {
            if event.chunks_processed == 1 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })
        .unwrap_err();
    assert!(matches!(error, EwfError::Aborted));
    assert_eq!(image.read_at(&mut [0; 1], 0).unwrap(), 1);
    image.signal_abort();
    assert!(matches!(image.verify(), Err(EwfError::Aborted)));
}

#[test]
fn verification_rejects_cached_recovery_zeros_and_analysis_continues() {
    let data = vec![0x57; 32768 * 3];
    let (_dir, path) = fixture(&data, WriteFormat::Ewf1Physical, WriteCompression::None);
    let pristine = Image::open(&path).unwrap();
    let sectors = pristine
        .sections()
        .iter()
        .find(|section| section.kind == SectionKind::Ewf1("sectors".into()))
        .unwrap();
    let offset = sectors.data_offset;
    drop(pristine);
    let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&[0xff]).unwrap();
    file.seek(SeekFrom::Start(offset + 32768 + 4)).unwrap();
    file.write_all(&[0xfe]).unwrap();
    drop(file);
    let image = Image::open_with_options(
        path,
        OpenOptions::default().with_read_zero_chunk_on_error(true),
    )
    .unwrap();
    let mut buffer = [0xff; 8];
    image.read_at(&mut buffer, 0).unwrap();
    assert_eq!(buffer, [0; 8]);
    assert!(image.verify().is_err());
    let report = image
        .analyze(&VerifyOptions::default().with_maximum_findings(1))
        .unwrap();
    assert_eq!(report.media_status, MediaScanStatus::Incomplete);
    assert_eq!(report.bytes_verified, 32768);
    assert!(report.hashes.is_none());
    assert_eq!(report.comparisons, []);
    assert_eq!(report.error_count, 2);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.suppressed_findings, 1);
    assert_eq!(report.findings[0].logical_offset, Some(0));
}

#[test]
fn no_reference_is_distinct_from_a_match() {
    let (_dir, path) = fixture(b"abc", WriteFormat::Ewf1Physical, WriteCompression::None);
    let image = Image::open(&path).unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    for section in image.sections().iter().filter(|section| matches!(&section.kind, SectionKind::Ewf1(name) if name == "hash" || name == "digest" || name == "xhash")) {
        let offset = section.descriptor_offset as usize;
        bytes[offset..offset + 16].fill(0);
        bytes[offset..offset + 7].copy_from_slice(b"unknown");
        bytes[offset + 72..offset + 76].fill(0);
    }
    let image =
        Image::open_sources([("memory.E01", ewf_image::SegmentSource::from_bytes(bytes))]).unwrap();
    assert_eq!(
        image
            .verify_with_options(&VerifyOptions::default())
            .unwrap()
            .references_match(),
        None
    );
}

#[test]
fn sha256_only_analysis_has_a_reference_and_path_progress_can_cancel() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sha256.E01");
    let mut options = WriteOptions::default();
    options
        .hashes
        .set_hash_value(
            "SHA256",
            Sha256::digest([0; 512])
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        )
        .unwrap();
    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&[0; 512]).unwrap();
    writer.finish().unwrap();
    let image = Image::open(&path).unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    for section in image.sections().iter().filter(
        |s| matches!(&s.kind, SectionKind::Ewf1(name) if name == "hash" || name == "digest"),
    ) {
        let offset = section.descriptor_offset as usize;
        bytes[offset..offset + 16].fill(0);
        bytes[offset..offset + 7].copy_from_slice(b"unknown");
        bytes[offset + 72..offset + 76].fill(0);
    }
    let xhash = image
        .sections()
        .iter()
        .find(|s| s.kind == SectionKind::Ewf1("xhash".into()))
        .unwrap();
    let xml = format!(
        "<xhash><SHA256>{}</SHA256></xhash>",
        image.hash_value("SHA256").unwrap()
    );
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(xml.as_bytes()).unwrap();
    let compressed = encoder.finish().unwrap();
    let start = xhash.data_offset as usize;
    let end = start + xhash.data_size as usize;
    assert!(compressed.len() <= end - start);
    bytes[start..end].fill(0);
    bytes[start..start + compressed.len()].copy_from_slice(&compressed);
    drop(image);
    std::fs::write(&path, bytes).unwrap();
    let image = Image::open(&path).unwrap();
    assert!(image.md5_hash().is_none() && image.sha1_hash().is_none());
    let report = ewf_image::analyze_path_with_progress(&path, &VerifyOptions::default(), |_| {
        ControlFlow::Continue(())
    })
    .unwrap();
    assert_eq!(report.warning_count, 0);
    assert_eq!(report.comparisons.len(), 1);
    assert!(report.comparisons[0].matches);
    assert!(matches!(
        ewf_image::analyze_path_with_progress(path, &VerifyOptions::default(), |_| {
            ControlFlow::Break(())
        }),
        Err(EwfError::Aborted)
    ));
}

#[test]
fn structural_failure_has_unavailable_coverage_even_when_findings_are_suppressed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.E01");
    std::fs::write(&path, b"not an EWF image").unwrap();
    let report =
        ewf_image::analyze_path(path, &VerifyOptions::default().with_maximum_findings(0)).unwrap();
    assert_eq!(report.media_status, MediaScanStatus::Unavailable);
    assert!(report.hashes.is_none());
    assert_eq!(report.error_count, 1);
    assert_eq!(report.suppressed_findings, 1);
}

#[test]
fn invalid_options_fail_before_progress() {
    let (_dir, path) = fixture(b"abc", WriteFormat::Ewf1Physical, WriteCompression::None);
    let image = Image::open(path).unwrap();
    for options in [
        VerifyOptions::default().with_parallelism(0),
        VerifyOptions::default().with_parallelism(65),
        VerifyOptions::default().with_chunk_buffer_size_bytes(0),
    ] {
        assert!(
            image
                .verify_with_progress(&options, |_| panic!("invalid options must not scan"))
                .is_err()
        );
    }
}

#[test]
fn empty_media_hashes_and_progress_are_well_defined() {
    let (_dir, path) = fixture(b"", WriteFormat::Ewf1Physical, WriteCompression::None);
    let image = Image::open(path).unwrap();
    let mut events = Vec::new();
    let report = image
        .verify_with_progress(&VerifyOptions::default(), |event| {
            events.push(event);
            ControlFlow::Continue(())
        })
        .unwrap();
    assert_eq!(
        report.hashes.sha256.as_slice(),
        Sha256::digest(b"").as_slice()
    );
    assert_eq!(report.bytes_verified, 0);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].chunks_total, 0);
}

#[cfg(feature = "parallel")]
#[test]
fn encrypted_positioned_sources_verify_against_the_reference_vector() {
    let expected = [
        0xa4, 0xa3, 0xec, 0x30, 0xd6, 0x38, 0x82, 0x44, 0xde, 0xd0, 0x6c, 0x36, 0xc1, 0xc7, 0xf5,
        0x01, 0xee, 0x42, 0xfd, 0x79, 0x40, 0xc0, 0x43, 0x50, 0xc6, 0xe3, 0x67, 0xa6, 0x44, 0x22,
        0x03, 0x13,
    ];
    for name in ["aes128-known-password.E01", "aes256-known-password.E01"] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/xways-encrypted")
            .join(name);
        let source = ewf_image::SegmentSource::from_bytes(std::fs::read(path).unwrap());
        let password = ewf_image::EwfPassword::utf8("xways-test");
        let image = Image::open_sources_with_options_and_password(
            [(name, source)],
            OpenOptions::default(),
            &password,
        )
        .unwrap();
        let options = VerifyOptions::default()
            .with_parallelism(4)
            .with_expected_sha256(expected);
        assert_eq!(
            image
                .verify_with_options(&options)
                .unwrap()
                .references_match(),
            Some(true)
        );
    }
}

#[cfg(feature = "parallel")]
#[test]
fn split_images_verify_across_positioned_backings_and_handle_limits() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("split.E01");
    let data: Vec<_> = (0..65536 * 2).map(|i| (i % 193) as u8).collect();
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
    assert!(written.segment_paths.len() > 1);
    let sources: Vec<_> = written
        .segment_paths
        .iter()
        .map(|path| {
            (
                path.clone(),
                ewf_image::SegmentSource::from_file(std::fs::File::open(path).unwrap()).unwrap(),
            )
        })
        .collect();
    let options = VerifyOptions::default().with_parallelism(4);
    let supplied = Image::open_sources(sources)
        .unwrap()
        .verify_with_options(&options)
        .unwrap();
    let image = Image::open_with_options(
        path,
        OpenOptions::default().with_maximum_open_handles(Some(1)),
    )
    .unwrap();
    assert_eq!(image.verify_with_options(&options).unwrap(), supplied);
    assert!(image.number_of_open_segment_handles().unwrap() <= 1);
}

#[cfg(feature = "parallel")]
#[test]
#[ignore = "manual release-mode throughput measurement"]
fn benchmark_verification_workers() {
    let data: Vec<_> = (0..32 * 1024 * 1024)
        .map(|i| ((i * 31 + i / 251) % 251) as u8)
        .collect();
    for (format, compression) in [
        (WriteFormat::Ewf1Physical, WriteCompression::Zlib),
        (WriteFormat::Ewf2Physical, WriteCompression::Bzip2),
    ] {
        let (_dir, path) = fixture(&data, format, compression);
        let image = Image::open_sources([(
            "benchmark.E01",
            ewf_image::SegmentSource::from_file(std::fs::File::open(path).unwrap()).unwrap(),
        )])
        .unwrap();
        let expected = Sha256::digest(&data);
        for workers in [1, 4] {
            let options = VerifyOptions::default().with_parallelism(workers);
            let mut times = Vec::new();
            for _ in 0..3 {
                let start = std::time::Instant::now();
                let report = image.verify_with_options(&options).unwrap();
                times.push(start.elapsed());
                assert_eq!(report.hashes.sha256.as_slice(), expected.as_slice());
            }
            times.sort();
            eprintln!(
                "{compression:?}, {workers} workers: median {:?}, {:.1} MiB/s",
                times[1],
                32.0 / times[1].as_secs_f64()
            );
        }
    }
}

#[cfg(feature = "parallel")]
#[test]
fn parallel_hashes_match_serial_across_formats_without_polluting_chunk_cache() {
    let data: Vec<u8> = (0..32768 * 9 + 17).map(|i| (i * 31 % 251) as u8).collect();
    for (format, compression) in [
        (WriteFormat::Ewf1Physical, WriteCompression::None),
        (WriteFormat::Ewf1Physical, WriteCompression::Zlib),
        (WriteFormat::Ewf2Physical, WriteCompression::Zlib),
        (WriteFormat::Ewf2Physical, WriteCompression::Bzip2),
        (WriteFormat::Ewf2Logical, WriteCompression::None),
    ] {
        let (_dir, path) = fixture(&data, format, compression);
        let image =
            Image::open_with_options(path, OpenOptions::default().with_reader_statistics(true))
                .unwrap();
        image.read_at(&mut [0; 8], 0).unwrap();
        let before = image.reader_statistics().unwrap();
        let serial = image
            .verify_with_options(&VerifyOptions::default())
            .unwrap();
        let parallel = image
            .verify_with_options(
                &VerifyOptions::default()
                    .with_parallelism(4)
                    .with_chunk_buffer_size_bytes(32768 * 3),
            )
            .unwrap();
        assert_eq!(parallel, serial);
        let after = image.reader_statistics().unwrap();
        assert_eq!(after.chunk_cache_hits(), before.chunk_cache_hits());
        assert_eq!(after.chunk_cache_misses(), before.chunk_cache_misses());
        assert_eq!(
            serial.hashes.sha256.as_slice(),
            Sha256::digest(&data).as_slice()
        );
    }
}

#[cfg(not(feature = "parallel"))]
#[test]
fn requesting_parallelism_requires_the_feature() {
    let (_dir, path) = fixture(b"abc", WriteFormat::Ewf1Physical, WriteCompression::None);
    let image = Image::open(path).unwrap();
    assert!(matches!(
        image.verify_with_options(&VerifyOptions::default().with_parallelism(2)),
        Err(EwfError::Unsupported(_))
    ));
}

#[cfg(feature = "serde")]
#[test]
fn reports_serialize_without_losing_coverage_or_reference_origin() {
    let (_dir, path) = fixture(b"abc", WriteFormat::Ewf1Physical, WriteCompression::None);
    let report = Image::open(path)
        .unwrap()
        .analyze(&VerifyOptions::default().with_expected_sha256([0; 32]))
        .unwrap();
    let json = serde_json::to_value(report).unwrap();
    assert_eq!(json["media_status"], "Complete");
    assert_eq!(json["error_count"], 1);
    assert!(
        json["comparisons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["reference"] == "External")
    );
}

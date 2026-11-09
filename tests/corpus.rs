// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) 2026 Elijah Brigham
//
// This file is changed from ebrig/ewf-image (https://github.com/ebrig/ewf-image), whose code is
// under the Apache License 2.0 (LICENSE-APACHE).
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

//! Optional external-corpus integration tests.

#![cfg(feature = "external-fixtures")]

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const BUFFER_SIZE: usize = 1024 * 1024;

#[test]
#[cfg(feature = "verify")]
#[ignore = "requires EWF_WINACQ_FIXTURE_DIR with the synthetic WinAcq 20.3 corpus"]
fn external_winacq_media_and_segment_provenance() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(
        env::var_os("EWF_WINACQ_FIXTURE_DIR")
            .ok_or("set EWF_WINACQ_FIXTURE_DIR to the synthetic WinAcq fixture directory")?,
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("interop-manifest.json"))?)?;
    assert_eq!(manifest["producer_versions"]["bundled_WinAcq"], "20.3");
    let source_path = root.join("synthetic-vhd-media.raw");
    assert_eq!(fs::metadata(&source_path)?.len(), 32 * 1024 * 1024);
    let source = fs::read(source_path)?;
    let expected: [u8; 32] = Sha256::digest(&source).into();
    assert_eq!(
        hex_lower(&expected),
        "e66dc1a029af43acdb01162cf4d4a4b752db4a1cbc2278142d222e0f4c605e84"
    );
    for (stem, segments) in [("encase-winacq", 1), ("encase-winacq-raw", 9)] {
        for ordinal in 1..=segments {
            let name = format!("{stem}.E{ordinal:02}");
            let recorded = &manifest["files"][&name];
            let path = root.join(&name);
            assert_eq!(
                Some(fs::metadata(&path)?.len()),
                recorded["bytes"].as_u64(),
                "{name}"
            );
            assert_eq!(
                sha256_hex(&fs::read(path)?),
                recorded["sha256"]
                    .as_str()
                    .ok_or("missing segment SHA256")?,
                "{name}"
            );
        }
        let image = ewf_image::Image::open(root.join(format!("{stem}.E01")))?;
        assert_eq!(image.number_of_segments(), segments as usize);
        let result = image.verify_with_options(
            &ewf_image::VerifyOptions::default().with_expected_sha256(expected),
        )?;
        assert_eq!(result.bytes_verified, source.len() as u64);
        assert_eq!(result.references_match(), Some(true));
        // Compare the strict media stream as well as the complete digest, including
        // boundaries between the native producer's nine uncompressed segments.
        let mut cursor = image.cursor();
        let mut buffer = vec![0; BUFFER_SIZE];
        for part in source.chunks(BUFFER_SIZE) {
            cursor.read_exact(&mut buffer[..part.len()])?;
            assert_eq!(&buffer[..part.len()], part);
        }
        assert_eq!(cursor.read(&mut buffer[..1])?, 0);
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
#[error("failed to open external EWF fixture {}: {source}", path.display())]
struct ExternalFixtureOpenError {
    path: PathBuf,
    #[source]
    source: ewf_image::EwfError,
}

fn open_external_fixture(path: &Path) -> Result<ewf_image::Image, ExternalFixtureOpenError> {
    ewf_image::Image::open(path).map_err(|source| ExternalFixtureOpenError {
        path: path.to_path_buf(),
        source,
    })
}

#[test]
#[ignore = "requires local external corpus"]
fn external_corpus_opens_and_reads() -> Result<(), Box<dyn Error>> {
    let paths = corpus_paths()?;
    let mut skipped = 0_usize;
    eprintln!("selected {} external EWF first segments", paths.len());
    eprintln!(
        "external fixture coverage: {:?}",
        FixtureCoverage::from_paths(&paths)
    );
    for path in paths {
        let image = match open_external_fixture(&path) {
            Ok(image) => image,
            Err(err) if is_unsupported_encrypted_image(&err.source) => {
                skipped += 1;
                eprintln!("skipping unsupported encrypted image {}", path.display());
                continue;
            }
            Err(err) => return Err(Box::new(err)),
        };
        let read_size = image.info().logical_size.min(4096) as usize;
        let mut buf = vec![0; read_size];
        let read = image.read_at(&mut buf, 0)?;
        assert_eq!(read, read_size, "short read for {}", path.display());
    }
    eprintln!("skipped {skipped} unsupported encrypted external images");
    Ok(())
}

#[test]
#[ignore = "requires local external corpus and ewfexport"]
fn external_corpus_matches_ewfexport_stdout() -> Result<(), Box<dyn Error>> {
    let ewfexport = env::var_os("EWFEXPORT").unwrap_or_else(|| OsString::from("ewfexport"));
    let paths = corpus_paths()?;
    eprintln!("selected {} external EWF first segments", paths.len());
    eprintln!(
        "external fixture coverage: {:?}",
        FixtureCoverage::from_paths(&paths)
    );
    for path in paths {
        compare_with_ewfexport(&ewfexport, &path)?;
    }
    Ok(())
}

#[test]
#[ignore = "requires local external corpus and ewfinfo"]
fn external_corpus_matches_ewfinfo_metadata() -> Result<(), Box<dyn Error>> {
    let ewfinfo = env::var_os("EWFINFO").unwrap_or_else(|| OsString::from("ewfinfo"));
    let paths = corpus_paths()?;
    eprintln!("selected {} external EWF first segments", paths.len());
    eprintln!(
        "external fixture coverage: {:?}",
        FixtureCoverage::from_paths(&paths)
    );
    for path in paths {
        compare_with_ewfinfo(&ewfinfo, &path)?;
    }
    Ok(())
}

#[test]
#[ignore = "requires local external corpus and ewfverify"]
fn external_corpus_matches_ewfverify() -> Result<(), Box<dyn Error>> {
    let ewfverify = env::var_os("EWFVERIFY").unwrap_or_else(|| OsString::from("ewfverify"));
    let paths = corpus_paths()?;
    eprintln!("selected {} external EWF first segments", paths.len());
    eprintln!(
        "external fixture coverage: {:?}",
        FixtureCoverage::from_paths(&paths)
    );
    for path in paths {
        let image = match open_external_fixture(&path) {
            Ok(image) => image,
            Err(err) if is_unsupported_encrypted_image(&err.source) => {
                eprintln!("skipping unsupported encrypted image {}", path.display());
                continue;
            }
            Err(err) => return Err(Box::new(err)),
        };
        if !is_ewfverify_candidate(image.info()) {
            eprintln!(
                "skipping incomplete acquisition for ewfverify {}",
                path.display()
            );
            continue;
        }
        verify_with_ewfverify(&ewfverify, &path)?;
    }
    Ok(())
}

#[test]
#[ignore = "requires closeout fixture corpus with every strict parity family"]
fn external_closeout_corpus_has_required_feature_coverage() -> Result<(), Box<dyn Error>> {
    let paths = corpus_paths()?;
    let coverage = ExternalFeatureCoverage::from_paths(&paths)?;
    eprintln!("external closeout feature coverage: {coverage:?}");

    let missing = missing_closeout_feature_families(&coverage);
    assert!(
        missing.is_empty(),
        "closeout corpus is missing strict fixture families: {missing:?}"
    );

    Ok(())
}

#[test]
#[ignore = "requires closeout fixture corpus for current external-tool parity"]
fn external_closeout_corpus_matches_current_toolchain_parity() -> Result<(), Box<dyn Error>> {
    let paths = corpus_paths()?;
    let coverage = ExternalFeatureCoverage::from_paths(&paths)?;
    eprintln!("external current-toolchain closeout coverage: {coverage:?}");

    let missing = missing_closeout_feature_families_for_current_toolchain(&coverage);
    assert!(
        missing.is_empty(),
        "current-toolchain closeout corpus is missing strict fixture families: {missing:?}"
    );

    Ok(())
}

#[test]
#[ignore = "requires ewfacquirestream, ewfexport, ewfinfo, and ewfverify"]
fn generated_closeout_feature_coverage_matches_oracles() -> Result<(), Box<dyn Error>> {
    let tools = EwfToolchain::from_env();
    let dir = tempfile::tempdir()?;
    let data = patterned_data(1_310_720);

    let paths = generated_closeout_oracle_paths(&tools, dir.path(), data.as_slice())?;
    let coverage = ExternalFeatureCoverage::from_paths(&paths)?;
    eprintln!("generated closeout feature coverage: {coverage:?}");

    let missing = missing_closeout_feature_families(&coverage);
    assert!(
        missing.is_empty(),
        "generated closeout coverage should satisfy all strict current external-tool parity families"
    );

    Ok(())
}

#[test]
#[ignore = "writes generated closeout fixtures to EWF_CLOSEOUT_FIXTURE_DIR"]
fn write_generated_closeout_fixture_corpus() -> Result<(), Box<dyn Error>> {
    let Some(destination) = env::var_os("EWF_CLOSEOUT_FIXTURE_DIR").map(PathBuf::from) else {
        return Err("set EWF_CLOSEOUT_FIXTURE_DIR to the output fixture directory".into());
    };
    fs::create_dir_all(&destination)?;

    let tools = EwfToolchain::from_env();
    let dir = tempfile::tempdir()?;
    let data = patterned_data(1_310_720);
    let paths = generated_closeout_oracle_paths(&tools, dir.path(), data.as_slice())?;

    for path in paths {
        copy_image_segment_set(&path, &destination)?;
    }

    Ok(())
}

#[test]
#[ignore = "requires ewfexport"]
fn external_writer_outputs_match_ewfexport_stdout() -> Result<(), Box<dyn Error>> {
    let ewfexport = env::var_os("EWFEXPORT").unwrap_or_else(|| OsString::from("ewfexport"));
    let dir = tempfile::tempdir()?;
    let data = patterned_data(4096);
    let split_data = patterned_data(70_000);
    let partial_sector_data = patterned_data(1500);
    let repeated_pattern_data = 0x1122_3344_5566_7788_u64.to_le_bytes().repeat(512);

    let cases = vec![
        WriterCase {
            filename: "writer-physical.E01",
            data: data.as_slice(),
            options: ewf_image::WriteOptions::default(),
        },
        WriterCase {
            filename: "writer-media-size.E01",
            data: data.as_slice(),
            options: ewf_image::WriteOptions {
                media_size: Some(8192),
                ..ewf_image::WriteOptions::default()
            },
        },
        WriterCase {
            filename: "writer-compressed.E01",
            data: partial_sector_data.as_slice(),
            options: ewf_image::WriteOptions {
                compression: ewf_image::WriteCompression::Zlib,
                ..ewf_image::WriteOptions::default()
            },
        },
        WriterCase {
            filename: "writer-logical.L01",
            data: data.as_slice(),
            options: ewf_image::WriteOptions {
                format: ewf_image::WriteFormat::Ewf1Logical,
                ..ewf_image::WriteOptions::default()
            },
        },
        WriterCase {
            filename: "writer-smart.s01",
            data: data.as_slice(),
            options: ewf_image::WriteOptions {
                format: ewf_image::WriteFormat::Ewf1Smart,
                ..ewf_image::WriteOptions::default()
            },
        },
        WriterCase {
            filename: "writer-logical-single-files.L01",
            data: data.as_slice(),
            options: ewf_image::WriteOptions {
                format: ewf_image::WriteFormat::Ewf1Logical,
                media_profile: ewf_image::WriteMediaProfile {
                    media_type: Some(ewf_image::MediaType::SingleFiles),
                    ..ewf_image::WriteMediaProfile::default()
                },
                single_files: Some(rich_single_file_catalog(data.len() as u64)),
                ..ewf_image::WriteOptions::default()
            },
        },
        WriterCase {
            filename: "writer-split.E01",
            data: split_data.as_slice(),
            options: ewf_image::WriteOptions {
                maximum_segment_size: Some(45_000),
                ..ewf_image::WriteOptions::default()
            },
        },
        WriterCase {
            filename: "writer-ewf2.Ex01",
            data: data.as_slice(),
            options: ewf_image::WriteOptions {
                format: ewf_image::WriteFormat::Ewf2Physical,
                ..ewf_image::WriteOptions::default()
            },
        },
        WriterCase {
            filename: "writer-ewf2-split.Ex01",
            data: split_data.as_slice(),
            options: ewf_image::WriteOptions {
                format: ewf_image::WriteFormat::Ewf2Physical,
                maximum_segment_size: Some(45_000),
                ..ewf_image::WriteOptions::default()
            },
        },
        // Some external tools try to read EWF2 device information as deflate
        // before applying the segment's BZip2 compression method. Keep BZip2
        // covered by local writer tests.
        WriterCase {
            filename: "writer-ewf2-pattern.Ex01",
            data: repeated_pattern_data.as_slice(),
            options: ewf_image::WriteOptions {
                format: ewf_image::WriteFormat::Ewf2Physical,
                ..ewf_image::WriteOptions::default()
            },
        },
        WriterCase {
            filename: "writer-ewf2-logical.Lx01",
            data: data.as_slice(),
            options: ewf_image::WriteOptions {
                format: ewf_image::WriteFormat::Ewf2Logical,
                ..ewf_image::WriteOptions::default()
            },
        },
        WriterCase {
            filename: "writer-ewf2-single-files.Lx01",
            data: data.as_slice(),
            options: ewf_image::WriteOptions {
                format: ewf_image::WriteFormat::Ewf2Logical,
                media_profile: ewf_image::WriteMediaProfile {
                    media_type: Some(ewf_image::MediaType::SingleFiles),
                    ..ewf_image::WriteMediaProfile::default()
                },
                single_files: Some(single_file_catalog(data.len() as u64)),
                ..ewf_image::WriteOptions::default()
            },
        },
        WriterCase {
            filename: "writer-ewf2-rich-single-files.Lx01",
            data: data.as_slice(),
            options: ewf_image::WriteOptions {
                format: ewf_image::WriteFormat::Ewf2Logical,
                media_profile: ewf_image::WriteMediaProfile {
                    media_type: Some(ewf_image::MediaType::SingleFiles),
                    ..ewf_image::WriteMediaProfile::default()
                },
                single_files: Some(rich_single_file_catalog(data.len() as u64)),
                ..ewf_image::WriteOptions::default()
            },
        },
    ];

    for case in cases {
        let path = dir.path().join(case.filename);
        let mut writer = ewf_image::EwfWriter::create(&path, case.options)?;
        writer.write_all(case.data)?;
        let result = writer.finish()?;

        let mut expected = case.data.to_vec();
        expected.resize(usize::try_from(result.logical_size)?, 0);

        compare_ewfexport_bytes(&ewfexport, &path, &expected)?;
        compare_with_ewfexport(&ewfexport, &path)?;
    }

    for (index, compression) in [
        ewf_image::WriteCompression::None,
        ewf_image::WriteCompression::Zlib,
    ]
    .into_iter()
    .enumerate()
    {
        let path = dir.path().join(format!("sequential-{index}.Ex01"));
        let mut settings = ewf_image::SequentialOptions::new(split_data.len() as u64);
        settings.write.compression = compression;
        settings.write.sectors_per_chunk = 1;
        settings.chunks_per_segment = 7;
        let mut writer = ewf_image::SequentialWriter::create(&path, settings)?;
        writer.write_all(&split_data)?;
        let written = writer.finish()?;
        let mut expected = split_data.clone();
        expected.resize(written.logical_size as usize, 0);
        compare_ewfexport_bytes(&ewfexport, &path, &expected)?;
    }

    Ok(())
}

#[test]
#[ignore = "requires ewfinfo"]
fn external_writer_metadata_matches_ewfinfo() -> Result<(), Box<dyn Error>> {
    let ewfinfo = env::var_os("EWFINFO").unwrap_or_else(|| OsString::from("ewfinfo"));
    let dir = tempfile::tempdir()?;

    for case in writer_metadata_oracle_cases() {
        let path = dir.path().join(case.filename);
        let mut writer = ewf_image::EwfWriter::create(&path, case.options)?;
        writer.write_all(&case.data)?;
        writer.finish()?;
        compare_with_ewfinfo(&ewfinfo, &path)?;
    }

    Ok(())
}

#[test]
#[ignore = "requires ewfinfo"]
fn external_writer_range_sections_match_ewfinfo() -> Result<(), Box<dyn Error>> {
    let ewfinfo = env::var_os("EWFINFO").unwrap_or_else(|| OsString::from("ewfinfo"));
    let dir = tempfile::tempdir()?;
    let data = patterned_data(4096);
    let sessions = vec![
        ewf_image::SectorRange {
            first_sector: 0,
            sector_count: 4,
        },
        ewf_image::SectorRange {
            first_sector: 4,
            sector_count: 4,
        },
    ];
    let tracks = vec![
        ewf_image::SectorRange {
            first_sector: 0,
            sector_count: 4,
        },
        ewf_image::SectorRange {
            first_sector: 4,
            sector_count: 4,
        },
    ];
    let acquisition_errors = vec![ewf_image::AcquisitionError {
        first_sector: 2,
        sector_count: 1,
    }];

    for (filename, format) in [
        ("writer-ranges.E01", ewf_image::WriteFormat::Ewf1Physical),
        ("writer-ranges.Ex01", ewf_image::WriteFormat::Ewf2Physical),
    ] {
        let path = dir.path().join(filename);
        let mut writer = ewf_image::EwfWriter::create(
            &path,
            ewf_image::WriteOptions {
                format,
                acquisition_errors: acquisition_errors.clone(),
                sessions: sessions.clone(),
                tracks: tracks.clone(),
                ..ewf_image::WriteOptions::default()
            },
        )?;
        writer.write_all(&data)?;
        writer.finish()?;
        compare_with_ewfinfo(&ewfinfo, &path)?;
    }

    Ok(())
}

#[test]
#[ignore = "requires ewfexport, ewfinfo, and ewfverify"]
fn external_acquisition_bad_sectors_match_ewf_tools() -> Result<(), Box<dyn Error>> {
    use std::io::{Cursor, Seek, SeekFrom};
    use std::ops::ControlFlow;

    struct DamagedSource(Cursor<Vec<u8>>);
    const BAD: [u64; 5] = [1, 7, 13, 14, 21];
    impl Read for DamagedSource {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            let start = self.0.position();
            let end = start + bytes.len() as u64;
            if BAD
                .iter()
                .any(|sector| sector * 512 < end && (sector + 1) * 512 > start)
            {
                return Err(std::io::Error::other("simulated unreadable sector"));
            }
            self.0.read(bytes)
        }
    }
    impl Seek for DamagedSource {
        fn seek(&mut self, offset: SeekFrom) -> std::io::Result<u64> {
            self.0.seek(offset)
        }
    }
    let tools = EwfToolchain::from_env();
    for compression in [
        ewf_image::WriteCompression::None,
        ewf_image::WriteCompression::Zlib,
    ] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("bad-sectors.E01");
        let mut expected = patterned_data(24 * 512);
        let mut source = DamagedSource(Cursor::new(expected.clone()));
        let mut options = ewf_image::AcquisitionOptions::new(expected.len() as u64);
        options.sectors_per_chunk = 2;
        options.chunks_per_segment = 3;
        options.compression = compression;
        let read_options = ewf_image::AcquisitionReadOptions {
            unreadable_sector_policy: ewf_image::UnreadableSectorPolicy::ZeroFill,
            ..ewf_image::AcquisitionReadOptions::default()
        };
        let identity = [0x31; 32];
        let mut writer = ewf_image::AcquisitionWriter::create(&path, &options, identity)?;
        let outcome = writer.acquire_with_progress(&mut source, &read_options, |progress| {
            if progress.checkpoint_bytes >= 12 * 512 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })?;
        assert_eq!(outcome.status, ewf_image::AcquisitionStatus::Cancelled);
        drop(writer);
        let checkpoint =
            ewf_image::AcquisitionWriter::inspect_checkpoint(&path, &options, identity)?;
        assert_eq!(checkpoint.substituted_sectors, 2);
        let mut writer = ewf_image::AcquisitionWriter::resume(&path, &options, identity)?;
        let outcome = writer.acquire_from(&mut source, &read_options)?;
        assert_eq!(outcome.progress.substituted_sectors, 5);
        writer.finish()?;
        for sector in BAD {
            expected[sector as usize * 512..(sector as usize + 1) * 512].fill(0);
        }
        compare_ewfexport_bytes(&tools.ewfexport, &path, &expected)?;
        compare_with_ewfinfo(&tools.ewfinfo, &path)?;
        verify_with_ewfverify(&tools.ewfverify, &path)?;
    }
    Ok(())
}

#[test]
#[ignore = "requires ewfexport, ewfinfo, and ewfverify"]
fn external_streaming_acquisition_matches_ewf_tools() -> Result<(), Box<dyn Error>> {
    let tools = EwfToolchain::from_env();
    let data = patterned_data(11 * 32_768 + 512);
    for compression in [
        ewf_image::WriteCompression::None,
        ewf_image::WriteCompression::Zlib,
    ] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("acquired.E01");
        let mut options = ewf_image::AcquisitionOptions::new(data.len() as u64);
        options.chunks_per_segment = 3;
        options.compression = compression;
        options
            .metadata
            .set_header_value("case_number", "streamed-resume-oracle");
        let identity = [0x35; 32];
        let mut writer = ewf_image::AcquisitionWriter::create(&path, &options, identity)?;
        writer.write_all(&data[..4 * 32_768 + 137])?;
        assert_eq!(writer.checkpoint()?, 4 * 32_768);
        drop(writer);
        let mut writer = ewf_image::AcquisitionWriter::resume(&path, &options, identity)?;
        writer.write_all(&data[writer.checkpoint_offset() as usize..])?;
        let result = writer.finish()?;
        assert_eq!(
            result.computed_sha256,
            <[u8; 32]>::from(Sha256::digest(&data))
        );
        compare_ewfexport_bytes(&tools.ewfexport, &path, &data)?;
        compare_with_ewfinfo(&tools.ewfinfo, &path)?;
        verify_with_ewfverify(&tools.ewfverify, &path)?;
    }
    Ok(())
}

#[test]
#[ignore = "requires ewfexport, ewfinfo, and ewfverify"]
fn external_writer_resumed_output_matches_ewf_tools() -> Result<(), Box<dyn Error>> {
    let ewfexport = env::var_os("EWFEXPORT").unwrap_or_else(|| OsString::from("ewfexport"));
    let ewfinfo = env::var_os("EWFINFO").unwrap_or_else(|| OsString::from("ewfinfo"));
    let ewfverify = env::var_os("EWFVERIFY").unwrap_or_else(|| OsString::from("ewfverify"));
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("resume.E01");
    let first = patterned_data(32_768);
    let second = patterned_data(49_152);

    {
        let mut writer = ewf_image::EwfWriter::create(&path, ewf_image::WriteOptions::default())?;
        writer.write_all(&first)?;
        writer.finish_incomplete()?;
    }

    {
        let mut writer = ewf_image::EwfWriter::resume(&path)?;
        writer.write_all(&second)?;
        writer.finish()?;
    }

    let mut expected = first;
    expected.extend_from_slice(&second);
    compare_ewfexport_bytes(&ewfexport, &path, &expected)?;
    compare_with_ewfinfo(&ewfinfo, &path)?;
    verify_with_ewfverify(&ewfverify, &path)?;

    Ok(())
}

#[test]
#[ignore = "requires ewfexport"]
fn external_writer_bzip2_documents_external_tool_limitation() -> Result<(), Box<dyn Error>> {
    let ewfexport = env::var_os("EWFEXPORT").unwrap_or_else(|| OsString::from("ewfexport"));
    let dir = tempfile::tempdir()?;
    let data = (0..131_072)
        .map(|index| ((index * 31 + index / 17) % 251) as u8)
        .collect::<Vec<_>>();
    let path = dir.path().join("writer-bzip2.Ex01");

    let mut writer = ewf_image::EwfWriter::create(
        &path,
        ewf_image::WriteOptions {
            format: ewf_image::WriteFormat::Ewf2Physical,
            compression: ewf_image::WriteCompression::Bzip2,
            compression_values: ewf_image::WriteCompressionValues {
                level: ewf_image::WriteCompressionLevel::Best,
                ..ewf_image::WriteCompressionValues::default()
            },
            ..ewf_image::WriteOptions::default()
        },
    )?;
    writer.write_all(&data)?;
    writer.finish()?;

    let image = ewf_image::Image::open(&path)?;
    assert_eq!(
        image.info().media.compression_method,
        Some(ewf_image::CompressionMethod::Bzip2)
    );
    let mut decoded = vec![0; data.len()];
    let read = image.read_at(&mut decoded, 0)?;
    assert_eq!(read, data.len());
    assert_eq!(decoded, data);

    let output = Command::new(ewfexport)
        .arg("-q")
        .arg("-f")
        .arg("raw")
        .arg("-t")
        .arg("-")
        .arg(&path)
        .stdin(Stdio::null())
        .output()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "external tool unexpectedly exported writer-created BZip2 EWF2 output successfully"
    );
    assert!(
        stderr.contains("device_information_section_read_file_io_pool")
            && stderr.contains("unable to decompress string"),
        "unexpected external-tool BZip2 failure for {}:\nstdout:\n{}\nstderr:\n{}",
        path.display(),
        String::from_utf8_lossy(&output.stdout),
        stderr
    );
    assert!(
        stderr.contains("internal_handle_open_read_segment_file_section_data")
            || stderr.contains("internal_handle_open_read_device_information"),
        "external-tool BZip2 failure did not identify the device-information read phase for {}:\nstdout:\n{}\nstderr:\n{}",
        path.display(),
        String::from_utf8_lossy(&output.stdout),
        stderr
    );

    Ok(())
}

#[test]
#[ignore = "requires an external tool build that can export EWF2 BZip2 output"]
fn external_writer_bzip2_matches_ewfexport_when_tool_supports_it() -> Result<(), Box<dyn Error>> {
    let ewfexport = env::var_os("EWFEXPORT").unwrap_or_else(|| OsString::from("ewfexport"));
    let dir = tempfile::tempdir()?;
    let data = patterned_data(131_072);
    let path = dir.path().join("writer-bzip2.Ex01");

    let mut writer = ewf_image::EwfWriter::create(
        &path,
        ewf_image::WriteOptions {
            format: ewf_image::WriteFormat::Ewf2Physical,
            compression: ewf_image::WriteCompression::Bzip2,
            compression_values: ewf_image::WriteCompressionValues {
                level: ewf_image::WriteCompressionLevel::Best,
                ..ewf_image::WriteCompressionValues::default()
            },
            ..ewf_image::WriteOptions::default()
        },
    )?;
    writer.write_all(&data)?;
    let result = writer.finish()?;

    let mut expected = data;
    expected.resize(usize::try_from(result.logical_size)?, 0);
    compare_ewfexport_bytes(&ewfexport, &path, &expected)?;
    Ok(())
}

#[test]
#[ignore = "requires ewfinfo"]
fn external_writer_logical_single_files_match_ewfinfo() -> Result<(), Box<dyn Error>> {
    let ewfinfo = env::var_os("EWFINFO").unwrap_or_else(|| OsString::from("ewfinfo"));
    let dir = tempfile::tempdir()?;
    let data = patterned_data(4096);

    for (filename, format) in [
        (
            "writer-ewf2-single-files.Lx01",
            ewf_image::WriteFormat::Ewf2Logical,
        ),
        (
            "writer-logical-single-files.L01",
            ewf_image::WriteFormat::Ewf1Logical,
        ),
    ] {
        let path = dir.path().join(filename);
        let mut writer = ewf_image::EwfWriter::create(
            &path,
            ewf_image::WriteOptions {
                format,
                media_profile: ewf_image::WriteMediaProfile {
                    media_type: Some(ewf_image::MediaType::SingleFiles),
                    ..ewf_image::WriteMediaProfile::default()
                },
                single_files: Some(rich_single_file_catalog(data.len() as u64)),
                ..ewf_image::WriteOptions::default()
            },
        )?;
        writer.write_all(&data)?;
        writer.finish()?;

        compare_with_ewfinfo(&ewfinfo, &path)?;
        let hierarchy = ewfinfo_hierarchy(&ewfinfo, &path)?;
        assert!(
            hierarchy.contains("/payload.bin"),
            "ewfinfo hierarchy output for {} did not contain /payload.bin:\n{hierarchy}",
            path.display()
        );
        let image = ewf_image::Image::open(&path)?;
        let entry = image
            .file_entry_by_path("payload.bin")?
            .ok_or("writer-created payload.bin was missing from crate reader")?;
        assert_eq!(entry.size, Some(data.len() as u64));

        let bodyfile_path = dir.path().join(format!("{filename}.bodyfile"));
        let bodyfile = ewfinfo_bodyfile(&ewfinfo, &path, &bodyfile_path)?;
        assert_eq!(
            crate_single_file_bodyfile_entries(&image),
            ewfinfo_bodyfile_entries(&bodyfile),
            "writer-created logical single-files bodyfile mismatch for {}",
            path.display()
        );
    }

    Ok(())
}

#[test]
#[ignore = "requires ewfinfo and ewfexport"]
fn external_logical_builder_files_match_ewfexport() -> Result<(), Box<dyn Error>> {
    use ewf_image::{
        LogicalEntryMetadata, LogicalWriter, SequentialOptions, WriteFormat, WriteOptions,
    };
    let ewfinfo = env::var_os("EWFINFO").unwrap_or_else(|| OsString::from("ewfinfo"));
    let ewfexport = env::var_os("EWFEXPORT").unwrap_or_else(|| OsString::from("ewfexport"));
    let dir = tempfile::tempdir()?;
    let split_payload: Vec<u8> = (0_u32..6000)
        .flat_map(|index| Sha256::digest(index.to_le_bytes()).to_vec())
        .collect();
    for (name, format) in [
        ("case.L01", WriteFormat::Ewf1Logical),
        ("case.Lx01", WriteFormat::Ewf2Logical),
        ("stream.Lx01", WriteFormat::Ewf2Logical),
        ("split.L01", WriteFormat::Ewf1Logical),
    ] {
        let path = dir.path().join(name);
        let mut writer = if name == "stream.Lx01" {
            let mut settings = SequentialOptions::new(150_003);
            settings.write.format = format;
            settings.chunks_per_segment = 2;
            LogicalWriter::create_sequential(&path, settings)?
        } else {
            LogicalWriter::create(
                &path,
                WriteOptions {
                    format,
                    maximum_segment_size: (name == "split.L01").then_some(65_536),
                    ..WriteOptions::default()
                },
            )?
        };
        let folder = writer.add_directory(
            1,
            LogicalEntryMetadata {
                name: "folder".into(),
                ..LogicalEntryMetadata::default()
            },
        )?;
        writer.add_file(
            folder,
            LogicalEntryMetadata {
                name: "data.txt".into(),
                ..LogicalEntryMetadata::default()
            },
            3,
            &mut std::io::Cursor::new(b"abc"),
        )?;
        if name == "stream.Lx01" {
            writer.add_file(
                folder,
                LogicalEntryMetadata {
                    name: "later.bin".into(),
                    ..Default::default()
                },
                150_000,
                &mut std::io::Cursor::new(vec![73; 150_000]),
            )?;
        } else if name == "split.L01" {
            writer.add_file(
                folder,
                LogicalEntryMetadata {
                    name: "later.bin".into(),
                    ..Default::default()
                },
                split_payload.len() as u64,
                &mut std::io::Cursor::new(split_payload.as_slice()),
            )?;
        }
        let written = writer.finish()?;
        if name == "split.L01" {
            assert!(written.segment_paths.len() > 1, "expected split L01 output");
            assert_eq!(written.chunk_size, 32_768);
        }
        assert!(ewfinfo_hierarchy(&ewfinfo, &path)?.contains("folder/data.txt"));
        let output = dir.path().join(format!("{name}-export"));
        let result = Command::new(&ewfexport)
            .args(["-u", "-q", "-f", "files", "-t"])
            .arg(&output)
            .arg(&path)
            .output()?;
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fs::read(output.join("folder/data.txt"))?, b"abc");
        if name == "stream.Lx01" {
            assert_eq!(
                fs::read(output.join("folder/later.bin"))?,
                vec![73; 150_000]
            );
        } else if name == "split.L01" {
            assert_eq!(fs::read(output.join("folder/later.bin"))?, split_payload);
        }
    }
    Ok(())
}

#[test]
#[ignore = "requires pinned ewfexport, ewfinfo, and ewfverify"]
fn external_sequential_ewf1_split_matches_libewf() -> Result<(), Box<dyn Error>> {
    use ewf_image::{SequentialOptions, SequentialWriter, WriteCompression, WriteFormat};

    let ewfinfo = env::var_os("EWFINFO").unwrap_or_else(|| OsString::from("ewfinfo"));
    let ewfexport = env::var_os("EWFEXPORT").unwrap_or_else(|| OsString::from("ewfexport"));
    let ewfverify = env::var_os("EWFVERIFY").unwrap_or_else(|| OsString::from("ewfverify"));
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("stream.E01");
    let mut data = patterned_data(18_777);
    let mut settings = SequentialOptions::new(data.len() as u64);
    settings.write.format = WriteFormat::Ewf1Physical;
    settings.write.compression = WriteCompression::Zlib;
    settings.write.sectors_per_chunk = 1;
    settings.write.maximum_segment_size = Some(4096);
    settings.chunks_per_segment = 3;
    let mut writer = SequentialWriter::create(&path, settings)?;
    writer.write_all(&data)?;
    let written = writer.finish()?;
    assert!(written.segment_paths.len() > 1);
    data.resize(data.len().div_ceil(512) * 512, 0);
    compare_ewfexport_bytes(&ewfexport, &path, &data)?;
    compare_with_ewfinfo(&ewfinfo, &path)?;
    verify_with_ewfverify(&ewfverify, &path)?;
    Ok(())
}

#[test]
#[ignore = "requires ewfexport and ewfinfo"]
fn external_8k_chunk_split_logical_matches_ewfexport() -> Result<(), Box<dyn Error>> {
    use ewf_image::{LogicalEntryMetadata, LogicalWriter, SequentialOptions, WriteFormat};

    let ewfinfo = env::var_os("EWFINFO").unwrap_or_else(|| OsString::from("ewfinfo"));
    let ewfexport = env::var_os("EWFEXPORT").unwrap_or_else(|| OsString::from("ewfexport"));
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("small.Lx01");
    let data = patterned_data(32_769);
    let mut settings = SequentialOptions::new(data.len() as u64);
    settings.write.format = WriteFormat::Ewf2Logical;
    settings.write.sectors_per_chunk = 16;
    settings.chunks_per_segment = 2;
    let mut writer = LogicalWriter::create_sequential(&path, settings)?;
    let folder = writer.add_directory(
        1,
        LogicalEntryMetadata {
            name: "folder".into(),
            ..Default::default()
        },
    )?;
    writer.add_file(
        folder,
        LogicalEntryMetadata {
            name: "small.bin".into(),
            ..Default::default()
        },
        data.len() as u64,
        &mut std::io::Cursor::new(&data),
    )?;
    let written = writer.finish()?;
    assert!(written.segment_paths.len() > 1);
    assert!(ewfinfo_hierarchy(&ewfinfo, &path)?.contains("folder/small.bin"));
    let target = dir.path().join("export");
    let result = Command::new(&ewfexport)
        .args(["-u", "-q", "-f", "files", "-t"])
        .arg(&target)
        .arg(&path)
        .output()?;
    assert!(
        result.status.success(),
        "ewfexport failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(target.join("folder/small.bin"))?, data);
    Ok(())
}

#[test]
#[ignore = "requires real L01/Lx01 single-files fixtures and ewfinfo"]
fn external_logical_single_files_fixtures_match_ewfinfo_hierarchy() -> Result<(), Box<dyn Error>> {
    let ewfinfo = env::var_os("EWFINFO").unwrap_or_else(|| OsString::from("ewfinfo"));
    let paths = logical_single_file_fixture_paths()?;
    assert!(
        !paths.is_empty(),
        "set EWF_LOGICAL_SINGLE_FILES_DIR to a directory containing real L01/Lx01 single-files fixtures"
    );

    for path in paths {
        compare_with_ewfinfo(&ewfinfo, &path)?;
        let hierarchy = ewfinfo_hierarchy(&ewfinfo, &path)?;
        let image = ewf_image::Image::open(&path)?;
        let Some(root_entry) = image.root_file_entry() else {
            return Err(format!("crate found no logical file root for {}", path.display()).into());
        };
        assert!(
            !root_entry.children.is_empty(),
            "crate found no logical file entries for {} but ewfinfo -H returned:\n{hierarchy}",
            path.display()
        );
        for entry in &root_entry.children {
            if let Some(name) = entry.name.as_deref() {
                assert!(
                    hierarchy.contains(name),
                    "ewfinfo hierarchy for {} did not contain crate entry {name:?}:\n{hierarchy}",
                    path.display()
                );
            }
        }
        let bodyfile_path = tempfile::NamedTempFile::new()?.into_temp_path();
        let bodyfile = ewfinfo_bodyfile(&ewfinfo, &path, bodyfile_path.as_ref())?;
        assert_eq!(
            crate_single_file_bodyfile_entries(&image),
            ewfinfo_bodyfile_entries(&bodyfile),
            "logical single-files bodyfile mismatch for {}",
            path.display()
        );
    }

    Ok(())
}

#[test]
#[cfg(feature = "verify")]
#[ignore = "requires external logical images and independently computed media hash sidecars"]
fn external_logical_entry_bytes_and_media_match_references() -> Result<(), Box<dyn Error>> {
    let image_root = PathBuf::from(
        env::var_os("EWF_LOGICAL_SINGLE_FILES_DIR")
            .ok_or("set EWF_LOGICAL_SINGLE_FILES_DIR to the external image directory")?,
    );
    let reference_root = PathBuf::from(
        env::var_os("EWF_LOGICAL_MEDIA_HASH_DIR")
            .ok_or("set EWF_LOGICAL_MEDIA_HASH_DIR to independent media hash sidecars")?,
    );
    let paths = logical_single_file_fixture_paths_from_root(&image_root)?;
    assert!(!paths.is_empty(), "external logical corpus is empty");

    let mut hashed_files = 0_usize;
    let mut split_images = 0_usize;
    for path in &paths {
        let image = ewf_image::Image::open(path)?;
        split_images += usize::from(image.number_of_segments() > 1);
        let relative = path.strip_prefix(&image_root)?;
        let mut sidecar_name = relative
            .file_name()
            .ok_or("logical image path has no file name")?
            .to_os_string();
        sidecar_name.push(".media.sha256");
        let sidecar = reference_root
            .join(relative.parent().unwrap_or_else(|| Path::new("")))
            .join(sidecar_name);
        let reference = fs::read_to_string(&sidecar)?;
        let mut fields = reference.split_whitespace();
        let expected_sha256 = fields.next().ok_or("media reference has no SHA256")?;
        let expected_bytes: u64 = fields
            .next()
            .ok_or("media reference has no byte count")?
            .parse()?;
        assert!(fields.next().is_none(), "media reference has extra fields");
        assert_eq!(expected_sha256.len(), 64, "invalid media SHA256 length");
        assert!(
            expected_sha256.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "invalid media SHA256"
        );

        let media = image.verify_with_options(&ewf_image::VerifyOptions::default())?;
        assert_eq!(media.bytes_verified, expected_bytes, "media size differs");
        assert_eq!(
            hex_lower(&media.hashes.sha256),
            expected_sha256.to_ascii_lowercase(),
            "media SHA256 differs"
        );

        let root = image
            .root_file_entry()
            .ok_or("logical image has no entry root")?;
        assert!(
            !root.children.is_empty(),
            "logical image has no child entries"
        );
        let mut stack = vec![root];
        let mut entries = 0_usize;
        while let Some(entry) = stack.pop() {
            let entry_index = entries;
            entries += 1;
            stack.extend(entry.children.iter().rev());
            if entry.file_entry_type == Some(ewf_image::SingleFileEntryType::File) {
                let result = image.verify_single_file(entry)?;
                assert_ne!(
                    result.references_match(),
                    Some(false),
                    "stored hash mismatch at entry {entry_index}"
                );
                hashed_files += usize::from(result.references_match() == Some(true));
            } else if let Some(size) = entry.size
                && size > 0
            {
                let mut buffer = vec![0_u8; BUFFER_SIZE];
                let mut offset = 0_u64;
                while offset < size {
                    let length = (size - offset).min(BUFFER_SIZE as u64) as usize;
                    let read =
                        image.read_single_file_at_strict(entry, &mut buffer[..length], offset)?;
                    assert_eq!(read, length, "short read at entry {entry_index}");
                    offset += read as u64;
                }
            }
        }
    }
    assert!(hashed_files > 0, "corpus has no stored file hashes");
    if env::var_os("EWF_LOGICAL_REQUIRE_SPLIT").as_deref() == Some(std::ffi::OsStr::new("1")) {
        assert!(split_images > 0, "corpus has no split logical image");
    }
    eprintln!(
        "validated {} logical images, {} split sets, and {} stored file hashes",
        paths.len(),
        split_images,
        hashed_files
    );
    Ok(())
}

#[test]
#[cfg(feature = "verify")]
#[ignore = "requires external logical images and independently produced entry manifests"]
fn external_logical_entries_match_independent_manifests() -> Result<(), Box<dyn Error>> {
    let image_root = PathBuf::from(
        env::var_os("EWF_LOGICAL_SINGLE_FILES_DIR")
            .ok_or("set EWF_LOGICAL_SINGLE_FILES_DIR to the external image directory")?,
    );
    let manifest_root = PathBuf::from(
        env::var_os("EWF_LOGICAL_ENTRY_MANIFEST_DIR")
            .ok_or("set EWF_LOGICAL_ENTRY_MANIFEST_DIR to independent entry manifests")?,
    );
    let paths = logical_single_file_fixture_paths_from_root(&image_root)?;
    assert!(!paths.is_empty(), "external logical corpus is empty");

    let mut split_images = 0_usize;
    let mut entries = 0_usize;
    for path in &paths {
        let image = ewf_image::Image::open(path)?;
        split_images += usize::from(image.number_of_segments() > 1);
        let relative = path.strip_prefix(&image_root)?;
        let mut sidecar_name = relative
            .file_name()
            .ok_or("logical image path has no file name")?
            .to_os_string();
        sidecar_name.push(".entries.jsonl");
        let manifest = manifest_root
            .join(relative.parent().unwrap_or_else(|| Path::new("")))
            .join(sidecar_name);
        entries += check_logical_entry_manifest(&image, &manifest)?;
    }
    if env::var_os("EWF_LOGICAL_REQUIRE_SPLIT").as_deref() == Some(std::ffi::OsStr::new("1")) {
        assert!(split_images > 0, "corpus has no split logical image");
    }
    eprintln!(
        "validated {} logical images, {} split sets, and {} entry digests",
        paths.len(),
        split_images,
        entries
    );
    Ok(())
}

#[cfg(feature = "verify")]
fn check_logical_entry_manifest(
    image: &ewf_image::Image,
    manifest: &Path,
) -> Result<usize, Box<dyn Error>> {
    let mut lines = BufReader::new(fs::File::open(manifest)?).lines();
    let header = next_logical_manifest_record(&mut lines, "manifest header")?;
    let expected_count = header["entry_count"]
        .as_u64()
        .ok_or("manifest header has no entry_count")?;
    let media = image.verify_with_options(&ewf_image::VerifyOptions::default())?;
    let expected_header = serde_json::json!({
        "schema": "ewf-logical-entries-v1",
        "media_size": media.bytes_verified,
        "media_sha256": hex_lower(&media.hashes.sha256),
        "segment_count": image.number_of_segments(),
        "entry_count": expected_count,
    });
    if header != expected_header {
        return Err(format!(
            "logical entry manifest header mismatch in {}: expected {header}, read {expected_header}",
            manifest.display()
        )
        .into());
    }

    let root = image
        .root_file_entry()
        .ok_or("logical image has no entry root")?;
    let mut stack = vec![(root, None)];
    let mut count = 0_u64;
    while let Some((entry, parent)) = stack.pop() {
        let record = next_logical_manifest_record(&mut lines, "entry record")?;
        let size = entry.size.unwrap_or(0);
        let sha256 = if entry.file_entry_type == Some(ewf_image::SingleFileEntryType::File) {
            let result = image.verify_single_file(entry)?;
            if result.references_match() == Some(false) {
                return Err(format!("stored hash mismatch at entry {count}").into());
            }
            if result.bytes_verified != size {
                return Err(format!("short verification at entry {count}").into());
            }
            hex_lower(&result.hashes.sha256)
        } else {
            hash_non_file_logical_entry(image, entry, size)?
        };
        let expected = serde_json::json!({
            "index": count,
            "parent": parent,
            "name_utf16": logical_name_utf16_hex(entry),
            "kind": logical_entry_kind(entry),
            "size": size,
            "sha256": sha256,
        });
        if record != expected {
            return Err(format!(
                "logical entry {count} differs from {}: expected {record}, read {expected}",
                manifest.display()
            )
            .into());
        }
        stack.extend(
            entry
                .children
                .iter()
                .rev()
                .map(|child| (child, Some(count))),
        );
        count += 1;
    }
    if count != expected_count || lines.next().transpose()?.is_some() {
        return Err(format!("logical entry count differs from {}", manifest.display()).into());
    }
    Ok(usize::try_from(count)?)
}

#[cfg(feature = "verify")]
fn next_logical_manifest_record(
    lines: &mut impl Iterator<Item = std::io::Result<String>>,
    label: &str,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let line = lines.next().ok_or_else(|| format!("missing {label}"))??;
    Ok(serde_json::from_str(&line)?)
}

#[cfg(feature = "verify")]
fn logical_name_utf16_hex(entry: &ewf_image::SingleFileEntry) -> String {
    let units = entry.name_utf16.clone().unwrap_or_else(|| {
        entry
            .name
            .as_deref()
            .unwrap_or_default()
            .encode_utf16()
            .collect()
    });
    units.iter().map(|unit| format!("{unit:04x}")).collect()
}

#[cfg(feature = "verify")]
fn logical_entry_kind(entry: &ewf_image::SingleFileEntry) -> &'static str {
    match entry.file_entry_type {
        Some(ewf_image::SingleFileEntryType::File) => "file",
        Some(ewf_image::SingleFileEntryType::Directory) => "directory",
        Some(ewf_image::SingleFileEntryType::Unknown) => "unknown",
        None => "unspecified",
    }
}

#[cfg(feature = "verify")]
fn hash_non_file_logical_entry(
    image: &ewf_image::Image,
    entry: &ewf_image::SingleFileEntry,
    size: u64,
) -> Result<String, Box<dyn Error>> {
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    let mut offset = 0_u64;
    while offset < size {
        let length = (size - offset).min(BUFFER_SIZE as u64) as usize;
        let read = image.read_single_file_at_strict(entry, &mut buffer[..length], offset)?;
        if read != length {
            return Err(format!("short logical entry read at offset {offset}").into());
        }
        hash.update(&buffer[..read]);
        offset += read as u64;
    }
    Ok(hex_lower(&hash.finalize()))
}

#[test]
#[cfg(feature = "verify")]
fn logical_entry_manifest_checks_hierarchy_and_content() -> Result<(), Box<dyn Error>> {
    use ewf_image::{LogicalEntryMetadata, LogicalWriter, WriteFormat, WriteOptions};

    let dir = tempfile::tempdir()?;
    let path = dir.path().join("known.L01");
    let mut writer = LogicalWriter::create(
        &path,
        WriteOptions {
            format: WriteFormat::Ewf1Logical,
            ..WriteOptions::default()
        },
    )?;
    let folder = writer.add_directory(
        1,
        LogicalEntryMetadata {
            name: "folder".into(),
            ..Default::default()
        },
    )?;
    writer.add_file(
        folder,
        LogicalEntryMetadata {
            name: "data.txt".into(),
            ..Default::default()
        },
        3,
        &mut std::io::Cursor::new(b"abc"),
    )?;
    let written = writer.finish()?;
    assert_eq!(written.segment_paths.len(), 1);
    let records = vec![
        serde_json::json!({
            "schema": "ewf-logical-entries-v1",
            "media_size": 3,
            "media_sha256": sha256_hex(b"abc"),
            "segment_count": 1,
            "entry_count": 3,
        }),
        serde_json::json!({
            "index": 0,
            "parent": null,
            "name_utf16": "",
            "kind": "directory",
            "size": 0,
            "sha256": sha256_hex(b""),
        }),
        serde_json::json!({
            "index": 1,
            "parent": 0,
            "name_utf16": "0066006f006c006400650072",
            "kind": "directory",
            "size": 0,
            "sha256": sha256_hex(b""),
        }),
        serde_json::json!({
            "index": 2,
            "parent": 1,
            "name_utf16": "0064006100740061002e007400780074",
            "kind": "file",
            "size": 3,
            "sha256": sha256_hex(b"abc"),
        }),
    ];
    let manifest = dir.path().join("known.L01.entries.jsonl");
    let write_records = |records: &[serde_json::Value]| -> Result<(), Box<dyn Error>> {
        let jsonl = records
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&manifest, format!("{jsonl}\n"))?;
        Ok(())
    };
    let image = ewf_image::Image::open(&path)?;
    write_records(&records)?;
    assert_eq!(check_logical_entry_manifest(&image, &manifest)?, 3);

    let mut wrong_parent = records.clone();
    wrong_parent[3]["parent"] = serde_json::json!(0);
    write_records(&wrong_parent)?;
    assert!(check_logical_entry_manifest(&image, &manifest).is_err());

    let mut wrong_digest = records;
    wrong_digest[3]["sha256"] = serde_json::json!(sha256_hex(b"abd"));
    write_records(&wrong_digest)?;
    assert!(check_logical_entry_manifest(&image, &manifest).is_err());
    Ok(())
}

#[test]
#[ignore = "requires ewfacquirestream, ewfexport, ewfinfo, and ewfverify"]
fn ewf_tool_generated_fixture_matrix_matches_oracles() -> Result<(), Box<dyn Error>> {
    let tools = EwfToolchain::from_env();
    let dir = tempfile::tempdir()?;
    let data = patterned_data(1_310_720);
    let _paths = generated_ewf_tool_oracle_paths(&tools, dir.path(), &data)?;

    Ok(())
}

#[derive(Debug)]
struct EwfToolchain {
    ewfacquirestream: OsString,
    ewfexport: OsString,
    ewfinfo: OsString,
    ewfverify: OsString,
}

impl EwfToolchain {
    fn from_env() -> Self {
        Self {
            ewfacquirestream: env::var_os("EWFACQUIRESTREAM")
                .unwrap_or_else(|| OsString::from("ewfacquirestream")),
            ewfexport: env::var_os("EWFEXPORT").unwrap_or_else(|| OsString::from("ewfexport")),
            ewfinfo: env::var_os("EWFINFO").unwrap_or_else(|| OsString::from("ewfinfo")),
            ewfverify: env::var_os("EWFVERIFY").unwrap_or_else(|| OsString::from("ewfverify")),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct EwfFixtureCase {
    name: &'static str,
    format: &'static str,
    compression: &'static str,
    media_type: &'static str,
    media_flags: &'static str,
    digest: Option<&'static str>,
    segment_size: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct EwfExportFixtureCase {
    name: &'static str,
    output_format: &'static str,
    output_extension: &'static str,
}

fn ewf_tool_export_fixture_cases() -> Vec<EwfExportFixtureCase> {
    vec![EwfExportFixtureCase {
        name: "smart-from-encase6",
        output_format: "smart",
        output_extension: "s01",
    }]
}

fn ewf_tool_fixture_cases() -> Vec<EwfFixtureCase> {
    vec![
        EwfFixtureCase {
            name: "encase2-none",
            format: "encase2",
            compression: "none",
            media_type: "fixed",
            media_flags: "physical",
            digest: None,
            segment_size: None,
        },
        EwfFixtureCase {
            name: "encase3-none",
            format: "encase3",
            compression: "none",
            media_type: "fixed",
            media_flags: "physical",
            digest: None,
            segment_size: None,
        },
        EwfFixtureCase {
            name: "encase4-none",
            format: "encase4",
            compression: "none",
            media_type: "fixed",
            media_flags: "physical",
            digest: None,
            segment_size: None,
        },
        EwfFixtureCase {
            name: "encase5-none",
            format: "encase5",
            compression: "none",
            media_type: "fixed",
            media_flags: "physical",
            digest: None,
            segment_size: None,
        },
        EwfFixtureCase {
            name: "encase6-fast",
            format: "encase6",
            compression: "fast",
            media_type: "fixed",
            media_flags: "physical",
            digest: None,
            segment_size: None,
        },
        EwfFixtureCase {
            name: "encase6-sha1",
            format: "encase6",
            compression: "none",
            media_type: "fixed",
            media_flags: "physical",
            digest: Some("sha1"),
            segment_size: None,
        },
        EwfFixtureCase {
            name: "encase6-split",
            format: "encase6",
            compression: "none",
            media_type: "fixed",
            media_flags: "physical",
            digest: None,
            segment_size: Some(1_048_576),
        },
        EwfFixtureCase {
            name: "encase6-removable",
            format: "encase6",
            compression: "none",
            media_type: "removable",
            media_flags: "physical",
            digest: None,
            segment_size: None,
        },
        EwfFixtureCase {
            name: "encase6-optical",
            format: "encase6",
            compression: "none",
            media_type: "optical",
            media_flags: "physical",
            digest: None,
            segment_size: None,
        },
        EwfFixtureCase {
            name: "encase7-best",
            format: "encase7",
            compression: "best",
            media_type: "fixed",
            media_flags: "physical",
            digest: None,
            segment_size: None,
        },
        EwfFixtureCase {
            name: "encase7-logical",
            format: "encase7",
            compression: "none",
            media_type: "fixed",
            media_flags: "logical",
            digest: None,
            segment_size: None,
        },
        EwfFixtureCase {
            name: "linen5-none",
            format: "linen5",
            compression: "none",
            media_type: "fixed",
            media_flags: "physical",
            digest: None,
            segment_size: None,
        },
        EwfFixtureCase {
            name: "linen6-fast",
            format: "linen6",
            compression: "fast",
            media_type: "fixed",
            media_flags: "physical",
            digest: None,
            segment_size: None,
        },
        EwfFixtureCase {
            name: "linen7-none",
            format: "linen7",
            compression: "none",
            media_type: "fixed",
            media_flags: "physical",
            digest: None,
            segment_size: None,
        },
        EwfFixtureCase {
            name: "ftk-none",
            format: "ftk",
            compression: "none",
            media_type: "fixed",
            media_flags: "physical",
            digest: None,
            segment_size: None,
        },
        EwfFixtureCase {
            name: "encase6-logical",
            format: "encase6",
            compression: "none",
            media_type: "fixed",
            media_flags: "logical",
            digest: None,
            segment_size: None,
        },
        EwfFixtureCase {
            name: "ewfx-none",
            format: "ewfx",
            compression: "none",
            media_type: "fixed",
            media_flags: "physical",
            digest: None,
            segment_size: None,
        },
        EwfFixtureCase {
            name: "ewfx-sha256",
            format: "ewfx",
            compression: "none",
            media_type: "fixed",
            media_flags: "physical",
            digest: Some("sha256"),
            segment_size: None,
        },
        EwfFixtureCase {
            name: "ewfx-memory",
            format: "ewfx",
            compression: "none",
            media_type: "memory",
            media_flags: "physical",
            digest: None,
            segment_size: None,
        },
        EwfFixtureCase {
            name: "ewfx-logical",
            format: "ewfx",
            compression: "none",
            media_type: "fixed",
            media_flags: "logical",
            digest: None,
            segment_size: None,
        },
    ]
}

fn generated_ewf_tool_oracle_paths(
    tools: &EwfToolchain,
    root: &Path,
    data: &[u8],
) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut paths = Vec::new();

    for case in ewf_tool_fixture_cases() {
        eprintln!("checking tool-generated fixture case {case:?}");
        let first_segment = acquire_ewf_tool_fixture(&tools.ewfacquirestream, root, &case, data)?;
        if case.digest == Some("sha256") {
            let image = ewf_image::Image::open(&first_segment)?;
            assert!(
                image.hash_value("SHA256").is_some(),
                "producer omitted SHA256"
            );
            #[cfg(feature = "verify")]
            assert_eq!(image.verify()?.sha256_match, Some(true));
        }
        compare_with_ewfexport(&tools.ewfexport, &first_segment)?;
        compare_with_ewfinfo(&tools.ewfinfo, &first_segment)?;
        verify_with_ewfverify(&tools.ewfverify, &first_segment)?;
        paths.push(first_segment);
    }

    for case in ewf_tool_export_fixture_cases() {
        eprintln!("checking tool-exported fixture case {case:?}");
        let first_segment =
            export_ewf_tool_fixture(&tools.ewfacquirestream, &tools.ewfexport, root, &case, data)?;
        compare_with_ewfexport(&tools.ewfexport, &first_segment)?;
        compare_with_ewfinfo(&tools.ewfinfo, &first_segment)?;
        verify_with_ewfverify(&tools.ewfverify, &first_segment)?;
        paths.push(first_segment);
    }

    Ok(paths)
}

fn generated_closeout_oracle_paths(
    tools: &EwfToolchain,
    root: &Path,
    data: &[u8],
) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut paths = generated_ewf_tool_oracle_paths(tools, root, data)?;
    let writer_data = patterned_data(4096);

    for (filename, options) in [
        (
            "closeout-ewf2.Ex01",
            ewf_image::WriteOptions {
                format: ewf_image::WriteFormat::Ewf2Physical,
                ..ewf_image::WriteOptions::default()
            },
        ),
        (
            "closeout-ewf2-logical.Lx01",
            ewf_image::WriteOptions {
                format: ewf_image::WriteFormat::Ewf2Logical,
                ..ewf_image::WriteOptions::default()
            },
        ),
        (
            "closeout-ewf2-memory.Ex01",
            ewf_image::WriteOptions {
                format: ewf_image::WriteFormat::Ewf2Physical,
                media_profile: ewf_image::WriteMediaProfile {
                    media_type: Some(ewf_image::MediaType::Memory),
                    ..ewf_image::WriteMediaProfile::default()
                },
                ..ewf_image::WriteOptions::default()
            },
        ),
    ] {
        let path = root.join(filename);
        write_image_and_match_ewf_tools(tools, &path, options, &writer_data)?;
        paths.push(path);
    }

    let single_files_path = root.join("closeout-single-files.L01");
    let mut writer = ewf_image::EwfWriter::create(
        &single_files_path,
        ewf_image::WriteOptions {
            format: ewf_image::WriteFormat::Ewf1Logical,
            media_profile: ewf_image::WriteMediaProfile {
                media_type: Some(ewf_image::MediaType::SingleFiles),
                ..ewf_image::WriteMediaProfile::default()
            },
            single_files: Some(rich_single_file_catalog(writer_data.len() as u64)),
            ..ewf_image::WriteOptions::default()
        },
    )?;
    writer.write_all(&writer_data)?;
    writer.finish()?;
    compare_with_ewfinfo(&tools.ewfinfo, &single_files_path)?;
    let image = ewf_image::Image::open(&single_files_path)?;
    let bodyfile_path = root.join("closeout-single-files.bodyfile");
    let bodyfile = ewfinfo_bodyfile(&tools.ewfinfo, &single_files_path, &bodyfile_path)?;
    assert_eq!(
        crate_single_file_bodyfile_entries(&image),
        ewfinfo_bodyfile_entries(&bodyfile),
        "generated closeout single-files bodyfile mismatch"
    );
    paths.push(single_files_path);

    let mut hashes = ewf_image::WriteHashes::default();
    hashes.set_hash_value("SHA256", sha256_hex(&writer_data))?;
    let generic_hash_path = root.join("closeout-generic-hashes.E01");
    let mut writer = ewf_image::EwfWriter::create(
        &generic_hash_path,
        ewf_image::WriteOptions {
            hashes,
            ..ewf_image::WriteOptions::default()
        },
    )?;
    writer.write_all(&writer_data)?;
    writer.finish()?;
    let image = ewf_image::Image::open(&generic_hash_path)?;
    let expected_sha256 = sha256_hex(&writer_data);
    assert_eq!(
        image.info().stored_hashes.hash_value("SHA256"),
        Some(expected_sha256.as_str())
    );
    paths.push(generic_hash_path);

    let range_path = root.join("closeout-ranges.E01");
    let sessions = vec![
        ewf_image::SectorRange {
            first_sector: 0,
            sector_count: 4,
        },
        ewf_image::SectorRange {
            first_sector: 4,
            sector_count: 4,
        },
    ];
    let tracks = sessions.clone();
    let acquisition_errors = vec![ewf_image::AcquisitionError {
        first_sector: 2,
        sector_count: 1,
    }];
    let mut writer = ewf_image::EwfWriter::create(
        &range_path,
        ewf_image::WriteOptions {
            acquisition_errors,
            sessions,
            tracks,
            ..ewf_image::WriteOptions::default()
        },
    )?;
    writer.write_all(&writer_data)?;
    writer.finish()?;
    compare_with_ewfinfo(&tools.ewfinfo, &range_path)?;
    paths.push(range_path);

    let incomplete_path = root.join("closeout-incomplete.E01");
    let mut writer =
        ewf_image::EwfWriter::create(&incomplete_path, ewf_image::WriteOptions::default())?;
    writer.write_all(&writer_data)?;
    writer.finish_incomplete()?;
    let image = ewf_image::Image::open(&incomplete_path)?;
    assert!(
        !image.info().acquisition_complete,
        "generated incomplete fixture was not marked incomplete"
    );
    paths.push(incomplete_path);

    Ok(paths)
}

fn write_image_and_match_ewf_tools(
    tools: &EwfToolchain,
    path: &Path,
    options: ewf_image::WriteOptions,
    data: &[u8],
) -> Result<(), Box<dyn Error>> {
    let mut writer = ewf_image::EwfWriter::create(path, options)?;
    writer.write_all(data)?;
    let result = writer.finish()?;

    let mut expected = data.to_vec();
    expected.resize(usize::try_from(result.logical_size)?, 0);
    compare_ewfexport_bytes(&tools.ewfexport, path, &expected)?;
    compare_with_ewfinfo(&tools.ewfinfo, path)?;
    verify_with_ewfverify(&tools.ewfverify, path)?;
    Ok(())
}

fn acquire_ewf_tool_fixture(
    ewfacquirestream: &OsString,
    root: &Path,
    case: &EwfFixtureCase,
    data: &[u8],
) -> Result<PathBuf, Box<dyn Error>> {
    let target = root.join(case.name);
    let mut command = Command::new(ewfacquirestream);
    command
        .args(["-q", "-B"])
        .arg(data.len().to_string())
        .args(["-f", case.format])
        .args(["-c", case.compression])
        .args(["-m", case.media_type])
        .args(["-M", case.media_flags])
        .args(["-C", "case_number"])
        .args(["-D", "description"])
        .args(["-e", "examiner_name"])
        .args(["-E", "evidence_number"])
        .args(["-N", "notes"])
        .args(["-t"])
        .arg(&target)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(segment_size) = case.segment_size {
        command.args(["-S", &segment_size.to_string()]);
    }
    if let Some(digest) = case.digest {
        command.args(["-d", digest]);
    }

    let mut child = command.spawn()?;
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(data)?;
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "ewfacquirestream failed for {case:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut paths = corpus_paths_from_root(root)?;
    paths.retain(|path| {
        path.file_stem()
            .and_then(|value| value.to_str())
            .is_some_and(|stem| stem == case.name)
    });
    paths.sort();
    paths
        .into_iter()
        .next()
        .ok_or_else(|| format!("no first segment generated for {}", case.name).into())
}

fn export_ewf_tool_fixture(
    ewfacquirestream: &OsString,
    ewfexport: &OsString,
    root: &Path,
    case: &EwfExportFixtureCase,
    data: &[u8],
) -> Result<PathBuf, Box<dyn Error>> {
    let source_case = EwfFixtureCase {
        name: "smart-export-source",
        format: "encase6",
        compression: "none",
        media_type: "fixed",
        media_flags: "physical",
        digest: None,
        segment_size: None,
    };
    let source = acquire_ewf_tool_fixture(ewfacquirestream, root, &source_case, data)?;
    let target = root.join(case.name);
    let output = Command::new(ewfexport)
        .args(["-q", "-u"])
        .args(["-f", case.output_format])
        .args(["-t"])
        .arg(&target)
        .arg(&source)
        .stdin(Stdio::null())
        .output()?;
    assert!(
        output.status.success(),
        "ewfexport failed for {case:?} from {}: {}",
        source.display(),
        String::from_utf8_lossy(&output.stderr)
    );

    let path = root.join(format!("{}.{}", case.name, case.output_extension));
    assert!(
        path.exists(),
        "ewfexport did not create expected first segment {}",
        path.display()
    );
    Ok(path)
}

fn verify_with_ewfverify(ewfverify: &OsString, path: &Path) -> Result<(), Box<dyn Error>> {
    let output = Command::new(ewfverify)
        .arg("-q")
        .arg(path)
        .stdin(Stdio::null())
        .output()?;
    assert!(
        output.status.success(),
        "ewfverify failed for {}:\nstdout:\n{}\nstderr:\n{}",
        path.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn compare_with_ewfinfo(ewfinfo: &OsString, path: &Path) -> Result<(), Box<dyn Error>> {
    let image = match open_external_fixture(path) {
        Ok(image) => image,
        Err(err) if is_unsupported_encrypted_image(&err.source) => {
            eprintln!("skipping unsupported encrypted image {}", path.display());
            return Ok(());
        }
        Err(err) => return Err(Box::new(err)),
    };
    let output = Command::new(ewfinfo)
        .arg(path)
        .stdin(Stdio::null())
        .output()?;
    assert!(
        output.status.success(),
        "ewfinfo failed for {}: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    let oracle = parse_ewfinfo_metadata(&stdout);
    let info = image.info();

    if let Some(file_format) = oracle.file_format.as_deref() {
        assert!(
            ewfinfo_format_profile_matches(info.format_profile, file_format),
            "file format mismatch for {}: ewfinfo={file_format:?}, crate={:?}",
            path.display(),
            info.format_profile
        );
    }
    assert_ewfinfo_string_eq(
        info.metadata.case_number.as_deref(),
        oracle.case_number.as_deref(),
        "case number",
        path,
    );
    assert_ewfinfo_string_eq(
        info.metadata.description.as_deref(),
        oracle.description.as_deref(),
        "description",
        path,
    );
    assert_ewfinfo_string_eq(
        info.metadata.examiner.as_deref(),
        oracle.examiner.as_deref(),
        "examiner",
        path,
    );
    assert_ewfinfo_string_eq(
        info.metadata.evidence_number.as_deref(),
        oracle.evidence_number.as_deref(),
        "evidence number",
        path,
    );
    assert_ewfinfo_string_eq(
        info.metadata.notes.as_deref(),
        oracle.notes.as_deref(),
        "notes",
        path,
    );
    let acquisition_date = image.header_value("acquiry_date");
    assert_ewfinfo_date_eq(
        acquisition_date.as_deref(),
        info.metadata.acquisition_date.as_deref(),
        oracle.acquisition_date.as_deref(),
        "acquisition date",
        path,
    );
    let system_date = image.header_value("system_date");
    assert_ewfinfo_date_eq(
        system_date.as_deref(),
        info.metadata.system_date.as_deref(),
        oracle.system_date.as_deref(),
        "system date",
        path,
    );
    assert_ewfinfo_string_eq(
        info.metadata.os_version.as_deref(),
        oracle.os_version.as_deref(),
        "operating system",
        path,
    );
    assert_ewfinfo_string_eq(
        info.metadata.acquisition_software.as_deref(),
        oracle.acquisition_software.as_deref(),
        "software used",
        path,
    );
    assert_ewfinfo_string_eq(
        info.metadata.acquisition_software_version.as_deref(),
        oracle.acquisition_software_version.as_deref(),
        "software version",
        path,
    );
    assert_ewfinfo_string_eq(
        info.metadata.password.as_deref(),
        oracle.password.as_deref(),
        "password",
        path,
    );
    assert_ewfinfo_string_eq(
        info.metadata.header_value("device_label"),
        oracle.device_label.as_deref(),
        "device label",
        path,
    );
    assert_ewfinfo_string_eq(
        info.metadata.header_value("model"),
        oracle.model.as_deref(),
        "model",
        path,
    );
    assert_ewfinfo_string_eq(
        info.metadata.header_value("serial_number"),
        oracle.serial_number.as_deref(),
        "serial number",
        path,
    );
    assert_ewfinfo_string_eq(
        info.metadata.header_value("process_identifier"),
        oracle.process_identifier.as_deref(),
        "process identifier",
        path,
    );
    assert_ewfinfo_field_eq(
        info.media.sectors_per_chunk,
        oracle.sectors_per_chunk,
        "sectors per chunk",
        path,
    );
    assert_ewfinfo_field_eq(
        info.media.error_granularity,
        oracle.error_granularity,
        "error granularity",
        path,
    );
    assert_ewfinfo_match(
        ewfinfo_compression_method_matches(
            info.media.compression_method,
            oracle.compression_method.as_deref(),
        ),
        oracle.compression_method.as_deref(),
        "compression method",
        path,
    );
    assert_ewfinfo_match(
        ewfinfo_compression_level_matches(
            info.media.compression_values,
            oracle.compression_level.as_deref(),
        ),
        oracle.compression_level.as_deref(),
        "compression level",
        path,
    );
    assert_ewfinfo_string_eq(
        info.media
            .set_identifier
            .as_ref()
            .map(format_set_identifier)
            .as_deref(),
        oracle.set_identifier.as_deref(),
        "set identifier",
        path,
    );
    assert_ewfinfo_string_eq(
        info.media
            .ewf2_segment_file_version
            .map(format_segment_file_version)
            .as_deref(),
        oracle.segment_file_version.as_deref(),
        "segment file version",
        path,
    );
    assert_ewfinfo_match(
        ewfinfo_media_type_matches(info.media.media_type, oracle.media_type.as_deref()),
        oracle.media_type.as_deref(),
        "media type",
        path,
    );
    assert_ewfinfo_bool_eq(
        info.media.media_flags.physical,
        oracle.is_physical,
        "is physical",
        path,
    );
    if !oracle.write_blocked.is_empty() {
        assert_eq!(
            ewfinfo_write_blocked_values(info.media.media_flags),
            oracle.write_blocked,
            "write blocked flags mismatch for {}",
            path.display()
        );
    }
    assert_ewfinfo_field_eq(
        info.media.bytes_per_sector,
        oracle.bytes_per_sector,
        "bytes per sector",
        path,
    );
    assert_ewfinfo_field_eq(
        info.media.sector_count,
        oracle.sector_count,
        "sector count",
        path,
    );
    if let Some(media_size) = oracle.media_size {
        assert_eq!(
            info.logical_size,
            media_size,
            "media size mismatch for {}",
            path.display()
        );
    }
    if let Some(md5) = oracle.md5.as_deref() {
        assert_eq!(
            info.stored_hashes
                .md5
                .as_ref()
                .map(|value| hex_lower(value)),
            Some(md5.to_owned()),
            "MD5 mismatch for {}",
            path.display()
        );
    }
    if let Some(sha1) = oracle.sha1.as_deref() {
        assert_eq!(
            info.stored_hashes
                .sha1
                .as_ref()
                .map(|value| hex_lower(value)),
            Some(sha1.to_owned()),
            "SHA1 mismatch for {}",
            path.display()
        );
    }
    assert_eq!(
        info.sessions,
        oracle.sessions,
        "sessions mismatch for {}",
        path.display()
    );
    assert_eq!(
        info.tracks,
        oracle.tracks,
        "tracks mismatch for {}",
        path.display()
    );
    assert_eq!(
        info.acquisition_errors,
        oracle.acquisition_errors,
        "acquisition errors mismatch for {}",
        path.display()
    );
    Ok(())
}

fn ewfinfo_hierarchy(ewfinfo: &OsString, path: &Path) -> Result<String, Box<dyn Error>> {
    let output = Command::new(ewfinfo)
        .arg("-H")
        .arg(path)
        .stdin(Stdio::null())
        .output()?;
    assert!(
        output.status.success(),
        "ewfinfo -H failed for {}:\nstdout:\n{}\nstderr:\n{}",
        path.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

fn ewfinfo_bodyfile(
    ewfinfo: &OsString,
    path: &Path,
    bodyfile_path: &Path,
) -> Result<String, Box<dyn Error>> {
    let output = Command::new(ewfinfo)
        .arg("-B")
        .arg(bodyfile_path)
        .arg("-H")
        .arg(path)
        .stdin(Stdio::null())
        .output()?;
    assert!(
        output.status.success(),
        "ewfinfo -B failed for {}:\nstdout:\n{}\nstderr:\n{}",
        path.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(fs::read_to_string(bodyfile_path)?)
}

fn crate_single_file_bodyfile_entries(image: &ewf_image::Image) -> BTreeMap<String, u64> {
    image
        .root_file_entry()
        .map(single_file_bodyfile_entries_from_root)
        .unwrap_or_default()
}

fn single_file_bodyfile_entries_from_root(
    root: &ewf_image::SingleFileEntry,
) -> BTreeMap<String, u64> {
    let mut entries = BTreeMap::new();
    insert_single_file_bodyfile_entry(root, root.name.as_deref().unwrap_or_default(), &mut entries);
    for child in &root.children {
        collect_single_file_bodyfile_entries(child, "", &mut entries);
    }
    entries
}

fn collect_single_file_bodyfile_entries(
    entry: &ewf_image::SingleFileEntry,
    parent: &str,
    entries: &mut BTreeMap<String, u64>,
) {
    let name = entry.name.as_deref().unwrap_or_default();
    let path = if parent.is_empty() {
        name.to_owned()
    } else if name.is_empty() {
        parent.to_owned()
    } else {
        format!("{parent}/{name}")
    };

    insert_single_file_bodyfile_entry(entry, &path, entries);

    for child in &entry.children {
        collect_single_file_bodyfile_entries(child, &path, entries);
    }
}

fn insert_single_file_bodyfile_entry(
    entry: &ewf_image::SingleFileEntry,
    path: &str,
    entries: &mut BTreeMap<String, u64>,
) {
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        return;
    }
    if matches!(
        entry.file_entry_type,
        Some(ewf_image::SingleFileEntryType::File | ewf_image::SingleFileEntryType::Directory)
    ) {
        entries.insert(path.to_owned(), entry.size.unwrap_or(0));
    }
}

fn ewfinfo_bodyfile_entries(output: &str) -> BTreeMap<String, u64> {
    let mut entries = BTreeMap::new();
    for line in output.lines() {
        let fields = line.split('|').collect::<Vec<_>>();
        if fields.len() < 7 {
            continue;
        }
        let path = fields[1].trim_start_matches('/').to_owned();
        let Ok(size) = fields[6].parse::<u64>() else {
            continue;
        };
        entries.insert(path, size);
    }
    entries
}

fn compare_with_ewfexport(ewfexport: &OsString, path: &Path) -> Result<(), Box<dyn Error>> {
    let image = match open_external_fixture(path) {
        Ok(image) => image,
        Err(err) if is_unsupported_encrypted_image(&err.source) => {
            eprintln!("skipping unsupported encrypted image {}", path.display());
            return Ok(());
        }
        Err(err) => return Err(Box::new(err)),
    };
    let mut cursor = image.cursor();
    let mut child = Command::new(ewfexport)
        .args(["-q", "-f", "raw", "-t", "-", "-u"])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let mut stdout = child.stdout.take().expect("stdout was piped");
    let mut stderr = child.stderr.take().expect("stderr was piped");
    let mut oracle = vec![0; BUFFER_SIZE];
    let mut actual = vec![0; BUFFER_SIZE];
    let mut offset = 0_u64;

    loop {
        let read = stdout.read(&mut oracle)?;
        if read == 0 {
            break;
        }

        cursor.read_exact(&mut actual[..read])?;
        assert_eq!(
            &actual[..read],
            &oracle[..read],
            "ewfexport mismatch at image offset {offset} for {}",
            path.display()
        );
        offset += u64::try_from(read).expect("usize fits u64");
    }

    let mut stderr_text = String::new();
    stderr.read_to_string(&mut stderr_text)?;
    let status = child.wait()?;
    assert!(
        status.success(),
        "ewfexport failed for {}: {stderr_text}",
        path.display()
    );
    assert_eq!(
        offset,
        image.info().logical_size,
        "ewfexport raw size differed for {}",
        path.display()
    );
    Ok(())
}

fn compare_ewfexport_bytes(
    ewfexport: &OsString,
    path: &Path,
    expected: &[u8],
) -> Result<(), Box<dyn Error>> {
    let mut child = Command::new(ewfexport)
        .args(["-q", "-f", "raw", "-t", "-", "-u"])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let mut stdout = child.stdout.take().expect("stdout was piped");
    let mut stderr = child.stderr.take().expect("stderr was piped");
    let mut oracle = vec![0; BUFFER_SIZE];
    let mut offset = 0_usize;

    loop {
        let read = stdout.read(&mut oracle)?;
        if read == 0 {
            break;
        }

        let end = offset
            .checked_add(read)
            .ok_or("ewfexport output offset overflow")?;
        assert!(
            end <= expected.len(),
            "ewfexport output exceeded expected raw size for {}",
            path.display()
        );
        assert_eq!(
            &oracle[..read],
            &expected[offset..end],
            "ewfexport mismatch at image offset {offset} for {}",
            path.display()
        );
        offset = end;
    }

    let mut stderr_text = String::new();
    stderr.read_to_string(&mut stderr_text)?;
    let status = child.wait()?;
    assert!(
        status.success(),
        "ewfexport failed for {}: {stderr_text}",
        path.display()
    );
    assert_eq!(
        offset,
        expected.len(),
        "ewfexport raw size differed for {}",
        path.display()
    );
    Ok(())
}

fn corpus_paths() -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let roots = corpus_roots(
        env::var_os("EWF_CORPUS_DIRS"),
        env::var_os("EWF_CORPUS_DIR"),
    );
    if roots.is_empty() {
        return Err(
            "external corpus test requested without an available EWF_CORPUS_DIR or EWF_CORPUS_DIRS"
                .into(),
        );
    }

    let mut paths = Vec::new();
    for root in roots {
        eprintln!("using external EWF corpus root {}", root.display());
        paths.extend(corpus_paths_from_root(&root)?);
    }
    paths.sort();
    paths.dedup();
    if paths.is_empty() {
        return Err("external corpus contains no EWF first segments".into());
    }
    Ok(paths)
}

fn corpus_paths_from_root(root: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut stack = vec![PathBuf::from(root)];
    let mut paths = Vec::new();
    while let Some(path) = stack.pop() {
        if path.is_dir() {
            for entry in fs::read_dir(path)? {
                stack.push(entry?.path());
            }
        } else if is_readable_first_segment(&path)? {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn copy_image_segment_set(first_segment: &Path, destination: &Path) -> Result<(), Box<dyn Error>> {
    let image = ewf_image::Image::open(first_segment)?;
    for segment_path in &image.info().segment_paths {
        let file_name = segment_path
            .file_name()
            .ok_or("segment path did not have a file name")?;
        fs::copy(segment_path, destination.join(file_name))?;
    }
    Ok(())
}

fn logical_single_file_fixture_paths() -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let Some(root) = env::var_os("EWF_LOGICAL_SINGLE_FILES_DIR").map(PathBuf::from) else {
        return Ok(Vec::new());
    };
    logical_single_file_fixture_paths_from_root(&root)
}

fn logical_single_file_fixture_paths_from_root(
    root: &Path,
) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let paths = corpus_paths_from_root(root)?
        .into_iter()
        .filter(|path| {
            path.extension()
                .and_then(|value| value.to_str())
                .is_some_and(|extension| {
                    matches!(extension.to_ascii_lowercase().as_str(), "l01" | "lx01")
                })
        })
        .collect();
    Ok(paths)
}

fn corpus_root(env_root: Option<OsString>) -> Option<PathBuf> {
    env_root.map(PathBuf::from)
}

fn corpus_roots(env_roots: Option<OsString>, env_root: Option<OsString>) -> Vec<PathBuf> {
    if let Some(value) = env_roots {
        return env::split_paths(&value)
            .filter(|path| path.exists())
            .collect();
    }
    corpus_root(env_root).into_iter().collect()
}

fn is_first_segment(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "e01" | "ex01" | "l01" | "lx01" | "s01"
            )
        })
}

fn is_readable_first_segment(path: &Path) -> Result<bool, Box<dyn Error>> {
    Ok(is_first_segment(path) && fs::metadata(path)?.len() >= 8)
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct FixtureCoverage {
    ewf1_physical: usize,
    ewf1_logical: usize,
    ewf1_smart: usize,
    ewf2_physical: usize,
    ewf2_logical: usize,
}

impl FixtureCoverage {
    fn from_paths(paths: &[PathBuf]) -> Self {
        let mut coverage = Self::default();
        for path in paths {
            let extension = path
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            match extension.as_str() {
                "e01" => coverage.ewf1_physical += 1,
                "l01" => coverage.ewf1_logical += 1,
                "s01" => coverage.ewf1_smart += 1,
                "ex01" => coverage.ewf2_physical += 1,
                "lx01" => coverage.ewf2_logical += 1,
                _ => {}
            }
        }
        coverage
    }

    fn total(self) -> usize {
        self.ewf1_physical
            + self.ewf1_logical
            + self.ewf1_smart
            + self.ewf2_physical
            + self.ewf2_logical
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ExternalFeatureCoverage {
    fixture: FixtureCoverage,
    bzip2: usize,
    memory_media: usize,
    single_files: usize,
    generic_hash_values: usize,
    acquisition_errors: usize,
    sessions: usize,
    tracks: usize,
    incomplete_acquisitions: usize,
}

impl ExternalFeatureCoverage {
    fn from_paths(paths: &[PathBuf]) -> Result<Self, Box<dyn Error>> {
        let mut coverage = Self {
            fixture: FixtureCoverage::default(),
            ..Self::default()
        };

        for path in paths {
            let image = match open_external_fixture(path) {
                Ok(image) => image,
                Err(err) if is_unsupported_encrypted_image(&err.source) => continue,
                Err(err) => return Err(Box::new(err)),
            };
            let info = image.info();
            coverage.fixture.add_image(path, info);
            if matches!(
                info.media.compression_method,
                Some(ewf_image::CompressionMethod::Bzip2)
            ) {
                coverage.bzip2 += 1;
            }
            if matches!(info.media.media_type, Some(ewf_image::MediaType::Memory)) {
                coverage.memory_media += 1;
            }
            if info.single_files.is_some() {
                coverage.single_files += 1;
            }
            if has_generic_hash_value(&info.stored_hashes) {
                coverage.generic_hash_values += 1;
            }
            if !info.acquisition_errors.is_empty() {
                coverage.acquisition_errors += 1;
            }
            if !info.sessions.is_empty() {
                coverage.sessions += 1;
            }
            if !info.tracks.is_empty() {
                coverage.tracks += 1;
            }
            if !info.acquisition_complete {
                coverage.incomplete_acquisitions += 1;
            }
        }

        Ok(coverage)
    }
}

impl FixtureCoverage {
    fn add_image(&mut self, path: &Path, info: &ewf_image::ImageInfo) {
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        match info.format {
            ewf_image::Format::Ewf1
                if extension == "s01" || info.format_profile == ewf_image::FormatProfile::Smart =>
            {
                self.ewf1_smart += 1;
            }
            ewf_image::Format::Ewf1 if info.media.media_flags.physical => {
                self.ewf1_physical += 1;
            }
            ewf_image::Format::Ewf1 => {
                self.ewf1_logical += 1;
            }
            ewf_image::Format::Ewf2 if info.media.media_flags.physical => {
                self.ewf2_physical += 1;
            }
            ewf_image::Format::Ewf2 => {
                self.ewf2_logical += 1;
            }
        }
    }
}

fn missing_closeout_feature_families(coverage: &ExternalFeatureCoverage) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if coverage.fixture.ewf1_physical == 0 {
        missing.push("EWF1 physical .E01 fixtures");
    }
    if coverage.fixture.ewf1_logical == 0 {
        missing.push("EWF1 logical .L01 fixtures");
    }
    if coverage.fixture.ewf1_smart == 0 {
        missing.push("EWF1 SMART .s01 fixtures");
    }
    if coverage.fixture.ewf2_physical == 0 {
        missing.push("EWF2 physical .Ex01 fixtures");
    }
    if coverage.fixture.ewf2_logical == 0 {
        missing.push("EWF2 logical .Lx01 fixtures");
    }
    if coverage.memory_media == 0 {
        missing.push("memory media fixtures");
    }
    if coverage.single_files == 0 {
        missing.push("logical single-files fixtures");
    }
    if coverage.generic_hash_values == 0 {
        missing.push("non-MD5/SHA1 generic hash fixtures");
    }
    if coverage.acquisition_errors == 0 {
        missing.push("acquisition-error fixtures");
    }
    if coverage.sessions == 0 {
        missing.push("session fixtures");
    }
    if coverage.tracks == 0 {
        missing.push("track fixtures");
    }
    if coverage.incomplete_acquisitions == 0 {
        missing.push("incomplete-acquisition fixtures");
    }
    missing
}

fn missing_closeout_feature_families_for_current_toolchain(
    coverage: &ExternalFeatureCoverage,
) -> Vec<&'static str> {
    missing_closeout_feature_families(coverage)
}

fn has_generic_hash_value(hashes: &ewf_image::StoredHashes) -> bool {
    hashes.hash_values.keys().any(|identifier| {
        !identifier.eq_ignore_ascii_case("MD5") && !identifier.eq_ignore_ascii_case("SHA1")
    })
}

fn is_ewfverify_candidate(info: &ewf_image::ImageInfo) -> bool {
    info.acquisition_complete
}

fn is_unsupported_encrypted_image(err: &ewf_image::EwfError) -> bool {
    matches!(
        err,
        ewf_image::EwfError::Unsupported(message)
            if message.contains("encrypted EWF2")
                || message.contains("encryption keys")
    )
}

#[derive(Debug, Default, PartialEq, Eq)]
struct EwfinfoMetadata {
    file_format: Option<String>,
    case_number: Option<String>,
    description: Option<String>,
    examiner: Option<String>,
    evidence_number: Option<String>,
    notes: Option<String>,
    acquisition_date: Option<String>,
    system_date: Option<String>,
    os_version: Option<String>,
    acquisition_software: Option<String>,
    acquisition_software_version: Option<String>,
    password: Option<String>,
    sectors_per_chunk: Option<u64>,
    error_granularity: Option<u64>,
    compression_method: Option<String>,
    compression_level: Option<String>,
    set_identifier: Option<String>,
    segment_file_version: Option<String>,
    media_type: Option<String>,
    is_physical: Option<bool>,
    write_blocked: Vec<String>,
    bytes_per_sector: Option<u64>,
    sector_count: Option<u64>,
    media_size: Option<u64>,
    md5: Option<String>,
    sha1: Option<String>,
    device_label: Option<String>,
    model: Option<String>,
    serial_number: Option<String>,
    process_identifier: Option<String>,
    sessions: Vec<ewf_image::SectorRange>,
    tracks: Vec<ewf_image::SectorRange>,
    acquisition_errors: Vec<ewf_image::AcquisitionError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EwfinfoRangeSection {
    Sessions,
    Tracks,
    AcquisitionErrors,
}

fn parse_ewfinfo_metadata(text: &str) -> EwfinfoMetadata {
    let mut metadata = EwfinfoMetadata::default();
    let mut range_section = None;
    for line in text.lines() {
        let Some((label, value)) = line.trim().split_once(':') else {
            continue;
        };
        let label = label.trim();
        let value = value.trim();
        match label {
            "File format" => metadata.file_format = ewfinfo_string_value(value),
            "Case number" => metadata.case_number = ewfinfo_string_value(value),
            "Description" => metadata.description = ewfinfo_string_value(value),
            "Examiner name" => metadata.examiner = ewfinfo_string_value(value),
            "Evidence number" => metadata.evidence_number = ewfinfo_string_value(value),
            "Notes" => metadata.notes = ewfinfo_string_value(value),
            "Acquisition date" => metadata.acquisition_date = ewfinfo_string_value(value),
            "System date" => metadata.system_date = ewfinfo_string_value(value),
            "Operating system used" => metadata.os_version = ewfinfo_string_value(value),
            "Software used" => metadata.acquisition_software = ewfinfo_string_value(value),
            "Software version used" => {
                metadata.acquisition_software_version = ewfinfo_string_value(value);
            }
            "Password" => metadata.password = ewfinfo_string_value(value),
            "Device label" => metadata.device_label = ewfinfo_string_value(value),
            "Model" => metadata.model = ewfinfo_string_value(value),
            "Serial number" => metadata.serial_number = ewfinfo_string_value(value),
            "Process identifier" => metadata.process_identifier = ewfinfo_string_value(value),
            "Sectors per chunk" => metadata.sectors_per_chunk = parse_u64_prefix(value),
            "Error granularity" => metadata.error_granularity = parse_u64_prefix(value),
            "Compression method" => metadata.compression_method = ewfinfo_string_value(value),
            "Compression level" => metadata.compression_level = ewfinfo_string_value(value),
            "Set identifier" => metadata.set_identifier = ewfinfo_string_value(value),
            "Segment file version" => {
                metadata.segment_file_version = ewfinfo_string_value(value);
            }
            "Media type" => metadata.media_type = ewfinfo_string_value(value),
            "Is physical" => {
                metadata.is_physical = match value {
                    "yes" => Some(true),
                    "no" => Some(false),
                    _ => None,
                };
            }
            "Write blocked" => {
                if let Some(value) = ewfinfo_string_value(value) {
                    metadata.write_blocked.push(value);
                }
            }
            "Bytes per sector" => metadata.bytes_per_sector = parse_u64_prefix(value),
            "Number of sectors" => metadata.sector_count = parse_u64_prefix(value),
            "Media size" => metadata.media_size = parse_media_size_bytes(value),
            "MD5" => metadata.md5 = Some(value.to_ascii_lowercase()),
            "SHA1" => metadata.sha1 = Some(value.to_ascii_lowercase()),
            "Sessions" => range_section = Some(EwfinfoRangeSection::Sessions),
            "Tracks" => range_section = Some(EwfinfoRangeSection::Tracks),
            "Read errors during acquiry" => {
                range_section = Some(EwfinfoRangeSection::AcquisitionErrors);
            }
            "at sector(s)" => {
                if let (Some(section), Some(range)) =
                    (range_section, parse_ewfinfo_sector_range(value))
                {
                    match section {
                        EwfinfoRangeSection::Sessions => metadata.sessions.push(range),
                        EwfinfoRangeSection::Tracks => metadata.tracks.push(range),
                        EwfinfoRangeSection::AcquisitionErrors => {
                            metadata
                                .acquisition_errors
                                .push(ewf_image::AcquisitionError {
                                    first_sector: range.first_sector,
                                    sector_count: range.sector_count,
                                });
                        }
                    }
                }
            }
            _ => {}
        }
    }
    metadata
}

fn ewfinfo_string_value(value: &str) -> Option<String> {
    (!value.is_empty() && value != "N/A").then(|| value.to_owned())
}

fn parse_u64_prefix(value: &str) -> Option<u64> {
    value.split_whitespace().next()?.parse().ok()
}

fn parse_ewfinfo_sector_range(value: &str) -> Option<ewf_image::SectorRange> {
    let (first_sector, remainder) = value.split_once(" - ")?;
    let (_last_sector, count) = remainder.split_once(" (number: ")?;
    let sector_count = count.strip_suffix(')')?;
    Some(ewf_image::SectorRange {
        first_sector: first_sector.trim().parse().ok()?,
        sector_count: sector_count.trim().parse().ok()?,
    })
}

fn ewfinfo_format_profile_matches(actual: ewf_image::FormatProfile, file_format: &str) -> bool {
    match file_format {
        "EnCase 1" => actual == ewf_image::FormatProfile::EnCase1,
        "EnCase 2" => actual == ewf_image::FormatProfile::EnCase2,
        "EnCase 3" => actual == ewf_image::FormatProfile::EnCase3,
        "EnCase 4" => actual == ewf_image::FormatProfile::EnCase4,
        "EnCase 5" => matches!(
            actual,
            ewf_image::FormatProfile::EnCase5 | ewf_image::FormatProfile::LogicalEnCase5
        ),
        "EnCase 6" => matches!(
            actual,
            ewf_image::FormatProfile::EnCase6
                | ewf_image::FormatProfile::LogicalEnCase5
                | ewf_image::FormatProfile::LogicalEnCase6
        ),
        "EnCase 7" => matches!(
            actual,
            ewf_image::FormatProfile::EnCase7 | ewf_image::FormatProfile::LogicalEnCase7
        ),
        "EnCase 7 (version 2)" => matches!(
            actual,
            ewf_image::FormatProfile::Ewf2EnCase7 | ewf_image::FormatProfile::Ewf2LogicalEnCase7
        ),
        "FTK Imager" => actual == ewf_image::FormatProfile::FtkImager,
        "SMART" => actual == ewf_image::FormatProfile::Smart,
        "Linen 5" => actual == ewf_image::FormatProfile::Linen5,
        "Linen 6" => actual == ewf_image::FormatProfile::Linen6,
        "Linen 7" => actual == ewf_image::FormatProfile::Linen7,
        _ => true,
    }
}

fn ewfinfo_media_type_matches(
    actual: Option<ewf_image::MediaType>,
    expected: Option<&str>,
) -> Option<bool> {
    let expected = expected?;
    Some(matches!(
        (actual, expected),
        (Some(ewf_image::MediaType::Fixed), "fixed disk")
            | (Some(ewf_image::MediaType::Removable), "removable disk")
            | (
                Some(ewf_image::MediaType::Optical),
                "optical disc" | "optical disk (CD/DVD/BD)"
            )
            | (
                Some(ewf_image::MediaType::Memory),
                "memory" | "memory (RAM)"
            )
            | (
                Some(ewf_image::MediaType::SingleFiles),
                "single files" | "logical files"
            )
    ))
}

fn ewfinfo_compression_method_matches(
    actual: Option<ewf_image::CompressionMethod>,
    expected: Option<&str>,
) -> Option<bool> {
    let expected = expected?;
    Some(matches!(
        (actual, expected),
        (Some(ewf_image::CompressionMethod::Zlib), "deflate")
            | (Some(ewf_image::CompressionMethod::Bzip2), "bzip2")
            | (Some(ewf_image::CompressionMethod::None), "none")
    ))
}

fn ewfinfo_compression_level_matches(
    actual: ewf_image::CompressionValues,
    expected: Option<&str>,
) -> Option<bool> {
    let expected = expected?;
    Some(matches!(
        (actual.level, expected),
        (ewf_image::CompressionLevel::None, "no compression")
            | (
                ewf_image::CompressionLevel::Fast,
                "fast" | "fast compression" | "good (fast) compression",
            )
            | (
                ewf_image::CompressionLevel::Best,
                "best" | "best compression"
            )
            | (
                ewf_image::CompressionLevel::Default,
                "default" | "default compression",
            )
    ))
}

fn ewfinfo_write_blocked_values(flags: ewf_image::MediaFlags) -> Vec<String> {
    let mut values = Vec::new();
    if flags.fastbloc {
        values.push("Fastbloc".to_owned());
    }
    if flags.tableau {
        values.push("Tableau".to_owned());
    }
    values
}

fn format_set_identifier(bytes: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{}-{}",
        bytes[3],
        bytes[2],
        bytes[1],
        bytes[0],
        bytes[5],
        bytes[4],
        bytes[7],
        bytes[6],
        hex_lower(&bytes[8..10]),
        hex_lower(&bytes[10..16])
    )
}

fn format_segment_file_version(version: ewf_image::SegmentFileVersion) -> String {
    format!("{}.{}", version.major, version.minor)
}

fn parse_media_size_bytes(value: &str) -> Option<u64> {
    let (_, bytes) = value.rsplit_once('(')?;
    bytes
        .strip_suffix(')')?
        .strip_suffix(" bytes")?
        .parse()
        .ok()
}

fn assert_ewfinfo_field_eq(actual: Option<u64>, expected: Option<u64>, field: &str, path: &Path) {
    if let Some(expected) = expected {
        assert_eq!(
            actual,
            Some(expected),
            "{field} mismatch for {}",
            path.display()
        );
    }
}

fn assert_ewfinfo_string_eq(
    actual: Option<&str>,
    expected: Option<&str>,
    field: &str,
    path: &Path,
) {
    if let Some(expected) = expected {
        assert_eq!(
            actual,
            Some(expected),
            "{field} mismatch for {}",
            path.display()
        );
    }
}

fn assert_ewfinfo_date_eq(
    actual: Option<&str>,
    raw: Option<&str>,
    expected: Option<&str>,
    field: &str,
    path: &Path,
) {
    let Some(expected) = expected else {
        return;
    };
    if actual == Some(expected) {
        return;
    }
    if raw.is_some_and(is_numeric_date_value) {
        eprintln!(
            "skipping timezone-dependent {field} comparison for {}",
            path.display()
        );
        return;
    }
    assert_eq!(
        actual,
        Some(expected),
        "{field} mismatch for {}",
        path.display()
    );
}

fn is_numeric_date_value(value: &str) -> bool {
    let parts: Vec<&str> = value.split_whitespace().collect();
    matches!(parts.len(), 1 | 6)
        && parts
            .iter()
            .all(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn assert_ewfinfo_bool_eq(actual: bool, expected: Option<bool>, field: &str, path: &Path) {
    if let Some(expected) = expected {
        assert_eq!(actual, expected, "{field} mismatch for {}", path.display());
    }
}

fn assert_ewfinfo_match(
    actual_matches: Option<bool>,
    expected: Option<&str>,
    field: &str,
    path: &Path,
) {
    if let Some(expected) = expected {
        assert!(
            actual_matches.unwrap_or(false),
            "{field} mismatch for {}: ewfinfo={expected:?}",
            path.display()
        );
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex_lower(&digest)
}

#[test]
fn external_fixture_open_error_includes_path_and_source() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("broken.E01");
    fs::write(&path, b"not an EWF image")?;

    let error = match open_external_fixture(&path) {
        Ok(_) => panic!("invalid fixture unexpectedly opened"),
        Err(error) => error,
    };

    assert_eq!(
        error.to_string(),
        format!(
            "failed to open external EWF fixture {}: invalid EWF signature",
            path.display()
        )
    );
    assert_eq!(
        error.source().map(ToString::to_string).as_deref(),
        Some("invalid EWF signature")
    );
    Ok(())
}

#[test]
fn corpus_root_uses_explicit_environment_value() {
    let explicit = OsString::from("/tmp/explicit-ewf-corpus");

    assert_eq!(
        corpus_root(Some(explicit)),
        Some(PathBuf::from("/tmp/explicit-ewf-corpus"))
    );
}

#[test]
fn corpus_root_requires_explicit_environment_value() {
    assert_eq!(corpus_root(None), None);
}

#[test]
fn corpus_roots_prefers_path_list_over_single_root() -> Result<(), Box<dyn Error>> {
    let first = tempfile::tempdir()?;
    let second = tempfile::tempdir()?;
    let single = tempfile::tempdir()?;
    let joined = env::join_paths([first.path(), second.path()])?;

    let roots = corpus_roots(Some(joined), Some(single.path().as_os_str().to_owned()));

    assert_eq!(
        roots,
        vec![first.path().to_path_buf(), second.path().to_path_buf()]
    );
    Ok(())
}

#[test]
fn corpus_paths_from_root_returns_only_first_segments() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let nested = dir.path().join("nested");
    fs::create_dir(&nested)?;
    for path in [
        dir.path().join("case.E01"),
        nested.join("logical.L01"),
        nested.join("v2.Ex01"),
        nested.join("logical-v2.Lx01"),
    ] {
        fs::write(path, [0; 8])?;
    }
    for path in [
        dir.path().join("case.E02"),
        nested.join("logical.L02"),
        nested.join("v2.Ex02"),
        nested.join("logical-v2.Lx02"),
        nested.join("notes.txt"),
    ] {
        fs::write(path, [])?;
    }

    let paths = corpus_paths_from_root(dir.path())?;
    let names = paths
        .iter()
        .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    assert_eq!(
        names,
        ["case.E01", "logical-v2.Lx01", "logical.L01", "v2.Ex01"]
    );
    Ok(())
}

#[test]
fn corpus_paths_from_root_skips_too_short_first_segments() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("empty.E01"), [])?;
    fs::write(dir.path().join("short.Ex01"), [0; 7])?;
    fs::write(dir.path().join("valid.L01"), [0; 8])?;

    let paths = corpus_paths_from_root(dir.path())?;
    let names = paths
        .iter()
        .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    assert_eq!(names, ["valid.L01"]);
    Ok(())
}

#[test]
fn logical_single_file_fixture_paths_from_root_selects_l01_and_lx01() -> Result<(), Box<dyn Error>>
{
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("physical.E01"), [0; 8])?;
    fs::write(dir.path().join("logical.L01"), [0; 8])?;
    fs::write(dir.path().join("logical-v2.Lx01"), [0; 8])?;
    fs::write(dir.path().join("notes.txt"), [0; 8])?;

    let paths = logical_single_file_fixture_paths_from_root(dir.path())?;
    let names = paths
        .iter()
        .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    assert_eq!(names, ["logical-v2.Lx01", "logical.L01"]);
    Ok(())
}

#[test]
fn fixture_coverage_summary_counts_first_segment_formats() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    for name in [
        "case.E01",
        "logical.L01",
        "v2.Ex01",
        "logical-v2.Lx01",
        "smart.s01",
    ] {
        fs::write(dir.path().join(name), [0; 8])?;
    }
    fs::write(dir.path().join("case.E02"), [0; 8])?;
    fs::write(dir.path().join("notes.txt"), [0; 8])?;

    let paths = corpus_paths_from_root(dir.path())?;
    let summary = FixtureCoverage::from_paths(&paths);

    assert_eq!(summary.ewf1_physical, 1);
    assert_eq!(summary.ewf1_logical, 1);
    assert_eq!(summary.ewf1_smart, 1);
    assert_eq!(summary.ewf2_physical, 1);
    assert_eq!(summary.ewf2_logical, 1);
    assert_eq!(summary.total(), 5);
    Ok(())
}

#[test]
fn feature_coverage_detects_non_standard_hash_identifiers() {
    let mut hashes = ewf_image::StoredHashes::default();
    hashes.set_hash_value("MD5", "00112233445566778899aabbccddeeff");
    hashes.set_hash_value("SHA1", "00112233445566778899aabbccddeeff00112233");
    assert!(!has_generic_hash_value(&hashes));

    hashes.set_hash_value(
        "SHA256",
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    );
    assert!(has_generic_hash_value(&hashes));
}

#[test]
fn closeout_feature_coverage_reports_all_strict_missing_families() {
    let coverage = ExternalFeatureCoverage {
        fixture: FixtureCoverage {
            ewf1_physical: 1,
            ewf1_logical: 1,
            ewf1_smart: 1,
            ewf2_physical: 1,
            ewf2_logical: 1,
        },
        memory_media: 1,
        single_files: 1,
        generic_hash_values: 1,
        ..ExternalFeatureCoverage::default()
    };

    assert_eq!(
        missing_closeout_feature_families(&coverage),
        [
            "acquisition-error fixtures",
            "session fixtures",
            "track fixtures",
            "incomplete-acquisition fixtures",
        ]
    );
}

#[test]
fn closeout_feature_coverage_does_not_require_future_bzip2_oracles() {
    let coverage = ExternalFeatureCoverage {
        fixture: FixtureCoverage {
            ewf1_physical: 1,
            ewf1_logical: 1,
            ewf1_smart: 1,
            ewf2_physical: 1,
            ewf2_logical: 1,
        },
        memory_media: 1,
        single_files: 1,
        generic_hash_values: 1,
        acquisition_errors: 1,
        sessions: 1,
        tracks: 1,
        incomplete_acquisitions: 1,
        ..ExternalFeatureCoverage::default()
    };

    assert_eq!(
        missing_closeout_feature_families(&coverage),
        [] as [&str; 0]
    );
    assert_eq!(
        missing_closeout_feature_families_for_current_toolchain(&coverage),
        [] as [&str; 0]
    );
}

#[test]
fn ewfverify_candidates_must_be_complete_acquisitions() {
    let mut info = ewf_image::ImageInfo {
        format: ewf_image::Format::Ewf1,
        format_profile: ewf_image::FormatProfile::EnCase6,
        segment_count: 1,
        segment_paths: vec!["case.E01".into()],
        chunk_size: 32_768,
        logical_size: 65_536,
        acquisition_complete: true,
        header_codepage: ewf_image::HeaderCodepage::Ascii,
        header_values_date_format: ewf_image::HeaderDateFormat::Ctime,
        media: ewf_image::MediaInfo::default(),
        metadata: ewf_image::EwfMetadata::default(),
        stored_hashes: ewf_image::StoredHashes::default(),
        acquisition_errors: Vec::new(),
        memory_extents: Vec::new(),
        single_files: None,
        ewf2_single_files_tables: ewf_image::SingleFilesAuxTables::default(),
        ewf2_increment_data: Vec::new(),
        ewf2_final_information: None,
        ewf2_restart_data: None,
        ewf2_analytical_data: None,
        sessions: Vec::new(),
        tracks: Vec::new(),
    };

    assert!(is_ewfverify_candidate(&info));
    info.acquisition_complete = false;
    assert!(!is_ewfverify_candidate(&info));
}

#[test]
fn generated_fixture_matrix_includes_non_default_media_types() {
    let cases = ewf_tool_fixture_cases();

    assert!(cases.iter().any(|case| case.media_type == "removable"));
    assert!(cases.iter().any(|case| case.media_type == "optical"));
    assert!(cases.iter().any(|case| case.media_type == "memory"));
}

#[test]
fn generated_fixture_matrix_includes_legacy_format_profiles() {
    let cases = ewf_tool_fixture_cases();

    for format in ["encase2", "encase3", "encase4", "linen5", "linen7"] {
        assert!(
            cases.iter().any(|case| case.format == format),
            "generated fixture matrix is missing format {format}"
        );
    }
    assert!(
        cases
            .iter()
            .any(|case| case.format == "encase7" && case.media_flags == "logical"),
        "generated fixture matrix is missing logical EnCase7 coverage"
    );
}

#[test]
fn generated_fixture_matrix_includes_sha1_digest_case() {
    let cases = ewf_tool_fixture_cases();

    assert!(
        cases.iter().any(|case| case.digest == Some("sha1")),
        "generated fixture matrix is missing SHA1 digest coverage"
    );
}

#[test]
fn generated_export_fixture_matrix_includes_smart_case() {
    let cases = ewf_tool_export_fixture_cases();

    assert!(
        cases
            .iter()
            .any(|case| case.output_format == "smart" && case.output_extension == "s01"),
        "generated export fixture matrix is missing SMART .s01 coverage"
    );
}

#[test]
fn encrypted_unsupported_errors_are_skipped_by_external_corpus() {
    assert!(is_unsupported_encrypted_image(
        &ewf_image::EwfError::Unsupported(
            "encrypted EWF2 image with encryption keys section".to_owned(),
        )
    ));
    assert!(is_unsupported_encrypted_image(
        &ewf_image::EwfError::Unsupported("encrypted EWF2 DeviceInformation section".to_owned(),)
    ));
    assert!(!is_unsupported_encrypted_image(
        &ewf_image::EwfError::Unsupported("unknown compression".to_owned())
    ));
}

#[test]
fn ewfinfo_metadata_parser_extracts_geometry_and_hashes() {
    let metadata = parse_ewfinfo_metadata(
        "\
ewfinfo 20251220

EWF information:
\tFile format:\t\tEnCase 6
\tSectors per chunk:\t64
\tError granularity:\t64
\tCompression method:\tdeflate
\tCompression level:\tno compression
\tSet identifier:\t\ta19a5aec-79b7-5041-b596-0ae082c61a17
\tSegment file version:\t2.1

Acquiry information:
\tCase number:\t\tCASE-1
\tDescription:\t\tDisk image
\tExaminer name:\t\tExaminer
\tEvidence number:\tEVID-1
\tNotes:\t\t\tNotes
\tAcquisition date:\tWed May 20 20:36:32 2026
\tSystem date:\t\tWed May 20 20:36:32 2026
\tOperating system used:\tDarwin
\tSoftware version used:\t20231119
\tPassword:\t\tN/A

Media information:
\tMedia type:\t\tfixed disk
\tIs physical:\t\tyes
\tWrite blocked:\t\tFastbloc
\tWrite blocked:\t\tTableau
\tBytes per sector:\t512
\tNumber of sectors:\t20480
\tMedia size:\t\t10 MiB (10485760 bytes)

Digest hash information:
\tMD5:\t\t\t2692f3177a389e58906b5c9080aa1add
\tSHA1:\t\t\t2d51e94e694ab425a73604e94d2020d00c182958
",
    );

    assert_eq!(metadata.file_format.as_deref(), Some("EnCase 6"));
    assert_eq!(metadata.case_number.as_deref(), Some("CASE-1"));
    assert_eq!(metadata.description.as_deref(), Some("Disk image"));
    assert_eq!(metadata.examiner.as_deref(), Some("Examiner"));
    assert_eq!(metadata.evidence_number.as_deref(), Some("EVID-1"));
    assert_eq!(metadata.notes.as_deref(), Some("Notes"));
    assert_eq!(
        metadata.acquisition_date.as_deref(),
        Some("Wed May 20 20:36:32 2026")
    );
    assert_eq!(
        metadata.system_date.as_deref(),
        Some("Wed May 20 20:36:32 2026")
    );
    assert_eq!(metadata.os_version.as_deref(), Some("Darwin"));
    assert_eq!(
        metadata.acquisition_software_version.as_deref(),
        Some("20231119")
    );
    assert_eq!(metadata.password.as_deref(), None);
    assert_eq!(metadata.sectors_per_chunk, Some(64));
    assert_eq!(metadata.error_granularity, Some(64));
    assert_eq!(metadata.compression_method.as_deref(), Some("deflate"));
    assert_eq!(
        metadata.compression_level.as_deref(),
        Some("no compression")
    );
    assert_eq!(
        metadata.set_identifier.as_deref(),
        Some("a19a5aec-79b7-5041-b596-0ae082c61a17")
    );
    assert_eq!(metadata.segment_file_version.as_deref(), Some("2.1"));
    assert_eq!(metadata.media_type.as_deref(), Some("fixed disk"));
    assert_eq!(metadata.is_physical, Some(true));
    assert_eq!(metadata.write_blocked, ["Fastbloc", "Tableau"]);
    assert_eq!(metadata.bytes_per_sector, Some(512));
    assert_eq!(metadata.sector_count, Some(20_480));
    assert_eq!(metadata.media_size, Some(10_485_760));
    assert_eq!(
        metadata.md5.as_deref(),
        Some("2692f3177a389e58906b5c9080aa1add")
    );
    assert_eq!(
        metadata.sha1.as_deref(),
        Some("2d51e94e694ab425a73604e94d2020d00c182958")
    );
}

#[test]
fn ewfinfo_metadata_parser_extracts_device_and_software_fields() {
    let metadata = parse_ewfinfo_metadata(
        "\
ewfinfo 20251220

Acquiry information:
\tSoftware used:\t\tewfacquire
\tDevice label:\t\tDisk Label
\tModel:\t\t\tModel X
\tSerial number:\t\tSN-001
\tProcess identifier:\tPID-1234
",
    );

    assert_eq!(metadata.acquisition_software.as_deref(), Some("ewfacquire"));
    assert_eq!(metadata.device_label.as_deref(), Some("Disk Label"));
    assert_eq!(metadata.model.as_deref(), Some("Model X"));
    assert_eq!(metadata.serial_number.as_deref(), Some("SN-001"));
    assert_eq!(metadata.process_identifier.as_deref(), Some("PID-1234"));
}

#[test]
fn ewfinfo_metadata_parser_extracts_range_sections() {
    let metadata = parse_ewfinfo_metadata(
        "\
ewfinfo 20251220

Media information:
\tBytes per sector:\t512
\tNumber of sectors:\t300

Sessions:
\ttotal number: 2
\tat sector(s): 0 - 99 (number: 100)
\tat sector(s): 100 - 199 (number: 100)

Tracks:
\ttotal number: 1
\tat sector(s): 20 - 49 (number: 30)

Read errors during acquiry:
\ttotal number: 1
\tat sector(s): 12 - 15 (number: 4)
",
    );

    assert_eq!(
        metadata.sessions,
        [
            ewf_image::SectorRange {
                first_sector: 0,
                sector_count: 100,
            },
            ewf_image::SectorRange {
                first_sector: 100,
                sector_count: 100,
            },
        ]
    );
    assert_eq!(
        metadata.tracks,
        [ewf_image::SectorRange {
            first_sector: 20,
            sector_count: 30,
        }]
    );
    assert_eq!(
        metadata.acquisition_errors,
        [ewf_image::AcquisitionError {
            first_sector: 12,
            sector_count: 4,
        }]
    );
}

#[test]
fn ewfinfo_bodyfile_entries_extract_paths_and_sizes() {
    let entries = ewfinfo_bodyfile_entries(
        "\
0|/payload.bin|0|0|0|0|4096|0|0|0
0|/Users/NTUSER.DAT|0|0|0|0|8192|0|0|0
malformed
",
    );

    assert_eq!(
        entries,
        BTreeMap::from([
            ("Users/NTUSER.DAT".to_owned(), 8192),
            ("payload.bin".to_owned(), 4096),
        ])
    );
}

#[test]
fn crate_single_file_bodyfile_entries_flatten_file_paths() {
    let root = ewf_image::SingleFileEntry {
        name: Some("root".to_owned()),
        file_entry_type: Some(ewf_image::SingleFileEntryType::Directory),
        children: vec![
            ewf_image::SingleFileEntry {
                name: Some("payload.bin".to_owned()),
                file_entry_type: Some(ewf_image::SingleFileEntryType::File),
                size: Some(4096),
                ..ewf_image::SingleFileEntry::default()
            },
            ewf_image::SingleFileEntry {
                name: Some("Users".to_owned()),
                file_entry_type: Some(ewf_image::SingleFileEntryType::Directory),
                children: vec![ewf_image::SingleFileEntry {
                    name: Some("NTUSER.DAT".to_owned()),
                    file_entry_type: Some(ewf_image::SingleFileEntryType::File),
                    size: Some(8192),
                    ..ewf_image::SingleFileEntry::default()
                }],
                ..ewf_image::SingleFileEntry::default()
            },
        ],
        ..ewf_image::SingleFileEntry::default()
    };

    assert_eq!(
        single_file_bodyfile_entries_from_root(&root),
        BTreeMap::from([
            ("Users".to_owned(), 0),
            ("Users/NTUSER.DAT".to_owned(), 8192),
            ("payload.bin".to_owned(), 4096),
            ("root".to_owned(), 0),
        ])
    );
}

struct WriterCase<'a> {
    filename: &'a str,
    data: &'a [u8],
    options: ewf_image::WriteOptions,
}

struct WriterMetadataOracleCase {
    filename: &'static str,
    data: Vec<u8>,
    options: ewf_image::WriteOptions,
}

fn writer_metadata_oracle_cases() -> Vec<WriterMetadataOracleCase> {
    let data = patterned_data(70_000);
    vec![
        WriterMetadataOracleCase {
            filename: "metadata-e01.E01",
            data: data.clone(),
            options: ewf_image::WriteOptions {
                metadata: rich_writer_metadata(),
                hashes: rich_writer_hashes(),
                ..ewf_image::WriteOptions::default()
            },
        },
        WriterMetadataOracleCase {
            filename: "metadata-smart.s01",
            data: data.clone(),
            options: ewf_image::WriteOptions {
                format: ewf_image::WriteFormat::Ewf1Smart,
                sectors_per_chunk: 64,
                bytes_per_sector: 512,
                media_profile: ewf_image::WriteMediaProfile {
                    media_type: Some(ewf_image::MediaType::Removable),
                    error_granularity: Some(64),
                    ..ewf_image::WriteMediaProfile::default()
                },
                metadata: rich_writer_metadata(),
                hashes: rich_writer_hashes(),
                ..ewf_image::WriteOptions::default()
            },
        },
        WriterMetadataOracleCase {
            filename: "metadata-ex01.Ex01",
            data,
            options: ewf_image::WriteOptions {
                format: ewf_image::WriteFormat::Ewf2Physical,
                media_profile: ewf_image::WriteMediaProfile {
                    fastbloc: true,
                    tableau: true,
                    ..ewf_image::WriteMediaProfile::default()
                },
                metadata: rich_writer_metadata(),
                acquisition_errors: vec![ewf_image::AcquisitionError {
                    first_sector: 1,
                    sector_count: 2,
                }],
                memory_extents: vec![ewf_image::MemoryExtent {
                    start_page: 4,
                    page_count: 8,
                }],
                hashes: rich_writer_hashes(),
                ..ewf_image::WriteOptions::default()
            },
        },
    ]
}

fn rich_writer_metadata() -> ewf_image::EwfMetadata {
    ewf_image::EwfMetadata {
        case_number: Some("case_number".to_owned()),
        evidence_number: Some("evidence_number".to_owned()),
        examiner: Some("examiner_name".to_owned()),
        description: Some("description".to_owned()),
        notes: Some("notes".to_owned()),
        acquisition_software: Some("ewfacquire".to_owned()),
        acquisition_software_version: Some("20260629".to_owned()),
        os_version: Some("Linux".to_owned()),
        acquisition_date: Some("2026 6 29 12 0 0".to_owned()),
        system_date: Some("2026 6 29 12 0 0".to_owned()),
        header_values: BTreeMap::from([
            ("device_label".to_owned(), "Disk Label".to_owned()),
            ("model".to_owned(), "Model X".to_owned()),
            ("serial_number".to_owned(), "SN-001".to_owned()),
            ("process_identifier".to_owned(), "PID-1234".to_owned()),
        ]),
        ..ewf_image::EwfMetadata::default()
    }
}

fn rich_writer_hashes() -> ewf_image::WriteHashes {
    ewf_image::WriteHashes {
        md5: Some([0x11; 16]),
        sha1: Some([0x22; 20]),
        ..ewf_image::WriteHashes::default()
    }
}

fn patterned_data(size: usize) -> Vec<u8> {
    (0..size)
        .map(|index| {
            let value = index.wrapping_mul(17).wrapping_add(index / 3);
            u8::try_from(value & 0xff).expect("masked to u8")
        })
        .collect()
}

fn single_file_catalog(data_size: u64) -> ewf_image::SingleFilesInfo {
    ewf_image::SingleFilesInfo {
        root: ewf_image::SingleFileEntry {
            identifier: Some(1),
            file_entry_type: Some(ewf_image::SingleFileEntryType::Directory),
            name: Some("root".to_owned()),
            children: vec![ewf_image::SingleFileEntry {
                identifier: Some(2),
                file_entry_type: Some(ewf_image::SingleFileEntryType::File),
                name: Some("payload.bin".to_owned()),
                size: Some(data_size),
                extents: vec![ewf_image::SingleFileExtent {
                    data_offset: 0,
                    data_size,
                    sparse: false,
                }],
                ..ewf_image::SingleFileEntry::default()
            }],
            ..ewf_image::SingleFileEntry::default()
        },
        ..ewf_image::SingleFilesInfo::default()
    }
}

fn rich_single_file_catalog(data_size: u64) -> ewf_image::SingleFilesInfo {
    ewf_image::SingleFilesInfo {
        root: ewf_image::SingleFileEntry {
            identifier: Some(1),
            file_entry_type: Some(ewf_image::SingleFileEntryType::Directory),
            name: Some("root".to_owned()),
            children: vec![ewf_image::SingleFileEntry {
                identifier: Some(2),
                file_entry_type: Some(ewf_image::SingleFileEntryType::File),
                name: Some("payload.bin".to_owned()),
                size: Some(data_size),
                source_identifier: Some(7),
                subject_identifier: Some(3),
                permission_group_index: Some(0),
                extents: vec![ewf_image::SingleFileExtent {
                    data_offset: 0,
                    data_size,
                    sparse: false,
                }],
                ..ewf_image::SingleFileEntry::default()
            }],
            ..ewf_image::SingleFileEntry::default()
        },
        sources: vec![
            ewf_image::SingleFileSource {
                identifier: Some(0),
                name: Some("root-source".to_owned()),
                ..ewf_image::SingleFileSource::default()
            },
            ewf_image::SingleFileSource {
                identifier: Some(7),
                name: Some("acquired-folder".to_owned()),
                evidence_number: Some("EV-7".to_owned()),
                ..ewf_image::SingleFileSource::default()
            },
        ],
        subjects: vec![
            ewf_image::SingleFileSubject {
                identifier: Some(0),
                name: Some("root-subject".to_owned()),
            },
            ewf_image::SingleFileSubject {
                identifier: Some(3),
                name: Some("desktop-user".to_owned()),
            },
        ],
        permission_groups: vec![ewf_image::SingleFilePermissionGroup {
            name: Some("acl".to_owned()),
            identifier: Some("S-1-5-32-544".to_owned()),
            permissions: vec![ewf_image::SingleFilePermission {
                name: Some("Administrators".to_owned()),
                identifier: Some("S-1-5-32-544".to_owned()),
                access_mask: Some(0x0012_0089),
                ace_flags: Some(0),
                ..ewf_image::SingleFilePermission::default()
            }],
            ..ewf_image::SingleFilePermissionGroup::default()
        }],
        ..ewf_image::SingleFilesInfo::default()
    }
}

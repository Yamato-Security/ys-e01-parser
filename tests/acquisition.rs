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

//! Streaming acquisition, checkpoint, and crash recovery regressions.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use ewf_image::{
    AcquisitionOptions, AcquisitionReadOptions, AcquisitionWriter, EwfWriter, Image,
    WriteCompression, WriteOptions,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

const IDENTITY: [u8; 32] = [0x51; 32];

#[test]
fn automatic_bulk_reads_span_chunks_without_changing_media_bytes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("bulk.E01");
    let bytes: Vec<u8> = (0..128 * 1024).map(|n| (n % 251) as u8).collect();
    let options = AcquisitionOptions::new(bytes.len() as u64);
    let mut writer = AcquisitionWriter::create(&path, &options, IDENTITY).unwrap();
    let mut source = std::io::Cursor::new(bytes.clone());
    let result = writer
        .acquire_from(&mut source, &AcquisitionReadOptions::default())
        .unwrap();
    assert_eq!(result.progress.read_attempts, 1);
    writer.finish().unwrap();
    check_image(&path, &bytes);
}

#[test]
fn cancellation_inside_bulk_batch_preserves_hash_and_resume_offset() {
    use std::ops::ControlFlow;

    let dir = tempdir().unwrap();
    let path = dir.path().join("bulk-cancel.E01");
    let bytes: Vec<u8> = (0..128 * 1024).map(|n| (n % 251) as u8).collect();
    let options = AcquisitionOptions::new(bytes.len() as u64);
    let mut writer = AcquisitionWriter::create(&path, &options, IDENTITY).unwrap();
    let mut source = std::io::Cursor::new(bytes.clone());
    let result = writer
        .acquire_with_progress(
            &mut source,
            &AcquisitionReadOptions::default(),
            |progress| {
                if progress.bytes_written == 32 * 1024 {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            },
        )
        .unwrap();
    assert_eq!(result.status, ewf_image::AcquisitionStatus::Cancelled);
    assert_eq!(result.progress.bytes_written, 32 * 1024);
    assert_eq!(result.progress.checkpoint_bytes, 32 * 1024);
    writer
        .acquire_from(&mut source, &AcquisitionReadOptions::default())
        .unwrap();
    writer.finish().unwrap();
    check_image(&path, &bytes);
}

#[test]
fn zlib_writers_bound_incompressible_chunks_and_resume_mixed_encodings() {
    let mut bytes = Vec::new();
    for counter in 0_u32..8192 {
        bytes.extend_from_slice(&Sha256::digest(counter.to_le_bytes()));
    }
    bytes.resize(524_288, 0);
    bytes.extend_from_within(..4096);
    for streaming in [false, true] {
        let root = tempdir().unwrap();
        let path = root.path().join("mixed.E01");
        if streaming {
            let options = AcquisitionOptions {
                bytes_per_sector: 4096,
                sectors_per_chunk: 64,
                chunks_per_segment: 1,
                compression: WriteCompression::Zlib,
                ..AcquisitionOptions::new(bytes.len() as u64)
            };
            let mut writer = AcquisitionWriter::create(&path, &options, IDENTITY).unwrap();
            writer.write_all(&bytes[..262_144]).unwrap();
            drop(writer);
            let mut writer = AcquisitionWriter::resume(&path, &options, IDENTITY).unwrap();
            writer.write_all(&bytes[262_144..]).unwrap();
            writer.finish().unwrap();
        } else {
            let options = WriteOptions {
                bytes_per_sector: 4096,
                sectors_per_chunk: 64,
                compression: WriteCompression::Zlib,
                ..WriteOptions::default()
            };
            let mut writer = EwfWriter::create(&path, options).unwrap();
            writer.write_all(&bytes).unwrap();
            writer.finish().unwrap();
        }
        check_image(&path, &bytes);
        let image = Image::open(&path).unwrap();
        for (index, encoding) in [
            ewf_image::DataChunkEncoding::Raw,
            ewf_image::DataChunkEncoding::Zlib,
            ewf_image::DataChunkEncoding::Raw,
        ]
        .into_iter()
        .enumerate()
        {
            let chunk = image.read_data_chunk(index as u64).unwrap();
            assert_eq!(chunk.encoding, encoding);
            assert!(chunk.encoded_size <= chunk.logical_size as u64 + 4);
        }
    }
}

fn options(size: usize, compression: WriteCompression) -> AcquisitionOptions {
    AcquisitionOptions {
        sectors_per_chunk: 2,
        chunks_per_segment: 3,
        compression,
        ..AcquisitionOptions::new(size as u64)
    }
}

fn data(size: usize) -> Vec<u8> {
    (0..size)
        .map(|index| ((index * 139 + index / 13) % 256) as u8)
        .collect()
}

fn check_image(path: &Path, expected: &[u8]) {
    let image = Image::open(path).unwrap();
    assert!(image.info().acquisition_complete);
    assert_eq!(image.media_size(), expected.len() as u64);
    let mut actual = Vec::new();
    image.cursor().read_to_end(&mut actual).unwrap();
    assert_eq!(actual, expected);
    let expected_sha256 = Sha256::digest(expected)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(image.hash_value("SHA256").unwrap(), expected_sha256);
    #[cfg(feature = "verify")]
    {
        let result = image.verify().unwrap();
        assert_eq!(result.md5_match, Some(true));
        assert_eq!(result.sha1_match, Some(true));
        assert_eq!(result.sha256_match, Some(true));
    }
}

#[test]
fn streaming_segment_names_cross_numeric_and_prefix_boundaries() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("case.E01");
    let bytes = data(780 * 512);
    let mut options = AcquisitionOptions::new(bytes.len() as u64);
    options.sectors_per_chunk = 1;
    options.chunks_per_segment = 1;
    let mut writer = AcquisitionWriter::create(&path, &options, IDENTITY).unwrap();
    writer.write_all(&bytes[..776 * 512]).unwrap();
    drop(writer);
    let mut writer = AcquisitionWriter::resume(&path, &options, IDENTITY).unwrap();
    writer.write_all(&bytes[776 * 512..]).unwrap();
    let result = writer.finish().unwrap();
    assert_eq!(result.segment_paths.len(), 780);
    assert_eq!(result.segment_paths[98].extension().unwrap(), "E99");
    assert_eq!(result.segment_paths[99].extension().unwrap(), "EAA");
    assert_eq!(result.segment_paths[103].extension().unwrap(), "EAE");
    assert_eq!(result.segment_paths[774].extension().unwrap(), "EZZ");
    assert_eq!(result.segment_paths[775].extension().unwrap(), "FAA");
    check_image(&path, &bytes);
}

#[test]
fn streaming_boundaries_and_final_short_chunk() {
    for compression in [WriteCompression::None, WriteCompression::Zlib] {
        for size in [512, 1024, 3072, 3584, 12 * 1024] {
            let dir = tempdir().unwrap();
            let path = dir.path().join("case.E01");
            let bytes = data(size);
            let mut writer =
                AcquisitionWriter::create(&path, &options(size, compression), IDENTITY).unwrap();
            for part in bytes.chunks(137) {
                writer.write_all(part).unwrap();
            }
            assert_eq!(writer.position(), size as u64);
            assert_eq!(writer.checkpoint_offset(), size as u64);
            assert_eq!(writer.sealed_segments(), size.div_ceil(3072));
            assert!(!path.exists());
            let result = writer.finish().unwrap();
            assert_eq!(
                result.computed_sha256,
                <[u8; 32]>::from(Sha256::digest(&bytes))
            );
            assert_eq!(result.chunk_count, size.div_ceil(1024) as u64);
            check_image(&path, &bytes);
        }
    }
}

#[test]
fn resume_discards_only_unsealed_tail_and_preserves_sealed_bytes() {
    for compression in [WriteCompression::None, WriteCompression::Zlib] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("case.E01");
        let bytes = data(9 * 1024 + 512);
        let opts = options(bytes.len(), compression);
        let mut writer = AcquisitionWriter::create(&path, &opts, IDENTITY).unwrap();
        writer.write_all(&bytes[..4500]).unwrap();
        assert_eq!(writer.checkpoint_offset(), 3072);
        assert_eq!(writer.checkpoint().unwrap(), 4096);
        assert_eq!(writer.position(), 4500);
        drop(writer);
        let state = dir.path().join(".case.E01.ewf-acquisition");
        let first_bytes = fs::read(state.join("case.E01")).unwrap();
        let second_bytes = fs::read(state.join("case.E02")).unwrap();
        // A segment written before its record is not an acknowledged checkpoint.
        fs::write(state.join("case.E03"), b"interrupted seal").unwrap();
        fs::write(state.join("scratch").join("orphan"), b"interrupted scratch").unwrap();
        let mut resumed = AcquisitionWriter::resume(&path, &opts, IDENTITY).unwrap();
        assert_eq!(resumed.position(), 4096);
        assert!(!state.join("case.E03").exists());
        assert!(!state.join("scratch").join("orphan").exists());
        resumed.write_all(&bytes[4096..]).unwrap();
        let result = resumed.finish().unwrap();
        assert_eq!(fs::read(&result.segment_paths[0]).unwrap(), first_bytes);
        assert_eq!(fs::read(&result.segment_paths[1]).unwrap(), second_bytes);
        check_image(&path, &bytes);
    }
}

#[test]
fn resume_zero_and_fully_checkpointed_sources() {
    for initial in [0, 317, 4096] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("case.E01");
        let bytes = data(4096);
        let opts = options(bytes.len(), WriteCompression::Zlib);
        let mut writer = AcquisitionWriter::create(&path, &opts, IDENTITY).unwrap();
        writer.write_all(&bytes[..initial]).unwrap();
        drop(writer);
        let mut writer = AcquisitionWriter::resume(&path, &opts, IDENTITY).unwrap();
        let offset = writer.position() as usize;
        writer.write_all(&bytes[offset..]).unwrap();
        writer.finish().unwrap();
        check_image(&path, &bytes);
    }
}

#[test]
fn identity_configuration_and_active_writer_are_checked() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("case.E01");
    let opts = options(4096, WriteCompression::Zlib);
    let mut writer = AcquisitionWriter::create(&path, &opts, IDENTITY).unwrap();
    writer.write_all(&data(3072)).unwrap();
    assert!(AcquisitionWriter::resume(&path, &opts, IDENTITY).is_err());
    assert!(AcquisitionWriter::create(&path, &opts, IDENTITY).is_err());
    drop(writer);
    assert!(AcquisitionWriter::resume(&path, &opts, [7; 32]).is_err());
    let mut changed = opts.clone();
    changed.source_size += 512;
    assert!(AcquisitionWriter::resume(&path, &changed, IDENTITY).is_err());
    let mut changed = opts.clone();
    changed.chunks_per_segment = 2;
    assert!(AcquisitionWriter::resume(&path, &changed, IDENTITY).is_err());
    let mut changed = opts.clone();
    changed.metadata.set_header_value("case_number", "changed");
    assert!(AcquisitionWriter::resume(&path, &changed, IDENTITY).is_err());
    let mut other = EwfWriter::create(
        &path,
        WriteOptions {
            overwrite_existing: true,
            ..WriteOptions::default()
        },
    )
    .unwrap();
    other.write_all(&data(4096)).unwrap();
    assert!(other.finish().is_err());
    assert!(AcquisitionWriter::resume(&path, &opts, IDENTITY).is_ok());
}

#[test]
fn damaged_sealed_data_or_checkpoint_is_rejected() {
    for corrupt_record in [false, true] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("case.E01");
        let opts = options(4096, WriteCompression::None);
        let mut writer = AcquisitionWriter::create(&path, &opts, IDENTITY).unwrap();
        writer.write_all(&data(3072)).unwrap();
        drop(writer);
        let state = dir.path().join(".case.E01.ewf-acquisition");
        let target = state.join(if corrupt_record {
            "checkpoint-00001"
        } else {
            "case.E01"
        });
        let mut bytes = fs::read(&target).unwrap();
        let index = bytes.len() / 2;
        bytes[index] ^= 1;
        fs::write(&target, &bytes).unwrap();
        assert!(AcquisitionWriter::resume(&path, &opts, IDENTITY).is_err());
        assert_eq!(fs::read(&target).unwrap(), bytes);
    }
}

#[test]
fn refuses_existing_outputs_and_wrong_lengths() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("case.E01");
    let opts = options(4096, WriteCompression::Zlib);
    fs::write(path.with_extension("E04"), b"existing").unwrap();
    assert!(AcquisitionWriter::create(&path, &opts, IDENTITY).is_err());
    fs::remove_file(path.with_extension("E04")).unwrap();
    let mut writer = AcquisitionWriter::create(&path, &opts, IDENTITY).unwrap();
    writer.write_all(&data(100)).unwrap();
    assert!(writer.finish().is_err());
    let mut writer = AcquisitionWriter::resume(&path, &opts, IDENTITY).unwrap();
    writer.write_all(&data(4096)).unwrap();
    assert!(writer.write_all(&[1]).is_err());
    assert!(writer.finish().is_err());
    AcquisitionWriter::resume(&path, &opts, IDENTITY)
        .unwrap()
        .finish()
        .unwrap();
    check_image(&path, &data(4096));
}

#[test]
fn rejects_unsupported_geometry_before_creating_state() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("case.E01");
    for size in [0, 1, 513] {
        assert!(
            AcquisitionWriter::create(&path, &AcquisitionOptions::new(size), IDENTITY).is_err()
        );
    }
    let mut opts = AcquisitionOptions::new(4096);
    opts.chunks_per_segment = 0;
    assert!(AcquisitionWriter::create(&path, &opts, IDENTITY).is_err());
    let mut opts = AcquisitionOptions::new(4096);
    opts.compression = WriteCompression::Bzip2;
    assert!(AcquisitionWriter::create(&path, &opts, IDENTITY).is_err());
    assert!(!dir.path().join(".case.E01.ewf-acquisition").exists());
}

struct FaultySource {
    data: std::io::Cursor<Vec<u8>>,
    failures: std::collections::BTreeMap<u64, u32>,
    short_read: usize,
}

impl FaultySource {
    fn new(bytes: Vec<u8>, failures: &[(u64, u32)]) -> Self {
        Self {
            data: std::io::Cursor::new(bytes),
            failures: failures.iter().copied().collect(),
            short_read: usize::MAX,
        }
    }
}

impl Read for FaultySource {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let offset = self.data.position();
        let end = offset + buffer.len() as u64;
        if let Some((&sector, count)) = self.failures.iter_mut().find(|(sector, count)| {
            **count > 0 && **sector * 512 < end && (**sector + 1) * 512 > offset
        }) {
            if sector * 512 > offset {
                let size = (sector * 512 - offset) as usize;
                return self.data.read(&mut buffer[..size.min(self.short_read)]);
            }
            // Transient failures apply to sector-sized retries, not bulk reads.
            if buffer.len() <= 512 && *count != u32::MAX {
                *count -= 1;
            }
            return Err(std::io::Error::other("injected source read failure"));
        }
        let size = buffer.len().min(self.short_read);
        self.data.read(&mut buffer[..size])
    }
}

impl std::io::Seek for FaultySource {
    fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
        self.data.seek(position)
    }
}

#[test]
fn source_retries_zero_fill_and_error_provenance_survive_resume() {
    use ewf_image::{
        AcquisitionError, AcquisitionReadOptions, AcquisitionStatus, UnreadableSectorPolicy,
    };
    use std::ops::ControlFlow;
    for compression in [WriteCompression::None, WriteCompression::Zlib] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("case.E01");
        let bytes = data(10 * 512);
        let opts = options(bytes.len(), compression);
        let read_options = AcquisitionReadOptions {
            retries: 1,
            unreadable_sector_policy: UnreadableSectorPolicy::ZeroFill,
            ..AcquisitionReadOptions::default()
        };
        let mut source = FaultySource::new(
            bytes.clone(),
            &[
                (1, u32::MAX),
                (3, 2),
                (5, u32::MAX),
                (6, u32::MAX),
                (9, u32::MAX),
            ],
        );
        let mut writer = AcquisitionWriter::create(&path, &opts, IDENTITY).unwrap();
        let result = writer
            .acquire_with_progress(&mut source, &read_options, |progress| {
                if progress.bytes_written >= 3072 {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            })
            .unwrap();
        assert_eq!(result.status, AcquisitionStatus::Cancelled);
        assert_eq!(result.progress.checkpoint_bytes, 3072);
        assert_eq!(result.progress.substituted_sectors, 3);
        assert!(result.progress.retry_attempts >= 3);
        drop(writer);
        let mut writer = AcquisitionWriter::resume(&path, &opts, IDENTITY).unwrap();
        assert_eq!(writer.acquisition_errors().len(), 3);
        let result = writer.acquire_from(&mut source, &read_options).unwrap();
        assert_eq!(result.status, AcquisitionStatus::Complete);
        assert_eq!(result.progress.substituted_sectors, 5);
        assert_eq!(
            writer.acquisition_errors(),
            &[
                AcquisitionError {
                    first_sector: 1,
                    sector_count: 1
                },
                AcquisitionError {
                    first_sector: 3,
                    sector_count: 1
                },
                AcquisitionError {
                    first_sector: 5,
                    sector_count: 2
                },
                AcquisitionError {
                    first_sector: 9,
                    sector_count: 1
                },
            ]
        );
        writer.finish().unwrap();
        let mut expected = bytes.clone();
        for sector in [1, 3, 5, 6, 9] {
            expected[sector * 512..(sector + 1) * 512].fill(0);
        }
        check_image(&path, &expected);
        assert_ne!(Sha256::digest(&bytes), Sha256::digest(&expected));
        let image = Image::open(&path).unwrap();
        assert_eq!(
            image
                .acquisition_errors()
                .iter()
                .map(|range| range.sector_count)
                .sum::<u64>(),
            5
        );
        assert!(
            image
                .acquisition_errors()
                .iter()
                .any(|range| range.first_sector == 9)
        );
    }
}

#[test]
fn default_source_failure_stops_without_poisoning_or_substitution() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("case.E01");
    let bytes = data(4096);
    let mut source = FaultySource::new(bytes.clone(), &[(1, u32::MAX)]);
    let mut writer = AcquisitionWriter::create(
        &path,
        &options(bytes.len(), WriteCompression::Zlib),
        IDENTITY,
    )
    .unwrap();
    assert!(
        writer
            .acquire_from(&mut source, &ewf_image::AcquisitionReadOptions::default())
            .is_err()
    );
    assert_eq!(writer.position(), 512);
    assert_eq!(writer.acquisition_errors(), []);
    source.failures.clear();
    writer
        .acquire_from(&mut source, &ewf_image::AcquisitionReadOptions::default())
        .unwrap();
    writer.finish().unwrap();
    check_image(&path, &bytes);
}

#[test]
fn unsealed_substitution_is_not_restored_by_resume() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("case.E01");
    let bytes = data(4096);
    let opts = options(bytes.len(), WriteCompression::None);
    let mut source = FaultySource::new(bytes.clone(), &[(0, u32::MAX)]);
    let read_options = ewf_image::AcquisitionReadOptions {
        unreadable_sector_policy: ewf_image::UnreadableSectorPolicy::ZeroFill,
        ..ewf_image::AcquisitionReadOptions::default()
    };
    let mut writer = AcquisitionWriter::create(&path, &opts, IDENTITY).unwrap();
    let outcome = writer
        .acquire_with_progress(&mut source, &read_options, |progress| {
            if progress.bytes_written >= 512 {
                std::ops::ControlFlow::Break(())
            } else {
                std::ops::ControlFlow::Continue(())
            }
        })
        .unwrap();
    assert_eq!(outcome.progress.bytes_written, 512);
    assert_eq!(outcome.progress.checkpoint_bytes, 0);
    assert_eq!(outcome.progress.substituted_sectors, 1);
    drop(writer);
    let mut writer = AcquisitionWriter::resume(&path, &opts, IDENTITY).unwrap();
    assert_eq!(writer.acquisition_errors(), []);
    source.failures.clear();
    writer.acquire_from(&mut source, &read_options).unwrap();
    writer.finish().unwrap();
    check_image(&path, &bytes);
}

#[test]
fn source_short_reads_and_configurable_checkpoints() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("case.E01");
    let bytes = data(4096);
    let mut source = FaultySource::new(bytes.clone(), &[]);
    source.short_read = 37;
    let mut writer = AcquisitionWriter::create(
        &path,
        &options(bytes.len(), WriteCompression::Zlib),
        IDENTITY,
    )
    .unwrap();
    let opts = ewf_image::AcquisitionReadOptions {
        checkpoint_interval: Some(1024),
        ..ewf_image::AcquisitionReadOptions::default()
    };
    let result = writer.acquire_from(&mut source, &opts).unwrap();
    assert_eq!(result.progress.sealed_segments, 4);
    assert_eq!(result.progress.substituted_sectors, 0);
    writer.finish().unwrap();
    check_image(&path, &bytes);
}

#[test]
fn source_eof_is_never_zero_filled_and_error_ranges_are_bounded() {
    for truncated in [true, false] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("case.E01");
        let mut source = FaultySource::new(
            data(if truncated { 512 } else { 4096 }),
            if truncated {
                &[]
            } else {
                &[(1, u32::MAX), (3, u32::MAX)]
            },
        );
        let mut writer =
            AcquisitionWriter::create(&path, &options(4096, WriteCompression::None), IDENTITY)
                .unwrap();
        let opts = ewf_image::AcquisitionReadOptions {
            unreadable_sector_policy: ewf_image::UnreadableSectorPolicy::ZeroFill,
            maximum_error_ranges: 1,
            ..ewf_image::AcquisitionReadOptions::default()
        };
        assert!(writer.acquire_from(&mut source, &opts).is_err());
        assert_eq!(writer.acquisition_errors().len(), usize::from(!truncated));
        assert!(writer.position() < 4096);
    }
}

#[test]
fn checkpoint_inspection_is_read_only_and_resume_cancellation_preserves_scratch() {
    use ewf_image::AcquisitionOperationPhase;
    use std::ops::ControlFlow;
    let dir = tempdir().unwrap();
    let path = dir.path().join("case.E01");
    let bytes = data(9216);
    let opts = options(bytes.len(), WriteCompression::None);
    let mut writer = AcquisitionWriter::create(&path, &opts, IDENTITY).unwrap();
    writer.write_all(&bytes[..4500]).unwrap();
    assert!(AcquisitionWriter::inspect_checkpoint(&path, &opts, IDENTITY).is_err());
    drop(writer);
    let state = dir.path().join(".case.E01.ewf-acquisition");
    let orphan = state.join("case.E02");
    let scratch = state.join("scratch").join("keep-until-resume");
    fs::write(&orphan, b"uncommitted segment").unwrap();
    fs::write(&scratch, b"uncommitted scratch").unwrap();
    let report = AcquisitionWriter::inspect_checkpoint(&path, &opts, IDENTITY).unwrap();
    assert_eq!(report.checkpoint_bytes, 3072);
    assert_eq!(report.sealed_segments, 1);
    assert!(!report.ready_to_finish);
    assert!(!report.publication_started);
    assert!(!report.segment_hashes_validated);
    let report = AcquisitionWriter::validate_checkpoint(&path, &opts, IDENTITY, |_| {
        ControlFlow::Continue(())
    })
    .unwrap();
    assert!(report.segment_hashes_validated);
    for phase in [
        AcquisitionOperationPhase::ValidatingSegments,
        AcquisitionOperationPhase::RehashingMedia,
    ] {
        let result = AcquisitionWriter::resume_with_progress(&path, &opts, IDENTITY, |progress| {
            if progress.phase == phase && progress.bytes_processed > 0 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        });
        assert!(matches!(result, Err(ewf_image::EwfError::Aborted)));
        assert_eq!(fs::read(&orphan).unwrap(), b"uncommitted segment");
        assert_eq!(fs::read(&scratch).unwrap(), b"uncommitted scratch");
    }
    let mut writer = AcquisitionWriter::resume(&path, &opts, IDENTITY).unwrap();
    assert!(!orphan.exists());
    assert!(!scratch.exists());
    writer.write_all(&bytes[3072..]).unwrap();
    writer.finish().unwrap();
    check_image(&path, &bytes);
}

#[test]
fn metadata_inspection_does_not_claim_to_validate_payload_bytes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("case.E01");
    let bytes = data(4096);
    let opts = options(bytes.len(), WriteCompression::None);
    let mut writer = AcquisitionWriter::create(&path, &opts, IDENTITY).unwrap();
    writer.write_all(&bytes[..3072]).unwrap();
    drop(writer);
    let sealed = dir
        .path()
        .join(".case.E01.ewf-acquisition")
        .join("case.E01");
    let mut container = fs::read(&sealed).unwrap();
    let offset = container
        .windows(1024)
        .position(|window| window == &bytes[..1024])
        .unwrap();
    container[offset] ^= 1;
    fs::write(sealed, container).unwrap();
    let report = AcquisitionWriter::inspect_checkpoint(&path, &opts, IDENTITY).unwrap();
    assert!(!report.segment_hashes_validated);
    assert!(
        AcquisitionWriter::validate_checkpoint(&path, &opts, IDENTITY, |_| {
            std::ops::ControlFlow::Continue(())
        })
        .is_err()
    );
    assert!(AcquisitionWriter::resume(&path, &opts, IDENTITY).is_err());
}

#[test]
fn cancelled_publication_can_be_inspected_and_finished() {
    use ewf_image::AcquisitionOperationPhase;
    use std::ops::ControlFlow;
    for phase in [
        AcquisitionOperationPhase::ValidatingSegments,
        AcquisitionOperationPhase::Publishing,
    ] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("case.E01");
        let bytes = data(9216);
        let opts = options(bytes.len(), WriteCompression::Zlib);
        let mut writer = AcquisitionWriter::create(&path, &opts, IDENTITY).unwrap();
        writer.write_all(&bytes).unwrap();
        let result = writer.finish_with_progress(|progress| {
            assert!(progress.bytes_processed <= progress.bytes_total);
            if progress.phase == phase && progress.bytes_processed > 0 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        });
        assert!(matches!(result, Err(ewf_image::EwfError::Aborted)));
        let report = AcquisitionWriter::inspect_checkpoint(&path, &opts, IDENTITY).unwrap();
        assert!(report.ready_to_finish);
        assert_eq!(
            report.publication_started,
            phase == AcquisitionOperationPhase::Publishing
        );
        assert!(Image::open(&path).is_err());
        let mut seen = Vec::new();
        let writer = AcquisitionWriter::resume_with_progress(&path, &opts, IDENTITY, |progress| {
            assert!(progress.bytes_processed <= progress.bytes_total);
            seen.push(progress.phase);
            ControlFlow::Continue(())
        })
        .unwrap();
        assert!(seen.contains(&AcquisitionOperationPhase::ValidatingSegments));
        assert!(seen.contains(&AcquisitionOperationPhase::RehashingMedia));
        writer.finish().unwrap();
        check_image(&path, &bytes);
    }
}

#[test]
fn cancellation_between_short_reads_does_not_commit_a_partial_attempt() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("case.E01");
    let bytes = data(4096);
    let opts = options(bytes.len(), WriteCompression::Zlib);
    let mut writer = AcquisitionWriter::create(&path, &opts, IDENTITY).unwrap();
    let mut source = FaultySource::new(bytes.clone(), &[]);
    source.short_read = 7;
    let result = writer
        .acquire_with_progress(
            &mut source,
            &ewf_image::AcquisitionReadOptions::default(),
            |progress| {
                if progress.read_attempts == 1 {
                    std::ops::ControlFlow::Break(())
                } else {
                    std::ops::ControlFlow::Continue(())
                }
            },
        )
        .unwrap();
    assert_eq!(result.status, ewf_image::AcquisitionStatus::Cancelled);
    assert_eq!(result.progress.bytes_written, 0);
    writer
        .acquire_from(&mut source, &ewf_image::AcquisitionReadOptions::default())
        .unwrap();
    writer.finish().unwrap();
    check_image(&path, &bytes);
}

#[test]
fn fatal_source_errors_and_invalid_controls_never_substitute_data() {
    struct FailedSource {
        seek_error: bool,
        kind: std::io::ErrorKind,
        reads: usize,
    }
    impl Read for FailedSource {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            self.reads += 1;
            Err(std::io::Error::new(
                self.kind,
                "injected fatal source failure",
            ))
        }
    }
    impl std::io::Seek for FailedSource {
        fn seek(&mut self, offset: std::io::SeekFrom) -> std::io::Result<u64> {
            if self.seek_error {
                return Err(std::io::Error::other("injected seek failure"));
            }
            match offset {
                std::io::SeekFrom::Start(offset) => Ok(offset),
                _ => unreachable!(),
            }
        }
    }
    for (seek_error, kind) in [
        (true, std::io::ErrorKind::Other),
        (false, std::io::ErrorKind::PermissionDenied),
        (false, std::io::ErrorKind::UnexpectedEof),
        (false, std::io::ErrorKind::Interrupted),
        (false, std::io::ErrorKind::TimedOut),
        (false, std::io::ErrorKind::InvalidInput),
        (false, std::io::ErrorKind::Unsupported),
        (false, std::io::ErrorKind::NotFound),
        (false, std::io::ErrorKind::NotConnected),
        (false, std::io::ErrorKind::ConnectionAborted),
        (false, std::io::ErrorKind::ConnectionReset),
        (false, std::io::ErrorKind::BrokenPipe),
    ] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("case.E01");
        let mut writer =
            AcquisitionWriter::create(&path, &options(4096, WriteCompression::None), IDENTITY)
                .unwrap();
        let opts = ewf_image::AcquisitionReadOptions {
            unreadable_sector_policy: ewf_image::UnreadableSectorPolicy::ZeroFill,
            ..ewf_image::AcquisitionReadOptions::default()
        };
        let mut source = FailedSource {
            seek_error,
            kind,
            reads: 0,
        };
        assert!(writer.acquire_from(&mut source, &opts).is_err());
        assert_eq!(source.reads, usize::from(!seek_error));
        assert_eq!(writer.position(), 0);
        assert_eq!(writer.acquisition_errors(), []);
        for bad_opts in [
            ewf_image::AcquisitionReadOptions {
                retries: 101,
                ..opts.clone()
            },
            ewf_image::AcquisitionReadOptions {
                maximum_error_ranges: 0,
                ..opts.clone()
            },
            ewf_image::AcquisitionReadOptions {
                checkpoint_interval: Some(1),
                ..opts.clone()
            },
        ] {
            assert!(writer.acquire_from(&mut source, &bad_opts).is_err());
            assert_eq!(source.reads, usize::from(!seek_error));
        }
    }
}

#[test]
fn checkpoint_interval_must_fit_native_segment_namespace() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("case.E01");
    let opts = ewf_image::AcquisitionOptions::new(512 * 1024 * 1024);
    let mut writer = AcquisitionWriter::create(&path, &opts, IDENTITY).unwrap();
    let read_options = ewf_image::AcquisitionReadOptions {
        checkpoint_interval: Some(32768),
        ..ewf_image::AcquisitionReadOptions::default()
    };
    let mut source = std::io::Cursor::new(Vec::<u8>::new());
    assert!(matches!(
        writer.acquire_from(&mut source, &read_options),
        Err(ewf_image::EwfError::Unsupported(_))
    ));
    assert_eq!(writer.position(), 0);
    assert_eq!(writer.sealed_segments(), 0);
}

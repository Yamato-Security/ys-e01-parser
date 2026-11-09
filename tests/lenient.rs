// Copyright (C) 2026 Shirofune Security Co., Ltd.
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

//! Lenient opening of damaged images: every chunk that can still be verified is
//! readable, every defect is reported, and no read returns wrong bytes.
#![cfg(feature = "verify")]

use std::io::Write;
use std::path::{Path, PathBuf};

use ewf_image::{
    EwfError, EwfWriter, Image, IntegrityFindingKind, OpenOptions, OpenStrictness, SectionInfo,
    SectionKind, VerifyOptions, WriteCompression, WriteFormat, WriteOptions,
};

const CHUNK: usize = 32_768;

/// Compressible media whose chunks all differ, so a chunk read from the
/// wrong place shows.
fn media(chunks: usize) -> Vec<u8> {
    (0..chunks * CHUNK)
        .map(|index| {
            let chunk = index / CHUNK;
            let run = (index % CHUNK) / 48;
            (run as u8).wrapping_mul(29) ^ (chunk as u8).wrapping_mul(37)
        })
        .collect()
}

/// Media that does not compress, so writers store its chunks raw.
fn noise(chunks: usize) -> Vec<u8> {
    (0..chunks * CHUNK)
        .map(|index| {
            let chunk = index / CHUNK;
            let byte = (index % CHUNK) as u32;
            (byte.wrapping_mul(2_654_435_761) >> 13) as u8 ^ (chunk as u8).wrapping_mul(37)
        })
        .collect()
}

struct Written {
    _dir: tempfile::TempDir,
    path: PathBuf,
    data: Vec<u8>,
}

fn write_image(
    name: &str,
    format: WriteFormat,
    compression: WriteCompression,
    data: &[u8],
    configure: impl FnOnce(&mut WriteOptions),
) -> Written {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    let mut options = WriteOptions {
        format,
        compression,
        ..WriteOptions::default()
    };
    configure(&mut options);
    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(data).unwrap();
    writer.finish().unwrap();
    Written {
        _dir: dir,
        path,
        data: data.to_vec(),
    }
}

fn e01(compression: WriteCompression, chunks: usize) -> Written {
    write_image(
        "image.E01",
        WriteFormat::Ewf1Physical,
        compression,
        &media(chunks),
        |_| {},
    )
}

fn ex01(chunks: usize) -> Written {
    ex01_of(&media(chunks))
}

fn ex01_of(data: &[u8]) -> Written {
    write_image(
        "image.Ex01",
        WriteFormat::Ewf2Physical,
        WriteCompression::Zlib,
        data,
        |_| {},
    )
}

fn open_strict(path: &Path) -> ewf_image::Result<Image> {
    Image::open_with_options(
        path,
        OpenOptions::default().with_strictness(OpenStrictness::Strict),
    )
}

/// Sections of the intact image, found before damaging it.
fn sections(path: &Path) -> Vec<SectionInfo> {
    Image::open(path).unwrap().sections().to_vec()
}

fn ewf1_section(sections: &[SectionInfo], segment: usize, name: &str) -> SectionInfo {
    sections
        .iter()
        .find(|section| {
            section.segment_index == segment && section.kind == SectionKind::Ewf1(name.into())
        })
        .unwrap_or_else(|| panic!("segment {segment} has a {name} section"))
        .clone()
}

fn ewf2_section(sections: &[SectionInfo], kind: u32) -> SectionInfo {
    sections
        .iter()
        .find(|section| section.kind == SectionKind::Ewf2(kind))
        .unwrap_or_else(|| panic!("image has an EWF2 section 0x{kind:x}"))
        .clone()
}

fn modify(path: &Path, change: impl FnOnce(&mut Vec<u8>)) {
    let mut bytes = std::fs::read(path).unwrap();
    change(&mut bytes);
    std::fs::write(path, bytes).unwrap();
}

fn flip(path: &Path, offset: u64) {
    modify(path, |bytes| {
        bytes[usize::try_from(offset).unwrap()] ^= 0x01;
    });
}

fn kinds(image: &Image) -> Vec<IntegrityFindingKind> {
    image
        .lenient_findings()
        .into_iter()
        .map(|finding| finding.kind)
        .collect()
}

/// Reads every chunk. Each one either fails or equals the original media.
/// Returns how many chunks were readable.
fn readable_chunks(image: &Image, original: &[u8]) -> usize {
    assert_eq!(image.media_size(), original.len() as u64);
    let mut readable = 0;
    for (index, expected) in original.chunks(CHUNK).enumerate() {
        let mut buffer = vec![0; expected.len()];
        match image.read_at(&mut buffer, (index * CHUNK) as u64) {
            Ok(read) => {
                assert_eq!(read, expected.len(), "chunk {index} short read");
                assert!(buffer == expected, "chunk {index} returned wrong bytes");
                readable += 1;
            }
            Err(error) => assert!(
                matches!(error, EwfError::Malformed(_)),
                "chunk {index}: {error}"
            ),
        }
    }
    readable
}

#[test]
fn intact_images_open_leniently_without_findings() {
    for written in [e01(WriteCompression::Zlib, 3), ex01(3)] {
        let image = Image::open(&written.path).unwrap();
        assert_eq!(image.open_strictness(), OpenStrictness::Lenient);
        assert_eq!(kinds(&image), Vec::<IntegrityFindingKind>::new());
        assert_eq!(readable_chunks(&image, &written.data), 3);
        let report = image.analyze(&VerifyOptions::default()).unwrap();
        assert_eq!(report.error_count, 0);
        assert_eq!(report.warning_count, 0);
    }
}

#[test]
fn damaged_ewf1_digest_is_ignored_and_reported() {
    let written = e01(WriteCompression::Zlib, 2);
    let digest = ewf1_section(&sections(&written.path), 0, "digest");
    // The stored MD5, inside the checksummed digest payload.
    flip(&written.path, digest.data_offset + 3);

    assert!(open_strict(&written.path).is_err());
    let image = Image::open(&written.path).unwrap();
    assert_eq!(kinds(&image), [IntegrityFindingKind::MetadataUnavailable]);
    let finding = &image.lenient_findings()[0];
    assert_eq!(finding.segment_index, Some(0));
    assert_eq!(finding.segment_offset, Some(digest.descriptor_offset));
    assert_eq!(readable_chunks(&image, &written.data), 2);
    // The analysis repeats the finding ahead of the media results.
    let report = image.analyze(&VerifyOptions::default()).unwrap();
    assert_eq!(
        report.findings[0].kind,
        IntegrityFindingKind::MetadataUnavailable
    );
}

#[test]
fn damaged_compressed_header_is_ignored_and_reported() {
    let written = write_image(
        "image.E01",
        WriteFormat::Ewf1Physical,
        WriteCompression::Zlib,
        &media(1),
        |options| {
            options
                .metadata
                .header_values
                .insert("case_number".into(), "case-17".into());
        },
    );
    assert_eq!(
        Image::open(&written.path)
            .unwrap()
            .header_value("case_number")
            .as_deref(),
        Some("case-17")
    );
    let header = ewf1_section(&sections(&written.path), 0, "header");
    // Damage the deflate data; the zlib Adler-32 no longer matches.
    flip(&written.path, header.data_offset + header.data_size - 6);

    let image = Image::open(&written.path).unwrap();
    assert_eq!(kinds(&image), [IntegrityFindingKind::MetadataUnavailable]);
    assert_eq!(readable_chunks(&image, &written.data), 1);
}

#[test]
fn damaged_ewf2_hashes_are_ignored_and_reported() {
    let written = ex01(2);
    let all = sections(&written.path);
    let md5 = ewf2_section(&all, 0x08);
    let sha1 = ewf2_section(&all, 0x09);
    flip(&written.path, md5.data_offset);
    flip(&written.path, sha1.data_offset);

    assert!(open_strict(&written.path).is_err());
    let image = Image::open(&written.path).unwrap();
    assert!(image.md5_hash().is_none() && image.sha1_hash().is_none());
    assert_eq!(
        kinds(&image),
        [
            IntegrityFindingKind::MetadataUnavailable,
            IntegrityFindingKind::MetadataUnavailable
        ]
    );
    assert_eq!(readable_chunks(&image, &written.data), 2);
}

/// One compressed chunk holding a full 32 KiB although the volume declares
/// fewer sectors, as some libewf versions wrote the final chunk.
fn overlong_final_chunk_image(sectors: u64) -> (tempfile::TempDir, PathBuf, Vec<u8>) {
    let data = media(1);
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&data).unwrap();
    let chunk = encoder.finish().unwrap();

    let volume_offset = 13_u64;
    let sectors_offset = volume_offset + 76 + 94;
    let chunk_offset = sectors_offset + 76;
    let table_offset = chunk_offset + chunk.len() as u64;
    let done_offset = table_offset + 76 + 24 + 4 + 4;

    let mut bytes = b"EVF\x09\x0d\x0a\xff\x00\x01\x01\x00\x00\x00".to_vec();
    bytes.extend(descriptor(b"volume", sectors_offset, 76 + 94));
    let mut volume = [0_u8; 94];
    volume[4..8].copy_from_slice(&1_u32.to_le_bytes());
    volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
    volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
    volume[16..20].copy_from_slice(&u32::try_from(sectors).unwrap().to_le_bytes());
    let checksum = adler32(&volume[..90]);
    volume[90..94].copy_from_slice(&checksum.to_le_bytes());
    bytes.extend(volume);
    bytes.extend(descriptor(
        b"sectors",
        table_offset,
        76 + chunk.len() as u64,
    ));
    bytes.extend(&chunk);
    bytes.extend(descriptor(b"table", done_offset, 76 + 24 + 8));
    let mut header = [0_u8; 24];
    header[0..4].copy_from_slice(&1_u32.to_le_bytes());
    header[8..16].copy_from_slice(&sectors_offset.to_le_bytes());
    let checksum = adler32(&header[..20]);
    header[20..24].copy_from_slice(&checksum.to_le_bytes());
    bytes.extend(header);
    let entry =
        (0x8000_0000_u32 | u32::try_from(chunk_offset - sectors_offset).unwrap()).to_le_bytes();
    bytes.extend(entry);
    bytes.extend(adler32(&entry).to_le_bytes());
    bytes.extend(descriptor(b"done", done_offset, 76));

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("overlong.E01");
    std::fs::write(&path, bytes).unwrap();
    let size = usize::try_from(sectors * 512).unwrap();
    (dir, path, data[..size].to_vec())
}

fn descriptor(kind: &[u8], next: u64, size: u64) -> [u8; 76] {
    let mut bytes = [0; 76];
    bytes[..kind.len()].copy_from_slice(kind);
    bytes[16..24].copy_from_slice(&next.to_le_bytes());
    bytes[24..32].copy_from_slice(&size.to_le_bytes());
    let checksum = adler32(&bytes[..72]);
    bytes[72..76].copy_from_slice(&checksum.to_le_bytes());
    bytes
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1_u32, 0_u32);
    for byte in data {
        a = (a + u32::from(*byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

#[test]
fn overlong_final_chunk_keeps_the_media_bytes() {
    let (_dir, path, expected) = overlong_final_chunk_image(56);
    let mut buffer = vec![0; expected.len()];

    let strict = open_strict(&path).unwrap();
    assert!(strict.read_at(&mut buffer, 0).is_err());

    let image = Image::open(&path).unwrap();
    assert_eq!(kinds(&image), Vec::<IntegrityFindingKind>::new());
    assert_eq!(image.read_at(&mut buffer, 0).unwrap(), expected.len());
    assert_eq!(buffer, expected);
    let findings = image.lenient_findings();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].kind, IntegrityFindingKind::OverlongChunk);
    assert_eq!(findings[0].chunk_index, Some(0));
    let md5: [u8; 16] = {
        use md5::Digest as _;
        md5::Md5::digest(&expected).into()
    };
    assert_eq!(image.verify().unwrap().computed_md5, Some(md5));

    // An analysis that reads the chunk first reports it too.
    let image = Image::open(&path).unwrap();
    let report = image.analyze(&VerifyOptions::default()).unwrap();
    assert_eq!(report.media_status, ewf_image::MediaScanStatus::Complete);
    assert_eq!(report.warning_count, 2);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.kind == IntegrityFindingKind::OverlongChunk)
    );
}

fn truncate(path: &Path, length: u64) {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_len(length)
        .unwrap();
}

#[test]
fn truncated_segment_keeps_its_complete_sections_and_decodes_the_rest() {
    let written = e01(WriteCompression::Zlib, 4);
    let sectors = ewf1_section(&sections(&written.path), 0, "sectors");
    truncate(&written.path, sectors.data_offset + sectors.data_size / 2);

    assert!(open_strict(&written.path).is_err());
    let image = Image::open(&written.path).unwrap();
    assert!(!image.info().acquisition_complete);
    assert_eq!(
        kinds(&image),
        [
            IntegrityFindingKind::TruncatedSegment,
            IntegrityFindingKind::UnverifiedChunkTable,
            IntegrityFindingKind::ChunksUnavailable
        ]
    );
    assert_eq!(
        image.lenient_findings()[0].segment_offset,
        Some(sectors.descriptor_offset)
    );
    // The tables followed the sectors section and are lost. The chunks that
    // are complete are found by decoding them in order; the rest fail.
    assert_eq!(image.lenient_findings()[2].chunk_index, Some(2));
    assert_eq!(readable_chunks(&image, &written.data), 2);
}

#[test]
fn truncation_after_the_tables_keeps_every_chunk() {
    let written = e01(WriteCompression::Zlib, 4);
    let digest = ewf1_section(&sections(&written.path), 0, "digest");
    truncate(&written.path, digest.data_offset + 10);

    let image = Image::open(&written.path).unwrap();
    assert_eq!(kinds(&image), [IntegrityFindingKind::TruncatedSegment]);
    assert!(!image.info().acquisition_complete);
    assert_eq!(readable_chunks(&image, &written.data), 4);
}

/// Five segments of two raw chunks each, then one of a single chunk.
fn multi_segment_e01() -> Written {
    write_image(
        "image.E01",
        WriteFormat::Ewf1Physical,
        WriteCompression::None,
        &media(9),
        |options| options.maximum_segment_size = Some(70_000),
    )
}

#[test]
fn segments_after_a_truncated_segment_are_placed_from_the_end() {
    let written = multi_segment_e01();
    let image = Image::open(&written.path).unwrap();
    assert_eq!(image.number_of_segments(), 5);
    let second = image.segment_filename(1).unwrap().to_path_buf();
    let sectors = ewf1_section(image.sections(), 1, "sectors");
    drop(image);
    truncate(&second, sectors.data_offset + 100);

    assert!(open_strict(&written.path).is_err());
    let image = Image::open(&written.path).unwrap();
    assert_eq!(
        kinds(&image),
        [
            IntegrityFindingKind::TruncatedSegment,
            IntegrityFindingKind::ChunksUnavailable
        ]
    );
    let gap = &image.lenient_findings()[1];
    assert_eq!(gap.chunk_index, Some(2));
    assert!(gap.message.contains("chunks 2 to 3"), "{}", gap.message);
    // Segment 2's chunks fail; the segments after it count back from the end.
    assert_eq!(readable_chunks(&image, &written.data), 7);
    assert!(image.info().acquisition_complete);
}

#[test]
fn segments_after_a_damaged_segment_are_not_placed_without_a_complete_end() {
    let written = multi_segment_e01();
    let image = Image::open(&written.path).unwrap();
    let second = image.segment_filename(1).unwrap().to_path_buf();
    let last = image.segment_filename(4).unwrap().to_path_buf();
    let second_sectors = ewf1_section(image.sections(), 1, "sectors");
    let last_digest = ewf1_section(image.sections(), 4, "digest");
    drop(image);
    truncate(&second, second_sectors.data_offset + 100);
    truncate(&last, last_digest.data_offset + 1);

    let image = Image::open(&written.path).unwrap();
    assert!(!image.info().acquisition_complete);
    let findings = image.lenient_findings();
    let unplaced: Vec<_> = findings
        .iter()
        .filter(|finding| {
            finding.kind == IntegrityFindingKind::ChunksUnavailable
                && finding.segment_index.is_some()
        })
        .map(|finding| finding.segment_index.unwrap())
        .collect();
    assert_eq!(unplaced, [2, 3, 4]);
    // Only the first segment's chunks have a known position.
    assert_eq!(readable_chunks(&image, &written.data), 2);
}

fn descriptor_offset(path: &Path, segment: usize, name: &str) -> u64 {
    ewf1_section(&sections(path), segment, name).descriptor_offset
}

#[test]
fn damaged_descriptor_with_consistent_offsets_is_followed() {
    let written = e01(WriteCompression::Zlib, 3);
    // A byte of the descriptor's padding: only the checksum notices.
    flip(
        &written.path,
        descriptor_offset(&written.path, 0, "sectors") + 40,
    );

    assert!(open_strict(&written.path).is_err());
    let image = Image::open(&written.path).unwrap();
    assert_eq!(
        kinds(&image),
        [IntegrityFindingKind::StructureChecksumMismatch]
    );
    assert_eq!(readable_chunks(&image, &written.data), 3);
}

#[test]
fn damaged_descriptor_size_is_derived_from_an_intact_next_descriptor() {
    let written = e01(WriteCompression::Zlib, 3);
    let volume = descriptor_offset(&written.path, 0, "volume");
    modify(&written.path, |bytes| {
        let size = usize::try_from(volume).unwrap() + 24;
        bytes[size..size + 4].copy_from_slice(&[0xff; 4]);
    });

    let image = Image::open(&written.path).unwrap();
    assert_eq!(
        kinds(&image),
        [IntegrityFindingKind::StructureChecksumMismatch]
    );
    assert_eq!(image.sections()[0].data_size, 1052);
    assert_eq!(readable_chunks(&image, &written.data), 3);
}

#[test]
fn damaged_sectors_type_name_still_locates_the_chunks() {
    let written = e01(WriteCompression::Zlib, 3);
    flip(
        &written.path,
        descriptor_offset(&written.path, 0, "sectors") + 1,
    );

    let image = Image::open(&written.path).unwrap();
    assert_eq!(
        kinds(&image),
        [IntegrityFindingKind::StructureChecksumMismatch]
    );
    assert_eq!(readable_chunks(&image, &written.data), 3);
}

#[test]
fn damaged_descriptor_with_inconsistent_offsets_is_skipped_by_finding_the_chain_again() {
    let written = e01(WriteCompression::Zlib, 3);
    let table = descriptor_offset(&written.path, 0, "table");
    let table2 = descriptor_offset(&written.path, 0, "table2");
    damage_next_and_size(&written.path, table);

    let image = Image::open(&written.path).unwrap();
    assert_eq!(
        kinds(&image),
        [
            IntegrityFindingKind::BrokenSectionChain,
            IntegrityFindingKind::BrokenSectionChain
        ]
    );
    assert_eq!(image.lenient_findings()[0].segment_offset, Some(table));
    // The chain continues at table2, whose entries locate the chunks.
    assert_eq!(image.lenient_findings()[1].segment_offset, Some(table2));
    assert_eq!(read_all(&image), written.data);
}

fn damage_next_and_size(path: &Path, descriptor: u64) {
    modify(path, |bytes| {
        let start = usize::try_from(descriptor).unwrap() + 16;
        // Both the next offset and the size, so neither leads anywhere.
        bytes[start..start + 16].copy_from_slice(&[0x7f; 16]);
    });
}

#[test]
fn damaged_sectors_descriptor_is_skipped_and_its_chunks_still_located() {
    let data = media(4);
    let (_dir, path) = Ewf1Build::libewf().write(&data);
    damage_next_and_size(&path, built_section(&path, "sectors").descriptor_offset);

    let image = Image::open(&path).unwrap();
    assert_eq!(
        kinds(&image),
        [
            IntegrityFindingKind::BrokenSectionChain,
            IntegrityFindingKind::BrokenSectionChain
        ]
    );
    assert_eq!(read_all(&image), data);
}

#[test]
fn damaged_volume_descriptor_is_skipped_and_the_data_copy_used() {
    let data = media(4);
    let (_dir, path) = Ewf1Build::libewf().write(&data);
    damage_next_and_size(&path, built_section(&path, "volume").descriptor_offset);

    let image = Image::open(&path).unwrap();
    assert_eq!(
        kinds(&image),
        [
            IntegrityFindingKind::BrokenSectionChain,
            IntegrityFindingKind::BrokenSectionChain
        ]
    );
    assert_eq!(image.media_size(), data.len() as u64);
    assert_eq!(read_all(&image), data);
}

#[test]
fn chain_found_again_must_end_at_the_end_of_the_segment() {
    let data = media(4);
    let (_dir, path) = Ewf1Build {
        table2: false,
        ..Ewf1Build::libewf()
    }
    .write(&data);
    damage_next_and_size(&path, built_section(&path, "table").descriptor_offset);
    // Bytes after the done descriptor: the intact chain after the damaged
    // table no longer ends at the end of the segment, so it is not taken.
    modify(&path, |bytes| bytes.extend([0x55; 100]));

    let image = Image::open(&path).unwrap();
    assert_eq!(
        kinds(&image),
        [
            IntegrityFindingKind::BrokenSectionChain,
            IntegrityFindingKind::UnverifiedChunkTable
        ]
    );
    // The table is lost; the chunks are found by decoding them in order.
    assert_eq!(read_all(&image), data);
}

/// A single EWF1 segment laid out the way the common writers lay it out:
/// volume, sectors, table, table2, a data copy of the volume, and done. Compressed
/// chunks are zlib streams; raw chunks carry their Adler-32.
struct Ewf1Build {
    compressed: bool,
    table2: bool,
    data_copy: bool,
}

impl Ewf1Build {
    const fn libewf() -> Self {
        Self {
            compressed: true,
            table2: true,
            data_copy: true,
        }
    }

    fn write(&self, media: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("built.E01");
        std::fs::write(&path, self.bytes(media)).unwrap();
        (dir, path)
    }

    fn bytes(&self, media: &[u8]) -> Vec<u8> {
        assert_eq!(media.len() % 512, 0);
        let chunks: Vec<Vec<u8>> = media
            .chunks(CHUNK)
            .map(|chunk| {
                if self.compressed {
                    let mut encoder =
                        flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                    encoder.write_all(chunk).unwrap();
                    encoder.finish().unwrap()
                } else {
                    let mut raw = chunk.to_vec();
                    raw.extend(adler32(chunk).to_le_bytes());
                    raw
                }
            })
            .collect();
        let mut volume = vec![0_u8; 1052];
        volume[0] = 1;
        volume[4..8].copy_from_slice(&u32::try_from(chunks.len()).unwrap().to_le_bytes());
        volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
        volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
        volume[16..24].copy_from_slice(&(media.len() as u64 / 512).to_le_bytes());
        volume[64..80].copy_from_slice(&[0x5e; 16]);
        let checksum = adler32(&volume[..1048]);
        volume[1048..].copy_from_slice(&checksum.to_le_bytes());

        let mut bytes = b"EVF\x09\x0d\x0a\xff\x00\x01\x01\x00\x00\x00".to_vec();
        let section = |bytes: &mut Vec<u8>, kind: &[u8], payload: &[u8]| {
            let offset = bytes.len() as u64;
            let size = 76 + payload.len() as u64;
            bytes.extend(descriptor(kind, offset + size, size));
            bytes.extend(payload);
        };
        section(&mut bytes, b"volume", &volume);
        let sectors_offset = bytes.len() as u64;
        let mut sectors = Vec::new();
        let mut entries = Vec::new();
        for chunk in &chunks {
            let relative = u32::try_from(76 + sectors.len()).unwrap();
            entries
                .extend((relative | if self.compressed { 0x8000_0000 } else { 0 }).to_le_bytes());
            sectors.extend(chunk);
        }
        section(&mut bytes, b"sectors", &sectors);
        let mut table = vec![0_u8; 24];
        table[0..4].copy_from_slice(&u32::try_from(chunks.len()).unwrap().to_le_bytes());
        table[8..16].copy_from_slice(&sectors_offset.to_le_bytes());
        let checksum = adler32(&table[..20]);
        table[20..24].copy_from_slice(&checksum.to_le_bytes());
        table.extend(&entries);
        table.extend(adler32(&entries).to_le_bytes());
        section(&mut bytes, b"table", &table);
        if self.table2 {
            section(&mut bytes, b"table2", &table);
        }
        if self.data_copy {
            section(&mut bytes, b"data", &volume);
        }
        let done = bytes.len() as u64;
        bytes.extend(descriptor(b"done", done, 76));
        bytes
    }
}

fn built_section(path: &Path, name: &str) -> SectionInfo {
    ewf1_section(&sections(path), 0, name)
}

fn read_all(image: &Image) -> Vec<u8> {
    let mut buffer = vec![0; usize::try_from(image.media_size()).unwrap()];
    assert_eq!(image.read_at(&mut buffer, 0).unwrap(), buffer.len());
    buffer
}

#[test]
fn damaged_volume_uses_the_intact_data_copy() {
    let data = media(3);
    let (_dir, path) = Ewf1Build::libewf().write(&data);
    let volume = built_section(&path, "volume");
    // The sector count: the damaged copy would make the media shorter.
    flip(&path, volume.data_offset + 16);

    assert!(open_strict(&path).is_err());
    let image = Image::open(&path).unwrap();
    assert_eq!(
        kinds(&image),
        [IntegrityFindingKind::StructureChecksumMismatch]
    );
    assert!(image.lenient_findings()[0].message.contains("data section"));
    assert_eq!(image.media_size(), data.len() as u64);
    assert_eq!(image.segment_file_set_identifier(), Some([0x5e; 16]));
    assert_eq!(read_all(&image), data);
}

#[test]
fn damaged_volume_without_a_copy_is_checked_against_the_tables() {
    let written = e01(WriteCompression::Zlib, 3);
    let volume = ewf1_section(&sections(&written.path), 0, "volume");
    // A byte outside the geometry fields.
    flip(&written.path, volume.data_offset + 300);

    let image = Image::open(&written.path).unwrap();
    assert_eq!(
        kinds(&image),
        [IntegrityFindingKind::StructureChecksumMismatch]
    );
    // Values the image cannot confirm are not reported.
    assert_eq!(image.media_type(), None);
    assert_eq!(read_all(&image), written.data);
}

#[test]
fn damaged_volume_geometry_without_a_copy_is_refused() {
    let written = e01(WriteCompression::Zlib, 3);
    let volume = ewf1_section(&sections(&written.path), 0, "volume");
    // The lowest bit of the sector count: the chunk count still agrees, but
    // the media would no longer fill its last chunk.
    flip(&written.path, volume.data_offset + 16);

    let error = Image::open(&written.path).unwrap_err();
    assert!(
        error.to_string().contains("EWF1 volume checksum mismatch"),
        "{error}"
    );
}

#[test]
fn damaged_media_copy_in_a_continuation_segment_is_ignored() {
    let written = multi_segment_e01();
    let image = Image::open(&written.path).unwrap();
    let third = image.segment_filename(2).unwrap().to_path_buf();
    let volume = ewf1_section(image.sections(), 2, "volume");
    drop(image);
    flip(&third, volume.data_offset + 4);

    let image = Image::open(&written.path).unwrap();
    assert_eq!(
        kinds(&image),
        [IntegrityFindingKind::StructureChecksumMismatch]
    );
    assert_eq!(image.lenient_findings()[0].segment_index, Some(2));
    assert_eq!(read_all(&image), written.data);
}

#[test]
fn damaged_first_volume_is_confirmed_by_a_later_copy() {
    // The media does not fill its last chunk, so only an intact copy can
    // confirm the sector count.
    let mut data = media(9);
    data.truncate(data.len() - 4096);
    let written = write_image(
        "image.E01",
        WriteFormat::Ewf1Physical,
        WriteCompression::None,
        &data,
        |options| options.maximum_segment_size = Some(70_000),
    );
    let volume = ewf1_section(&sections(&written.path), 0, "volume");
    flip(&written.path, volume.data_offset + 500);

    let image = Image::open(&written.path).unwrap();
    assert_eq!(
        kinds(&image),
        [IntegrityFindingKind::StructureChecksumMismatch]
    );
    assert_eq!(read_all(&image), data);
}

/// Byte offset of EWF1 table entry `index` in a built image's `name` section.
fn ewf1_entry(path: &Path, name: &str, index: u64) -> u64 {
    built_section(path, name).data_offset + 24 + 4 * index
}

fn set_u32(path: &Path, offset: u64, value: u32) {
    modify(path, |bytes| {
        let start = usize::try_from(offset).unwrap();
        bytes[start..start + 4].copy_from_slice(&value.to_le_bytes());
    });
}

fn get_u32(path: &Path, offset: u64) -> u32 {
    let bytes = std::fs::read(path).unwrap();
    let start = usize::try_from(offset).unwrap();
    u32::from_le_bytes(bytes[start..start + 4].try_into().unwrap())
}

#[test]
fn damaged_table_entries_use_the_intact_table2() {
    let data = media(4);
    let (_dir, path) = Ewf1Build::libewf().write(&data);
    flip(&path, ewf1_entry(&path, "table", 2));

    assert!(open_strict(&path).is_err());
    let image = Image::open(&path).unwrap();
    assert_eq!(
        kinds(&image),
        [IntegrityFindingKind::StructureChecksumMismatch]
    );
    assert!(image.lenient_findings()[0].message.contains("table2"));
    assert_eq!(read_all(&image), data);
}

#[test]
fn damaged_table_header_uses_the_matching_table2() {
    let data = media(4);
    let (_dir, path) = Ewf1Build::libewf().write(&data);
    // The entry count.
    flip(&path, built_section(&path, "table").data_offset);

    assert!(open_strict(&path).is_err());
    let image = Image::open(&path).unwrap();
    assert_eq!(
        kinds(&image),
        [IntegrityFindingKind::StructureChecksumMismatch]
    );
    assert_eq!(read_all(&image), data);
}

#[test]
fn damaged_table_header_without_a_copy_locates_the_chunks_by_decoding() {
    let data = media(4);
    let (_dir, path) = Ewf1Build {
        table2: false,
        ..Ewf1Build::libewf()
    }
    .write(&data);
    flip(&path, built_section(&path, "table").data_offset);

    let image = Image::open(&path).unwrap();
    assert_eq!(
        kinds(&image),
        [
            IntegrityFindingKind::StructureChecksumMismatch,
            IntegrityFindingKind::UnverifiedChunkTable
        ]
    );
    assert_eq!(read_all(&image), data);
}

#[test]
fn unverified_table_returns_only_chunks_that_verify_themselves() {
    let data = media(6);
    let (_dir, path) = Ewf1Build {
        table2: false,
        ..Ewf1Build::libewf()
    }
    .write(&data);
    // Entry 1 now starts one byte late, so chunks 0 and 1 no longer fill
    // their stored bytes with one zlib stream. Entry 4 repeats entry 5, so
    // chunk 3's bytes now run on into chunk 4's stream.
    let entry1 = ewf1_entry(&path, "table", 1);
    set_u32(&path, entry1, get_u32(&path, entry1) + 1);
    let entry5 = get_u32(&path, ewf1_entry(&path, "table", 5));
    set_u32(&path, ewf1_entry(&path, "table", 4), entry5);

    assert!(open_strict(&path).is_err());
    let image = Image::open(&path).unwrap();
    assert_eq!(kinds(&image), [IntegrityFindingKind::UnverifiedChunkTable]);
    // Chunks 2 and 5 still verify themselves.
    assert_eq!(readable_chunks(&image, &data), 2);
    let mut chunk = vec![0; CHUNK];
    assert!(image.read_at(&mut chunk, 2 * CHUNK as u64).is_ok());
    assert!(image.read_at(&mut chunk, 5 * CHUNK as u64).is_ok());
    assert!(image.read_encoded_data_chunk(1).is_err());
    assert!(image.read_encoded_data_chunk(2).is_ok());
}

#[test]
fn unverified_table_returns_raw_chunks_only_with_their_checksum() {
    let data = media(4);
    let (_dir, path) = Ewf1Build {
        compressed: false,
        table2: false,
        data_copy: true,
    }
    .write(&data);
    // Chunk 0 grows by 4 bytes and chunk 1 loses its checksum.
    let entry1 = ewf1_entry(&path, "table", 1);
    set_u32(&path, entry1, get_u32(&path, entry1) + 4);

    let image = Image::open(&path).unwrap();
    assert_eq!(kinds(&image), [IntegrityFindingKind::UnverifiedChunkTable]);
    assert_eq!(readable_chunks(&image, &data), 2);
}

/// Byte offset of EWF2 table entry `index` in an image written by this crate.
fn ewf2_entry(path: &Path, index: u64) -> u64 {
    ewf2_section(&sections(path), 0x04).data_offset + 32 + 16 * index
}

#[test]
fn unverified_ewf2_table_returns_only_chunks_that_verify_themselves() {
    let written = ex01(4);
    // Chunk 1's stored size.
    flip(&written.path, ewf2_entry(&written.path, 1) + 8);

    assert!(open_strict(&written.path).is_err());
    let image = Image::open(&written.path).unwrap();
    assert_eq!(kinds(&image), [IntegrityFindingKind::UnverifiedChunkTable]);
    assert_eq!(readable_chunks(&image, &written.data), 3);
}

#[test]
fn unverified_ewf2_entries_pointing_at_another_chunk_fail() {
    // Compressed chunks, then raw chunks with checksums: either kind of chunk
    // verifies itself, so only the overlap shows that entry 1 is wrong.
    for data in [media(4), noise(4)] {
        let written = ex01_of(&data);
        let entry1 = ewf2_entry(&written.path, 1);
        let entry2 = ewf2_entry(&written.path, 2);
        // Entry 1 becomes a copy of entry 2: chunk 1 would read as chunk 2.
        modify(&written.path, |bytes| {
            let (from, to) = (
                usize::try_from(entry2).unwrap(),
                usize::try_from(entry1).unwrap(),
            );
            let copy = bytes[from..from + 16].to_vec();
            bytes[to..to + 16].copy_from_slice(&copy);
        });

        let image = Image::open(&written.path).unwrap();
        assert_eq!(kinds(&image), [IntegrityFindingKind::UnverifiedChunkTable]);
        assert_eq!(readable_chunks(&image, &written.data), 2);
    }
}

#[test]
fn damaged_ewf2_table_header_is_used_when_its_entries_confirm_it() {
    let written = ex01(4);
    let table = ewf2_section(&sections(&written.path), 0x04);
    // The header checksum itself.
    flip(&written.path, table.data_offset + 16);

    assert!(open_strict(&written.path).is_err());
    let image = Image::open(&written.path).unwrap();
    assert_eq!(
        kinds(&image),
        [IntegrityFindingKind::StructureChecksumMismatch]
    );
    assert_eq!(read_all(&image), written.data);
}

#[test]
fn damaged_ewf2_table_header_with_a_wrong_count_is_not_used() {
    let written = ex01(4);
    let table = ewf2_section(&sections(&written.path), 0x04);
    // The entry count.
    flip(&written.path, table.data_offset + 8);

    let image = Image::open(&written.path).unwrap();
    assert_eq!(
        kinds(&image),
        [
            IntegrityFindingKind::StructureChecksumMismatch,
            IntegrityFindingKind::ChunksUnavailable
        ]
    );
    assert_eq!(readable_chunks(&image, &written.data), 0);
}

#[test]
fn corruption_probes_report_damage_that_lenient_opening_goes_past() {
    let written = e01(WriteCompression::Zlib, 3);
    assert!(!ewf_image::check_file_corruption(&written.path).unwrap());
    flip(
        &written.path,
        descriptor_offset(&written.path, 0, "sectors") + 40,
    );

    assert!(Image::open(&written.path).is_ok());
    assert!(ewf_image::check_file_corruption(&written.path).unwrap());
    assert!(ewf_image::check_segment_files_corruption([&written.path]).unwrap());
}

#[test]
fn truncated_ewf2_segment_keeps_the_complete_entries_of_its_last_table() {
    let written = ex01(8);
    let table = ewf2_section(&sections(&written.path), 0x04);
    // Five complete entries and three bytes of the sixth remain.
    truncate(&written.path, table.data_offset + 32 + 16 * 5 + 3);

    assert!(open_strict(&written.path).is_err());
    let image = Image::open(&written.path).unwrap();
    assert!(!image.info().acquisition_complete);
    assert_eq!(
        kinds(&image),
        [
            IntegrityFindingKind::TruncatedSegment,
            IntegrityFindingKind::BrokenSectionChain,
            IntegrityFindingKind::UnverifiedChunkTable,
            IntegrityFindingKind::ChunksUnavailable
        ]
    );
    assert_eq!(readable_chunks(&image, &written.data), 5);
}

#[test]
fn truncation_after_the_ewf2_table_keeps_every_chunk() {
    let written = ex01(4);
    let md5 = ewf2_section(&sections(&written.path), 0x08);
    truncate(&written.path, md5.data_offset + 7);

    let image = Image::open(&written.path).unwrap();
    assert!(!image.info().acquisition_complete);
    assert_eq!(
        kinds(&image),
        [
            IntegrityFindingKind::TruncatedSegment,
            IntegrityFindingKind::BrokenSectionChain
        ]
    );
    assert_eq!(read_all(&image), written.data);
}

#[test]
fn truncation_in_ewf2_sector_data_leaves_the_chunks_unavailable() {
    let written = ex01(4);
    let data = ewf2_section(&sections(&written.path), 0x03);
    truncate(&written.path, data.data_offset + data.data_size / 2);

    let image = Image::open(&written.path).unwrap();
    assert_eq!(
        kinds(&image),
        [
            IntegrityFindingKind::TruncatedSegment,
            IntegrityFindingKind::BrokenSectionChain,
            IntegrityFindingKind::ChunksUnavailable
        ]
    );
    assert_eq!(readable_chunks(&image, &written.data), 0);
}

#[test]
fn damaged_ewf2_descriptor_with_consistent_sizes_is_followed() {
    let written = ex01(4);
    let data = ewf2_section(&sections(&written.path), 0x03);
    // A padding byte of the sector data descriptor.
    flip(&written.path, data.descriptor_offset + 50);

    assert!(open_strict(&written.path).is_err());
    let image = Image::open(&written.path).unwrap();
    assert_eq!(
        kinds(&image),
        [IntegrityFindingKind::StructureChecksumMismatch]
    );
    assert_eq!(read_all(&image), written.data);
}

#[test]
fn damaged_ewf2_descriptor_is_skipped_by_finding_the_chain_again() {
    let written = ex01(4);
    let md5 = ewf2_section(&sections(&written.path), 0x08);
    // The MD5 descriptor's link to the table descriptor.
    flip(&written.path, md5.descriptor_offset + 9);

    let image = Image::open(&written.path).unwrap();
    assert_eq!(
        kinds(&image),
        [
            IntegrityFindingKind::BrokenSectionChain,
            IntegrityFindingKind::BrokenSectionChain
        ]
    );
    assert!(image.md5_hash().is_none());
    assert!(image.sha1_hash().is_some());
    assert!(image.info().acquisition_complete);
    assert_eq!(read_all(&image), written.data);
}

#[test]
fn truncated_raw_chunks_are_located_by_their_checksums() {
    let data = media(5);
    let (_dir, path) = Ewf1Build {
        compressed: false,
        table2: true,
        data_copy: true,
    }
    .write(&data);
    let sectors = built_section(&path, "sectors");
    // Two and a half stored chunks remain.
    truncate(&path, sectors.data_offset + 5 * (CHUNK as u64 + 4) / 2);

    let image = Image::open(&path).unwrap();
    assert_eq!(
        kinds(&image),
        [
            IntegrityFindingKind::TruncatedSegment,
            IntegrityFindingKind::UnverifiedChunkTable,
            IntegrityFindingKind::ChunksUnavailable
        ]
    );
    assert_eq!(readable_chunks(&image, &data), 2);
}

#[test]
fn locating_chunks_by_decoding_stops_at_a_damaged_chunk() {
    let data = media(5);
    let (_dir, path) = Ewf1Build {
        table2: false,
        ..Ewf1Build::libewf()
    }
    .write(&data);
    let table = built_section(&path, "table");
    let second_chunk = u64::from(get_u32(&path, ewf1_entry(&path, "table", 1)) & 0x7fff_ffff);
    let sectors = built_section(&path, "sectors");
    // Lose the table, and damage chunk 1: where chunk 2 starts is then unknown.
    flip(&path, table.data_offset);
    flip(&path, sectors.descriptor_offset + second_chunk + 10);

    let image = Image::open(&path).unwrap();
    assert_eq!(readable_chunks(&image, &data), 1);
    let gap = image
        .lenient_findings()
        .into_iter()
        .find(|finding| finding.kind == IntegrityFindingKind::ChunksUnavailable)
        .unwrap();
    assert_eq!(gap.chunk_index, Some(1));
}

#[test]
fn truncated_middle_segment_keeps_its_complete_chunks() {
    let written = write_image(
        "image.E01",
        WriteFormat::Ewf1Physical,
        WriteCompression::Zlib,
        &media(24),
        |options| options.maximum_segment_size = Some(12_000),
    );
    let image = Image::open(&written.path).unwrap();
    assert!(image.number_of_segments() >= 3);
    let second = image.segment_filename(1).unwrap().to_path_buf();
    let in_second: Vec<u64> = (0..24)
        .filter(|chunk| image.segment_filename_for_chunk(*chunk).unwrap() == second)
        .collect();
    assert!(in_second.len() >= 2, "{in_second:?}");
    let sectors = ewf1_section(image.sections(), 1, "sectors");
    drop(image);
    truncate(&second, sectors.data_offset + sectors.data_size - 10);

    let image = Image::open(&written.path).unwrap();
    // Every chunk of the other segments, and all but the last chunk of the
    // truncated segment, are readable; the last one fails.
    assert_eq!(readable_chunks(&image, &written.data), 23);
    let mut chunk = vec![0; CHUNK];
    let last = *in_second.last().unwrap();
    assert!(image.read_at(&mut chunk, last * CHUNK as u64).is_err());
}

/// A single EWF2 segment with trailing descriptors: device information
/// (`device_info` as UTF-16 text), sector data of zlib chunks, a sector table
/// and done.
fn build_ex01(media: &[u8], device_info: &str) -> (tempfile::TempDir, PathBuf) {
    fn ewf2_descriptor(kind: u32, data_size: u64, previous: u64) -> [u8; 64] {
        let mut bytes = [0_u8; 64];
        bytes[0..4].copy_from_slice(&kind.to_le_bytes());
        bytes[8..16].copy_from_slice(&previous.to_le_bytes());
        bytes[16..24].copy_from_slice(&data_size.to_le_bytes());
        bytes[24..28].copy_from_slice(&64_u32.to_le_bytes());
        let checksum = adler32(&bytes[..60]);
        bytes[60..64].copy_from_slice(&checksum.to_le_bytes());
        bytes
    }
    let mut bytes = b"EVF2\x0d\x0a\x81\x00\x02\x01\x01\x00\x01\x00\x00\x00".to_vec();
    bytes.extend([0x3c; 16]);
    let section = |bytes: &mut Vec<u8>, kind: u32, data: &[u8], previous: &mut u64| {
        bytes.extend(data);
        let offset = bytes.len() as u64;
        bytes.extend(ewf2_descriptor(kind, data.len() as u64, *previous));
        *previous = offset;
    };
    let mut previous = 0;
    let text: Vec<u8> = device_info
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    section(&mut bytes, 0x01, &text, &mut previous);
    let sector_data_start = bytes.len() as u64;
    let mut sector_data = Vec::new();
    let mut entries = Vec::new();
    for chunk in media.chunks(CHUNK) {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(chunk).unwrap();
        let stream = encoder.finish().unwrap();
        entries.extend((sector_data_start + sector_data.len() as u64).to_le_bytes());
        entries.extend(u32::try_from(stream.len()).unwrap().to_le_bytes());
        entries.extend(1_u32.to_le_bytes());
        sector_data.extend(stream);
    }
    section(&mut bytes, 0x03, &sector_data, &mut previous);
    let mut table = vec![0_u8; 32];
    table[8..12].copy_from_slice(
        &u32::try_from(media.len().div_ceil(CHUNK))
            .unwrap()
            .to_le_bytes(),
    );
    let checksum = adler32(&table[..16]);
    table[16..20].copy_from_slice(&checksum.to_le_bytes());
    table.extend(&entries);
    let mut footer = [0_u8; 16];
    footer[..4].copy_from_slice(&adler32(&entries).to_le_bytes());
    table.extend(footer);
    section(&mut bytes, 0x04, &table, &mut previous);
    section(&mut bytes, 0x0f, &[], &mut previous);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("built.Ex01");
    std::fs::write(&path, bytes).unwrap();
    (dir, path)
}

#[test]
fn media_size_taken_from_damaged_tables_is_reported() {
    let data = media(3);
    // No total sector count in the device information.
    let (_dir, path) = build_ex01(&data, "1\nmain\nbp\tsb\n512\t64\n\n");
    assert_eq!(Image::open(&path).unwrap().media_size(), data.len() as u64);
    let table = ewf2_section(&sections(&path), 0x04);
    // One complete entry remains.
    truncate(&path, table.data_offset + 32 + 16 + 5);

    let image = Image::open(&path).unwrap();
    assert_eq!(image.media_size(), CHUNK as u64);
    let size = image
        .lenient_findings()
        .into_iter()
        .find(|finding| finding.message.contains("media may be larger"))
        .unwrap();
    assert_eq!(size.kind, IntegrityFindingKind::ChunksUnavailable);
    assert_eq!(readable_chunks(&image, &data[..CHUNK]), 1);
}

#[test]
fn media_size_recorded_in_the_metadata_survives_a_lost_table() {
    let data = media(3);
    let (_dir, path) = build_ex01(&data, "1\nmain\nbp\tsb\tts\n512\t64\t192\n\n");
    let table = ewf2_section(&sections(&path), 0x04);
    truncate(&path, table.data_offset + 32 + 16 + 5);

    let image = Image::open(&path).unwrap();
    assert_eq!(image.media_size(), data.len() as u64);
    assert_eq!(readable_chunks(&image, &data), 1);
}

#[test]
fn damaged_segment_number_is_accepted_where_it_orders_nothing() {
    let e01 = e01(WriteCompression::Zlib, 2);
    let ex01 = ex01(2);
    // The EWF1 segment number is at byte 9, the EWF2 one at byte 12.
    flip(&e01.path, 10);
    flip(&ex01.path, 14);

    for written in [&e01, &ex01] {
        assert!(open_strict(&written.path).is_err());
        let image = Image::open(&written.path).unwrap();
        let findings = image.lenient_findings();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, IntegrityFindingKind::LenientOpen);
        assert_eq!(findings[0].severity, ewf_image::IntegritySeverity::Error);
        assert_eq!(read_all(&image), written.data);
    }
}

#[test]
fn damaged_segment_number_still_fails_a_multi_segment_ewf1_image() {
    let written = multi_segment_e01();
    let third = Image::open(&written.path)
        .unwrap()
        .segment_filename(2)
        .unwrap()
        .to_path_buf();
    flip(&third, 10);

    let error = Image::open(&written.path).unwrap_err();
    assert!(error.to_string().contains("segment number"), "{error}");
}

#[test]
fn resuming_a_writer_does_not_go_past_damage() {
    let written = e01(WriteCompression::Zlib, 2);
    let digest = ewf1_section(&sections(&written.path), 0, "digest");
    flip(&written.path, digest.data_offset + 3);

    // Lenient opening would drop the digest; resuming rewrites the image, so
    // it refuses instead.
    assert!(Image::open(&written.path).is_ok());
    assert!(EwfWriter::resume(&written.path).is_err());
}

#[test]
fn damaged_descriptor_next_offset_is_derived_from_its_size() {
    let written = e01(WriteCompression::Zlib, 3);
    let volume = descriptor_offset(&written.path, 0, "volume");
    modify(&written.path, |bytes| {
        let next = usize::try_from(volume).unwrap() + 16;
        bytes[next..next + 4].copy_from_slice(&[0; 4]);
    });

    let image = Image::open(&written.path).unwrap();
    assert_eq!(
        kinds(&image),
        [IntegrityFindingKind::StructureChecksumMismatch]
    );
    assert_eq!(read_all(&image), written.data);
}

#[test]
fn segment_ending_inside_a_descriptor_keeps_the_sections_before_it() {
    let written = e01(WriteCompression::Zlib, 3);
    let digest = descriptor_offset(&written.path, 0, "digest");
    truncate(&written.path, digest + 30);

    let image = Image::open(&written.path).unwrap();
    assert_eq!(kinds(&image), [IntegrityFindingKind::TruncatedSegment]);
    assert_eq!(image.lenient_findings()[0].segment_offset, Some(digest));
    assert_eq!(read_all(&image), written.data);
}

#[test]
fn analysis_of_a_damaged_image_reports_its_defects_and_unreadable_chunks() {
    let written = e01(WriteCompression::Zlib, 4);
    let sectors = ewf1_section(&sections(&written.path), 0, "sectors");
    truncate(&written.path, sectors.data_offset + sectors.data_size / 2);

    let report = ewf_image::analyze_path(&written.path, &VerifyOptions::default()).unwrap();
    assert_eq!(report.media_status, ewf_image::MediaScanStatus::Incomplete);
    assert_eq!(report.bytes_verified, 2 * CHUNK as u64);
    let found: Vec<_> = report
        .findings
        .iter()
        .map(|finding| &finding.kind)
        .collect();
    assert_eq!(found[0], &IntegrityFindingKind::TruncatedSegment);
    assert_eq!(
        found
            .iter()
            .filter(|kind| ***kind == IntegrityFindingKind::ChunkUnreadable)
            .count(),
        2
    );
}

/// A single EWF2 segment whose descriptors precede their data.
fn build_ex01_leading(media: &[u8]) -> (tempfile::TempDir, PathBuf, Vec<u64>) {
    fn descriptor(kind: u32, data_size: u64, previous: u64) -> [u8; 64] {
        let mut bytes = [0_u8; 64];
        bytes[0..4].copy_from_slice(&kind.to_le_bytes());
        bytes[8..16].copy_from_slice(&previous.to_le_bytes());
        bytes[16..24].copy_from_slice(&data_size.to_le_bytes());
        bytes[24..28].copy_from_slice(&64_u32.to_le_bytes());
        let checksum = adler32(&bytes[..60]);
        bytes[60..64].copy_from_slice(&checksum.to_le_bytes());
        bytes
    }
    let mut bytes = b"EVF2\x0d\x0a\x81\x00\x02\x01\x01\x00\x01\x00\x00\x00".to_vec();
    bytes.extend([0x3c; 16]);
    let mut offsets = Vec::new();
    let mut previous = 0;
    let mut section = |bytes: &mut Vec<u8>, kind: u32, data: &[u8]| {
        let offset = bytes.len() as u64;
        offsets.push(offset);
        bytes.extend(descriptor(kind, data.len() as u64, previous));
        bytes.extend(data);
        previous = offset;
        bytes.len() as u64
    };
    let text: Vec<u8> = "1\nmain\nbp\tsb\tts\n512\t64\t192\n\n"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let sector_data_start = section(&mut bytes, 0x01, &text) + 64;
    let mut sector_data = Vec::new();
    let mut entries = Vec::new();
    for chunk in media.chunks(CHUNK) {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(chunk).unwrap();
        let stream = encoder.finish().unwrap();
        entries.extend((sector_data_start + sector_data.len() as u64).to_le_bytes());
        entries.extend(u32::try_from(stream.len()).unwrap().to_le_bytes());
        entries.extend(1_u32.to_le_bytes());
        sector_data.extend(stream);
    }
    section(&mut bytes, 0x03, &sector_data);
    let mut table = vec![0_u8; 32];
    table[8..12].copy_from_slice(
        &u32::try_from(media.len().div_ceil(CHUNK))
            .unwrap()
            .to_le_bytes(),
    );
    let checksum = adler32(&table[..16]);
    table[16..20].copy_from_slice(&checksum.to_le_bytes());
    table.extend(&entries);
    let mut footer = [0_u8; 16];
    footer[..4].copy_from_slice(&adler32(&entries).to_le_bytes());
    table.extend(footer);
    section(&mut bytes, 0x04, &table);
    section(&mut bytes, 0x0f, &[]);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("leading.Ex01");
    std::fs::write(&path, bytes).unwrap();
    (dir, path, offsets)
}

#[test]
fn damaged_leading_ewf2_descriptor_is_followed_when_it_leads_to_an_intact_one() {
    let data = media(3);
    let (_dir, path, descriptors) = build_ex01_leading(&data);
    assert_eq!(read_all(&Image::open(&path).unwrap()), data);
    // A padding byte of the sector data descriptor.
    flip(&path, descriptors[1] + 50);

    assert!(open_strict(&path).is_err());
    let image = Image::open(&path).unwrap();
    assert_eq!(
        kinds(&image),
        [IntegrityFindingKind::StructureChecksumMismatch]
    );
    assert_eq!(read_all(&image), data);
}

#[test]
fn damaged_leading_ewf2_descriptor_with_a_wrong_size_ends_the_chain() {
    let data = media(3);
    let (_dir, path, descriptors) = build_ex01_leading(&data);
    // The sector data size: the next descriptor is no longer where it points.
    flip(&path, descriptors[1] + 17);

    let image = Image::open(&path).unwrap();
    assert_eq!(
        kinds(&image),
        [
            IntegrityFindingKind::BrokenSectionChain,
            IntegrityFindingKind::ChunksUnavailable
        ]
    );
    assert_eq!(image.media_size(), data.len() as u64);
    assert_eq!(readable_chunks(&image, &data), 0);
}

#[test]
fn damaged_compression_marker_of_a_repaired_descriptor_is_not_used() {
    let written = write_image(
        "image.E01",
        WriteFormat::Ewf1Physical,
        WriteCompression::Zlib,
        &media(2),
        |options| {
            options
                .metadata
                .header_values
                .insert("case_number".into(), "case-17".into());
        },
    );
    let header = descriptor_offset(&written.path, 0, "header");
    modify(&written.path, |bytes| {
        let marker = usize::try_from(header).unwrap() + 32;
        bytes[marker..marker + 4].copy_from_slice(&[0xff; 4]);
    });

    let image = Image::open(&written.path).unwrap();
    assert_eq!(
        kinds(&image),
        [IntegrityFindingKind::StructureChecksumMismatch]
    );
    assert_eq!(
        image.header_value("case_number").as_deref(),
        Some("case-17")
    );
    assert_eq!(read_all(&image), written.data);
}

#[test]
fn damaged_volume_without_a_copy_is_confirmed_by_a_partial_final_chunk() {
    for compression in [WriteCompression::Zlib, WriteCompression::None] {
        let mut data = media(3);
        data.truncate(data.len() - 4096);
        let written = write_image(
            "image.E01",
            WriteFormat::Ewf1Physical,
            compression,
            &data,
            |_| {},
        );
        let volume = ewf1_section(&sections(&written.path), 0, "volume");
        flip(&written.path, volume.data_offset + 300);
        assert_eq!(read_all(&Image::open(&written.path).unwrap()), data);

        // The sector count's lowest bit: the final chunk no longer matches.
        flip(&written.path, volume.data_offset + 16);
        let error = Image::open(&written.path).unwrap_err();
        assert!(error.to_string().contains("final chunk"), "{error}");
    }
}

#[test]
fn damaged_ewf2_file_header_of_a_later_segment_is_read_like_the_first() {
    let written = write_image(
        "image.Ex01",
        WriteFormat::Ewf2Physical,
        WriteCompression::Zlib,
        &media(8),
        |options| options.maximum_segment_size = Some(4_000),
    );
    let image = Image::open(&written.path).unwrap();
    assert!(image.number_of_segments() >= 2);
    let second = image.segment_filename(1).unwrap().to_path_buf();
    drop(image);
    // The compression method in the second segment's file header.
    modify(&second, |bytes| bytes[10] = 2);

    assert!(open_strict(&written.path).is_err());
    let image = Image::open(&written.path).unwrap();
    let findings = image.lenient_findings();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].kind, IntegrityFindingKind::LenientOpen);
    assert_eq!(findings[0].segment_index, Some(1));
    assert_eq!(read_all(&image), written.data);
}

#[test]
fn damaged_section_name_close_to_one_known_name_is_restored() {
    let written = e01(WriteCompression::Zlib, 3);
    let volume = descriptor_offset(&written.path, 0, "volume");
    // "volume" becomes "voluMe".
    modify(&written.path, |bytes| {
        bytes[usize::try_from(volume).unwrap() + 4] ^= 0x20;
    });

    let image = Image::open(&written.path).unwrap();
    assert_eq!(
        kinds(&image),
        [IntegrityFindingKind::StructureChecksumMismatch]
    );
    assert_eq!(image.sections()[0].kind, SectionKind::Ewf1("volume".into()));
    assert_eq!(read_all(&image), written.data);
}

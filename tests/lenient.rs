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

/// Media whose chunks all differ, so a chunk read from the wrong place shows.
fn media(chunks: usize) -> Vec<u8> {
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
    write_image(
        "image.Ex01",
        WriteFormat::Ewf2Physical,
        WriteCompression::Zlib,
        &media(chunks),
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
fn truncated_segment_keeps_its_complete_sections() {
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
            IntegrityFindingKind::ChunksUnavailable
        ]
    );
    assert_eq!(
        image.lenient_findings()[0].segment_offset,
        Some(sectors.descriptor_offset)
    );
    assert_eq!(image.lenient_findings()[1].chunk_index, Some(0));
    // The tables followed the sectors section, so no chunk can be located.
    assert_eq!(readable_chunks(&image, &written.data), 0);
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
fn damaged_descriptor_with_inconsistent_offsets_stops_the_segment() {
    let written = e01(WriteCompression::Zlib, 3);
    let table = descriptor_offset(&written.path, 0, "table");
    modify(&written.path, |bytes| {
        let start = usize::try_from(table).unwrap() + 16;
        // Both the next offset and the size, so neither leads anywhere.
        bytes[start..start + 16].copy_from_slice(&[0x7f; 16]);
    });

    let image = Image::open(&written.path).unwrap();
    assert_eq!(
        kinds(&image),
        [
            IntegrityFindingKind::BrokenSectionChain,
            IntegrityFindingKind::ChunksUnavailable
        ]
    );
    assert_eq!(image.lenient_findings()[0].segment_offset, Some(table));
    assert_eq!(readable_chunks(&image, &written.data), 0);
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

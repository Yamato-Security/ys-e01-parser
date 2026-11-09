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

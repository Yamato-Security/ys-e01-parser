//! Lenient opening of damaged images: every chunk that can still be verified is
//! readable, every defect is reported, and no read returns wrong bytes.
#![cfg(feature = "verify")]

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

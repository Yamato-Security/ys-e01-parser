//! Reader integration tests.

use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::thread;

use bzip2::write::BzEncoder;
use flate2::write::ZlibEncoder;
use md5::{Digest, Md5};
use tempfile::NamedTempFile;

#[cfg(feature = "verify")]
use sha1::Sha1;

const EVF_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];
const LVF_SIGNATURE: [u8; 8] = [0x4c, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];
const EX01_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00];
const LEF2_SIGNATURE: [u8; 8] = [0x4c, 0x45, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00];
// A valid frame produced with `zstd --long=27`. It expands to 184,320 bytes but
// declares a 128 MiB window, which must be rejected before that window is allocated.
const ZSTD_128_MIB_WINDOW_FRAME: [u8; 80] = [
    0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x88, 0xbc, 0x01, 0x00, 0xd4, 0x02, 0x54, 0x68, 0x65, 0x20, 0x71,
    0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20, 0x66, 0x6f, 0x78, 0x20, 0x6a,
    0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6c, 0x61,
    0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67, 0x2e, 0x0a, 0x01, 0x00, 0x85, 0xfe, 0x87, 0xb9, 0x2a, 0x03,
    0x4d, 0x00, 0x00, 0x08, 0x68, 0x01, 0x00, 0xfc, 0x4f, 0x1d, 0x08, 0x01, 0xba, 0xb8, 0xd5, 0xc8,
];

#[derive(Clone, Copy)]
struct Ewf1BytesOptions<'a> {
    signature: [u8; 8],
    segment_number: u16,
    total_chunks: u32,
    total_sectors: u64,
    is_compressed: bool,
    compression_level: u8,
    digest: Option<&'a [u8]>,
    media_section_type: &'a [u8],
}

/// Opens with strict structural validation. The default is lenient, so tests of
/// strict rejection use this.
fn open_strict(path: impl AsRef<std::path::Path>) -> ewf_image::Result<ewf_image::Image> {
    ewf_image::Image::open_with_options(
        path,
        ewf_image::OpenOptions::default().with_strictness(ewf_image::OpenStrictness::Strict),
    )
}

fn section_desc(section_type: &[u8], next: u64, size: u64) -> [u8; 76] {
    let mut desc = [0; 76];
    desc[..section_type.len()].copy_from_slice(section_type);
    desc[16..24].copy_from_slice(&next.to_le_bytes());
    desc[24..32].copy_from_slice(&size.to_le_bytes());
    desc
}

fn section_desc_with_marker(section_type: &[u8], next: u64, size: u64, marker: &[u8]) -> [u8; 76] {
    let mut desc = section_desc(section_type, next, size);
    desc[32..32 + marker.len()].copy_from_slice(marker);
    desc
}

fn compressed_chunk(data: &[u8], chunk_size: usize) -> Vec<u8> {
    let mut padded = data.to_vec();
    padded.resize(chunk_size, 0);
    zlib_bytes(&padded)
}

fn zlib_bytes(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn zstd_bytes(data: &[u8]) -> Vec<u8> {
    ruzstd::encoding::compress_to_vec(
        Cursor::new(data),
        ruzstd::encoding::CompressionLevel::Fastest,
    )
}

fn xways_magicless_zstd_chunk(data: &[u8]) -> Vec<u8> {
    let mut padded = data.to_vec();
    padded.resize(32_768, 0);
    let encoded = zstd_bytes(&padded);
    assert_eq!(&encoded[..4], &[0x28, 0xb5, 0x2f, 0xfd]);
    encoded[4..].to_vec()
}

fn ewf1_chunk_only_segment_bytes(
    payload: &[u8],
    segment_number: u16,
    file_header_marker: u8,
) -> Vec<u8> {
    let table_desc_offset = 13_u64;
    let table_data_offset = table_desc_offset + 76;
    let sectors_desc_offset = table_data_offset + 24 + 4;
    let sectors_data_offset = sectors_desc_offset + 76;
    let done_desc_offset = sectors_data_offset + payload.len() as u64;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(file_header_marker);
    bytes.extend_from_slice(&segment_number.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());

    bytes.extend_from_slice(&section_desc(b"table", sectors_desc_offset, 76 + 24 + 4));
    let mut table_header = [0; 24];
    table_header[0..4].copy_from_slice(&1_u32.to_le_bytes());
    table_header[8..16].copy_from_slice(&sectors_data_offset.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    bytes.extend_from_slice(&0x8000_0000_u32.to_le_bytes());

    bytes.extend_from_slice(&section_desc(
        b"sectors",
        done_desc_offset,
        76 + payload.len() as u64,
    ));
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(&section_desc(b"done", 0, 76));
    bytes
}

fn ewf1_chunk_and_session_segment_bytes(
    payload: &[u8],
    session: &[u8],
    segment_number: u16,
    file_header_marker: u8,
) -> Vec<u8> {
    let table_desc_offset = 13_u64;
    let table_data_offset = table_desc_offset + 76;
    let sectors_desc_offset = table_data_offset + 24 + 4;
    let sectors_data_offset = sectors_desc_offset + 76;
    let session_desc_offset = sectors_data_offset + payload.len() as u64;
    let session_data_offset = session_desc_offset + 76;
    let done_desc_offset = session_data_offset + session.len() as u64;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(file_header_marker);
    bytes.extend_from_slice(&segment_number.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());

    bytes.extend_from_slice(&section_desc(b"table", sectors_desc_offset, 76 + 24 + 4));
    let mut table_header = [0; 24];
    table_header[0..4].copy_from_slice(&1_u32.to_le_bytes());
    table_header[8..16].copy_from_slice(&sectors_data_offset.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    bytes.extend_from_slice(&0x8000_0000_u32.to_le_bytes());

    bytes.extend_from_slice(&section_desc(
        b"sectors",
        session_desc_offset,
        76 + payload.len() as u64,
    ));
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(&section_desc(
        b"session",
        done_desc_offset,
        76 + session.len() as u64,
    ));
    bytes.extend_from_slice(session);
    bytes.extend_from_slice(&section_desc(b"done", 0, 76));
    bytes
}

fn xways_ewf1_segment_bytes(payload: &[u8], header_text: &[u8]) -> Vec<u8> {
    let header = zstd_bytes(header_text);
    xways_ewf1_segment_bytes_with_encoded_header(payload, &header)
}

fn xways_ewf1_segment_bytes_with_encoded_header(payload: &[u8], header: &[u8]) -> Vec<u8> {
    let header_desc_offset = 13_u64;
    let disk_desc_offset = header_desc_offset + 76 + header.len() as u64;
    let disk_data_offset = disk_desc_offset + 76;
    let table_desc_offset = disk_data_offset + 1052;
    let table_data_offset = table_desc_offset + 76;
    let sectors_desc_offset = table_data_offset + 24 + 4;
    let sectors_data_offset = sectors_desc_offset + 76;
    let done_desc_offset = sectors_data_offset + payload.len() as u64;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(0x21);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());

    bytes.extend_from_slice(&section_desc_with_marker(
        b"header",
        disk_desc_offset,
        76 + header.len() as u64,
        b"Zstd",
    ));
    bytes.extend_from_slice(header);

    bytes.extend_from_slice(&section_desc(b"disk", table_desc_offset, 76 + 1052));
    let mut disk = vec![0; 1052];
    disk[0] = 1;
    disk[4..8].copy_from_slice(&1_u32.to_le_bytes());
    disk[8..12].copy_from_slice(&64_u32.to_le_bytes());
    disk[12..16].copy_from_slice(&512_u32.to_le_bytes());
    disk[16..24].copy_from_slice(&64_u64.to_le_bytes());
    disk[36] = 0x02;
    disk[64..80].fill(0x58);
    bytes.extend_from_slice(&disk);

    bytes.extend_from_slice(&section_desc(b"table", sectors_desc_offset, 76 + 24 + 4));
    let mut table_header = [0; 24];
    table_header[0..4].copy_from_slice(&1_u32.to_le_bytes());
    table_header[8..16].copy_from_slice(&sectors_data_offset.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    bytes.extend_from_slice(&0x8000_0000_u32.to_le_bytes());

    bytes.extend_from_slice(&section_desc(
        b"sectors",
        done_desc_offset,
        76 + payload.len() as u64,
    ));
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(&section_desc(b"done", 0, 76));
    bytes
}

fn stored_zlib_bytes(data: &[u8], block_size: usize) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&[0x78, 0x01]);
    for (index, block) in data.chunks(block_size).enumerate() {
        let final_block = index + 1 == data.len().div_ceil(block_size);
        encoded.push(u8::from(final_block));
        let len = u16::try_from(block.len()).unwrap();
        encoded.extend_from_slice(&len.to_le_bytes());
        encoded.extend_from_slice(&(!len).to_le_bytes());
        encoded.extend_from_slice(block);
    }
    encoded.extend_from_slice(&adler32(data).to_be_bytes());
    encoded
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

fn ewf2_single_files_aux_u64_table(entries: &[u64]) -> Vec<u8> {
    let mut entry_data = Vec::with_capacity(entries.len() * 8);
    for entry in entries {
        entry_data.extend_from_slice(&entry.to_le_bytes());
    }
    ewf2_single_files_aux_table(entries.len(), &entry_data)
}

fn ewf2_single_files_md5_hash_table(hashes: &[[u8; 16]]) -> Vec<u8> {
    let mut entry_data = Vec::with_capacity(hashes.len() * 16);
    for hash in hashes {
        entry_data.extend_from_slice(hash);
    }
    ewf2_single_files_aux_table(hashes.len(), &entry_data)
}

fn ewf2_single_files_aux_table(entry_count: usize, entry_data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(32 + entry_data.len() + 16);
    payload.extend_from_slice(&(entry_count as u32).to_le_bytes());
    payload.extend_from_slice(&[0; 12]);
    let header_checksum = adler32(&payload);
    payload.extend_from_slice(&header_checksum.to_le_bytes());
    payload.extend_from_slice(&[0; 12]);
    payload.extend_from_slice(entry_data);
    let entries_checksum = adler32(entry_data);
    payload.extend_from_slice(&entries_checksum.to_le_bytes());
    payload.extend_from_slice(&[0; 12]);
    payload
}

fn bzip2_chunk(data: &[u8], chunk_size: usize) -> Vec<u8> {
    let mut padded = data.to_vec();
    padded.resize(chunk_size, 0);
    bzip2_bytes(&padded)
}

fn bzip2_bytes(data: &[u8]) -> Vec<u8> {
    let mut encoder = BzEncoder::new(Vec::new(), bzip2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn deterministic_noise(len: usize) -> Vec<u8> {
    let mut state = 0x1234_5678_9abc_def0_u64;
    let mut data = Vec::with_capacity(len);
    for _ in 0..len {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        data.push((state >> 32) as u8);
    }
    data
}

fn synthetic_e01(data: &[u8]) -> NamedTempFile {
    synthetic_e01_with_digest(data, None)
}

fn synthetic_e01_zero_sized_done(data: &[u8]) -> NamedTempFile {
    let mut bytes = ewf1_bytes(data, EVF_SIGNATURE, 1, 1, 64, true, None);
    let done_desc_offset = bytes
        .len()
        .checked_sub(76)
        .expect("synthetic EWF1 includes done descriptor");
    bytes[done_desc_offset + 24..done_desc_offset + 32].copy_from_slice(&0_u64.to_le_bytes());
    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_e01_next_terminated(data: &[u8]) -> NamedTempFile {
    let mut bytes = ewf1_bytes(data, EVF_SIGNATURE, 1, 1, 64, true, None);
    let done_desc_offset = bytes
        .len()
        .checked_sub(76)
        .expect("synthetic EWF1 includes done descriptor");
    bytes[done_desc_offset..done_desc_offset + 4].copy_from_slice(b"next");
    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_e01_with_max_section_next() -> NamedTempFile {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&section_desc(b"volume", u64::MAX, 76 + 94));
    let mut volume = [0; 94];
    volume[4..8].copy_from_slice(&1_u32.to_le_bytes());
    volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
    volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
    volume[16..20].copy_from_slice(&64_u32.to_le_bytes());
    volume[85..90].copy_from_slice(b"SMART");
    bytes.extend_from_slice(&volume);

    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_e01_with_max_sectors_section_size() -> NamedTempFile {
    let sectors_desc_offset = 13_u64 + 76 + 94;
    let done_desc_offset = sectors_desc_offset + 76;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&section_desc(b"volume", sectors_desc_offset, 76 + 94));
    let mut volume = [0; 94];
    volume[4..8].copy_from_slice(&1_u32.to_le_bytes());
    volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
    volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
    volume[16..24].copy_from_slice(&64_u64.to_le_bytes());
    bytes.extend_from_slice(&volume);
    bytes.extend_from_slice(&section_desc(b"sectors", done_desc_offset, u64::MAX));
    bytes.extend_from_slice(&section_desc(b"done", 0, 76));

    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_e01_without_table_coverage() -> NamedTempFile {
    let done_desc_offset = 13_u64 + 76 + 94;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&section_desc(b"volume", done_desc_offset, 76 + 94));
    let mut volume = [0; 94];
    volume[4..8].copy_from_slice(&2_u32.to_le_bytes());
    volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
    volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
    volume[16..24].copy_from_slice(&128_u64.to_le_bytes());
    bytes.extend_from_slice(&volume);
    bytes.extend_from_slice(&section_desc(b"done", 0, 76));

    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_l01(data: &[u8]) -> NamedTempFile {
    let bytes = ewf1_bytes(data, LVF_SIGNATURE, 1, 1, 64, true, None);
    write_temp_with_suffix(".L01", &bytes)
}

fn synthetic_s01_oversized_compressed_chunk(data: &[u8]) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let mut logical = data.to_vec();
    logical.resize(chunk_size, 0);
    let compressed = stored_zlib_bytes(&logical, 512);
    assert!(compressed.len() > 32_791);
    assert!(compressed.len() < chunk_size * 2);

    let volume_desc_offset = 13_u64;
    let volume_data_offset = volume_desc_offset + 76;
    let table_desc_offset = volume_data_offset + 94;
    let table_data_offset = table_desc_offset + 76;
    let table_entries_offset = table_data_offset + 24;
    let sectors_desc_offset = table_entries_offset + 4;
    let sectors_data_offset = sectors_desc_offset + 76;
    let done_desc_offset = sectors_data_offset + compressed.len() as u64;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());

    bytes.extend_from_slice(&section_desc(b"volume", table_desc_offset, 76 + 94));
    let mut volume = [0; 94];
    volume[0] = 1;
    volume[4..8].copy_from_slice(&1_u32.to_le_bytes());
    volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
    volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
    volume[16..20].copy_from_slice(&64_u32.to_le_bytes());
    volume[85..90].copy_from_slice(b"SMART");
    bytes.extend_from_slice(&volume);

    bytes.extend_from_slice(&section_desc(b"table", sectors_desc_offset, 76 + 24 + 4));
    let mut table_header = [0; 24];
    table_header[0..4].copy_from_slice(&1_u32.to_le_bytes());
    table_header[8..16].copy_from_slice(&sectors_data_offset.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    bytes.extend_from_slice(&0x8000_0000_u32.to_le_bytes());

    bytes.extend_from_slice(&section_desc(
        b"sectors",
        done_desc_offset,
        76 + compressed.len() as u64,
    ));
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&section_desc(b"done", 0, 76));

    write_temp_with_suffix(".s01", &bytes)
}

fn smart_ewf1_bytes(data: &[u8], segment_number: u16, total_chunks: u32) -> Vec<u8> {
    let chunk_size = 32_768_usize;
    let payload = compressed_chunk(data, chunk_size);

    let volume_desc_offset = 13_u64;
    let volume_data_offset = volume_desc_offset + 76;
    let table_desc_offset = volume_data_offset + 94;
    let table_data_offset = table_desc_offset + 76;
    let table_entries_offset = table_data_offset + 24;
    let sectors_desc_offset = table_entries_offset + 4;
    let sectors_data_offset = sectors_desc_offset + 76;
    let done_desc_offset = sectors_data_offset + payload.len() as u64;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(1);
    bytes.extend_from_slice(&segment_number.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());

    bytes.extend_from_slice(&section_desc(b"volume", table_desc_offset, 76 + 94));
    let mut volume = [0; 94];
    volume[0] = 1;
    volume[4..8].copy_from_slice(&total_chunks.to_le_bytes());
    volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
    volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
    volume[16..20].copy_from_slice(&(total_chunks * 64).to_le_bytes());
    volume[85..90].copy_from_slice(b"SMART");
    bytes.extend_from_slice(&volume);

    bytes.extend_from_slice(&section_desc(b"table", sectors_desc_offset, 76 + 24 + 4));
    let mut table_header = [0; 24];
    table_header[0..4].copy_from_slice(&1_u32.to_le_bytes());
    table_header[8..16].copy_from_slice(&sectors_data_offset.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    bytes.extend_from_slice(&0x8000_0000_u32.to_le_bytes());

    bytes.extend_from_slice(&section_desc(
        b"sectors",
        done_desc_offset,
        76 + payload.len() as u64,
    ));
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(&section_desc(b"done", 0, 76));

    bytes
}

fn synthetic_e01_large_stored_zlib_chunk(data: &[u8]) -> NamedTempFile {
    synthetic_e01_stored_zlib_chunk(data, true)
}

fn synthetic_e01_unflagged_stored_zlib_chunk(data: &[u8]) -> NamedTempFile {
    synthetic_e01_stored_zlib_chunk(data, false)
}

fn synthetic_e01_stored_zlib_chunk(data: &[u8], table_entry_compressed: bool) -> NamedTempFile {
    const SECTORS_PER_CHUNK: u32 = 32_768;
    const BYTES_PER_SECTOR: u32 = 512;
    const CHUNK_SIZE: usize = SECTORS_PER_CHUNK as usize * BYTES_PER_SECTOR as usize;

    let mut logical = data.to_vec();
    logical.resize(CHUNK_SIZE, 0);
    let compressed = stored_zlib_bytes(&logical, 512);
    assert!(compressed.len() as u64 > CHUNK_SIZE as u64 + 1024);
    assert!(compressed.len() < CHUNK_SIZE * 2);

    let volume_data_size = 1052_u64;
    let volume_desc_offset = 13_u64;
    let volume_data_offset = volume_desc_offset + 76;
    let table_desc_offset = volume_data_offset + volume_data_size;
    let table_data_offset = table_desc_offset + 76;
    let table_entries_offset = table_data_offset + 24;
    let sectors_desc_offset = table_entries_offset + 4;
    let sectors_data_offset = sectors_desc_offset + 76;
    let done_desc_offset = sectors_data_offset + compressed.len() as u64;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());

    bytes.extend_from_slice(&section_desc(
        b"volume",
        table_desc_offset,
        76 + volume_data_size,
    ));
    let mut volume = vec![0; volume_data_size as usize];
    volume[4..8].copy_from_slice(&1_u32.to_le_bytes());
    volume[8..12].copy_from_slice(&SECTORS_PER_CHUNK.to_le_bytes());
    volume[12..16].copy_from_slice(&BYTES_PER_SECTOR.to_le_bytes());
    volume[16..24].copy_from_slice(&u64::from(SECTORS_PER_CHUNK).to_le_bytes());
    bytes.extend_from_slice(&volume);

    bytes.extend_from_slice(&section_desc(b"table", sectors_desc_offset, 76 + 24 + 4));
    let mut table_header = [0; 24];
    table_header[0..4].copy_from_slice(&1_u32.to_le_bytes());
    table_header[8..16].copy_from_slice(&sectors_data_offset.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let table_entry = if table_entry_compressed {
        0x8000_0000_u32
    } else {
        0
    };
    bytes.extend_from_slice(&table_entry.to_le_bytes());

    bytes.extend_from_slice(&section_desc(
        b"sectors",
        done_desc_offset,
        76 + compressed.len() as u64,
    ));
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&section_desc(b"done", 0, 76));

    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_e01_raw(data: &[u8]) -> NamedTempFile {
    let bytes = ewf1_bytes(data, EVF_SIGNATURE, 1, 1, 64, false, None);
    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_e01_final_partial_raw_chunk_with_checksum(data: &[u8]) -> NamedTempFile {
    let table_desc_offset = 13_u64 + 76 + 94;
    let table_data_offset = table_desc_offset + 76;
    let table_entries_offset = table_data_offset + 24;
    let sectors_desc_offset = table_entries_offset + 4;
    let sectors_data_offset = sectors_desc_offset + 76;
    let raw_size = data.len() as u64 + 4;
    let done_desc_offset = sectors_data_offset + raw_size;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());

    bytes.extend_from_slice(&section_desc(b"volume", table_desc_offset, 76 + 94));
    let mut volume = [0; 94];
    volume[4..8].copy_from_slice(&1_u32.to_le_bytes());
    volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
    volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
    volume[16..24].copy_from_slice(&1_u64.to_le_bytes());
    bytes.extend_from_slice(&volume);

    bytes.extend_from_slice(&section_desc(b"table", sectors_desc_offset, 76 + 24 + 4));
    let mut table_header = [0; 24];
    table_header[0..4].copy_from_slice(&1_u32.to_le_bytes());
    table_header[8..16].copy_from_slice(&sectors_data_offset.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    bytes.extend_from_slice(&0_u32.to_le_bytes());

    bytes.extend_from_slice(&section_desc(b"sectors", done_desc_offset, 76 + raw_size));
    bytes.extend_from_slice(data);
    bytes.extend_from_slice(&adler32(data).to_le_bytes());
    bytes.extend_from_slice(&section_desc(b"done", 0, 76));

    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_e01_separate_table_sector_ranges(chunks: &[&[u8]]) -> NamedTempFile {
    let table_types = vec![b"table".as_slice(); chunks.len()];
    synthetic_e01_separate_table_sector_ranges_with_types(chunks, &table_types)
}

fn synthetic_e01_separate_table_sector_ranges_with_types(
    chunks: &[&[u8]],
    table_types: &[&[u8]],
) -> NamedTempFile {
    assert_ne!(chunks, [] as [&[u8]; 0]);
    assert_eq!(chunks.len(), table_types.len());
    let compressed_chunks: Vec<Vec<u8>> = chunks
        .iter()
        .map(|chunk| compressed_chunk(chunk, 32_768))
        .collect();

    #[derive(Clone, Copy)]
    struct RangeLayout {
        table_section_offset: u64,
        sectors_section_offset: u64,
        sectors_data_start: u64,
    }

    let mut next_offset = 13_u64 + 76 + 94;
    let mut layouts = Vec::with_capacity(compressed_chunks.len());
    for compressed in &compressed_chunks {
        let table_desc_offset = next_offset;
        let table_data_offset = table_desc_offset + 76;
        let table_entries_offset = table_data_offset + 24;
        let sectors_desc_offset = table_entries_offset + 4;
        let sectors_data_offset = sectors_desc_offset + 76;
        layouts.push(RangeLayout {
            table_section_offset: table_desc_offset,
            sectors_section_offset: sectors_desc_offset,
            sectors_data_start: sectors_data_offset,
        });
        next_offset = sectors_data_offset + compressed.len() as u64;
    }
    let done_desc_offset = next_offset;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&section_desc(
        b"volume",
        layouts[0].table_section_offset,
        76 + 94,
    ));
    let mut volume = [0; 94];
    volume[4..8].copy_from_slice(&(chunks.len() as u32).to_le_bytes());
    volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
    volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
    volume[16..24].copy_from_slice(&((chunks.len() as u64) * 64).to_le_bytes());
    bytes.extend_from_slice(&volume);

    for (index, compressed) in compressed_chunks.iter().enumerate() {
        let layout = layouts[index];
        let next_after_sectors = layouts
            .get(index + 1)
            .map_or(done_desc_offset, |next| next.table_section_offset);
        bytes.extend_from_slice(&section_desc(
            table_types[index],
            layout.sectors_section_offset,
            76 + 24 + 4,
        ));
        let mut table_header = [0; 24];
        table_header[0..4].copy_from_slice(&1_u32.to_le_bytes());
        table_header[8..16].copy_from_slice(&layout.sectors_data_start.to_le_bytes());
        bytes.extend_from_slice(&table_header);
        bytes.extend_from_slice(&0x8000_0000_u32.to_le_bytes());

        bytes.extend_from_slice(&section_desc(
            b"sectors",
            next_after_sectors,
            76 + compressed.len() as u64,
        ));
        bytes.extend_from_slice(compressed);
    }

    bytes.extend_from_slice(&section_desc(b"done", 0, 76));
    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_e01_with_filler_sections(data: &[u8], filler_count: usize) -> NamedTempFile {
    let compressed = compressed_chunk(data, 32_768);
    let volume_desc_offset = 13_u64;
    let volume_data_offset = volume_desc_offset + 76;
    let filler_desc_offset = volume_data_offset + 94;
    let table_desc_offset = filler_desc_offset + (filler_count as u64 * 76);
    let table_data_offset = table_desc_offset + 76;
    let sectors_desc_offset = table_data_offset + 24 + 4;
    let sectors_data_offset = sectors_desc_offset + 76;
    let done_desc_offset = sectors_data_offset + compressed.len() as u64;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&section_desc(
        b"volume",
        if filler_count == 0 {
            table_desc_offset
        } else {
            filler_desc_offset
        },
        76 + 94,
    ));
    let mut volume = [0; 94];
    volume[4..8].copy_from_slice(&1_u32.to_le_bytes());
    volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
    volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
    volume[16..24].copy_from_slice(&64_u64.to_le_bytes());
    bytes.extend_from_slice(&volume);

    for index in 0..filler_count {
        let offset = filler_desc_offset + (index as u64 * 76);
        let next = if index + 1 == filler_count {
            table_desc_offset
        } else {
            offset + 76
        };
        bytes.extend_from_slice(&section_desc(b"padding", next, 76));
    }

    bytes.extend_from_slice(&section_desc(b"table", sectors_desc_offset, 76 + 24 + 4));
    let mut table_header = [0; 24];
    table_header[0..4].copy_from_slice(&1_u32.to_le_bytes());
    table_header[8..16].copy_from_slice(&sectors_data_offset.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    bytes.extend_from_slice(&0x8000_0000_u32.to_le_bytes());

    bytes.extend_from_slice(&section_desc(
        b"sectors",
        done_desc_offset,
        76 + compressed.len() as u64,
    ));
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&section_desc(b"done", 0, 76));
    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_e01_with_volume_next(next: u64) -> NamedTempFile {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&section_desc(b"volume", next, 76 + 94));
    bytes.extend_from_slice(&[0; 94]);
    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_e01_table2_mirror_then_later_table() -> NamedTempFile {
    let first = compressed_chunk(b"first mirrored table", 32_768);
    let second = compressed_chunk(b"second real table", 32_768);
    let sectors_bytes = (first.len() + second.len()) as u64;

    let volume_desc_offset = 13_u64;
    let volume_data_offset = volume_desc_offset + 76;
    let sectors_desc_offset = volume_data_offset + 94;
    let sectors_data_offset = sectors_desc_offset + 76;
    let table1_desc_offset = sectors_data_offset + sectors_bytes;
    let table2_desc_offset = table1_desc_offset + 76 + 24 + 4;
    let table3_desc_offset = table2_desc_offset + 76 + 24 + 4;
    let done_desc_offset = table3_desc_offset + 76 + 24 + 4;
    let second_offset = first.len() as u32;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&section_desc(b"volume", sectors_desc_offset, 76 + 94));
    let mut volume = [0; 94];
    volume[4..8].copy_from_slice(&2_u32.to_le_bytes());
    volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
    volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
    volume[16..24].copy_from_slice(&128_u64.to_le_bytes());
    bytes.extend_from_slice(&volume);

    bytes.extend_from_slice(&section_desc(
        b"sectors",
        table1_desc_offset,
        76 + sectors_bytes,
    ));
    bytes.extend_from_slice(&first);
    bytes.extend_from_slice(&second);

    for (section_type, next, entry) in [
        (b"table".as_slice(), table2_desc_offset, 0_u32),
        (b"table2".as_slice(), table3_desc_offset, 0_u32),
        (b"table".as_slice(), done_desc_offset, second_offset),
    ] {
        bytes.extend_from_slice(&section_desc(section_type, next, 76 + 24 + 4));
        let mut table_header = [0; 24];
        table_header[0..4].copy_from_slice(&1_u32.to_le_bytes());
        table_header[8..16].copy_from_slice(&sectors_data_offset.to_le_bytes());
        bytes.extend_from_slice(&table_header);
        bytes.extend_from_slice(&(0x8000_0000_u32 | entry).to_le_bytes());
    }

    bytes.extend_from_slice(&section_desc(b"done", 0, 76));
    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_e01_preceding_sectors_table(data: &[u8], descriptor_base: bool) -> NamedTempFile {
    let compressed = compressed_chunk(data, 32_768);
    let sectors_bytes = compressed.len() as u64;

    let volume_desc_offset = 13_u64;
    let volume_data_offset = volume_desc_offset + 76;
    let sectors_desc_offset = volume_data_offset + 94;
    let sectors_data_offset = sectors_desc_offset + 76;
    let table_desc_offset = sectors_data_offset + sectors_bytes;
    let done_desc_offset = table_desc_offset + 76 + 24 + 4;
    let table_base = if descriptor_base {
        sectors_desc_offset
    } else {
        sectors_data_offset
    };
    let table_entry = if descriptor_base { 76_u32 } else { 0_u32 };

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&section_desc(b"volume", sectors_desc_offset, 76 + 94));
    let mut volume = [0; 94];
    volume[4..8].copy_from_slice(&1_u32.to_le_bytes());
    volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
    volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
    volume[16..24].copy_from_slice(&64_u64.to_le_bytes());
    bytes.extend_from_slice(&volume);

    bytes.extend_from_slice(&section_desc(
        b"sectors",
        table_desc_offset,
        76 + sectors_bytes,
    ));
    bytes.extend_from_slice(&compressed);

    bytes.extend_from_slice(&section_desc(b"table", done_desc_offset, 76 + 24 + 4));
    let mut table_header = [0; 24];
    table_header[0..4].copy_from_slice(&1_u32.to_le_bytes());
    table_header[8..16].copy_from_slice(&table_base.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    bytes.extend_from_slice(&(0x8000_0000_u32 | table_entry).to_le_bytes());

    bytes.extend_from_slice(&section_desc(b"done", 0, 76));
    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_e01_preceding_sectors_absolute_raw_table() -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let first = vec![0x11; chunk_size];
    let second = vec![0x22; chunk_size];
    let mut sectors = Vec::new();
    sectors.extend_from_slice(&first);
    sectors.extend_from_slice(&adler32(&first).to_le_bytes());
    sectors.extend_from_slice(&second);
    sectors.extend_from_slice(&adler32(&second).to_le_bytes());
    let first_chunk_offset = 0_u32;
    let second_chunk_offset = u32::try_from(first.len() + 4).unwrap();

    let volume_desc_offset = 13_u64;
    let volume_data_offset = volume_desc_offset + 76;
    let sectors_desc_offset = volume_data_offset + 94;
    let sectors_data_offset = sectors_desc_offset + 76;
    let table_desc_offset = sectors_data_offset + sectors.len() as u64;
    let table_data_size = 24_u64 + 8;
    let done_desc_offset = table_desc_offset + 76 + table_data_size;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&section_desc(b"volume", sectors_desc_offset, 76 + 94));
    let mut volume = [0; 94];
    volume[4..8].copy_from_slice(&2_u32.to_le_bytes());
    volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
    volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
    volume[16..24].copy_from_slice(&128_u64.to_le_bytes());
    bytes.extend_from_slice(&volume);

    bytes.extend_from_slice(&section_desc(
        b"sectors",
        table_desc_offset,
        76 + sectors.len() as u64,
    ));
    bytes.extend_from_slice(&sectors);

    bytes.extend_from_slice(&section_desc(
        b"table",
        done_desc_offset,
        76 + table_data_size,
    ));
    let mut table_header = [0; 24];
    table_header[0..4].copy_from_slice(&2_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    bytes.extend_from_slice(&(first_chunk_offset + sectors_data_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&(second_chunk_offset + sectors_data_offset as u32).to_le_bytes());

    bytes.extend_from_slice(&section_desc(b"done", 0, 76));
    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_e01_with_geometry(
    chunk_count: u32,
    sectors_per_chunk: u32,
    bytes_per_sector: u32,
    sector_count: u64,
) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let compressed = compressed_chunk(b"geometry", chunk_size);
    let volume_data_size = 105_u64;

    let volume_desc_offset = 13_u64;
    let volume_data_offset = volume_desc_offset + 76;
    let table_desc_offset = volume_data_offset + volume_data_size;
    let table_data_offset = table_desc_offset + 76;
    let table_entries_offset = table_data_offset + 24;
    let sectors_desc_offset = table_entries_offset + 4;
    let sectors_data_offset = sectors_desc_offset + 76;
    let done_desc_offset = sectors_data_offset + compressed.len() as u64;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());

    bytes.extend_from_slice(&section_desc(
        b"volume",
        table_desc_offset,
        76 + volume_data_size,
    ));
    let mut volume = [0; 105];
    volume[4..8].copy_from_slice(&chunk_count.to_le_bytes());
    volume[8..12].copy_from_slice(&sectors_per_chunk.to_le_bytes());
    volume[12..16].copy_from_slice(&bytes_per_sector.to_le_bytes());
    volume[16..24].copy_from_slice(&sector_count.to_le_bytes());
    bytes.extend_from_slice(&volume);

    bytes.extend_from_slice(&section_desc(b"table", sectors_desc_offset, 76 + 24 + 4));
    let mut table_header = [0; 24];
    table_header[0..4].copy_from_slice(&1_u32.to_le_bytes());
    table_header[8..16].copy_from_slice(&sectors_data_offset.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    bytes.extend_from_slice(&0x8000_0000_u32.to_le_bytes());

    bytes.extend_from_slice(&section_desc(
        b"sectors",
        done_desc_offset,
        76 + compressed.len() as u64,
    ));
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&section_desc(b"done", 0, 76));

    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_e01_data_section(data: &[u8]) -> NamedTempFile {
    let bytes = ewf1_bytes_with_options(
        data,
        Ewf1BytesOptions {
            signature: EVF_SIGNATURE,
            segment_number: 1,
            total_chunks: 1,
            total_sectors: 64,
            is_compressed: true,
            compression_level: 0,
            digest: None,
            media_section_type: b"data",
        },
    );
    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_e01_table_resident(data: &[u8]) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let compressed = compressed_chunk(data, chunk_size);

    let volume_desc_offset = 13_u64;
    let volume_data_offset = volume_desc_offset + 76;
    let table_desc_offset = volume_data_offset + 94;
    let table_data_offset = table_desc_offset + 76;
    let table_entries_offset = table_data_offset + 24;
    let table_footer_offset = table_entries_offset + 4;
    let chunk_data_offset = table_footer_offset + 4;
    let done_desc_offset = chunk_data_offset + compressed.len() as u64;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());

    bytes.extend_from_slice(&section_desc(b"volume", table_desc_offset, 76 + 94));
    let mut volume = [0; 94];
    volume[4..8].copy_from_slice(&1_u32.to_le_bytes());
    volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
    volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
    volume[16..24].copy_from_slice(&64_u64.to_le_bytes());
    bytes.extend_from_slice(&volume);

    bytes.extend_from_slice(&section_desc(
        b"table",
        done_desc_offset,
        76 + 24 + 4 + 4 + compressed.len() as u64,
    ));
    let mut table_header = [0; 24];
    table_header[0..4].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    bytes.extend_from_slice(&(0x8000_0000_u32 | chunk_data_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&section_desc(b"done", 0, 76));

    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_e01_table_resident_without_entries_checksum(data: &[u8]) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let compressed = compressed_chunk(data, chunk_size);

    let volume_desc_offset = 13_u64;
    let volume_data_offset = volume_desc_offset + 76;
    let table_desc_offset = volume_data_offset + 94;
    let table_data_offset = table_desc_offset + 76;
    let table_entries_offset = table_data_offset + 24;
    let chunk_data_offset = table_entries_offset + 4;
    let done_desc_offset = chunk_data_offset + compressed.len() as u64;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());

    bytes.extend_from_slice(&section_desc(b"volume", table_desc_offset, 76 + 94));
    let mut volume = [0; 94];
    volume[4..8].copy_from_slice(&1_u32.to_le_bytes());
    volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
    volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
    volume[16..24].copy_from_slice(&64_u64.to_le_bytes());
    bytes.extend_from_slice(&volume);

    bytes.extend_from_slice(&section_desc(
        b"table",
        done_desc_offset,
        76 + 24 + 4 + compressed.len() as u64,
    ));
    let mut table_header = [0; 24];
    table_header[0..4].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    bytes.extend_from_slice(&(0x8000_0000_u32 | chunk_data_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&section_desc(b"done", 0, 76));

    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_e01_full_width_offset(data: &[u8]) -> NamedTempFile {
    const FULL_WIDTH_OFFSET: u32 = 0x8000_1000;
    let chunk_size = 32_768_usize;

    let volume_desc_offset = 13_u64;
    let volume_data_offset = volume_desc_offset + 76;
    let table_desc_offset = volume_data_offset + 94;
    let table_data_offset = table_desc_offset + 76;
    let table_entries_offset = table_data_offset + 24;
    let sectors_desc_offset = table_entries_offset + 4;
    let sectors_data_offset = sectors_desc_offset + 76;
    let chunk_offset = sectors_data_offset + u64::from(FULL_WIDTH_OFFSET);
    let done_desc_offset = chunk_offset + chunk_size as u64;

    let mut file = tempfile::Builder::new().suffix(".E01").tempfile().unwrap();
    file.write_all(&EVF_SIGNATURE).unwrap();
    file.write_all(&[1]).unwrap();
    file.write_all(&1_u16.to_le_bytes()).unwrap();
    file.write_all(&0_u16.to_le_bytes()).unwrap();
    file.write_all(&section_desc(b"volume", table_desc_offset, 76 + 94))
        .unwrap();
    let mut volume = [0; 94];
    volume[4..8].copy_from_slice(&1_u32.to_le_bytes());
    volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
    volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
    volume[16..24].copy_from_slice(&64_u64.to_le_bytes());
    file.write_all(&volume).unwrap();
    file.write_all(&section_desc(b"table", sectors_desc_offset, 76 + 24 + 4))
        .unwrap();
    let mut table_header = [0; 24];
    table_header[0..4].copy_from_slice(&1_u32.to_le_bytes());
    table_header[8..16].copy_from_slice(&sectors_data_offset.to_le_bytes());
    file.write_all(&table_header).unwrap();
    file.write_all(&FULL_WIDTH_OFFSET.to_le_bytes()).unwrap();
    file.write_all(&section_desc(
        b"sectors",
        done_desc_offset,
        76 + u64::from(FULL_WIDTH_OFFSET) + chunk_size as u64,
    ))
    .unwrap();

    let mut chunk = vec![0; chunk_size];
    chunk[..data.len()].copy_from_slice(data);
    file.seek(SeekFrom::Start(chunk_offset)).unwrap();
    file.write_all(&chunk).unwrap();
    file.write_all(&section_desc(b"done", 0, 76)).unwrap();
    file.flush().unwrap();
    file
}

fn synthetic_e01_full_width_offset_with_zero_base(data: &[u8]) -> NamedTempFile {
    let chunk_size = 32_768_usize;

    let volume_desc_offset = 13_u64;
    let volume_data_offset = volume_desc_offset + 76;
    let table_desc_offset = volume_data_offset + 94;
    let table_data_offset = table_desc_offset + 76;
    let table_entries_offset = table_data_offset + 24;
    let sectors_desc_offset = table_entries_offset + 4;
    let sectors_data_offset = sectors_desc_offset + 76;
    let chunk_offset = sectors_data_offset + 0x8000_1000;
    let done_desc_offset = chunk_offset + chunk_size as u64;

    let mut file = tempfile::Builder::new().suffix(".E01").tempfile().unwrap();
    file.write_all(&EVF_SIGNATURE).unwrap();
    file.write_all(&[1]).unwrap();
    file.write_all(&1_u16.to_le_bytes()).unwrap();
    file.write_all(&0_u16.to_le_bytes()).unwrap();
    file.write_all(&section_desc(b"volume", table_desc_offset, 76 + 94))
        .unwrap();
    let mut volume = [0; 94];
    volume[4..8].copy_from_slice(&1_u32.to_le_bytes());
    volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
    volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
    volume[16..24].copy_from_slice(&64_u64.to_le_bytes());
    file.write_all(&volume).unwrap();
    file.write_all(&section_desc(b"table", sectors_desc_offset, 76 + 24 + 4))
        .unwrap();
    let mut table_header = [0; 24];
    table_header[0..4].copy_from_slice(&1_u32.to_le_bytes());
    file.write_all(&table_header).unwrap();
    let full_width_entry = u32::try_from(chunk_offset).unwrap();
    assert!(full_width_entry & 0x8000_0000 != 0);
    file.write_all(&full_width_entry.to_le_bytes()).unwrap();
    file.write_all(&section_desc(
        b"sectors",
        done_desc_offset,
        76 + (chunk_offset - sectors_data_offset) + chunk_size as u64,
    ))
    .unwrap();

    let mut chunk = vec![0; chunk_size];
    chunk[..data.len()].copy_from_slice(data);
    file.seek(SeekFrom::Start(chunk_offset)).unwrap();
    file.write_all(&chunk).unwrap();
    file.write_all(&section_desc(b"done", 0, 76)).unwrap();
    file.flush().unwrap();
    file
}

#[cfg(feature = "verify")]
fn synthetic_e01_with_stored_digest(data: &[u8]) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let mut logical = data.to_vec();
    logical.resize(chunk_size, 0);

    let mut md5 = Md5::new();
    md5.update(&logical);
    let md5: [u8; 16] = md5.finalize().into();

    let mut sha1 = Sha1::new();
    sha1.update(&logical);
    let sha1: [u8; 20] = sha1.finalize().into();

    synthetic_e01_with_digest(data, Some((md5, sha1)))
}

fn synthetic_e01_with_xhash(data: &[u8], md5: [u8; 16], sha1: [u8; 20]) -> NamedTempFile {
    let mut bytes = ewf1_bytes(data, EVF_SIGNATURE, 1, 1, 64, true, None);
    let xhash_text = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<xhash>\n\t<MD5>{}</MD5>\n\t<SHA1>{}</SHA1>\n</xhash>\n\n",
        hex_string(&md5),
        hex_string(&sha1)
    );
    let mut xhash_raw = vec![0xef, 0xbb, 0xbf];
    xhash_raw.extend_from_slice(xhash_text.as_bytes());
    let xhash = zlib_bytes(&xhash_raw);
    let xhash_desc_offset = bytes
        .len()
        .checked_sub(76)
        .expect("synthetic EWF1 includes done descriptor");
    let done_desc_offset = xhash_desc_offset + 76 + xhash.len();
    let sectors_desc_offset = bytes
        .windows(b"sectors".len())
        .position(|window| window == b"sectors")
        .expect("synthetic EWF1 includes sectors section");

    bytes[sectors_desc_offset + 16..sectors_desc_offset + 24]
        .copy_from_slice(&(xhash_desc_offset as u64).to_le_bytes());
    bytes.truncate(xhash_desc_offset);
    bytes.extend_from_slice(&section_desc(
        b"xhash",
        done_desc_offset as u64,
        76 + xhash.len() as u64,
    ));
    bytes.extend_from_slice(&xhash);
    bytes.extend_from_slice(&section_desc(b"done", 0, 76));

    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_e01_with_xheader(data: &[u8]) -> NamedTempFile {
    let mut bytes = ewf1_bytes(data, EVF_SIGNATURE, 1, 1, 64, true, None);
    let xheader_text = concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
        "<xheader>\n",
        "\t<case_number>CASE-X</case_number>\n",
        "\t<description>Extended header image</description>\n",
        "\t<examiner_name>Analyst X</examiner_name>\n",
        "\t<evidence_number>EVID-X</evidence_number>\n",
        "\t<notes>Extended notes</notes>\n",
        "\t<acquiry_operating_system>Linux</acquiry_operating_system>\n",
        "\t<acquiry_date>Sat Jan 20 18:32:08 2007 CET</acquiry_date>\n",
        "\t<acquiry_software>ewfacquire</acquiry_software>\n",
        "\t<acquiry_software_version>20070120</acquiry_software_version>\n",
        "</xheader>\n\n",
    );
    let mut xheader_raw = vec![0xef, 0xbb, 0xbf];
    xheader_raw.extend_from_slice(xheader_text.as_bytes());
    let xheader = zlib_bytes(&xheader_raw);
    let xheader_desc_offset = bytes
        .len()
        .checked_sub(76)
        .expect("synthetic EWF1 includes done descriptor");
    let done_desc_offset = xheader_desc_offset + 76 + xheader.len();
    let sectors_desc_offset = bytes
        .windows(b"sectors".len())
        .position(|window| window == b"sectors")
        .expect("synthetic EWF1 includes sectors section");

    bytes[sectors_desc_offset + 16..sectors_desc_offset + 24]
        .copy_from_slice(&(xheader_desc_offset as u64).to_le_bytes());
    bytes.truncate(xheader_desc_offset);
    bytes.extend_from_slice(&section_desc(
        b"xheader",
        done_desc_offset as u64,
        76 + xheader.len() as u64,
    ));
    bytes.extend_from_slice(&xheader);
    bytes.extend_from_slice(&section_desc(b"done", 0, 76));

    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_e01_with_digest(data: &[u8], digest: Option<([u8; 16], [u8; 20])>) -> NamedTempFile {
    let bytes = ewf1_bytes(data, EVF_SIGNATURE, 1, 1, 64, true, digest);
    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_e01_with_digest_payload(data: &[u8], digest: &[u8]) -> NamedTempFile {
    let bytes = ewf1_bytes_with_options(
        data,
        Ewf1BytesOptions {
            signature: EVF_SIGNATURE,
            segment_number: 1,
            total_chunks: 1,
            total_sectors: 64,
            is_compressed: true,
            compression_level: 0,
            digest: Some(digest),
            media_section_type: b"volume",
        },
    );
    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_e01_with_hash_payload(data: &[u8], hash: &[u8]) -> NamedTempFile {
    let mut bytes = ewf1_bytes(data, EVF_SIGNATURE, 1, 1, 64, true, None);
    let sectors_desc_offset = 13 + 76 + 94 + 76 + 24 + 4;
    let hash_desc_offset = bytes.len() - 76;
    let done_desc_offset = hash_desc_offset + 76 + hash.len();
    bytes[sectors_desc_offset + 16..sectors_desc_offset + 24]
        .copy_from_slice(&(hash_desc_offset as u64).to_le_bytes());
    bytes.truncate(hash_desc_offset);
    bytes.extend_from_slice(&section_desc(
        b"hash",
        done_desc_offset as u64,
        76 + hash.len() as u64,
    ));
    bytes.extend_from_slice(hash);
    bytes.extend_from_slice(&section_desc(b"done", 0, 76));
    write_temp_with_suffix(".E01", &bytes)
}

fn ewf1_bytes_with_metadata_section(
    data: &[u8],
    segment_number: u16,
    total_chunks: u32,
    total_sectors: u64,
    section_type: &[u8],
    metadata: &[u8],
) -> Vec<u8> {
    ewf1_bytes_with_metadata_sections(
        data,
        segment_number,
        total_chunks,
        total_sectors,
        &[(section_type, metadata)],
    )
}

fn ewf1_bytes_with_metadata_sections(
    data: &[u8],
    segment_number: u16,
    total_chunks: u32,
    total_sectors: u64,
    metadata_sections: &[(&[u8], &[u8])],
) -> Vec<u8> {
    let chunk_size = 32_768_usize;
    let payload = compressed_chunk(data, chunk_size);
    let volume_data_size = 1052_u64;

    let volume_desc_offset = 13_u64;
    let volume_data_offset = volume_desc_offset + 76;
    let first_metadata_desc_offset = volume_data_offset + volume_data_size;
    let metadata_size = metadata_sections
        .iter()
        .map(|(_, metadata)| 76 + metadata.len() as u64)
        .sum::<u64>();
    let table_desc_offset = first_metadata_desc_offset + metadata_size;
    let table_data_offset = table_desc_offset + 76;
    let table_entries_offset = table_data_offset + 24;
    let sectors_desc_offset = table_entries_offset + 4;
    let sectors_data_offset = sectors_desc_offset + 76;
    let done_desc_offset = sectors_data_offset + payload.len() as u64;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(1);
    bytes.extend_from_slice(&segment_number.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());

    bytes.extend_from_slice(&section_desc(
        b"volume",
        if metadata_sections.is_empty() {
            table_desc_offset
        } else {
            first_metadata_desc_offset
        },
        76 + volume_data_size,
    ));
    let mut volume = vec![0; volume_data_size as usize];
    volume[4..8].copy_from_slice(&total_chunks.to_le_bytes());
    volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
    volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
    volume[16..24].copy_from_slice(&total_sectors.to_le_bytes());
    bytes.extend_from_slice(&volume);

    let mut metadata_desc_offset = first_metadata_desc_offset;
    for (index, (section_type, metadata)) in metadata_sections.iter().enumerate() {
        let next = if index + 1 == metadata_sections.len() {
            table_desc_offset
        } else {
            metadata_desc_offset + 76 + metadata.len() as u64
        };
        bytes.extend_from_slice(&section_desc(
            section_type,
            next,
            76 + metadata.len() as u64,
        ));
        bytes.extend_from_slice(metadata);
        metadata_desc_offset = next;
    }

    bytes.extend_from_slice(&section_desc(b"table", sectors_desc_offset, 76 + 24 + 4));
    let mut table_header = [0; 24];
    table_header[0..4].copy_from_slice(&1_u32.to_le_bytes());
    table_header[8..16].copy_from_slice(&sectors_data_offset.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    bytes.extend_from_slice(&0x8000_0000_u32.to_le_bytes());

    bytes.extend_from_slice(&section_desc(
        b"sectors",
        done_desc_offset,
        76 + payload.len() as u64,
    ));
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(&section_desc(b"done", 0, 76));

    bytes
}

fn synthetic_e01_with_header_text(data: &[u8], header_text: &str) -> NamedTempFile {
    let bytes = ewf1_bytes_with_metadata_section(data, 1, 1, 64, b"header", header_text.as_bytes());
    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_s01_with_header_text(data: &[u8], header_text: &str) -> NamedTempFile {
    let mut bytes =
        ewf1_bytes_with_metadata_section(data, 1, 1, 64, b"header", header_text.as_bytes());
    let volume_data_offset = 13 + 76;
    bytes[volume_data_offset + 85..volume_data_offset + 90].copy_from_slice(b"SMART");
    write_temp_with_suffix(".s01", &bytes)
}

fn synthetic_e01_full_volume_with_suffix(data: &[u8], suffix: &str) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let payload = compressed_chunk(data, chunk_size);
    let volume_data_size = 1052_u64;

    let volume_desc_offset = 13_u64;
    let volume_data_offset = volume_desc_offset + 76;
    let table_desc_offset = volume_data_offset + volume_data_size;
    let table_data_offset = table_desc_offset + 76;
    let table_entries_offset = table_data_offset + 24;
    let sectors_desc_offset = table_entries_offset + 4;
    let sectors_data_offset = sectors_desc_offset + 76;
    let done_desc_offset = sectors_data_offset + payload.len() as u64;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());

    bytes.extend_from_slice(&section_desc(
        b"volume",
        table_desc_offset,
        76 + volume_data_size,
    ));
    let mut volume = vec![0; volume_data_size as usize];
    volume[4..8].copy_from_slice(&1_u32.to_le_bytes());
    volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
    volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
    volume[16..24].copy_from_slice(&64_u64.to_le_bytes());
    bytes.extend_from_slice(&volume);

    bytes.extend_from_slice(&section_desc(b"table", sectors_desc_offset, 76 + 24 + 4));
    let mut table_header = [0; 24];
    table_header[0..4].copy_from_slice(&1_u32.to_le_bytes());
    table_header[8..16].copy_from_slice(&sectors_data_offset.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    bytes.extend_from_slice(&0x8000_0000_u32.to_le_bytes());

    bytes.extend_from_slice(&section_desc(
        b"sectors",
        done_desc_offset,
        76 + payload.len() as u64,
    ));
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(&section_desc(b"done", 0, 76));

    write_temp_with_suffix(suffix, &bytes)
}

fn ewf1_bytes(
    data: &[u8],
    signature: [u8; 8],
    segment_number: u16,
    total_chunks: u32,
    total_sectors: u64,
    is_compressed: bool,
    digest: Option<([u8; 16], [u8; 20])>,
) -> Vec<u8> {
    let digest_payload = digest.map(|(md5, sha1)| ewf1_digest_payload(md5, sha1));
    ewf1_bytes_with_options(
        data,
        Ewf1BytesOptions {
            signature,
            segment_number,
            total_chunks,
            total_sectors,
            is_compressed,
            compression_level: 0,
            digest: digest_payload.as_deref(),
            media_section_type: b"volume",
        },
    )
}

fn ewf1_digest_payload(md5: [u8; 16], sha1: [u8; 20]) -> Vec<u8> {
    let mut digest = Vec::with_capacity(80);
    digest.extend_from_slice(&md5);
    digest.extend_from_slice(&sha1);
    digest.extend_from_slice(&[0; 40]);
    let checksum = adler32(&digest);
    digest.extend_from_slice(&checksum.to_le_bytes());
    digest
}

fn ewf1_hash_payload(md5: [u8; 16]) -> Vec<u8> {
    let mut hash = Vec::with_capacity(36);
    hash.extend_from_slice(&md5);
    hash.extend_from_slice(&[0; 16]);
    let checksum = adler32(&hash);
    hash.extend_from_slice(&checksum.to_le_bytes());
    hash
}

fn ewf1_session_payload(entries: &[(u32, u32)]) -> Vec<u8> {
    let mut payload = vec![0; 36];
    payload[0..4].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    let header_checksum = adler32(&payload[..32]);
    payload[32..36].copy_from_slice(&header_checksum.to_le_bytes());

    let entries_start = payload.len();
    for (start_sector, flags) in entries {
        payload.extend_from_slice(&flags.to_le_bytes());
        payload.extend_from_slice(&start_sector.to_le_bytes());
        payload.extend_from_slice(&[0; 24]);
    }
    let entries_checksum = adler32(&payload[entries_start..]);
    payload.extend_from_slice(&entries_checksum.to_le_bytes());
    payload
}

fn ewf1_error2_payload(entries: &[(u32, u32)]) -> Vec<u8> {
    let mut payload = vec![0; 520];
    payload[0..4].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    let header_checksum = adler32(&payload[..516]);
    payload[516..520].copy_from_slice(&header_checksum.to_le_bytes());

    let entries_start = payload.len();
    for (first_sector, sector_count) in entries {
        payload.extend_from_slice(&first_sector.to_le_bytes());
        payload.extend_from_slice(&sector_count.to_le_bytes());
    }
    let entries_checksum = adler32(&payload[entries_start..]);
    payload.extend_from_slice(&entries_checksum.to_le_bytes());
    payload
}

fn ewf1_ltree_payload(single_files_data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(48 + single_files_data.len());
    let mut hasher = Md5::new();
    hasher.update(single_files_data);
    payload.extend_from_slice(&hasher.finalize());
    payload.extend_from_slice(&(single_files_data.len() as u64).to_le_bytes());
    payload.extend_from_slice(&0_u32.to_le_bytes());
    payload.extend_from_slice(&[0; 20]);
    let checksum = adler32(&payload[..48]);
    payload[24..28].copy_from_slice(&checksum.to_le_bytes());
    payload.extend_from_slice(single_files_data);
    payload
}

fn ewf1_metadata_segment_bytes(
    segment_number: u16,
    media_section_type: &[u8],
    set_identifier: [u8; 16],
) -> Vec<u8> {
    let media_desc_offset = 13_u64;
    let media_data_size = 1052_u64;
    let done_desc_offset = media_desc_offset + 76 + media_data_size;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(1);
    bytes.extend_from_slice(&segment_number.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());

    bytes.extend_from_slice(&section_desc(
        media_section_type,
        done_desc_offset,
        76 + media_data_size,
    ));
    let mut media = vec![0; media_data_size as usize];
    media[8..12].copy_from_slice(&64_u32.to_le_bytes());
    media[12..16].copy_from_slice(&512_u32.to_le_bytes());
    media[64..80].copy_from_slice(&set_identifier);
    bytes.extend_from_slice(&media);
    bytes.extend_from_slice(&section_desc(b"done", 0, 76));

    bytes
}

fn synthetic_l01_with_ltree(data: &[u8], single_files_data: &[u8]) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let payload = compressed_chunk(data, chunk_size);
    let ltree = ewf1_ltree_payload(single_files_data);

    let volume_desc_offset = 13_u64;
    let volume_data_offset = volume_desc_offset + 76;
    let table_desc_offset = volume_data_offset + 94;
    let table_data_offset = table_desc_offset + 76;
    let table_entries_offset = table_data_offset + 24;
    let ltree_desc_offset = table_entries_offset + 4;
    let sectors_desc_offset = ltree_desc_offset + 76 + ltree.len() as u64;
    let sectors_data_offset = sectors_desc_offset + 76;
    let done_desc_offset = sectors_data_offset + payload.len() as u64;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&LVF_SIGNATURE);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());

    bytes.extend_from_slice(&section_desc(b"volume", table_desc_offset, 76 + 94));
    let mut volume = [0; 94];
    volume[4..8].copy_from_slice(&1_u32.to_le_bytes());
    volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
    volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
    volume[16..24].copy_from_slice(&64_u64.to_le_bytes());
    bytes.extend_from_slice(&volume);

    bytes.extend_from_slice(&section_desc(b"table", ltree_desc_offset, 76 + 24 + 4));
    let mut table_header = [0; 24];
    table_header[0..4].copy_from_slice(&1_u32.to_le_bytes());
    table_header[8..16].copy_from_slice(&sectors_data_offset.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    bytes.extend_from_slice(&0x8000_0000_u32.to_le_bytes());

    bytes.extend_from_slice(&section_desc(
        b"ltree",
        sectors_desc_offset,
        76 + ltree.len() as u64,
    ));
    bytes.extend_from_slice(&ltree);
    bytes.extend_from_slice(&section_desc(
        b"sectors",
        done_desc_offset,
        76 + payload.len() as u64,
    ));
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(&section_desc(b"done", 0, 76));

    write_temp_with_suffix(".L01", &bytes)
}

fn synthetic_e01_with_error2(data: &[u8]) -> NamedTempFile {
    synthetic_e01_with_error2_payload(data, &ewf1_error2_payload(&[(2, 3), (40, 2)]))
}

fn synthetic_e01_with_error2_payload(data: &[u8], error2: &[u8]) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let payload = compressed_chunk(data, chunk_size);

    let volume_desc_offset = 13_u64;
    let volume_data_offset = volume_desc_offset + 76;
    let error2_desc_offset = volume_data_offset + 94;
    let error2_data_offset = error2_desc_offset + 76;
    let table_desc_offset = error2_data_offset + error2.len() as u64;
    let table_data_offset = table_desc_offset + 76;
    let table_entries_offset = table_data_offset + 24;
    let sectors_desc_offset = table_entries_offset + 4;
    let sectors_data_offset = sectors_desc_offset + 76;
    let done_desc_offset = sectors_data_offset + payload.len() as u64;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());

    bytes.extend_from_slice(&section_desc(b"volume", error2_desc_offset, 76 + 94));
    let mut volume = [0; 94];
    volume[4..8].copy_from_slice(&1_u32.to_le_bytes());
    volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
    volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
    volume[16..24].copy_from_slice(&64_u64.to_le_bytes());
    bytes.extend_from_slice(&volume);

    bytes.extend_from_slice(&section_desc(
        b"error2",
        table_desc_offset,
        76 + error2.len() as u64,
    ));
    bytes.extend_from_slice(error2);

    bytes.extend_from_slice(&section_desc(b"table", sectors_desc_offset, 76 + 24 + 4));
    let mut table_header = [0; 24];
    table_header[0..4].copy_from_slice(&1_u32.to_le_bytes());
    table_header[8..16].copy_from_slice(&sectors_data_offset.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    bytes.extend_from_slice(&0x8000_0000_u32.to_le_bytes());

    bytes.extend_from_slice(&section_desc(
        b"sectors",
        done_desc_offset,
        76 + payload.len() as u64,
    ));
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(&section_desc(b"done", 0, 76));

    write_temp_with_suffix(".E01", &bytes)
}

fn synthetic_e01_with_session_tracks(data: &[u8]) -> NamedTempFile {
    synthetic_e01_with_session_payload(
        data,
        &ewf1_session_payload(&[(0, 0), (0, 1), (4, 0), (4, 1)]),
    )
}

fn synthetic_e01_with_session_payload(data: &[u8], session: &[u8]) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let payload = compressed_chunk(data, chunk_size);

    let volume_desc_offset = 13_u64;
    let volume_data_offset = volume_desc_offset + 76;
    let session_desc_offset = volume_data_offset + 94;
    let session_data_offset = session_desc_offset + 76;
    let table_desc_offset = session_data_offset + session.len() as u64;
    let table_data_offset = table_desc_offset + 76;
    let table_entries_offset = table_data_offset + 24;
    let sectors_desc_offset = table_entries_offset + 4;
    let sectors_data_offset = sectors_desc_offset + 76;
    let done_desc_offset = sectors_data_offset + payload.len() as u64;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVF_SIGNATURE);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());

    bytes.extend_from_slice(&section_desc(b"volume", session_desc_offset, 76 + 94));
    let mut volume = [0; 94];
    volume[4..8].copy_from_slice(&1_u32.to_le_bytes());
    volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
    volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
    volume[16..24].copy_from_slice(&64_u64.to_le_bytes());
    bytes.extend_from_slice(&volume);

    bytes.extend_from_slice(&section_desc(
        b"session",
        table_desc_offset,
        76 + session.len() as u64,
    ));
    bytes.extend_from_slice(session);

    bytes.extend_from_slice(&section_desc(b"table", sectors_desc_offset, 76 + 24 + 4));
    let mut table_header = [0; 24];
    table_header[0..4].copy_from_slice(&1_u32.to_le_bytes());
    table_header[8..16].copy_from_slice(&sectors_data_offset.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    bytes.extend_from_slice(&0x8000_0000_u32.to_le_bytes());

    bytes.extend_from_slice(&section_desc(
        b"sectors",
        done_desc_offset,
        76 + payload.len() as u64,
    ));
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(&section_desc(b"done", 0, 76));

    write_temp_with_suffix(".E01", &bytes)
}

fn ewf1_bytes_with_options(data: &[u8], options: Ewf1BytesOptions<'_>) -> Vec<u8> {
    let chunk_size = 32_768_usize;
    let payload = if options.is_compressed {
        compressed_chunk(data, chunk_size)
    } else {
        let mut padded = data.to_vec();
        padded.resize(chunk_size, 0);
        padded
    };

    let volume_desc_offset = 13_u64;
    let volume_data_offset = volume_desc_offset + 76;
    let table_desc_offset = volume_data_offset + 94;
    let table_data_offset = table_desc_offset + 76;
    let table_entries_offset = table_data_offset + 24;
    let sectors_desc_offset = table_entries_offset + 4;
    let sectors_data_offset = sectors_desc_offset + 76;
    let digest_size = options.digest.map_or(0, |digest| digest.len() as u64);
    let digest_desc_offset = sectors_data_offset + payload.len() as u64;
    let done_desc_offset = if options.digest.is_some() {
        digest_desc_offset + 76 + digest_size
    } else {
        digest_desc_offset
    };

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&options.signature);
    bytes.push(1);
    bytes.extend_from_slice(&options.segment_number.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());

    bytes.extend_from_slice(&section_desc(
        options.media_section_type,
        table_desc_offset,
        76 + 94,
    ));
    let mut volume = [0; 94];
    volume[4..8].copy_from_slice(&options.total_chunks.to_le_bytes());
    volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
    volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
    volume[16..24].copy_from_slice(&options.total_sectors.to_le_bytes());
    volume[52] = options.compression_level;
    bytes.extend_from_slice(&volume);

    bytes.extend_from_slice(&section_desc(b"table", sectors_desc_offset, 76 + 24 + 4));
    let mut table_header = [0; 24];
    table_header[0..4].copy_from_slice(&1_u32.to_le_bytes());
    table_header[8..16].copy_from_slice(&sectors_data_offset.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let entry = if options.is_compressed {
        0x8000_0000_u32
    } else {
        0
    };
    bytes.extend_from_slice(&entry.to_le_bytes());

    bytes.extend_from_slice(&section_desc(
        b"sectors",
        if options.digest.is_some() {
            digest_desc_offset
        } else {
            done_desc_offset
        },
        76 + payload.len() as u64,
    ));
    bytes.extend_from_slice(&payload);
    if let Some(digest) = options.digest {
        bytes.extend_from_slice(&section_desc(b"digest", done_desc_offset, 76 + digest_size));
        bytes.extend_from_slice(digest);
    }
    bytes.extend_from_slice(&section_desc(b"done", 0, 76));

    bytes
}

fn write_temp_with_suffix(suffix: &str, bytes: &[u8]) -> NamedTempFile {
    let mut file = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
    file.write_all(bytes).unwrap();
    file.flush().unwrap();
    file
}

fn writer_e01_with_bad_raw_chunk_checksum() -> NamedTempFile {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad-checksum.E01");
    let mut writer =
        ewf_image::EwfWriter::create(&path, ewf_image::WriteOptions::default()).unwrap();
    writer.write_all(b"bad raw checksum").unwrap();
    writer.finish().unwrap();

    let mut bytes = std::fs::read(&path).unwrap();
    corrupt_ewf1_section_trailing_checksum(&mut bytes, b"sectors");
    write_temp_with_suffix(".E01", &bytes)
}

fn writer_ex01_with_bad_raw_chunk_checksum() -> NamedTempFile {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad-checksum.Ex01");
    let options = ewf_image::WriteOptions {
        format: ewf_image::WriteFormat::Ewf2Physical,
        ..ewf_image::WriteOptions::default()
    };
    let mut writer = ewf_image::EwfWriter::create(&path, options).unwrap();
    writer.write_all(b"bad raw checksum").unwrap();
    writer.finish().unwrap();

    let mut bytes = std::fs::read(&path).unwrap();
    corrupt_ewf2_section_trailing_checksum(&mut bytes, 0x03);
    write_temp_with_suffix(".Ex01", &bytes)
}

fn writer_e01_with_bad_table_header_checksum() -> NamedTempFile {
    let mut bytes = writer_image_bytes("bad-table-header.E01", ewf_image::WriteOptions::default());
    corrupt_ewf1_section_data_byte(&mut bytes, b"table", 20);
    write_temp_with_suffix(".E01", &bytes)
}

fn writer_e01_with_bad_table_entries_checksum() -> NamedTempFile {
    let mut bytes = writer_image_bytes("bad-table-entries.E01", ewf_image::WriteOptions::default());
    corrupt_ewf1_section_data_byte(&mut bytes, b"table", 28);
    write_temp_with_suffix(".E01", &bytes)
}

fn writer_ex01_with_bad_table_header_checksum() -> NamedTempFile {
    let options = ewf_image::WriteOptions {
        format: ewf_image::WriteFormat::Ewf2Physical,
        ..ewf_image::WriteOptions::default()
    };
    let mut bytes = writer_image_bytes("bad-table-header.Ex01", options);
    corrupt_ewf2_section_data_byte(&mut bytes, 0x04, 16);
    write_temp_with_suffix(".Ex01", &bytes)
}

fn writer_ex01_with_bad_table_entries_checksum() -> NamedTempFile {
    let options = ewf_image::WriteOptions {
        format: ewf_image::WriteFormat::Ewf2Physical,
        ..ewf_image::WriteOptions::default()
    };
    let mut bytes = writer_image_bytes("bad-table-entries.Ex01", options);
    corrupt_ewf2_section_data_byte(&mut bytes, 0x04, 48);
    write_temp_with_suffix(".Ex01", &bytes)
}

fn writer_e01_with_bad_descriptor_checksum() -> NamedTempFile {
    let mut bytes = writer_image_bytes("bad-descriptor.E01", ewf_image::WriteOptions::default());
    corrupt_ewf1_section_descriptor_checksum(&mut bytes, b"volume");
    write_temp_with_suffix(".E01", &bytes)
}

fn writer_e01_with_bad_volume_checksum() -> NamedTempFile {
    let mut bytes = writer_image_bytes("bad-volume.E01", ewf_image::WriteOptions::default());
    corrupt_ewf1_section_trailing_checksum(&mut bytes, b"volume");
    write_temp_with_suffix(".E01", &bytes)
}

fn writer_ex01_with_bad_descriptor_checksum() -> NamedTempFile {
    let options = ewf_image::WriteOptions {
        format: ewf_image::WriteFormat::Ewf2Physical,
        ..ewf_image::WriteOptions::default()
    };
    let mut bytes = writer_image_bytes("bad-descriptor.Ex01", options);
    corrupt_ewf2_section_descriptor_checksum(&mut bytes, 0x01);
    write_temp_with_suffix(".Ex01", &bytes)
}

fn writer_image_bytes(filename: &str, options: ewf_image::WriteOptions) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(filename);
    let mut writer = ewf_image::EwfWriter::create(&path, options).unwrap();
    writer.write_all(b"table checksum").unwrap();
    writer.finish().unwrap();
    std::fs::read(&path).unwrap()
}

fn corrupt_ewf1_section_trailing_checksum(bytes: &mut [u8], section_type: &[u8]) {
    let (offset, section_size) = ewf1_section_range(bytes, section_type);
    bytes[offset + section_size - 4] ^= 0xff;
}

fn corrupt_ewf1_section_data_byte(bytes: &mut [u8], section_type: &[u8], relative_offset: usize) {
    let (offset, section_size) = ewf1_section_range(bytes, section_type);
    assert!(relative_offset < section_size);
    bytes[offset + relative_offset] ^= 0xff;
}

fn corrupt_ewf1_section_descriptor_checksum(bytes: &mut [u8], section_type: &[u8]) {
    let offset = ewf1_section_descriptor_offset(bytes, section_type);
    bytes[offset + 72] ^= 0xff;
}

fn ewf1_section_range(bytes: &[u8], section_type: &[u8]) -> (usize, usize) {
    let offset = ewf1_section_descriptor_offset(bytes, section_type);
    let desc = bytes
        .get(offset..offset + 76)
        .expect("EWF1 section descriptor exists");
    let section_size = u64::from_le_bytes(desc[24..32].try_into().unwrap()) as usize;
    (offset + 76, section_size - 76)
}

fn ewf1_section_descriptor_offset(bytes: &[u8], section_type: &[u8]) -> usize {
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
        if current_type == section_type {
            return offset;
        }
        assert!(next != 0 && current_type != b"done");
        offset = next;
    }
}

fn corrupt_ewf2_section_trailing_checksum(bytes: &mut [u8], section_type: u32) {
    let (offset, data_size) = ewf2_section_range(bytes, section_type);
    bytes[offset + data_size - 4] ^= 0xff;
}

fn corrupt_ewf2_section_data_byte(bytes: &mut [u8], section_type: u32, relative_offset: usize) {
    let (offset, data_size) = ewf2_section_range(bytes, section_type);
    assert!(relative_offset < data_size);
    bytes[offset + relative_offset] ^= 0xff;
}

fn corrupt_ewf2_section_descriptor_checksum(bytes: &mut [u8], section_type: u32) {
    let offset = ewf2_section_descriptor_offset(bytes, section_type);
    bytes[offset + 60] ^= 0xff;
}

fn ewf2_section_range(bytes: &[u8], section_type: u32) -> (usize, usize) {
    let section = ewf2_section_location(bytes, section_type);
    (section.data_offset, section.data_size)
}

fn ewf2_section_descriptor_offset(bytes: &[u8], section_type: u32) -> usize {
    ewf2_section_location(bytes, section_type).desc_offset
}

#[derive(Clone, Copy)]
struct Ewf2SectionLocation {
    data_offset: usize,
    data_size: usize,
    desc_offset: usize,
}

fn ewf2_section_location(bytes: &[u8], section_type: u32) -> Ewf2SectionLocation {
    ewf2_leading_section_location(bytes, section_type)
        .unwrap_or_else(|| ewf2_trailing_section_location(bytes, section_type))
}

fn ewf2_leading_section_location(bytes: &[u8], section_type: u32) -> Option<Ewf2SectionLocation> {
    let mut offset = 32;
    loop {
        let desc = bytes.get(offset..offset + 64)?;
        let current_type = u32::from_le_bytes(desc[0..4].try_into().unwrap());
        let data_size = u64::from_le_bytes(desc[16..24].try_into().unwrap()) as usize;
        let descriptor_size = u32::from_le_bytes(desc[24..28].try_into().unwrap()) as usize;
        if descriptor_size != 64 {
            return None;
        }
        let data_offset = offset + descriptor_size;
        bytes.get(data_offset..data_offset.checked_add(data_size)?)?;
        if current_type == section_type {
            return Some(Ewf2SectionLocation {
                data_offset,
                data_size,
                desc_offset: offset,
            });
        }
        if matches!(current_type, 0x0d | 0x0f) {
            return None;
        }
        offset = data_offset.checked_add(data_size)?;
    }
}

fn ewf2_trailing_section_location(bytes: &[u8], section_type: u32) -> Ewf2SectionLocation {
    let mut offset = bytes
        .len()
        .checked_sub(64)
        .expect("EWF2 terminal descriptor exists");
    loop {
        let desc = bytes
            .get(offset..offset + 64)
            .expect("EWF2 trailing section descriptor exists");
        let current_type = u32::from_le_bytes(desc[0..4].try_into().unwrap());
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
        if current_type == section_type {
            return Ewf2SectionLocation {
                data_offset,
                data_size,
                desc_offset: offset,
            };
        }
        assert!(
            previous_offset != 0,
            "EWF2 section {section_type:#x} not found"
        );
        offset = previous_offset;
    }
}

fn ewf2_desc(section_type: u32, data_size: u64, previous_offset: u64) -> [u8; 64] {
    ewf2_desc_with_flags(section_type, 0, data_size, previous_offset)
}

fn ewf2_desc_with_flags(
    section_type: u32,
    data_flags: u32,
    data_size: u64,
    previous_offset: u64,
) -> [u8; 64] {
    let mut desc = [0; 64];
    desc[0..4].copy_from_slice(&section_type.to_le_bytes());
    desc[4..8].copy_from_slice(&data_flags.to_le_bytes());
    desc[8..16].copy_from_slice(&previous_offset.to_le_bytes());
    desc[16..24].copy_from_slice(&data_size.to_le_bytes());
    desc[24..28].copy_from_slice(&64_u32.to_le_bytes());
    desc
}

fn ewf2_desc_with_integrity_hash(section_type: u32, data: &[u8], previous_offset: u64) -> [u8; 64] {
    use md5::{Digest as _, Md5};

    let mut desc = ewf2_desc_with_flags(section_type, 0x01, data.len() as u64, previous_offset);
    let mut hasher = Md5::new();
    hasher.update(data);
    desc[32..48].copy_from_slice(&hasher.finalize());
    desc
}

fn utf16le(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn utf16le_lines<I, S>(lines: I) -> Vec<u8>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let text = lines
        .into_iter()
        .map(|line| line.as_ref().to_owned())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    utf16le(&text)
}

fn default_single_files_prefix() -> Vec<String> {
    [
        "5", "rec", "tb", "4096", "", "perm", "0\t1", "pt", "0\t0", "10", "", "srce", "0\t1", "id",
        "0\t0", "0", "", "sub", "0\t1", "id", "0\t0", "0", "",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn single_files_stream_with_default_categories(entry_lines: &[&str]) -> Vec<u8> {
    let mut lines = default_single_files_prefix();
    lines.extend(entry_lines.iter().map(|line| (*line).to_owned()));
    utf16le_lines(lines)
}

fn single_files_stream_with_record_prefix(category_lines: &[&str]) -> Vec<u8> {
    let mut lines = ["5", "rec", "tb", "4096", ""]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    lines.extend(category_lines.iter().map(|line| (*line).to_owned()));
    utf16le_lines(lines)
}

fn single_files_stream_with_permission_prefix(category_lines: &[&str]) -> Vec<u8> {
    let mut lines = [
        "5", "rec", "tb", "4096", "", "perm", "0\t1", "pt", "0\t0", "10", "",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    lines.extend(category_lines.iter().map(|line| (*line).to_owned()));
    utf16le_lines(lines)
}

fn single_files_stream_with_source_prefix(category_lines: &[&str]) -> Vec<u8> {
    let mut lines = [
        "5", "rec", "tb", "4096", "", "perm", "0\t1", "pt", "0\t0", "10", "", "srce", "0\t1", "id",
        "0\t0", "0", "",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    lines.extend(category_lines.iter().map(|line| (*line).to_owned()));
    utf16le_lines(lines)
}

fn single_files_stream_with_entry_tree() -> Vec<u8> {
    let text = [
        "5",
        "rec",
        "tb",
        "4096",
        "",
        "perm",
        "0\t1",
        "pt",
        "0\t0",
        "10",
        "",
        "srce",
        "0\t1",
        "id",
        "0\t0",
        "0",
        "",
        "sub",
        "0\t1",
        "id",
        "0\t0",
        "0",
        "",
        "entry",
        "0\t1",
        "id\tp\tn\tls\tlo\tpo\tcr\twr\tac\tmo\tdl\tsrc\tsub\tpm\tcid\topr\tbe\tha\tsha",
        "26\t1",
        "1\td\troot\t0\t0\t0\t0\t0\t0\t0\t-1\t0\t0\t0\t0\t0\t\t\t",
        "26\t0",
        "2\tf\treport.txt\t11\t4096\t8192\t1700000000\t1700000100\t1700000200\t1700000300\t-1\t1\t7\t0\t3\t4\t2 13135c1 3f44 S 2000 10\t00112233445566778899aabbccddeeff\t00112233445566778899aabbccddeeff00112233",
        "",
    ]
    .join("\n")
        + "\n";
    utf16le(&text)
}

fn single_files_stream_with_nested_entry_tree() -> Vec<u8> {
    single_files_stream_with_default_categories(&[
        "entry",
        "0\t1",
        "id\tp\tn\tls",
        "26\t1",
        "1\td\troot\t0",
        "26\t1",
        "2\td\tUsers\t0",
        "26\t0",
        "3\tf\tntuser.dat\t128",
        "",
    ])
}

fn single_files_stream_with_entry_guid() -> Vec<u8> {
    single_files_stream_with_default_categories(&[
        "entry",
        "0\t1",
        "id\tp\tmid\tn\tls",
        "26\t1",
        "1\td\t\troot\t0",
        "26\t0",
        "2\tf\t00112233445566778899aabbccddeeff\treport.txt\t11",
        "",
    ])
}

fn single_files_stream_with_uppercase_entry_base16() -> Vec<u8> {
    single_files_stream_with_default_categories(&[
        "entry",
        "0\t1",
        "id\tp\tn\tls\tha\tsha",
        "26\t0",
        "1\tf\treport.txt\t11\tAABBCCDDEEFF\tAABBCCDDEEFF00112233",
        "",
    ])
}

fn single_files_stream_with_zero_entry_base16() -> Vec<u8> {
    single_files_stream_with_default_categories(&[
        "entry",
        "0\t1",
        "id\tp\tmid\tn\tls\tha\tsha",
        "26\t0",
        "1\tf\t00000000000000000000000000000000\treport.txt\t11\t0000\t0000",
        "",
    ])
}

fn single_files_stream_with_invalid_entry_base16() -> Vec<u8> {
    single_files_stream_with_default_categories(&[
        "entry",
        "0\t1",
        "id\tp\tn\tls\tha",
        "26\t0",
        "1\tf\treport.txt\t11\t001g",
        "",
    ])
}

fn single_files_stream_with_entry_short_name() -> Vec<u8> {
    single_files_stream_with_default_categories(&[
        "entry",
        "0\t1",
        "id\tp\tn\tls\tsnh",
        "26\t0",
        "1\tf\treport.txt\t11\t13 REPORT~1.TXT",
        "",
    ])
}

fn single_files_stream_with_plain_entry_short_name() -> Vec<u8> {
    single_files_stream_with_default_categories(&[
        "entry",
        "0\t1",
        "id\tp\tn\tls\tsnh",
        "26\t0",
        "1\tf\treport.txt\t11\tREPORT~1.TXT",
        "",
    ])
}

fn single_files_stream_with_entry_missing_trailing_values() -> Vec<u8> {
    single_files_stream_with_default_categories(&[
        "entry",
        "0\t1",
        "id\tp\tn\tls",
        "26\t0",
        "1\tf\treport.txt",
        "",
    ])
}

fn single_files_stream_with_entry_extra_trailing_values() -> Vec<u8> {
    single_files_stream_with_default_categories(&[
        "entry",
        "0\t1",
        "id\tp\tn\tls",
        "26\t0",
        "1\tf\treport.txt\t11\tignored",
        "",
    ])
}

fn single_files_stream_with_unsupported_entry_count_shape() -> Vec<u8> {
    single_files_stream_with_default_categories(&[
        "entry",
        "0\t2",
        "id\tp\tn\tls",
        "26\t0",
        "1\tf\treport.txt\t11",
        "",
    ])
}

fn single_files_stream_with_unsupported_entry_child_count_parent_value() -> Vec<u8> {
    single_files_stream_with_default_categories(&[
        "entry",
        "0\t1",
        "id\tp\tn\tls",
        "27\t0",
        "1\tf\treport.txt\t11",
        "",
    ])
}

fn single_files_stream_with_empty_entry_type() -> Vec<u8> {
    single_files_stream_with_default_categories(&[
        "entry",
        "0\t1",
        "id\t\tls",
        "26\t0",
        "1\tignored\t11",
        "",
    ])
}

fn single_files_stream_with_non_empty_entry_terminator() -> Vec<u8> {
    single_files_stream_with_default_categories(&[
        "entry",
        "0\t1",
        "id\tp\tn\tls",
        "26\t0",
        "1\tf\treport.txt\t11",
        "unexpected",
        "",
    ])
}

fn single_files_stream_with_non_empty_record_terminator() -> Vec<u8> {
    let text = [
        "5",
        "rec",
        "tb",
        "4096",
        "unexpected",
        "entry",
        "0\t1",
        "id\tp\tn\tls",
        "26\t0",
        "1\tf\treport.txt\t11",
        "",
    ]
    .join("\n")
        + "\n";
    utf16le(&text)
}

fn single_files_stream_without_record_category() -> Vec<u8> {
    let text = [
        "5",
        "entry",
        "0\t1",
        "id\tp\tn\tls",
        "26\t0",
        "1\tf\treport.txt\t11",
        "",
    ]
    .join("\n")
        + "\n";
    utf16le(&text)
}

fn single_files_stream_with_empty_record_type() -> Vec<u8> {
    let text = [
        "5",
        "rec",
        "tb\t",
        "4096\tignored",
        "",
        "entry",
        "0\t1",
        "id\tp\tn\tls",
        "26\t0",
        "1\tf\treport.txt\t11",
        "",
    ]
    .join("\n")
        + "\n";
    utf16le(&text)
}

fn single_files_stream_with_non_empty_source_terminator() -> Vec<u8> {
    single_files_stream_with_permission_prefix(&[
        "srce",
        "1\t1",
        "id\tn",
        "0\t1",
        "0\troot-source",
        "0\t0",
        "1\tDisk 1",
        "unexpected",
        "entry",
        "0\t1",
        "id\tp\tn\tls\tsrc",
        "26\t0",
        "1\tf\treport.txt\t11\t1",
        "",
    ])
}

fn single_files_stream_with_unsupported_source_count_shape() -> Vec<u8> {
    single_files_stream_with_permission_prefix(&[
        "srce",
        "0\t2",
        "id\tn",
        "0\t2",
        "0\troot-source",
        "0\t0",
        "1\tDisk 1",
        "0\t0",
        "2\tDisk 2",
        "",
        "entry",
        "0\t1",
        "id\tp\tn\tls\tsrc",
        "26\t0",
        "1\tf\treport.txt\t11\t1",
        "",
    ])
}

fn single_files_stream_with_extra_source_values() -> Vec<u8> {
    single_files_stream_with_permission_prefix(&[
        "srce",
        "0\t1",
        "id",
        "0\t0",
        "0\tignored",
        "",
        "sub",
        "0\t1",
        "id",
        "0\t0",
        "0",
        "",
        "entry",
        "0\t1",
        "id\tp\tn\tls\tsrc",
        "26\t0",
        "1\tf\treport.txt\t11\t0",
        "",
    ])
}

fn single_files_stream_with_negative_source_identifier() -> Vec<u8> {
    single_files_stream_with_permission_prefix(&[
        "srce",
        "0\t1",
        "id",
        "0\t0",
        "-1",
        "",
        "sub",
        "0\t1",
        "id",
        "0\t0",
        "0",
        "",
        "entry",
        "0\t1",
        "id\tp\tn\tls\tsrc",
        "26\t0",
        "1\tf\treport.txt\t11\t0",
        "",
    ])
}

fn single_files_stream_with_mismatched_source_identifier() -> Vec<u8> {
    single_files_stream_with_permission_prefix(&[
        "srce",
        "1\t1",
        "id\tn",
        "0\t1",
        "0\troot-source",
        "0\t0",
        "2\tDisk 2",
        "",
        "sub",
        "0\t1",
        "id",
        "0\t0",
        "0",
        "",
        "entry",
        "0\t1",
        "id\tp\tn\tls\tsrc",
        "26\t0",
        "1\tf\treport.txt\t11\t2",
        "",
    ])
}

fn single_files_stream_with_invalid_source_base16() -> Vec<u8> {
    single_files_stream_with_permission_prefix(&[
        "srce",
        "0\t1",
        "id\tgu",
        "0\t0",
        "0\tzzzz",
        "",
        "sub",
        "0\t1",
        "id",
        "0\t0",
        "0",
        "",
        "entry",
        "0\t1",
        "id\tp\tn\tls\tsrc",
        "26\t0",
        "1\tf\treport.txt\t11\t0",
        "",
    ])
}

fn single_files_stream_with_extra_subject_values() -> Vec<u8> {
    single_files_stream_with_source_prefix(&[
        "sub",
        "0\t1",
        "id",
        "0\t0",
        "0\tignored",
        "",
        "entry",
        "0\t1",
        "id\tp\tn\tls\tsub",
        "26\t0",
        "1\tf\treport.txt\t11\t0",
        "",
    ])
}

fn single_files_stream_with_extra_permission_values() -> Vec<u8> {
    single_files_stream_with_record_prefix(&[
        "perm",
        "0\t1",
        "pt",
        "0\t0",
        "10\tignored",
        "",
        "srce",
        "0\t1",
        "id",
        "0\t0",
        "0",
        "",
        "sub",
        "0\t1",
        "id",
        "0\t0",
        "0",
        "",
        "entry",
        "0\t1",
        "id\tp\tn\tls",
        "26\t0",
        "1\tf\treport.txt\t11",
        "",
    ])
}

fn single_files_stream_with_negative_entry_source_identifier() -> Vec<u8> {
    single_files_stream_with_default_categories(&[
        "entry",
        "0\t1",
        "id\tp\tn\tls\tsrc",
        "26\t0",
        "1\tf\treport.txt\t11\t-1",
        "",
    ])
}

fn single_files_stream_with_non_empty_subject_terminator() -> Vec<u8> {
    single_files_stream_with_source_prefix(&[
        "sub",
        "1\t1",
        "id\tn",
        "0\t1",
        "0\troot-subject",
        "0\t0",
        "7\tCase Subject",
        "unexpected",
        "entry",
        "0\t1",
        "id\tp\tn\tls\tsub",
        "26\t0",
        "1\tf\treport.txt\t11\t7",
        "",
    ])
}

fn single_files_stream_with_non_empty_permission_terminator() -> Vec<u8> {
    single_files_stream_with_record_prefix(&[
        "perm",
        "1\t1",
        "n\tpr\ts\tnta\tnti",
        "0\t1",
        "root-permissions\t10\troot-sid\t0\t0",
        "0\t1",
        "Administrators\t10\tgroup-sid\t0\t0",
        "0\t0",
        "Alice\t1\tS-1-5-21\t2032127\t3",
        "unexpected",
        "entry",
        "0\t1",
        "id\tp\tn\tls\tpm",
        "26\t0",
        "1\tf\treport.txt\t11\t0",
        "",
    ])
}

fn single_files_stream_with_invalid_permission_root_type() -> Vec<u8> {
    single_files_stream_with_record_prefix(&[
        "perm",
        "0\t1",
        "pt",
        "0\t0",
        "9",
        "",
        "entry",
        "0\t1",
        "id\tp\tn\tls",
        "26\t0",
        "1\tf\treport.txt\t11",
        "",
    ])
}

fn single_files_stream_with_invalid_permission_group_type() -> Vec<u8> {
    single_files_stream_with_record_prefix(&[
        "perm",
        "1\t1",
        "pt",
        "0\t1",
        "10",
        "0\t0",
        "9",
        "",
        "entry",
        "0\t1",
        "id\tp\tn\tls\tpm",
        "26\t0",
        "1\tf\treport.txt\t11\t0",
        "",
    ])
}

fn single_files_stream_with_metadata_tables() -> Vec<u8> {
    let source_types = [
        "id", "n", "ev", "loc", "gu", "pgu", "dt", "mfr", "mo", "se", "do", "ip", "ma", "tb", "lo",
        "po", "aq", "ah", "sh",
    ]
    .join("\t");
    let source_root = [
        "0",
        "root-source",
        "",
        "",
        "",
        "",
        "f",
        "",
        "",
        "",
        "",
        "",
        "",
        "0",
        "0",
        "0",
        "0",
        "",
        "",
    ]
    .join("\t");
    let source = [
        "1",
        "Disk 1",
        "EV-1",
        "Lab",
        "00112233445566778899aabbccddeeff",
        "ffeeddccbbaa99887766554433221100",
        "f",
        "Acme",
        "Model X",
        "SN123",
        "DOMAIN",
        "192.0.2.1",
        "001122aabbcc",
        "4096",
        "512",
        "1024",
        "1700000000",
        "00112233445566778899aabbccddeeff",
        "00112233445566778899aabbccddeeff00112233",
    ]
    .join("\t");
    let text = vec![
        "5".to_owned(),
        "rec".to_owned(),
        "tb".to_owned(),
        "4096".to_owned(),
        String::new(),
        "perm".to_owned(),
        "1\t1".to_owned(),
        "n\tpr\ts\tnta\tnti".to_owned(),
        "0\t1".to_owned(),
        "root-permissions\t10\troot-sid\t0\t0".to_owned(),
        "0\t1".to_owned(),
        "Administrators\t10\tgroup-sid\t0\t0".to_owned(),
        "0\t0".to_owned(),
        "Alice\t1\tS-1-5-21\t2032127\t3".to_owned(),
        String::new(),
        "srce".to_owned(),
        "1\t1".to_owned(),
        source_types,
        "0\t1".to_owned(),
        source_root,
        "0\t0".to_owned(),
        source,
        String::new(),
        "sub".to_owned(),
        "1\t1".to_owned(),
        "id\tn".to_owned(),
        "0\t1".to_owned(),
        "0\troot-subject".to_owned(),
        "0\t0".to_owned(),
        "7\tCase Subject".to_owned(),
        String::new(),
        "entry".to_owned(),
        "0\t1".to_owned(),
        "id\tp\tn\tls\tsrc\tsub\tpm".to_owned(),
        "26\t1".to_owned(),
        "1\td\troot\t0\t0\t0\t-1".to_owned(),
        "26\t0".to_owned(),
        "2\tf\treport.txt\t11\t1\t7\t0".to_owned(),
        String::new(),
    ]
    .join("\n")
        + "\n";
    utf16le(&text)
}

fn single_files_stream_with_duplicate_root_source_identifier() -> Vec<u8> {
    single_files_stream_with_permission_prefix(&[
        "srce",
        "1\t1",
        "id\tn",
        "0\t1",
        "1\troot-source",
        "0\t0",
        "1\tDisk 1",
        "",
        "sub",
        "0\t1",
        "id",
        "0\t0",
        "0",
        "",
        "entry",
        "0\t1",
        "id\tp\tn\tls\tsrc",
        "26\t1",
        "1\td\troot\t0\t0",
        "26\t0",
        "2\tf\treport.txt\t11\t1",
        "",
    ])
}

fn extended_attribute_record(is_branch: bool, name: &str, value: &str) -> Vec<u8> {
    let name: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let value: Vec<u16> = value.encode_utf16().chain([0]).collect();
    let mut bytes = Vec::with_capacity(13 + (name.len() + value.len()) * 2);
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.push(u8::from(is_branch));
    bytes.extend_from_slice(&(name.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
    bytes.extend(name.into_iter().flat_map(u16::to_le_bytes));
    bytes.extend(value.into_iter().flat_map(u16::to_le_bytes));
    bytes
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn single_files_stream_with_extended_attributes() -> Vec<u8> {
    let mut attributes = vec![
        0x00, 0x00, 0x00, 0x00, 0x01, 0x0b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x41, 0x00,
        0x74, 0x00, 0x74, 0x00, 0x72, 0x00, 0x69, 0x00, 0x62, 0x00, 0x75, 0x00, 0x74, 0x00, 0x65,
        0x00, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    attributes.extend(extended_attribute_record(
        false,
        "Zone.Identifier",
        "[ZoneTransfer]",
    ));
    attributes.extend(extended_attribute_record(true, "IgnoredBranch", ""));
    attributes.extend(extended_attribute_record(false, "Comment", "Recovered"));
    let attributes = hex_bytes(&attributes);

    let mut lines = default_single_files_prefix();
    lines.extend([
        "entry".to_owned(),
        "0\t1".to_owned(),
        "id\tp\tn\tls\tea".to_owned(),
        "26\t1".to_owned(),
        "1\td\troot\t0\t".to_owned(),
        "26\t0".to_owned(),
        format!("2\tf\treport.txt\t11\t{attributes}"),
        String::new(),
    ]);
    utf16le_lines(lines)
}

fn single_files_stream_with_single_extent(offset: u64, size: u64) -> Vec<u8> {
    let extent = format!("1 {offset:x} {size:x}");
    let mut lines = default_single_files_prefix();
    lines.extend([
        "entry".to_owned(),
        "0\t1".to_owned(),
        "id\tp\tn\tls\tbe".to_owned(),
        "26\t1".to_owned(),
        "1\td\troot\t0\t".to_owned(),
        "26\t0".to_owned(),
        format!("2\tf\treport.bin\t{size}\t{extent}"),
        String::new(),
    ]);
    utf16le_lines(lines)
}

fn single_files_stream_with_ewf1_sparse_entry(
    size: u64,
    extent: &str,
    duplicate_offset: &str,
) -> Vec<u8> {
    let mut lines = default_single_files_prefix();
    lines.extend([
        "entry".to_owned(),
        "0\t1".to_owned(),
        "id\tp\tn\tls\tbe\tdu\topr".to_owned(),
        "26\t1".to_owned(),
        "1\td\troot\t0\t\t\t".to_owned(),
        "26\t0".to_owned(),
        format!("2\tf\tsparse.bin\t{size}\t{extent}\t{duplicate_offset}\t67108864"),
        String::new(),
    ]);
    utf16le_lines(lines)
}

fn single_files_stream_with_duplicate_data(offset: i64, size: u64) -> Vec<u8> {
    let mut lines = default_single_files_prefix();
    lines.extend([
        "entry".to_owned(),
        "0\t1".to_owned(),
        "id\tp\tn\tls\tdu".to_owned(),
        "26\t1".to_owned(),
        "1\td\troot\t0\t-1".to_owned(),
        "26\t0".to_owned(),
        format!("2\tf\tcopy.bin\t{size}\t{offset}"),
        String::new(),
    ]);
    utf16le_lines(lines)
}

fn single_files_stream_with_sparse_extent(
    offset: u64,
    data_size: u64,
    sparse_size: u64,
) -> Vec<u8> {
    let total_size = data_size + sparse_size;
    let extent = format!("2 {offset:x} {data_size:x} S 0 {sparse_size:x}");
    let mut lines = default_single_files_prefix();
    lines.extend([
        "entry".to_owned(),
        "0\t1".to_owned(),
        "id\tp\tn\tls\tbe".to_owned(),
        "26\t1".to_owned(),
        "1\td\troot\t0\t".to_owned(),
        "26\t0".to_owned(),
        format!("2\tf\tsparse.bin\t{total_size}\t{extent}"),
        String::new(),
    ]);
    utf16le_lines(lines)
}

fn synthetic_ex01(data: &[u8]) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let compressed = compressed_chunk(data, chunk_size);
    synthetic_ewf2_with_entry(EX01_SIGNATURE, ".Ex01", 1, Some(&compressed), 1, 0)
}

fn ewf2_md5_hash_payload(md5: [u8; 16]) -> [u8; 32] {
    let mut payload = [0; 32];
    payload[..16].copy_from_slice(&md5);
    let checksum = adler32(&payload[..16]);
    payload[16..20].copy_from_slice(&checksum.to_le_bytes());
    payload
}

fn synthetic_ex01_with_zero_md5_hash(data: &[u8]) -> NamedTempFile {
    synthetic_ex01_with_md5_hash(data, &ewf2_md5_hash_payload([0; 16]))
}

fn synthetic_ex01_without_device_or_case_metadata(data: &[u8]) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let compressed = compressed_chunk(data, chunk_size);
    let table_data_size = 32 + 16;

    let sector_data_offset = 32_usize;
    let sector_desc_offset = sector_data_offset + compressed.len();
    let table_data_offset = sector_desc_offset + 64;
    let table_desc_offset = table_data_offset + table_data_size;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EX01_SIGNATURE);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&ewf2_desc(0x03, compressed.len() as u64, 0));

    let mut table_header = [0; 32];
    table_header[0..8].copy_from_slice(&0_u64.to_le_bytes());
    table_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let mut entry = [0; 16];
    entry[0..8].copy_from_slice(&(sector_data_offset as u64).to_le_bytes());
    entry[8..12].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
    entry[12..16].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&ewf2_desc(
        0x04,
        table_data_size as u64,
        sector_desc_offset as u64,
    ));
    bytes.extend_from_slice(&ewf2_desc(0x0f, 0, table_desc_offset as u64));

    write_temp_with_suffix(".Ex01", &bytes)
}

fn synthetic_ex01_with_md5_hash(data: &[u8], md5_hash: &[u8]) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let compressed = compressed_chunk(data, chunk_size);
    let device_info = utf16le("2\nmain\nb\tsc\tts\n512\t64\t64\n\n");
    let table_data_size = 32 + 16;

    let device_data_offset = 32_usize;
    let device_desc_offset = device_data_offset + device_info.len();
    let sector_data_offset = device_desc_offset + 64;
    let sector_desc_offset = sector_data_offset + compressed.len();
    let md5_data_offset = sector_desc_offset + 64;
    let md5_desc_offset = md5_data_offset + md5_hash.len();
    let table_data_offset = md5_desc_offset + 64;
    let table_desc_offset = table_data_offset + table_data_size;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EX01_SIGNATURE);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&device_info);
    bytes.extend_from_slice(&ewf2_desc(0x01, device_info.len() as u64, 0));
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&ewf2_desc(
        0x03,
        compressed.len() as u64,
        device_desc_offset as u64,
    ));
    bytes.extend_from_slice(md5_hash);
    bytes.extend_from_slice(&ewf2_desc(
        0x08,
        md5_hash.len() as u64,
        sector_desc_offset as u64,
    ));

    let mut table_header = [0; 32];
    table_header[0..8].copy_from_slice(&0_u64.to_le_bytes());
    table_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let mut entry = [0; 16];
    entry[0..8].copy_from_slice(&(sector_data_offset as u64).to_le_bytes());
    entry[8..12].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
    entry[12..16].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&ewf2_desc(
        0x04,
        table_data_size as u64,
        md5_desc_offset as u64,
    ));
    bytes.extend_from_slice(&ewf2_desc(0x0f, 0, table_desc_offset as u64));

    write_temp_with_suffix(".Ex01", &bytes)
}

fn synthetic_ex01_leading_sections(data: &[u8]) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let compressed = compressed_chunk(data, chunk_size);
    let device_info = utf16le("2\nmain\nb\tsc\tts\n512\t64\t64\n\n");
    let table_data_size = 20 + 16;

    let device_desc_offset = 32_usize;
    let device_data_offset = device_desc_offset + 64;
    let table_desc_offset = device_data_offset + device_info.len();
    let table_data_offset = table_desc_offset + 64;
    let sectors_desc_offset = table_data_offset + table_data_size;
    let sectors_data_offset = sectors_desc_offset + 64;
    let done_desc_offset = sectors_data_offset + compressed.len();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EX01_SIGNATURE);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&ewf2_desc(0x01, device_info.len() as u64, 0));
    bytes.extend_from_slice(&device_info);
    bytes.extend_from_slice(&ewf2_desc(
        0x04,
        table_data_size as u64,
        device_desc_offset as u64,
    ));
    let mut table_header = [0; 20];
    table_header[0..8].copy_from_slice(&0_u64.to_le_bytes());
    table_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let mut entry = [0; 16];
    entry[0..8].copy_from_slice(&(sectors_data_offset as u64).to_le_bytes());
    entry[8..12].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
    entry[12..16].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&ewf2_desc(
        0x03,
        compressed.len() as u64,
        table_desc_offset as u64,
    ));
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&ewf2_desc(0x0f, 0, sectors_desc_offset as u64));

    assert_eq!(bytes.len(), done_desc_offset + 64);
    write_temp_with_suffix(".Ex01", &bytes)
}

fn synthetic_ex01_trailing_table_with_padding(data: &[u8]) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let mut chunk = data.to_vec();
    chunk.resize(chunk_size, 0);
    let device_info = utf16le("2\nmain\nb\tsc\tts\n512\t64\t64\n\n");
    let table_data_size = 20 + 12 + 16 + 4 + 12;

    let device_data_offset = 32_usize;
    let device_desc_offset = device_data_offset + device_info.len();
    let sectors_data_offset = device_desc_offset + 64;
    let sectors_desc_offset = sectors_data_offset + chunk.len();
    let table_data_offset = sectors_desc_offset + 64;
    let table_desc_offset = table_data_offset + table_data_size;
    let done_desc_offset = table_desc_offset + 64;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EX01_SIGNATURE);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&device_info);
    bytes.extend_from_slice(&ewf2_desc(0x01, device_info.len() as u64, 0));
    bytes.extend_from_slice(&chunk);
    bytes.extend_from_slice(&ewf2_desc(
        0x03,
        chunk.len() as u64,
        device_desc_offset as u64,
    ));

    let mut table_header = [0; 20];
    table_header[0..8].copy_from_slice(&0_u64.to_le_bytes());
    table_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    bytes.extend_from_slice(&[0; 12]);
    let mut entry = [0; 16];
    entry[0..8].copy_from_slice(&(sectors_data_offset as u64).to_le_bytes());
    entry[8..12].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
    entry[12..16].copy_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(&[0; 12]);
    let mut table_desc = ewf2_desc(0x04, table_data_size as u64, sectors_desc_offset as u64);
    table_desc[28..32].copy_from_slice(&24_u32.to_le_bytes());
    bytes.extend_from_slice(&table_desc);
    bytes.extend_from_slice(&ewf2_desc(0x0f, 0, table_desc_offset as u64));

    assert_eq!(bytes.len(), done_desc_offset + 64);
    write_temp_with_suffix(".Ex01", &bytes)
}

fn synthetic_ex01_overlapping_sector_tables() -> NamedTempFile {
    let device_info = utf16le("2\nmain\nb\tsc\tts\n512\t64\t128\n\n");
    let first_table_data_size = 20 + 32;
    let second_table_data_size = 20 + 16;

    let device_desc_offset = 32_usize;
    let device_data_offset = device_desc_offset + 64;
    let first_table_desc_offset = device_data_offset + device_info.len();
    let first_table_data_offset = first_table_desc_offset + 64;
    let second_table_desc_offset = first_table_data_offset + first_table_data_size;
    let second_table_data_offset = second_table_desc_offset + 64;
    let done_desc_offset = second_table_data_offset + second_table_data_size;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EX01_SIGNATURE);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&ewf2_desc(0x01, device_info.len() as u64, 0));
    bytes.extend_from_slice(&device_info);

    bytes.extend_from_slice(&ewf2_desc(
        0x04,
        first_table_data_size as u64,
        device_desc_offset as u64,
    ));
    let mut first_header = [0; 20];
    first_header[0..8].copy_from_slice(&0_u64.to_le_bytes());
    first_header[8..12].copy_from_slice(&2_u32.to_le_bytes());
    bytes.extend_from_slice(&first_header);
    for _ in 0..2 {
        let mut entry = [0; 16];
        entry[8..12].copy_from_slice(&32_768_u32.to_le_bytes());
        bytes.extend_from_slice(&entry);
    }

    bytes.extend_from_slice(&ewf2_desc(
        0x04,
        second_table_data_size as u64,
        first_table_desc_offset as u64,
    ));
    let mut second_header = [0; 20];
    second_header[0..8].copy_from_slice(&1_u64.to_le_bytes());
    second_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&second_header);
    let mut entry = [0; 16];
    entry[8..12].copy_from_slice(&32_768_u32.to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&ewf2_desc(0x0f, 0, second_table_desc_offset as u64));

    assert_eq!(bytes.len(), done_desc_offset + 64);
    write_temp_with_suffix(".Ex01", &bytes)
}

fn ewf2_leading_segment_bytes(
    segment_number: u32,
    first_chunk: u64,
    terminal_section_type: u32,
    data: &[u8],
) -> Vec<u8> {
    ewf2_leading_segment_bytes_with_device_information(
        segment_number,
        first_chunk,
        terminal_section_type,
        data,
        "2\nmain\nb\tsc\tts\n512\t64\t128\n\n",
    )
}

fn ewf2_leading_segment_bytes_with_device_information(
    segment_number: u32,
    first_chunk: u64,
    terminal_section_type: u32,
    data: &[u8],
    device_information: &str,
) -> Vec<u8> {
    ewf2_leading_segment_bytes_with_device_information_and_compression_method(
        segment_number,
        first_chunk,
        terminal_section_type,
        data,
        device_information,
        1,
    )
}

fn ewf2_leading_segment_bytes_with_compression_method(
    segment_number: u32,
    first_chunk: u64,
    terminal_section_type: u32,
    data: &[u8],
    compression_method: u16,
) -> Vec<u8> {
    ewf2_leading_segment_bytes_with_device_information_and_compression_method(
        segment_number,
        first_chunk,
        terminal_section_type,
        data,
        "2\nmain\nb\tsc\tts\n512\t64\t128\n\n",
        compression_method,
    )
}

fn ewf2_leading_segment_bytes_with_device_information_and_compression_method(
    segment_number: u32,
    first_chunk: u64,
    terminal_section_type: u32,
    data: &[u8],
    device_information: &str,
    compression_method: u16,
) -> Vec<u8> {
    ewf2_leading_segment_bytes_with_signature(
        EX01_SIGNATURE,
        segment_number,
        first_chunk,
        terminal_section_type,
        data,
        device_information,
        compression_method,
    )
}

fn ewf2_logical_leading_segment_bytes(
    segment_number: u32,
    first_chunk: u64,
    terminal_section_type: u32,
    data: &[u8],
) -> Vec<u8> {
    ewf2_leading_segment_bytes_with_signature(
        LEF2_SIGNATURE,
        segment_number,
        first_chunk,
        terminal_section_type,
        data,
        "2\nmain\nb\tsc\tts\n512\t64\t128\n\n",
        1,
    )
}

fn ewf2_leading_segment_bytes_with_signature(
    signature: [u8; 8],
    segment_number: u32,
    first_chunk: u64,
    terminal_section_type: u32,
    data: &[u8],
    device_information: &str,
    compression_method: u16,
) -> Vec<u8> {
    let chunk_size = 32_768_usize;
    let mut chunk = data.to_vec();
    chunk.resize(chunk_size, 0);
    let device_info = utf16le(device_information);
    let table_data_size = 20 + 16;

    let device_desc_offset = 32_usize;
    let device_data_offset = device_desc_offset + 64;
    let table_desc_offset = device_data_offset + device_info.len();
    let table_data_offset = table_desc_offset + 64;
    let sectors_desc_offset = table_data_offset + table_data_size;
    let sectors_data_offset = sectors_desc_offset + 64;
    let terminal_desc_offset = sectors_data_offset + chunk.len();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&signature);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&compression_method.to_le_bytes());
    bytes.extend_from_slice(&segment_number.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&ewf2_desc(0x01, device_info.len() as u64, 0));
    bytes.extend_from_slice(&device_info);
    bytes.extend_from_slice(&ewf2_desc(
        0x04,
        table_data_size as u64,
        device_desc_offset as u64,
    ));
    let mut table_header = [0; 20];
    table_header[0..8].copy_from_slice(&first_chunk.to_le_bytes());
    table_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let mut entry = [0; 16];
    entry[0..8].copy_from_slice(&(sectors_data_offset as u64).to_le_bytes());
    entry[8..12].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&ewf2_desc(
        0x03,
        chunk.len() as u64,
        table_desc_offset as u64,
    ));
    bytes.extend_from_slice(&chunk);
    bytes.extend_from_slice(&ewf2_desc(
        terminal_section_type,
        0,
        sectors_desc_offset as u64,
    ));

    assert_eq!(bytes.len(), terminal_desc_offset + 64);
    bytes
}

fn synthetic_ex01_leading_restart_data(data: &[u8]) -> NamedTempFile {
    synthetic_ex01_leading_restart_data_with_integrity(data, false)
}

fn synthetic_ex01_leading_restart_data_with_integrity(
    data: &[u8],
    corrupt_restart_data: bool,
) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let compressed = compressed_chunk(data, chunk_size);
    let device_info = utf16le("2\nmain\nb\tsc\tts\n512\t64\t64\n\n");
    let mut restart_data = zlib_bytes(&utf16le("<restart_data />\n"));
    let restart_desc = ewf2_desc_with_integrity_hash(0x0a, &restart_data, 32);
    if corrupt_restart_data {
        restart_data[4] ^= 0x80;
    }
    let table_data_size = 20 + 16;

    let device_desc_offset = 32_usize;
    let device_data_offset = device_desc_offset + 64;
    let restart_desc_offset = device_data_offset + device_info.len();
    let restart_data_offset = restart_desc_offset + 64;
    let table_desc_offset = restart_data_offset + restart_data.len();
    let table_data_offset = table_desc_offset + 64;
    let sectors_desc_offset = table_data_offset + table_data_size;
    let sectors_data_offset = sectors_desc_offset + 64;
    let done_desc_offset = sectors_data_offset + compressed.len();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EX01_SIGNATURE);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&ewf2_desc(0x01, device_info.len() as u64, 0));
    bytes.extend_from_slice(&device_info);
    bytes.extend_from_slice(&restart_desc);
    bytes.extend_from_slice(&restart_data);
    bytes.extend_from_slice(&ewf2_desc(
        0x04,
        table_data_size as u64,
        restart_desc_offset as u64,
    ));
    let mut table_header = [0; 20];
    table_header[0..8].copy_from_slice(&0_u64.to_le_bytes());
    table_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let mut entry = [0; 16];
    entry[0..8].copy_from_slice(&(sectors_data_offset as u64).to_le_bytes());
    entry[8..12].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
    entry[12..16].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&ewf2_desc(
        0x03,
        compressed.len() as u64,
        table_desc_offset as u64,
    ));
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&ewf2_desc(0x0f, 0, sectors_desc_offset as u64));

    assert_eq!(bytes.len(), done_desc_offset + 64);
    write_temp_with_suffix(".Ex01", &bytes)
}

fn synthetic_ex01_leading_padded_restart_data(data: &[u8]) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let compressed = compressed_chunk(data, chunk_size);
    let device_info = utf16le("2\nmain\nb\tsc\tts\n512\t64\t64\n\n");
    let restart_data = zlib_bytes(&utf16le("<restart_data />\n"));
    let restart_padding_size = 12_usize;
    let table_data_size = 20 + 16;

    let device_desc_offset = 32_usize;
    let device_data_offset = device_desc_offset + 64;
    let restart_desc_offset = device_data_offset + device_info.len();
    let restart_data_offset = restart_desc_offset + 64;
    let table_desc_offset = restart_data_offset + restart_data.len() + restart_padding_size;
    let table_data_offset = table_desc_offset + 64;
    let sectors_desc_offset = table_data_offset + table_data_size;
    let sectors_data_offset = sectors_desc_offset + 64;
    let done_desc_offset = sectors_data_offset + compressed.len();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EX01_SIGNATURE);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&ewf2_desc(0x01, device_info.len() as u64, 0));
    bytes.extend_from_slice(&device_info);
    let mut restart_desc = ewf2_desc(0x0a, restart_data.len() as u64, device_desc_offset as u64);
    restart_desc[28..32].copy_from_slice(&(restart_padding_size as u32).to_le_bytes());
    bytes.extend_from_slice(&restart_desc);
    bytes.extend_from_slice(&restart_data);
    bytes.extend_from_slice(&[0; 12]);
    bytes.extend_from_slice(&ewf2_desc(
        0x04,
        table_data_size as u64,
        restart_desc_offset as u64,
    ));
    let mut table_header = [0; 20];
    table_header[0..8].copy_from_slice(&0_u64.to_le_bytes());
    table_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let mut entry = [0; 16];
    entry[0..8].copy_from_slice(&(sectors_data_offset as u64).to_le_bytes());
    entry[8..12].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
    entry[12..16].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&ewf2_desc(
        0x03,
        compressed.len() as u64,
        table_desc_offset as u64,
    ));
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&ewf2_desc(0x0f, 0, sectors_desc_offset as u64));

    assert_eq!(bytes.len(), done_desc_offset + 64);
    write_temp_with_suffix(".Ex01", &bytes)
}

fn synthetic_ex01_leading_application_sections(
    data: &[u8],
    sections: &[(u32, &[u8])],
) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let compressed = compressed_chunk(data, chunk_size);
    let device_info = utf16le("2\nmain\nb\tsc\tts\n512\t64\t64\n\n");
    let table_data_size = 20 + 16;

    let device_desc_offset = 32_usize;
    let device_data_offset = device_desc_offset + 64;
    let application_desc_offset = device_data_offset + device_info.len();
    let application_sections_size = sections
        .iter()
        .map(|(_, section_data)| 64 + section_data.len())
        .sum::<usize>();
    let table_desc_offset = application_desc_offset + application_sections_size;
    let table_data_offset = table_desc_offset + 64;
    let sectors_desc_offset = table_data_offset + table_data_size;
    let sectors_data_offset = sectors_desc_offset + 64;
    let done_desc_offset = sectors_data_offset + compressed.len();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EX01_SIGNATURE);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&ewf2_desc(0x01, device_info.len() as u64, 0));
    bytes.extend_from_slice(&device_info);

    let mut previous_desc_offset = device_desc_offset;
    let mut current_desc_offset = application_desc_offset;
    for (section_type, section_data) in sections {
        bytes.extend_from_slice(&ewf2_desc(
            *section_type,
            section_data.len() as u64,
            previous_desc_offset as u64,
        ));
        bytes.extend_from_slice(section_data);
        previous_desc_offset = current_desc_offset;
        current_desc_offset += 64 + section_data.len();
    }

    bytes.extend_from_slice(&ewf2_desc(
        0x04,
        table_data_size as u64,
        previous_desc_offset as u64,
    ));
    let mut table_header = [0; 20];
    table_header[0..8].copy_from_slice(&0_u64.to_le_bytes());
    table_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let mut entry = [0; 16];
    entry[0..8].copy_from_slice(&(sectors_data_offset as u64).to_le_bytes());
    entry[8..12].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
    entry[12..16].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&ewf2_desc(
        0x03,
        compressed.len() as u64,
        table_desc_offset as u64,
    ));
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&ewf2_desc(0x0f, 0, sectors_desc_offset as u64));

    assert_eq!(current_desc_offset, table_desc_offset);
    assert_eq!(bytes.len(), done_desc_offset + 64);
    write_temp_with_suffix(".Ex01", &bytes)
}

fn synthetic_ex01_leading_unknown_section(data: &[u8]) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let compressed = compressed_chunk(data, chunk_size);
    let device_info = utf16le("2\nmain\nb\tsc\tts\n512\t64\t64\n\n");
    let unknown_data = b"unknown but skippable";
    let table_data_size = 20 + 16;

    let device_desc_offset = 32_usize;
    let device_data_offset = device_desc_offset + 64;
    let unknown_desc_offset = device_data_offset + device_info.len();
    let unknown_data_offset = unknown_desc_offset + 64;
    let table_desc_offset = unknown_data_offset + unknown_data.len();
    let table_data_offset = table_desc_offset + 64;
    let sectors_desc_offset = table_data_offset + table_data_size;
    let sectors_data_offset = sectors_desc_offset + 64;
    let done_desc_offset = sectors_data_offset + compressed.len();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EX01_SIGNATURE);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&ewf2_desc(0x01, device_info.len() as u64, 0));
    bytes.extend_from_slice(&device_info);
    bytes.extend_from_slice(&ewf2_desc(
        0xff,
        unknown_data.len() as u64,
        device_desc_offset as u64,
    ));
    bytes.extend_from_slice(unknown_data);
    bytes.extend_from_slice(&ewf2_desc(
        0x04,
        table_data_size as u64,
        unknown_desc_offset as u64,
    ));
    let mut table_header = [0; 20];
    table_header[0..8].copy_from_slice(&0_u64.to_le_bytes());
    table_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let mut entry = [0; 16];
    entry[0..8].copy_from_slice(&(sectors_data_offset as u64).to_le_bytes());
    entry[8..12].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
    entry[12..16].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&ewf2_desc(
        0x03,
        compressed.len() as u64,
        table_desc_offset as u64,
    ));
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&ewf2_desc(0x0f, 0, sectors_desc_offset as u64));

    assert_eq!(bytes.len(), done_desc_offset + 64);
    write_temp_with_suffix(".Ex01", &bytes)
}

fn synthetic_lx01_leading_single_files_table(data: &[u8], section_type: u32) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let compressed = compressed_chunk(data, chunk_size);
    let device_info = utf16le("2\nmain\nb\tsc\tts\tdt\n512\t64\t64\tl\n\n");
    let single_files_table = match section_type {
        0x21 => ewf2_single_files_aux_u64_table(&[0x10, 0x20]),
        0x22 => ewf2_single_files_md5_hash_table(&[[0x11; 16], [0x22; 16]]),
        0x23 => ewf2_single_files_aux_u64_table(&[0x30]),
        _ => panic!("unsupported synthetic single files table type"),
    };
    let table_data_size = 20 + 16;

    let device_desc_offset = 32_usize;
    let device_data_offset = device_desc_offset + 64;
    let single_files_table_desc_offset = device_data_offset + device_info.len();
    let single_files_table_data_offset = single_files_table_desc_offset + 64;
    let table_desc_offset = single_files_table_data_offset + single_files_table.len();
    let table_data_offset = table_desc_offset + 64;
    let sectors_desc_offset = table_data_offset + table_data_size;
    let sectors_data_offset = sectors_desc_offset + 64;
    let done_desc_offset = sectors_data_offset + compressed.len();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&LEF2_SIGNATURE);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&ewf2_desc(0x01, device_info.len() as u64, 0));
    bytes.extend_from_slice(&device_info);
    bytes.extend_from_slice(&ewf2_desc(
        section_type,
        single_files_table.len() as u64,
        device_desc_offset as u64,
    ));
    bytes.extend_from_slice(&single_files_table);
    bytes.extend_from_slice(&ewf2_desc(
        0x04,
        table_data_size as u64,
        single_files_table_desc_offset as u64,
    ));
    let mut table_header = [0; 20];
    table_header[0..8].copy_from_slice(&0_u64.to_le_bytes());
    table_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let mut entry = [0; 16];
    entry[0..8].copy_from_slice(&(sectors_data_offset as u64).to_le_bytes());
    entry[8..12].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
    entry[12..16].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&ewf2_desc(
        0x03,
        compressed.len() as u64,
        table_desc_offset as u64,
    ));
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&ewf2_desc(0x0f, 0, sectors_desc_offset as u64));

    assert_eq!(bytes.len(), done_desc_offset + 64);
    write_temp_with_suffix(".Lx01", &bytes)
}

fn synthetic_lx01_leading_single_files_data(data: &[u8]) -> NamedTempFile {
    synthetic_lx01_leading_single_files_data_with_stream(
        data,
        &single_files_stream_with_entry_tree(),
    )
}

fn synthetic_lx01_leading_single_files_data_with_stream(
    data: &[u8],
    single_files_data: &[u8],
) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let compressed = compressed_chunk(data, chunk_size);
    let device_info = utf16le("2\nmain\nb\tsc\tts\tdt\n512\t64\t64\tl\n\n");
    let table_data_size = 20 + 16;

    let device_desc_offset = 32_usize;
    let device_data_offset = device_desc_offset + 64;
    let single_files_desc_offset = device_data_offset + device_info.len();
    let single_files_data_offset = single_files_desc_offset + 64;
    let table_desc_offset = single_files_data_offset + single_files_data.len();
    let table_data_offset = table_desc_offset + 64;
    let sectors_desc_offset = table_data_offset + table_data_size;
    let sectors_data_offset = sectors_desc_offset + 64;
    let done_desc_offset = sectors_data_offset + compressed.len();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&LEF2_SIGNATURE);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&ewf2_desc(0x01, device_info.len() as u64, 0));
    bytes.extend_from_slice(&device_info);
    bytes.extend_from_slice(&ewf2_desc(
        0x20,
        single_files_data.len() as u64,
        device_desc_offset as u64,
    ));
    bytes.extend_from_slice(single_files_data);
    bytes.extend_from_slice(&ewf2_desc(
        0x04,
        table_data_size as u64,
        single_files_desc_offset as u64,
    ));
    let mut table_header = [0; 20];
    table_header[0..8].copy_from_slice(&0_u64.to_le_bytes());
    table_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let mut entry = [0; 16];
    entry[0..8].copy_from_slice(&(sectors_data_offset as u64).to_le_bytes());
    entry[8..12].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
    entry[12..16].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&ewf2_desc(
        0x03,
        compressed.len() as u64,
        table_desc_offset as u64,
    ));
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&ewf2_desc(0x0f, 0, sectors_desc_offset as u64));

    assert_eq!(bytes.len(), done_desc_offset + 64);
    write_temp_with_suffix(".Lx01", &bytes)
}

fn synthetic_lx01_single_file_extent_read(data: &[u8], offset: u64, size: u64) -> NamedTempFile {
    synthetic_lx01_leading_single_files_data_with_stream(
        data,
        &single_files_stream_with_single_extent(offset, size),
    )
}

fn synthetic_lx01_single_file_duplicate_read(data: &[u8], offset: i64, size: u64) -> NamedTempFile {
    synthetic_lx01_leading_single_files_data_with_stream(
        data,
        &single_files_stream_with_duplicate_data(offset, size),
    )
}

fn synthetic_lx01_nested_single_files_data(data: &[u8]) -> NamedTempFile {
    synthetic_lx01_leading_single_files_data_with_stream(
        data,
        &single_files_stream_with_nested_entry_tree(),
    )
}

fn synthetic_lx01_single_files_metadata_tables(data: &[u8]) -> NamedTempFile {
    synthetic_lx01_leading_single_files_data_with_stream(
        data,
        &single_files_stream_with_metadata_tables(),
    )
}

fn synthetic_lx01_single_file_extended_attributes(data: &[u8]) -> NamedTempFile {
    synthetic_lx01_leading_single_files_data_with_stream(
        data,
        &single_files_stream_with_extended_attributes(),
    )
}

fn synthetic_lx01_sparse_single_file_extent_read(
    data: &[u8],
    offset: u64,
    data_size: u64,
    sparse_size: u64,
) -> NamedTempFile {
    synthetic_lx01_leading_single_files_data_with_stream(
        data,
        &single_files_stream_with_sparse_extent(offset, data_size, sparse_size),
    )
}

fn ewf2_memory_extents_table(entries: &[(u64, u64)]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(entries.len() * 16);
    for (start_page, page_count) in entries {
        payload.extend_from_slice(&start_page.to_le_bytes());
        payload.extend_from_slice(&page_count.to_le_bytes());
    }
    payload
}

fn synthetic_ex01_memory_extents_table(data: &[u8]) -> NamedTempFile {
    synthetic_ex01_memory_extents_table_with_payload(
        data,
        &ewf2_memory_extents_table(&[(0x1000, 7), (0x2000, 11)]),
    )
}

fn synthetic_ex01_memory_extents_table_with_payload(
    data: &[u8],
    memory_extents: &[u8],
) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let compressed = compressed_chunk(data, chunk_size);
    let device_info = utf16le("2\nmain\nb\tsc\tts\tdt\n512\t64\t64\tm\n\n");
    let table_data_size = 20 + 16;

    let device_desc_offset = 32_usize;
    let device_data_offset = device_desc_offset + 64;
    let memory_extents_desc_offset = device_data_offset + device_info.len();
    let memory_extents_data_offset = memory_extents_desc_offset + 64;
    let table_desc_offset = memory_extents_data_offset + memory_extents.len();
    let table_data_offset = table_desc_offset + 64;
    let sectors_desc_offset = table_data_offset + table_data_size;
    let sectors_data_offset = sectors_desc_offset + 64;
    let done_desc_offset = sectors_data_offset + compressed.len();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EX01_SIGNATURE);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&ewf2_desc(0x01, device_info.len() as u64, 0));
    bytes.extend_from_slice(&device_info);
    bytes.extend_from_slice(&ewf2_desc(
        0x0c,
        memory_extents.len() as u64,
        device_desc_offset as u64,
    ));
    bytes.extend_from_slice(memory_extents);
    bytes.extend_from_slice(&ewf2_desc(
        0x04,
        table_data_size as u64,
        memory_extents_desc_offset as u64,
    ));
    let mut table_header = [0; 20];
    table_header[0..8].copy_from_slice(&0_u64.to_le_bytes());
    table_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let mut entry = [0; 16];
    entry[0..8].copy_from_slice(&(sectors_data_offset as u64).to_le_bytes());
    entry[8..12].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
    entry[12..16].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&ewf2_desc(
        0x03,
        compressed.len() as u64,
        table_desc_offset as u64,
    ));
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&ewf2_desc(0x0f, 0, sectors_desc_offset as u64));

    assert_eq!(bytes.len(), done_desc_offset + 64);
    write_temp_with_suffix(".Ex01", &bytes)
}

fn ewf2_error_table_payload(entries: &[(u64, u32)]) -> Vec<u8> {
    let entry_count = u32::try_from(entries.len()).unwrap();
    let mut payload = vec![0; 32];
    payload[0..4].copy_from_slice(&entry_count.to_le_bytes());
    let header_checksum = adler32(&payload[..16]);
    payload[16..20].copy_from_slice(&header_checksum.to_le_bytes());

    let entry_start = payload.len();
    for (first_sector, sector_count) in entries {
        payload.extend_from_slice(&first_sector.to_le_bytes());
        payload.extend_from_slice(&sector_count.to_le_bytes());
        payload.extend_from_slice(&[0; 4]);
    }
    let entries_checksum = adler32(&payload[entry_start..]);
    payload.extend_from_slice(&entries_checksum.to_le_bytes());
    payload.extend_from_slice(&[0; 12]);
    payload
}

fn synthetic_ex01_error_table(data: &[u8]) -> NamedTempFile {
    synthetic_ex01_error_table_with_payload(data, &ewf2_error_table_payload(&[(0x1_0000_002a, 7)]))
}

fn synthetic_ex01_error_table_with_payload(data: &[u8], error_table: &[u8]) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let compressed = compressed_chunk(data, chunk_size);
    let device_info = utf16le("2\nmain\nb\tsc\tts\n512\t64\t64\n\n");
    let table_data_size = 20 + 16;

    let device_desc_offset = 32_usize;
    let device_data_offset = device_desc_offset + 64;
    let error_desc_offset = device_data_offset + device_info.len();
    let error_data_offset = error_desc_offset + 64;
    let table_desc_offset = error_data_offset + error_table.len();
    let table_data_offset = table_desc_offset + 64;
    let sectors_desc_offset = table_data_offset + table_data_size;
    let sectors_data_offset = sectors_desc_offset + 64;
    let done_desc_offset = sectors_data_offset + compressed.len();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EX01_SIGNATURE);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&ewf2_desc(0x01, device_info.len() as u64, 0));
    bytes.extend_from_slice(&device_info);
    bytes.extend_from_slice(&ewf2_desc(
        0x05,
        error_table.len() as u64,
        device_desc_offset as u64,
    ));
    bytes.extend_from_slice(error_table);
    bytes.extend_from_slice(&ewf2_desc(
        0x04,
        table_data_size as u64,
        error_desc_offset as u64,
    ));
    let mut table_header = [0; 20];
    table_header[0..8].copy_from_slice(&0_u64.to_le_bytes());
    table_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let mut entry = [0; 16];
    entry[0..8].copy_from_slice(&(sectors_data_offset as u64).to_le_bytes());
    entry[8..12].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
    entry[12..16].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&ewf2_desc(
        0x03,
        compressed.len() as u64,
        table_desc_offset as u64,
    ));
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&ewf2_desc(0x0f, 0, sectors_desc_offset as u64));

    assert_eq!(bytes.len(), done_desc_offset + 64);
    write_temp_with_suffix(".Ex01", &bytes)
}

fn ewf2_session_table_payload(entries: &[(u64, u32)]) -> Vec<u8> {
    let entry_count = u32::try_from(entries.len()).unwrap();
    let mut payload = vec![0; 32];
    payload[0..4].copy_from_slice(&entry_count.to_le_bytes());
    let header_checksum = adler32(&payload[..16]);
    payload[16..20].copy_from_slice(&header_checksum.to_le_bytes());

    let entry_start = payload.len();
    for (start_sector, flags) in entries {
        payload.extend_from_slice(&start_sector.to_le_bytes());
        payload.extend_from_slice(&flags.to_le_bytes());
        payload.extend_from_slice(&[0; 20]);
    }
    let entries_checksum = adler32(&payload[entry_start..]);
    payload.extend_from_slice(&entries_checksum.to_le_bytes());
    payload.extend_from_slice(&[0; 12]);
    payload
}

fn synthetic_ex01_session_table(data: &[u8]) -> NamedTempFile {
    synthetic_ex01_session_table_with_payload(data, &ewf2_session_table_payload(&[(0, 0), (32, 0)]))
}

fn synthetic_ex01_session_table_with_payload(data: &[u8], session_table: &[u8]) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let compressed = compressed_chunk(data, chunk_size);
    let device_info = utf16le("2\nmain\nb\tsc\tts\n512\t64\t64\n\n");
    let table_data_size = 20 + 16;

    let device_desc_offset = 32_usize;
    let device_data_offset = device_desc_offset + 64;
    let session_desc_offset = device_data_offset + device_info.len();
    let session_data_offset = session_desc_offset + 64;
    let table_desc_offset = session_data_offset + session_table.len();
    let table_data_offset = table_desc_offset + 64;
    let sectors_desc_offset = table_data_offset + table_data_size;
    let sectors_data_offset = sectors_desc_offset + 64;
    let done_desc_offset = sectors_data_offset + compressed.len();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EX01_SIGNATURE);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&ewf2_desc(0x01, device_info.len() as u64, 0));
    bytes.extend_from_slice(&device_info);
    bytes.extend_from_slice(&ewf2_desc(
        0x06,
        session_table.len() as u64,
        device_desc_offset as u64,
    ));
    bytes.extend_from_slice(session_table);
    bytes.extend_from_slice(&ewf2_desc(
        0x04,
        table_data_size as u64,
        session_desc_offset as u64,
    ));
    let mut table_header = [0; 20];
    table_header[0..8].copy_from_slice(&0_u64.to_le_bytes());
    table_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let mut entry = [0; 16];
    entry[0..8].copy_from_slice(&(sectors_data_offset as u64).to_le_bytes());
    entry[8..12].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
    entry[12..16].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&ewf2_desc(
        0x03,
        compressed.len() as u64,
        table_desc_offset as u64,
    ));
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&ewf2_desc(0x0f, 0, sectors_desc_offset as u64));

    assert_eq!(bytes.len(), done_desc_offset + 64);
    write_temp_with_suffix(".Ex01", &bytes)
}

fn synthetic_ex01_compressed_device_info(data: &[u8]) -> NamedTempFile {
    let chunk_size = 65_536_usize;
    let compressed = compressed_chunk(data, chunk_size);
    let device_info = zlib_bytes(&utf16le("2\nmain\nb\tsc\tts\n512\t128\t128\n\n"));
    let table_data_size = 32 + 16;

    let device_data_offset = 32_usize;
    let device_desc_offset = device_data_offset + device_info.len();
    let sector_data_offset = device_desc_offset + 64;
    let sector_desc_offset = sector_data_offset + compressed.len();
    let table_data_offset = sector_desc_offset + 64;
    let table_desc_offset = table_data_offset + table_data_size;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EX01_SIGNATURE);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&device_info);
    bytes.extend_from_slice(&ewf2_desc(0x01, device_info.len() as u64, 0));
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&ewf2_desc(
        0x03,
        compressed.len() as u64,
        device_desc_offset as u64,
    ));

    let mut table_header = [0; 32];
    table_header[0..8].copy_from_slice(&0_u64.to_le_bytes());
    table_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let mut entry = [0; 16];
    entry[0..8].copy_from_slice(&(sector_data_offset as u64).to_le_bytes());
    entry[8..12].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
    entry[12..16].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&ewf2_desc(
        0x04,
        table_data_size as u64,
        sector_desc_offset as u64,
    ));
    bytes.extend_from_slice(&ewf2_desc(0x0f, 0, table_desc_offset as u64));

    write_temp_with_suffix(".Ex01", &bytes)
}

fn synthetic_ex01_bzip2_compressed_device_info(data: &[u8]) -> NamedTempFile {
    let chunk_size = 65_536_usize;
    let compressed = bzip2_chunk(data, chunk_size);
    let device_info = bzip2_bytes(&utf16le("2\nmain\nb\tsc\tts\n512\t128\t128\n\n"));
    let table_data_size = 32 + 16;

    let device_data_offset = 32_usize;
    let device_desc_offset = device_data_offset + device_info.len();
    let sector_data_offset = device_desc_offset + 64;
    let sector_desc_offset = sector_data_offset + compressed.len();
    let table_data_offset = sector_desc_offset + 64;
    let table_desc_offset = table_data_offset + table_data_size;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EX01_SIGNATURE);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&2_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&device_info);
    bytes.extend_from_slice(&ewf2_desc(0x01, device_info.len() as u64, 0));
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&ewf2_desc(
        0x03,
        compressed.len() as u64,
        device_desc_offset as u64,
    ));

    let mut table_header = [0; 32];
    table_header[0..8].copy_from_slice(&0_u64.to_le_bytes());
    table_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let mut entry = [0; 16];
    entry[0..8].copy_from_slice(&(sector_data_offset as u64).to_le_bytes());
    entry[8..12].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
    entry[12..16].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&ewf2_desc(
        0x04,
        table_data_size as u64,
        sector_desc_offset as u64,
    ));
    bytes.extend_from_slice(&ewf2_desc(0x0f, 0, table_desc_offset as u64));

    write_temp_with_suffix(".Ex01", &bytes)
}

fn synthetic_ex01_device_info_text(data: &[u8], device_info_text: &str) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let compressed = compressed_chunk(data, chunk_size);
    let device_info = utf16le(device_info_text);
    let table_data_size = 32 + 16;

    let device_data_offset = 32_usize;
    let device_desc_offset = device_data_offset + device_info.len();
    let sector_data_offset = device_desc_offset + 64;
    let sector_desc_offset = sector_data_offset + compressed.len();
    let table_data_offset = sector_desc_offset + 64;
    let table_desc_offset = table_data_offset + table_data_size;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EX01_SIGNATURE);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&device_info);
    bytes.extend_from_slice(&ewf2_desc(0x01, device_info.len() as u64, 0));
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&ewf2_desc(
        0x03,
        compressed.len() as u64,
        device_desc_offset as u64,
    ));

    let mut table_header = [0; 32];
    table_header[0..8].copy_from_slice(&0_u64.to_le_bytes());
    table_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let mut entry = [0; 16];
    entry[0..8].copy_from_slice(&(sector_data_offset as u64).to_le_bytes());
    entry[8..12].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
    entry[12..16].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&ewf2_desc(
        0x04,
        table_data_size as u64,
        sector_desc_offset as u64,
    ));
    bytes.extend_from_slice(&ewf2_desc(0x0f, 0, table_desc_offset as u64));

    write_temp_with_suffix(".Ex01", &bytes)
}

fn synthetic_ex01_mismatched_device_info_sections(data: &[u8]) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let compressed = compressed_chunk(data, chunk_size);
    let first_device_info = utf16le("2\nmain\nb\tsc\tts\tu\n512\t64\t64\tone\n\n");
    let second_device_info = utf16le("2\nmain\nb\tsc\tts\tu\n512\t64\t64\ttwo\n\n");
    let table_data_size = 32 + 16;

    let first_data_offset = 32_usize;
    let first_desc_offset = first_data_offset + first_device_info.len();
    let second_data_offset = first_desc_offset + 64;
    let second_desc_offset = second_data_offset + second_device_info.len();
    let sector_data_offset = second_desc_offset + 64;
    let sector_desc_offset = sector_data_offset + compressed.len();
    let table_data_offset = sector_desc_offset + 64;
    let table_desc_offset = table_data_offset + table_data_size;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EX01_SIGNATURE);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&first_device_info);
    bytes.extend_from_slice(&ewf2_desc(0x01, first_device_info.len() as u64, 0));
    bytes.extend_from_slice(&second_device_info);
    bytes.extend_from_slice(&ewf2_desc(
        0x01,
        second_device_info.len() as u64,
        first_desc_offset as u64,
    ));
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&ewf2_desc(
        0x03,
        compressed.len() as u64,
        second_desc_offset as u64,
    ));

    let mut table_header = [0; 32];
    table_header[0..8].copy_from_slice(&0_u64.to_le_bytes());
    table_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let mut entry = [0; 16];
    entry[0..8].copy_from_slice(&(sector_data_offset as u64).to_le_bytes());
    entry[8..12].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
    entry[12..16].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&ewf2_desc(
        0x04,
        table_data_size as u64,
        sector_desc_offset as u64,
    ));
    bytes.extend_from_slice(&ewf2_desc(0x0f, 0, table_desc_offset as u64));

    write_temp_with_suffix(".Ex01", &bytes)
}

fn synthetic_ex01_case_data_geometry(data: &[u8]) -> NamedTempFile {
    let chunk_size = 65_536_usize;
    let compressed = compressed_chunk(data, chunk_size);
    let case_data = utf16le("2\nmain\nbp\tsb\ttb\n512\t128\t1\n\n");
    let table_data_size = 32 + 16;

    let case_data_offset = 32_usize;
    let case_desc_offset = case_data_offset + case_data.len();
    let sector_data_offset = case_desc_offset + 64;
    let sector_desc_offset = sector_data_offset + compressed.len();
    let table_data_offset = sector_desc_offset + 64;
    let table_desc_offset = table_data_offset + table_data_size;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EX01_SIGNATURE);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&case_data);
    bytes.extend_from_slice(&ewf2_desc(0x02, case_data.len() as u64, 0));
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&ewf2_desc(
        0x03,
        compressed.len() as u64,
        case_desc_offset as u64,
    ));

    let mut table_header = [0; 32];
    table_header[0..8].copy_from_slice(&0_u64.to_le_bytes());
    table_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let mut entry = [0; 16];
    entry[0..8].copy_from_slice(&(sector_data_offset as u64).to_le_bytes());
    entry[8..12].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
    entry[12..16].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&ewf2_desc(
        0x04,
        table_data_size as u64,
        sector_desc_offset as u64,
    ));
    bytes.extend_from_slice(&ewf2_desc(0x0f, 0, table_desc_offset as u64));

    write_temp_with_suffix(".Ex01", &bytes)
}

fn synthetic_lx01(data: &[u8]) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let compressed = compressed_chunk(data, chunk_size);
    synthetic_ewf2_with_entry(LEF2_SIGNATURE, ".Lx01", 1, Some(&compressed), 1, 0)
}

fn synthetic_ex01_bzip2(data: &[u8]) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let compressed = bzip2_chunk(data, chunk_size);
    synthetic_ewf2_with_entry(EX01_SIGNATURE, ".Ex01", 2, Some(&compressed), 1, 0)
}

fn synthetic_ex01_pattern_fill(pattern: u64) -> NamedTempFile {
    synthetic_ewf2_with_entry(EX01_SIGNATURE, ".Ex01", 1, None, 0x0000_0005, pattern)
}

fn synthetic_ex01_with_descriptor_like_chunk_bytes(data: &[u8]) -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let mut chunk = vec![0; chunk_size];
    chunk[..data.len()].copy_from_slice(data);
    chunk[1024..1088].copy_from_slice(&ewf2_desc(0x04, 0, 0));

    synthetic_ewf2_with_entry(EX01_SIGNATURE, ".Ex01", 1, Some(&chunk), 0, 0)
}

fn synthetic_ex01_out_of_bounds_chunk() -> NamedTempFile {
    let device_info = utf16le("2\nmain\nb\tsc\tts\n512\t64\t64\n\n");
    let table_data_size = 32 + 16;

    let device_data_offset = 32_usize;
    let device_desc_offset = device_data_offset + device_info.len();
    let table_data_offset = device_desc_offset + 64;
    let table_desc_offset = table_data_offset + table_data_size;
    let done_desc_offset = table_desc_offset + 64;
    let missing_chunk_offset = done_desc_offset + 1024;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EX01_SIGNATURE);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&device_info);
    bytes.extend_from_slice(&ewf2_desc(0x01, device_info.len() as u64, 0));

    let mut table_header = [0; 32];
    table_header[0..8].copy_from_slice(&0_u64.to_le_bytes());
    table_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let mut entry = [0; 16];
    entry[0..8].copy_from_slice(&(missing_chunk_offset as u64).to_le_bytes());
    entry[8..12].copy_from_slice(&16_u32.to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&ewf2_desc(
        0x04,
        table_data_size as u64,
        device_desc_offset as u64,
    ));
    bytes.extend_from_slice(&ewf2_desc(0x0f, 0, table_desc_offset as u64));

    write_temp_with_suffix(".Ex01", &bytes)
}

fn synthetic_ex01_encryption_keys_section() -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let compressed = compressed_chunk(b"encrypted by section", chunk_size);
    let device_info = utf16le("2\nmain\nb\tsc\tts\n512\t64\t64\n\n");
    let encryption_keys = b"key material";
    let table_data_size = 32 + 16;

    let device_data_offset = 32_usize;
    let device_desc_offset = device_data_offset + device_info.len();
    let keys_data_offset = device_desc_offset + 64;
    let keys_desc_offset = keys_data_offset + encryption_keys.len();
    let sector_data_offset = keys_desc_offset + 64;
    let sector_desc_offset = sector_data_offset + compressed.len();
    let table_data_offset = sector_desc_offset + 64;
    let table_desc_offset = table_data_offset + table_data_size;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EX01_SIGNATURE);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&device_info);
    bytes.extend_from_slice(&ewf2_desc(0x01, device_info.len() as u64, 0));
    bytes.extend_from_slice(encryption_keys);
    bytes.extend_from_slice(&ewf2_desc(
        0x0b,
        encryption_keys.len() as u64,
        device_desc_offset as u64,
    ));
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&ewf2_desc(
        0x03,
        compressed.len() as u64,
        keys_desc_offset as u64,
    ));

    let mut table_header = [0; 32];
    table_header[0..8].copy_from_slice(&0_u64.to_le_bytes());
    table_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let mut entry = [0; 16];
    entry[0..8].copy_from_slice(&(sector_data_offset as u64).to_le_bytes());
    entry[8..12].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
    entry[12..16].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&ewf2_desc(
        0x04,
        table_data_size as u64,
        sector_desc_offset as u64,
    ));
    bytes.extend_from_slice(&ewf2_desc(0x0f, 0, table_desc_offset as u64));

    write_temp_with_suffix(".Ex01", &bytes)
}

fn synthetic_ex01_encrypted_device_info() -> NamedTempFile {
    let chunk_size = 32_768_usize;
    let compressed = compressed_chunk(b"encrypted marker", chunk_size);
    let device_info = utf16le("2\nmain\nb\tsc\tts\n512\t64\t64\n\n");
    let table_data_size = 32 + 16;

    let device_data_offset = 32_usize;
    let device_desc_offset = device_data_offset + device_info.len();
    let sector_data_offset = device_desc_offset + 64;
    let sector_desc_offset = sector_data_offset + compressed.len();
    let table_data_offset = sector_desc_offset + 64;
    let table_desc_offset = table_data_offset + table_data_size;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EX01_SIGNATURE);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&device_info);
    bytes.extend_from_slice(&ewf2_desc_with_flags(
        0x01,
        0x0000_0002,
        device_info.len() as u64,
        0,
    ));
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&ewf2_desc(
        0x03,
        compressed.len() as u64,
        device_desc_offset as u64,
    ));

    let mut table_header = [0; 32];
    table_header[0..8].copy_from_slice(&0_u64.to_le_bytes());
    table_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let mut entry = [0; 16];
    entry[0..8].copy_from_slice(&(sector_data_offset as u64).to_le_bytes());
    entry[8..12].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
    entry[12..16].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&ewf2_desc(
        0x04,
        table_data_size as u64,
        sector_desc_offset as u64,
    ));
    bytes.extend_from_slice(&ewf2_desc(0x0f, 0, table_desc_offset as u64));

    write_temp_with_suffix(".Ex01", &bytes)
}

fn synthetic_ewf2_with_entry(
    signature: [u8; 8],
    suffix: &str,
    compression_method: u16,
    chunk_payload: Option<&[u8]>,
    entry_flags: u32,
    pattern: u64,
) -> NamedTempFile {
    let device_info = utf16le("2\nmain\nb\tsc\tts\n512\t64\t64\n\n");
    let table_data_size = 32 + 16;

    let device_data_offset = 32_usize;
    let device_desc_offset = device_data_offset + device_info.len();
    let sector_data_offset = device_desc_offset + 64;
    let sector_data_size = chunk_payload.map_or(0, <[u8]>::len);
    let sector_desc_size = if chunk_payload.is_some() { 64 } else { 0 };
    let sector_desc_offset = sector_data_offset + sector_data_size;
    let table_data_offset = sector_desc_offset + sector_desc_size;
    let table_desc_offset = table_data_offset + table_data_size;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&signature);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&compression_method.to_le_bytes());
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);

    bytes.extend_from_slice(&device_info);
    bytes.extend_from_slice(&ewf2_desc(0x01, device_info.len() as u64, 0));
    if let Some(payload) = chunk_payload {
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&ewf2_desc(
            0x03,
            payload.len() as u64,
            device_desc_offset as u64,
        ));
    }

    let mut table_header = [0; 32];
    table_header[0..8].copy_from_slice(&0_u64.to_le_bytes());
    table_header[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&table_header);
    let mut entry = [0; 16];
    let chunk_data_offset = chunk_payload.map_or(pattern, |_| sector_data_offset as u64);
    let chunk_data_size = chunk_payload.map_or(0, |payload| payload.len() as u32);
    entry[0..8].copy_from_slice(&chunk_data_offset.to_le_bytes());
    entry[8..12].copy_from_slice(&chunk_data_size.to_le_bytes());
    entry[12..16].copy_from_slice(&entry_flags.to_le_bytes());
    bytes.extend_from_slice(&entry);
    let previous_offset = if chunk_payload.is_some() {
        sector_desc_offset as u64
    } else {
        device_desc_offset as u64
    };
    bytes.extend_from_slice(&ewf2_desc(0x04, table_data_size as u64, previous_offset));
    bytes.extend_from_slice(&ewf2_desc(0x0f, 0, table_desc_offset as u64));

    let mut file = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
    file.write_all(&bytes).unwrap();
    file.flush().unwrap();
    file
}

#[test]
fn image_open_reads_synthetic_ewf1_with_read_at() {
    let file = synthetic_e01(b"hello ewf");

    let image = ewf_image::Image::open(file.path()).unwrap();
    let info = image.info();
    assert_eq!(info.format, ewf_image::Format::Ewf1);
    assert_eq!(info.segment_count, 1);
    assert_eq!(info.chunk_size, 32_768);
    assert_eq!(info.logical_size, 32_768);

    let mut buf = [0; 9];
    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 9);
    assert_eq!(&buf, b"hello ewf");
}

#[test]
fn image_exposes_compatibility_style_read_buffer_at_offset_alias() {
    let file = synthetic_e01(b"hello ewf");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 3];

    let read = image.read_buffer_at_offset(&mut buf, 6).unwrap();

    assert_eq!(read, 3);
    assert_eq!(&buf, b"ewf");
}

#[test]
fn image_exposes_opened_segment_status_probes() {
    let file = synthetic_e01(b"clean segments");
    let image = ewf_image::Image::open(file.path()).unwrap();

    assert!(!image.segment_files_corrupted().unwrap());
    assert!(!image.segment_files_encrypted().unwrap());
}

#[test]
fn image_open_exposes_ewf1_media_info() {
    let file = synthetic_e01_with_geometry(1, 64, 512, 64);

    let image = ewf_image::Image::open(file.path()).unwrap();
    let media = &image.info().media;

    assert_eq!(media.sectors_per_chunk, Some(64));
    assert_eq!(media.bytes_per_sector, Some(512));
    assert_eq!(media.sector_count, Some(64));
    assert_eq!(media.chunk_count, Some(1));
    assert_eq!(media.error_granularity, None);
    assert_eq!(media.set_identifier, None);
    assert_eq!(media.ewf2_segment_file_version, None);
    assert_eq!(
        media.compression_method,
        Some(ewf_image::CompressionMethod::Zlib)
    );
    assert_eq!(media.media_type, None);
    assert_eq!(
        media.media_flags,
        ewf_image::MediaFlags {
            physical: true,
            fastbloc: false,
            tableau: false,
        }
    );
    assert_eq!(image.format(), ewf_image::Format::Ewf1);
    assert_eq!(image.format_profile(), ewf_image::FormatProfile::EnCase2);
    assert_eq!(image.chunk_size(), 32_768);
    assert_eq!(image.media_size(), 32_768);
    assert_eq!(image.sectors_per_chunk(), Some(64));
    assert_eq!(image.bytes_per_sector(), Some(512));
    assert_eq!(image.number_of_sectors(), Some(64));
    assert_eq!(image.number_of_chunks(), Some(1));
    assert_eq!(image.error_granularity(), None);
    assert_eq!(image.segment_file_set_identifier(), None);
    assert_eq!(image.segment_file_version(), None);
    assert_eq!(
        image.compression_method(),
        Some(ewf_image::CompressionMethod::Zlib)
    );
    assert_eq!(image.media_type(), None);
    assert_eq!(image.media_flags(), media.media_flags);
}

#[test]
fn image_open_exposes_ewf1_compression_values() {
    let bytes = ewf1_bytes_with_options(
        b"best compression metadata",
        Ewf1BytesOptions {
            signature: EVF_SIGNATURE,
            segment_number: 1,
            total_chunks: 1,
            total_sectors: 64,
            is_compressed: true,
            compression_level: 2,
            digest: None,
            media_section_type: b"volume",
        },
    );
    let file = write_temp_with_suffix(".E01", &bytes);
    let image = ewf_image::Image::open(file.path()).unwrap();
    let expected = ewf_image::CompressionValues {
        level: ewf_image::CompressionLevel::Best,
        flags: ewf_image::CompressionFlags::default(),
    };

    assert_eq!(image.info().media.compression_values, expected);
    assert_eq!(image.compression_values(), expected);
}

#[test]
fn image_open_exposes_logical_ewf1_media_flag() {
    let file = synthetic_l01(b"logical ewf1");

    let image = ewf_image::Image::open(file.path()).unwrap();

    assert_eq!(
        image.info().media.media_flags,
        ewf_image::MediaFlags {
            physical: false,
            fastbloc: false,
            tableau: false,
        }
    );
}

#[test]
fn image_open_accepts_ewf1_zero_sized_done_section() {
    let file = synthetic_e01_zero_sized_done(b"zero done");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 9];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert!(image.info().acquisition_complete);
    assert_eq!(read, 9);
    assert_eq!(&buf, b"zero done");
}

#[test]
fn image_open_reads_incomplete_ewf1_next_terminated_image() {
    let file = synthetic_e01_next_terminated(b"incomplete ewf1");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 15];

    assert!(!image.info().acquisition_complete);
    assert_eq!(image.read_at(&mut buf, 0).unwrap(), 15);
    assert_eq!(&buf, b"incomplete ewf1");
}

#[test]
fn image_open_rejects_ewf1_section_chain_that_does_not_advance() {
    let file = synthetic_e01_with_volume_next(13);

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message == "EWF1 section chain does not advance"
    ));
}

#[test]
fn image_open_rejects_ewf1_overlapping_section_chain() {
    let file = synthetic_e01_with_volume_next(13 + 76);

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message == "EWF1 next section offset overlaps current section"
    ));
}

#[test]
fn image_open_rejects_ewf1_section_next_overflow() {
    let file = synthetic_e01_with_max_section_next();

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Malformed(_)));
}

#[test]
fn image_open_rejects_ewf1_section_size_overflow() {
    let file = synthetic_e01_with_max_sectors_section_size();

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message) if message.contains("section data exceeds file")
    ));
}

#[test]
fn image_open_reads_synthetic_ewf1_raw_chunk() {
    let file = synthetic_e01_raw(b"hello raw");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 9];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 9);
    assert_eq!(&buf, b"hello raw");
}

#[test]
fn image_open_reads_ewf1_final_partial_raw_chunk_with_checksum() {
    let expected = vec![0x5a; 512];
    let file = synthetic_e01_final_partial_raw_chunk_with_checksum(&expected);
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = vec![0; expected.len()];

    let read = image.read_at(&mut buf, 0).unwrap();
    let chunk = image.read_data_chunk(0).unwrap();

    assert_eq!(image.media_size(), expected.len() as u64);
    assert_eq!(read, expected.len());
    assert_eq!(buf, expected);
    assert_eq!(chunk.logical_size, expected.len());
    assert_eq!(chunk.data, expected);
    assert!(!chunk.corrupted);
}

#[test]
fn image_read_rejects_ewf1_raw_chunk_bad_checksum() {
    let file = writer_e01_with_bad_raw_chunk_checksum();
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 16];

    let err = image.read_at(&mut buf, 0).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message) if message == "raw chunk checksum mismatch"
    ));
}

#[test]
fn image_read_zeroes_ewf1_raw_chunk_bad_checksum_when_requested() {
    let file = writer_e01_with_bad_raw_chunk_checksum();
    let image = ewf_image::Image::open_with_options(
        file.path(),
        ewf_image::OpenOptions::default().with_read_zero_chunk_on_error(true),
    )
    .unwrap();
    let mut buf = [0x55; 16];

    assert_eq!(image.number_of_checksum_errors().unwrap(), 0);
    assert!(image.checksum_error(0).unwrap().is_none());

    let read = image.read_at(&mut buf, 0).unwrap();
    let chunk = image.read_data_chunk(0).unwrap();

    assert_eq!(read, 16);
    assert_eq!(buf, [0; 16]);
    assert!(chunk.corrupted);
    assert_eq!(chunk.data, vec![0; chunk.logical_size]);
    assert_eq!(image.number_of_checksum_errors().unwrap(), 1);
    assert_eq!(
        image.checksum_error(0).unwrap(),
        Some(ewf_image::SectorRange {
            first_sector: 0,
            sector_count: 1,
        })
    );
    assert!(image.checksum_error(1).unwrap().is_none());
    assert_eq!(
        image.checksum_errors().unwrap(),
        vec![ewf_image::SectorRange {
            first_sector: 0,
            sector_count: 1,
        }]
    );
}

#[test]
fn image_set_read_zero_chunk_on_error_updates_existing_handle() {
    let file = writer_e01_with_bad_raw_chunk_checksum();
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = vec![0xff; b"bad raw checksum".len()];

    assert!(!image.read_zero_chunk_on_error());

    let err = image.read_at(&mut buf, 0).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message) if message == "raw chunk checksum mismatch"
    ));
    assert_eq!(image.number_of_checksum_errors().unwrap(), 0);

    image.set_read_zero_chunk_on_error(true);

    assert!(image.read_zero_chunk_on_error());

    let mut zeroed = vec![0xff; b"bad raw checksum".len()];
    let read = image.read_at(&mut zeroed, 0).unwrap();

    assert_eq!(read, b"bad raw checksum".len());
    assert_eq!(zeroed, vec![0; b"bad raw checksum".len()]);
    assert_eq!(image.number_of_checksum_errors().unwrap(), 1);
}

#[test]
fn image_signal_abort_stops_subsequent_reads() {
    let file = synthetic_e01(b"abortable data");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let clone = image.clone();
    let mut initial = [0; 4];

    assert_eq!(image.read_at(&mut initial, 0).unwrap(), 4);
    assert_eq!(&initial, b"abor");

    image.signal_abort();

    let mut buf = [0; 4];
    assert!(matches!(
        image.read_at(&mut buf, 0).unwrap_err(),
        ewf_image::EwfError::Aborted
    ));
    assert!(matches!(
        clone.read_at(&mut buf, 0).unwrap_err(),
        ewf_image::EwfError::Aborted
    ));
    assert!(matches!(
        image.read_data_chunk(0).unwrap_err(),
        ewf_image::EwfError::Aborted
    ));
    assert!(matches!(
        image.read_encoded_data_chunk(0).unwrap_err(),
        ewf_image::EwfError::Aborted
    ));

    let mut cursor = image.cursor();
    assert!(matches!(
        cursor.read_buffer(&mut buf).unwrap_err(),
        ewf_image::EwfError::Aborted
    ));
}

#[test]
fn image_open_rejects_ewf1_table_bad_header_checksum() {
    let file = writer_e01_with_bad_table_header_checksum();

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message) if message.contains("EWF1 table header checksum")
    ));
}

#[test]
fn image_open_rejects_ewf1_table_bad_entries_checksum() {
    let file = writer_e01_with_bad_table_entries_checksum();

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message) if message.contains("EWF1 table entries checksum")
    ));
}

#[test]
fn image_open_rejects_ewf1_section_bad_descriptor_checksum() {
    let file = writer_e01_with_bad_descriptor_checksum();

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message) if message.contains("EWF1 section descriptor checksum")
    ));
}

#[test]
fn image_open_rejects_ewf1_volume_bad_checksum() {
    let file = writer_e01_with_bad_volume_checksum();

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message) if message.contains("EWF1 volume checksum")
    ));
}

#[test]
fn image_open_rejects_ewf1_logical_size_overflow() {
    let file = synthetic_e01_with_geometry(1, 64, u32::MAX, u64::MAX);

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Malformed(_)));
}

#[test]
fn image_open_rejects_ewf1_declared_media_without_table_coverage() {
    let file = synthetic_e01_without_table_coverage();

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message) if message.contains("table coverage")
    ));
}

#[test]
fn image_open_rejects_ewf1_oversized_chunk_size() {
    let file = synthetic_e01_with_geometry(1, 32_769, 4096, 32_769);

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Malformed(_)));
}

#[test]
fn image_open_reads_synthetic_ewf1_data_section_media() {
    let file = synthetic_e01_data_section(b"data section");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 12];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 12);
    assert_eq!(&buf, b"data section");
}

#[test]
fn image_open_reads_synthetic_ewf1_table_resident_chunk() {
    let file = synthetic_e01_table_resident(b"table resident");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 14];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 14);
    assert_eq!(&buf, b"table resident");
}

#[test]
fn image_open_reads_ewf1_table_resident_chunk_without_entries_checksum() {
    let file = synthetic_e01_table_resident_without_entries_checksum(b"resident no footer");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 18];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 18);
    assert_eq!(&buf, b"resident no footer");
}

#[test]
fn image_open_reads_ewf1_multiple_table_sector_pairs() {
    let file = synthetic_e01_separate_table_sector_ranges(&[b"first range", b"second range"]);
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 12];

    let read = image.read_at(&mut buf, 32_768).unwrap();

    assert_eq!(read, 12);
    assert_eq!(&buf, b"second range");
}

#[test]
fn image_open_reads_ewf1_section_chain_longer_than_4096() {
    let file = synthetic_e01_with_filler_sections(b"long section chain", 4096);
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 18];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(image.info().segment_count, 1);
    assert_eq!(read, 18);
    assert_eq!(&buf, b"long section chain");
}

#[test]
fn image_open_reads_unique_ewf1_table2_range() {
    let file = synthetic_e01_separate_table_sector_ranges_with_types(
        &[b"table range", b"table2 range"],
        &[b"table", b"table2"],
    );
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 12];

    let read = image.read_at(&mut buf, 32_768).unwrap();

    assert_eq!(read, 12);
    assert_eq!(&buf, b"table2 range");
}

#[test]
fn image_open_reads_later_ewf1_table_after_table2_mirror() {
    let file = synthetic_e01_table2_mirror_then_later_table();
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 17];

    let read = image.read_at(&mut buf, 32_768).unwrap();

    assert_eq!(read, 17);
    assert_eq!(&buf, b"second real table");
}

#[test]
fn image_open_reads_ewf1_table_after_preceding_sectors() {
    let file = synthetic_e01_preceding_sectors_table(b"preceding sectors", false);
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 17];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 17);
    assert_eq!(&buf, b"preceding sectors");
}

#[test]
fn image_open_reads_ewf1_table_after_preceding_sectors_with_descriptor_base() {
    let file = synthetic_e01_preceding_sectors_table(b"descriptor base", true);
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 15];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 15);
    assert_eq!(&buf, b"descriptor base");
}

#[test]
fn image_open_reads_final_chunk_from_ewf1_absolute_trailing_table() {
    let file = synthetic_e01_preceding_sectors_absolute_raw_table();
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 16];

    let read = image.read_at(&mut buf, 32_768).unwrap();

    assert_eq!(read, 16);
    assert_eq!(buf, [0x22; 16]);
}

#[test]
fn image_open_reads_synthetic_ewf1_full_width_table_offset() {
    let file = synthetic_e01_full_width_offset(b"full width");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 10];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 10);
    assert_eq!(&buf, b"full width");
}

#[test]
fn image_open_reads_synthetic_ewf1_full_width_table_offset_with_zero_base() {
    let file = synthetic_e01_full_width_offset_with_zero_base(b"overflowed");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 10];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 10);
    assert_eq!(&buf, b"overflowed");
}

#[test]
fn image_open_parses_synthetic_ewf1_xhash_section() {
    let md5 = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let sha1 = [
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00, 0x10, 0x32, 0x54, 0x76,
    ];
    let file = synthetic_e01_with_xhash(b"xhash section", md5, sha1);
    let md5_text = hex_string(&md5);
    let sha1_text = hex_string(&sha1);

    let image = ewf_image::Image::open(file.path()).unwrap();

    assert_eq!(image.info().stored_hashes.md5, Some(md5));
    assert_eq!(image.info().stored_hashes.sha1, Some(sha1));
    assert_eq!(image.number_of_hash_values(), 2);
    assert_eq!(image.hash_value_identifier(0), Some("MD5"));
    assert_eq!(image.hash_value_identifier(1), Some("SHA1"));
    assert_eq!(image.hash_value_identifier(2), None);
    assert_eq!(image.hash_value("MD5"), Some(md5_text.as_str()));
    assert_eq!(image.hash_value("SHA1"), Some(sha1_text.as_str()));
    assert_eq!(image.hash_value("SHA256"), None);
    assert_eq!(
        image
            .info()
            .stored_hashes
            .hash_values
            .get("MD5")
            .map(String::as_str),
        Some(md5_text.as_str())
    );
    assert_eq!(
        image
            .info()
            .stored_hashes
            .hash_values
            .get("SHA1")
            .map(String::as_str),
        Some(sha1_text.as_str())
    );
}

#[test]
fn image_open_parses_synthetic_ewf1_xheader_section() {
    let file = synthetic_e01_with_xheader(b"xheader section");

    let image = ewf_image::Image::open(file.path()).unwrap();
    let metadata = &image.info().metadata;

    assert_eq!(metadata.case_number.as_deref(), Some("CASE-X"));
    assert_eq!(
        metadata.description.as_deref(),
        Some("Extended header image")
    );
    assert_eq!(metadata.examiner.as_deref(), Some("Analyst X"));
    assert_eq!(metadata.evidence_number.as_deref(), Some("EVID-X"));
    assert_eq!(metadata.notes.as_deref(), Some("Extended notes"));
    assert_eq!(metadata.os_version.as_deref(), Some("Linux"));
    assert_eq!(
        metadata.acquisition_date.as_deref(),
        Some("Sat Jan 20 18:32:08 2007 CET")
    );
    assert_eq!(metadata.acquisition_software.as_deref(), Some("ewfacquire"));
    assert_eq!(
        metadata.acquisition_software_version.as_deref(),
        Some("20070120")
    );
    assert_eq!(
        metadata
            .header_values
            .get("acquiry_software_version")
            .map(String::as_str),
        Some("20070120")
    );
    assert_eq!(image.number_of_header_values(), 9);
    assert_eq!(image.header_value_identifier(0), Some("case_number"));
    assert_eq!(
        image.header_value_identifier(8),
        Some("acquiry_software_version")
    );
    assert_eq!(image.header_value_identifier(9), None);
    assert_eq!(image.header_value("case_number").as_deref(), Some("CASE-X"));
    assert_eq!(
        image.header_value("examiner_name").as_deref(),
        Some("Analyst X")
    );
    assert_eq!(image.header_value("missing"), None);
}

#[test]
fn image_open_applies_date_format_to_xheader_ctime_dates() {
    let file = synthetic_e01_with_xheader(b"xheader date format");

    let image = ewf_image::Image::open_with_options(
        file.path(),
        ewf_image::OpenOptions::default()
            .with_header_values_date_format(ewf_image::HeaderDateFormat::Iso8601),
    )
    .unwrap();

    assert_eq!(
        image.header_value("acquiry_date").as_deref(),
        Some("2007-01-20T18:32:08")
    );
}

#[test]
fn image_open_ignores_zero_filled_digest_hashes() {
    let sha1 = [
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00, 0x10, 0x32, 0x54, 0x76,
    ];
    let file = synthetic_e01_with_digest(b"zero md5 digest", Some(([0; 16], sha1)));

    let image = ewf_image::Image::open(file.path()).unwrap();

    assert_eq!(image.info().stored_hashes.md5, None);
    assert_eq!(image.info().stored_hashes.sha1, Some(sha1));
}

#[test]
fn image_open_rejects_short_ewf1_digest_section() {
    let file = synthetic_e01_with_digest_payload(b"short digest", &[0xab; 36]);

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Malformed(_)));
}

#[test]
fn image_open_rejects_ewf1_digest_bad_checksum() {
    let md5 = [
        0xc1, 0x4c, 0xa9, 0x70, 0x91, 0x5e, 0x64, 0x22, 0xb9, 0x4f, 0xaa, 0xf8, 0x95, 0xfa, 0xb3,
        0xaa,
    ];
    let sha1 = [
        0x59, 0x68, 0x2b, 0xdd, 0xd4, 0xb2, 0xa3, 0x1b, 0x08, 0xbc, 0x69, 0x77, 0x16, 0x96, 0x91,
        0xc1, 0x0d, 0xb7, 0xa5, 0x01,
    ];
    let mut digest = ewf1_digest_payload(md5, sha1);
    digest[76] ^= 0x80;
    let file = synthetic_e01_with_digest_payload(b"bad digest checksum", &digest);

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message) if message.contains("EWF1 digest checksum")
    ));
}

#[test]
fn image_open_rejects_short_ewf1_hash_section() {
    let file = synthetic_e01_with_hash_payload(b"short hash", &[0xab; 16]);

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Malformed(_)));
}

#[test]
fn image_open_rejects_ewf1_hash_bad_checksum() {
    let md5 = [
        0x19, 0xb8, 0xbb, 0xe1, 0xf3, 0x2b, 0x02, 0x5b, 0xd7, 0xd6, 0x3b, 0x08, 0xad, 0x16, 0x07,
        0x7a,
    ];
    let mut hash = ewf1_hash_payload(md5);
    hash[32] ^= 0x80;
    let file = synthetic_e01_with_hash_payload(b"bad hash checksum", &hash);

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message) if message.contains("EWF1 MD5 hash checksum")
    ));
}

#[test]
fn image_open_reads_synthetic_l01_lvf() {
    let file = synthetic_l01(b"hello l01");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 9];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(image.info().format, ewf_image::Format::Ewf1);
    assert_eq!(read, 9);
    assert_eq!(&buf, b"hello l01");
}

#[test]
fn image_open_reads_synthetic_s01_oversized_compressed_chunk() {
    let file = synthetic_s01_oversized_compressed_chunk(b"hello s01");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 9];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(image.info().format, ewf_image::Format::Ewf1);
    assert_eq!(read, 9);
    assert_eq!(&buf, b"hello s01");
}

#[test]
fn image_open_reads_large_stored_zlib_e01_chunk() {
    let file = synthetic_e01_large_stored_zlib_chunk(b"large stored zlib");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 17];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 17);
    assert_eq!(&buf, b"large stored zlib");
}

#[test]
fn image_open_reads_unflagged_stored_zlib_e01_chunk() {
    let file = synthetic_e01_unflagged_stored_zlib_chunk(b"unflagged zlib");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 14];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 14);
    assert_eq!(&buf, b"unflagged zlib");
}

#[test]
fn image_open_exposes_smart_format_profile() {
    let file = synthetic_s01_oversized_compressed_chunk(b"smart profile");
    let image = ewf_image::Image::open(file.path()).unwrap();

    assert_eq!(image.info().format_profile, ewf_image::FormatProfile::Smart);
}

#[test]
fn sparse_ewf1_header_does_not_claim_encase1_generation() {
    let file = synthetic_e01_with_header_text(b"sparse metadata", "1\nmain\nc\nCASE-001\n");
    let image = ewf_image::Image::open(file.path()).unwrap();
    assert_eq!(image.format_profile(), ewf_image::FormatProfile::EnCase2);
    assert_eq!(
        image.info().metadata.case_number.as_deref(),
        Some("CASE-001")
    );
}

#[test]
fn image_open_detects_ewf1_encase1_format_profile_from_header() {
    let file = synthetic_e01_with_header_text(
        b"encase1 profile",
        "1\r\nmain\r\nc\tn\ta\te\tm\tu\tp\tov\tr\r\nCASE\tEVID\tDesc\tExaminer\t2026\t2026\tpassword\tWindows\tgood\r\n",
    );
    let image = ewf_image::Image::open(file.path()).unwrap();

    assert_eq!(
        image.info().format_profile,
        ewf_image::FormatProfile::EnCase1
    );
    assert_eq!(image.info().metadata.password.as_deref(), Some("password"));
}

#[test]
fn image_open_detects_ewf1_ftk_imager_format_profile_from_header() {
    let file = synthetic_e01_with_header_text(
        b"ftk profile",
        "1\nmain\nc\tn\ta\te\tm\tu\tp\tav\tov\tdc\tr\nCASE\tEVID\tDesc\tExaminer\t2026\t2026\tpassword\t3.4\tWindows\tunknown\tgood\n",
    );
    let image = ewf_image::Image::open(file.path()).unwrap();

    assert_eq!(
        image.info().format_profile,
        ewf_image::FormatProfile::FtkImager
    );
}

#[test]
fn image_open_detects_ftk_profile_from_smart_image_header() {
    let file = synthetic_s01_with_header_text(
        b"smart ftk profile",
        "1\nmain\nc\tn\ta\te\tm\tu\tp\tav\tov\tdc\tr\nCASE\tEVID\tDesc\tExaminer\t2026\t2026\tpassword\t3.4\tWindows\tunknown\tgood\n",
    );
    let image = ewf_image::Image::open(file.path()).unwrap();

    assert_eq!(
        image.info().format_profile,
        ewf_image::FormatProfile::FtkImager
    );
}

#[test]
fn image_open_detects_ewf1_linen6_format_profile_from_header() {
    let file = synthetic_e01_with_header_text(
        b"linen6 profile",
        "3\nmain\nc\tn\ta\te\tm\tmd\nCASE\tEVID\tDesc\tExaminer\t2026\tModel\n",
    );
    let image = ewf_image::Image::open(file.path()).unwrap();

    assert_eq!(
        image.info().format_profile,
        ewf_image::FormatProfile::Linen6
    );
}

#[test]
fn image_open_preserves_ewf1_header2_profile_after_legacy_header() {
    let header2 = utf16le(
        "3\nmain\na\tc\tn\te\tt\tmd\tsn\tav\tov\tm\tu\tp\tdc\n\t\t\t\t\t\t\t20231119\tDarwin\t1779327940\t1779327940\t\t\n\n",
    );
    let legacy_header = "1\r\nmain\r\nc\tn\ta\te\tt\tav\tov\tm\tu\tp\r\n\t\t\t\t\t20231119\tDarwin\t2026 5 21 9 45 40\t2026 5 21 9 45 40\t0\r\n\r\n";
    let bytes = ewf1_bytes_with_metadata_sections(
        b"header2 profile",
        1,
        1,
        64,
        &[
            (b"header2", header2.as_slice()),
            (b"header", legacy_header.as_bytes()),
        ],
    );
    let file = write_temp_with_suffix(".E01", &bytes);
    let image = ewf_image::Image::open(file.path()).unwrap();

    assert_eq!(
        image.info().format_profile,
        ewf_image::FormatProfile::EnCase6
    );
}

#[test]
fn image_open_detects_ewf_format_profile_from_lowercase_extension() {
    let file = synthetic_e01_full_volume_with_suffix(b"ewf profile", ".e01");
    let image = ewf_image::Image::open(file.path()).unwrap();

    assert_eq!(image.info().format_profile, ewf_image::FormatProfile::Ewf);
}

#[test]
fn image_open_reads_synthetic_multisegment_ewf1() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("multi.E01");
    let second = dir.path().join("multi.E02");
    std::fs::write(
        &first,
        ewf1_bytes(b"first segment", EVF_SIGNATURE, 1, 2, 128, true, None),
    )
    .unwrap();
    std::fs::write(
        &second,
        ewf1_bytes(b"second segment", EVF_SIGNATURE, 2, 2, 128, true, None),
    )
    .unwrap();

    let image = ewf_image::Image::open(&first).unwrap();
    let expected_segment_set_size =
        std::fs::metadata(&first).unwrap().len() + std::fs::metadata(&second).unwrap().len();
    let mut first_buf = [0; 13];
    let mut second_buf = [0; 14];

    let first_read = image.read_at(&mut first_buf, 0).unwrap();
    let second_read = image.read_at(&mut second_buf, 32_768).unwrap();

    assert_eq!(image.info().segment_count, 2);
    assert_eq!(image.info().segment_paths, vec![first, second]);
    assert_eq!(image.info().logical_size, 65_536);
    assert_eq!(image.segment_set_size().unwrap(), expected_segment_set_size);
    assert_eq!(first_read, 13);
    assert_eq!(&first_buf, b"first segment");
    assert_eq!(second_read, 14);
    assert_eq!(&second_buf, b"second segment");
}

#[test]
fn image_open_reads_ewf1_continuation_without_media_section() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("media-once.E01");
    let second = dir.path().join("media-once.E02");
    std::fs::write(
        &first,
        ewf1_bytes(b"first segment", EVF_SIGNATURE, 1, 2, 128, true, None),
    )
    .unwrap();
    std::fs::write(
        &second,
        ewf1_chunk_only_segment_bytes(&compressed_chunk(b"second segment", 32_768), 2, 1),
    )
    .unwrap();

    let image = ewf_image::Image::open(&first).unwrap();
    let mut second_buf = [0; 14];

    let second_read = image.read_at(&mut second_buf, 32_768).unwrap();

    assert_eq!(image.info().logical_size, 65_536);
    assert_eq!(second_read, 14);
    assert_eq!(&second_buf, b"second segment");
}

#[test]
fn image_open_reads_ewf1_continuation_session_without_media_section() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("session-inherit.E01");
    let second = dir.path().join("session-inherit.E02");
    std::fs::write(
        &first,
        ewf1_bytes(b"first segment", EVF_SIGNATURE, 1, 2, 128, true, None),
    )
    .unwrap();
    std::fs::write(
        &second,
        ewf1_chunk_and_session_segment_bytes(
            &compressed_chunk(b"second segment", 32_768),
            &ewf1_session_payload(&[(0, 0), (64, 0)]),
            2,
            1,
        ),
    )
    .unwrap();

    let image = ewf_image::Image::open(&first).unwrap();

    assert_eq!(
        image.info().sessions,
        [
            ewf_image::SectorRange {
                first_sector: 0,
                sector_count: 64,
            },
            ewf_image::SectorRange {
                first_sector: 64,
                sector_count: 64,
            },
        ]
    );
}

#[test]
fn image_open_rejects_mismatched_ewf1_continuation_media() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("media-mismatch.E01");
    let second = dir.path().join("media-mismatch.E02");
    std::fs::write(
        &first,
        ewf1_bytes(b"first segment", EVF_SIGNATURE, 1, 2, 128, true, None),
    )
    .unwrap();
    let mut second_bytes = ewf1_bytes(b"second segment", EVF_SIGNATURE, 2, 2, 128, true, None);
    second_bytes[97..101].copy_from_slice(&32_u32.to_le_bytes());
    std::fs::write(&second, second_bytes).unwrap();

    let err = ewf_image::Image::open(&first).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("EWF1 media geometry mismatch")
    ));
}

#[test]
fn image_open_rejects_mismatched_ewf1_compression_across_segments() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("compression-mismatch.E01");
    let second = dir.path().join("compression-mismatch.E02");
    std::fs::write(
        &first,
        ewf1_bytes(b"first segment", EVF_SIGNATURE, 1, 2, 128, true, None),
    )
    .unwrap();
    std::fs::write(
        &second,
        ewf1_chunk_only_segment_bytes(&xways_magicless_zstd_chunk(b"second segment"), 2, 0x21),
    )
    .unwrap();

    let err = ewf_image::Image::open(&first).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("EWF1 compression method mismatch across segments")
    ));
}

#[test]
fn image_open_rejects_conflicting_xways_compression_markers() {
    let mut bytes = xways_ewf1_segment_bytes(&xways_magicless_zstd_chunk(b"marker conflict"), b"");
    bytes[8] = 1;
    let file = write_temp_with_suffix(".e01", &bytes);

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("compression marker conflict")
    ));
}

#[test]
fn image_open_rejects_unknown_ewf1_descriptor_compression_marker() {
    let mut bytes = xways_ewf1_segment_bytes(&xways_magicless_zstd_chunk(b"unknown marker"), b"");
    bytes[13 + 32..13 + 72].fill(0);
    bytes[13 + 32..13 + 38].copy_from_slice(b"Snappy");
    let file = write_temp_with_suffix(".e01", &bytes);

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("unsupported EWF1 descriptor compression marker")
    ));
}

#[test]
fn image_open_rejects_unknown_ewf1_file_header_marker() {
    let mut bytes = ewf1_bytes(
        b"unknown header marker",
        EVF_SIGNATURE,
        1,
        1,
        64,
        true,
        None,
    );
    bytes[8] = 0x7f;
    let file = write_temp_with_suffix(".e01", &bytes);

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("unsupported EWF1 file header marker")
    ));
}

#[test]
fn image_open_decodes_xways_zstd_header_metadata() {
    let header = b"1\r\nmain\r\nc\tn\ta\te\tm\tu\tp\tov\tr\r\nXW-CASE\tEVID\tDesc\tExaminer\t2026\t2026\tpassword\tWindows\tgood\r\n";
    let bytes = xways_ewf1_segment_bytes(&xways_magicless_zstd_chunk(b"xways data"), header);
    let file = write_temp_with_suffix(".e01", &bytes);

    let image = ewf_image::Image::open(file.path()).unwrap();

    assert_eq!(
        image.info().metadata.case_number.as_deref(),
        Some("XW-CASE")
    );
}

#[test]
fn image_open_reports_xways_zstd_compression_method() {
    let bytes = xways_ewf1_segment_bytes(&xways_magicless_zstd_chunk(b"xways compression"), b"");
    let file = write_temp_with_suffix(".e01", &bytes);

    let image = ewf_image::Image::open(file.path()).unwrap();

    assert_eq!(
        image.compression_method(),
        Some(ewf_image::CompressionMethod::Zstd)
    );
}

#[test]
fn image_open_reads_xways_magicless_zstd_chunk() {
    let bytes = xways_ewf1_segment_bytes(&xways_magicless_zstd_chunk(b"xways compressed"), b"");
    let file = write_temp_with_suffix(".e01", &bytes);
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 16];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 16);
    assert_eq!(&buf, b"xways compressed");
}

#[test]
fn image_open_reads_xways_zero_chunk_marker() {
    let bytes = xways_ewf1_segment_bytes(&[0], b"");
    let file = write_temp_with_suffix(".e01", &bytes);
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0xff; 32];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 32);
    assert_eq!(buf, [0; 32]);
}

#[test]
fn image_read_rejects_invalid_xways_zero_chunk_marker() {
    let bytes = xways_ewf1_segment_bytes(&[1], b"");
    let file = write_temp_with_suffix(".e01", &bytes);
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 32];

    let err = image.read_at(&mut buf, 0).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("invalid X-Ways zero chunk marker")
    ));
}

#[test]
fn image_read_rejects_xways_zstd_window_above_limit() {
    let bytes = xways_ewf1_segment_bytes(&ZSTD_128_MIB_WINDOW_FRAME[4..], b"");
    let file = write_temp_with_suffix(".e01", &bytes);
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 32];

    let err = image.read_at(&mut buf, 0).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.to_ascii_lowercase().contains("window")
    ));
}

#[test]
fn image_open_rejects_xways_zstd_metadata_window_above_limit() {
    let bytes = xways_ewf1_segment_bytes_with_encoded_header(
        &xways_magicless_zstd_chunk(b"metadata window"),
        &ZSTD_128_MIB_WINDOW_FRAME,
    );
    let file = write_temp_with_suffix(".e01", &bytes);

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.to_ascii_lowercase().contains("window")
    ));
}

#[test]
#[ignore = "requires EWF_XWAYS_FIXTURE pointing to a complete X-Ways E01 set"]
fn external_xways_zstd_fixture_opens_and_reads() {
    let path = std::env::var_os("EWF_XWAYS_FIXTURE")
        .expect("EWF_XWAYS_FIXTURE must point to the first X-Ways segment");

    let image = ewf_image::Image::open(path).unwrap();
    let mut boot = [0; 1024];
    let mut sparse = [0xff; 32];

    assert_eq!(image.read_at(&mut boot, 0).unwrap(), boot.len());
    assert_eq!(image.read_at(&mut sparse, 32_768).unwrap(), sparse.len());
    assert_eq!(image.number_of_segments(), 6);
    assert_eq!(image.info().chunk_size, 32_768);
    assert_eq!(image.info().logical_size, 136_365_211_648);
    assert_eq!(
        image.compression_method(),
        Some(ewf_image::CompressionMethod::Zstd)
    );
    assert_eq!(
        image.info().stored_hashes.md5,
        Some([
            0xef, 0x1a, 0xaa, 0x4a, 0xc3, 0x47, 0xc3, 0x91, 0x98, 0x38, 0x37, 0x9e, 0x00, 0x4c,
            0xa5, 0x6c,
        ])
    );
    assert_eq!(&boot[510..512], &[0x55, 0xaa]);
    assert_eq!(&boot[512..520], b"EFI PART");
    assert_eq!(sparse, [0; 32]);

    let chunk_count = image.number_of_chunks().unwrap();
    let segment_index_for_chunk = |chunk_index| {
        let path = image.segment_filename_for_chunk(chunk_index).unwrap();
        image
            .segment_filenames()
            .iter()
            .position(|candidate| candidate == path)
            .unwrap()
    };
    for target_segment in 1..image.number_of_segments() {
        let mut low = 0;
        let mut high = chunk_count;
        while low < high {
            let middle = low + (high - low) / 2;
            if segment_index_for_chunk(middle) < target_segment {
                low = middle + 1;
            } else {
                high = middle;
            }
        }

        assert!(low > 0);
        assert!(low < chunk_count);
        assert_eq!(segment_index_for_chunk(low), target_segment);
        let boundary_offset = low.checked_mul(image.info().chunk_size).unwrap();
        let mut cross_boundary = [0; 32];
        assert_eq!(
            image
                .read_at(&mut cross_boundary, boundary_offset - 16)
                .unwrap(),
            cross_boundary.len()
        );
    }
}

#[test]
fn image_open_reads_ewf1_continuation_after_detected_encase6_profile() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("encase6.E01");
    let second = dir.path().join("encase6.E02");
    let header2 = utf16le("3\nmain\nc\tn\ta\te\tm\tmd\nCASE\tEVID\tDesc\tExaminer\t2026\tModel\n");
    std::fs::write(
        &first,
        ewf1_bytes_with_metadata_section(b"first segment", 1, 2, 128, b"header2", &header2),
    )
    .unwrap();
    std::fs::write(
        &second,
        ewf1_bytes_with_metadata_section(b"second segment", 2, 2, 128, b"header", b""),
    )
    .unwrap();

    let image = ewf_image::Image::open(&first).unwrap();
    let mut first_buf = [0; 13];
    let mut second_buf = [0; 14];

    let first_read = image.read_at(&mut first_buf, 0).unwrap();
    let second_read = image.read_at(&mut second_buf, 32_768).unwrap();

    assert_eq!(image.info().segment_count, 2);
    assert_eq!(
        image.info().format_profile,
        ewf_image::FormatProfile::EnCase6
    );
    assert_eq!(image.info().logical_size, 65_536);
    assert_eq!(first_read, 13);
    assert_eq!(&first_buf, b"first segment");
    assert_eq!(second_read, 14);
    assert_eq!(&second_buf, b"second segment");
}

#[test]
fn image_open_reads_ewf1_continuation_extension_after_ezz() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("continued.EZZ");
    let decoy = dir.path().join("continued.F01");
    let second = dir.path().join("continued.FAA");
    std::fs::write(
        &first,
        ewf1_bytes(b"first segment", EVF_SIGNATURE, 1, 2, 128, true, None),
    )
    .unwrap();
    std::fs::write(
        &decoy,
        ewf1_bytes(b"wrong segment", EVF_SIGNATURE, 2, 2, 128, true, None),
    )
    .unwrap();
    std::fs::write(
        &second,
        ewf1_bytes(b"second segment", EVF_SIGNATURE, 2, 2, 128, true, None),
    )
    .unwrap();

    let image = ewf_image::Image::open(&first).unwrap();
    let mut first_buf = [0; 13];
    let mut second_buf = [0; 14];

    let first_read = image.read_at(&mut first_buf, 0).unwrap();
    let second_read = image.read_at(&mut second_buf, 32_768).unwrap();

    assert_eq!(image.info().segment_count, 2);
    assert_eq!(image.info().segment_paths, vec![first, second]);
    assert_eq!(first_read, 13);
    assert_eq!(&first_buf, b"first segment");
    assert_eq!(second_read, 14);
    assert_eq!(&second_buf, b"second segment");
}

#[test]
fn image_open_reads_logical_ewf1_continuation_extension_after_lzz() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("logical.LZZ");
    let decoy = dir.path().join("logical.M01");
    let second = dir.path().join("logical.MAA");
    std::fs::write(
        &first,
        ewf1_bytes(b"first logical", LVF_SIGNATURE, 1, 2, 128, true, None),
    )
    .unwrap();
    std::fs::write(
        &decoy,
        ewf1_bytes(b"wrong logical", LVF_SIGNATURE, 2, 2, 128, true, None),
    )
    .unwrap();
    std::fs::write(
        &second,
        ewf1_bytes(b"second logical", LVF_SIGNATURE, 2, 2, 128, true, None),
    )
    .unwrap();

    let image = ewf_image::Image::open(&first).unwrap();
    let mut first_buf = [0; 13];
    let mut second_buf = [0; 14];

    let first_read = image.read_at(&mut first_buf, 0).unwrap();
    let second_read = image.read_at(&mut second_buf, 32_768).unwrap();

    assert_eq!(image.info().segment_count, 2);
    assert_eq!(image.info().segment_paths, vec![first, second]);
    assert_eq!(
        image.info().format_profile,
        ewf_image::FormatProfile::LogicalEnCase5
    );
    assert_eq!(first_read, 13);
    assert_eq!(&first_buf, b"first logical");
    assert_eq!(second_read, 14);
    assert_eq!(&second_buf, b"second logical");
}

#[test]
fn image_open_reads_smart_ewf1_continuation_extension_after_szz() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("smart.sZZ");
    let decoy = dir.path().join("smart.t01");
    let second = dir.path().join("smart.taa");
    std::fs::write(&first, smart_ewf1_bytes(b"first smart", 1, 2)).unwrap();
    std::fs::write(&decoy, smart_ewf1_bytes(b"wrong smart", 2, 2)).unwrap();
    std::fs::write(&second, smart_ewf1_bytes(b"second smart", 2, 2)).unwrap();

    let image = ewf_image::Image::open(&first).unwrap();
    let mut first_buf = [0; 11];
    let mut second_buf = [0; 12];

    let first_read = image.read_at(&mut first_buf, 0).unwrap();
    let second_read = image.read_at(&mut second_buf, 32_768).unwrap();

    assert_eq!(image.info().segment_count, 2);
    assert_eq!(image.info().segment_paths, vec![first, second]);
    assert_eq!(image.info().format_profile, ewf_image::FormatProfile::Smart);
    assert_eq!(first_read, 11);
    assert_eq!(&first_buf, b"first smart");
    assert_eq!(second_read, 12);
    assert_eq!(&second_buf, b"second smart");
}

#[test]
fn image_open_rejects_mismatched_ewf1_set_identifiers_across_segments() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("mismatch.E01");
    let second = dir.path().join("mismatch.E02");
    std::fs::write(
        &first,
        ewf1_metadata_segment_bytes(1, b"volume", [0x11; 16]),
    )
    .unwrap();
    std::fs::write(&second, ewf1_metadata_segment_bytes(2, b"data", [0x22; 16])).unwrap();

    let err = ewf_image::Image::open(&first).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("segment set identifier mismatch")
    ));
}

#[test]
fn image_open_reads_segments_from_supplied_readers() {
    let first = ewf1_bytes(b"first segment", EVF_SIGNATURE, 1, 2, 128, true, None);
    let second = ewf1_bytes(b"second segment", EVF_SIGNATURE, 2, 2, 128, true, None);

    let image = ewf_image::Image::open_readers([
        ("reader.E01", Cursor::new(first)),
        ("reader.E02", Cursor::new(second)),
    ])
    .unwrap();
    let mut first_buf = [0; 13];
    let mut second_buf = [0; 14];

    let first_read = image.read_at(&mut first_buf, 0).unwrap();
    let second_read = image.read_at(&mut second_buf, 32_768).unwrap();

    assert_eq!(image.info().segment_count, 2);
    assert_eq!(
        image.info().segment_paths,
        vec![
            std::path::PathBuf::from("reader.E01"),
            std::path::PathBuf::from("reader.E02")
        ]
    );
    assert_eq!(image.info().logical_size, 65_536);
    assert!(!image.segment_files_corrupted().unwrap());
    assert!(!image.segment_files_encrypted().unwrap());
    assert_eq!(first_read, 13);
    assert_eq!(&first_buf, b"first segment");
    assert_eq!(second_read, 14);
    assert_eq!(&second_buf, b"second segment");
}

#[test]
fn image_supplied_readers_reject_handle_limits_that_require_eviction() {
    let first = ewf1_bytes(b"first segment", EVF_SIGNATURE, 1, 2, 128, true, None);
    let second = ewf1_bytes(b"second segment", EVF_SIGNATURE, 2, 2, 128, true, None);

    let err = ewf_image::Image::open_readers_with_options(
        [
            ("reader.E01", Cursor::new(first.clone())),
            ("reader.E02", Cursor::new(second.clone())),
        ],
        ewf_image::OpenOptions::default().with_maximum_open_handles(Some(1)),
    )
    .unwrap_err();
    assert!(matches!(err, ewf_image::EwfError::Unsupported(_)));

    let image = ewf_image::Image::open_readers([
        ("reader.E01", Cursor::new(first)),
        ("reader.E02", Cursor::new(second)),
    ])
    .unwrap();
    assert_eq!(image.number_of_open_segment_handles().unwrap(), 2);

    let err = image
        .set_maximum_number_of_open_handles(Some(1))
        .unwrap_err();
    assert!(matches!(err, ewf_image::EwfError::Unsupported(_)));
    assert_eq!(image.maximum_number_of_open_handles().unwrap(), None);
    assert_eq!(image.number_of_open_segment_handles().unwrap(), 2);
}

#[test]
fn image_respects_maximum_open_segment_handles() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("limited.E01");
    let second = dir.path().join("limited.E02");
    std::fs::write(
        &first,
        ewf1_bytes(b"first segment", EVF_SIGNATURE, 1, 2, 128, true, None),
    )
    .unwrap();
    std::fs::write(
        &second,
        ewf1_bytes(b"second segment", EVF_SIGNATURE, 2, 2, 128, true, None),
    )
    .unwrap();

    let image = ewf_image::Image::open_with_options(
        &first,
        ewf_image::OpenOptions::default().with_maximum_open_handles(Some(1)),
    )
    .unwrap();

    assert_eq!(image.maximum_number_of_open_handles().unwrap(), Some(1));
    assert!(image.number_of_open_segment_handles().unwrap() <= 1);

    let mut first_buf = [0; 13];
    let mut second_buf = [0; 14];
    assert_eq!(image.read_at(&mut first_buf, 0).unwrap(), 13);
    assert_eq!(&first_buf, b"first segment");
    assert!(image.number_of_open_segment_handles().unwrap() <= 1);

    assert_eq!(image.read_at(&mut second_buf, 32_768).unwrap(), 14);
    assert_eq!(&second_buf, b"second segment");
    assert!(image.number_of_open_segment_handles().unwrap() <= 1);
}

#[test]
fn image_set_maximum_open_segment_handles_evicts_existing_handles() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("limit-after-open.E01");
    let second = dir.path().join("limit-after-open.E02");
    std::fs::write(
        &first,
        ewf1_bytes(b"first segment", EVF_SIGNATURE, 1, 2, 128, true, None),
    )
    .unwrap();
    std::fs::write(
        &second,
        ewf1_bytes(b"second segment", EVF_SIGNATURE, 2, 2, 128, true, None),
    )
    .unwrap();

    let image = ewf_image::Image::open(&first).unwrap();
    assert_eq!(image.maximum_number_of_open_handles().unwrap(), None);
    assert_eq!(image.number_of_open_segment_handles().unwrap(), 2);

    image.set_maximum_number_of_open_handles(Some(1)).unwrap();
    assert_eq!(image.maximum_number_of_open_handles().unwrap(), Some(1));
    assert!(image.number_of_open_segment_handles().unwrap() <= 1);

    let err = image
        .set_maximum_number_of_open_handles(Some(0))
        .unwrap_err();
    assert!(matches!(err, ewf_image::EwfError::Unsupported(_)));
    assert_eq!(image.maximum_number_of_open_handles().unwrap(), Some(1));

    let mut first_buf = [0; 13];
    let mut second_buf = [0; 14];
    assert_eq!(image.read_at(&mut first_buf, 0).unwrap(), 13);
    assert_eq!(image.read_at(&mut second_buf, 32_768).unwrap(), 14);
    assert_eq!(&first_buf, b"first segment");
    assert_eq!(&second_buf, b"second segment");
    assert!(image.number_of_open_segment_handles().unwrap() <= 1);
}

#[test]
fn image_open_reads_multisegment_ewf2_leading_next_section() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("multi.Ex01");
    let second = dir.path().join("multi.Ex02");
    std::fs::write(
        &first,
        ewf2_leading_segment_bytes(1, 0, 0x0d, b"first segment"),
    )
    .unwrap();
    std::fs::write(
        &second,
        ewf2_leading_segment_bytes(2, 1, 0x0f, b"second segment"),
    )
    .unwrap();

    let image = ewf_image::Image::open(&first).unwrap();
    let mut first_buf = [0; 13];
    let mut second_buf = [0; 14];

    let first_read = image.read_at(&mut first_buf, 0).unwrap();
    let second_read = image.read_at(&mut second_buf, 32_768).unwrap();

    assert_eq!(image.info().segment_count, 2);
    assert_eq!(image.info().segment_paths, vec![first, second]);
    assert_eq!(image.info().logical_size, 65_536);
    assert_eq!(first_read, 13);
    assert_eq!(&first_buf, b"first segment");
    assert_eq!(second_read, 14);
    assert_eq!(&second_buf, b"second segment");
}

#[test]
fn image_open_reads_incomplete_ewf2_next_terminated_image() {
    let file = write_temp_with_suffix(
        ".Ex01",
        &ewf2_leading_segment_bytes_with_device_information(
            1,
            0,
            0x0d,
            b"incomplete ewf2",
            "2\nmain\nb\tsc\tts\n512\t64\t64\n\n",
        ),
    );
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 15];

    assert!(!image.info().acquisition_complete);
    assert_eq!(image.read_at(&mut buf, 0).unwrap(), 15);
    assert_eq!(&buf, b"incomplete ewf2");
}

#[test]
fn image_open_reads_ewf2_continuation_extension_after_exzz() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("continued.ExZZ");
    let decoy = dir.path().join("continued.Ey01");
    let second = dir.path().join("continued.EyAA");
    std::fs::write(
        &first,
        ewf2_leading_segment_bytes(1, 0, 0x0d, b"first segment"),
    )
    .unwrap();
    std::fs::write(
        &decoy,
        ewf2_leading_segment_bytes(2, 1, 0x0f, b"wrong segment"),
    )
    .unwrap();
    std::fs::write(
        &second,
        ewf2_leading_segment_bytes(2, 1, 0x0f, b"second segment"),
    )
    .unwrap();

    let image = ewf_image::Image::open(&first).unwrap();
    let mut first_buf = [0; 13];
    let mut second_buf = [0; 14];

    let first_read = image.read_at(&mut first_buf, 0).unwrap();
    let second_read = image.read_at(&mut second_buf, 32_768).unwrap();

    assert_eq!(image.info().segment_count, 2);
    assert_eq!(image.info().segment_paths, vec![first, second]);
    assert_eq!(image.info().logical_size, 65_536);
    assert_eq!(first_read, 13);
    assert_eq!(&first_buf, b"first segment");
    assert_eq!(second_read, 14);
    assert_eq!(&second_buf, b"second segment");
}

#[test]
fn image_open_reads_logical_ewf2_continuation_extension_after_lxzz() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("logical.LxZZ");
    let decoy = dir.path().join("logical.Ly01");
    let second = dir.path().join("logical.LyAA");
    std::fs::write(
        &first,
        ewf2_logical_leading_segment_bytes(1, 0, 0x0d, b"first logical"),
    )
    .unwrap();
    std::fs::write(
        &decoy,
        ewf2_logical_leading_segment_bytes(2, 1, 0x0f, b"wrong logical"),
    )
    .unwrap();
    std::fs::write(
        &second,
        ewf2_logical_leading_segment_bytes(2, 1, 0x0f, b"second logical"),
    )
    .unwrap();

    let image = ewf_image::Image::open(&first).unwrap();
    let mut first_buf = [0; 13];
    let mut second_buf = [0; 14];

    let first_read = image.read_at(&mut first_buf, 0).unwrap();
    let second_read = image.read_at(&mut second_buf, 32_768).unwrap();

    assert_eq!(image.info().segment_count, 2);
    assert_eq!(image.info().segment_paths, vec![first, second]);
    assert_eq!(
        image.info().format_profile,
        ewf_image::FormatProfile::Ewf2LogicalEnCase7
    );
    assert_eq!(image.info().logical_size, 65_536);
    assert_eq!(first_read, 13);
    assert_eq!(&first_buf, b"first logical");
    assert_eq!(second_read, 14);
    assert_eq!(&second_buf, b"second logical");
}

#[test]
fn image_open_rejects_mismatched_ewf2_device_information_across_segments() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("multi.Ex01");
    let second = dir.path().join("multi.Ex02");
    std::fs::write(
        &first,
        ewf2_leading_segment_bytes_with_device_information(
            1,
            0,
            0x0d,
            b"first segment",
            "2\nmain\nb\tsc\tts\tu\n512\t64\t128\tone\n\n",
        ),
    )
    .unwrap();
    std::fs::write(
        &second,
        ewf2_leading_segment_bytes_with_device_information(
            2,
            1,
            0x0f,
            b"second segment",
            "2\nmain\nb\tsc\tts\tu\n512\t64\t128\ttwo\n\n",
        ),
    )
    .unwrap();

    let err = ewf_image::Image::open(&first).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Malformed(_)));
}

#[test]
fn image_open_rejects_mismatched_ewf2_compression_methods_across_segments() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("multi.Ex01");
    let second = dir.path().join("multi.Ex02");
    std::fs::write(
        &first,
        ewf2_leading_segment_bytes_with_compression_method(1, 0, 0x0d, b"first segment", 1),
    )
    .unwrap();
    std::fs::write(
        &second,
        ewf2_leading_segment_bytes_with_compression_method(2, 1, 0x0f, b"second segment", 2),
    )
    .unwrap();

    let err = ewf_image::Image::open(&first).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Malformed(_)));
}

#[test]
fn image_open_rejects_mismatched_ewf2_format_versions_across_segments() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("multi.Ex01");
    let second = dir.path().join("multi.Ex02");
    let mut second_segment = ewf2_leading_segment_bytes(2, 1, 0x0f, b"second segment");
    second_segment[9] = 2;
    std::fs::write(
        &first,
        ewf2_leading_segment_bytes(1, 0, 0x0d, b"first segment"),
    )
    .unwrap();
    std::fs::write(&second, second_segment).unwrap();

    let err = ewf_image::Image::open(&first).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Malformed(_)));
}

#[test]
fn image_open_rejects_zeroed_ewf2_set_identifier_across_segments() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("multi.Ex01");
    let second = dir.path().join("multi.Ex02");
    let mut second_segment = ewf2_leading_segment_bytes(2, 1, 0x0f, b"second segment");
    second_segment[16..32].fill(0);
    std::fs::write(
        &first,
        ewf2_leading_segment_bytes(1, 0, 0x0d, b"first segment"),
    )
    .unwrap();
    std::fs::write(&second, second_segment).unwrap();

    let err = ewf_image::Image::open(&first).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Malformed(_)));
}

#[test]
fn image_read_at_returns_zero_at_eof() {
    let file = synthetic_e01(b"hello ewf");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 16];

    let read = image.read_at(&mut buf, image.info().logical_size).unwrap();

    assert_eq!(read, 0);
}

#[test]
fn image_open_reads_synthetic_ewf2_with_read_at() {
    let file = synthetic_ex01(b"hello ex01");

    let image = ewf_image::Image::open(file.path()).unwrap();
    let info = image.info();
    assert_eq!(info.format, ewf_image::Format::Ewf2);
    assert_eq!(info.segment_count, 1);
    assert_eq!(info.chunk_size, 32_768);
    assert_eq!(info.logical_size, 32_768);

    let mut buf = [0; 10];
    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 10);
    assert_eq!(&buf, b"hello ex01");
}

#[test]
fn image_open_exposes_ewf2_format_profiles() {
    let physical = synthetic_ex01(b"physical profile");
    let logical = synthetic_lx01(b"logical profile");

    let physical = ewf_image::Image::open(physical.path()).unwrap();
    let logical = ewf_image::Image::open(logical.path()).unwrap();

    assert_eq!(
        physical.info().format_profile,
        ewf_image::FormatProfile::Ewf2EnCase7
    );
    assert_eq!(
        logical.info().format_profile,
        ewf_image::FormatProfile::Ewf2LogicalEnCase7
    );
}

#[test]
fn image_open_exposes_ewf2_media_info() {
    let file = synthetic_ex01(b"hello ex01");

    let image = ewf_image::Image::open(file.path()).unwrap();
    let media = &image.info().media;

    assert_eq!(media.sectors_per_chunk, Some(64));
    assert_eq!(media.bytes_per_sector, Some(512));
    assert_eq!(media.sector_count, Some(64));
    assert_eq!(media.chunk_count, Some(1));
    assert_eq!(media.error_granularity, None);
    assert_eq!(media.set_identifier, Some([0xab; 16]));
    assert_eq!(
        media.ewf2_segment_file_version,
        Some(ewf_image::SegmentFileVersion { major: 2, minor: 1 })
    );
    assert_eq!(
        media.compression_method,
        Some(ewf_image::CompressionMethod::Zlib)
    );
    assert_eq!(media.media_type, None);
    assert_eq!(
        media.media_flags,
        ewf_image::MediaFlags {
            physical: true,
            fastbloc: false,
            tableau: false,
        }
    );
    assert_eq!(image.format(), ewf_image::Format::Ewf2);
    assert_eq!(
        image.format_profile(),
        ewf_image::FormatProfile::Ewf2EnCase7
    );
    assert_eq!(image.chunk_size(), 32_768);
    assert_eq!(image.media_size(), 32_768);
    assert_eq!(image.sectors_per_chunk(), Some(64));
    assert_eq!(image.bytes_per_sector(), Some(512));
    assert_eq!(image.number_of_sectors(), Some(64));
    assert_eq!(image.number_of_chunks(), Some(1));
    assert_eq!(image.error_granularity(), None);
    assert_eq!(image.segment_file_set_identifier(), Some([0xab; 16]));
    assert_eq!(
        image.segment_file_version(),
        Some(ewf_image::SegmentFileVersion { major: 2, minor: 1 })
    );
    assert_eq!(
        image.compression_method(),
        Some(ewf_image::CompressionMethod::Zlib)
    );
    assert_eq!(image.media_type(), None);
    assert_eq!(image.media_flags(), media.media_flags);
}

#[test]
fn image_read_rejects_ewf2_raw_chunk_bad_checksum() {
    let file = writer_ex01_with_bad_raw_chunk_checksum();
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 16];

    let err = image.read_at(&mut buf, 0).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message) if message == "raw chunk checksum mismatch"
    ));
}

#[test]
fn image_read_zeroes_ewf2_raw_chunk_bad_checksum_when_requested() {
    let file = writer_ex01_with_bad_raw_chunk_checksum();
    let image = ewf_image::Image::open_with_options(
        file.path(),
        ewf_image::OpenOptions::default().with_read_zero_chunk_on_error(true),
    )
    .unwrap();
    let mut buf = [0x55; 16];

    assert_eq!(image.checksum_errors().unwrap(), []);

    let read = image.read_at(&mut buf, 0).unwrap();
    let _ = image.read_data_chunk(0).unwrap();

    assert_eq!(read, 16);
    assert_eq!(buf, [0; 16]);
    assert_eq!(
        image.checksum_errors().unwrap(),
        vec![ewf_image::SectorRange {
            first_sector: 0,
            sector_count: 1,
        }]
    );
}

#[test]
fn image_open_rejects_ewf2_table_bad_header_checksum() {
    let file = writer_ex01_with_bad_table_header_checksum();

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message) if message.contains("EWF2 table header checksum")
    ));
}

#[test]
fn image_open_rejects_ewf2_table_bad_entries_checksum() {
    let file = writer_ex01_with_bad_table_entries_checksum();

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message) if message.contains("EWF2 table entries checksum")
    ));
}

#[test]
fn image_open_rejects_overlapping_ewf2_sector_tables() {
    let file = synthetic_ex01_overlapping_sector_tables();

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message) if message.contains("overlap")
    ));
}

#[test]
fn image_open_rejects_ewf2_section_bad_descriptor_checksum() {
    let file = writer_ex01_with_bad_descriptor_checksum();

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message) if message.contains("EWF2 section descriptor checksum")
    ));
}

#[test]
fn image_open_exposes_ewf2_media_type_and_flags() {
    let file = synthetic_ex01_device_info_text(
        b"typed ex01",
        "2\nmain\nb\tsc\tts\ttb\tgr\tdt\tph\twb\n512\t64\t64\t1\t8\tf\t1\t3\n\n",
    );

    let image = ewf_image::Image::open(file.path()).unwrap();
    let media = &image.info().media;

    assert_eq!(media.media_type, Some(ewf_image::MediaType::Fixed));
    assert_eq!(media.chunk_count, Some(1));
    assert_eq!(media.error_granularity, Some(8));
    assert_eq!(
        media.media_flags,
        ewf_image::MediaFlags {
            physical: true,
            fastbloc: true,
            tableau: true,
        }
    );
}

#[test]
fn image_open_ignores_zero_filled_ewf2_hashes() {
    let file = synthetic_ex01_with_zero_md5_hash(b"zero ex01");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 9];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 9);
    assert_eq!(&buf, b"zero ex01");
    assert_eq!(image.info().stored_hashes.md5, None);
}

#[test]
fn image_open_rejects_short_ewf2_md5_hash_section() {
    let file = synthetic_ex01_with_md5_hash(b"short md5", &[0xab; 16]);

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Malformed(_)));
}

#[test]
fn image_open_rejects_ewf2_md5_hash_bad_checksum() {
    let mut md5 = ewf2_md5_hash_payload([
        0x19, 0xb8, 0xbb, 0xe1, 0xf3, 0x2b, 0x02, 0x5b, 0xd7, 0xd6, 0x3b, 0x08, 0xad, 0x16, 0x07,
        0x7a,
    ]);
    md5[16] ^= 0x80;
    let file = synthetic_ex01_with_md5_hash(b"bad md5 checksum", &md5);

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message) if message.contains("EWF2 MD5 hash checksum")
    ));
}

#[test]
fn image_open_rejects_ewf2_without_device_or_case_metadata() {
    let file = synthetic_ex01_without_device_or_case_metadata(b"missing metadata");

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Malformed(_)));
}

#[test]
fn image_open_reads_synthetic_ewf2_leading_section_layout() {
    let file = synthetic_ex01_leading_sections(b"hello lead");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 10];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(image.info().format, ewf_image::Format::Ewf2);
    assert_eq!(read, 10);
    assert_eq!(&buf, b"hello lead");
}

#[test]
fn image_open_reads_ewf2_trailing_table_with_padding() {
    let file = synthetic_ex01_trailing_table_with_padding(b"trailing table padding");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 22];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 22);
    assert_eq!(&buf, b"trailing table padding");
}

#[test]
fn image_open_parses_synthetic_ewf2_restart_data_section() {
    let file = synthetic_ex01_leading_restart_data(b"restart ok");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 10];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 10);
    assert_eq!(&buf, b"restart ok");
    assert_eq!(
        image.info().ewf2_restart_data.as_deref(),
        Some("<restart_data />\n")
    );
    assert_eq!(image.ewf2_restart_data(), Some("<restart_data />\n"));
}

#[test]
fn image_open_rejects_ewf2_section_integrity_hash_mismatch() {
    let file = synthetic_ex01_leading_restart_data_with_integrity(b"bad section hash", true);

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("EWF2 section data integrity hash")
    ));
}

#[test]
fn image_open_reads_ewf2_leading_section_with_padding() {
    let file = synthetic_ex01_leading_padded_restart_data(b"padded ok");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 9];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 9);
    assert_eq!(&buf, b"padded ok");
    assert_eq!(
        image.info().ewf2_restart_data.as_deref(),
        Some("<restart_data />\n")
    );
}

#[test]
fn image_open_parses_synthetic_ewf2_increment_and_final_information_sections() {
    let increment_one = b"increment one".as_slice();
    let increment_two = b"increment two".as_slice();
    let final_information = b"final information";
    let file = synthetic_ex01_leading_application_sections(
        b"opaque app data",
        &[
            (0x07, increment_one),
            (0x07, increment_two),
            (0x0e, final_information.as_slice()),
        ],
    );

    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 15];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 15);
    assert_eq!(&buf, b"opaque app data");
    assert_eq!(
        image.info().ewf2_increment_data,
        vec![increment_one.to_vec(), increment_two.to_vec()]
    );
    assert_eq!(image.number_of_ewf2_increment_data_sections(), 2);
    assert_eq!(image.ewf2_increment_data_section(0), Some(increment_one));
    assert_eq!(image.ewf2_increment_data_section(1), Some(increment_two));
    assert_eq!(image.ewf2_increment_data_section(2), None);
    assert_eq!(
        image.info().ewf2_final_information.as_deref(),
        Some(final_information.as_slice())
    );
    assert_eq!(
        image.ewf2_final_information(),
        Some(final_information.as_slice())
    );
}

#[test]
fn image_open_parses_synthetic_ewf2_analytical_data_section() {
    let analytical_data = "1\nmain\ntps\n327680\n\n";
    let analytical_section = zlib_bytes(&utf16le(analytical_data));
    let file = synthetic_ex01_leading_application_sections(
        b"analytical app data",
        &[(0x10, analytical_section.as_slice())],
    );

    let image = ewf_image::Image::open(file.path()).unwrap();

    assert_eq!(
        image.info().ewf2_analytical_data.as_deref(),
        Some(analytical_data)
    );
    assert_eq!(image.ewf2_analytical_data(), Some(analytical_data));
}

#[test]
fn image_open_rejects_duplicate_ewf2_final_information_sections() {
    let file = synthetic_ex01_leading_application_sections(
        b"duplicate final information",
        &[
            (0x0e, b"final one".as_slice()),
            (0x0e, b"final two".as_slice()),
        ],
    );

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("duplicate final information")
    ));
}

#[test]
fn image_open_rejects_ewf2_analytical_data_with_odd_utf16_size() {
    let file = synthetic_ex01_leading_application_sections(
        b"bad analytical data",
        &[(0x10, b"odd".as_slice())],
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("analytical data section has odd UTF-16 size")
    ));
}

#[test]
fn image_open_lenient_skips_unknown_ewf2_section() {
    let file = synthetic_ex01_leading_unknown_section(b"unknown ok");
    let image = ewf_image::Image::open_with_options(
        file.path(),
        ewf_image::OpenOptions::default().with_strictness(ewf_image::OpenStrictness::Lenient),
    )
    .unwrap();
    let mut buf = [0; 10];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 10);
    assert_eq!(&buf, b"unknown ok");
}

#[test]
fn image_open_strict_rejects_unknown_ewf2_section() {
    let file = synthetic_ex01_leading_unknown_section(b"unknown strict");

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Malformed(_)));
}

#[test]
fn image_open_parses_known_ewf2_single_files_table_sections() {
    for section_type in [0x21, 0x22, 0x23] {
        let file = synthetic_lx01_leading_single_files_table(b"single ok", section_type);
        let image = ewf_image::Image::open(file.path()).unwrap();
        let mut buf = [0; 9];

        let read = image.read_at(&mut buf, 0).unwrap();

        assert_eq!(read, 9);
        assert_eq!(&buf, b"single ok");
        match section_type {
            0x21 => assert_eq!(
                image.info().ewf2_single_files_tables.table_0x21_entries,
                vec![0x10, 0x20]
            ),
            0x22 => assert_eq!(
                image.info().ewf2_single_files_tables.md5_hashes,
                vec![[0x11; 16], [0x22; 16]]
            ),
            0x23 => assert_eq!(
                image.info().ewf2_single_files_tables.table_0x23_entries,
                vec![0x30]
            ),
            _ => unreachable!(),
        }
    }
}

#[test]
fn image_open_parses_ewf1_ltree_single_files_data() {
    let data = b"l01 file".to_vec();
    let file = synthetic_l01_with_ltree(
        &data,
        &single_files_stream_with_single_extent(0, data.len() as u64),
    );
    let image = ewf_image::Image::open(file.path()).unwrap();
    let single_files = image.info().single_files.as_ref().unwrap();
    let child = &single_files.root.children[0];
    let mut decoded = vec![0; data.len()];

    let read = image.read_single_file_at(child, &mut decoded, 0).unwrap();

    assert_eq!(image.media_size(), 4096);
    assert_eq!(image.info().media.sector_count, Some(64));
    assert_eq!(image.number_of_chunks(), Some(1));
    assert_eq!(image.read_at(&mut [0; 1], 4096).unwrap(), 0);
    assert_eq!(child.name.as_deref(), Some("report.bin"));
    assert_eq!(read, data.len());
    assert_eq!(decoded, data);
}

#[test]
fn image_reads_ewf1_sparse_entry_from_duplicate_offset_before_extent() {
    let file = synthetic_l01_with_ltree(
        b"XbadHELLOtail",
        &single_files_stream_with_ewf1_sparse_entry(5, "1 0 1", "4"),
    );
    let image = ewf_image::Image::open(file.path()).unwrap();
    let child = &image.info().single_files.as_ref().unwrap().root.children[0];
    let mut full = [0; 5];
    let mut middle = [0; 3];

    assert_eq!(image.read_single_file_at(child, &mut full, 0).unwrap(), 5);
    assert_eq!(&full, b"HELLO");
    assert_eq!(
        image
            .read_single_file_at_strict(child, &mut middle, 1)
            .unwrap(),
        3
    );
    assert_eq!(&middle, b"ELL");
}

#[test]
fn image_preserves_logical_names_and_reads_data_bearing_parent() {
    let mut lines = default_single_files_prefix();
    lines.extend([
        "entry".to_owned(),
        "0\t1".to_owned(),
        "id\tp\tn\tls\tbe".to_owned(),
        "26\t1".to_owned(),
        "1\td\troot\t0\t".to_owned(),
        "26\t1".to_owned(),
        "2\td\tfolder/name\t4\t1 0 4".to_owned(),
        "26\t0".to_owned(),
        "3\tf\tpart\\name·stream\t5\t1 4 5".to_owned(),
        String::new(),
    ]);
    let file = synthetic_l01_with_ltree(b"HEADhello", &utf16le_lines(lines));
    let image = ewf_image::Image::open(file.path()).unwrap();
    let catalog = image.info().single_files.as_ref().unwrap();
    let parent = catalog.entry_by_path("folder/name").unwrap().unwrap();
    let child = catalog
        .entry_by_path("folder/name\tpart\\name·stream")
        .unwrap()
        .unwrap();
    let mut parent_data = [0; 4];
    let mut child_data = [0; 5];

    assert_eq!(parent.name.as_deref(), Some("folder/name"));
    assert_eq!(child.name.as_deref(), Some("part\\name·stream"));
    assert_eq!(parent.children.len(), 1);
    assert_eq!(
        image
            .read_single_file_at_strict(parent, &mut parent_data, 0)
            .unwrap(),
        4
    );
    assert_eq!(&parent_data, b"HEAD");
    assert_eq!(
        image
            .read_single_file_at(child, &mut child_data, 0)
            .unwrap(),
        5
    );
    assert_eq!(&child_data, b"hello");
}

#[test]
fn image_preserves_unpaired_utf16_entry_name_units() {
    let mut catalog = single_files_stream_with_single_extent(0, 7);
    let name = utf16le("report.bin");
    let offset = catalog
        .windows(name.len())
        .position(|window| window == name)
        .unwrap();
    catalog[offset..offset + 2].copy_from_slice(&0xd800_u16.to_le_bytes());
    let file = synthetic_l01_with_ltree(b"payload", &catalog);
    let image = ewf_image::Image::open(file.path()).unwrap();
    let entry = &image.info().single_files.as_ref().unwrap().root.children[0];
    let mut expected_units = "report.bin".encode_utf16().collect::<Vec<_>>();
    expected_units[0] = 0xd800;
    let mut content = [0; 7];

    assert_eq!(entry.name.as_deref(), Some("�eport.bin"));
    assert_eq!(entry.name_utf16.as_deref(), Some(expected_units.as_slice()));
    assert_eq!(
        image.read_single_file_at(entry, &mut content, 0).unwrap(),
        7
    );
    assert_eq!(&content, b"payload");
}

#[test]
fn image_rejects_unpaired_utf16_outside_entry_name() {
    let mut catalog = single_files_stream_with_single_extent(0, 7);
    let row = utf16le("2\tf\treport.bin");
    let offset = catalog
        .windows(row.len())
        .position(|window| window == row)
        .unwrap();
    catalog[offset + 4..offset + 6].copy_from_slice(&0xd800_u16.to_le_bytes());
    let file = synthetic_l01_with_ltree(b"payload", &catalog);

    let error = open_strict(file.path()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("invalid UTF-16 outside its name")
    );
}

#[test]
fn image_reads_ewf1_sparse_entry_as_repeated_stored_byte() {
    let file = synthetic_l01_with_ltree(
        b"Qother-data",
        &single_files_stream_with_ewf1_sparse_entry(7, "1 0 1", ""),
    );
    let image = ewf_image::Image::open(file.path()).unwrap();
    let child = &image.info().single_files.as_ref().unwrap().root.children[0];
    let mut buf = [0; 4];

    assert_eq!(image.read_single_file_at(child, &mut buf, 2).unwrap(), 4);
    assert_eq!(&buf, b"QQQQ");
}

#[test]
fn image_rejects_ewf1_sparse_entry_without_stored_data() {
    let file = synthetic_l01_with_ltree(
        b"other-data",
        &single_files_stream_with_ewf1_sparse_entry(7, "0", ""),
    );
    let image = ewf_image::Image::open(file.path()).unwrap();
    let child = &image.info().single_files.as_ref().unwrap().root.children[0];
    let error = image
        .read_single_file_at(child, &mut [0; 1], 0)
        .unwrap_err();

    assert!(error.to_string().contains("has no stored byte"));
}

#[test]
fn image_rejects_ewf1_ltree_text_with_bad_md5_and_valid_header_checksum() {
    let data = b"catalog text";
    let file = synthetic_l01_with_ltree(
        data,
        &single_files_stream_with_single_extent(0, data.len() as u64),
    );
    let image = ewf_image::Image::open(file.path()).unwrap();
    let ltree = image
        .sections()
        .iter()
        .find(|section| section.kind == ewf_image::SectionKind::Ewf1("ltree".into()))
        .unwrap();
    let offset = ltree.data_offset as usize;
    drop(image);

    let mut bytes = std::fs::read(file.path()).unwrap();
    bytes[offset] ^= 1;
    bytes[offset + 24..offset + 28].fill(0);
    let checksum = adler32(&bytes[offset..offset + 48]);
    bytes[offset + 24..offset + 28].copy_from_slice(&checksum.to_le_bytes());
    std::fs::write(file.path(), bytes).unwrap();

    let error = open_strict(file.path()).unwrap_err();
    assert!(error.to_string().contains("ltree text MD5 mismatch"));
}

#[test]
fn image_rejects_ewf1_ltree_without_recorded_media_size() {
    let data = b"catalog text";
    let mut catalog = single_files_stream_with_single_extent(0, data.len() as u64);
    let field = utf16le("tb");
    let offset = catalog
        .windows(field.len())
        .position(|window| window == field)
        .unwrap();
    catalog[offset..offset + field.len()].copy_from_slice(&utf16le("xx"));
    let file = synthetic_l01_with_ltree(data, &catalog);

    let error = open_strict(file.path()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("ltree record has no total data size")
    );
}

#[test]
fn image_open_parses_ewf2_single_files_entry_tree() {
    let file = synthetic_lx01_leading_single_files_data(b"single tree");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let single_files = image.info().single_files.as_ref().unwrap();

    assert_eq!(single_files.data_size, 4096);
    assert_eq!(single_files.root.identifier, Some(1));
    assert_eq!(
        single_files.root.file_entry_type,
        Some(ewf_image::SingleFileEntryType::Directory)
    );
    assert_eq!(single_files.root.name.as_deref(), Some("root"));
    assert_eq!(single_files.root.children.len(), 1);
    assert_eq!(single_files.root.number_of_sub_file_entries(), 1);

    let child = &single_files.root.children[0];
    assert_eq!(
        single_files.root.sub_file_entry(0).unwrap().identifier,
        Some(2)
    );
    assert!(single_files.root.sub_file_entry(1).is_none());
    assert_eq!(
        single_files
            .root
            .sub_file_entry_by_name("report.txt")
            .unwrap()
            .identifier,
        Some(2)
    );
    assert_eq!(child.identifier, Some(2));
    assert_eq!(
        child.file_entry_type,
        Some(ewf_image::SingleFileEntryType::File)
    );
    assert_eq!(child.name.as_deref(), Some("report.txt"));
    assert_eq!(child.size, Some(11));
    assert_eq!(child.logical_offset, Some(4096));
    assert_eq!(child.physical_offset, Some(8192));
    assert_eq!(child.creation_time, Some(1_700_000_000));
    assert_eq!(child.modification_time, Some(1_700_000_100));
    assert_eq!(child.access_time, Some(1_700_000_200));
    assert_eq!(child.entry_modification_time, Some(1_700_000_300));
    assert_eq!(child.deletion_time, Some(-1));
    assert_eq!(child.source_identifier, Some(1));
    assert_eq!(child.subject_identifier, Some(7));
    assert_eq!(child.permission_group_index, Some(0));
    assert_eq!(child.record_type, Some(3));
    assert_eq!(child.flags, Some(4));
    assert_eq!(
        child.extents,
        [
            ewf_image::SingleFileExtent {
                data_offset: 0x0131_35c1,
                data_size: 0x3f44,
                sparse: false,
            },
            ewf_image::SingleFileExtent {
                data_offset: 0x2000,
                data_size: 0x10,
                sparse: true,
            },
        ]
    );
    assert_eq!(child.number_of_extents(), 2);
    assert_eq!(
        child.extent(0),
        Some(&ewf_image::SingleFileExtent {
            data_offset: 0x0131_35c1,
            data_size: 0x3f44,
            sparse: false,
        })
    );
    assert!(child.extent(2).is_none());
    assert_eq!(
        child.md5.as_deref(),
        Some("00112233445566778899aabbccddeeff")
    );
    assert_eq!(
        child.sha1.as_deref(),
        Some("00112233445566778899aabbccddeeff00112233")
    );
}

#[test]
fn image_finds_ewf2_single_file_entries_by_name_and_path() {
    let file = synthetic_lx01_nested_single_files_data(b"nested single tree");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let single_files = image.info().single_files.as_ref().unwrap();
    let separator = ewf_image::SINGLE_FILE_PATH_SEPARATOR;

    let users = single_files.root.child_by_name("Users").unwrap();
    let ntuser = users.child_by_name("ntuser.dat").unwrap();
    let ntuser_from_sub_path = single_files
        .root
        .sub_file_entry_by_path("Users\tntuser.dat")
        .unwrap()
        .unwrap();

    assert_eq!(users.identifier, Some(2));
    assert_eq!(ntuser.identifier, Some(3));
    assert_eq!(ntuser_from_sub_path.identifier, Some(3));
    assert!(single_files.root.child_by_name("Missing").is_none());

    let root_from_empty = single_files.entry_by_path("").unwrap().unwrap();
    let root_from_separator = single_files
        .entry_by_path(&separator.to_string())
        .unwrap()
        .unwrap();
    let ntuser_from_path = single_files
        .entry_by_path(&format!("Users{separator}ntuser.dat"))
        .unwrap()
        .unwrap();
    let ntuser_from_leading_path = single_files
        .entry_by_path(&format!("{separator}Users{separator}ntuser.dat"))
        .unwrap()
        .unwrap();
    let ntuser_from_relative_path = single_files
        .root
        .child_by_path("Users\tntuser.dat")
        .unwrap()
        .unwrap();

    assert_eq!(root_from_empty.identifier, Some(1));
    assert_eq!(root_from_separator.identifier, Some(1));
    assert_eq!(ntuser_from_path.identifier, Some(3));
    assert_eq!(ntuser_from_leading_path.identifier, Some(3));
    assert_eq!(ntuser_from_relative_path.identifier, Some(3));
    assert!(
        single_files
            .entry_by_path("Users\tmissing.dat")
            .unwrap()
            .is_none()
    );

    let image_root = image.root_file_entry().unwrap();
    let image_ntuser = image
        .file_entry_by_path(&format!("Users{separator}ntuser.dat"))
        .unwrap()
        .unwrap();

    assert_eq!(image_root.identifier, Some(1));
    assert_eq!(image_ntuser.identifier, Some(3));
    assert!(
        image
            .file_entry_by_path("Users\tmissing.dat")
            .unwrap()
            .is_none()
    );
}

#[test]
fn image_file_entry_lookup_returns_none_without_single_files_catalog() {
    let file = synthetic_e01(b"physical only");
    let image = ewf_image::Image::open(file.path()).unwrap();

    assert!(image.root_file_entry().is_none());
    assert!(image.file_entry_by_path("anything").unwrap().is_none());
}

#[test]
fn image_rejects_malformed_ewf2_single_file_entry_paths() {
    let file = synthetic_lx01_nested_single_files_data(b"nested single tree");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let single_files = image.info().single_files.as_ref().unwrap();
    let err = single_files
        .entry_by_path("Users\t\tntuser.dat")
        .unwrap_err();

    assert!(
        matches!(err, ewf_image::EwfError::Malformed(message) if message.contains("missing entry name"))
    );
}

#[test]
fn image_open_parses_ewf2_single_file_entry_guid() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"single file guid",
        &single_files_stream_with_entry_guid(),
    );
    let image = ewf_image::Image::open(file.path()).unwrap();
    let single_files = image.info().single_files.as_ref().unwrap();
    let child = single_files.entry_by_path("report.txt").unwrap().unwrap();

    assert_eq!(
        child.guid.as_deref(),
        Some("00112233445566778899aabbccddeeff")
    );
    assert_eq!(child.guid(), Some("00112233445566778899aabbccddeeff"));
}

#[test]
fn image_open_normalizes_ewf2_single_files_entry_base16_values() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"single file uppercase hashes",
        &single_files_stream_with_uppercase_entry_base16(),
    );

    let image = ewf_image::Image::open(file.path()).unwrap();
    let entry = image.root_file_entry().unwrap();

    assert_eq!(entry.md5.as_deref(), Some("aabbccddeeff"));
    assert_eq!(entry.sha1.as_deref(), Some("aabbccddeeff00112233"));
}

#[test]
fn image_open_ignores_ewf2_single_files_zero_base16_values() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"single file zero hashes",
        &single_files_stream_with_zero_entry_base16(),
    );

    let image = ewf_image::Image::open(file.path()).unwrap();
    let entry = image.root_file_entry().unwrap();

    assert_eq!(entry.guid, None);
    assert_eq!(entry.md5, None);
    assert_eq!(entry.sha1, None);
}

#[test]
fn image_open_rejects_ewf2_single_files_invalid_entry_base16_value() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"bad single file entry hash",
        &single_files_stream_with_invalid_entry_base16(),
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("MD5 hash")
                && message.contains("hexadecimal")
    ));
}

#[test]
fn image_open_parses_ewf2_single_files_entry_short_name() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"single file short name",
        &single_files_stream_with_entry_short_name(),
    );

    let image = ewf_image::Image::open(file.path()).unwrap();
    let entry = image.root_file_entry().unwrap();

    assert_eq!(entry.short_name.as_deref(), Some("REPORT~1.TXT"));
    assert_eq!(entry.short_name(), Some("REPORT~1.TXT"));
}

#[test]
fn image_open_rejects_ewf2_single_files_plain_entry_short_name() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"plain single file short name",
        &single_files_stream_with_plain_entry_short_name(),
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(
        matches!(err, ewf_image::EwfError::Malformed(message) if message.contains("short name"))
    );
}

#[test]
fn image_open_treats_missing_ewf2_single_files_entry_values_as_empty() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"short single file entry",
        &single_files_stream_with_entry_missing_trailing_values(),
    );

    let image = ewf_image::Image::open(file.path()).unwrap();
    let entry = image.root_file_entry().unwrap();

    assert_eq!(entry.identifier, Some(1));
    assert_eq!(entry.name.as_deref(), Some("report.txt"));
    assert_eq!(entry.size, None);
}

#[test]
fn image_open_ignores_extra_ewf2_single_files_entry_values() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"long single file entry",
        &single_files_stream_with_entry_extra_trailing_values(),
    );

    let image = ewf_image::Image::open(file.path()).unwrap();
    let entry = image.root_file_entry().unwrap();

    assert_eq!(entry.identifier, Some(1));
    assert_eq!(entry.name.as_deref(), Some("report.txt"));
    assert_eq!(entry.size, Some(11));
}

#[test]
fn image_open_rejects_ewf2_single_files_unsupported_entry_count_shape() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"bad single file entry count",
        &single_files_stream_with_unsupported_entry_count_shape(),
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("entry count")
    ));
}

#[test]
fn image_open_rejects_ewf2_single_files_unsupported_entry_child_count_parent_value() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"bad single file entry child count",
        &single_files_stream_with_unsupported_entry_child_count_parent_value(),
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("entry child count")
    ));
}

#[test]
fn image_open_rejects_ewf2_single_files_empty_entry_type() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"bad single file entry type",
        &single_files_stream_with_empty_entry_type(),
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("entry category")
                && message.contains("type")
    ));
}

#[test]
fn image_open_rejects_ewf2_single_files_non_empty_entry_terminator() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"bad single file terminator",
        &single_files_stream_with_non_empty_entry_terminator(),
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("entry category terminator")
    ));
}

#[test]
fn image_open_rejects_ewf2_single_files_non_empty_record_terminator() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"bad single file record",
        &single_files_stream_with_non_empty_record_terminator(),
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("record category terminator")
    ));
}

#[test]
fn image_open_rejects_ewf2_single_files_missing_record_category() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"missing single file record",
        &single_files_stream_without_record_category(),
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("record category")
    ));
}

#[test]
fn image_open_rejects_ewf2_single_files_empty_record_type() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"bad single file record type",
        &single_files_stream_with_empty_record_type(),
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("record category")
                && message.contains("type")
    ));
}

#[test]
fn image_open_rejects_ewf2_single_files_non_empty_source_terminator() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"bad single file source",
        &single_files_stream_with_non_empty_source_terminator(),
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("source category terminator")
    ));
}

#[test]
fn image_open_rejects_ewf2_single_files_unsupported_source_count_shape() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"bad single file source count",
        &single_files_stream_with_unsupported_source_count_shape(),
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("category count")
    ));
}

#[test]
fn image_open_rejects_ewf2_single_files_extra_source_values() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"bad single file source row",
        &single_files_stream_with_extra_source_values(),
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("source row")
                && message.contains("value count")
    ));
}

#[test]
fn image_open_rejects_ewf2_single_files_negative_source_identifier() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"bad single file source identifier",
        &single_files_stream_with_negative_source_identifier(),
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("source identifier")
    ));
}

#[test]
fn image_open_rejects_ewf2_single_files_source_identifier_index_mismatch() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"bad single file source index",
        &single_files_stream_with_mismatched_source_identifier(),
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("source identifier")
                && message.contains("index")
    ));
}

#[test]
fn image_open_rejects_ewf2_single_files_invalid_source_base16_value() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"bad single file source guid",
        &single_files_stream_with_invalid_source_base16(),
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("source device GUID")
                && message.contains("hexadecimal")
    ));
}

#[test]
fn image_open_rejects_ewf2_single_files_extra_subject_values() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"bad single file subject row",
        &single_files_stream_with_extra_subject_values(),
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("subject row")
                && message.contains("value count")
    ));
}

#[test]
fn image_open_rejects_ewf2_single_files_negative_entry_source_identifier() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"bad single file entry source identifier",
        &single_files_stream_with_negative_entry_source_identifier(),
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("source identifier")
    ));
}

#[test]
fn image_open_rejects_ewf2_single_files_extra_permission_values() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"bad single file permission row",
        &single_files_stream_with_extra_permission_values(),
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("permission row")
                && message.contains("value count")
    ));
}

#[test]
fn image_open_rejects_ewf2_single_files_non_empty_subject_terminator() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"bad single file subject",
        &single_files_stream_with_non_empty_subject_terminator(),
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("subject category terminator")
    ));
}

#[test]
fn image_open_rejects_ewf2_single_files_non_empty_permission_terminator() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"bad single file permissions",
        &single_files_stream_with_non_empty_permission_terminator(),
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("permission category terminator")
    ));
}

#[test]
fn image_open_rejects_ewf2_single_files_invalid_permission_root_type() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"bad single file permission root",
        &single_files_stream_with_invalid_permission_root_type(),
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("permission group type")
    ));
}

#[test]
fn image_open_rejects_ewf2_single_files_invalid_permission_group_type() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"bad single file permission group",
        &single_files_stream_with_invalid_permission_group_type(),
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("permission group type")
    ));
}

#[test]
fn image_open_parses_ewf2_single_files_metadata_tables() {
    let file = synthetic_lx01_single_files_metadata_tables(b"single files metadata");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let single_files = image.info().single_files.as_ref().unwrap();

    assert_eq!(single_files.sources.len(), 2);
    assert_eq!(single_files.sources[0].identifier, Some(0));
    assert_eq!(single_files.sources[0].name.as_deref(), Some("root-source"));

    let source = &single_files.sources[1];
    assert_eq!(source.identifier, Some(1));
    assert_eq!(source.name.as_deref(), Some("Disk 1"));
    assert_eq!(source.evidence_number.as_deref(), Some("EV-1"));
    assert_eq!(source.location.as_deref(), Some("Lab"));
    assert_eq!(
        source.device_guid.as_deref(),
        Some("00112233445566778899aabbccddeeff")
    );
    assert_eq!(
        source.primary_device_guid.as_deref(),
        Some("ffeeddccbbaa99887766554433221100")
    );
    assert_eq!(source.drive_type, Some('f'));
    assert_eq!(source.manufacturer.as_deref(), Some("Acme"));
    assert_eq!(source.model.as_deref(), Some("Model X"));
    assert_eq!(source.serial_number.as_deref(), Some("SN123"));
    assert_eq!(source.domain.as_deref(), Some("DOMAIN"));
    assert_eq!(source.ip_address.as_deref(), Some("192.0.2.1"));
    assert_eq!(source.mac_address.as_deref(), Some("001122aabbcc"));
    assert_eq!(source.size, Some(4096));
    assert_eq!(source.logical_offset, Some(512));
    assert_eq!(source.physical_offset, Some(1024));
    assert_eq!(source.acquisition_time, Some(1_700_000_000));
    assert_eq!(
        source.md5.as_deref(),
        Some("00112233445566778899aabbccddeeff")
    );
    assert_eq!(
        source.sha1.as_deref(),
        Some("00112233445566778899aabbccddeeff00112233")
    );

    assert_eq!(single_files.subjects.len(), 2);
    assert_eq!(single_files.subjects[0].identifier, Some(0));
    assert_eq!(
        single_files.subjects[0].name.as_deref(),
        Some("root-subject")
    );
    assert_eq!(single_files.subjects[1].identifier, Some(7));
    assert_eq!(
        single_files.subjects[1].name.as_deref(),
        Some("Case Subject")
    );

    assert_eq!(single_files.permission_groups.len(), 1);
    let group = &single_files.permission_groups[0];
    assert_eq!(group.name.as_deref(), Some("Administrators"));
    assert_eq!(group.identifier.as_deref(), Some("group-sid"));
    assert_eq!(group.property_type, Some(10));
    assert_eq!(group.permissions.len(), 1);
    assert_eq!(group.permissions[0].name.as_deref(), Some("Alice"));
    assert_eq!(group.permissions[0].identifier.as_deref(), Some("S-1-5-21"));
    assert_eq!(group.permissions[0].property_type, Some(1));
    assert_eq!(group.permissions[0].access_mask, Some(2_032_127));
    assert_eq!(group.permissions[0].ace_flags, Some(3));

    let child = single_files.entry_by_path("report.txt").unwrap().unwrap();
    assert_eq!(child.source_identifier, Some(1));
    assert_eq!(child.subject_identifier, Some(7));
    assert_eq!(child.permission_group_index, Some(0));
}

#[test]
fn image_resolves_ewf2_single_file_entry_metadata_references() {
    let file = synthetic_lx01_single_files_metadata_tables(b"single files metadata");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let single_files = image.info().single_files.as_ref().unwrap();
    let child = single_files.entry_by_path("report.txt").unwrap().unwrap();

    let source = single_files.source_for_entry(child).unwrap();
    assert_eq!(source.name.as_deref(), Some("Disk 1"));
    assert_eq!(
        single_files
            .source_by_identifier(1)
            .unwrap()
            .evidence_number
            .as_deref(),
        Some("EV-1")
    );
    assert!(single_files.source_for_entry(&single_files.root).is_none());
    assert!(single_files.source_by_identifier(99).is_none());

    let subject = single_files.subject_for_entry(child).unwrap();
    assert_eq!(subject.name.as_deref(), Some("Case Subject"));
    assert_eq!(
        single_files
            .subject_by_identifier(0)
            .unwrap()
            .name
            .as_deref(),
        Some("root-subject")
    );
    assert!(single_files.subject_by_identifier(99).is_none());

    let group = single_files.permission_group_for_entry(child).unwrap();
    assert_eq!(group.name.as_deref(), Some("Administrators"));
    assert_eq!(
        single_files
            .permission_group_by_index(0)
            .unwrap()
            .identifier
            .as_deref(),
        Some("group-sid")
    );
    assert!(single_files.permission_group_by_index(-1).is_none());
    assert!(single_files.permission_group_by_index(99).is_none());

    let entries = single_files.access_control_entries_for_entry(child);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name.as_deref(), Some("Alice"));
    assert_eq!(
        single_files
            .access_control_entry_for_entry(child, 0)
            .unwrap()
            .identifier
            .as_deref(),
        Some("S-1-5-21")
    );
    assert!(
        single_files
            .access_control_entry_for_entry(child, 1)
            .is_none()
    );
    assert_eq!(
        single_files.access_control_entries_for_entry(&single_files.root),
        []
    );
}

#[test]
fn image_resolves_ewf2_single_file_source_references_by_index() {
    let file = synthetic_lx01_leading_single_files_data_with_stream(
        b"single files source index",
        &single_files_stream_with_duplicate_root_source_identifier(),
    );
    let image = ewf_image::Image::open(file.path()).unwrap();
    let single_files = image.info().single_files.as_ref().unwrap();
    assert_eq!(single_files.root.name.as_deref(), Some("root"));
    assert_eq!(single_files.root.children.len(), 1);
    let child = &single_files.root.children[0];
    assert_eq!(child.name.as_deref(), Some("report.txt"));

    assert_eq!(
        single_files
            .source_by_identifier(1)
            .unwrap()
            .name
            .as_deref(),
        Some("root-source")
    );
    assert_eq!(
        single_files
            .source_for_entry(child)
            .unwrap()
            .name
            .as_deref(),
        Some("Disk 1")
    );
}

#[test]
fn image_open_parses_ewf2_single_file_extended_attributes() {
    let file = synthetic_lx01_single_file_extended_attributes(b"single file attributes");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let single_files = image.info().single_files.as_ref().unwrap();
    let child = single_files.entry_by_path("report.txt").unwrap().unwrap();

    assert_eq!(
        child.attributes,
        [
            ewf_image::SingleFileAttribute {
                name: Some("Zone.Identifier".to_owned()),
                value: Some("[ZoneTransfer]".to_owned()),
            },
            ewf_image::SingleFileAttribute {
                name: Some("Comment".to_owned()),
                value: Some("Recovered".to_owned()),
            },
        ]
    );
    assert_eq!(child.number_of_attributes(), 2);
    assert_eq!(
        child.attribute(1),
        Some(&ewf_image::SingleFileAttribute {
            name: Some("Comment".to_owned()),
            value: Some("Recovered".to_owned()),
        })
    );
    assert!(child.attribute(2).is_none());
}

#[test]
fn image_reads_ewf2_single_file_entry_extent() {
    let file = synthetic_lx01_single_file_extent_read(b"prefix-report-data-tail", 7, 11);
    let image = ewf_image::Image::open(file.path()).unwrap();
    let single_files = image.info().single_files.as_ref().unwrap();
    let child = &single_files.root.children[0];
    let mut buf = [0; 6];

    let read = image.read_single_file_at(child, &mut buf, 2).unwrap();

    assert_eq!(read, 6);
    assert_eq!(&buf, b"port-d");
}

#[test]
fn image_single_file_cursor_implements_read_and_seek() {
    let file = synthetic_lx01_single_file_extent_read(b"prefix-report-data-tail", 7, 11);
    let image = ewf_image::Image::open(file.path()).unwrap();
    let single_files = image.info().single_files.as_ref().unwrap();
    let child = &single_files.root.children[0];
    let mut cursor = image.single_file_cursor(child);
    let mut prefix = [0; 4];

    cursor.read_exact(&mut prefix).unwrap();
    assert_eq!(&prefix, b"repo");
    assert_eq!(cursor.position(), 4);

    assert_eq!(cursor.seek(SeekFrom::Current(3)).unwrap(), 7);
    let mut tail = Vec::new();
    cursor.read_to_end(&mut tail).unwrap();
    assert_eq!(tail, b"data");

    assert_eq!(cursor.seek(SeekFrom::End(-4)).unwrap(), 7);
    let mut tail = [0; 4];
    cursor.read_exact(&mut tail).unwrap();
    assert_eq!(&tail, b"data");

    let err = cursor.seek(SeekFrom::Current(-100)).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn image_single_file_cursor_exposes_offset_read_helpers() {
    let file = synthetic_lx01_single_file_extent_read(b"prefix-report-data-tail", 7, 11);
    let image = ewf_image::Image::open(file.path()).unwrap();
    let single_files = image.info().single_files.as_ref().unwrap();
    let child = &single_files.root.children[0];
    let mut cursor = image.single_file_cursor(child);
    let mut head = [0; 4];
    let mut tail = [0; 4];

    assert_eq!(cursor.offset(), 0);
    assert_eq!(cursor.read_buffer(&mut head).unwrap(), 4);
    assert_eq!(&head, b"repo");
    assert_eq!(cursor.offset(), 4);

    assert_eq!(cursor.seek_offset(SeekFrom::Current(3)).unwrap(), 7);
    assert_eq!(cursor.read_buffer_at_offset(&mut tail, 7).unwrap(), 4);
    assert_eq!(&tail, b"data");
    assert_eq!(cursor.offset(), 11);
}

#[test]
fn image_reads_single_file_entry_by_path_cursor_and_alias() {
    let file = synthetic_lx01_single_file_extent_read(b"prefix-report-data-tail", 7, 11);
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut cursor = image
        .single_file_cursor_by_path("report.bin")
        .unwrap()
        .unwrap();
    let child = image.file_entry_by_path("report.bin").unwrap().unwrap();
    let mut alias_buf = [0; 4];
    let mut cursor_buf = Vec::new();

    let read = image.read_file_entry_at(child, &mut alias_buf, 7).unwrap();
    cursor.seek(SeekFrom::Start(7)).unwrap();
    cursor.read_to_end(&mut cursor_buf).unwrap();

    assert_eq!(read, 4);
    assert_eq!(&alias_buf, b"data");
    assert_eq!(cursor_buf, b"data");
    assert!(
        image
            .single_file_cursor_by_path("missing.txt")
            .unwrap()
            .is_none()
    );
}

#[test]
fn image_reads_ewf2_single_file_entry_duplicate_data() {
    let file = synthetic_lx01_single_file_duplicate_read(b"prefix-duplicate-content-tail", 7, 17);
    let image = ewf_image::Image::open(file.path()).unwrap();
    let single_files = image.info().single_files.as_ref().unwrap();
    let child = &single_files.root.children[0];
    let mut buf = [0; 7];

    let read = image.read_single_file_at(child, &mut buf, 10).unwrap();

    assert_eq!(read, 7);
    assert_eq!(&buf, b"content");
}

#[test]
fn image_reads_ewf2_sparse_single_file_entry_extent_as_zeroes() {
    let file = synthetic_lx01_sparse_single_file_extent_read(b"prefix-data-tail", 7, 4, 3);
    let image = ewf_image::Image::open(file.path()).unwrap();
    let single_files = image.info().single_files.as_ref().unwrap();
    let child = &single_files.root.children[0];
    let mut buf = [0xff; 7];

    let read = image.read_single_file_at(child, &mut buf, 0).unwrap();

    assert_eq!(read, 7);
    assert_eq!(&buf, b"data\0\0\0");
}

#[test]
fn image_open_parses_synthetic_ewf2_memory_extents_table() {
    let file = synthetic_ex01_memory_extents_table(b"memory ok");
    let image = ewf_image::Image::open(file.path()).unwrap();

    assert_eq!(
        image.info().memory_extents,
        [
            ewf_image::MemoryExtent {
                start_page: 0x1000,
                page_count: 7,
            },
            ewf_image::MemoryExtent {
                start_page: 0x2000,
                page_count: 11,
            },
        ]
    );
    assert_eq!(image.number_of_memory_extents(), 2);
    assert_eq!(image.memory_extents(), image.info().memory_extents);
    assert_eq!(
        image.memory_extent(0),
        Some(&ewf_image::MemoryExtent {
            start_page: 0x1000,
            page_count: 7,
        })
    );
    assert_eq!(image.memory_extent(2), None);
}

#[test]
fn image_open_rejects_ewf2_memory_extents_table_partial_entry() {
    let mut memory_extents = ewf2_memory_extents_table(&[(0x1000, 7)]);
    memory_extents.push(0xff);
    let file =
        synthetic_ex01_memory_extents_table_with_payload(b"bad memory extents", &memory_extents);

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("memory extents table has partial entry")
    ));
}

#[test]
fn image_open_parses_synthetic_ewf2_error_table() {
    let file = synthetic_ex01_error_table(b"error ok");

    let image = ewf_image::Image::open(file.path()).unwrap();

    assert_eq!(
        image.info().acquisition_errors,
        [ewf_image::AcquisitionError {
            first_sector: 0x1_0000_002a,
            sector_count: 7,
        }]
    );
}

#[test]
fn image_open_parses_synthetic_ewf1_error2_section() {
    let file = synthetic_e01_with_error2(b"error2 ok");

    let image = ewf_image::Image::open(file.path()).unwrap();

    assert_eq!(
        image.info().acquisition_errors,
        [
            ewf_image::AcquisitionError {
                first_sector: 2,
                sector_count: 3,
            },
            ewf_image::AcquisitionError {
                first_sector: 40,
                sector_count: 2,
            },
        ]
    );
    assert_eq!(image.acquisition_errors(), image.info().acquisition_errors);
    assert_eq!(image.number_of_acquisition_errors(), 2);
    assert_eq!(
        image.acquisition_error(1),
        Some(&ewf_image::AcquisitionError {
            first_sector: 40,
            sector_count: 2,
        })
    );
    assert_eq!(image.acquisition_error(2), None);
}

#[test]
fn image_open_rejects_ewf1_error2_bad_header_checksum() {
    let mut error2 = ewf1_error2_payload(&[(2, 3)]);
    error2[516] ^= 0x80;
    let file = synthetic_e01_with_error2_payload(b"bad error2 header", &error2);

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message) if message.contains("error2 header checksum")
    ));
}

#[test]
fn image_open_rejects_ewf1_error2_bad_entries_checksum() {
    let mut error2 = ewf1_error2_payload(&[(2, 3)]);
    error2[520] ^= 0x80;
    let file = synthetic_e01_with_error2_payload(b"bad error2 entries", &error2);

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message) if message.contains("error2 entries checksum")
    ));
}

#[test]
fn image_open_rejects_ewf2_error_table_bad_header_checksum() {
    let mut error_table = ewf2_error_table_payload(&[(0x1_0000_002a, 7)]);
    error_table[16] ^= 0x80;
    let file = synthetic_ex01_error_table_with_payload(b"bad error header", &error_table);

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("error table header checksum")
    ));
}

#[test]
fn image_open_rejects_ewf2_error_table_bad_entries_checksum() {
    let mut error_table = ewf2_error_table_payload(&[(0x1_0000_002a, 7)]);
    error_table[32] ^= 0x80;
    let file = synthetic_ex01_error_table_with_payload(b"bad error entries", &error_table);

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message)
            if message.contains("error table entries checksum")
    ));
}

#[test]
fn image_open_parses_synthetic_ewf2_session_table() {
    let file = synthetic_ex01_session_table(b"session ok");

    let image = ewf_image::Image::open(file.path()).unwrap();

    assert_eq!(
        image.info().sessions,
        [
            ewf_image::SectorRange {
                first_sector: 0,
                sector_count: 32,
            },
            ewf_image::SectorRange {
                first_sector: 32,
                sector_count: 32,
            },
        ]
    );
    assert_eq!(image.info().tracks, []);
}

#[test]
fn image_open_parses_synthetic_ewf1_session_tracks() {
    let file = synthetic_e01_with_session_tracks(b"session tracks");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let expected_sessions = vec![
        ewf_image::SectorRange {
            first_sector: 0,
            sector_count: 4,
        },
        ewf_image::SectorRange {
            first_sector: 4,
            sector_count: 60,
        },
    ];
    let expected_tracks = expected_sessions.clone();
    let mut buf = [0; 14];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 14);
    assert_eq!(&buf, b"session tracks");
    assert_eq!(image.info().sessions, expected_sessions);
    assert_eq!(image.info().tracks, expected_tracks);
    assert_eq!(image.sessions(), image.info().sessions.as_slice());
    assert_eq!(image.tracks(), image.info().tracks.as_slice());
    assert_eq!(image.number_of_sessions(), 2);
    assert_eq!(image.number_of_tracks(), 2);
    assert_eq!(image.session(1), Some(&image.info().sessions[1]));
    assert_eq!(image.track(1), Some(&image.info().tracks[1]));
}

#[test]
fn image_open_matches_reference_for_ewf1_single_audio_session_entry() {
    let session = ewf1_session_payload(&[(0, 1)]);
    let file = synthetic_e01_with_session_payload(b"single audio", &session);
    let image = ewf_image::Image::open(file.path()).unwrap();

    assert_eq!(
        image.info().sessions,
        [ewf_image::SectorRange {
            first_sector: 0,
            sector_count: 64,
        }]
    );
    assert_eq!(image.info().tracks, []);
}

#[test]
fn image_open_parses_synthetic_ewf2_session_tracks() {
    let session_table = ewf2_session_table_payload(&[(0, 0), (0, 1), (32, 0), (32, 1)]);
    let file = synthetic_ex01_session_table_with_payload(b"session tracks", &session_table);
    let image = ewf_image::Image::open(file.path()).unwrap();
    let expected_sessions = vec![
        ewf_image::SectorRange {
            first_sector: 0,
            sector_count: 32,
        },
        ewf_image::SectorRange {
            first_sector: 32,
            sector_count: 32,
        },
    ];
    let expected_tracks = expected_sessions.clone();
    let mut buf = [0; 14];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 14);
    assert_eq!(&buf, b"session tracks");
    assert_eq!(image.info().sessions, expected_sessions);
    assert_eq!(image.info().tracks, expected_tracks);
    assert_eq!(image.sessions(), image.info().sessions.as_slice());
    assert_eq!(image.tracks(), image.info().tracks.as_slice());
    assert_eq!(image.number_of_sessions(), 2);
    assert_eq!(image.number_of_tracks(), 2);
    assert_eq!(image.session(1), Some(&image.info().sessions[1]));
    assert_eq!(image.track(1), Some(&image.info().tracks[1]));
}

#[test]
fn image_open_matches_reference_for_ewf2_single_audio_session_entry() {
    let session_table = ewf2_session_table_payload(&[(0, 1)]);
    let file = synthetic_ex01_session_table_with_payload(b"single audio", &session_table);
    let image = ewf_image::Image::open(file.path()).unwrap();

    assert_eq!(
        image.info().sessions,
        [ewf_image::SectorRange {
            first_sector: 0,
            sector_count: 64,
        }]
    );
    assert_eq!(image.info().tracks, []);
}

#[test]
fn image_open_rejects_ewf2_session_table_bad_header_checksum() {
    let mut session_table = ewf2_session_table_payload(&[(0, 0), (32, 0)]);
    session_table[16] ^= 0xff;
    let file = synthetic_ex01_session_table_with_payload(b"session bad", &session_table);

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Malformed(_)));
}

#[test]
fn image_open_rejects_ewf2_session_table_bad_entries_checksum() {
    let mut session_table = ewf2_session_table_payload(&[(0, 0), (32, 0)]);
    let footer_offset = session_table.len() - 16;
    session_table[footer_offset] ^= 0xff;
    let file = synthetic_ex01_session_table_with_payload(b"session bad", &session_table);

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Malformed(_)));
}

#[test]
fn image_open_parses_zlib_compressed_ewf2_device_info() {
    let file = synthetic_ex01_compressed_device_info(b"hello 64k");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 9];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(image.info().chunk_size, 65_536);
    assert_eq!(image.info().logical_size, 65_536);
    assert_eq!(read, 9);
    assert_eq!(&buf, b"hello 64k");
}

#[test]
fn image_open_parses_bzip2_compressed_ewf2_device_info() {
    let file = synthetic_ex01_bzip2_compressed_device_info(b"hello bz2");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 9];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(image.info().chunk_size, 65_536);
    assert_eq!(image.info().logical_size, 65_536);
    assert_eq!(read, 9);
    assert_eq!(&buf, b"hello bz2");
}

#[test]
fn image_open_rejects_ewf2_logical_size_overflow() {
    let file = synthetic_ex01_device_info_text(
        b"overflow",
        "2\nmain\nb\tsc\tts\n512\t64\t18446744073709551615\n\n",
    );

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Malformed(_)));
}

#[test]
fn image_open_rejects_ewf2_oversized_device_info_chunk_size() {
    let file =
        synthetic_ex01_device_info_text(b"oversized", "2\nmain\nb\tsc\tts\n4096\t32769\t32769\n\n");

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message) if message.contains("chunk size")
    ));
}

#[test]
fn image_open_rejects_ewf2_device_info_chunk_size_overflow() {
    let file = synthetic_ex01_device_info_text(
        b"overflow",
        "2\nmain\nb\tsc\tts\n18446744073709551615\t2\t2\n\n",
    );

    let err = open_strict(file.path()).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message) if message.contains("overflow")
    ));
}

#[test]
fn image_open_rejects_mismatched_ewf2_device_information_sections() {
    let file = synthetic_ex01_mismatched_device_info_sections(b"device mismatch");

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Malformed(_)));
}

#[test]
fn image_open_applies_ewf2_case_data_geometry() {
    let file = synthetic_ex01_case_data_geometry(b"case geom");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 9];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(image.info().chunk_size, 65_536);
    assert_eq!(image.info().logical_size, 65_536);
    assert_eq!(read, 9);
    assert_eq!(&buf, b"case geom");
}

#[test]
fn image_open_reads_synthetic_lx01_lef2() {
    let file = synthetic_lx01(b"hello lx01");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 10];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(image.info().format, ewf_image::Format::Ewf2);
    assert_eq!(read, 10);
    assert_eq!(&buf, b"hello lx01");
}

#[test]
fn image_open_reads_synthetic_ewf2_bzip2_chunk() {
    let file = synthetic_ex01_bzip2(b"hello bzip2");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 11];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 11);
    assert_eq!(&buf, b"hello bzip2");
}

#[test]
fn image_open_reads_ewf2_bzip2_chunk_above_zlib_size_cap() {
    let expected = deterministic_noise(32_768);
    let compressed = bzip2_bytes(&expected);
    assert!(compressed.len() as u64 > 32_768 + (32_768 >> 12) + (32_768 >> 14) + 13);
    let file = synthetic_ewf2_with_entry(EX01_SIGNATURE, ".Ex01", 2, Some(&compressed), 1, 0);
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = vec![0; expected.len()];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, expected.len());
    assert_eq!(buf, expected);
}

#[test]
fn image_read_rejects_ewf2_zlib_chunk_above_size_cap() {
    let oversized = vec![0; 32_768 + 2_048];
    let file = synthetic_ewf2_with_entry(EX01_SIGNATURE, ".Ex01", 1, Some(&oversized), 1, 0);
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 1];

    let err = image.read_at(&mut buf, 0).unwrap_err();

    assert!(matches!(
        err,
        ewf_image::EwfError::Malformed(message) if message.contains("encoded chunk size")
    ));
}

#[test]
fn image_open_reads_synthetic_ewf2_pattern_fill_chunk() {
    let file = synthetic_ex01_pattern_fill(0x1122_3344_5566_7788);
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 10];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 10);
    assert_eq!(
        buf,
        [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x88, 0x77]
    );
}

#[test]
fn image_open_ignores_descriptor_like_bytes_inside_ewf2_chunk_data() {
    let file = synthetic_ex01_with_descriptor_like_chunk_bytes(b"fake ok");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 7];

    let read = image.read_at(&mut buf, 0).unwrap();

    assert_eq!(read, 7);
    assert_eq!(&buf, b"fake ok");
}

#[test]
fn image_read_rejects_ewf2_chunk_range_beyond_segment() {
    let file = synthetic_ex01_out_of_bounds_chunk();
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut buf = [0; 1];

    let err = image.read_at(&mut buf, 0).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Malformed(_)));
}

#[test]
fn image_rejects_ewf2_encryption_keys_section() {
    let file = synthetic_ex01_encryption_keys_section();

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Unsupported(_)));
}

#[test]
fn image_rejects_encrypted_ewf2_sections() {
    let file = synthetic_ex01_encrypted_device_info();

    let err = ewf_image::Image::open(file.path()).unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Unsupported(_)));
}

#[test]
fn image_cursor_implements_read_and_seek() {
    let file = synthetic_e01(b"hello cursor");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut cursor = image.cursor();

    let mut first = [0; 5];
    cursor.read_exact(&mut first).unwrap();
    assert_eq!(&first, b"hello");
    assert_eq!(cursor.position(), 5);

    cursor.seek(SeekFrom::Start(6)).unwrap();
    let mut second = [0; 6];
    cursor.read_exact(&mut second).unwrap();
    assert_eq!(&second, b"cursor");
}

#[test]
fn image_cursor_exposes_offset_read_helpers() {
    let file = synthetic_e01(b"hello cursor");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let mut cursor = image.cursor();
    let mut first = [0; 5];
    let mut second = [0; 6];

    assert_eq!(cursor.offset(), 0);
    assert_eq!(cursor.read_buffer(&mut first).unwrap(), 5);
    assert_eq!(&first, b"hello");
    assert_eq!(cursor.offset(), 5);

    assert_eq!(cursor.seek_offset(SeekFrom::Start(6)).unwrap(), 6);
    assert_eq!(cursor.read_buffer_at_offset(&mut second, 6).unwrap(), 6);
    assert_eq!(&second, b"cursor");
    assert_eq!(cursor.offset(), 12);
}

#[test]
fn image_supports_concurrent_read_at() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ewf_image::Image>();

    let file = synthetic_e01(b"concurrent reads");
    let image = ewf_image::Image::open(file.path()).unwrap();
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let image = image.clone();
            thread::spawn(move || {
                let mut buf = [0; 16];
                image.read_at(&mut buf, 0).unwrap();
                buf
            })
        })
        .collect();

    for handle in handles {
        assert_eq!(handle.join().unwrap(), *b"concurrent reads");
    }
}

#[cfg(feature = "verify")]
#[test]
fn verify_computes_hashes_and_compares_stored_digest() {
    let file = synthetic_e01_with_stored_digest(b"verify digest");
    let image = ewf_image::Image::open(file.path()).unwrap();

    assert!(image.info().stored_hashes.md5.is_some());
    assert!(image.info().stored_hashes.sha1.is_some());

    let result = image.verify().unwrap();

    assert_eq!(result.md5_match, Some(true));
    assert_eq!(result.sha1_match, Some(true));
    assert!(result.computed_md5.is_some());
    assert!(result.computed_sha1.is_some());
}

#[cfg(feature = "parallel")]
#[test]
fn verification_supports_xways_zstd_zero_markers_and_ewf2_patterns() {
    use sha2::Sha256;
    let zstd = write_temp_with_suffix(
        ".e01",
        &xways_ewf1_segment_bytes(&xways_magicless_zstd_chunk(b"zstd verification"), b""),
    );
    let zero = write_temp_with_suffix(".e01", &xways_ewf1_segment_bytes(&[0], b""));
    let pattern = synthetic_ex01_pattern_fill(0x0807_0605_0403_0201);
    for file in [zstd, zero, pattern] {
        let image = ewf_image::Image::open(file.path()).unwrap();
        let mut expected = Vec::new();
        image.cursor().read_to_end(&mut expected).unwrap();
        let report = image
            .verify_with_options(&ewf_image::VerifyOptions::default().with_parallelism(4))
            .unwrap();
        assert_eq!(
            report.hashes.sha256.as_slice(),
            Sha256::digest(&expected).as_slice()
        );
    }
}

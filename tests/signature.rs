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

//! Signature, encryption, and corruption probe tests.

use std::io::Write;
use std::path::{Path, PathBuf};

const EVF_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];
const LVF_SIGNATURE: [u8; 8] = [0x4c, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];
const EX01_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00];
const LEF2_SIGNATURE: [u8; 8] = [0x4c, 0x45, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00];

fn xways_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/xways-encrypted")
        .join(name)
}

fn temp_file(bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(bytes).unwrap();
    file.flush().unwrap();
    file
}

fn temp_file_with_suffix(suffix: &str, bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut file = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
    file.write_all(bytes).unwrap();
    file.flush().unwrap();
    file
}

fn ewf2_header(signature: [u8; 8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&signature);
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; 16]);
    bytes
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

fn ewf2_desc_with_checksum(
    section_type: u32,
    data_flags: u32,
    data_size: u64,
    previous_offset: u64,
    checksum: u32,
) -> [u8; 64] {
    let mut desc = ewf2_desc_with_flags(section_type, data_flags, data_size, previous_offset);
    desc[60..64].copy_from_slice(&checksum.to_le_bytes());
    desc
}

fn leading_padded_ewf2_section(
    section_type: u32,
    data_flags: u32,
    data: &[u8],
    padding_size: usize,
) -> tempfile::NamedTempFile {
    let mut bytes = ewf2_header(EX01_SIGNATURE);
    let mut desc = ewf2_desc_with_flags(section_type, data_flags, data.len() as u64, 0);
    desc[28..32].copy_from_slice(&(padding_size as u32).to_le_bytes());
    bytes.extend_from_slice(&desc);
    bytes.extend_from_slice(data);
    bytes.extend_from_slice(&vec![0; padding_size]);
    bytes.extend_from_slice(&ewf2_desc_with_flags(0x0f, 0, 0, 32));
    temp_file(&bytes)
}

fn trailing_ewf2_section(
    section_type: u32,
    data_flags: u32,
    data: &[u8],
) -> tempfile::NamedTempFile {
    let mut bytes = ewf2_header(EX01_SIGNATURE);
    bytes.extend_from_slice(data);
    bytes.extend_from_slice(&ewf2_desc_with_flags(
        section_type,
        data_flags,
        data.len() as u64,
        0,
    ));
    temp_file(&bytes)
}

#[test]
fn check_file_signature_accepts_supported_signatures() {
    for signature in [EVF_SIGNATURE, LVF_SIGNATURE, EX01_SIGNATURE, LEF2_SIGNATURE] {
        let file = temp_file(&signature);

        assert!(ewf_image::check_file_signature(file.path()).unwrap());
    }
}

#[test]
fn check_file_signature_rejects_unknown_and_short_files() {
    let unknown = temp_file(b"not-ewf!");
    let short = temp_file(b"EVF");

    assert!(!ewf_image::check_file_signature(unknown.path()).unwrap());
    assert!(!ewf_image::check_file_signature(short.path()).unwrap());
}

#[test]
fn check_file_signature_reports_io_errors() {
    let err = ewf_image::check_file_signature("/no/such/ewf/file.E01").unwrap_err();

    assert!(matches!(err, ewf_image::EwfError::Io(_)));
}

#[test]
fn check_file_encryption_reports_false_for_unknown_short_and_ewf1_files() {
    let unknown = temp_file(b"not-ewf!");
    let short = temp_file(b"EVF");
    let ewf1 = temp_file(&EVF_SIGNATURE);

    assert!(!ewf_image::check_file_encryption(unknown.path()).unwrap());
    assert!(!ewf_image::check_file_encryption(short.path()).unwrap());
    assert!(!ewf_image::check_file_encryption(ewf1.path()).unwrap());
}

#[test]
fn check_file_encryption_detects_xways_encrypted_ewf1_files() {
    for name in [
        "aes128-compatible.E01",
        "aes128-zstd.E01",
        "aes256-compatible.E01",
        "aes256-zstd.E01",
    ] {
        assert!(
            ewf_image::check_file_encryption(xways_fixture(name)).unwrap(),
            "fixture {name} was not detected as encrypted"
        );
    }
}

#[test]
fn check_file_encryption_reports_false_for_plain_ewf2_files() {
    let mut bytes = ewf2_header(EX01_SIGNATURE);
    bytes.extend_from_slice(&ewf2_desc_with_flags(0x0f, 0, 0, 0));
    let file = temp_file(&bytes);

    assert!(!ewf_image::check_file_encryption(file.path()).unwrap());
}

#[test]
fn check_file_encryption_detects_ewf2_encryption_keys_sections() {
    let file = trailing_ewf2_section(0x0b, 0, b"key material");

    assert!(ewf_image::check_file_encryption(file.path()).unwrap());
}

#[test]
fn check_file_encryption_detects_ewf2_encrypted_section_flags() {
    let file = trailing_ewf2_section(0x01, 0x0000_0002, b"encrypted device information");

    assert!(ewf_image::check_file_encryption(file.path()).unwrap());
}

#[test]
fn check_file_encryption_skips_leading_ewf2_section_padding() {
    let file = leading_padded_ewf2_section(0x01, 0, b"plain device information", 12);

    assert!(!ewf_image::check_file_encryption(file.path()).unwrap());
}

#[test]
fn check_segment_files_encryption_detects_later_explicit_segment() {
    let mut clean_bytes = ewf2_header(EX01_SIGNATURE);
    clean_bytes.extend_from_slice(&ewf2_desc_with_flags(0x0f, 0, 0, 0));
    let clean = temp_file_with_suffix(".Ex01", &clean_bytes);
    let encrypted = trailing_ewf2_section(0x0b, 0, b"key material");

    assert!(ewf_image::check_segment_files_encryption([clean.path(), encrypted.path()]).unwrap());
}

#[test]
fn check_file_corruption_reports_false_for_unknown_short_and_clean_probe_files() {
    let unknown = temp_file(b"not-ewf!");
    let short = temp_file(b"EVF");
    let mut clean_ewf2 = ewf2_header(EX01_SIGNATURE);
    clean_ewf2.extend_from_slice(&ewf2_desc_with_flags(0x0f, 0, 0, 0));
    let clean_ewf2 = temp_file_with_suffix(".Ex01", &clean_ewf2);

    assert!(!ewf_image::check_file_corruption(unknown.path()).unwrap());
    assert!(!ewf_image::check_file_corruption(short.path()).unwrap());
    assert!(!ewf_image::check_file_corruption(clean_ewf2.path()).unwrap());
}

#[test]
fn check_file_corruption_detects_ewf2_descriptor_checksum_mismatch() {
    let mut bytes = ewf2_header(EX01_SIGNATURE);
    bytes.extend_from_slice(&ewf2_desc_with_checksum(0x0f, 0, 0, 0, 0xdead_beef));
    let file = temp_file_with_suffix(".Ex01", &bytes);

    assert!(ewf_image::check_file_corruption(file.path()).unwrap());
}

#[test]
fn check_segment_files_corruption_uses_explicit_segment_list() {
    let mut bytes = ewf2_header(EX01_SIGNATURE);
    bytes.extend_from_slice(&ewf2_desc_with_checksum(0x0f, 0, 0, 0, 0xdead_beef));
    let file = temp_file_with_suffix(".Ex01", &bytes);

    assert!(ewf_image::check_segment_files_corruption([file.path()]).unwrap());
}

#[test]
fn check_file_corruption_reports_false_for_encrypted_ewf2_sections() {
    let mut bytes = ewf2_header(EX01_SIGNATURE);
    let data = b"encrypted device information";
    bytes.extend_from_slice(data);
    bytes.extend_from_slice(&ewf2_desc_with_flags(
        0x01,
        0x0000_0002,
        data.len() as u64,
        0,
    ));
    let file = temp_file_with_suffix(".Ex01", &bytes);

    assert!(!ewf_image::check_file_corruption(file.path()).unwrap());
}

#[test]
fn check_file_corruption_reports_false_for_xways_encrypted_ewf1() {
    assert!(!ewf_image::check_file_corruption(xways_fixture("aes128-compatible.E01")).unwrap());
}

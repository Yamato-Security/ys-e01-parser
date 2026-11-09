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

//! X-Ways encrypted EWF1 integration tests.

use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use ewf_image::{
    EncryptionMethod, EwfError, EwfPassword, EwfWriter, Image, OpenOptions, WriteFormat,
    WriteOptions,
};
use sha2::{Digest, Sha256};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/xways-encrypted")
        .join(name)
}

fn without_password_verifier(name: &str) -> tempfile::NamedTempFile {
    let mut data = std::fs::read(fixture(name)).unwrap();
    let descriptor = data
        .windows(b"x_encryption".len())
        .position(|window| window == b"x_encryption")
        .expect("X-Ways encryption section");
    data[descriptor + 78..descriptor + 80].copy_from_slice(&0x1002_u16.to_le_bytes());
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), data).unwrap();
    file
}

#[test]
fn encrypted_open_requires_a_password() {
    for name in [
        "aes128-compatible.E01",
        "aes128-zstd.E01",
        "aes256-compatible.E01",
        "aes256-zstd.E01",
    ] {
        let error = Image::open(fixture(name)).unwrap_err();
        assert!(
            matches!(error, EwfError::PasswordRequired),
            "fixture {name} returned {error:?}"
        );
    }
}

#[test]
fn encrypted_open_rejects_an_incorrect_password() {
    let password = EwfPassword::utf8("definitely-wrong");
    for name in [
        "aes128-compatible.E01",
        "aes128-zstd.E01",
        "aes256-compatible.E01",
        "aes256-zstd.E01",
    ] {
        let error = Image::open_with_password(fixture(name), &password).unwrap_err();
        assert!(
            matches!(error, EwfError::PasswordRejected),
            "fixture {name} returned {error:?}"
        );
    }
}

#[test]
fn opens_and_reads_known_password_xways_images() {
    let password = EwfPassword::utf8("xways-test");
    for (name, expected_method) in [
        (
            "aes128-known-password.E01",
            EncryptionMethod::XWaysAes128Ctr,
        ),
        (
            "aes256-known-password.E01",
            EncryptionMethod::XWaysAes256Ctr,
        ),
    ] {
        let image = Image::open_with_password(fixture(name), &password).unwrap();
        let info = image.encryption_info().expect("encrypted image info");
        assert_eq!(info.method(), expected_method);
        assert!(info.password_verifier_present());

        let mut data = Vec::new();
        image.cursor().read_to_end(&mut data).unwrap();
        assert_eq!(data.len(), 1_048_576);
        assert_eq!(
            Sha256::digest(&data)[..],
            [
                0xa4, 0xa3, 0xec, 0x30, 0xd6, 0x38, 0x82, 0x44, 0xde, 0xd0, 0x6c, 0x36, 0xc1, 0xc7,
                0xf5, 0x01, 0xee, 0x42, 0xfd, 0x79, 0x40, 0xc0, 0x43, 0x50, 0xc6, 0xe3, 0x67, 0xa6,
                0x44, 0x22, 0x03, 0x13,
            ]
        );

        let offsets = [0_usize, 1, 15, 16, 17, 32_767, 32_768, data.len() - 31];
        for offset in offsets.into_iter().chain(offsets.into_iter().rev()) {
            let expected = &data[offset..data.len().min(offset + 73)];
            let mut actual = vec![0_u8; expected.len()];
            assert_eq!(
                image
                    .read_at(&mut actual, u64::try_from(offset).unwrap())
                    .unwrap(),
                expected.len(),
                "fixture {name}, offset {offset}"
            );
            assert_eq!(actual, expected, "fixture {name}, offset {offset}");
        }
    }
}

#[test]
fn supplied_reader_opens_and_reads_a_known_password_xways_image() {
    let bytes = std::fs::read(fixture("aes256-known-password.E01")).unwrap();
    let password = EwfPassword::utf8("xways-test");
    let image = Image::open_readers_with_options_and_password(
        [("fixture.E01", Cursor::new(bytes))],
        OpenOptions::default(),
        &password,
    )
    .unwrap();

    let mut data = Vec::new();
    image.cursor().read_to_end(&mut data).unwrap();
    assert_eq!(data.len(), 1_048_576);
    assert_eq!(
        Sha256::digest(data)[..],
        [
            0xa4, 0xa3, 0xec, 0x30, 0xd6, 0x38, 0x82, 0x44, 0xde, 0xd0, 0x6c, 0x36, 0xc1, 0xc7,
            0xf5, 0x01, 0xee, 0x42, 0xfd, 0x79, 0x40, 0xc0, 0x43, 0x50, 0xc6, 0xe3, 0x67, 0xa6,
            0x44, 0x22, 0x03, 0x13,
        ]
    );
}

#[test]
fn verifier_less_image_uses_decrypted_structure_validation() {
    let file = without_password_verifier("aes256-known-password.E01");
    let password = EwfPassword::utf8("xways-test");
    let image = Image::open_segments_with_options_and_password(
        [file.path()],
        OpenOptions::default(),
        &password,
    )
    .unwrap();
    assert!(
        !image
            .encryption_info()
            .expect("encrypted image info")
            .password_verifier_present()
    );
    image.read_data_chunk(0).unwrap();

    let wrong_password = EwfPassword::utf8("definitely-wrong");
    let error = Image::open_segments_with_options_and_password(
        [file.path()],
        OpenOptions::default(),
        &wrong_password,
    )
    .unwrap_err();
    assert!(matches!(error, EwfError::DecryptionValidationFailed));
}

#[test]
fn authentic_xways_fixtures_read_with_operator_supplied_password() {
    let Ok(password) = std::env::var("EWF_IMAGE_XWAYS_TEST_PASSWORD") else {
        return;
    };
    let password = EwfPassword::utf8(&password);
    for (name, expected_method) in [
        ("aes128-compatible.E01", EncryptionMethod::XWaysAes128Ctr),
        ("aes128-zstd.E01", EncryptionMethod::XWaysAes128Ctr),
        ("aes256-compatible.E01", EncryptionMethod::XWaysAes256Ctr),
        ("aes256-zstd.E01", EncryptionMethod::XWaysAes256Ctr),
    ] {
        let image = Image::open_with_password(fixture(name), &password).unwrap();
        assert_eq!(
            image
                .encryption_info()
                .expect("encrypted image info")
                .method(),
            expected_method
        );
        let mut data = Vec::new();
        image.cursor().read_to_end(&mut data).unwrap();
        assert_eq!(
            Sha256::digest(data)[..],
            [
                0xa4, 0xa3, 0xec, 0x30, 0xd6, 0x38, 0x82, 0x44, 0xde, 0xd0, 0x6c, 0x36, 0xc1, 0xc7,
                0xf5, 0x01, 0xee, 0x42, 0xfd, 0x79, 0x40, 0xc0, 0x43, 0x50, 0xc6, 0xe3, 0x67, 0xa6,
                0x44, 0x22, 0x03, 0x13,
            ],
            "fixture {name}"
        );
    }
}

#[test]
fn password_open_methods_preserve_plain_image_behavior() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("plain.E01");
    let options = WriteOptions {
        format: WriteFormat::Ewf1Physical,
        ..WriteOptions::default()
    };
    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(b"plain image data").unwrap();
    writer.finish().unwrap();
    let password = EwfPassword::utf8("unused-public-test-password");

    let image = Image::open_with_password(&path, &password).unwrap();
    assert!(image.encryption_info().is_none());

    let image =
        Image::open_with_options_and_password(&path, OpenOptions::default(), &password).unwrap();
    assert!(image.encryption_info().is_none());

    let image =
        Image::open_segments_with_options_and_password([&path], OpenOptions::default(), &password)
            .unwrap();
    assert!(image.encryption_info().is_none());

    let bytes = std::fs::read(&path).unwrap();
    let image = Image::open_readers_with_options_and_password(
        [("plain.E01", Cursor::new(bytes))],
        OpenOptions::default(),
        &password,
    )
    .unwrap();
    assert!(image.encryption_info().is_none());
}

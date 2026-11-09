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

use std::fmt;

use aes::{Aes128, Aes256};
use ctr::cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{EwfError, Result};

/// Password bytes supplied for one encrypted EWF image open attempt.
///
/// The password owns its byte allocation and zeroizes that allocation when it
/// is dropped. Its [`Debug`](fmt::Debug) representation is always redacted.
pub struct EwfPassword {
    bytes: Zeroizing<Vec<u8>>,
}

impl EwfPassword {
    /// Takes ownership of raw password bytes without applying an encoding or
    /// normalization step.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: Zeroizing::new(bytes.into()),
        }
    }

    /// Copies a UTF-8 password into zeroizing owned storage.
    #[must_use]
    pub fn utf8(password: &str) -> Self {
        Self::from_bytes(password.as_bytes().to_vec())
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for EwfPassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _secret_length = self.bytes.len();
        formatter.write_str("EwfPassword([REDACTED])")
    }
}

/// Encryption method applied to an opened EWF image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMethod {
    /// X-Ways AES-128 in big-endian counter mode.
    XWaysAes128Ctr,
    /// X-Ways AES-256 in little-endian counter mode.
    XWaysAes256Ctr,
}

/// Non-secret encryption status for an opened EWF image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionInfo {
    method: EncryptionMethod,
    password_verifier_present: bool,
}

impl EncryptionInfo {
    pub(crate) fn from_xways(metadata: &XWaysEncryptionMetadata) -> Self {
        Self {
            method: metadata.method,
            password_verifier_present: metadata.password_verifier.is_some(),
        }
    }

    /// Returns the image's encryption method.
    #[must_use]
    pub const fn method(self) -> EncryptionMethod {
        self.method
    }

    /// Returns whether the image contained a password verification hash.
    #[must_use]
    pub const fn password_verifier_present(self) -> bool {
        self.password_verifier_present
    }
}

pub(crate) const XWAYS_ENCRYPTION_DATA_SIZE: usize = 84;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct XWaysEncryptionMetadata {
    pub(crate) method: EncryptionMethod,
    pub(crate) flags: u16,
    pub(crate) salt: [u8; 32],
    pub(crate) initial_counter: [u8; 16],
    pub(crate) password_verifier: Option<[u8; 32]>,
}

impl XWaysEncryptionMetadata {
    pub(crate) fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != XWAYS_ENCRYPTION_DATA_SIZE {
            return Err(EwfError::Malformed(format!(
                "X-Ways EWF1 encryption section has size {}, expected {XWAYS_ENCRYPTION_DATA_SIZE}",
                data.len()
            )));
        }

        let raw_method = u16::from_le_bytes([data[0], data[1]]);
        let flags = u16::from_le_bytes([data[2], data[3]]);
        if raw_method >= 3 {
            return Err(EwfError::Malformed(format!(
                "invalid X-Ways EWF1 encryption method {raw_method}"
            )));
        }
        if flags & 0x0fff >= 8 {
            return Err(EwfError::Malformed(format!(
                "invalid X-Ways EWF1 encryption flags 0x{flags:04x}"
            )));
        }
        if (raw_method == 0 && flags & 1 == 0) || (raw_method == 1 && flags & 1 != 0) {
            return Err(EwfError::Malformed(format!(
                "X-Ways EWF1 encryption method {raw_method} conflicts with flags 0x{flags:04x}"
            )));
        }

        let method = match raw_method {
            0 => EncryptionMethod::XWaysAes128Ctr,
            1 => EncryptionMethod::XWaysAes256Ctr,
            2 => {
                return Err(EwfError::Unsupported(
                    "X-Ways EWF1 encryption method 2".into(),
                ));
            }
            _ => unreachable!("raw method was validated above"),
        };
        let salt = data[4..36]
            .try_into()
            .expect("X-Ways encryption metadata length checked");
        let initial_counter = data[36..52]
            .try_into()
            .expect("X-Ways encryption metadata length checked");
        let password_verifier = (flags & 2 == 0).then(|| {
            data[52..84]
                .try_into()
                .expect("X-Ways encryption metadata length checked")
        });

        Ok(Self {
            method,
            flags,
            salt,
            initial_counter,
            password_verifier,
        })
    }
}

pub(crate) struct EncryptionContext {
    method: EncryptionMethod,
    key: DerivedKey,
    initial_counter: [u8; 16],
}

enum DerivedKey {
    Aes128(Zeroizing<[u8; 16]>),
    Aes256(Zeroizing<[u8; 32]>),
}

impl fmt::Debug for EncryptionContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptionContext")
            .field("method", &self.method)
            .field("key", &"[REDACTED]")
            .field("initial_counter", &"[REDACTED]")
            .finish()
    }
}

impl EncryptionContext {
    pub(crate) fn derive(
        metadata: &XWaysEncryptionMetadata,
        password: &EwfPassword,
    ) -> Result<Self> {
        let password = xways_password_bytes(metadata.method, password.as_bytes())?;
        if metadata.password_verifier.as_ref().is_some_and(|expected| {
            let actual = xways_password_verifier(metadata.method, &password, &metadata.salt);
            !bool::from(actual[..].ct_eq(expected))
        }) {
            return Err(EwfError::PasswordRejected);
        }

        let key = match metadata.method {
            EncryptionMethod::XWaysAes128Ctr => {
                DerivedKey::Aes128(derive_aes128_key(&password, &metadata.salt))
            }
            EncryptionMethod::XWaysAes256Ctr => {
                DerivedKey::Aes256(derive_aes256_key(&password, &metadata.salt))
            }
        };
        Ok(Self {
            method: metadata.method,
            key,
            initial_counter: metadata.initial_counter,
        })
    }

    pub(crate) fn apply_keystream(&self, stream_offset: u64, bytes: &mut [u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        if !stream_offset.is_multiple_of(16) {
            return Err(EwfError::Malformed(
                "X-Ways AES chunk offset is not block aligned".into(),
            ));
        }

        let block_index = stream_offset / 16;
        let final_block_delta =
            u64::try_from((bytes.len() - 1) / 16).map_err(|_| counter_overflow())?;
        let counter = counter_at_chunk_offset(self.initial_counter, block_index)?;

        match &self.key {
            DerivedKey::Aes128(key) => {
                u128::from_be_bytes(counter)
                    .checked_add(u128::from(final_block_delta))
                    .ok_or_else(counter_overflow)?;
                type Aes128Ctr = ctr::Ctr128BE<Aes128>;
                let mut cipher = Aes128Ctr::new((&**key).into(), (&counter).into());
                cipher.apply_keystream(bytes);
            }
            DerivedKey::Aes256(key) => {
                u64::from_le_bytes(counter[..8].try_into().expect("counter prefix length"))
                    .checked_add(final_block_delta)
                    .ok_or_else(counter_overflow)?;
                type Aes256Ctr = ctr::Ctr64LE<Aes256>;
                let mut cipher = Aes256Ctr::new((&**key).into(), (&counter).into());
                cipher.apply_keystream(bytes);
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn from_test_aes128_key(key: [u8; 16], initial_counter: [u8; 16]) -> Self {
        Self {
            method: EncryptionMethod::XWaysAes128Ctr,
            key: DerivedKey::Aes128(Zeroizing::new(key)),
            initial_counter,
        }
    }
}

fn counter_at_chunk_offset(initial_counter: [u8; 16], block_index: u64) -> Result<[u8; 16]> {
    let mut counter = initial_counter;
    let prefix = u64::from_le_bytes(counter[..8].try_into().expect("counter prefix length"))
        .checked_add(block_index)
        .ok_or_else(counter_overflow)?;
    counter[..8].copy_from_slice(&prefix.to_le_bytes());
    Ok(counter)
}

fn counter_overflow() -> EwfError {
    EwfError::Malformed("X-Ways AES counter overflow".into())
}

fn xways_password_bytes(method: EncryptionMethod, password: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let maximum_length = match method {
        EncryptionMethod::XWaysAes128Ctr => 16,
        EncryptionMethod::XWaysAes256Ctr => 32,
    };
    if password.len() > maximum_length {
        return Err(EwfError::PasswordRejected);
    }

    let mut bytes = Zeroizing::new([0_u8; 32]);
    bytes[..password.len()].copy_from_slice(password);
    Ok(bytes)
}

fn derive_aes256_key(password: &[u8; 32], salt: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(
        Sha256::new()
            .chain_update(password)
            .chain_update(salt)
            .finalize()
            .into(),
    )
}

fn derive_aes128_key(password: &[u8; 32], salt: &[u8; 32]) -> Zeroizing<[u8; 16]> {
    let key = derive_aes256_key(password, salt);
    let mut reduced = Zeroizing::new([0_u8; 16]);
    for (output, (first, second)) in reduced.iter_mut().zip(key[..16].iter().zip(&key[16..])) {
        *output = first ^ second;
    }
    reduced
}

fn xways_password_verifier(
    method: EncryptionMethod,
    password: &[u8; 32],
    salt: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let rounds = match method {
        EncryptionMethod::XWaysAes128Ctr => 100_000,
        EncryptionMethod::XWaysAes256Ctr => 1,
    };
    let mut previous: Zeroizing<[u8; 32]> = Zeroizing::new(Sha256::digest(password).into());
    let mut current = Zeroizing::new([0_u8; 32]);
    for round in 0..rounds {
        *current = Sha256::new()
            .chain_update(password)
            .chain_update(previous.as_slice())
            .finalize()
            .into();
        if round + 1 < rounds {
            previous.copy_from_slice(current.as_slice());
        }
    }
    Zeroizing::new(
        Sha256::new()
            .chain_update(salt)
            .chain_update(previous.as_slice())
            .chain_update(current.as_slice())
            .finalize()
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &[u8] = b"xways-test";
    const SALT: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    fn hex_vec(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let high = char::from(pair[0]).to_digit(16).expect("hex digit");
                let low = char::from(pair[1]).to_digit(16).expect("hex digit");
                u8::try_from((high << 4) | low).expect("hex byte")
            })
            .collect()
    }

    fn hex_array<const N: usize>(value: &str) -> [u8; N] {
        hex_vec(value).try_into().expect("hex has expected length")
    }

    fn aes256_context(initial_counter: [u8; 16]) -> EncryptionContext {
        let password = EwfPassword::from_bytes(PASSWORD.to_vec());
        let metadata = XWaysEncryptionMetadata {
            method: EncryptionMethod::XWaysAes256Ctr,
            flags: 0x1000,
            salt: SALT,
            initial_counter,
            password_verifier: None,
        };
        EncryptionContext::derive(&metadata, &password).unwrap()
    }

    #[test]
    fn parses_authentic_xways_encryption_metadata() {
        let aes128 = XWaysEncryptionMetadata::parse(&hex_vec(
            "0000011061F995F4B65662828E420139572C452260666DCD481BBBCA8E98528E3F8D8BBA9342D4A3AE0E16F923C5A37B9389A83D14F51270CF749C0E82CA06C8A0ED97602A55ACF684A6A18FCC4F0021BCCC95E4",
        ))
        .unwrap();
        assert_eq!(aes128.method, EncryptionMethod::XWaysAes128Ctr);
        assert_eq!(aes128.flags, 0x1001);
        assert_eq!(
            aes128.salt,
            hex_array("61F995F4B65662828E420139572C452260666DCD481BBBCA8E98528E3F8D8BBA")
        );
        assert_eq!(
            aes128.initial_counter,
            hex_array("9342D4A3AE0E16F923C5A37B9389A83D")
        );
        assert_eq!(
            aes128.password_verifier,
            Some(hex_array(
                "14F51270CF749C0E82CA06C8A0ED97602A55ACF684A6A18FCC4F0021BCCC95E4"
            ))
        );

        let aes256 = XWaysEncryptionMetadata::parse(&hex_vec(
            "01000010FD1E9C28B616BF087EAB72E63578FA65998724AB118F5977485FD0CA970492724376F18ED9736D06E3AB9D3D80EA2DC0F54130378826D53F929D6AE526A1974CA63A10593D097535EE481DD29CA81163",
        ))
        .unwrap();
        assert_eq!(aes256.method, EncryptionMethod::XWaysAes256Ctr);
        assert_eq!(aes256.flags, 0x1000);
        assert_eq!(
            aes256.salt,
            hex_array("FD1E9C28B616BF087EAB72E63578FA65998724AB118F5977485FD0CA97049272")
        );
        assert_eq!(
            aes256.initial_counter,
            hex_array("4376F18ED9736D06E3AB9D3D80EA2DC0")
        );
        assert_eq!(
            aes256.password_verifier,
            Some(hex_array(
                "F54130378826D53F929D6AE526A1974CA63A10593D097535EE481DD29CA81163"
            ))
        );
    }

    #[test]
    fn parses_verifier_absence_from_xways_flags() {
        let mut data = [0_u8; 84];
        data[..2].copy_from_slice(&1_u16.to_le_bytes());
        data[2..4].copy_from_slice(&0x1002_u16.to_le_bytes());

        let metadata = XWaysEncryptionMetadata::parse(&data).unwrap();

        assert_eq!(metadata.password_verifier, None);
    }

    #[test]
    fn rejects_invalid_xways_encryption_metadata() {
        let error = XWaysEncryptionMetadata::parse(&[0_u8; 83]).unwrap_err();
        assert!(matches!(error, EwfError::Malformed(_)));

        for (method, flags) in [(3_u16, 0_u16), (0, 0), (1, 1), (0, 0x1009)] {
            let mut data = [0_u8; 84];
            data[..2].copy_from_slice(&method.to_le_bytes());
            data[2..4].copy_from_slice(&flags.to_le_bytes());

            let error = XWaysEncryptionMetadata::parse(&data).unwrap_err();
            assert!(
                matches!(error, EwfError::Malformed(_)),
                "method={method}, flags=0x{flags:04x}, error={error:?}"
            );
        }
    }

    #[test]
    fn derives_reverse_engineered_xways_keys() {
        let password = xways_password_bytes(EncryptionMethod::XWaysAes256Ctr, PASSWORD).unwrap();
        assert_eq!(
            *derive_aes256_key(&password, &SALT),
            hex_array("e6e743cc93230c187367b822f06a5207dbbb2f76ca9782ddf7387f1112f71c7c")
        );
        assert_eq!(
            *derive_aes128_key(&password, &SALT),
            hex_array("3d5c6cba59b48ec5845fc733e29d4e7b")
        );
    }

    #[test]
    fn computes_method_specific_xways_password_verifiers() {
        let password = xways_password_bytes(EncryptionMethod::XWaysAes256Ctr, PASSWORD).unwrap();
        assert_eq!(
            *xways_password_verifier(EncryptionMethod::XWaysAes256Ctr, &password, &SALT),
            hex_array("67848e0c6345512ce5fd75dd57d6ee5f94fcae9fefb5eddc85f147d706c6364b")
        );
        assert_eq!(
            *xways_password_verifier(EncryptionMethod::XWaysAes128Ctr, &password, &SALT),
            hex_array("bc2387cb286603d72cd6cc0b83c0a9fff7ff08f3ebefe57ad74464f3698abd2d")
        );
    }

    #[test]
    fn canonicalizes_xways_passwords_to_fixed_zero_padded_buffers() {
        let password = xways_password_bytes(EncryptionMethod::XWaysAes128Ctr, b"abc").unwrap();
        assert_eq!(&password[..3], b"abc");
        assert!(password[3..].iter().all(|byte| *byte == 0));

        assert!(matches!(
            xways_password_bytes(EncryptionMethod::XWaysAes128Ctr, &[b'a'; 17]),
            Err(EwfError::PasswordRejected)
        ));
        assert!(matches!(
            xways_password_bytes(EncryptionMethod::XWaysAes256Ctr, &[b'a'; 33]),
            Err(EwfError::PasswordRejected)
        ));
    }

    #[test]
    fn aes128_ctr_matches_nist_big_endian_vector() {
        let mut data = hex_vec("6bc1bee22e409f96e93d7e117393172a");
        let context = EncryptionContext::from_test_aes128_key(
            hex_array("2b7e151628aed2a6abf7158809cf4f3c"),
            hex_array("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        );

        context.apply_keystream(0, &mut data).unwrap();

        assert_eq!(data, hex_vec("874d6191b620e3261bef6864990db6ce"));
    }

    #[test]
    fn aes256_ctr_increments_the_low_order_first_byte() {
        let context = aes256_context(hex_array("000102030405060708090a0b0c0d0e0f"));
        let mut two_blocks = vec![0_u8; 32];

        context.apply_keystream(0, &mut two_blocks).unwrap();

        assert_eq!(
            &two_blocks[..16],
            hex_vec("d6d49d46ee7b6965ca7cb74ee3923d5f")
        );
        assert_eq!(
            &two_blocks[16..],
            hex_vec("d980e413ca4e5da559db937f4712841c")
        );
    }

    #[test]
    fn aes128_chunk_offsets_advance_the_counter_prefix() {
        let context = EncryptionContext::from_test_aes128_key(
            hex_array("2b7e151628aed2a6abf7158809cf4f3c"),
            hex_array("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        );
        let mut data = [0_u8; 16];

        context.apply_keystream(16, &mut data).unwrap();

        assert_eq!(data, hex_array("eeb9afc6c9b7e3d53576f29fe1e17805"));
    }

    #[test]
    fn rejects_unaligned_xways_chunk_offsets() {
        let context = aes256_context(hex_array("000102030405060708090a0b0c0d0e0f"));
        let mut data = [0_u8; 16];

        let error = context.apply_keystream(1, &mut data).unwrap_err();

        assert!(
            matches!(error, EwfError::Malformed(message) if message == "X-Ways AES chunk offset is not block aligned")
        );
    }

    #[test]
    fn empty_ctr_read_at_maximum_counter_is_allowed() {
        let context = EncryptionContext::from_test_aes128_key([0; 16], [0xff; 16]);
        let mut empty = [];

        context.apply_keystream(u64::MAX, &mut empty).unwrap();
    }

    #[test]
    fn ctr_read_rejects_counter_wrap() {
        let context = EncryptionContext::from_test_aes128_key([0; 16], [0xff; 16]);
        let mut data = [0_u8; 1];

        let error = context.apply_keystream(16, &mut data).unwrap_err();

        assert!(
            matches!(error, EwfError::Malformed(message) if message == "X-Ways AES counter overflow")
        );
    }
}

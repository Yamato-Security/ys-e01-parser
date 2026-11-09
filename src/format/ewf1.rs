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

use std::io::{Read, Seek, SeekFrom};

use crate::encryption::{XWAYS_ENCRYPTION_DATA_SIZE, XWaysEncryptionMetadata};
use crate::{EwfError, Result};

pub(crate) const EVF_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];
pub(crate) const LVF_SIGNATURE: [u8; 8] = [0x4c, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];

const XWAYS_ENCRYPTED_ZLIB_MARKER: u8 = 0x81;
const XWAYS_ENCRYPTED_ZSTD_MARKER: u8 = 0xa1;
pub(crate) fn probe_xways_encryption<R: Read + Seek + ?Sized>(file: &mut R) -> Result<bool> {
    Ok(read_xways_encryption(file)?.is_some())
}

pub(crate) fn read_xways_encryption<R: Read + Seek + ?Sized>(
    file: &mut R,
) -> Result<Option<XWaysEncryptionMetadata>> {
    let file_len = file.seek(SeekFrom::End(0))?;
    if file_len < FILE_HEADER_SIZE as u64 {
        return Ok(None);
    }

    let mut header = [0; FILE_HEADER_SIZE];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut header)?;
    if header[..8] != EVF_SIGNATURE && header[..8] != LVF_SIGNATURE {
        return Ok(None);
    }
    let header = FileHeader::parse(&header)?;
    if !matches!(
        header.format_marker,
        XWAYS_ENCRYPTED_ZLIB_MARKER | XWAYS_ENCRYPTED_ZSTD_MARKER
    ) {
        return Ok(None);
    }

    let mut offset = FILE_HEADER_SIZE as u64;
    let max_sections = ((file_len - offset) / SECTION_DESCRIPTOR_SIZE as u64).saturating_add(1);
    for _ in 0..max_sections {
        let descriptor_end = offset
            .checked_add(SECTION_DESCRIPTOR_SIZE as u64)
            .ok_or_else(|| EwfError::Malformed("EWF1 section descriptor overflow".into()))?;
        if descriptor_end > file_len {
            return Err(EwfError::Malformed(
                "X-Ways EWF1 section descriptor exceeds file".into(),
            ));
        }

        let mut bytes = [0; SECTION_DESCRIPTOR_SIZE];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut bytes)?;
        let descriptor = SectionDescriptor::parse(&bytes, offset)?;
        let data_size = descriptor.data_size()?;
        let section_end = descriptor_end
            .checked_add(data_size)
            .ok_or_else(|| EwfError::Malformed("X-Ways EWF1 section overflow".into()))?;
        if section_end > file_len {
            return Err(EwfError::Malformed(
                "X-Ways EWF1 section exceeds file".into(),
            ));
        }

        if descriptor.section_type == "x_encryption" {
            let data_size = usize::try_from(data_size).map_err(|_| {
                EwfError::Malformed("X-Ways EWF1 encryption section size does not fit usize".into())
            })?;
            if data_size != XWAYS_ENCRYPTION_DATA_SIZE {
                return Err(EwfError::Malformed(format!(
                    "X-Ways EWF1 encryption section has size {data_size}, expected {XWAYS_ENCRYPTION_DATA_SIZE}"
                )));
            }
            let mut data = [0_u8; XWAYS_ENCRYPTION_DATA_SIZE];
            file.read_exact(&mut data)?;
            return XWaysEncryptionMetadata::parse(&data).map(Some);
        }
        if matches!(descriptor.section_type.as_str(), "done" | "next") {
            return Err(EwfError::Malformed(
                "X-Ways EWF1 encrypted marker has no encryption section".into(),
            ));
        }
        if descriptor.next < section_end || descriptor.next <= offset {
            return Err(EwfError::Malformed(
                "X-Ways EWF1 section chain does not advance".into(),
            ));
        }
        offset = descriptor.next;
    }

    Err(EwfError::Malformed(
        "X-Ways EWF1 section chain is too long".into(),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileHeader {
    pub(crate) segment_number: u16,
    pub(crate) logical: bool,
    pub(crate) format_marker: u8,
}

impl FileHeader {
    pub(crate) fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < FILE_HEADER_SIZE {
            return Err(EwfError::BufferTooShort {
                needed: FILE_HEADER_SIZE,
                actual: buf.len(),
            });
        }

        let logical = if buf[0..8] == EVF_SIGNATURE {
            false
        } else if buf[0..8] == LVF_SIGNATURE {
            true
        } else {
            return Err(EwfError::InvalidSignature);
        };

        Ok(Self {
            segment_number: u16::from_le_bytes([buf[9], buf[10]]),
            logical,
            format_marker: buf[8],
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SectionDescriptor {
    pub(crate) section_type: String,
    pub(crate) next: u64,
    pub(crate) size: u64,
    pub(crate) offset: u64,
    pub(crate) compression_method: Option<String>,
}

impl SectionDescriptor {
    pub(crate) fn parse(buf: &[u8], offset: u64) -> Result<Self> {
        if buf.len() < SECTION_DESCRIPTOR_SIZE {
            return Err(EwfError::BufferTooShort {
                needed: SECTION_DESCRIPTOR_SIZE,
                actual: buf.len(),
            });
        }

        let type_end = buf[..16].iter().position(|&b| b == 0).unwrap_or(16);
        let section_type = String::from_utf8_lossy(&buf[..type_end]).into_owned();
        let next = u64::from_le_bytes(buf[16..24].try_into().expect("slice length checked"));
        let size = u64::from_le_bytes(buf[24..32].try_into().expect("slice length checked"));
        let compression_end = buf[32..72].iter().position(|&byte| byte == 0).unwrap_or(40);
        let compression_method = (compression_end > 0)
            .then(|| String::from_utf8_lossy(&buf[32..32 + compression_end]).into_owned());

        Ok(Self {
            section_type,
            next,
            size,
            offset,
            compression_method,
        })
    }

    pub(crate) fn data_size(&self) -> Result<u64> {
        if self.size == 0 && matches!(self.section_type.as_str(), "done" | "next") {
            return Ok(0);
        }

        self.size
            .checked_sub(SECTION_DESCRIPTOR_SIZE as u64)
            .ok_or_else(|| EwfError::Malformed("section is smaller than descriptor".into()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Volume {
    pub(crate) chunk_count: u32,
    pub(crate) sectors_per_chunk: u32,
    pub(crate) bytes_per_sector: u32,
    pub(crate) sector_count: u64,
    pub(crate) set_identifier: Option<[u8; 16]>,
    pub(crate) media_type: Option<u8>,
    pub(crate) media_flags: Option<u8>,
    pub(crate) compression_level: Option<u8>,
    pub(crate) error_granularity: Option<u32>,
    pub(crate) smart: bool,
}

impl Volume {
    pub(crate) fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 24 {
            return Err(EwfError::BufferTooShort {
                needed: 24,
                actual: buf.len(),
            });
        }

        let smart_volume = buf.len() == SMART_VOLUME_SIZE;
        let sector_count = if smart_volume {
            u64::from(u32::from_le_bytes(
                buf[16..20].try_into().expect("slice length checked"),
            ))
        } else {
            u64::from_le_bytes(buf[16..24].try_into().expect("slice length checked"))
        };
        let set_identifier = if smart_volume {
            None
        } else {
            buf.get(64..80).and_then(|value| {
                let mut identifier = [0; 16];
                identifier.copy_from_slice(value);
                (identifier != [0; 16]).then_some(identifier)
            })
        };
        let has_full_volume_profile = !smart_volume && buf.len() >= VOLUME_DATA_SIZE;
        let error_granularity = has_full_volume_profile
            .then(|| u32::from_le_bytes(buf[56..60].try_into().expect("slice length checked")))
            .filter(|value| *value != 0);

        Ok(Self {
            chunk_count: u32::from_le_bytes(buf[4..8].try_into().expect("slice length checked")),
            sectors_per_chunk: u32::from_le_bytes(
                buf[8..12].try_into().expect("slice length checked"),
            ),
            bytes_per_sector: u32::from_le_bytes(
                buf[12..16].try_into().expect("slice length checked"),
            ),
            sector_count,
            set_identifier,
            media_type: has_full_volume_profile.then_some(buf[0]),
            media_flags: has_full_volume_profile.then(|| buf[36]),
            compression_level: buf.get(52).copied(),
            error_granularity,
            smart: smart_volume,
        })
    }

    pub(crate) fn chunk_size(&self) -> Result<u64> {
        u64::from(self.sectors_per_chunk)
            .checked_mul(u64::from(self.bytes_per_sector))
            .ok_or_else(|| EwfError::Malformed("EWF1 chunk size overflow".into()))
    }

    pub(crate) fn logical_size(&self) -> Result<u64> {
        self.sector_count
            .checked_mul(u64::from(self.bytes_per_sector))
            .ok_or_else(|| EwfError::Malformed("EWF1 logical size overflow".into()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TableEntry {
    pub(crate) compressed: bool,
    pub(crate) offset: u64,
    pub(crate) raw: u32,
}

impl TableEntry {
    pub(crate) fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 4 {
            return Err(EwfError::BufferTooShort {
                needed: 4,
                actual: buf.len(),
            });
        }

        let raw = u32::from_le_bytes(buf[..4].try_into().expect("slice length checked"));
        Ok(Self {
            compressed: raw & 0x8000_0000 != 0,
            offset: u64::from(raw & 0x7fff_ffff),
            raw,
        })
    }
}

pub(crate) const FILE_HEADER_SIZE: usize = 13;
pub(crate) const SECTION_DESCRIPTOR_SIZE: usize = 76;
const VOLUME_DATA_SIZE: usize = 1052;
const SMART_VOLUME_SIZE: usize = 94;

#[cfg(test)]
mod tests {
    use super::*;

    fn file_header(signature: [u8; 8], segment_number: u16) -> [u8; FILE_HEADER_SIZE] {
        let mut buf = [0; FILE_HEADER_SIZE];
        buf[0..8].copy_from_slice(&signature);
        buf[8] = 1;
        buf[9..11].copy_from_slice(&segment_number.to_le_bytes());
        buf
    }

    #[test]
    fn parses_evf_file_header() {
        let header = FileHeader::parse(&file_header(EVF_SIGNATURE, 42)).unwrap();

        assert_eq!(header.segment_number, 42);
        assert!(!header.logical);
        assert_eq!(header.format_marker, 1);
    }

    #[test]
    fn parses_lvf_file_header_as_logical() {
        let header = FileHeader::parse(&file_header(LVF_SIGNATURE, 7)).unwrap();

        assert_eq!(header.segment_number, 7);
        assert!(header.logical);
    }

    #[test]
    fn rejects_invalid_file_header_signature() {
        let err = FileHeader::parse(&[0; FILE_HEADER_SIZE]).unwrap_err();

        assert!(matches!(err, EwfError::InvalidSignature));
    }

    #[test]
    fn rejects_short_file_header() {
        let err = FileHeader::parse(&[0; 4]).unwrap_err();

        assert!(matches!(
            err,
            EwfError::BufferTooShort {
                needed: FILE_HEADER_SIZE,
                actual: 4
            }
        ));
    }

    #[test]
    fn parses_section_descriptor() {
        let mut buf = [0; SECTION_DESCRIPTOR_SIZE];
        buf[0..6].copy_from_slice(b"volume");
        buf[16..24].copy_from_slice(&1234_u64.to_le_bytes());
        buf[24..32].copy_from_slice(&170_u64.to_le_bytes());
        buf[32..36].copy_from_slice(b"Zstd");

        let desc = SectionDescriptor::parse(&buf, FILE_HEADER_SIZE as u64).unwrap();

        assert_eq!(desc.section_type, "volume");
        assert_eq!(desc.next, 1234);
        assert_eq!(desc.size, 170);
        assert_eq!(desc.offset, FILE_HEADER_SIZE as u64);
        assert_eq!(desc.compression_method.as_deref(), Some("Zstd"));
        assert_eq!(desc.data_size().unwrap(), 94);
    }

    #[test]
    fn zero_sized_terminal_section_has_no_data() {
        let mut buf = [0; SECTION_DESCRIPTOR_SIZE];
        buf[0..4].copy_from_slice(b"done");

        let desc = SectionDescriptor::parse(&buf, FILE_HEADER_SIZE as u64).unwrap();

        assert_eq!(desc.data_size().unwrap(), 0);
    }

    #[test]
    fn parses_volume_geometry() {
        let mut buf = [0; 94];
        buf[4..8].copy_from_slice(&1000_u32.to_le_bytes());
        buf[8..12].copy_from_slice(&64_u32.to_le_bytes());
        buf[12..16].copy_from_slice(&512_u32.to_le_bytes());
        buf[16..24].copy_from_slice(&64_000_u64.to_le_bytes());

        let volume = Volume::parse(&buf).unwrap();

        assert_eq!(volume.chunk_count, 1000);
        assert_eq!(volume.sectors_per_chunk, 64);
        assert_eq!(volume.bytes_per_sector, 512);
        assert_eq!(volume.sector_count, 64_000);
        assert_eq!(volume.set_identifier, None);
        assert_eq!(volume.chunk_size().unwrap(), 32_768);
        assert_eq!(volume.logical_size().unwrap(), 32_768_000);
    }

    #[test]
    fn parses_smart_volume_sector_count_as_u32() {
        let mut buf = [0; 94];
        buf[4..8].copy_from_slice(&1000_u32.to_le_bytes());
        buf[8..12].copy_from_slice(&64_u32.to_le_bytes());
        buf[12..16].copy_from_slice(&512_u32.to_le_bytes());
        buf[16..20].copy_from_slice(&64_000_u32.to_le_bytes());
        buf[20..24].copy_from_slice(&0xfeed_beef_u32.to_le_bytes());

        let volume = Volume::parse(&buf).unwrap();

        assert_eq!(volume.chunk_count, 1000);
        assert_eq!(volume.sectors_per_chunk, 64);
        assert_eq!(volume.bytes_per_sector, 512);
        assert_eq!(volume.sector_count, 64_000);
        assert_eq!(volume.logical_size().unwrap(), 32_768_000);
    }

    #[test]
    fn short_volume_profile_does_not_read_optional_flags() {
        let volume = Volume::parse(&[0; 28]).unwrap();
        assert_eq!(volume.media_flags, None);
    }

    #[test]
    fn parses_volume_set_identifier() {
        let mut buf = [0; 1052];
        buf[4..8].copy_from_slice(&1_u32.to_le_bytes());
        buf[8..12].copy_from_slice(&64_u32.to_le_bytes());
        buf[12..16].copy_from_slice(&512_u32.to_le_bytes());
        buf[16..24].copy_from_slice(&64_u64.to_le_bytes());
        buf[64..80].copy_from_slice(&[0xab; 16]);

        let volume = Volume::parse(&buf).unwrap();

        assert_eq!(volume.set_identifier, Some([0xab; 16]));
    }

    #[test]
    fn ignores_smart_volume_padding_as_set_identifier() {
        let mut buf = [0; SMART_VOLUME_SIZE];
        buf[4..8].copy_from_slice(&1_u32.to_le_bytes());
        buf[8..12].copy_from_slice(&64_u32.to_le_bytes());
        buf[12..16].copy_from_slice(&512_u32.to_le_bytes());
        buf[16..20].copy_from_slice(&64_u32.to_le_bytes());
        buf[64..80].copy_from_slice(&[0xab; 16]);

        let volume = Volume::parse(&buf).unwrap();

        assert_eq!(volume.set_identifier, None);
    }

    #[test]
    fn parses_table_entry_compression_bit_and_masked_offset() {
        let entry = TableEntry::parse(&0x8000_1234_u32.to_le_bytes()).unwrap();

        assert!(entry.compressed);
        assert_eq!(entry.offset, 0x1234);
        assert_eq!(entry.raw, 0x8000_1234);
    }
}

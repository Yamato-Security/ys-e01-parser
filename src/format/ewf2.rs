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

use crate::{EwfError, Result};

pub(crate) const EX01_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00];
pub(crate) const LEF2_SIGNATURE: [u8; 8] = [0x4c, 0x45, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileHeader {
    pub(crate) major_version: u8,
    pub(crate) minor_version: u8,
    pub(crate) compression_method: CompressionMethod,
    pub(crate) segment_number: u32,
    pub(crate) set_identifier: [u8; 16],
    pub(crate) logical: bool,
}

impl FileHeader {
    pub(crate) fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < FILE_HEADER_SIZE {
            return Err(EwfError::BufferTooShort {
                needed: FILE_HEADER_SIZE,
                actual: buf.len(),
            });
        }

        let logical = if buf[0..8] == EX01_SIGNATURE {
            false
        } else if buf[0..8] == LEF2_SIGNATURE {
            true
        } else {
            return Err(EwfError::InvalidSignature);
        };

        let mut set_identifier = [0; 16];
        set_identifier.copy_from_slice(&buf[16..32]);

        Ok(Self {
            major_version: buf[8],
            minor_version: buf[9],
            compression_method: CompressionMethod::from(u16::from_le_bytes([buf[10], buf[11]])),
            segment_number: u32::from_le_bytes(
                buf[12..16].try_into().expect("slice length checked"),
            ),
            set_identifier,
            logical,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SectionType {
    DeviceInformation,
    CaseData,
    SectorData,
    SectorTable,
    ErrorTable,
    SessionTable,
    IncrementData,
    Md5Hash,
    Sha1Hash,
    RestartData,
    EncryptionKeys,
    MemoryExtentsTable,
    Next,
    FinalInformation,
    Done,
    AnalyticalData,
    SingleFilesData,
    SingleFilesTable,
    SingleFilesMd5HashTable,
    SingleFilesUnknownTable,
    Unknown(u32),
}

impl From<u32> for SectionType {
    fn from(value: u32) -> Self {
        match value {
            0x01 => Self::DeviceInformation,
            0x02 => Self::CaseData,
            0x03 => Self::SectorData,
            0x04 => Self::SectorTable,
            0x05 => Self::ErrorTable,
            0x06 => Self::SessionTable,
            0x07 => Self::IncrementData,
            0x08 => Self::Md5Hash,
            0x09 => Self::Sha1Hash,
            0x0a => Self::RestartData,
            0x0b => Self::EncryptionKeys,
            0x0c => Self::MemoryExtentsTable,
            0x0d => Self::Next,
            0x0e => Self::FinalInformation,
            0x0f => Self::Done,
            0x10 => Self::AnalyticalData,
            0x20 => Self::SingleFilesData,
            0x21 => Self::SingleFilesTable,
            0x22 => Self::SingleFilesMd5HashTable,
            0x23 => Self::SingleFilesUnknownTable,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompressionMethod {
    None,
    Zlib,
    Bzip2,
    Unknown(u16),
}

impl From<u16> for CompressionMethod {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Zlib,
            2 => Self::Bzip2,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChunkKind {
    Raw,
    Compressed(CompressionMethod),
    PatternFill,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SectionDescriptor {
    pub(crate) section_type: SectionType,
    pub(crate) data_flags: u32,
    pub(crate) previous_offset: u64,
    pub(crate) data_size: u64,
    pub(crate) descriptor_size: u32,
    pub(crate) padding_size: u32,
    pub(crate) data_integrity_hash: [u8; 16],
    pub(crate) offset: u64,
    pub(crate) has_integrity_hash: bool,
    pub(crate) encrypted: bool,
}

impl SectionDescriptor {
    pub(crate) fn parse(buf: &[u8], offset: u64) -> Result<Self> {
        if buf.len() < SECTION_DESCRIPTOR_SIZE {
            return Err(EwfError::BufferTooShort {
                needed: SECTION_DESCRIPTOR_SIZE,
                actual: buf.len(),
            });
        }

        let data_flags = u32::from_le_bytes(buf[4..8].try_into().expect("slice length checked"));
        let mut data_integrity_hash = [0; 16];
        data_integrity_hash.copy_from_slice(&buf[32..48]);
        Ok(Self {
            section_type: SectionType::from(u32::from_le_bytes(
                buf[0..4].try_into().expect("slice length checked"),
            )),
            data_flags,
            previous_offset: u64::from_le_bytes(
                buf[8..16].try_into().expect("slice length checked"),
            ),
            data_size: u64::from_le_bytes(buf[16..24].try_into().expect("slice length checked")),
            descriptor_size: u32::from_le_bytes(
                buf[24..28].try_into().expect("slice length checked"),
            ),
            padding_size: u32::from_le_bytes(buf[28..32].try_into().expect("slice length checked")),
            data_integrity_hash,
            offset,
            has_integrity_hash: data_flags & DATA_FLAG_INTEGRITY_HASH != 0,
            encrypted: data_flags & DATA_FLAG_ENCRYPTED != 0,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TableEntry {
    pub(crate) chunk_data_offset: u64,
    pub(crate) chunk_data_size: u32,
    pub(crate) flags: u32,
    pub(crate) kind: ChunkKind,
}

impl TableEntry {
    pub(crate) fn parse(buf: &[u8], compression_method: CompressionMethod) -> Result<Self> {
        if buf.len() < TABLE_ENTRY_SIZE {
            return Err(EwfError::BufferTooShort {
                needed: TABLE_ENTRY_SIZE,
                actual: buf.len(),
            });
        }

        let flags = u32::from_le_bytes(buf[12..16].try_into().expect("slice length checked"));
        let kind = if flags & CHUNK_FLAG_PATTERN_FILL != 0 && flags & CHUNK_FLAG_COMPRESSED != 0 {
            ChunkKind::PatternFill
        } else if flags & CHUNK_FLAG_COMPRESSED != 0 {
            ChunkKind::Compressed(compression_method)
        } else {
            ChunkKind::Raw
        };

        Ok(Self {
            chunk_data_offset: u64::from_le_bytes(
                buf[0..8].try_into().expect("slice length checked"),
            ),
            chunk_data_size: u32::from_le_bytes(
                buf[8..12].try_into().expect("slice length checked"),
            ),
            flags,
            kind,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TableHeader {
    pub(crate) first_chunk: u64,
    pub(crate) entry_count: u32,
}

impl TableHeader {
    pub(crate) fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < TABLE_HEADER_SIZE {
            return Err(EwfError::BufferTooShort {
                needed: TABLE_HEADER_SIZE,
                actual: buf.len(),
            });
        }

        Ok(Self {
            first_chunk: u64::from_le_bytes(buf[0..8].try_into().expect("slice length checked")),
            entry_count: u32::from_le_bytes(buf[8..12].try_into().expect("slice length checked")),
        })
    }
}

pub(crate) const DATA_FLAG_INTEGRITY_HASH: u32 = 0x0000_0001;
pub(crate) const DATA_FLAG_ENCRYPTED: u32 = 0x0000_0002;
pub(crate) const CHUNK_FLAG_COMPRESSED: u32 = 0x0000_0001;
pub(crate) const CHUNK_FLAG_HAS_CHECKSUM: u32 = 0x0000_0002;
pub(crate) const CHUNK_FLAG_PATTERN_FILL: u32 = 0x0000_0004;

pub(crate) const FILE_HEADER_SIZE: usize = 32;
pub(crate) const SECTION_DESCRIPTOR_SIZE: usize = 64;
pub(crate) const TABLE_HEADER_SIZE: usize = 20;
pub(crate) const TABLE_ENTRY_SIZE: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;

    fn file_header(signature: [u8; 8], segment_number: u32) -> [u8; FILE_HEADER_SIZE] {
        let mut buf = [0; FILE_HEADER_SIZE];
        buf[0..8].copy_from_slice(&signature);
        buf[8] = 2;
        buf[9] = 1;
        buf[10..12].copy_from_slice(&1_u16.to_le_bytes());
        buf[12..16].copy_from_slice(&segment_number.to_le_bytes());
        buf[16..32].copy_from_slice(&[0xab; 16]);
        buf
    }

    #[test]
    fn parses_ex01_file_header() {
        let header = FileHeader::parse(&file_header(EX01_SIGNATURE, 2)).unwrap();

        assert_eq!(header.major_version, 2);
        assert_eq!(header.minor_version, 1);
        assert_eq!(header.compression_method, CompressionMethod::Zlib);
        assert_eq!(header.segment_number, 2);
        assert_eq!(header.set_identifier, [0xab; 16]);
        assert!(!header.logical);
    }

    #[test]
    fn parses_lx01_file_header_as_logical() {
        let header = FileHeader::parse(&file_header(LEF2_SIGNATURE, 1)).unwrap();

        assert!(header.logical);
    }

    #[test]
    fn parses_32_bit_segment_number() {
        let header = FileHeader::parse(&file_header(EX01_SIGNATURE, 70_000)).unwrap();

        assert_eq!(header.segment_number, 70_000);
    }

    #[test]
    fn parses_section_descriptor() {
        let mut buf = [0; SECTION_DESCRIPTOR_SIZE];
        buf[0..4].copy_from_slice(&0x03_u32.to_le_bytes());
        buf[4..8].copy_from_slice(&DATA_FLAG_ENCRYPTED.to_le_bytes());
        buf[8..16].copy_from_slice(&100_u64.to_le_bytes());
        buf[16..24].copy_from_slice(&4096_u64.to_le_bytes());
        buf[24..28].copy_from_slice(&(SECTION_DESCRIPTOR_SIZE as u32).to_le_bytes());
        buf[28..32].copy_from_slice(&16_u32.to_le_bytes());
        buf[32..48].copy_from_slice(&[0x5a; 16]);

        let desc = SectionDescriptor::parse(&buf, FILE_HEADER_SIZE as u64).unwrap();

        assert_eq!(desc.section_type, SectionType::SectorData);
        assert_eq!(desc.data_flags, DATA_FLAG_ENCRYPTED);
        assert_eq!(desc.previous_offset, 100);
        assert_eq!(desc.data_size, 4096);
        assert_eq!(desc.descriptor_size, SECTION_DESCRIPTOR_SIZE as u32);
        assert_eq!(desc.padding_size, 16);
        assert_eq!(desc.data_integrity_hash, [0x5a; 16]);
        assert_eq!(desc.offset, FILE_HEADER_SIZE as u64);
        assert!(!desc.has_integrity_hash);
        assert!(desc.encrypted);
    }

    #[test]
    fn parses_table_header() {
        let mut buf = [0; TABLE_HEADER_SIZE];
        buf[0..8].copy_from_slice(&128_u64.to_le_bytes());
        buf[8..12].copy_from_slice(&64_u32.to_le_bytes());

        let header = TableHeader::parse(&buf).unwrap();

        assert_eq!(header.first_chunk, 128);
        assert_eq!(header.entry_count, 64);
    }

    #[test]
    fn parses_table_entry_compressed_bzip2() {
        let mut buf = [0; TABLE_ENTRY_SIZE];
        buf[0..8].copy_from_slice(&1234_u64.to_le_bytes());
        buf[8..12].copy_from_slice(&2048_u32.to_le_bytes());
        buf[12..16].copy_from_slice(&CHUNK_FLAG_COMPRESSED.to_le_bytes());

        let entry = TableEntry::parse(&buf, CompressionMethod::Bzip2).unwrap();

        assert_eq!(entry.chunk_data_offset, 1234);
        assert_eq!(entry.chunk_data_size, 2048);
        assert_eq!(entry.flags, CHUNK_FLAG_COMPRESSED);
        assert_eq!(entry.kind, ChunkKind::Compressed(CompressionMethod::Bzip2));
    }

    #[test]
    fn parses_table_entry_pattern_fill() {
        let mut buf = [0; TABLE_ENTRY_SIZE];
        buf[12..16]
            .copy_from_slice(&(CHUNK_FLAG_COMPRESSED | CHUNK_FLAG_PATTERN_FILL).to_le_bytes());

        let entry = TableEntry::parse(&buf, CompressionMethod::Zlib).unwrap();

        assert_eq!(entry.kind, ChunkKind::PatternFill);
    }

    #[test]
    fn maps_section_and_compression_unknowns_losslessly() {
        assert_eq!(SectionType::from(0x0a), SectionType::RestartData);
        assert_eq!(SectionType::from(0x20), SectionType::SingleFilesData);
        assert_eq!(SectionType::from(0x21), SectionType::SingleFilesTable);
        assert_eq!(
            SectionType::from(0x22),
            SectionType::SingleFilesMd5HashTable
        );
        assert_eq!(
            SectionType::from(0x23),
            SectionType::SingleFilesUnknownTable
        );
        assert_eq!(SectionType::from(999), SectionType::Unknown(999));
        assert_eq!(
            CompressionMethod::from(777),
            CompressionMethod::Unknown(777)
        );
    }
}

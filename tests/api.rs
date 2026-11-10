// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) 2026 Elijah Brigham
//
// This file is changed from ebrig/ewf-image (https://github.com/ebrig/ewf-image), whose code is
// under the Apache License 2.0 (LICENSE-APACHE).
//
// SPDX-License-Identifier: (RPL-1.5 OR AGPL-3.0-only) AND Apache-2.0
//
// You may instead use this file under the GNU Affero General Public License, version 3 only
// (LICENSE-AGPL-3.0). The notice below is for the RPL.
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

//! Public API regression tests.

use std::collections::BTreeMap;

use ewf_image::{
    ChunkCacheCapacity, CompressionFlags, CompressionLevel, CompressionMethod, CompressionValues,
    DataChunk, DataChunkEncoding, EncodedDataChunk, EncryptionMethod, EwfError, EwfMetadata,
    EwfPassword, EwfWriter, Format, FormatProfile, HeaderCodepage, HeaderDateFormat, ImageInfo,
    MediaFlags, MediaInfo, MediaType, MemoryExtent, OpenOptions, OpenStrictness, ReaderCacheInfo,
    ReaderStatistics, SectorRange, SegmentFileVersion, SingleFileEntry, SingleFileEntryType,
    SingleFileSource, StoredHashes, WriteOptions,
};

fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for &byte in data {
        a = (a + u32::from(byte)) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    (b << 16) | a
}

#[test]
fn public_crate_name_is_ewf_image() {
    let _ = ewf_image::OpenOptions::default();
}

#[test]
fn password_debug_is_redacted() {
    let password = EwfPassword::utf8("ewf-image-secret-sentinel");
    let rendered = format!("{password:?}");

    assert_eq!(rendered, "EwfPassword([REDACTED])");
    assert!(!rendered.contains("secret-sentinel"));
}

#[test]
fn password_accepts_owned_raw_bytes() {
    let password = EwfPassword::from_bytes(vec![0xff, 0x00, 0x80]);

    assert_eq!(format!("{password:?}"), "EwfPassword([REDACTED])");
}

#[test]
fn encryption_methods_are_stable_public_values() {
    assert_ne!(
        EncryptionMethod::XWaysAes128Ctr,
        EncryptionMethod::XWaysAes256Ctr
    );
}

#[test]
fn password_errors_do_not_require_secret_context() {
    assert_eq!(
        EwfError::PasswordRequired.to_string(),
        "password required for encrypted EWF image"
    );
    assert_eq!(
        EwfError::PasswordRejected.to_string(),
        "password rejected for encrypted EWF image"
    );
    assert_eq!(
        EwfError::DecryptionValidationFailed.to_string(),
        "decrypted EWF data failed validation"
    );
}

#[test]
fn open_options_default_is_lenient_with_bounded_cache() {
    let options = OpenOptions::default();

    assert_eq!(options.strictness(), OpenStrictness::Lenient);
    assert_eq!(
        options.chunk_cache_capacity(),
        ChunkCacheCapacity::Chunks(64)
    );
    assert_eq!(options.table_entry_cache_size_bytes(), 4 * 1024 * 1024);
    assert!(!options.reader_statistics_enabled());
    assert!(!options.read_zero_chunk_on_error());
    assert_eq!(options.header_codepage(), HeaderCodepage::Ascii);
    assert_eq!(options.header_values_date_format(), HeaderDateFormat::Ctime);
    assert_eq!(options.maximum_open_handles(), None);
}

#[test]
fn open_options_builders_configure_reader_controls() {
    let options = OpenOptions::default()
        .with_strictness(OpenStrictness::Strict)
        .with_chunk_cache_size_bytes(8 * 1024 * 1024)
        .with_table_entry_cache_size_bytes(2 * 1024 * 1024)
        .with_reader_statistics(true)
        .with_read_zero_chunk_on_error(true)
        .with_header_codepage(HeaderCodepage::Windows1252)
        .with_header_values_date_format(HeaderDateFormat::Iso8601)
        .with_maximum_open_handles(Some(8));

    assert_eq!(options.strictness(), OpenStrictness::Strict);
    assert_eq!(
        options.chunk_cache_capacity(),
        ChunkCacheCapacity::Bytes(8 * 1024 * 1024)
    );
    assert_eq!(options.table_entry_cache_size_bytes(), 2 * 1024 * 1024);
    assert!(options.reader_statistics_enabled());
    assert!(options.read_zero_chunk_on_error());
    assert_eq!(options.header_codepage(), HeaderCodepage::Windows1252);
    assert_eq!(
        options.header_values_date_format(),
        HeaderDateFormat::Iso8601
    );
    assert_eq!(options.maximum_open_handles(), Some(8));
}

#[test]
fn open_options_chunk_count_builder_replaces_byte_capacity() {
    let options = OpenOptions::default()
        .with_chunk_cache_size_bytes(1024 * 1024)
        .with_chunk_cache_size(12);

    assert_eq!(
        options.chunk_cache_capacity(),
        ChunkCacheCapacity::Chunks(12)
    );
}

#[test]
fn reader_diagnostic_snapshots_have_future_proof_getters() {
    let statistics = ReaderStatistics::default();
    let cache = ReaderCacheInfo::default();

    assert_eq!(statistics.chunk_cache_hits(), 0);
    assert_eq!(statistics.chunk_cache_misses(), 0);
    assert_eq!(statistics.chunk_cache_coalesced(), 0);
    assert_eq!(statistics.table_page_cache_hits(), 0);
    assert_eq!(statistics.table_page_cache_misses(), 0);
    assert_eq!(statistics.segment_read_bytes(), 0);
    assert_eq!(statistics.segment_read_nanos(), 0);
    assert_eq!(statistics.segment_pool_wait_nanos(), 0);
    assert_eq!(statistics.encoded_bytes_read(), 0);
    assert_eq!(statistics.decoded_bytes(), 0);
    assert_eq!(statistics.saturating_delta(statistics), statistics);
    assert_eq!(cache.chunk_cache_capacity_bytes(), 0);
    assert_eq!(cache.table_entry_cache_capacity_bytes(), 0);
    assert_eq!(cache.table_entry_cache_current_bytes(), 0);
    assert_eq!(cache.table_entry_cache_peak_bytes(), 0);
}

#[test]
fn writer_exposes_resume_constructor() {
    fn accepts_resume_constructor(_: fn(std::path::PathBuf) -> ewf_image::Result<EwfWriter>) {}

    accepts_resume_constructor(EwfWriter::resume::<std::path::PathBuf>);
}

#[test]
fn header_codepage_and_date_format_match_reference_values() {
    assert_eq!(HeaderCodepage::Ascii.as_i32(), 20_127);
    assert_eq!(HeaderCodepage::Windows1252.as_i32(), 1252);
    assert_eq!(
        HeaderCodepage::from_i32(1252),
        Some(HeaderCodepage::Windows1252)
    );
    assert_eq!(HeaderCodepage::from_i32(12_345), None);

    assert_eq!(HeaderDateFormat::DayMonth.as_i32(), 1);
    assert_eq!(HeaderDateFormat::MonthDay.as_i32(), 2);
    assert_eq!(HeaderDateFormat::Iso8601.as_i32(), 3);
    assert_eq!(HeaderDateFormat::Ctime.as_i32(), 4);
    assert_eq!(
        HeaderDateFormat::from_i32(3),
        Some(HeaderDateFormat::Iso8601)
    );
    assert_eq!(HeaderDateFormat::from_i32(99), None);

    let write_options = WriteOptions::default();
    assert_eq!(write_options.header_codepage, HeaderCodepage::Ascii);
    assert_eq!(
        write_options.header_values_date_format,
        HeaderDateFormat::Ctime
    );
}

#[test]
fn metadata_and_hashes_default_to_empty_values() {
    let metadata = EwfMetadata::default();
    let hashes = StoredHashes::default();
    let media = MediaInfo::default();

    assert!(metadata.case_number.is_none());
    assert!(metadata.evidence_number.is_none());
    assert!(metadata.examiner.is_none());
    assert!(metadata.password.is_none());
    assert!(metadata.header_values.is_empty());
    assert!(hashes.md5.is_none());
    assert!(hashes.sha1.is_none());
    assert!(hashes.hash_values.is_empty());
    assert!(media.sectors_per_chunk.is_none());
    assert!(media.bytes_per_sector.is_none());
    assert!(media.sector_count.is_none());
    assert!(media.chunk_count.is_none());
    assert!(media.error_granularity.is_none());
    assert!(media.set_identifier.is_none());
    assert!(media.ewf2_segment_file_version.is_none());
    assert!(media.compression_method.is_none());
    assert_eq!(media.compression_values, CompressionValues::default());
    assert!(media.media_type.is_none());
    assert_eq!(media.media_flags, MediaFlags::default());
}

#[test]
fn compression_values_match_reference_codes_and_flags() {
    assert_eq!(CompressionLevel::Default.as_i8(), -1);
    assert_eq!(CompressionLevel::None.as_i8(), 0);
    assert_eq!(CompressionLevel::Fast.as_i8(), 1);
    assert_eq!(CompressionLevel::Best.as_i8(), 2);
    assert_eq!(CompressionLevel::Unknown(7).as_i8(), 7);
    assert_eq!(CompressionLevel::from_i8(-1), CompressionLevel::Default);
    assert_eq!(CompressionLevel::from_i8(0), CompressionLevel::None);
    assert_eq!(CompressionLevel::from_i8(1), CompressionLevel::Fast);
    assert_eq!(CompressionLevel::from_i8(2), CompressionLevel::Best);
    assert_eq!(CompressionLevel::from_i8(7), CompressionLevel::Unknown(7));

    let flags = CompressionFlags::from_bits(0x93);
    assert!(flags.empty_block);
    assert!(flags.pattern_fill);
    assert_eq!(flags.unknown_bits, 0x82);
    assert_eq!(flags.bits(), 0x93);
}

#[test]
fn data_chunks_expose_compatibility_style_buffer_helpers() {
    let decoded = DataChunk {
        chunk_index: 2,
        logical_offset: 12,
        logical_size: 6,
        encoded_size: 10,
        encoding: DataChunkEncoding::Raw,
        corrupted: true,
        data: b"abcdef".to_vec(),
    };

    assert!(decoded.is_corrupted());
    let mut decoded_buffer = [0; 4];
    assert_eq!(decoded.read_buffer(&mut decoded_buffer).unwrap(), 4);
    assert_eq!(&decoded_buffer, b"abcd");

    let mut encoded_data = b"abcdef".to_vec();
    encoded_data.extend_from_slice(&adler32(b"abcdef").to_le_bytes());
    let encoded = EncodedDataChunk {
        chunk_index: 2,
        logical_offset: 12,
        logical_size: 6,
        encoded_size: encoded_data.len() as u64,
        encoding: DataChunkEncoding::Raw,
        has_checksum: true,
        data: encoded_data,
    };

    let mut encoded_buffer = [0; 8];
    assert_eq!(encoded.read_buffer(&mut encoded_buffer).unwrap(), 6);
    assert_eq!(&encoded_buffer[..6], b"abcdef");

    let mut corrupted = encoded;
    corrupted.data[6] ^= 0xff;
    assert!(corrupted.read_buffer(&mut encoded_buffer).is_err());
}

#[test]
fn data_chunk_write_buffer_replaces_payload_for_writer_use() {
    let mut chunk = DataChunk {
        chunk_index: 7,
        logical_offset: 14,
        logical_size: 4,
        encoded_size: 9,
        encoding: DataChunkEncoding::Zlib,
        corrupted: true,
        data: b"old!".to_vec(),
    };

    assert_eq!(chunk.write_buffer(b"replacement").unwrap(), 11);

    assert_eq!(chunk.chunk_index, 7);
    assert_eq!(chunk.logical_offset, 14);
    assert_eq!(chunk.logical_size, 11);
    assert_eq!(chunk.encoded_size, 11);
    assert_eq!(chunk.encoding, DataChunkEncoding::Raw);
    assert!(!chunk.is_corrupted());
    assert_eq!(chunk.data, b"replacement");

    let mut buffer = [0; 16];
    assert_eq!(chunk.read_buffer(&mut buffer).unwrap(), 11);
    assert_eq!(&buffer[..11], b"replacement");
}

#[test]
fn metadata_exposes_typed_and_generic_header_values() {
    let mut header_values = BTreeMap::new();
    header_values.insert("case_number".to_string(), "generic-case".to_string());
    header_values.insert("model".to_string(), "Model X".to_string());
    header_values.insert("custom_field".to_string(), "custom value".to_string());
    let metadata = EwfMetadata {
        case_number: Some("typed-case".to_string()),
        examiner: Some("Examiner".to_string()),
        acquisition_software: Some("ewfacquire".to_string()),
        acquisition_software_version: Some("20260627".to_string()),
        header_values,
        ..EwfMetadata::default()
    };

    assert_eq!(metadata.header_value("case_number"), Some("typed-case"));
    assert_eq!(metadata.header_value("examiner_name"), Some("Examiner"));
    assert_eq!(
        metadata.header_value("acquiry_software"),
        Some("ewfacquire")
    );
    assert_eq!(
        metadata.header_value("acquiry_software_version"),
        Some("20260627")
    );
    assert_eq!(metadata.header_value("model"), Some("Model X"));
    assert_eq!(metadata.header_value("custom_field"), Some("custom value"));
    assert_eq!(metadata.header_value("missing"), None);

    assert_eq!(metadata.number_of_header_values(), 6);
    assert_eq!(metadata.header_value_identifier(0), Some("case_number"));
    assert_eq!(metadata.header_value_identifier(1), Some("examiner_name"));
    assert_eq!(
        metadata.header_value_identifier(2),
        Some("acquiry_software")
    );
    assert_eq!(
        metadata.header_value_identifier(3),
        Some("acquiry_software_version")
    );
    assert_eq!(metadata.header_value_identifier(4), Some("model"));
    assert_eq!(metadata.header_value_identifier(5), Some("custom_field"));
    assert_eq!(metadata.header_value_identifier(6), None);
}

#[test]
fn metadata_sets_compatibility_style_header_values() {
    let mut metadata = EwfMetadata::default();

    assert_eq!(metadata.set_header_value("case_number", "CASE-1"), None);
    assert_eq!(metadata.case_number.as_deref(), Some("CASE-1"));
    assert_eq!(metadata.header_value("case_number"), Some("CASE-1"));
    assert!(!metadata.header_values.contains_key("case_number"));

    assert_eq!(
        metadata.set_header_value("case_number", "CASE-2"),
        Some("CASE-1".to_string())
    );
    assert_eq!(metadata.case_number.as_deref(), Some("CASE-2"));

    assert_eq!(metadata.set_header_value("model", "Model X"), None);
    assert_eq!(metadata.header_value("model"), Some("Model X"));
    assert_eq!(
        metadata.header_values.get("model").map(String::as_str),
        Some("Model X")
    );
    assert_eq!(
        metadata.set_header_value("model", "Model Y"),
        Some("Model X".to_string())
    );
    assert_eq!(metadata.header_value("model"), Some("Model Y"));

    assert_eq!(
        metadata.set_header_value("acquiry_software", "ewfacquire"),
        None
    );
    assert_eq!(
        metadata.set_header_value("acquiry_software_version", "20260627"),
        None
    );
    assert_eq!(
        metadata.header_value("acquiry_software"),
        Some("ewfacquire")
    );
    assert_eq!(
        metadata.header_value("acquiry_software_version"),
        Some("20260627")
    );
    assert_eq!(metadata.acquisition_software.as_deref(), Some("ewfacquire"));
    assert_eq!(
        metadata.acquisition_software_version.as_deref(),
        Some("20260627")
    );
}

#[test]
fn metadata_set_header_value_removes_stale_generic_standard_values() {
    let mut header_values = BTreeMap::new();
    header_values.insert("case_number".to_string(), "generic-case".to_string());
    let mut metadata = EwfMetadata {
        header_values,
        ..EwfMetadata::default()
    };

    assert_eq!(metadata.header_value("case_number"), Some("generic-case"));
    assert_eq!(
        metadata.set_header_value("case_number", "typed-case"),
        Some("generic-case".to_string())
    );
    assert_eq!(metadata.header_value("case_number"), Some("typed-case"));
    assert_eq!(metadata.case_number.as_deref(), Some("typed-case"));
    assert!(!metadata.header_values.contains_key("case_number"));
}

#[test]
fn stored_hashes_expose_compatibility_style_hash_values() {
    let mut hashes = StoredHashes::default();

    assert_eq!(hashes.number_of_hash_values(), 0);
    assert_eq!(hashes.hash_value_identifier(0), None);
    assert_eq!(hashes.hash_value("MD5"), None);

    assert_eq!(hashes.set_hash_value("SHA1", "sha1-value"), None);
    assert_eq!(hashes.set_hash_value("MD5", "md5-value"), None);
    assert_eq!(
        hashes.set_hash_value("SHA1", "sha1-replacement"),
        Some("sha1-value".to_string())
    );

    assert_eq!(hashes.number_of_hash_values(), 2);
    assert_eq!(hashes.hash_value_identifier(0), Some("MD5"));
    assert_eq!(hashes.hash_value_identifier(1), Some("SHA1"));
    assert_eq!(hashes.hash_value_identifier(2), None);
    assert_eq!(hashes.hash_value("MD5"), Some("md5-value"));
    assert_eq!(hashes.hash_value("SHA1"), Some("sha1-replacement"));
    assert_eq!(hashes.hash_value("SHA256"), None);
}

#[test]
fn stored_hashes_set_typed_hashes_from_hex_values() {
    let mut hashes = StoredHashes::default();
    let md5 = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let sha1 = [
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23,
        0x01, 0xaa, 0xbb, 0xcc, 0xdd,
    ];

    hashes.set_hash_value("MD5", "0123456789abcdeffedcba9876543210");
    hashes.set_hash_value("SHA1", "1032547698badcfeefcdab8967452301aabbccdd");
    hashes.set_hash_value("SHA256", "not parsed into typed fields");

    assert_eq!(hashes.md5, Some(md5));
    assert_eq!(hashes.sha1, Some(sha1));
    assert_eq!(
        hashes.hash_value("SHA1"),
        Some("1032547698badcfeefcdab8967452301aabbccdd")
    );
}

#[test]
fn single_file_objects_expose_compatibility_style_hash_values() {
    let entry = SingleFileEntry {
        md5: Some("entry-md5".to_string()),
        sha1: Some("entry-sha1".to_string()),
        ..SingleFileEntry::default()
    };
    let source = SingleFileSource {
        md5: Some("source-md5".to_string()),
        sha1: Some("source-sha1".to_string()),
        ..SingleFileSource::default()
    };

    assert_eq!(entry.md5_hash(), Some("entry-md5"));
    assert_eq!(entry.sha1_hash(), Some("entry-sha1"));
    assert_eq!(source.md5_hash(), Some("source-md5"));
    assert_eq!(source.sha1_hash(), Some("source-sha1"));
}

#[test]
fn single_file_source_exposes_compatibility_style_metadata_getters() {
    let source = SingleFileSource {
        identifier: Some(7),
        name: Some("Disk 7".to_string()),
        evidence_number: Some("EV-7".to_string()),
        location: Some("Lab".to_string()),
        device_guid: Some("device-guid".to_string()),
        primary_device_guid: Some("primary-guid".to_string()),
        manufacturer: Some("Acme".to_string()),
        model: Some("Model X".to_string()),
        serial_number: Some("SN123".to_string()),
        domain: Some("DOMAIN".to_string()),
        ip_address: Some("192.0.2.1".to_string()),
        mac_address: Some("001122aabbcc".to_string()),
        size: Some(4096),
        drive_type: Some('f'),
        logical_offset: Some(512),
        physical_offset: Some(1024),
        acquisition_time: Some(1_700_000_000),
        ..SingleFileSource::default()
    };

    assert_eq!(source.identifier(), Some(7));
    assert_eq!(source.name(), Some("Disk 7"));
    assert_eq!(source.evidence_number(), Some("EV-7"));
    assert_eq!(source.location(), Some("Lab"));
    assert_eq!(source.device_guid(), Some("device-guid"));
    assert_eq!(source.primary_device_guid(), Some("primary-guid"));
    assert_eq!(source.manufacturer(), Some("Acme"));
    assert_eq!(source.model(), Some("Model X"));
    assert_eq!(source.serial_number(), Some("SN123"));
    assert_eq!(source.domain(), Some("DOMAIN"));
    assert_eq!(source.ip_address(), Some("192.0.2.1"));
    assert_eq!(source.mac_address(), Some("001122aabbcc"));
    assert_eq!(source.size(), Some(4096));
    assert_eq!(source.drive_type(), Some('f'));
    assert_eq!(source.logical_offset(), Some(512));
    assert_eq!(source.physical_offset(), Some(1024));
    assert_eq!(source.acquisition_time(), Some(1_700_000_000));
}

#[test]
fn single_file_attributes_and_permissions_expose_compatibility_style_getters() {
    let attribute = ewf_image::SingleFileAttribute {
        name: Some("Zone.Identifier".to_string()),
        value: Some("ZoneId=3".to_string()),
    };
    let permission = ewf_image::SingleFilePermission {
        name: Some("Administrators".to_string()),
        identifier: Some("S-1-5-32-544".to_string()),
        property_type: Some(10),
        access_mask: Some(0x0012_0089),
        ace_flags: Some(3),
    };
    let group = ewf_image::SingleFilePermissionGroup {
        name: Some("Admins".to_string()),
        identifier: Some("S-1-5-32-544".to_string()),
        property_type: Some(10),
        access_mask: Some(0x001f_01ff),
        ace_flags: Some(2),
        permissions: vec![permission.clone()],
    };

    assert_eq!(attribute.name(), Some("Zone.Identifier"));
    assert_eq!(attribute.value(), Some("ZoneId=3"));
    assert_eq!(permission.name(), Some("Administrators"));
    assert_eq!(permission.identifier(), Some("S-1-5-32-544"));
    assert_eq!(permission.property_type(), Some(10));
    assert_eq!(permission.access_mask(), Some(0x0012_0089));
    assert_eq!(permission.flags(), Some(3));
    assert_eq!(group.name(), Some("Admins"));
    assert_eq!(group.identifier(), Some("S-1-5-32-544"));
    assert_eq!(group.property_type(), Some(10));
    assert_eq!(group.access_mask(), Some(0x001f_01ff));
    assert_eq!(group.flags(), Some(2));
    assert_eq!(group.number_of_entries(), 1);
    assert_eq!(group.entry_by_index(0), Some(&permission));
    assert!(group.entry_by_index(-1).is_none());
    assert!(group.entry_by_index(1).is_none());
}

#[test]
fn single_files_info_exposes_compatibility_style_catalog_indexes() {
    let info = ewf_image::SingleFilesInfo {
        sources: vec![
            ewf_image::SingleFileSource {
                identifier: Some(10),
                name: Some("first source".to_string()),
                ..ewf_image::SingleFileSource::default()
            },
            ewf_image::SingleFileSource {
                identifier: Some(20),
                name: Some("second source".to_string()),
                ..ewf_image::SingleFileSource::default()
            },
        ],
        permission_groups: vec![
            ewf_image::SingleFilePermissionGroup {
                name: Some("owner".to_string()),
                ..ewf_image::SingleFilePermissionGroup::default()
            },
            ewf_image::SingleFilePermissionGroup {
                name: Some("admins".to_string()),
                ..ewf_image::SingleFilePermissionGroup::default()
            },
        ],
        ..ewf_image::SingleFilesInfo::default()
    };

    assert_eq!(info.number_of_permission_groups(), 2);
    assert_eq!(
        info.permission_group_by_index(0)
            .and_then(|group| group.name.as_deref()),
        Some("owner")
    );
    assert_eq!(
        info.permission_group_by_index(1)
            .and_then(|group| group.name.as_deref()),
        Some("admins")
    );
    assert!(info.permission_group_by_index(-1).is_none());
    assert!(info.permission_group_by_index(2).is_none());

    assert_eq!(
        info.source_by_index(0).and_then(|source| source.name()),
        Some("first source")
    );
    assert_eq!(
        info.source_by_index(1)
            .and_then(ewf_image::SingleFileSource::identifier),
        Some(20)
    );
    assert!(info.source_by_index(-1).is_none());
    assert!(info.source_by_index(2).is_none());
}

#[test]
fn single_files_info_counts_access_control_entries_for_file_entries() {
    let info = ewf_image::SingleFilesInfo {
        permission_groups: vec![ewf_image::SingleFilePermissionGroup {
            permissions: vec![
                ewf_image::SingleFilePermission {
                    name: Some("owner".to_string()),
                    ..ewf_image::SingleFilePermission::default()
                },
                ewf_image::SingleFilePermission {
                    name: Some("admins".to_string()),
                    ..ewf_image::SingleFilePermission::default()
                },
            ],
            ..ewf_image::SingleFilePermissionGroup::default()
        }],
        ..ewf_image::SingleFilesInfo::default()
    };
    let entry = ewf_image::SingleFileEntry {
        permission_group_index: Some(0),
        ..ewf_image::SingleFileEntry::default()
    };
    let missing_group_entry = ewf_image::SingleFileEntry {
        permission_group_index: Some(9),
        ..ewf_image::SingleFileEntry::default()
    };

    assert_eq!(info.number_of_access_control_entries_for_entry(&entry), 2);
    assert_eq!(
        info.access_control_entry_for_entry(&entry, 1)
            .and_then(|permission| permission.name()),
        Some("admins")
    );
    assert_eq!(entry.permission_group_index(), Some(0));
    assert_eq!(
        info.number_of_access_control_entries_for_entry(&missing_group_entry),
        0
    );
    assert_eq!(
        info.number_of_access_control_entries_for_entry(&ewf_image::SingleFileEntry::default()),
        0
    );
}

#[test]
fn single_file_entry_exposes_compatibility_style_metadata_getters() {
    let entry = SingleFileEntry {
        identifier: Some(42),
        file_entry_type: Some(SingleFileEntryType::File),
        flags: Some(0x12),
        name: Some("payload.bin".to_string()),
        short_name: Some("PAYLOA~1.BIN".to_string()),
        size: Some(1234),
        logical_offset: Some(4096),
        physical_offset: Some(6144),
        duplicate_data_offset: Some(8192),
        source_identifier: Some(7),
        subject_identifier: Some(3),
        permission_group_index: Some(1),
        record_type: Some(2),
        creation_time: Some(1_700_000_001),
        modification_time: Some(1_700_000_002),
        access_time: Some(1_700_000_003),
        entry_modification_time: Some(1_700_000_004),
        deletion_time: Some(1_700_000_005),
        ..SingleFileEntry::default()
    };

    assert_eq!(entry.identifier(), Some(42));
    assert_eq!(entry.entry_type(), Some(SingleFileEntryType::File));
    assert_eq!(entry.flags(), Some(0x12));
    assert_eq!(entry.media_data_offset(), Some(4096));
    assert_eq!(entry.media_data_size(), Some(1234));
    assert_eq!(entry.physical_offset(), Some(6144));
    assert_eq!(entry.duplicate_media_data_offset(), Some(8192));
    assert_eq!(entry.source_identifier(), Some(7));
    assert_eq!(entry.subject_identifier(), Some(3));
    assert_eq!(entry.permission_group_index(), Some(1));
    assert_eq!(entry.record_type(), Some(2));
    assert_eq!(entry.name(), Some("payload.bin"));
    assert_eq!(entry.short_name(), Some("PAYLOA~1.BIN"));
    assert_eq!(entry.size(), Some(1234));
    assert_eq!(entry.creation_time(), Some(1_700_000_001));
    assert_eq!(entry.modification_time(), Some(1_700_000_002));
    assert_eq!(entry.access_time(), Some(1_700_000_003));
    assert_eq!(entry.entry_modification_time(), Some(1_700_000_004));
    assert_eq!(entry.deletion_time(), Some(1_700_000_005));
}

#[test]
fn image_info_groups_public_metadata_and_media_info() {
    let info = ImageInfo {
        format: Format::Ewf1,
        format_profile: FormatProfile::Smart,
        segment_count: 1,
        segment_paths: vec!["case.E01".into()],
        chunk_size: 32_768,
        logical_size: 65_536,
        acquisition_complete: true,
        header_codepage: HeaderCodepage::Windows1252,
        header_values_date_format: HeaderDateFormat::Iso8601,
        media: MediaInfo {
            sectors_per_chunk: Some(64),
            bytes_per_sector: Some(512),
            sector_count: Some(128),
            chunk_count: Some(2),
            error_granularity: Some(64),
            set_identifier: Some([0xab; 16]),
            ewf2_segment_file_version: Some(SegmentFileVersion { major: 2, minor: 1 }),
            compression_method: Some(CompressionMethod::Zlib),
            compression_values: CompressionValues {
                level: CompressionLevel::Fast,
                ..CompressionValues::default()
            },
            media_type: Some(MediaType::Fixed),
            media_flags: MediaFlags {
                physical: true,
                fastbloc: true,
                tableau: false,
            },
        },
        metadata: EwfMetadata::default(),
        stored_hashes: StoredHashes::default(),
        acquisition_errors: Vec::new(),
        memory_extents: vec![MemoryExtent {
            start_page: 16,
            page_count: 4,
        }],
        single_files: None,
        ewf2_single_files_tables: ewf_image::SingleFilesAuxTables::default(),
        ewf2_increment_data: Vec::new(),
        ewf2_final_information: None,
        ewf2_restart_data: None,
        ewf2_analytical_data: None,
        sessions: vec![SectorRange {
            first_sector: 0,
            sector_count: 128,
        }],
        tracks: Vec::new(),
    };

    assert_eq!(info.format, Format::Ewf1);
    assert_eq!(info.format_profile, FormatProfile::Smart);
    assert_eq!(info.segment_count, 1);
    assert_eq!(
        info.segment_paths,
        vec![std::path::PathBuf::from("case.E01")]
    );
    assert_eq!(info.chunk_size, 32_768);
    assert_eq!(info.logical_size, 65_536);
    assert!(info.acquisition_complete);
    assert_eq!(info.header_codepage, HeaderCodepage::Windows1252);
    assert_eq!(info.header_values_date_format, HeaderDateFormat::Iso8601);
    assert_eq!(info.media.sectors_per_chunk, Some(64));
    assert_eq!(info.media.bytes_per_sector, Some(512));
    assert_eq!(info.media.sector_count, Some(128));
    assert_eq!(info.media.chunk_count, Some(2));
    assert_eq!(info.media.error_granularity, Some(64));
    assert_eq!(info.media.set_identifier, Some([0xab; 16]));
    assert_eq!(
        info.media.ewf2_segment_file_version,
        Some(SegmentFileVersion { major: 2, minor: 1 })
    );
    assert_eq!(info.media.compression_method, Some(CompressionMethod::Zlib));
    assert_eq!(
        info.media.compression_values,
        CompressionValues {
            level: CompressionLevel::Fast,
            ..CompressionValues::default()
        }
    );
    assert_eq!(info.media.media_type, Some(MediaType::Fixed));
    assert_eq!(
        info.media.media_flags,
        MediaFlags {
            physical: true,
            fastbloc: true,
            tableau: false,
        }
    );
    assert_eq!(info.acquisition_errors, []);
    assert_eq!(
        info.memory_extents,
        [MemoryExtent {
            start_page: 16,
            page_count: 4,
        }]
    );
    assert_eq!(
        info.sessions,
        [SectorRange {
            first_sector: 0,
            sector_count: 128,
        }]
    );
    assert_eq!(info.tracks, []);
}

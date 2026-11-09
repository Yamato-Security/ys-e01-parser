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

use crate::codepage::decode_header_bytes;
use crate::types::{
    AcquisitionError, EwfMetadata, FormatProfile, HeaderCodepage, MediaType, SectorRange,
    StoredHashes,
};
use crate::{EwfError, Result};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Ewf2Geometry {
    pub(crate) sectors_per_chunk: Option<u64>,
    pub(crate) bytes_per_sector: Option<u64>,
    pub(crate) sector_count: Option<u64>,
    pub(crate) chunk_count: Option<u64>,
    pub(crate) error_granularity: Option<u64>,
    pub(crate) chunk_size: Option<u64>,
    pub(crate) logical_size: Option<u64>,
    pub(crate) media_type: Option<MediaType>,
    pub(crate) physical: Option<bool>,
    pub(crate) fastbloc: bool,
    pub(crate) tableau: bool,
}

pub(crate) fn parse_header_text(text: &str, metadata: &mut EwfMetadata) {
    for_each_tabular_field(text, |name, value| {
        if value.is_empty() {
            return;
        }
        metadata
            .header_values
            .insert(ewf1_header_identifier(name).to_string(), value.to_string());
        match name {
            "c" => metadata.case_number = Some(value.to_string()),
            "n" => metadata.evidence_number = Some(value.to_string()),
            "a" => metadata.description = Some(value.to_string()),
            "e" => metadata.examiner = Some(value.to_string()),
            "t" => metadata.notes = Some(value.to_string()),
            "av" => metadata.acquisition_software_version = Some(value.to_string()),
            "ov" => metadata.os_version = Some(value.to_string()),
            "m" => metadata.acquisition_date = Some(value.to_string()),
            "u" => metadata.system_date = Some(value.to_string()),
            "p" => metadata.password = Some(value.to_string()),
            _ => {}
        }
    });
}

pub(crate) fn parse_header_data(
    raw: &[u8],
    header_codepage: HeaderCodepage,
    metadata: &mut EwfMetadata,
) {
    let text = decode_header_bytes(raw, header_codepage);
    parse_header_text(&text, metadata);
}

pub(crate) fn parse_header2_data(raw: &[u8], metadata: &mut EwfMetadata) {
    if let Some(text) = decode_utf16le(raw) {
        parse_header_text(&text, metadata);
    }
}

pub(crate) fn detect_ewf1_header_profile(
    text: &str,
    header_section_number: u8,
) -> Option<FormatProfile> {
    let has_carriage_return = text.contains('\r');
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<&str> = normalized.lines().collect();
    if lines.len() < 3 {
        return None;
    }

    let number_of_sections = lines[0];
    let types: Vec<&str> = lines[2].split('\t').collect();
    let values: Vec<&str> = lines.get(3).map_or("", |line| *line).split('\t').collect();
    let acquisition_software_version = types
        .iter()
        .position(|name| *name == "av")
        .and_then(|index| values.get(index))
        .and_then(|value| value.as_bytes().first().copied());

    // A single main section also appears in sparse, producer-neutral headers.
    // Keep the container hint unless a characteristic field layout identifies
    // the generation (including the EnCase 1 compression field below).
    let mut profile =
        (header_section_number == 1 && number_of_sections == "3").then_some(FormatProfile::Linen5);

    for (index, name) in types.iter().enumerate() {
        match (header_section_number, index, *name) {
            (1, 5, "av") => profile = Some(FormatProfile::Linen5),
            (2, 5, "av") if number_of_sections == "1" => profile = Some(FormatProfile::EnCase4),
            (2, 5, "av") if number_of_sections == "3" => profile = Some(FormatProfile::EnCase5),
            (1, 5, "md") => profile = Some(FormatProfile::Linen6),
            (2, 5, "md") => profile = Some(FormatProfile::EnCase6),
            (1, _, "l") => profile = Some(FormatProfile::Linen7),
            (2, _, "l") => profile = Some(FormatProfile::EnCase7),
            (1, 8, "r") => profile = Some(FormatProfile::EnCase1),
            (1, 10, "r") if has_carriage_return => {
                profile = match acquisition_software_version {
                    Some(b'2') => Some(FormatProfile::EnCase2),
                    Some(b'3') => Some(FormatProfile::EnCase3),
                    _ => profile,
                };
            }
            (1, 10, "r") => profile = Some(FormatProfile::FtkImager),
            _ => {}
        }
    }

    profile
}

pub(crate) fn detect_ewf1_header2_profile(raw: &[u8]) -> Option<FormatProfile> {
    decode_utf16le(raw).and_then(|text| detect_ewf1_header_profile(&text, 2))
}

pub(crate) fn parse_error2_data(data: &[u8]) -> Result<Vec<AcquisitionError>> {
    parse_error_table_data(data, 1, "error2")
}

pub(crate) fn parse_ewf2_error_table_data(data: &[u8]) -> Result<Vec<AcquisitionError>> {
    parse_error_table_data(data, 2, "error table")
}

fn parse_error_table_data(
    data: &[u8],
    format_version: u8,
    label: &str,
) -> Result<Vec<AcquisitionError>> {
    let (header_size, entry_size, footer_size, header_checksum_offset, header_checksum_size) =
        match format_version {
            1 => (520_usize, 8_usize, 4_usize, 516_usize, 516_usize),
            2 => (32_usize, 16_usize, 16_usize, 16_usize, 16_usize),
            _ => {
                return Err(EwfError::Malformed(
                    "unsupported error table format version".into(),
                ));
            }
        };
    if data.len() < header_size {
        return Err(EwfError::Malformed(format!("{label} section is too short")));
    }

    let stored_header_checksum = u32::from_le_bytes(
        data[header_checksum_offset..header_checksum_offset + 4]
            .try_into()
            .expect("slice length checked"),
    );
    let calculated_header_checksum = adler32(&data[..header_checksum_size]);
    if stored_header_checksum != calculated_header_checksum {
        return Err(EwfError::Malformed(format!(
            "{label} header checksum mismatch"
        )));
    }

    let entry_count = u32::from_le_bytes(data[0..4].try_into().expect("slice length checked"));
    if entry_count == 0 {
        return Ok(Vec::new());
    }
    let entry_count = usize::try_from(entry_count)
        .map_err(|_| EwfError::Malformed(format!("{label} entry count does not fit usize")))?;
    let entries_size = entry_count
        .checked_mul(entry_size)
        .ok_or_else(|| EwfError::Malformed(format!("{label} entries size overflow")))?;
    let entries_end = header_size
        .checked_add(entries_size)
        .ok_or_else(|| EwfError::Malformed(format!("{label} entries end overflow")))?;
    let required_size = entries_end
        .checked_add(footer_size)
        .ok_or_else(|| EwfError::Malformed(format!("{label} section size overflow")))?;
    if data.len() < required_size {
        return Err(EwfError::Malformed(format!(
            "{label} entries exceed section size"
        )));
    }

    let stored_entries_checksum = u32::from_le_bytes(
        data[entries_end..entries_end + 4]
            .try_into()
            .expect("slice length checked"),
    );
    let calculated_entries_checksum = adler32(&data[header_size..entries_end]);
    if stored_entries_checksum != calculated_entries_checksum {
        return Err(EwfError::Malformed(format!(
            "{label} entries checksum mismatch"
        )));
    }

    let mut errors = Vec::with_capacity(entry_count);
    for index in 0..entry_count {
        let offset = header_size + index * entry_size;
        let (first_sector, sector_count) = if format_version == 1 {
            (
                u64::from(u32::from_le_bytes(
                    data[offset..offset + 4]
                        .try_into()
                        .expect("slice length checked"),
                )),
                u64::from(u32::from_le_bytes(
                    data[offset + 4..offset + 8]
                        .try_into()
                        .expect("slice length checked"),
                )),
            )
        } else {
            (
                u64::from_le_bytes(
                    data[offset..offset + 8]
                        .try_into()
                        .expect("slice length checked"),
                ),
                u64::from(u32::from_le_bytes(
                    data[offset + 8..offset + 12]
                        .try_into()
                        .expect("slice length checked"),
                )),
            )
        };
        errors.push(AcquisitionError {
            first_sector,
            sector_count,
        });
    }

    Ok(errors)
}

#[derive(Debug, Default)]
pub(crate) struct SessionRanges {
    pub(crate) sessions: Vec<SectorRange>,
    pub(crate) tracks: Vec<SectorRange>,
}

pub(crate) fn parse_session_data(
    data: &[u8],
    format_version: u8,
    media_sector_count: u64,
) -> Result<SessionRanges> {
    const AUDIO_TRACK_FLAG: u32 = 0x01;

    let (header_size, entry_size, footer_size, header_checksum_offset, header_checksum_size) =
        match format_version {
            1 => (36_usize, 32_usize, 4_usize, 32_usize, 32_usize),
            2 => (32_usize, 32_usize, 16_usize, 16_usize, 16_usize),
            _ => {
                return Err(EwfError::Malformed(
                    "unsupported session section format version".into(),
                ));
            }
        };
    if data.len() < header_size {
        return Err(EwfError::Malformed("session section is too short".into()));
    }

    let stored_header_checksum = u32::from_le_bytes(
        data[header_checksum_offset..header_checksum_offset + 4]
            .try_into()
            .expect("slice length checked"),
    );
    let calculated_header_checksum = adler32(&data[..header_checksum_size]);
    if stored_header_checksum != calculated_header_checksum {
        return Err(EwfError::Malformed(
            "session header checksum mismatch".into(),
        ));
    }

    let entry_count = u32::from_le_bytes(data[0..4].try_into().expect("slice length checked"));
    if entry_count == 0 {
        return Ok(SessionRanges::default());
    }
    let entry_count = usize::try_from(entry_count)
        .map_err(|_| EwfError::Malformed("session entry count does not fit usize".into()))?;
    let entries_size = entry_count
        .checked_mul(entry_size)
        .ok_or_else(|| EwfError::Malformed("session entries size overflow".into()))?;
    let entries_end = header_size
        .checked_add(entries_size)
        .ok_or_else(|| EwfError::Malformed("session entries end overflow".into()))?;
    let required_size = entries_end
        .checked_add(footer_size)
        .ok_or_else(|| EwfError::Malformed("session section size overflow".into()))?;
    if data.len() < required_size {
        return Err(EwfError::Malformed(
            "session entries exceed section size".into(),
        ));
    }

    let stored_entries_checksum = u32::from_le_bytes(
        data[entries_end..entries_end + 4]
            .try_into()
            .expect("slice length checked"),
    );
    let calculated_entries_checksum = adler32(&data[header_size..entries_end]);
    if stored_entries_checksum != calculated_entries_checksum {
        return Err(EwfError::Malformed(
            "session entries checksum mismatch".into(),
        ));
    }

    let mut entries = Vec::with_capacity(entry_count);
    for index in 0..entry_count {
        let offset = header_size + index * entry_size;
        let (start_sector, flags) = if format_version == 1 {
            (
                u64::from(u32::from_le_bytes(
                    data[offset + 4..offset + 8]
                        .try_into()
                        .expect("slice length checked"),
                )),
                u32::from_le_bytes(
                    data[offset..offset + 4]
                        .try_into()
                        .expect("slice length checked"),
                ),
            )
        } else {
            (
                u64::from_le_bytes(
                    data[offset..offset + 8]
                        .try_into()
                        .expect("slice length checked"),
                ),
                u32::from_le_bytes(
                    data[offset + 8..offset + 12]
                        .try_into()
                        .expect("slice length checked"),
                ),
            )
        };
        entries.push((start_sector, flags));
    }

    let mut ranges = SessionRanges::default();
    let mut session_start_sector = 0_u64;
    let mut track_start_sector = 0_u64;
    let mut previous_start_sector = entries[0].0;
    let mut previous_flags = entries[0].1;
    let mut current_flags = 0_u32;

    for &(start_sector, flags) in entries.iter().skip(1) {
        if start_sector < previous_start_sector {
            return Err(EwfError::Malformed(
                "session start sector moves backwards".into(),
            ));
        }
        if flags & AUDIO_TRACK_FLAG == 0 {
            ranges.sessions.push(SectorRange {
                first_sector: session_start_sector,
                sector_count: start_sector.saturating_sub(session_start_sector),
            });
            session_start_sector = start_sector;
        }
        if previous_flags & AUDIO_TRACK_FLAG != 0 {
            ranges.tracks.push(SectorRange {
                first_sector: track_start_sector,
                sector_count: start_sector.saturating_sub(track_start_sector),
            });
            track_start_sector = start_sector;
        }
        previous_start_sector = start_sector;
        previous_flags = flags;
        current_flags = flags;
    }

    ranges.sessions.push(SectorRange {
        first_sector: session_start_sector,
        sector_count: media_sector_count.saturating_sub(session_start_sector),
    });
    if current_flags & AUDIO_TRACK_FLAG != 0 {
        ranges.tracks.push(SectorRange {
            first_sector: track_start_sector,
            sector_count: media_sector_count.saturating_sub(track_start_sector),
        });
    }

    Ok(ranges)
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

pub(crate) fn parse_xhash_data(raw: &[u8], stored_hashes: &mut StoredHashes) -> Result<()> {
    let raw = raw.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(raw);
    let text = String::from_utf8_lossy(raw);
    let mut result = Ok(());
    for_each_simple_xml_child(&text, "xhash", |tag, value| {
        if result.is_err() {
            return;
        }
        let value = decode_xml_entities(value.trim());
        if value.is_empty() && crate::hashes::canonical_identifier(tag).is_none() {
            return;
        }
        result = crate::hashes::insert_stored_hash(stored_hashes, tag, &value);
    });
    result
}

pub(crate) fn parse_xheader_data(raw: &[u8], metadata: &mut EwfMetadata) {
    let raw = raw.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(raw);
    let text = String::from_utf8_lossy(raw);
    for_each_simple_xml_child(&text, "xheader", |tag, value| {
        let value = value.trim();
        if value.is_empty() {
            return;
        }
        let value = decode_xml_entities(value);
        metadata
            .header_values
            .entry(tag.to_string())
            .or_insert_with(|| value.clone());
        match tag {
            "case_number" => metadata.case_number = Some(value),
            "description" => metadata.description = Some(value),
            "examiner_name" => metadata.examiner = Some(value),
            "evidence_number" => metadata.evidence_number = Some(value),
            "notes" => metadata.notes = Some(value),
            "acquiry_operating_system" => metadata.os_version = Some(value),
            "acquiry_date" => metadata.acquisition_date = Some(value),
            "acquiry_software" => metadata.acquisition_software = Some(value),
            "acquiry_software_version" => metadata.acquisition_software_version = Some(value),
            "password" => metadata.password = Some(value),
            _ => {}
        }
    });
}

fn for_each_simple_xml_child(text: &str, root_tag: &str, mut visit: impl FnMut(&str, &str)) {
    let root_open = format!("<{root_tag}");
    let Some(root_start) = text.find(&root_open) else {
        return;
    };
    let Some(root_open_size) = text[root_start..].find('>') else {
        return;
    };
    let root_open_end = root_start + root_open_size + 1;
    let root_close = format!("</{root_tag}>");
    let Some(root_end) = text[root_open_end..].find(&root_close) else {
        return;
    };
    let mut body = &text[root_open_end..root_open_end + root_end];

    while let Some(tag_start) = body.find('<') {
        body = &body[tag_start + 1..];
        if body.starts_with('/') || body.starts_with('?') || body.starts_with('!') {
            let Some(skip_end) = body.find('>') else {
                return;
            };
            body = &body[skip_end + 1..];
            continue;
        }
        let Some(open_end) = body.find('>') else {
            return;
        };
        let tag_name = body[..open_end].split_whitespace().next().unwrap_or("");
        if tag_name.is_empty() {
            body = &body[open_end + 1..];
            continue;
        }
        let value_start = open_end + 1;
        let close_tag = format!("</{tag_name}>");
        let Some(value_end) = body[value_start..].find(&close_tag) else {
            return;
        };
        visit(tag_name, &body[value_start..value_start + value_end]);
        body = &body[value_start + value_end + close_tag.len()..];
    }
}

fn decode_xml_entities(value: &str) -> String {
    let mut decoded = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(entity_start) = rest.find('&') {
        decoded.push_str(&rest[..entity_start]);
        rest = &rest[entity_start..];
        let Some(entity_end) = rest.find(';') else {
            decoded.push_str(rest);
            return decoded;
        };
        let entity = &rest[..=entity_end];
        match entity {
            "&amp;" => decoded.push('&'),
            "&lt;" => decoded.push('<'),
            "&gt;" => decoded.push('>'),
            "&quot;" => decoded.push('"'),
            "&apos;" => decoded.push('\''),
            _ => decoded.push_str(entity),
        }
        rest = &rest[entity_end + 1..];
    }
    decoded.push_str(rest);
    decoded
}

pub(crate) fn parse_ewf2_case_data(raw: &[u8], metadata: &mut EwfMetadata) {
    let Some(text) = decode_utf16le(raw) else {
        return;
    };

    for_each_tabular_field(&text, |name, value| {
        if value.is_empty() {
            return;
        }
        metadata.header_values.insert(
            ewf2_case_header_identifier(name).to_string(),
            value.to_string(),
        );
        match name {
            "cn" => metadata.case_number = Some(value.to_string()),
            "en" => metadata.evidence_number = Some(value.to_string()),
            "ex" => metadata.examiner = Some(value.to_string()),
            "de" | "nm" => metadata.description = Some(value.to_string()),
            "nt" => metadata.notes = Some(value.to_string()),
            "av" => metadata.acquisition_software_version = Some(value.to_string()),
            "acquiry_software" => metadata.acquisition_software = Some(value.to_string()),
            "ov" | "os" => metadata.os_version = Some(value.to_string()),
            "ad" | "at" => metadata.acquisition_date = Some(value.to_string()),
            "sd" | "tt" => metadata.system_date = Some(value.to_string()),
            "password" => metadata.password = Some(value.to_string()),
            _ => {}
        }
    });
}

pub(crate) fn parse_ewf2_device_info_values(raw: &[u8], metadata: &mut EwfMetadata) {
    let Some(text) = decode_utf16le(raw) else {
        return;
    };

    for_each_tabular_field(&text, |name, value| {
        if value.is_empty() {
            return;
        }
        let Some(identifier) = ewf2_device_header_identifier(name) else {
            return;
        };
        metadata
            .header_values
            .insert(identifier.to_string(), value.to_string());
    });
}

pub(crate) fn parse_ewf2_device_info(raw: &[u8]) -> Result<Ewf2Geometry> {
    let Some(text) = decode_utf16le(raw) else {
        return Ok(Ewf2Geometry::default());
    };

    let mut bytes_per_sector = None;
    let mut sectors_per_chunk = None;
    let mut total_sectors = None;
    let mut chunk_count = None;
    let mut error_granularity = None;
    let mut media_type = None;
    let mut physical = None;
    let mut fastbloc = false;
    let mut tableau = false;
    for_each_tabular_field(&text, |name, value| match name {
        "dt" => media_type = parse_ewf2_media_type(value),
        "ph" => match value {
            "0" => physical = Some(false),
            "1" => physical = Some(true),
            _ => {}
        },
        "wb" => {
            if let Ok(parsed) = value.parse::<u64>() {
                fastbloc |= parsed & 0x1 != 0;
                tableau |= parsed & 0x2 != 0;
            }
        }
        _ => {
            let Ok(parsed) = value.parse::<u64>() else {
                return;
            };
            match name {
                "b" | "bp" => bytes_per_sector = Some(parsed),
                "gr" => error_granularity = Some(parsed),
                "sc" | "sb" => sectors_per_chunk = Some(parsed),
                "ts" => total_sectors = Some(parsed),
                "tb" => chunk_count = Some(parsed),
                _ => {}
            }
        }
    });

    let chunk_size = match (bytes_per_sector, sectors_per_chunk) {
        (Some(bytes), Some(sectors)) if bytes > 0 && sectors > 0 => {
            Some(checked_ewf2_geometry_mul(bytes, sectors, "chunk size")?)
        }
        _ => None,
    };
    let sector_count = if let Some(sectors) = total_sectors.filter(|sectors| *sectors > 0) {
        Some(sectors)
    } else if let (Some(sectors), Some(chunks)) = (sectors_per_chunk, chunk_count) {
        if sectors > 0 && chunks > 0 {
            Some(checked_ewf2_geometry_mul(sectors, chunks, "sector count")?)
        } else {
            None
        }
    } else {
        None
    };
    let logical_size = if let (Some(bytes), Some(sectors)) = (bytes_per_sector, sector_count) {
        if bytes > 0 && sectors > 0 {
            Some(checked_ewf2_geometry_mul(bytes, sectors, "logical size")?)
        } else {
            None
        }
    } else {
        None
    };

    Ok(Ewf2Geometry {
        sectors_per_chunk: sectors_per_chunk.filter(|value| *value > 0),
        bytes_per_sector: bytes_per_sector.filter(|value| *value > 0),
        sector_count,
        chunk_count: chunk_count.filter(|value| *value > 0),
        error_granularity: error_granularity.filter(|value| *value > 0),
        chunk_size,
        logical_size,
        media_type,
        physical,
        fastbloc,
        tableau,
    })
}

fn checked_ewf2_geometry_mul(left: u64, right: u64, field: &str) -> Result<u64> {
    left.checked_mul(right)
        .ok_or_else(|| EwfError::Malformed(format!("EWF2 geometry {field} overflow")))
}

fn decode_utf16le(raw: &[u8]) -> Option<String> {
    if raw.len() < 2 {
        return None;
    }
    let mut units: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    if units.first() == Some(&0xfeff) {
        units.remove(0);
    }
    String::from_utf16(&units).ok()
}

fn ewf1_header_identifier(name: &str) -> &str {
    match name {
        "a" => "description",
        "av" => "acquiry_software_version",
        "c" => "case_number",
        "dc" => "unknown_dc",
        "e" => "examiner_name",
        "ext" => "extents",
        "l" => "device_label",
        "m" => "acquiry_date",
        "md" => "model",
        "n" => "evidence_number",
        "ov" => "acquiry_operating_system",
        "p" => "password",
        "pid" => "process_identifier",
        "r" => "compression_level",
        "sn" => "serial_number",
        "t" => "notes",
        "u" => "system_date",
        _ => name,
    }
}

fn ewf2_case_header_identifier(name: &str) -> &str {
    match name {
        "ad" | "at" => "acquiry_date",
        "av" => "acquiry_software_version",
        "cn" => "case_number",
        "cp" => "compression_method",
        "de" | "nm" => "description",
        "en" => "evidence_number",
        "ex" => "examiner_name",
        "nt" => "notes",
        "os" | "ov" => "acquiry_operating_system",
        "sd" | "tt" => "system_date",
        _ => name,
    }
}

fn ewf2_device_header_identifier(name: &str) -> Option<&'static str> {
    match name {
        "lb" => Some("device_label"),
        "md" => Some("model"),
        "pid" => Some("process_identifier"),
        "sn" => Some("serial_number"),
        _ => None,
    }
}

fn parse_ewf2_media_type(value: &str) -> Option<MediaType> {
    let value = value.as_bytes();
    if value.len() != 1 {
        return None;
    }
    Some(match value[0] {
        b'c' => MediaType::Optical,
        b'f' => MediaType::Fixed,
        b'l' => MediaType::SingleFiles,
        b'm' => MediaType::Memory,
        b'r' => MediaType::Removable,
        other => MediaType::Unknown(other),
    })
}

fn for_each_tabular_field(text: &str, mut visit: impl FnMut(&str, &str)) {
    let normalized = text.replace("\r\n", "\n");
    let lines: Vec<&str> = normalized.lines().collect();
    if lines.len() < 4 {
        return;
    }

    let names = lines[2].split('\t');
    let values: Vec<&str> = lines[3].split('\t').collect();
    for (index, name) in names.enumerate() {
        if let Some(value) = values.get(index) {
            visit(name, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn parses_ewf1_header_text_metadata() {
        let text = "1\r\nmain\r\nc\tn\ta\te\tt\tav\tov\tm\tu\tp\r\nCASE\tEVID\tDesc\tExaminer\tNotes\tEnCase\tWindows\t2026-01-02\t2026-01-01\tignored\r\n";
        let mut metadata = EwfMetadata::default();

        parse_header_text(text, &mut metadata);

        assert_eq!(metadata.case_number.as_deref(), Some("CASE"));
        assert_eq!(metadata.evidence_number.as_deref(), Some("EVID"));
        assert_eq!(metadata.description.as_deref(), Some("Desc"));
        assert_eq!(metadata.examiner.as_deref(), Some("Examiner"));
        assert_eq!(metadata.notes.as_deref(), Some("Notes"));
        assert_eq!(metadata.acquisition_software.as_deref(), None);
        assert_eq!(
            metadata.acquisition_software_version.as_deref(),
            Some("EnCase")
        );
        assert_eq!(metadata.os_version.as_deref(), Some("Windows"));
        assert_eq!(metadata.acquisition_date.as_deref(), Some("2026-01-02"));
        assert_eq!(metadata.system_date.as_deref(), Some("2026-01-01"));
        assert_eq!(metadata.password.as_deref(), Some("ignored"));
        assert_eq!(
            metadata
                .header_values
                .get("case_number")
                .map(String::as_str),
            Some("CASE")
        );
        assert_eq!(
            metadata
                .header_values
                .get("evidence_number")
                .map(String::as_str),
            Some("EVID")
        );
        assert_eq!(
            metadata.header_values.get("password").map(String::as_str),
            Some("ignored")
        );
    }

    #[test]
    fn parses_ewf1_header_data_with_windows1252_codepage() {
        let raw = b"1\nmain\nc\ta\nCASE-\xe9\tDescription-\x93quoted\x94\n";
        let mut metadata = EwfMetadata::default();

        parse_header_data(raw, HeaderCodepage::Windows1252, &mut metadata);

        assert_eq!(metadata.case_number.as_deref(), Some("CASE-\u{e9}"));
        assert_eq!(
            metadata.description.as_deref(),
            Some("Description-\u{201c}quoted\u{201d}")
        );
    }

    #[test]
    fn parses_header2_utf16le_with_bom() {
        let text = "1\r\nmain\r\nc\tn\te\tav\tov\tm\tu\r\nCASE-2\tEVID-2\tExaminer\tEnCase 8\tWindows 11\t2026-02-02\t2026-02-01\r\n";
        let mut raw = Vec::from([0xff, 0xfe]);
        raw.extend(utf16le(text));
        let mut metadata = EwfMetadata::default();

        parse_header2_data(&raw, &mut metadata);

        assert_eq!(metadata.case_number.as_deref(), Some("CASE-2"));
        assert_eq!(metadata.evidence_number.as_deref(), Some("EVID-2"));
        assert_eq!(metadata.examiner.as_deref(), Some("Examiner"));
        assert_eq!(metadata.acquisition_software.as_deref(), None);
        assert_eq!(
            metadata.acquisition_software_version.as_deref(),
            Some("EnCase 8")
        );
        assert_eq!(metadata.os_version.as_deref(), Some("Windows 11"));
        assert_eq!(
            metadata
                .header_values
                .get("examiner_name")
                .map(String::as_str),
            Some("Examiner")
        );
    }

    #[test]
    fn error2_parser_rejects_short_section() {
        let mut data = Vec::new();
        data.extend_from_slice(&3_u32.to_le_bytes());
        data.extend_from_slice(&[0; 4]);
        data.extend_from_slice(&42_u32.to_le_bytes());
        data.extend_from_slice(&7_u32.to_le_bytes());

        let err = parse_error2_data(&data).unwrap_err();

        assert!(matches!(err, EwfError::Malformed(message) if message.contains("too short")));
    }

    #[test]
    fn error2_parser_reads_ewf1_header_layout() {
        let mut data = vec![0; 520];
        data[0..4].copy_from_slice(&1_u32.to_le_bytes());
        let header_checksum = adler32(&data[..516]);
        data[516..520].copy_from_slice(&header_checksum.to_le_bytes());
        let entries_start = data.len();
        data.extend_from_slice(&42_u32.to_le_bytes());
        data.extend_from_slice(&7_u32.to_le_bytes());
        let entries_checksum = adler32(&data[entries_start..]);
        data.extend_from_slice(&entries_checksum.to_le_bytes());

        let errors = parse_error2_data(&data).unwrap();

        assert_eq!(
            errors,
            [AcquisitionError {
                first_sector: 42,
                sector_count: 7
            }]
        );
    }

    #[test]
    fn parses_ewf2_case_data_metadata() {
        let raw = utf16le(
            "2\nmain\ncn\ten\tex\tde\tnt\tav\tov\tad\tsd\tpassword\nCASE\tEVID\tExaminer\tDesc\tNotes\tEnCase\tWindows\t2026-03-02\t2026-03-01\tsecret\n\n",
        );
        let mut metadata = EwfMetadata::default();

        parse_ewf2_case_data(&raw, &mut metadata);

        assert_eq!(metadata.case_number.as_deref(), Some("CASE"));
        assert_eq!(metadata.evidence_number.as_deref(), Some("EVID"));
        assert_eq!(metadata.examiner.as_deref(), Some("Examiner"));
        assert_eq!(metadata.description.as_deref(), Some("Desc"));
        assert_eq!(metadata.notes.as_deref(), Some("Notes"));
        assert_eq!(metadata.acquisition_software.as_deref(), None);
        assert_eq!(
            metadata.acquisition_software_version.as_deref(),
            Some("EnCase")
        );
        assert_eq!(metadata.os_version.as_deref(), Some("Windows"));
        assert_eq!(metadata.acquisition_date.as_deref(), Some("2026-03-02"));
        assert_eq!(metadata.system_date.as_deref(), Some("2026-03-01"));
        assert_eq!(metadata.password.as_deref(), Some("secret"));
        assert_eq!(
            metadata
                .header_values
                .get("case_number")
                .map(String::as_str),
            Some("CASE")
        );
        assert_eq!(
            metadata
                .header_values
                .get("examiner_name")
                .map(String::as_str),
            Some("Examiner")
        );
        assert_eq!(
            metadata
                .header_values
                .get("acquiry_date")
                .map(String::as_str),
            Some("2026-03-02")
        );
    }

    #[test]
    fn parses_ewf2_device_info_header_values() {
        let raw = utf16le("2\nmain\nmd\tsn\tlb\tpid\nModel X\tSER123\tDisk Label\tPROC42\n\n");
        let mut metadata = EwfMetadata::default();

        parse_ewf2_device_info_values(&raw, &mut metadata);

        assert_eq!(
            metadata.header_values.get("model").map(String::as_str),
            Some("Model X")
        );
        assert_eq!(
            metadata
                .header_values
                .get("serial_number")
                .map(String::as_str),
            Some("SER123")
        );
        assert_eq!(
            metadata
                .header_values
                .get("device_label")
                .map(String::as_str),
            Some("Disk Label")
        );
        assert_eq!(
            metadata
                .header_values
                .get("process_identifier")
                .map(String::as_str),
            Some("PROC42")
        );
    }

    #[test]
    fn ewf2_case_data_ignores_empty_and_unknown_fields() {
        let raw = utf16le("2\nmain\ncn\tunknown\ten\n\tignored\tEVID\n\n");
        let mut metadata = EwfMetadata::default();

        parse_ewf2_case_data(&raw, &mut metadata);

        assert!(metadata.case_number.is_none());
        assert_eq!(metadata.evidence_number.as_deref(), Some("EVID"));
        assert_eq!(
            metadata.header_values.get("unknown").map(String::as_str),
            Some("ignored")
        );
    }

    #[test]
    fn parses_xhash_data_hash_values() {
        let mut stored_hashes = StoredHashes::default();

        parse_xhash_data(
            b"<xhash><MD5>00112233445566778899aabbccddeeff</MD5><SHA1>ffeeddccbbaa9988776655443322110010325476</SHA1></xhash>",
            &mut stored_hashes,
        ).unwrap();

        assert_eq!(
            stored_hashes.hash_values.get("MD5").map(String::as_str),
            Some("00112233445566778899aabbccddeeff")
        );
        assert_eq!(
            stored_hashes.hash_values.get("SHA1").map(String::as_str),
            Some("ffeeddccbbaa9988776655443322110010325476")
        );
    }

    #[test]
    fn parses_xhash_data_lowercase_hash_tags() {
        let mut stored_hashes = StoredHashes::default();

        parse_xhash_data(
            b"<xhash><md5>00112233445566778899aabbccddeeff</md5><sha1>ffeeddccbbaa9988776655443322110010325476</sha1></xhash>",
            &mut stored_hashes,
        ).unwrap();

        assert_eq!(
            stored_hashes.md5,
            Some([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ])
        );
        assert_eq!(
            stored_hashes.sha1,
            Some([
                0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
                0x11, 0x00, 0x10, 0x32, 0x54, 0x76,
            ])
        );
    }

    #[test]
    fn parses_xhash_data_preserves_unknown_hash_values() {
        let mut stored_hashes = StoredHashes::default();

        parse_xhash_data(
            b"<xhash><MD5>00112233445566778899aabbccddeeff</MD5><SHA256>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</SHA256></xhash>",
            &mut stored_hashes,
        ).unwrap();

        assert_eq!(
            stored_hashes.hash_values.get("SHA256").map(String::as_str),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn parses_xheader_data_decodes_xml_entities() {
        let mut metadata = EwfMetadata::default();

        parse_xheader_data(
            b"<xheader><case_number>CASE &amp; &lt;tag&gt;</case_number><notes>&quot;quoted&quot; &apos;single&apos;</notes></xheader>",
            &mut metadata,
        );

        assert_eq!(metadata.case_number.as_deref(), Some("CASE & <tag>"));
        assert_eq!(metadata.notes.as_deref(), Some("\"quoted\" 'single'"));
        assert_eq!(
            metadata
                .header_values
                .get("case_number")
                .map(String::as_str),
            Some("CASE & <tag>")
        );
    }

    #[test]
    fn parses_xheader_data_preserves_unknown_fields() {
        let mut metadata = EwfMetadata::default();

        parse_xheader_data(
            b"<xheader><case_number>CASE-X</case_number><custom_field>custom value</custom_field></xheader>",
            &mut metadata,
        );

        assert_eq!(metadata.case_number.as_deref(), Some("CASE-X"));
        assert_eq!(
            metadata
                .header_values
                .get("custom_field")
                .map(String::as_str),
            Some("custom value")
        );
    }

    #[test]
    fn parses_ewf2_device_info_geometry_aliases() {
        let raw = utf16le("2\nmain\nbp\tsb\tts\n512\t128\t256\n\n");

        let geometry = parse_ewf2_device_info(&raw).unwrap();

        assert_eq!(geometry.chunk_size, Some(65_536));
        assert_eq!(geometry.logical_size, Some(131_072));
    }

    #[test]
    fn parses_ewf2_geometry_from_chunk_count() {
        let raw = utf16le("2\nmain\nbp\tsb\ttb\n512\t128\t3\n\n");

        let geometry = parse_ewf2_device_info(&raw).unwrap();

        assert_eq!(geometry.chunk_size, Some(65_536));
        assert_eq!(geometry.logical_size, Some(196_608));
    }

    #[test]
    fn ewf2_device_info_leaves_zero_geometry_unset() {
        let raw = utf16le("2\nmain\nb\tsc\tts\n0\t64\t128\n\n");

        let geometry = parse_ewf2_device_info(&raw).unwrap();

        assert_eq!(geometry.chunk_size, None);
        assert_eq!(geometry.logical_size, None);
    }
}

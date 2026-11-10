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

use crate::types::{
    SingleFileAttribute, SingleFileEntry, SingleFileEntryType, SingleFileExtent,
    SingleFilePermission, SingleFilePermissionGroup, SingleFileSource, SingleFileSubject,
    SingleFilesInfo,
};
use crate::{EwfError, Result};
use std::collections::BTreeMap;

/// Path separator used by EWF2 logical single-file catalogs.
///
/// Paths are represented with tab-separated entry names. A leading separator
/// refers to the root entry.
pub const SINGLE_FILE_PATH_SEPARATOR: char = '\t';
const EXTENDED_ATTRIBUTES_HEADER: &[u8; 37] = &[
    0x00, 0x00, 0x00, 0x00, 0x01, 0x0b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x41, 0x00, 0x74,
    0x00, 0x74, 0x00, 0x72, 0x00, 0x69, 0x00, 0x62, 0x00, 0x75, 0x00, 0x74, 0x00, 0x65, 0x00, 0x73,
    0x00, 0x00, 0x00, 0x00, 0x00,
];

impl SingleFilesInfo {
    /// Returns the catalog entry at a single-file path.
    ///
    /// # Errors
    ///
    /// Returns an error if the path contains an empty entry name.
    pub fn entry_by_path(&self, path: &str) -> Result<Option<&SingleFileEntry>> {
        self.root.child_by_path(path)
    }

    /// Returns a source record by its source identifier.
    pub fn source_by_identifier(&self, identifier: i32) -> Option<&SingleFileSource> {
        self.sources
            .iter()
            .find(|source| source.identifier == Some(identifier))
    }

    /// Returns a source record by its source table index.
    pub fn source_by_index(&self, index: i32) -> Option<&SingleFileSource> {
        usize::try_from(index)
            .ok()
            .and_then(|index| self.sources.get(index))
    }

    /// Returns the source record associated with a catalog entry.
    pub fn source_for_entry(&self, entry: &SingleFileEntry) -> Option<&SingleFileSource> {
        let identifier = entry.source_identifier?;
        if identifier < 1 {
            return None;
        }
        self.source_by_index(identifier)
    }

    /// Returns a subject record by its subject identifier.
    pub fn subject_by_identifier(&self, identifier: u32) -> Option<&SingleFileSubject> {
        self.subjects
            .iter()
            .find(|subject| subject.identifier == Some(identifier))
    }

    /// Returns the subject record associated with a catalog entry.
    pub fn subject_for_entry(&self, entry: &SingleFileEntry) -> Option<&SingleFileSubject> {
        self.subject_by_identifier(entry.subject_identifier?)
    }

    /// Returns the number of permission groups.
    pub fn number_of_permission_groups(&self) -> usize {
        self.permission_groups.len()
    }

    /// Returns a permission group by its table index.
    pub fn permission_group_by_index(&self, index: i32) -> Option<&SingleFilePermissionGroup> {
        usize::try_from(index)
            .ok()
            .and_then(|index| self.permission_groups.get(index))
    }

    /// Returns the permission group associated with a catalog entry.
    pub fn permission_group_for_entry(
        &self,
        entry: &SingleFileEntry,
    ) -> Option<&SingleFilePermissionGroup> {
        self.permission_group_by_index(entry.permission_group_index?)
    }

    /// Returns access-control entries associated with a catalog entry.
    pub fn access_control_entries_for_entry(
        &self,
        entry: &SingleFileEntry,
    ) -> &[SingleFilePermission] {
        self.permission_group_for_entry(entry)
            .map_or(&[], |group| group.permissions.as_slice())
    }

    /// Returns the number of access-control entries for a catalog entry.
    pub fn number_of_access_control_entries_for_entry(&self, entry: &SingleFileEntry) -> usize {
        self.access_control_entries_for_entry(entry).len()
    }

    /// Returns one access-control entry for a catalog entry by index.
    pub fn access_control_entry_for_entry(
        &self,
        entry: &SingleFileEntry,
        index: usize,
    ) -> Option<&SingleFilePermission> {
        self.access_control_entries_for_entry(entry).get(index)
    }
}

impl SingleFileSource {
    /// Returns the source identifier.
    pub fn identifier(&self) -> Option<i32> {
        self.identifier
    }

    /// Returns the source name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns the evidence number associated with the source.
    pub fn evidence_number(&self) -> Option<&str> {
        self.evidence_number.as_deref()
    }

    /// Returns the source location.
    pub fn location(&self) -> Option<&str> {
        self.location.as_deref()
    }

    /// Returns the source device GUID.
    pub fn device_guid(&self) -> Option<&str> {
        self.device_guid.as_deref()
    }

    /// Returns the primary source device GUID.
    pub fn primary_device_guid(&self) -> Option<&str> {
        self.primary_device_guid.as_deref()
    }

    /// Returns the source manufacturer.
    pub fn manufacturer(&self) -> Option<&str> {
        self.manufacturer.as_deref()
    }

    /// Returns the source model.
    pub fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }

    /// Returns the source serial number.
    pub fn serial_number(&self) -> Option<&str> {
        self.serial_number.as_deref()
    }

    /// Returns the source domain.
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// Returns the source IP address.
    pub fn ip_address(&self) -> Option<&str> {
        self.ip_address.as_deref()
    }

    /// Returns the source MAC address.
    pub fn mac_address(&self) -> Option<&str> {
        self.mac_address.as_deref()
    }

    /// Returns the source size in bytes.
    pub fn size(&self) -> Option<u64> {
        self.size
    }

    /// Returns the source drive type code.
    pub fn drive_type(&self) -> Option<char> {
        self.drive_type
    }

    /// Returns the source logical offset.
    pub fn logical_offset(&self) -> Option<i64> {
        self.logical_offset
    }

    /// Returns the source physical offset.
    pub fn physical_offset(&self) -> Option<i64> {
        self.physical_offset
    }

    /// Returns the source acquisition timestamp.
    pub fn acquisition_time(&self) -> Option<i64> {
        self.acquisition_time
    }

    /// Returns the source MD5 hash string.
    pub fn md5_hash(&self) -> Option<&str> {
        self.md5.as_deref()
    }

    /// Returns the source SHA1 hash string.
    pub fn sha1_hash(&self) -> Option<&str> {
        self.sha1.as_deref()
    }
}

impl SingleFileEntry {
    /// Returns the entry identifier.
    pub fn identifier(&self) -> Option<u64> {
        self.identifier
    }

    /// Returns the entry type.
    pub fn entry_type(&self) -> Option<SingleFileEntryType> {
        self.file_entry_type
    }

    /// Returns the raw entry flags.
    pub fn flags(&self) -> Option<u32> {
        self.flags
    }

    /// Returns the entry GUID.
    pub fn guid(&self) -> Option<&str> {
        self.guid.as_deref()
    }

    /// Returns the logical media offset for entry data.
    pub fn media_data_offset(&self) -> Option<i64> {
        self.logical_offset
    }

    /// Returns the entry data size in bytes.
    pub fn media_data_size(&self) -> Option<u64> {
        self.size
    }

    /// Returns the physical source offset for entry data.
    pub fn physical_offset(&self) -> Option<i64> {
        self.physical_offset
    }

    /// Returns the duplicate-data logical media offset.
    pub fn duplicate_media_data_offset(&self) -> Option<i64> {
        self.duplicate_data_offset
    }

    /// Returns the associated source identifier.
    pub fn source_identifier(&self) -> Option<i32> {
        self.source_identifier
    }

    /// Returns the associated subject identifier.
    pub fn subject_identifier(&self) -> Option<u32> {
        self.subject_identifier
    }

    /// Returns the associated permission group index.
    pub fn permission_group_index(&self) -> Option<i32> {
        self.permission_group_index
    }

    /// Returns the raw record type.
    pub fn record_type(&self) -> Option<u32> {
        self.record_type
    }

    /// Returns the entry name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns the short entry name.
    pub fn short_name(&self) -> Option<&str> {
        self.short_name.as_deref()
    }

    /// Returns the entry size in bytes.
    pub fn size(&self) -> Option<u64> {
        self.size
    }

    /// Returns the creation timestamp.
    pub fn creation_time(&self) -> Option<i64> {
        self.creation_time
    }

    /// Returns the modification timestamp.
    pub fn modification_time(&self) -> Option<i64> {
        self.modification_time
    }

    /// Returns the access timestamp.
    pub fn access_time(&self) -> Option<i64> {
        self.access_time
    }

    /// Returns the entry metadata modification timestamp.
    pub fn entry_modification_time(&self) -> Option<i64> {
        self.entry_modification_time
    }

    /// Returns the deletion timestamp.
    pub fn deletion_time(&self) -> Option<i64> {
        self.deletion_time
    }

    /// Returns the entry MD5 hash string.
    pub fn md5_hash(&self) -> Option<&str> {
        self.md5.as_deref()
    }

    /// Returns the entry SHA1 hash string.
    pub fn sha1_hash(&self) -> Option<&str> {
        self.sha1.as_deref()
    }

    /// Returns the number of child entries.
    pub fn number_of_sub_file_entries(&self) -> usize {
        self.children.len()
    }

    /// Returns a child entry by index.
    pub fn sub_file_entry(&self, index: usize) -> Option<&SingleFileEntry> {
        self.children.get(index)
    }

    /// Returns a child entry by name.
    pub fn sub_file_entry_by_name(&self, name: &str) -> Option<&SingleFileEntry> {
        self.child_by_name(name)
    }

    /// Returns a descendant entry by single-file path.
    ///
    /// # Errors
    ///
    /// Returns an error if the path contains an empty entry name.
    pub fn sub_file_entry_by_path(&self, path: &str) -> Result<Option<&SingleFileEntry>> {
        self.child_by_path(path)
    }

    /// Returns the number of data extents.
    pub fn number_of_extents(&self) -> usize {
        self.extents.len()
    }

    /// Returns a data extent by index.
    pub fn extent(&self, index: usize) -> Option<&SingleFileExtent> {
        self.extents.get(index)
    }

    /// Returns the number of extended attributes.
    pub fn number_of_attributes(&self) -> usize {
        self.attributes.len()
    }

    /// Returns an extended attribute by index.
    pub fn attribute(&self, index: usize) -> Option<&SingleFileAttribute> {
        self.attributes.get(index)
    }

    /// Returns a direct child entry by name.
    pub fn child_by_name(&self, name: &str) -> Option<&SingleFileEntry> {
        self.children
            .iter()
            .find(|child| child.name.as_deref() == Some(name))
    }

    /// Returns a descendant entry by single-file path.
    ///
    /// # Errors
    ///
    /// Returns an error if the path contains an empty entry name.
    pub fn child_by_path(&self, path: &str) -> Result<Option<&SingleFileEntry>> {
        entry_by_path(self, path)
    }
}

impl SingleFilePermission {
    /// Returns the permission name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns the permission identifier.
    pub fn identifier(&self) -> Option<&str> {
        self.identifier.as_deref()
    }

    /// Returns the permission property type.
    pub fn property_type(&self) -> Option<u32> {
        self.property_type
    }

    /// Returns the access mask.
    pub fn access_mask(&self) -> Option<u32> {
        self.access_mask
    }

    /// Returns the ACE flags.
    pub fn flags(&self) -> Option<u32> {
        self.ace_flags
    }
}

impl SingleFilePermissionGroup {
    /// Returns the group name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns the group identifier.
    pub fn identifier(&self) -> Option<&str> {
        self.identifier.as_deref()
    }

    /// Returns the group property type.
    pub fn property_type(&self) -> Option<u32> {
        self.property_type
    }

    /// Returns the group access mask.
    pub fn access_mask(&self) -> Option<u32> {
        self.access_mask
    }

    /// Returns the group ACE flags.
    pub fn flags(&self) -> Option<u32> {
        self.ace_flags
    }

    /// Returns the number of permissions in the group.
    pub fn number_of_entries(&self) -> usize {
        self.permissions.len()
    }

    /// Returns a permission in the group by table index.
    pub fn entry_by_index(&self, index: i32) -> Option<&SingleFilePermission> {
        usize::try_from(index)
            .ok()
            .and_then(|index| self.permissions.get(index))
    }
}

impl SingleFileAttribute {
    /// Returns the attribute name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns the attribute value.
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

pub(crate) fn parse_ewf2_single_files_data(data: &[u8]) -> Result<SingleFilesInfo> {
    parse_single_files_data(data, false)
}

pub(crate) fn parse_ewf1_single_files_data(data: &[u8]) -> Result<SingleFilesInfo> {
    parse_single_files_data(data, true)
}

fn parse_single_files_data(data: &[u8], require_record_size: bool) -> Result<SingleFilesInfo> {
    let DecodedUtf16Lines {
        lines,
        mut invalid_utf16_lines,
    } = decode_utf16le_lines(data)?;
    if lines.first().map(String::as_str) != Some("5") {
        return Err(EwfError::Malformed(
            "EWF2 single files data has unsupported category count".into(),
        ));
    }

    let mut category_index = 1;

    let (data_size, next_category_index) = parse_record_category(&lines, category_index)?;
    category_index = next_category_index;
    let (permission_groups, next_category_index) =
        parse_permission_groups_category(&lines, category_index)?;
    category_index = next_category_index;
    let (sources, next_category_index) = parse_sources_category(&lines, category_index)?;
    category_index = next_category_index;
    let (subjects, entry_index) = parse_subjects_category(&lines, category_index)?;

    require_category_at(&lines, entry_index, "entry", "entry category")?;
    let types_line_index = entry_index
        .checked_add(2)
        .ok_or_else(|| EwfError::Malformed("EWF2 single files entry index overflow".into()))?;
    let mut cursor = entry_index
        .checked_add(3)
        .ok_or_else(|| EwfError::Malformed("EWF2 single files entry index overflow".into()))?;
    if types_line_index >= lines.len() {
        return Err(EwfError::Malformed(
            "EWF2 single files entry category is truncated".into(),
        ));
    }

    parse_category_entry_count(&lines[entry_index + 1], "EWF2 single files entry count")?;
    let types = parse_type_line(
        &lines[types_line_index],
        "EWF2 single files entry category types",
    )?;

    let data_size = match data_size {
        Some(size) => size,
        None if require_record_size => {
            return Err(EwfError::Malformed(
                "EWF1 ltree record has no total data size".into(),
            ));
        }
        None => u64::try_from(data.len())
            .map_err(|_| EwfError::Malformed("single files data size overflow".into()))?,
    };
    let root = parse_entry(&lines, &types, &mut cursor, &mut invalid_utf16_lines)?;
    require_empty_category_terminator(
        &lines,
        cursor,
        "EWF2 single files entry category terminator",
    )?;
    if !invalid_utf16_lines.is_empty() {
        return Err(EwfError::Malformed(
            "single files data has invalid UTF-16 outside an entry name".into(),
        ));
    }
    Ok(SingleFilesInfo {
        data_size,
        root,
        sources,
        subjects,
        permission_groups,
    })
}

fn entry_by_path<'a>(
    mut entry: &'a SingleFileEntry,
    path: &str,
) -> Result<Option<&'a SingleFileEntry>> {
    let mut rest = path
        .strip_prefix(SINGLE_FILE_PATH_SEPARATOR)
        .unwrap_or(path);
    if rest.is_empty() {
        return Ok(Some(entry));
    }

    while !rest.is_empty() {
        let (segment, next_rest) = match rest.find([SINGLE_FILE_PATH_SEPARATOR, '\0']) {
            Some(separator_index) => {
                let separator_size = rest[separator_index..]
                    .chars()
                    .next()
                    .expect("separator index points to a character")
                    .len_utf8();
                (
                    &rest[..separator_index],
                    &rest[separator_index + separator_size..],
                )
            }
            None => (rest, ""),
        };
        if segment.is_empty() {
            return Err(EwfError::Malformed(
                "single file path is missing entry name".into(),
            ));
        }

        entry = match entry.child_by_name(segment) {
            Some(child) => child,
            None => return Ok(None),
        };
        rest = next_rest;
    }

    Ok(Some(entry))
}

fn parse_sources_category(
    lines: &[String],
    category_index: usize,
) -> Result<(Vec<SingleFileSource>, usize)> {
    require_category_at(lines, category_index, "srce", "source category")?;
    let (types, entry_count, mut cursor) = parse_category_header(lines, category_index, "srce")?;

    let root = parse_source_row(&types, get_line(lines, cursor, "EWF2 source root")?)?;
    cursor += 1;
    let mut sources = Vec::new();
    sources.push(root);

    for source_index in 0..entry_count {
        let child_count = parse_child_entry_count(
            get_line(lines, cursor, "EWF2 source child count")?,
            "EWF2 source child count",
        )?;
        if child_count != 0 {
            return Err(EwfError::Malformed(
                "EWF2 source entries cannot have children".into(),
            ));
        }
        cursor += 1;

        let source = parse_source_row(&types, get_line(lines, cursor, "EWF2 source row")?)?;
        let expected_identifier = source_index
            .checked_add(1)
            .and_then(|identifier| i32::try_from(identifier).ok())
            .ok_or_else(|| EwfError::Malformed("EWF2 source identifier index overflow".into()))?;
        if source.identifier != Some(expected_identifier) {
            return Err(EwfError::Malformed(
                "EWF2 source identifier does not match source index".into(),
            ));
        }
        sources.push(source);
        cursor += 1;
    }
    require_empty_category_terminator(
        lines,
        cursor,
        "EWF2 single files source category terminator",
    )?;
    Ok((
        sources,
        next_category_index(cursor, "EWF2 source category terminator")?,
    ))
}

fn parse_subjects_category(
    lines: &[String],
    category_index: usize,
) -> Result<(Vec<SingleFileSubject>, usize)> {
    require_category_at(lines, category_index, "sub", "subject category")?;
    let (types, entry_count, mut cursor) = parse_category_header(lines, category_index, "sub")?;

    let root = parse_subject_row(&types, get_line(lines, cursor, "EWF2 subject root")?)?;
    cursor += 1;
    let mut subjects = Vec::new();
    subjects.push(root);

    for _ in 0..entry_count {
        let child_count = parse_child_entry_count(
            get_line(lines, cursor, "EWF2 subject child count")?,
            "EWF2 subject child count",
        )?;
        if child_count != 0 {
            return Err(EwfError::Malformed(
                "EWF2 subject entries cannot have children".into(),
            ));
        }
        cursor += 1;

        let subject = parse_subject_row(&types, get_line(lines, cursor, "EWF2 subject row")?)?;
        subjects.push(subject);
        cursor += 1;
    }
    require_empty_category_terminator(
        lines,
        cursor,
        "EWF2 single files subject category terminator",
    )?;
    Ok((
        subjects,
        next_category_index(cursor, "EWF2 subject category terminator")?,
    ))
}

fn parse_permission_groups_category(
    lines: &[String],
    category_index: usize,
) -> Result<(Vec<SingleFilePermissionGroup>, usize)> {
    require_category_at(lines, category_index, "perm", "permission category")?;
    let (types, entry_count, mut cursor) = parse_category_header(lines, category_index, "perm")?;

    let root_permission = parse_permission_row(
        &types,
        get_line(lines, cursor, "EWF2 permission category root")?,
    )?;
    require_permission_group_type(&root_permission, "EWF2 permission category root")?;
    cursor += 1;
    let mut groups = Vec::new();

    for _ in 0..entry_count {
        let permission_count = parse_child_entry_count(
            get_line(lines, cursor, "EWF2 permission group child count")?,
            "EWF2 permission group child count",
        )?;
        cursor += 1;

        let group_permission = parse_permission_row(
            &types,
            get_line(lines, cursor, "EWF2 permission group row")?,
        )?;
        require_permission_group_type(&group_permission, "EWF2 permission group row")?;
        cursor += 1;
        let mut group = permission_group_from_permission(group_permission);

        for _ in 0..permission_count {
            let child_count = parse_child_entry_count(
                get_line(lines, cursor, "EWF2 permission child count")?,
                "EWF2 permission child count",
            )?;
            if child_count != 0 {
                return Err(EwfError::Malformed(
                    "EWF2 permission entries cannot have children".into(),
                ));
            }
            cursor += 1;

            let permission =
                parse_permission_row(&types, get_line(lines, cursor, "EWF2 permission row")?)?;
            group.permissions.push(permission);
            cursor += 1;
        }
        groups.push(group);
    }
    require_empty_category_terminator(
        lines,
        cursor,
        "EWF2 single files permission category terminator",
    )?;
    Ok((
        groups,
        next_category_index(cursor, "EWF2 permission category terminator")?,
    ))
}

fn require_category_at(lines: &[String], index: usize, name: &str, label: &str) -> Result<()> {
    let line = get_line(lines, index, &format!("EWF2 single files {label}"))?;
    if line != name {
        return Err(EwfError::Malformed(format!(
            "EWF2 single files {label} is missing or out of order"
        )));
    }
    Ok(())
}

fn next_category_index(index: usize, label: &str) -> Result<usize> {
    index
        .checked_add(1)
        .ok_or_else(|| EwfError::Malformed(format!("{label} index overflow")))
}

fn parse_record_category(lines: &[String], category_index: usize) -> Result<(Option<u64>, usize)> {
    require_category_at(lines, category_index, "rec", "record category")?;
    let types_line_index = category_index
        .checked_add(1)
        .ok_or_else(|| EwfError::Malformed("EWF2 record category index overflow".into()))?;
    let values_line_index = category_index
        .checked_add(2)
        .ok_or_else(|| EwfError::Malformed("EWF2 record category index overflow".into()))?;
    let types = parse_type_line(
        get_line(lines, types_line_index, "EWF2 record category types")?,
        "EWF2 record category types",
    )?;
    let values: Vec<&str> = get_line(lines, values_line_index, "EWF2 record category values")?
        .split('\t')
        .collect();
    let terminator_index = category_index
        .checked_add(3)
        .ok_or_else(|| EwfError::Malformed("EWF2 record category index overflow".into()))?;

    require_empty_category_terminator(
        lines,
        terminator_index,
        "EWF2 single files record category terminator",
    )?;
    let next_category_index =
        next_category_index(terminator_index, "EWF2 record category terminator")?;

    for (index, value_type) in types.iter().enumerate() {
        if *value_type != "tb" {
            continue;
        }
        let Some(value) = values.get(index).copied().filter(|value| !value.is_empty()) else {
            return Ok((None, next_category_index));
        };
        return Ok((
            parse_u64(value, "record data size").map(Some)?,
            next_category_index,
        ));
    }
    Ok((None, next_category_index))
}

fn parse_category_header<'a>(
    lines: &'a [String],
    category_index: usize,
    label: &str,
) -> Result<(Vec<&'a str>, usize, usize)> {
    let count_line_index = category_index
        .checked_add(1)
        .ok_or_else(|| EwfError::Malformed(format!("EWF2 {label} category index overflow")))?;
    let types_line_index = category_index
        .checked_add(2)
        .ok_or_else(|| EwfError::Malformed(format!("EWF2 {label} category index overflow")))?;
    let copy_count_line_index = category_index
        .checked_add(3)
        .ok_or_else(|| EwfError::Malformed(format!("EWF2 {label} category index overflow")))?;
    let root_line_index = category_index
        .checked_add(4)
        .ok_or_else(|| EwfError::Malformed(format!("EWF2 {label} category index overflow")))?;

    let entry_count = parse_category_entry_count(
        get_line(lines, count_line_index, "EWF2 category count")?,
        "EWF2 category count",
    )?;
    let types = parse_type_line(
        get_line(lines, types_line_index, "EWF2 category types")?,
        &format!("EWF2 {label} category types"),
    )?;
    let copy_entry_count = parse_child_entry_count(
        get_line(lines, copy_count_line_index, "EWF2 category copy count")?,
        "EWF2 category copy count",
    )?;
    if copy_entry_count != entry_count {
        return Err(EwfError::Malformed(format!(
            "EWF2 {label} category entry count mismatch"
        )));
    }
    Ok((types, entry_count, root_line_index))
}

fn parse_source_row(types: &[&str], row: &str) -> Result<SingleFileSource> {
    let values = split_exact_typed_values(types, row, "EWF2 source row")?;
    let mut source = SingleFileSource::default();
    for (value_type, value) in types.iter().zip(values.iter()) {
        if value.is_empty() {
            continue;
        }
        match *value_type {
            "ah" => source.md5 = parse_serialized_base16_string(value, "source MD5 hash")?,
            "aq" => source.acquisition_time = Some(parse_i64(value, "source acquisition time")?),
            "do" => source.domain = Some((*value).to_owned()),
            "dt" => source.drive_type = Some(parse_single_char(value, "source drive type")?),
            "ev" => source.evidence_number = Some((*value).to_owned()),
            "gu" => {
                source.device_guid = parse_serialized_base16_string(value, "source device GUID")?;
            }
            "id" => source.identifier = Some(parse_non_negative_i32(value, "source identifier")?),
            "ip" => source.ip_address = Some((*value).to_owned()),
            "lo" => source.logical_offset = Some(parse_i64(value, "source logical offset")?),
            "loc" => source.location = Some((*value).to_owned()),
            "ma" => {
                source.mac_address = parse_serialized_base16_string(value, "source MAC address")?;
            }
            "mfr" => source.manufacturer = Some((*value).to_owned()),
            "mo" => source.model = Some((*value).to_owned()),
            "n" => source.name = Some((*value).to_owned()),
            "pgu" => {
                source.primary_device_guid =
                    parse_serialized_base16_string(value, "source primary device GUID")?;
            }
            "po" => source.physical_offset = Some(parse_i64(value, "source physical offset")?),
            "se" => source.serial_number = Some((*value).to_owned()),
            "sh" => source.sha1 = parse_serialized_base16_string(value, "source SHA1 hash")?,
            "tb" => source.size = Some(parse_u64(value, "source size")?),
            _ => {}
        }
    }
    Ok(source)
}

fn parse_subject_row(types: &[&str], row: &str) -> Result<SingleFileSubject> {
    let values = split_exact_typed_values(types, row, "EWF2 subject row")?;
    let mut subject = SingleFileSubject::default();
    for (value_type, value) in types.iter().zip(values.iter()) {
        if value.is_empty() {
            continue;
        }
        match *value_type {
            "id" => subject.identifier = Some(parse_u32(value, "subject identifier")?),
            "n" => subject.name = Some((*value).to_owned()),
            _ => {}
        }
    }
    Ok(subject)
}

fn parse_permission_row(types: &[&str], row: &str) -> Result<SingleFilePermission> {
    let values = split_exact_typed_values(types, row, "EWF2 permission row")?;
    let mut permission = SingleFilePermission::default();
    for (value_type, value) in types.iter().zip(values.iter()) {
        if value.is_empty() {
            continue;
        }
        match *value_type {
            "n" => permission.name = Some((*value).to_owned()),
            "nta" => permission.access_mask = Some(parse_u32(value, "permission access mask")?),
            "nti" => permission.ace_flags = Some(parse_u32(value, "permission ACE flags")?),
            "pr" | "pt" => {
                permission.property_type = Some(parse_u32(value, "permission property type")?);
            }
            "s" => permission.identifier = Some((*value).to_owned()),
            _ => {}
        }
    }
    Ok(permission)
}

fn require_permission_group_type(permission: &SingleFilePermission, label: &str) -> Result<()> {
    if permission.property_type != Some(10) {
        return Err(EwfError::Malformed(format!(
            "{label} has unsupported permission group type"
        )));
    }
    Ok(())
}

fn permission_group_from_permission(permission: SingleFilePermission) -> SingleFilePermissionGroup {
    SingleFilePermissionGroup {
        name: permission.name,
        identifier: permission.identifier,
        property_type: permission.property_type,
        access_mask: permission.access_mask,
        ace_flags: permission.ace_flags,
        permissions: Vec::new(),
    }
}

fn split_typed_values<'a>(types: &[&str], row: &'a str) -> Vec<&'a str> {
    let mut values: Vec<&str> = row.split('\t').collect();
    values.truncate(types.len());
    values.resize(types.len(), "");
    values
}

fn split_exact_typed_values<'a>(types: &[&str], row: &'a str, label: &str) -> Result<Vec<&'a str>> {
    let values: Vec<&str> = row.split('\t').collect();
    if values.len() != types.len() {
        return Err(EwfError::Malformed(format!(
            "{label} value count does not match type count"
        )));
    }
    Ok(values)
}

fn parse_type_line<'a>(line: &'a str, label: &str) -> Result<Vec<&'a str>> {
    let types: Vec<&str> = line.split('\t').collect();
    if types.is_empty() || types.iter().any(|value_type| value_type.is_empty()) {
        return Err(EwfError::Malformed(format!("{label} has empty type")));
    }
    Ok(types)
}

fn parse_category_entry_count(line: &str, label: &str) -> Result<usize> {
    let (first, second) = parse_number_pair(line, label)?;
    if second != 1 {
        return Err(EwfError::Malformed(format!(
            "{label} has unsupported category count shape"
        )));
    }
    usize::try_from(first).map_err(|_| EwfError::Malformed(format!("{label} does not fit usize")))
}

fn parse_child_entry_count(line: &str, label: &str) -> Result<usize> {
    let (first, second) = parse_number_pair(line, label)?;
    if first != 0 {
        return Err(EwfError::Malformed(format!(
            "{label} has unsupported child count shape"
        )));
    }
    Ok(second)
}

fn parse_file_entry_child_count(line: &str, label: &str) -> Result<usize> {
    let (parent_value, child_count) = parse_number_pair(line, label)?;
    if parent_value != 0 && parent_value != 26 {
        return Err(EwfError::Malformed(format!(
            "{label} has unsupported parent value"
        )));
    }
    Ok(child_count)
}

fn get_line<'a>(lines: &'a [String], index: usize, label: &str) -> Result<&'a str> {
    lines
        .get(index)
        .map(String::as_str)
        .ok_or_else(|| EwfError::Malformed(format!("{label} is truncated")))
}

fn require_empty_category_terminator(lines: &[String], cursor: usize, label: &str) -> Result<()> {
    if !get_line(lines, cursor, label)?.is_empty() {
        return Err(EwfError::Malformed(format!("{label} is not empty")));
    }
    Ok(())
}

fn parse_single_char(value: &str, label: &str) -> Result<char> {
    let mut characters = value.chars();
    let character = characters
        .next()
        .ok_or_else(|| EwfError::Malformed(format!("{label} is empty")))?;
    if characters.next().is_some() {
        return Err(EwfError::Malformed(format!(
            "{label} has more than one character"
        )));
    }
    Ok(character)
}

struct DecodedUtf16Lines {
    lines: Vec<String>,
    invalid_utf16_lines: BTreeMap<usize, Vec<u16>>,
}

fn decode_utf16le_lines(data: &[u8]) -> Result<DecodedUtf16Lines> {
    if !data.len().is_multiple_of(2) {
        return Err(EwfError::Malformed(
            "EWF2 single files data has odd UTF-16 size".into(),
        ));
    }

    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u16::from_le_bytes(*chunk))
        .collect();
    let units = units.strip_prefix(&[0xfeff]).unwrap_or(&units);
    let mut lines = Vec::new();
    let mut invalid = BTreeMap::new();
    for raw in units.split(|unit| *unit == u16::from(b'\n')) {
        let raw = raw.strip_suffix(&[u16::from(b'\r')]).unwrap_or(raw);
        if let Ok(line) = String::from_utf16(raw) {
            lines.push(line);
        } else {
            invalid.insert(lines.len(), raw.to_vec());
            lines.push(String::from_utf16_lossy(raw));
        }
    }
    Ok(DecodedUtf16Lines {
        lines,
        invalid_utf16_lines: invalid,
    })
}

fn parse_entry(
    lines: &[String],
    types: &[&str],
    cursor: &mut usize,
    invalid_utf16_lines: &mut BTreeMap<usize, Vec<u16>>,
) -> Result<SingleFileEntry> {
    let count_line = lines
        .get(*cursor)
        .ok_or_else(|| EwfError::Malformed("EWF2 single file entry missing count".into()))?;
    let child_count =
        parse_file_entry_child_count(count_line, "EWF2 single file entry child count")?;
    *cursor = cursor
        .checked_add(1)
        .ok_or_else(|| EwfError::Malformed("EWF2 single file entry index overflow".into()))?;

    let value_line_index = *cursor;
    let value_line = lines
        .get(*cursor)
        .ok_or_else(|| EwfError::Malformed("EWF2 single file entry missing values".into()))?;
    let values = split_typed_values(types, value_line);
    *cursor = cursor
        .checked_add(1)
        .ok_or_else(|| EwfError::Malformed("EWF2 single file entry index overflow".into()))?;

    let mut entry = SingleFileEntry::default();
    for (value_type, value) in types.iter().zip(values.iter()) {
        apply_entry_value(&mut entry, value_type, value)?;
    }
    if let Some(raw) = invalid_utf16_lines.remove(&value_line_index) {
        for (index, field) in raw.split(|unit| *unit == u16::from(b'\t')).enumerate() {
            if String::from_utf16(field).is_err() {
                if types.get(index) != Some(&"n") || entry.name_utf16.is_some() {
                    return Err(EwfError::Malformed(
                        "single files entry has invalid UTF-16 outside its name".into(),
                    ));
                }
                entry.name_utf16 = Some(field.to_vec());
            }
        }
        if entry.name_utf16.is_none() {
            return Err(EwfError::Malformed(
                "single files entry has invalid UTF-16 outside its name".into(),
            ));
        }
    }

    for _ in 0..child_count {
        let child = parse_entry(lines, types, cursor, invalid_utf16_lines)?;
        entry.children.push(child);
    }
    Ok(entry)
}

fn apply_entry_value(entry: &mut SingleFileEntry, value_type: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        if value_type == "p" {
            entry.file_entry_type = Some(SingleFileEntryType::File);
        }
        return Ok(());
    }

    match value_type {
        "ac" => entry.access_time = Some(parse_i64(value, "access time")?),
        "be" => entry.extents = parse_binary_extents(value)?,
        "cid" => entry.record_type = Some(parse_u32(value, "record type")?),
        "cr" => entry.creation_time = Some(parse_i64(value, "creation time")?),
        "dl" => entry.deletion_time = Some(parse_i64(value, "deletion time")?),
        "du" => entry.duplicate_data_offset = Some(parse_i64(value, "duplicate data offset")?),
        "ea" => entry.attributes = parse_extended_attributes(value)?,
        "ha" => entry.md5 = parse_serialized_base16_string(value, "MD5 hash")?,
        "id" => entry.identifier = Some(parse_u64(value, "identifier")?),
        "lo" => entry.logical_offset = Some(parse_i64(value, "logical offset")?),
        "ls" => entry.size = Some(parse_u64(value, "file size")?),
        "mid" => entry.guid = parse_serialized_base16_string(value, "GUID")?,
        "mo" => entry.entry_modification_time = Some(parse_i64(value, "entry modification time")?),
        "n" => entry.name = Some(value.to_owned()),
        "opr" => entry.flags = Some(parse_u32(value, "entry flags")?),
        "p" => {
            entry.file_entry_type = Some(match value {
                "f" | "0" => SingleFileEntryType::File,
                "d" | "1" => SingleFileEntryType::Directory,
                _ => SingleFileEntryType::Unknown,
            });
        }
        "pm" => entry.permission_group_index = Some(parse_i32(value, "permission group index")?),
        "po" => entry.physical_offset = Some(parse_i64(value, "physical offset")?),
        "sha" => entry.sha1 = parse_serialized_base16_string(value, "SHA1 hash")?,
        "snh" => entry.short_name = Some(parse_short_name(value)?),
        "src" => {
            entry.source_identifier = Some(parse_non_negative_i32(value, "source identifier")?);
        }
        "sub" => entry.subject_identifier = Some(parse_u32(value, "subject identifier")?),
        "wr" => entry.modification_time = Some(parse_i64(value, "modification time")?),
        _ => {}
    }
    Ok(())
}

fn parse_binary_extents(value: &str) -> Result<Vec<SingleFileExtent>> {
    let mut parts = value.split(' ').filter(|part| !part.is_empty()).peekable();
    let extent_count = parts
        .next()
        .ok_or_else(|| EwfError::Malformed("EWF2 single files extents missing count".into()))
        .and_then(|part| parse_hex_usize(part, "extent count"))?;
    // The declared count is untrusted. Grow only as actual extent pairs parse.
    let mut extents = Vec::new();

    while parts.peek().is_some() {
        let sparse = if parts.peek() == Some(&"S") {
            parts.next();
            true
        } else {
            false
        };
        let data_offset = parts
            .next()
            .ok_or_else(|| EwfError::Malformed("EWF2 single files extent missing offset".into()))
            .and_then(|part| parse_hex_u64(part, "extent offset"))?;
        let data_size = parts
            .next()
            .ok_or_else(|| EwfError::Malformed("EWF2 single files extent missing size".into()))
            .and_then(|part| parse_hex_u64(part, "extent size"))?;
        extents.push(SingleFileExtent {
            data_offset,
            data_size,
            sparse,
        });
    }

    if extents.len() != extent_count {
        return Err(EwfError::Malformed(
            "EWF2 single files extent count mismatch".into(),
        ));
    }
    Ok(extents)
}

fn parse_short_name(value: &str) -> Result<String> {
    let mut parts = value.split(' ');
    let declared_size = parts
        .next()
        .ok_or_else(|| EwfError::Malformed("short name is missing size".into()))?;
    let short_name = parts
        .next()
        .ok_or_else(|| EwfError::Malformed("short name is missing value".into()))?;
    if parts.next().is_some() {
        return Err(EwfError::Malformed(
            "short name has unsupported value count".into(),
        ));
    }
    let declared_size = parse_u64(declared_size, "short name size")?;
    let actual_size = short_name
        .len()
        .checked_add(1)
        .ok_or_else(|| EwfError::Malformed("short name size overflow".into()))?;
    let actual_size = u64::try_from(actual_size)
        .map_err(|_| EwfError::Malformed("short name size does not fit u64".into()))?;
    if declared_size != actual_size {
        return Err(EwfError::Malformed(
            "short name size does not match value size".into(),
        ));
    }
    Ok(short_name.to_owned())
}

fn parse_extended_attributes(value: &str) -> Result<Vec<SingleFileAttribute>> {
    let data = parse_hex_byte_stream(value, "extended attributes")?;
    if data.is_empty() {
        return Ok(Vec::new());
    }
    if data.len() < EXTENDED_ATTRIBUTES_HEADER.len()
        || &data[..EXTENDED_ATTRIBUTES_HEADER.len()] != EXTENDED_ATTRIBUTES_HEADER
    {
        return Err(EwfError::Malformed(
            "EWF2 single files extended attributes header is unsupported".into(),
        ));
    }

    let mut attributes = Vec::new();
    let mut offset = 0_usize;
    while offset < data.len() {
        let (attribute, read_size) = parse_extended_attribute_record(&data[offset..])?;
        offset = offset
            .checked_add(read_size)
            .ok_or_else(|| EwfError::Malformed("extended attribute offset overflow".into()))?;
        if !attribute.is_branch {
            attributes.push(SingleFileAttribute {
                name: attribute.name,
                value: attribute.value,
            });
        }
    }
    Ok(attributes)
}

struct ParsedExtendedAttribute {
    name: Option<String>,
    value: Option<String>,
    is_branch: bool,
}

fn parse_extended_attribute_record(data: &[u8]) -> Result<(ParsedExtendedAttribute, usize)> {
    if data.len() < 13 {
        return Err(EwfError::Malformed(
            "EWF2 single files extended attribute is truncated".into(),
        ));
    }

    let is_branch = data[4] != 0;
    let name_units = u32::from_le_bytes(data[5..9].try_into().expect("slice length checked"));
    let value_units = u32::from_le_bytes(data[9..13].try_into().expect("slice length checked"));
    let name_size = utf16_byte_size(name_units, "extended attribute name")?;
    let value_size = utf16_byte_size(value_units, "extended attribute value")?;
    let value_offset = 13_usize
        .checked_add(name_size)
        .ok_or_else(|| EwfError::Malformed("extended attribute value offset overflow".into()))?;
    let end_offset = value_offset
        .checked_add(value_size)
        .ok_or_else(|| EwfError::Malformed("extended attribute end offset overflow".into()))?;
    if data.len() < end_offset {
        return Err(EwfError::Malformed(
            "EWF2 single files extended attribute is truncated".into(),
        ));
    }

    let name = decode_optional_utf16le_string(&data[13..value_offset], "extended attribute name")?;
    let value = decode_optional_utf16le_string(
        &data[value_offset..end_offset],
        "extended attribute value",
    )?;

    Ok((
        ParsedExtendedAttribute {
            name,
            value,
            is_branch,
        },
        end_offset,
    ))
}

fn utf16_byte_size(units: u32, label: &str) -> Result<usize> {
    let units = usize::try_from(units)
        .map_err(|_| EwfError::Malformed(format!("{label} size does not fit usize")))?;
    units
        .checked_mul(2)
        .ok_or_else(|| EwfError::Malformed(format!("{label} size overflow")))
}

fn decode_optional_utf16le_string(data: &[u8], label: &str) -> Result<Option<String>> {
    if data.is_empty() {
        return Ok(None);
    }
    if !data.len().is_multiple_of(2) {
        return Err(EwfError::Malformed(format!("{label} has odd UTF-16 size")));
    }

    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u16::from_le_bytes(*chunk))
        .collect();
    let mut text = String::from_utf16(&units)
        .map_err(|_| EwfError::Malformed(format!("{label} is not valid UTF-16LE")))?;
    if text.ends_with('\0') {
        text.pop();
    }
    if text.is_empty() {
        Ok(None)
    } else {
        Ok(Some(text))
    }
}

fn parse_hex_byte_stream(value: &str, label: &str) -> Result<Vec<u8>> {
    let hex: String = value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if !hex.len().is_multiple_of(2) {
        return Err(EwfError::Malformed(format!(
            "EWF2 single files {label} has odd hexadecimal size"
        )));
    }
    if !hex.is_ascii() {
        return Err(EwfError::Malformed(format!(
            "invalid EWF2 single files {label} hexadecimal value"
        )));
    }

    (0..hex.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&hex[index..index + 2], 16).map_err(|_| {
                EwfError::Malformed(format!(
                    "invalid EWF2 single files {label} hexadecimal value"
                ))
            })
        })
        .collect()
}

fn parse_serialized_base16_string(value: &str, label: &str) -> Result<Option<String>> {
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EwfError::Malformed(format!(
            "invalid EWF2 single files {label} hexadecimal value"
        )));
    }
    if value.bytes().all(|byte| byte == b'0') {
        Ok(None)
    } else {
        Ok(Some(value.to_ascii_lowercase()))
    }
}

fn parse_number_pair(line: &str, label: &str) -> Result<(u64, usize)> {
    let mut parts = line.split('\t');
    let first = parts
        .next()
        .ok_or_else(|| EwfError::Malformed(format!("{label} is missing first value")))?;
    let second = parts
        .next()
        .ok_or_else(|| EwfError::Malformed(format!("{label} is missing second value")))?;
    if parts.next().is_some() {
        return Err(EwfError::Malformed(format!("{label} has too many values")));
    }
    let first = parse_u64(first, label)?;
    let second = parse_u64(second, label)?;
    let second = usize::try_from(second)
        .map_err(|_| EwfError::Malformed(format!("{label} does not fit usize")))?;
    Ok((first, second))
}

fn parse_hex_usize(value: &str, label: &str) -> Result<usize> {
    let value = parse_hex_u64(value, label)?;
    usize::try_from(value)
        .map_err(|_| EwfError::Malformed(format!("EWF2 single files {label} out of bounds")))
}

fn parse_hex_u64(value: &str, label: &str) -> Result<u64> {
    u64::from_str_radix(value, 16)
        .map_err(|_| EwfError::Malformed(format!("invalid EWF2 single files {label} value")))
}

fn parse_u64(value: &str, label: &str) -> Result<u64> {
    value
        .parse()
        .map_err(|_| EwfError::Malformed(format!("invalid EWF2 single files {label} value")))
}

fn parse_u32(value: &str, label: &str) -> Result<u32> {
    parse_u64(value, label).and_then(|value| {
        u32::try_from(value)
            .map_err(|_| EwfError::Malformed(format!("EWF2 single files {label} out of bounds")))
    })
}

fn parse_i64(value: &str, label: &str) -> Result<i64> {
    value
        .parse()
        .map_err(|_| EwfError::Malformed(format!("invalid EWF2 single files {label} value")))
}

fn parse_i32(value: &str, label: &str) -> Result<i32> {
    parse_i64(value, label).and_then(|value| {
        i32::try_from(value)
            .map_err(|_| EwfError::Malformed(format!("EWF2 single files {label} out of bounds")))
    })
}

fn parse_non_negative_i32(value: &str, label: &str) -> Result<i32> {
    let value = parse_i32(value, label)?;
    if value < 0 {
        return Err(EwfError::Malformed(format!(
            "EWF2 single files {label} out of bounds"
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod entry_type_tests {
    use super::*;

    #[test]
    fn standard_and_legacy_entry_types() {
        for (value, expected) in [
            ("", SingleFileEntryType::File),
            ("0", SingleFileEntryType::File),
            ("1", SingleFileEntryType::Directory),
            ("f", SingleFileEntryType::File),
            ("d", SingleFileEntryType::Directory),
            ("x", SingleFileEntryType::Unknown),
        ] {
            let mut entry = SingleFileEntry::default();
            apply_entry_value(&mut entry, "p", value).unwrap();
            assert_eq!(entry.file_entry_type, Some(expected));
        }
    }

    #[test]
    fn unbacked_catalog_counts_do_not_reserve_memory() {
        assert!(parse_binary_extents("ffffffffffffffff").is_err());
        assert!(parse_binary_extents("4000000 0 1").is_err());
    }

    #[test]
    fn extended_attribute_hex_rejects_multibyte_characters() {
        assert!(parse_hex_byte_stream("䀊a", "extended attributes").is_err());
        assert_eq!(
            parse_hex_byte_stream("ab cd", "extended attributes").unwrap(),
            vec![0xab, 0xcd]
        );
    }
}

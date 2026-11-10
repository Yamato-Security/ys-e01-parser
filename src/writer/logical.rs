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

//! Catalog construction on top of the EWF writer's transactional publication.

use std::collections::BTreeMap;
use std::io::Read;
use std::ops::ControlFlow;
use std::path::Path;

use md5::{Digest, Md5};
use sha1::Sha1;

use super::{
    EwfWriter, SequentialOptions, SequentialWriter, WriteFormat, WriteOptions, WriteResult,
    hex_string,
};
use crate::{
    EwfError, MediaType, Result, SingleFileEntry, SingleFileEntryType, SingleFileExtent,
    SingleFilesInfo,
};

/// Caller-supplied metadata for a logical acquisition entry.
///
/// Names are stored verbatim; NUL, tab, CR, and LF are rejected because the
/// EWF catalog is line/tab-delimited. No host filesystem metadata is inferred.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogicalEntryMetadata {
    /// Entry name, independent of any source filesystem path.
    pub name: String,
    /// Creation timestamp in Unix seconds.
    pub creation_time: Option<i64>,
    /// Content modification timestamp in Unix seconds.
    pub modification_time: Option<i64>,
    /// Access timestamp in Unix seconds.
    pub access_time: Option<i64>,
    /// Metadata modification timestamp in Unix seconds.
    pub entry_modification_time: Option<i64>,
    /// Deletion timestamp in Unix seconds.
    pub deletion_time: Option<i64>,
}

/// Progress within the file currently being added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LogicalWriteProgress {
    /// Automatically assigned entry identifier.
    pub identifier: u64,
    /// File bytes accepted by the writer.
    pub bytes_written: u64,
    /// Declared file size.
    pub bytes_total: u64,
}

/// Builds an L01/Lx01 catalog and file hashes while accepting file streams.
///
/// Uses the general writer's temporary spools and publication transaction.
/// This is not checkpoint-resumable acquisition. Input errors or cancellation
/// poison the builder so partial files cannot be published by `finish`.
pub struct LogicalWriter {
    writer: Backend,
    paths: BTreeMap<u64, Vec<usize>>,
    next_identifier: u64,
    poisoned: bool,
}

enum Backend {
    General(Box<EwfWriter>),
    Sequential(Box<SequentialWriter>),
}

impl Backend {
    fn position(&self) -> u64 {
        match self {
            Self::General(w) => w.position(),
            Self::Sequential(w) => w.position(),
        }
    }
    fn options(&mut self) -> &mut WriteOptions {
        match self {
            Self::General(w) => &mut w.options,
            Self::Sequential(w) => &mut w.options,
        }
    }
    fn write_all(&mut self, data: &[u8]) -> Result<()> {
        match self {
            Self::General(w) => w.write_all(data),
            Self::Sequential(w) => w.write_all(data),
        }
    }
    fn finish(self) -> Result<WriteResult> {
        match self {
            Self::General(w) => w.finish(),
            Self::Sequential(w) => w.finish(),
        }
    }
}

impl LogicalWriter {
    /// Creates a logical writer. Select `Ewf1Logical` or `Ewf2Logical` explicitly.
    /// Caller-authored catalogs and auxiliary file tables are rejected; this
    /// builder owns those. The root has identifier 1 and an empty name.
    pub fn create(path: impl AsRef<Path>, mut options: WriteOptions) -> Result<Self> {
        Self::catalog(&mut options)?;
        Ok(Self::from_backend(Backend::General(Box::new(
            EwfWriter::create(path, options)?,
        ))))
    }

    /// Creates bounded sequential Lx01 output. `source_size` is the sum of all
    /// file payload lengths. Catalog metadata remains in memory; one encoded
    /// segment is retained as payload scratch. No checkpoint resume.
    pub fn create_sequential(
        path: impl AsRef<Path>,
        mut options: SequentialOptions,
    ) -> Result<Self> {
        if options.write.format != WriteFormat::Ewf2Logical {
            return Err(EwfError::Unsupported(
                "sequential logical builder requires EWF2 logical format".into(),
            ));
        }
        Self::catalog(&mut options.write)?;
        Ok(Self::from_backend(Backend::Sequential(Box::new(
            SequentialWriter::create(path, options)?,
        ))))
    }

    fn from_backend(writer: Backend) -> Self {
        Self {
            writer,
            paths: BTreeMap::from([(1, vec![])]),
            next_identifier: 2,
            poisoned: false,
        }
    }

    fn catalog(options: &mut WriteOptions) -> Result<()> {
        if !matches!(
            options.format,
            WriteFormat::Ewf1Logical | WriteFormat::Ewf2Logical
        ) || options.single_files.is_some()
            || !options.ewf2_single_files_tables.is_empty()
        {
            return Err(EwfError::Unsupported(
                "logical builder requires a logical format and no prebuilt catalog".into(),
            ));
        }
        options.media_profile.media_type = Some(MediaType::SingleFiles);
        options.single_files = Some(SingleFilesInfo {
            root: SingleFileEntry {
                identifier: Some(1),
                name: Some(String::new()),
                file_entry_type: Some(SingleFileEntryType::Directory),
                permission_group_index: Some(-1),
                ..SingleFileEntry::default()
            },
            ..SingleFilesInfo::default()
        });
        Ok(())
    }

    /// Adds a directory beneath an existing directory and returns its identifier.
    /// Duplicate names are permitted: identifiers disambiguate them.
    pub fn add_directory(&mut self, parent: u64, metadata: LogicalEntryMetadata) -> Result<u64> {
        let entry = self.prepare(parent, metadata, SingleFileEntryType::Directory)?;
        Ok(self.insert(parent, entry))
    }

    /// Reads exactly `size` bytes, assigns extents, and computes MD5/SHA1.
    /// Trailing input bytes are left unread, allowing bounded source streams.
    /// Callers own snapshot consistency and source metadata collection.
    pub fn add_file(
        &mut self,
        parent: u64,
        metadata: LogicalEntryMetadata,
        size: u64,
        input: &mut impl Read,
    ) -> Result<u64> {
        self.add_file_with_progress(parent, metadata, size, input, |_| ControlFlow::Continue(()))
    }

    /// Adds a file with cooperative cancellation between input/output buffers.
    /// Cancellation or an I/O error requires discarding this builder.
    pub fn add_file_with_progress(
        &mut self,
        parent: u64,
        metadata: LogicalEntryMetadata,
        size: u64,
        input: &mut impl Read,
        mut progress: impl FnMut(LogicalWriteProgress) -> ControlFlow<()>,
    ) -> Result<u64> {
        let mut entry = self.prepare(parent, metadata, SingleFileEntryType::File)?;
        let offset = self.writer.position();
        let end = offset
            .checked_add(size)
            .filter(|end| i64::try_from(*end).is_ok())
            .ok_or_else(|| {
                EwfError::Malformed("logical file address exceeds EWF catalog range".into())
            })?;
        self.poisoned = true;
        let mut written = 0;
        let mut buffer = vec![0; 1024 * 1024];
        let mut md5 = Md5::new();
        let mut sha1 = Sha1::new();
        loop {
            if progress(LogicalWriteProgress {
                identifier: self.next_identifier,
                bytes_written: written,
                bytes_total: size,
            })
            .is_break()
            {
                return Err(EwfError::Aborted);
            }
            if written == size {
                break;
            }
            let length = (size - written).min(buffer.len() as u64) as usize;
            input.read_exact(&mut buffer[..length])?;
            self.writer.write_all(&buffer[..length])?;
            md5.update(&buffer[..length]);
            sha1.update(&buffer[..length]);
            written += length as u64;
        }
        entry.size = Some(size);
        entry.logical_offset = Some(offset as i64);
        if size != 0 {
            entry.extents.push(SingleFileExtent {
                data_offset: offset,
                data_size: size,
                sparse: false,
            });
        }
        entry.md5 = Some(hex_string(&md5.finalize()));
        entry.sha1 = Some(hex_string(&sha1.finalize()));
        self.writer
            .options()
            .single_files
            .as_mut()
            .expect("builder catalog")
            .data_size = end;
        let identifier = self.insert(parent, entry);
        self.poisoned = false;
        Ok(identifier)
    }

    /// Publishes the completed image with the EWF writer's normal durability rules.
    pub fn finish(self) -> Result<WriteResult> {
        self.ensure_healthy()?;
        self.writer.finish()
    }

    fn ensure_healthy(&self) -> Result<()> {
        if self.poisoned {
            return Err(EwfError::Unsupported(
                "logical acquisition failed; discard this writer".into(),
            ));
        }
        Ok(())
    }

    fn prepare(
        &self,
        parent: u64,
        metadata: LogicalEntryMetadata,
        kind: SingleFileEntryType,
    ) -> Result<SingleFileEntry> {
        self.ensure_healthy()?;
        if metadata.name.is_empty() || metadata.name.contains(['\0', '\t', '\r', '\n']) {
            return Err(EwfError::Malformed(
                "logical entry name is empty or contains catalog delimiters".into(),
            ));
        }
        let path = self
            .paths
            .get(&parent)
            .ok_or_else(|| EwfError::Malformed("logical parent does not exist".into()))?;
        if path.len() >= 128 {
            return Err(EwfError::Unsupported(
                "logical directory nesting exceeds 128".into(),
            ));
        }
        self.next_identifier
            .checked_add(1)
            .ok_or_else(|| EwfError::Malformed("logical identifier overflow".into()))?;
        Ok(SingleFileEntry {
            identifier: Some(self.next_identifier),
            name: Some(metadata.name),
            file_entry_type: Some(kind),
            permission_group_index: Some(-1),
            creation_time: metadata.creation_time,
            modification_time: metadata.modification_time,
            access_time: metadata.access_time,
            entry_modification_time: metadata.entry_modification_time,
            deletion_time: metadata.deletion_time,
            ..SingleFileEntry::default()
        })
    }

    fn insert(&mut self, parent: u64, entry: SingleFileEntry) -> u64 {
        let mut path = self.paths[&parent].clone();
        let mut node = &mut self
            .writer
            .options()
            .single_files
            .as_mut()
            .expect("builder catalog")
            .root;
        for &index in &path {
            node = &mut node.children[index];
        }
        path.push(node.children.len());
        if entry.file_entry_type == Some(SingleFileEntryType::Directory) {
            self.paths.insert(self.next_identifier, path);
        }
        node.children.push(entry);
        let identifier = self.next_identifier;
        self.next_identifier += 1;
        identifier
    }
}

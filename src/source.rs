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

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;

/// A stable-length, thread-safe segment backing with independent positioned reads.
///
/// Implementations may return short reads and must never return more than the
/// supplied buffer length. Evidence bytes must remain unchanged while open.
pub trait SegmentReadAt: Send + Sync {
    /// Reads bytes at a segment-relative offset without a shared cursor.
    fn read_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<usize>;
    /// Returns the backing length.
    fn len(&self) -> io::Result<u64>;
    /// Returns whether the backing is empty.
    fn is_empty(&self) -> io::Result<bool> {
        self.len().map(|length| length == 0)
    }
}

/// A bounded view of a positioned backing, memory buffer, or file.
///
/// Clones share the backing, never a seek position. No temporary extraction is
/// needed for a segment stored in a contiguous range of another file.
#[derive(Clone)]
pub struct SegmentSource {
    backing: Arc<dyn SegmentReadAt>,
    base: u64,
    length: u64,
}

impl std::fmt::Debug for SegmentSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SegmentSource")
            .field("base", &self.base)
            .field("length", &self.length)
            .finish_non_exhaustive()
    }
}

impl SegmentSource {
    /// Wraps a caller-provided positioned backend, caching its stable length.
    pub fn from_backing(backing: Arc<dyn SegmentReadAt>) -> io::Result<Self> {
        let length = backing.len()?;
        Ok(Self {
            backing,
            base: 0,
            length,
        })
    }

    /// Wraps immutable bytes as a segment.
    pub fn from_bytes(bytes: impl Into<Arc<[u8]>>) -> Self {
        let bytes = bytes.into();
        Self {
            length: bytes.len() as u64,
            base: 0,
            backing: Arc::new(MemoryBacking(bytes)),
        }
    }

    /// Wraps a file using native positioned reads on Windows and Unix.
    /// Other platforms use a mutex-protected seek/read fallback.
    pub fn from_file(file: File) -> io::Result<Self> {
        #[cfg(any(unix, windows))]
        let backing = FileBacking(file);
        #[cfg(not(any(unix, windows)))]
        let backing = FileBacking(std::sync::Mutex::new(file));
        Self::from_backing(Arc::new(backing))
    }

    /// Returns a bounded subrange. Rejects overflow and ranges outside this view.
    pub fn subrange(&self, offset: u64, length: u64) -> io::Result<Self> {
        if offset
            .checked_add(length)
            .is_none_or(|end| end > self.length)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "segment subrange exceeds backing",
            ));
        }
        Ok(Self {
            backing: Arc::clone(&self.backing),
            base: self.base + offset,
            length,
        })
    }

    /// Returns the bounded view length.
    pub fn len(&self) -> u64 {
        self.length
    }

    /// Returns whether this view is empty.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Reads within this view. Reads at or beyond its end return zero.
    pub fn read_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
        let count = self.length.saturating_sub(offset).min(buffer.len() as u64) as usize;
        if count == 0 {
            return Ok(0);
        }
        let read = self
            .backing
            .read_at(&mut buffer[..count], self.base + offset)?;
        if read > count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "segment backing over-reported read length",
            ));
        }
        Ok(read)
    }

    pub(crate) fn read_exact_at(&self, buffer: &mut [u8], mut offset: u64) -> io::Result<()> {
        let mut remaining = buffer;
        while !remaining.is_empty() {
            match self.read_at(remaining, offset) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "segment backing ended before requested range",
                    ));
                }
                Ok(count) => {
                    offset += count as u64;
                    remaining = &mut remaining[count..];
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    pub(crate) fn cursor(&self) -> SourceCursor {
        SourceCursor {
            source: self.clone(),
            position: 0,
        }
    }
}

struct MemoryBacking(Arc<[u8]>);

impl SegmentReadAt for MemoryBacking {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.len() as u64)
    }
    fn read_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(self.0.len());
        let count = buffer.len().min(self.0.len() - start);
        buffer[..count].copy_from_slice(&self.0[start..start + count]);
        Ok(count)
    }
}

#[cfg(any(unix, windows))]
struct FileBacking(File);
#[cfg(not(any(unix, windows)))]
struct FileBacking(std::sync::Mutex<File>);

impl SegmentReadAt for FileBacking {
    fn len(&self) -> io::Result<u64> {
        #[cfg(any(unix, windows))]
        {
            self.0.metadata().map(|metadata| metadata.len())
        }
        #[cfg(not(any(unix, windows)))]
        {
            self.0
                .lock()
                .map_err(|_| io::Error::other("file backing lock poisoned"))?
                .metadata()
                .map(|metadata| metadata.len())
        }
    }

    fn read_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
        #[cfg(unix)]
        {
            std::os::unix::fs::FileExt::read_at(&self.0, buffer, offset)
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::FileExt::seek_read(&self.0, buffer, offset)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let mut file = self
                .0
                .lock()
                .map_err(|_| io::Error::other("file backing lock poisoned"))?;
            file.seek(SeekFrom::Start(offset))?;
            file.read(buffer)
        }
    }
}

pub(crate) struct SourceCursor {
    source: SegmentSource,
    position: u64,
}

impl Read for SourceCursor {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.source.read_at(buffer, self.position)?;
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for SourceCursor {
    fn seek(&mut self, seek: SeekFrom) -> io::Result<u64> {
        let position = match seek {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::Current(offset) => self.position.checked_add_signed(offset),
            SeekFrom::End(offset) => self.source.len().checked_add_signed(offset),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "segment seek out of range"))?;
        self.position = position;
        Ok(position)
    }
}

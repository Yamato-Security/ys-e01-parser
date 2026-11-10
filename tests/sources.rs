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

//! Positioned backings, bounded ranges, and section inspection.
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use ewf_image::{
    EwfWriter, Image, OpenOptions, SectionKind, SegmentReadAt, SegmentSource, WriteFormat,
    WriteOptions,
};

fn image_bytes(format: WriteFormat) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source.E01");
    let mut writer = EwfWriter::create(
        &path,
        WriteOptions {
            format,
            bytes_per_sector: 1,
            sectors_per_chunk: if format == WriteFormat::Ewf2Logical {
                8192
            } else {
                64
            },
            ..WriteOptions::default()
        },
    )
    .unwrap();
    writer.write_all(&vec![0x42; 100_003]).unwrap();
    writer.finish().unwrap();
    std::fs::read(path).unwrap()
}

#[test]
fn embedded_sources_support_both_families_without_reading_adjacent_bytes() {
    for format in [
        WriteFormat::Ewf1Physical,
        WriteFormat::Ewf2Physical,
        WriteFormat::Ewf2Logical,
    ] {
        let bytes = image_bytes(format);
        let length = bytes.len() as u64;
        let mut container = vec![0xff; 137];
        container.extend_from_slice(&bytes);
        container.extend_from_slice(&[0x55; 100]);
        let source = SegmentSource::from_bytes(container)
            .subrange(137, length)
            .unwrap();
        let mut edge = [0; 16];
        assert_eq!(source.read_at(&mut edge, length - 1).unwrap(), 1);
        assert_eq!(source.read_at(&mut edge, u64::MAX).unwrap(), 0);
        let image = Image::open_sources([("embedded.E01", source)]).unwrap();
        assert_eq!(image.media_size(), 100_003);
        assert_eq!(image.read_at(&mut edge, 99_999).unwrap(), 4);
        assert_eq!(&edge[..4], &[0x42; 4]);
        assert_ne!(image.sections(), []);
        for section in image.sections() {
            assert!(section.data_offset + section.data_size <= length);
            match &section.kind {
                SectionKind::Ewf1(name) => assert_eq!(
                    &bytes[section.descriptor_offset as usize..][..name.len()],
                    name.as_bytes()
                ),
                SectionKind::Ewf2(value) => assert_eq!(
                    *value,
                    u32::from_le_bytes(
                        bytes[section.descriptor_offset as usize..][..4]
                            .try_into()
                            .unwrap()
                    )
                ),
            }
        }
    }
}

#[test]
fn subranges_reject_overflow_and_escape() {
    let source = SegmentSource::from_bytes(vec![1; 16]);
    assert!(source.subrange(u64::MAX, 2).is_err());
    assert!(source.subrange(8, 9).is_err());
    assert!(source.subrange(16, 0).unwrap().is_empty());
    let nested = source.subrange(3, 5).unwrap();
    assert!(nested.subrange(1, 5).is_err());
}

struct ShortBacking {
    bytes: Vec<u8>,
    interrupted: AtomicBool,
}
impl SegmentReadAt for ShortBacking {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
        if !self.interrupted.swap(true, Ordering::Relaxed) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let start = offset as usize;
        let count = buffer
            .len()
            .min(7)
            .min(self.bytes.len().saturating_sub(start));
        buffer[..count].copy_from_slice(&self.bytes[start..start + count]);
        Ok(count)
    }
}

#[test]
fn short_and_interrupted_reads_are_completed() {
    let source = SegmentSource::from_backing(Arc::new(ShortBacking {
        bytes: image_bytes(WriteFormat::Ewf1Physical),
        interrupted: AtomicBool::new(false),
    }))
    .unwrap();
    let image = Image::open_sources([("short.E01", source)]).unwrap();
    let mut bytes = [0; 100];
    image.read_at(&mut bytes, 0).unwrap();
    assert_eq!(bytes, [0x42; 100]);
}

struct ConcurrentBacking {
    bytes: Vec<u8>,
    active: AtomicUsize,
    peak: AtomicUsize,
    observe: AtomicBool,
}
impl SegmentReadAt for ConcurrentBacking {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
        let observe = self.observe.load(Ordering::Relaxed);
        if observe {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(15));
        }
        let start = offset as usize;
        let count = buffer.len().min(self.bytes.len().saturating_sub(start));
        buffer[..count].copy_from_slice(&self.bytes[start..start + count]);
        if observe {
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
        Ok(count)
    }
}

#[test]
fn positioned_chunk_reads_can_overlap_and_share_the_table_cache() {
    let backing = Arc::new(ConcurrentBacking {
        bytes: image_bytes(WriteFormat::Ewf1Physical),
        active: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
        observe: AtomicBool::new(false),
    });
    let source = SegmentSource::from_backing(backing.clone()).unwrap();
    let image = Image::open_sources_with_options(
        [("concurrent.E01", source)],
        OpenOptions::default().with_reader_statistics(true),
    )
    .unwrap();
    backing.observe.store(true, Ordering::Relaxed);
    let barrier = std::sync::Barrier::new(3);
    std::thread::scope(|scope| {
        for index in 0..3 {
            let image = &image;
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                assert_eq!(image.read_at(&mut [0; 10], index * 32768).unwrap(), 10);
            });
        }
    });
    assert!(backing.peak.load(Ordering::SeqCst) > 1);
    assert!(image.reader_cache_info().table_entry_cache_current_bytes() > 0);
}

#[test]
fn concurrent_reads_of_one_chunk_share_one_decode() {
    let backing = Arc::new(ConcurrentBacking {
        bytes: image_bytes(WriteFormat::Ewf1Physical),
        active: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
        observe: AtomicBool::new(false),
    });
    let source = SegmentSource::from_backing(backing.clone()).unwrap();
    let image = Image::open_sources_with_options(
        [("coalesced.E01", source)],
        OpenOptions::default().with_reader_statistics(true),
    )
    .unwrap();
    let opened = image.reader_statistics().unwrap();
    backing.observe.store(true, Ordering::Relaxed);
    let barrier = std::sync::Barrier::new(3);
    std::thread::scope(|scope| {
        for _ in 0..3 {
            let image = &image;
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                assert_eq!(image.read_at(&mut [0; 10], 4096).unwrap(), 10);
            });
        }
    });
    let statistics = image.reader_statistics().unwrap().saturating_delta(opened);
    assert_eq!(statistics.chunk_cache_misses(), 3);
    assert_eq!(statistics.chunk_cache_coalesced(), 2);
    assert_eq!(statistics.decoded_bytes(), image.chunk_size());
}

#[test]
fn file_source_reads_match_memory_source() {
    let bytes = image_bytes(WriteFormat::Ewf2Physical);
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), bytes).unwrap();
    let image = Image::open_sources([(
        "file.Ex01",
        SegmentSource::from_file(std::fs::File::open(file.path()).unwrap()).unwrap(),
    )])
    .unwrap();
    let mut data = vec![0; 100_003];
    assert_eq!(image.read_at(&mut data, 0).unwrap(), data.len());
    assert!(data.iter().all(|byte| *byte == 0x42));
}

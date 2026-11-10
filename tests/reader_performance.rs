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

//! Deterministic reader I/O characterization tests.

use std::fs;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

use ewf_image::{EwfWriter, Image, OpenOptions, WriteCompression, WriteOptions};
use tempfile::tempdir;

const CHUNK_SIZE: usize = 512;
const CHUNK_COUNT: usize = 2_048;

#[derive(Debug, Clone, Copy, Default)]
struct ReadSnapshot {
    calls: u64,
    bytes: u64,
    four_byte_calls: u64,
    seek_from_end_calls: u64,
}

impl ReadSnapshot {
    fn delta(self, earlier: Self) -> Self {
        Self {
            calls: self.calls.saturating_sub(earlier.calls),
            bytes: self.bytes.saturating_sub(earlier.bytes),
            four_byte_calls: self.four_byte_calls.saturating_sub(earlier.four_byte_calls),
            seek_from_end_calls: self
                .seek_from_end_calls
                .saturating_sub(earlier.seek_from_end_calls),
        }
    }
}

struct CountingReader {
    cursor: Cursor<Vec<u8>>,
    counters: Arc<Mutex<ReadSnapshot>>,
}

impl Read for CountingReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.cursor.read(buffer)?;
        let mut counters = self.counters.lock().expect("counter lock poisoned");
        counters.calls = counters.calls.saturating_add(1);
        counters.bytes = counters
            .bytes
            .saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if buffer.len() == 4 {
            counters.four_byte_calls = counters.four_byte_calls.saturating_add(1);
        }
        Ok(read)
    }
}

impl Seek for CountingReader {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        if matches!(position, SeekFrom::End(_)) {
            let mut counters = self.counters.lock().expect("counter lock poisoned");
            counters.seek_from_end_calls = counters.seek_from_end_calls.saturating_add(1);
        }
        self.cursor.seek(position)
    }
}

fn synthetic_e01() -> (Vec<u8>, Vec<u8>) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("reader-performance.E01");
    let data: Vec<u8> = (0..CHUNK_SIZE * CHUNK_COUNT)
        .map(|index| (index % 251) as u8)
        .collect();
    let options = WriteOptions {
        sectors_per_chunk: 1,
        bytes_per_sector: CHUNK_SIZE as u32,
        compression: WriteCompression::None,
        ..WriteOptions::default()
    };
    let mut writer = EwfWriter::create(&path, options).unwrap();
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    (fs::read(path).unwrap(), data)
}

fn open_counted(bytes: Vec<u8>, options: OpenOptions) -> (Image, Arc<Mutex<ReadSnapshot>>) {
    let counters = Arc::new(Mutex::new(ReadSnapshot::default()));
    let reader = CountingReader {
        cursor: Cursor::new(bytes),
        counters: Arc::clone(&counters),
    };
    let image =
        Image::open_readers_with_options([("reader-performance.E01", reader)], options).unwrap();
    (image, counters)
}

fn read_chunk_starts(
    image: &Image,
    expected: &[u8],
    counters: &Arc<Mutex<ReadSnapshot>>,
) -> ReadSnapshot {
    let before = *counters.lock().expect("counter lock poisoned");
    for chunk in 0..CHUNK_COUNT {
        let offset = chunk * CHUNK_SIZE;
        let mut byte = [0];
        assert_eq!(image.read_at(&mut byte, offset as u64).unwrap(), 1);
        assert_eq!(byte[0], expected[offset]);
    }
    counters
        .lock()
        .expect("counter lock poisoned")
        .delta(before)
}

#[test]
fn table_page_cache_reduces_sequential_table_reads() {
    let (bytes, expected) = synthetic_e01();
    let (uncached, uncached_counters) = open_counted(
        bytes.clone(),
        OpenOptions::default().with_table_entry_cache_size_bytes(0),
    );
    let (cached, cached_counters) = open_counted(
        bytes,
        OpenOptions::default().with_table_entry_cache_size_bytes(4 * 1024 * 1024),
    );

    let uncached_reads = read_chunk_starts(&uncached, &expected, &uncached_counters);
    let cached_reads = read_chunk_starts(&cached, &expected, &cached_counters);

    assert!(cached_reads.calls < uncached_reads.calls);
}

#[test]
fn disabled_table_page_cache_uses_exact_table_entry_reads() {
    let (bytes, expected) = synthetic_e01();
    let (image, counters) = open_counted(
        bytes,
        OpenOptions::default().with_table_entry_cache_size_bytes(0),
    );

    let reads = read_chunk_starts(&image, &expected, &counters);

    assert!(reads.four_byte_calls > 0);
}

#[test]
fn reader_statistics_are_optional_and_shared_with_cache_information() {
    let (bytes, expected) = synthetic_e01();
    let (disabled, _) = open_counted(bytes.clone(), OpenOptions::default());
    assert!(disabled.reader_statistics().is_none());

    let options = OpenOptions::default()
        .with_chunk_cache_size_bytes(2 * CHUNK_SIZE)
        .with_table_entry_cache_size_bytes(4 * 1024 * 1024)
        .with_reader_statistics(true);
    let (image, _) = open_counted(bytes, options);
    let opened = image.reader_statistics().unwrap();
    assert_eq!(opened.segment_parses(), 1);
    assert_eq!(opened.segment_handle_opens(), 1);
    assert!(opened.table_checksum_bytes() > 0);

    let mut first = [0];
    image.read_at(&mut first, 0).unwrap();
    let mut second = [0];
    image.read_at(&mut second, 0).unwrap();
    let _cursor = image.cursor();

    let statistics = image
        .clone()
        .reader_statistics()
        .unwrap()
        .saturating_delta(opened);
    assert_eq!(first, second);
    assert_eq!(first[0], expected[0]);
    assert_eq!(statistics.cursors_created(), 1);
    assert_eq!(statistics.chunk_cache_misses(), 1);
    assert_eq!(statistics.chunk_cache_hits(), 1);
    assert_eq!(statistics.chunk_cache_coalesced(), 0);
    assert!(statistics.table_page_cache_misses() >= 1);
    assert!(statistics.table_page_cache_hits() >= 1);
    assert!(statistics.encoded_bytes_read() > 0);
    assert!(statistics.decoded_bytes() > 0);

    let cache = image.reader_cache_info();
    assert_eq!(cache.chunk_cache_capacity_bytes(), (2 * CHUNK_SIZE) as u64);
    assert_eq!(cache.table_entry_cache_capacity_bytes(), 4 * 1024 * 1024);
    assert!(cache.table_entry_cache_current_bytes() > 0);
    assert!(cache.table_entry_cache_peak_bytes() >= cache.table_entry_cache_current_bytes());
    assert!(cache.table_entry_cache_peak_bytes() <= cache.table_entry_cache_capacity_bytes());
}

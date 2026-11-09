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

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
/// Cumulative performance counters for one shared EWF image reader.
///
/// Collection is opt-in through [`crate::OpenOptions::with_reader_statistics`].
/// Cloned [`crate::Image`] values and their cursors share the same counters.
pub struct ReaderStatistics {
    cursors_created: u64,
    segment_parses: u64,
    segment_handle_opens: u64,
    segment_handle_reopens: u64,
    table_checksum_bytes: u64,
    table_checksum_nanos: u64,
    chunk_cache_hits: u64,
    chunk_cache_misses: u64,
    chunk_cache_coalesced: u64,
    table_page_cache_hits: u64,
    table_page_cache_misses: u64,
    segment_read_bytes: u64,
    segment_read_nanos: u64,
    segment_pool_wait_nanos: u64,
    encoded_bytes_read: u64,
    decoded_bytes: u64,
    decompression_nanos: u64,
}

impl ReaderStatistics {
    /// Returns the number of logical-media and single-file cursors created.
    pub fn cursors_created(&self) -> u64 {
        self.cursors_created
    }

    /// Returns the number of segment metadata parses performed while opening.
    pub fn segment_parses(&self) -> u64 {
        self.segment_parses
    }

    /// Returns the number of segment handles opened for the first time.
    pub fn segment_handle_opens(&self) -> u64 {
        self.segment_handle_opens
    }

    /// Returns the number of previously evicted segment handles reopened.
    pub fn segment_handle_reopens(&self) -> u64 {
        self.segment_handle_reopens
    }

    /// Returns the table-entry bytes processed for checksum validation.
    pub fn table_checksum_bytes(&self) -> u64 {
        self.table_checksum_bytes
    }

    /// Returns nanoseconds spent validating table-entry checksums.
    pub fn table_checksum_nanos(&self) -> u64 {
        self.table_checksum_nanos
    }

    /// Returns decoded chunk-cache hits.
    pub fn chunk_cache_hits(&self) -> u64 {
        self.chunk_cache_hits
    }

    /// Returns decoded chunk-cache misses.
    pub fn chunk_cache_misses(&self) -> u64 {
        self.chunk_cache_misses
    }

    /// Returns misses that waited for an already-running decode of the same chunk.
    pub fn chunk_cache_coalesced(&self) -> u64 {
        self.chunk_cache_coalesced
    }

    /// Returns table-entry page-cache hits.
    pub fn table_page_cache_hits(&self) -> u64 {
        self.table_page_cache_hits
    }

    /// Returns table-entry page-cache misses.
    pub fn table_page_cache_misses(&self) -> u64 {
        self.table_page_cache_misses
    }

    /// Returns bytes read from path-backed segment files after opening.
    pub fn segment_read_bytes(&self) -> u64 {
        self.segment_read_bytes
    }

    /// Returns nanoseconds spent in path-backed positioned segment reads.
    pub fn segment_read_nanos(&self) -> u64 {
        self.segment_read_nanos
    }

    /// Returns nanoseconds spent waiting for a bounded segment handle to become idle.
    pub fn segment_pool_wait_nanos(&self) -> u64 {
        self.segment_pool_wait_nanos
    }

    /// Returns encoded chunk bytes read from segment files.
    pub fn encoded_bytes_read(&self) -> u64 {
        self.encoded_bytes_read
    }

    /// Returns decoded logical chunk bytes produced.
    pub fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes
    }

    /// Returns nanoseconds spent decompressing chunks.
    pub fn decompression_nanos(&self) -> u64 {
        self.decompression_nanos
    }

    /// Returns a field-wise saturating delta from an earlier snapshot.
    #[must_use]
    pub fn saturating_delta(self, earlier: Self) -> Self {
        Self {
            cursors_created: self.cursors_created.saturating_sub(earlier.cursors_created),
            segment_parses: self.segment_parses.saturating_sub(earlier.segment_parses),
            segment_handle_opens: self
                .segment_handle_opens
                .saturating_sub(earlier.segment_handle_opens),
            segment_handle_reopens: self
                .segment_handle_reopens
                .saturating_sub(earlier.segment_handle_reopens),
            table_checksum_bytes: self
                .table_checksum_bytes
                .saturating_sub(earlier.table_checksum_bytes),
            table_checksum_nanos: self
                .table_checksum_nanos
                .saturating_sub(earlier.table_checksum_nanos),
            chunk_cache_hits: self
                .chunk_cache_hits
                .saturating_sub(earlier.chunk_cache_hits),
            chunk_cache_misses: self
                .chunk_cache_misses
                .saturating_sub(earlier.chunk_cache_misses),
            chunk_cache_coalesced: self
                .chunk_cache_coalesced
                .saturating_sub(earlier.chunk_cache_coalesced),
            table_page_cache_hits: self
                .table_page_cache_hits
                .saturating_sub(earlier.table_page_cache_hits),
            table_page_cache_misses: self
                .table_page_cache_misses
                .saturating_sub(earlier.table_page_cache_misses),
            segment_read_bytes: self
                .segment_read_bytes
                .saturating_sub(earlier.segment_read_bytes),
            segment_read_nanos: self
                .segment_read_nanos
                .saturating_sub(earlier.segment_read_nanos),
            segment_pool_wait_nanos: self
                .segment_pool_wait_nanos
                .saturating_sub(earlier.segment_pool_wait_nanos),
            encoded_bytes_read: self
                .encoded_bytes_read
                .saturating_sub(earlier.encoded_bytes_read),
            decoded_bytes: self.decoded_bytes.saturating_sub(earlier.decoded_bytes),
            decompression_nanos: self
                .decompression_nanos
                .saturating_sub(earlier.decompression_nanos),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
/// Configured and observed payload bytes for one shared EWF reader cache set.
pub struct ReaderCacheInfo {
    chunk_cache_capacity: u64,
    table_entry_cache_capacity: u64,
    table_entry_cache_current: u64,
    table_entry_cache_peak: u64,
}

impl ReaderCacheInfo {
    pub(crate) fn new(
        chunk_cache_capacity_bytes: u64,
        table_entry_cache_capacity_bytes: usize,
        table_entry_cache_current_bytes: usize,
        table_entry_cache_peak_bytes: usize,
    ) -> Self {
        Self {
            chunk_cache_capacity: chunk_cache_capacity_bytes,
            table_entry_cache_capacity: usize_to_u64(table_entry_cache_capacity_bytes),
            table_entry_cache_current: usize_to_u64(table_entry_cache_current_bytes),
            table_entry_cache_peak: usize_to_u64(table_entry_cache_peak_bytes),
        }
    }

    /// Returns the decoded chunk-cache byte capacity.
    pub fn chunk_cache_capacity_bytes(&self) -> u64 {
        self.chunk_cache_capacity
    }

    /// Returns the configured table-entry cache byte capacity.
    pub fn table_entry_cache_capacity_bytes(&self) -> u64 {
        self.table_entry_cache_capacity
    }

    /// Returns the currently retained table-entry page payload bytes.
    pub fn table_entry_cache_current_bytes(&self) -> u64 {
        self.table_entry_cache_current
    }

    /// Returns the peak retained table-entry page payload bytes.
    pub fn table_entry_cache_peak_bytes(&self) -> u64 {
        self.table_entry_cache_peak
    }
}

#[derive(Debug, Default)]
pub(crate) struct ReaderStatisticsCollector {
    enabled: bool,
    cursors_created: AtomicU64,
    segment_parses: AtomicU64,
    segment_handle_opens: AtomicU64,
    segment_handle_reopens: AtomicU64,
    table_checksum_bytes: AtomicU64,
    table_checksum_nanos: AtomicU64,
    chunk_cache_hits: AtomicU64,
    chunk_cache_misses: AtomicU64,
    chunk_cache_coalesced: AtomicU64,
    table_page_cache_hits: AtomicU64,
    table_page_cache_misses: AtomicU64,
    segment_read_bytes: AtomicU64,
    segment_read_nanos: AtomicU64,
    segment_pool_wait_nanos: AtomicU64,
    encoded_bytes_read: AtomicU64,
    decoded_bytes: AtomicU64,
    decompression_nanos: AtomicU64,
}

impl ReaderStatisticsCollector {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            ..Self::default()
        }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn snapshot(&self) -> Option<ReaderStatistics> {
        self.enabled.then(|| ReaderStatistics {
            cursors_created: self.cursors_created.load(Ordering::Relaxed),
            segment_parses: self.segment_parses.load(Ordering::Relaxed),
            segment_handle_opens: self.segment_handle_opens.load(Ordering::Relaxed),
            segment_handle_reopens: self.segment_handle_reopens.load(Ordering::Relaxed),
            table_checksum_bytes: self.table_checksum_bytes.load(Ordering::Relaxed),
            table_checksum_nanos: self.table_checksum_nanos.load(Ordering::Relaxed),
            chunk_cache_hits: self.chunk_cache_hits.load(Ordering::Relaxed),
            chunk_cache_misses: self.chunk_cache_misses.load(Ordering::Relaxed),
            chunk_cache_coalesced: self.chunk_cache_coalesced.load(Ordering::Relaxed),
            table_page_cache_hits: self.table_page_cache_hits.load(Ordering::Relaxed),
            table_page_cache_misses: self.table_page_cache_misses.load(Ordering::Relaxed),
            segment_read_bytes: self.segment_read_bytes.load(Ordering::Relaxed),
            segment_read_nanos: self.segment_read_nanos.load(Ordering::Relaxed),
            segment_pool_wait_nanos: self.segment_pool_wait_nanos.load(Ordering::Relaxed),
            encoded_bytes_read: self.encoded_bytes_read.load(Ordering::Relaxed),
            decoded_bytes: self.decoded_bytes.load(Ordering::Relaxed),
            decompression_nanos: self.decompression_nanos.load(Ordering::Relaxed),
        })
    }

    pub(crate) fn record_cursor_created(&self) {
        self.add(&self.cursors_created, 1);
    }

    pub(crate) fn record_segment_parse(&self) {
        self.add(&self.segment_parses, 1);
    }

    pub(crate) fn record_segment_handle_open(&self, count: usize) {
        self.add(&self.segment_handle_opens, usize_to_u64(count));
    }

    pub(crate) fn record_segment_handle_reopen(&self) {
        self.add(&self.segment_handle_reopens, 1);
    }

    pub(crate) fn record_table_checksum(&self, bytes: u64, elapsed: Duration) {
        self.add(&self.table_checksum_bytes, bytes);
        self.add(&self.table_checksum_nanos, duration_nanos(elapsed));
    }

    pub(crate) fn record_chunk_cache_access(&self, hit: bool) {
        if hit {
            self.add(&self.chunk_cache_hits, 1);
        } else {
            self.add(&self.chunk_cache_misses, 1);
        }
    }

    pub(crate) fn record_chunk_cache_coalesced(&self) {
        self.add(&self.chunk_cache_coalesced, 1);
    }

    pub(crate) fn record_segment_read(&self, bytes: usize, elapsed: Duration) {
        self.add(&self.segment_read_bytes, usize_to_u64(bytes));
        self.add(&self.segment_read_nanos, duration_nanos(elapsed));
    }

    pub(crate) fn record_segment_pool_wait(&self, elapsed: Duration) {
        self.add(&self.segment_pool_wait_nanos, duration_nanos(elapsed));
    }

    pub(crate) fn record_table_page_cache_access(&self, hit: bool) {
        if hit {
            self.add(&self.table_page_cache_hits, 1);
        } else {
            self.add(&self.table_page_cache_misses, 1);
        }
    }

    pub(crate) fn record_encoded_bytes_read(&self, bytes: u64) {
        self.add(&self.encoded_bytes_read, bytes);
    }

    pub(crate) fn record_decoded_bytes(&self, bytes: usize) {
        self.add(&self.decoded_bytes, usize_to_u64(bytes));
    }

    pub(crate) fn record_decompression(&self, elapsed: Duration) {
        self.add(&self.decompression_nanos, duration_nanos(elapsed));
    }

    fn add(&self, counter: &AtomicU64, value: u64) {
        if !self.enabled || value == 0 {
            return;
        }
        let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(current.saturating_add(value))
        });
    }
}

fn duration_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_addition_saturates() {
        let statistics = ReaderStatisticsCollector::new(true);
        let counter = AtomicU64::new(u64::MAX - 1);
        statistics.add(&counter, 2);
        statistics.add(&counter, 1);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn disabled_and_zero_additions_preserve_counter() {
        let counter = AtomicU64::new(42);
        ReaderStatisticsCollector::new(false).add(&counter, 5);
        ReaderStatisticsCollector::new(true).add(&counter, 0);
        assert_eq!(counter.load(Ordering::Relaxed), 42);
    }

    #[test]
    fn concurrent_additions_are_not_lost() {
        let statistics = ReaderStatisticsCollector::new(true);
        let counter = AtomicU64::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..1_000 {
                        statistics.add(&counter, 1);
                    }
                });
            }
        });
        assert_eq!(counter.load(Ordering::Relaxed), 8_000);
    }
}

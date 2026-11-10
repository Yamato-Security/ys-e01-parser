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

use std::sync::Arc;

use lru::LruCache;

pub(crate) const TABLE_PAGE_SIZE: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct TablePageKey {
    pub(crate) segment_index: usize,
    pub(crate) page_offset: u64,
}

#[derive(Debug)]
pub(crate) struct TablePageCache {
    pages: LruCache<TablePageKey, Arc<Vec<u8>>>,
    capacity_bytes: usize,
    cached_bytes: usize,
    peak_bytes: usize,
}

impl TablePageCache {
    pub(crate) fn new(capacity_bytes: usize) -> Self {
        Self {
            pages: LruCache::unbounded(),
            capacity_bytes,
            cached_bytes: 0,
            peak_bytes: 0,
        }
    }

    pub(crate) fn get(&mut self, key: &TablePageKey) -> Option<Arc<Vec<u8>>> {
        self.pages.get(key).cloned()
    }

    pub(crate) fn is_disabled(&self) -> bool {
        self.capacity_bytes == 0
    }

    pub(crate) fn insert(&mut self, key: TablePageKey, bytes: Vec<u8>) -> Arc<Vec<u8>> {
        let bytes = Arc::new(bytes);
        if self.capacity_bytes == 0 || bytes.len() > self.capacity_bytes {
            return bytes;
        }
        if let Some(previous) = self.pages.pop(&key) {
            self.cached_bytes = self.cached_bytes.saturating_sub(previous.len());
        }
        while self.cached_bytes.saturating_add(bytes.len()) > self.capacity_bytes {
            let Some((_key, evicted)) = self.pages.pop_lru() else {
                break;
            };
            self.cached_bytes = self.cached_bytes.saturating_sub(evicted.len());
        }
        self.cached_bytes = self.cached_bytes.saturating_add(bytes.len());
        self.peak_bytes = self.peak_bytes.max(self.cached_bytes);
        self.pages.put(key, Arc::clone(&bytes));
        bytes
    }

    pub(crate) fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }

    pub(crate) fn cached_bytes(&self) -> usize {
        self.cached_bytes
    }

    pub(crate) fn peak_bytes(&self) -> usize {
        self.peak_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(page_offset: u64) -> TablePageKey {
        TablePageKey {
            segment_index: 0,
            page_offset,
        }
    }

    #[test]
    fn table_page_cache_evicts_least_recently_used_pages_by_bytes() {
        let mut cache = TablePageCache::new(8);
        let first = key(0);
        let second = key(4);
        let third = key(8);

        cache.insert(first, vec![1; 4]);
        cache.insert(second, vec![2; 4]);
        assert_eq!(
            cache.get(&first).as_deref().map(Vec::as_slice),
            Some(&[1; 4][..])
        );
        cache.insert(third, vec![3; 4]);

        assert!(cache.get(&second).is_none());
        assert!(cache.get(&first).is_some());
        assert!(cache.get(&third).is_some());
        assert_eq!(cache.cached_bytes(), 8);
        assert_eq!(cache.peak_bytes(), 8);
    }

    #[test]
    fn table_page_cache_zero_capacity_does_not_retain_pages() {
        let mut cache = TablePageCache::new(0);
        let page = key(0);

        let inserted = cache.insert(page, vec![1, 2, 3, 4]);

        assert_eq!(inserted.as_slice(), &[1, 2, 3, 4]);
        assert!(cache.get(&page).is_none());
        assert_eq!(cache.cached_bytes(), 0);
        assert_eq!(cache.peak_bytes(), 0);
    }

    #[test]
    fn table_page_cache_replacement_updates_retained_bytes() {
        let mut cache = TablePageCache::new(8);
        let page = key(0);

        cache.insert(page, vec![1; 3]);
        cache.insert(page, vec![2; 5]);

        assert_eq!(cache.cached_bytes(), 5);
        assert_eq!(cache.peak_bytes(), 5);
        assert_eq!(
            cache.get(&page).as_deref().map(Vec::as_slice),
            Some(&[2; 5][..])
        );
    }
}

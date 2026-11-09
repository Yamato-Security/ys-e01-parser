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

#![no_main]
use ewf_image::{Image, OpenOptions, SegmentSource};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    let options = OpenOptions::default()
        .with_chunk_cache_size_bytes(64 * 1024)
        .with_table_entry_cache_size_bytes(64 * 1024);
    if let Ok(image) = Image::open_sources_with_options(
        [("input.E01", SegmentSource::from_bytes(data.to_vec()))],
        options,
    ) {
        let mut buffer = [0; 4096];
        for offset in [
            0,
            image.media_size() / 2,
            image.media_size().saturating_sub(1),
        ] {
            let _ = image.read_at(&mut buffer, offset);
        }
    }
});

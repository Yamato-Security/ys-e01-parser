// Copyright (C) 2026 Shirofune Security Co., Ltd.
//
// SPDX-License-Identifier: RPL-1.5 OR AGPL-3.0-only
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

//! The public images in `tests/fixtures/` read as libewf reads them: the media size, the SHA-256
//! of the whole media, and the SHA-256 of 2,000 seeded random reads (what a FUSE mount does),
//! recorded with pyewf 20260924 in `tests/fixtures/libewf.tsv`.

use std::path::Path;

use sha2::{Digest, Sha256};

/// xorshift64*, as the script that recorded libewf's reads.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn read_fully(image: &ewf_image::Image, offset: u64, buf: &mut [u8]) {
    let mut done = 0;
    while done < buf.len() {
        let n = image
            .read_at(&mut buf[done..], offset + done as u64)
            .unwrap();
        assert!(n > 0, "short read at {}", offset + done as u64);
        done += n;
    }
}

#[test]
fn public_images_read_as_libewf_reads_them() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let table = std::fs::read_to_string(root.join("libewf.tsv")).unwrap();
    let mut checked = 0;
    for line in table.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        let [file, size, total, random] = fields[..] else {
            panic!("bad line: {line}");
        };
        let image = ewf_image::Image::open(root.join(file)).unwrap();
        let size: u64 = size.parse().unwrap();
        assert_eq!(image.media_size(), size, "{file}");

        let mut digest = Sha256::new();
        let mut buf = vec![0_u8; 1 << 20];
        let mut offset = 0;
        while offset < size {
            let n = usize::try_from((size - offset).min(1 << 20)).unwrap();
            read_fully(&image, offset, &mut buf[..n]);
            digest.update(&buf[..n]);
            offset += n as u64;
        }
        assert_eq!(hex(&digest.finalize()), total, "{file}: media");

        let mut rng = Rng(42);
        let mut digest = Sha256::new();
        let mut buf = vec![0_u8; 65536];
        for _ in 0..2000 {
            let offset = rng.next() % size;
            let len = usize::try_from((1 + rng.next() % 65536).min(size - offset)).unwrap();
            read_fully(&image, offset, &mut buf[..len]);
            digest.update(&buf[..len]);
        }
        assert_eq!(hex(&digest.finalize()), random, "{file}: random reads");
        checked += 1;
    }
    assert_eq!(checked, 13);
}

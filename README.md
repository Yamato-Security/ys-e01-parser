# ys-e01-parser

Yamato Security's reader of EWF forensic images: EnCase's `.E01` (and `.S01`, `.L01`) and EWF2's
`.Ex01` (and `.Lx01`), split into segments or not. It reads them without libewf, read-only, and
leniently, so that what can be read of a damaged image is read and the damage is reported, and it
never returns bytes it could not verify. It is the E01 reader of
[Juntei](https://github.com/Yamato-Security/juntei), which mounts E01 images and scans the files in
them (`juntei mount`, `auto-parse --e01`).

It is a fork of Elijah Brigham's [ewf-image](https://github.com/ebrig/ewf-image) (at `04137ee`,
imported with its history), whose code stays under the Apache License 2.0 (see [Licence](#licence)).

| Crate | Library | What it reads |
| --- | --- | --- |
| `ys-e01-parser` | `ewf_image` | EWF1 (`.E01`, `.S01`, `.L01`) and EWF2 (`.Ex01`, `.Lx01`) segment sets: the media, its metadata and stored hashes, acquisition errors, logical file catalogs, and X-Ways encrypted EWF1 images given their password. With the `writer` feature, it also writes EWF images and acquires devices. |

```toml
[dependencies]
ewf_image = { package = "ys-e01-parser", git = "https://github.com/Yamato-Security/ys-e01-parser" }
```

```rust,no_run
use std::io::Read;

let image = ewf_image::Image::open("host1.E01")?; // finds host1.E02, host1.E03, ...
for finding in image.lenient_findings() {
    println!("{:?}: {}", finding.kind, finding.message);
}
let mut sector = [0_u8; 512];
image.cursor().read_exact(&mut sector)?; // a Read + Seek over the media
image.read_at(&mut sector, 1 << 20)?; // or read at an offset; Image is a cheap shared handle
# Ok::<(), Box<dyn std::error::Error>>(())
```

The guides in [docs/](docs/) describe ewf-image's compatibility, limitations and analysis
functions, which this fork keeps.

## Why ewf-image

Six pure-Rust EWF readers were compared with libewf (pyewf 20260924) on public images, byte by
byte: SecurityRonin's `ewf` 0.4.10, `ewf-image` 0.6.1, `sootmark-ewf` 0.1.3, `inodex` 0.1.2,
keramics' `keramics-formats` 0.0.1, and the `ewf` crate of Omer Ben-Amram's `mft`.

- **Public images:** 39 images from dfvfs, plaso, keramics, SecurityRonin's ewf-forensic,
  Sootmark's ewf, Velociraptor, `mft`, ewf-image's X-Ways encrypted samples and Digital Corpora,
  including three Windows disks of 10 to 40 GiB in one to three segments. `ewf-image` read every
  byte as libewf did, except one image whose last chunk decodes to more bytes than the media needs
  (fixed here), two X-Ways encrypted images (which need their password) and two crafted fuzz
  files.
- **Damaged images:** 750 copies of five images (four EWF1 images written by libewf's tools, one
  of them split in 8 segments, and an Ex01 written by EnCase 7) with bits flipped, 32-bit fields
  overwritten or segments cut short, each read in 32 KiB units and compared with the undamaged
  image:

| Reader | Opened | Images with units read wrong without an error | Crashes |
| --- | ---: | ---: | ---: |
| libewf | 570 | 373 | 0 |
| SecurityRonin `ewf` | 702 | 328 | 12 (allocation aborts) |
| `ewf-image` | 402 | 0 | 0 |
| `sootmark-ewf` | 451 | 0 | 0 |
| `inodex` | 337 | 0 | 0 |
| `mft`'s `ewf` | 488 | 136 | 0 |
| `keramics-formats` | 346 | 276 | 0 |
| **this fork** | **749** | **0** | **0** |

`ewf-image` was the only complete reader that never returned wrong bytes: libewf and three others
return damaged or misplaced data as if it were the media. It refused to open many damaged images
instead, which is what this fork changes.

## Changes from ewf-image

- **Lenient by default.** `OpenOptions::default()` is lenient. Damage that the data can still be
  checked without is gone past and reported by `Image::lenient_findings` (and first in
  `Image::analyze`): a truncated segment keeps its complete sections, and its chunks are found
  by decoding them in order when its tables were lost; a damaged volume, data or table section
  uses its intact copy (`table2`, the other geometry section, a later segment's); a damaged
  section descriptor is followed when its offsets agree with the file; damaged hash, digest and
  header sections are left out. A chunk that can't be verified (zlib's Adler-32, a raw chunk's
  checksum) fails when read, and nothing else is substituted. When a table's entries fail their
  checksum and no intact copy exists, reads through that table also fail: a payload checksum
  verifies bytes, not their logical position in the image. `OpenStrictness::Strict` keeps
  ewf-image's behaviour.
- **An overlong last chunk**, which some writers store with more bytes than the media needs, gives
  the media's bytes with an `OverlongChunk` warning instead of failing. A raw one is first checked
  against its checksum over the whole stored chunk, which ewf-image didn't check.
- **EWF2 metadata compressed with a small zlib window** is decompressed, not read as text.
- **Read-only by default.** Writing EWF images and acquiring devices is behind the `writer`
  feature, which readers of evidence leave off. The images it reads are only opened for reading.
- **Only the library.** ewf-image's command-line tool (`ewf-cli`, which acquires, converts and
  collects) and its experimental AFF4 crate are not kept.
- Named `ys-e01-parser` 1.0.0 (its library keeps the name `ewf_image`), Rust 1.99, under the RPL.

## Validation

- **Against libewf:** `tests/oracle.rs` reads 13 public images in [tests/fixtures/](tests/fixtures/)
  (EnCase 5 and 6, `ewfacquire`, split sets, Ex01 compressed and not) and compares the media size,
  the SHA-256 of the whole media and of 2,000 seeded random reads with libewf's.
- **Damaged images:** the 750 copies above and 1,010 more (including multi-segment EWF1 and EWF2
  images), read with overflow checks on: no panic, no wrong data; 1,754 of the 1,760 open.
  `tests/lenient.rs` checks each case the fork goes past.
- **The upstream tests:** `cargo test --all-features` runs ewf-image's tests too (668 in all).

One thing found on the way: libewf reads 3 chunks of an image written by the `writer` feature as
zeros, where the Rust readers read the bytes that were written. Images written by libewf's
`ewfacquire` read the same in both.

## Licence

ys-e01-parser is copyright Shirofune Security Co., Ltd. and released under the [Reciprocal Public
License 1.5](LICENSE) (RPL-1.5) or, at your choice, the [GNU Affero General Public License, version 3
only](LICENSE-AGPL-3.0) (AGPL-3.0-only), so that both Juntei (RPL) and
[Hayabusa](https://github.com/Yamato-Security/hayabusa) (AGPL) can use it. It is changed from
[ebrig/ewf-image](https://github.com/ebrig/ewf-image) (copyright Elijah Brigham), whose code stays
under the Apache License 2.0 ([LICENSE-APACHE](LICENSE-APACHE)): each Rust file from it says so in
its header, and the crate is `(RPL-1.5 OR AGPL-3.0-only) AND Apache-2.0`. The test images keep
their licences, given in [tests/fixtures/README.md](tests/fixtures/README.md).

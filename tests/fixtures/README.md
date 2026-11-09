# Test images

Public EWF images that `tests/oracle.rs` reads and compares with what libewf (pyewf 20260924) read
from them: the media size, the SHA-256 of the whole media and of 2,000 seeded random reads
(`libewf.tsv`). Each keeps its source's licence.

| Directory | Source | Licence | What |
| --- | --- | --- | --- |
| `dfvfs/` | [log2timeline/dfvfs](https://github.com/log2timeline/dfvfs) `test_data/` | Apache-2.0 | ext2 volume; split in two segments |
| `plaso/` | [log2timeline/plaso](https://github.com/log2timeline/plaso) `test_data/` | Apache-2.0 | small disks; split in two segments |
| `keramics/` | [keramics/keramics](https://github.com/keramics/keramics) `test_data/ewf/` | Apache-2.0 | the same ext2 volume as EWF1 and EWF2 (Ex01) |
| `sootmark/` | [Sootmark/ewf](https://github.com/Sootmark/ewf) `tests/fixtures/` | MIT OR Apache-2.0 | EnCase 5 and 6 profiles; split in two segments |
| `ewf-forensic/` | [SecurityRonin/ewf-forensic](https://github.com/SecurityRonin/ewf-forensic) `core/tests/data/` | Apache-2.0 | libewf's ewfacquire output; Ex01, compressed and not |
| `digitalcorpora/` | [Digital Corpora](https://digitalcorpora.org/corpora/disk-images/) `nps-2010-emails`, as copied in SecurityRonin/ewf-forensic | Public domain (an NPS test disk image; Digital Corpora's terms: CC0) | a small disk image of e-mail files |

| File | SHA-256 |
| --- | --- |
| `dfvfs/ext2.E01` | `ab9ea9a4951b74c37025ba40a978e85b1e4a0d94438080afb636144170d3f35b` |
| `dfvfs/ext2.split.E01` | `d14f130c462b0ab8efb6bb44bbfe5680e00ffaa90538cde84579d1eb0dcac00f` |
| `dfvfs/ext2.split.E02` | `b508375954ec1d1caeed8a6e5fc503f98493816ad6a3af89f5d220244c5f2864` |
| `digitalcorpora/nps-2010-emails.E01` | `c9ffd969954c2f9b9f97f459916c3d2e8755f596eda952c306ab3f9bc0d43bf1` |
| `ewf-forensic/ewfacquire_clean.E01` | `51a5ee7b3256cafc911205f2636a9f3b6a6e759162912317a52c98d0685b2b8e` |
| `ewf-forensic/zeros_128s_compressed.Ex01` | `0c42ae1635b486bdc4844a9f291af9ca44beaf173362bce76f315e248fa1c833` |
| `ewf-forensic/zeros_128s.Ex01` | `870747746a87b3f08c7b26f6d11b58209a924372b4e8d275a8484f172f86b309` |
| `keramics/ext2.E01` | `474ef7a9bbfd5e1b95098614c9e4693012458d8b60f5597def7f5104a9a81125` |
| `keramics/ext2.Ex01` | `1a63777e7e5e4185b8c7fb15e80175fae76f296265e23175011e1aa343e4ec34` |
| `plaso/image.E01` | `00f41c8cfa87f2aedfe81f9de3a28d1c6eb0d43e0d47ec4592f80cca3ada7868` |
| `plaso/image-split.E01` | `0e3ad47cc5f61c1d7851a6ccbb0dbbc97834b93f2fa8033a5b99a5a154f579bc` |
| `plaso/image-split.E02` | `9f39804fa373b536802793e0783da801d9dafb882d4b632fe7706a6ae999b91a` |
| `sootmark/encase5-fast.E01` | `1e6cd0ae6da843033770b339a7d873ad3e0144fba45f56494cfc84ac057fb131` |
| `sootmark/encase6-best.E01` | `d2ba20ffb03cce06994ba10926e152e02aff6f76cf020cab9801353ae850dc33` |
| `sootmark/encase6-split.E01` | `a837ad5ca43aefb82bf1740863b9e5db202ceecba7e78402c3ac1579693c76b5` |
| `sootmark/encase6-split.E02` | `2bda2bcef9c2e99fa1a1c0d60c252ae5e5eddf4d2c8cea512ddeb907c8a25e85` |

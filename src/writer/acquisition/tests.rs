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

use super::*;
use crate::Image;

const ID: [u8; 32] = [0x21; 32];
const SIZE: usize = 9 * 1024 + 512;

fn options() -> AcquisitionOptions {
    AcquisitionOptions {
        sectors_per_chunk: 2,
        chunks_per_segment: 3,
        ..AcquisitionOptions::new(SIZE as u64)
    }
}

fn input() -> Vec<u8> {
    (0..SIZE)
        .map(|index| (index * 71 + index / 11) as u8)
        .collect()
}

pub(super) fn crash_at(point: &str, index: usize) {
    if std::env::var("EWF_ACQUISITION_CRASH_POINT")
        .is_ok_and(|value| value == format!("{point}:{index}"))
    {
        std::process::exit(77);
    }
}

#[test]
fn acquisition_crash_worker() {
    let Some(path) = std::env::var_os("EWF_ACQUISITION_CRASH_OUTPUT") else {
        return;
    };
    let mut writer = AcquisitionWriter::create(Path::new(&path), &options(), ID).unwrap();
    writer.write_all(&input()).unwrap();
    writer.finish().unwrap();
    panic!("crash point was not reached");
}

#[test]
fn process_exit_at_each_checkpoint_and_publication_boundary() {
    let points = [
        ("segment-synced:1", 0),
        ("segment-installed:1", 0),
        ("record-installed:1", 3072),
        ("checkpoint-synced:1", 3072),
        ("segment-synced:2", 3072),
        ("segment-installed:2", 3072),
        ("record-installed:2", 6144),
        ("checkpoint-synced:2", 6144),
        ("publishing:0", SIZE as u64),
        ("linked:1", SIZE as u64),
        ("linked:2", SIZE as u64),
        ("linked:3", SIZE as u64),
        ("linked:4", SIZE as u64),
        ("published:0", SIZE as u64),
        ("retired:0", SIZE as u64),
    ];
    for (point, offset) in points {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("case.E01");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "writer::acquisition::tests::acquisition_crash_worker",
                "--nocapture",
            ])
            .env("EWF_ACQUISITION_CRASH_OUTPUT", &path)
            .env("EWF_ACQUISITION_CRASH_POINT", point)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(77),
            "{point}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if point != "retired:0" {
            assert!(
                Image::open(&path).is_err(),
                "pending output opened at {point}"
            );
            let mut resumed = AcquisitionWriter::resume(&path, &options(), ID)
                .unwrap_or_else(|error| panic!("{point}: {error}"));
            assert_eq!(resumed.position(), offset, "{point}");
            resumed.write_all(&input()[offset as usize..]).unwrap();
            resumed.finish().unwrap();
        }
        let image = Image::open(&path).unwrap();
        let mut bytes = Vec::new();
        image.cursor().read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, input(), "{point}");
        #[cfg(feature = "verify")]
        {
            let result = image.verify().unwrap();
            assert_eq!(result.md5_match, Some(true), "{point}");
            assert_eq!(result.sha1_match, Some(true), "{point}");
            assert_eq!(result.sha256_match, Some(true), "{point}");
        }
    }
}

#[test]
fn failed_seal_poisoning_and_resume_keep_prior_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.E01");
    let mut writer = AcquisitionWriter::create(&path, &options(), ID).unwrap();
    let bytes = input();
    writer.write_all(&bytes[..3072]).unwrap();
    writer.fail_seal = true;
    assert!(writer.write_all(&bytes[3072..6144]).is_err());
    assert_eq!(writer.checkpoint_offset(), 3072);
    assert!(writer.write_all(&[0]).is_err());
    assert!(writer.checkpoint().is_err());
    assert!(writer.finish().is_err());
    let mut writer = AcquisitionWriter::resume(&path, &options(), ID).unwrap();
    assert_eq!(writer.position(), 3072);
    writer.write_all(&bytes[3072..]).unwrap();
    writer.finish().unwrap();
    let mut actual = Vec::new();
    Image::open(&path)
        .unwrap()
        .cursor()
        .read_to_end(&mut actual)
        .unwrap();
    assert_eq!(actual, bytes);
}

#[test]
fn chunk_buffers_and_scratch_stay_within_one_segment() {
    for compression in [WriteCompression::None, WriteCompression::Zlib] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("case.E01");
        let mut options = options();
        options.source_size = 256 * 1024;
        options.compression = compression;
        let mut writer = AcquisitionWriter::create(&path, &options, ID).unwrap();
        let bytes = [0x42; 512];
        for _ in 0..512 {
            writer.write_all(&bytes).unwrap();
            assert!(writer.pending.capacity() <= 1024);
            assert!(writer.pending.len() < 1024);
            assert_eq!(writer.chunks.capacity(), 3);
            assert!(writer.chunks.len() < 3);
            let spool = writer.spool.as_ref().unwrap();
            assert!(spool.len < 3 * (1024 + 128));
            assert_eq!(spool.file.as_file().metadata().unwrap().len(), spool.len);
        }
        assert_eq!(writer.sealed_segments(), 86);
        writer.finish().unwrap();
    }
}

#[test]
fn interrupted_publication_preserves_conflicting_output() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.E01");
    let mut writer = AcquisitionWriter::create(&path, &options(), ID).unwrap();
    writer.write_all(&input()).unwrap();
    let state = writer.state.clone();
    // Simulate interruption after the publication decision but before all links.
    atomic_file(&state.join("scratch"), &state.join("publishing"), &[]).unwrap();
    fs::hard_link(state.join("case.E01"), &path).unwrap();
    let collision = path.with_extension("E02");
    fs::write(&collision, b"unrelated output").unwrap();
    assert!(writer.finish().is_err());
    assert_eq!(fs::read(&collision).unwrap(), b"unrelated output");
    assert!(Image::open(&path).is_err());
    fs::remove_file(collision).unwrap();
    AcquisitionWriter::resume(&path, &options(), ID)
        .unwrap()
        .finish()
        .unwrap();
    let mut actual = Vec::new();
    Image::open(&path)
        .unwrap()
        .cursor()
        .read_to_end(&mut actual)
        .unwrap();
    assert_eq!(actual, input());
}

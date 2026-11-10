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

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::format::{ewf1, ewf2};
use crate::{EwfError, Result};

pub(crate) fn segment_dir(first: &Path) -> &Path {
    match first.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

pub(crate) fn discover_segments(first: &Path) -> Result<Vec<PathBuf>> {
    let stem = first
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| EwfError::NoSegments(first.display().to_string()))?;
    let ext = first
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("E01");
    let Some(prefix) = ext.chars().next().map(|ch| ch.to_ascii_uppercase()) else {
        return Err(EwfError::NoSegments(first.display().to_string()));
    };
    let is_v2 = ext.chars().count() == 4;
    let expected_signature = expected_segment_signature(prefix, is_v2);
    let parent = segment_dir(first);
    let requested_name = first.file_name();
    let mut segments = Vec::new();

    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let path = entry.path();
        if path.file_stem().and_then(|value| value.to_str()) != Some(stem) {
            continue;
        }

        let Some(candidate_ext) = path.extension().and_then(|value| value.to_str()) else {
            continue;
        };
        if !is_segment_extension(candidate_ext, prefix, is_v2) {
            continue;
        }

        if is_discoverable_segment(requested_name, &path, expected_signature)? {
            segments.push(path);
        }
    }

    if segments.is_empty() {
        return Err(EwfError::NoSegments(first.display().to_string()));
    }

    segments.sort_by(|left, right| {
        extension_key(left)
            .cmp(&extension_key(right))
            .then_with(|| left.file_name().cmp(&right.file_name()))
    });

    Ok(segments)
}

fn extension_key(path: &Path) -> String {
    path.extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_uppercase()
}

pub(crate) fn is_segment_extension(ext: &str, prefix: char, is_v2: bool) -> bool {
    let chars: Vec<char> = ext.chars().collect();
    if is_v2 {
        chars.len() == 4 && v2_segment_extension_matches(&chars, prefix)
    } else {
        chars.len() == 3 && v1_segment_extension_matches(&chars, prefix)
    }
}

fn v2_segment_extension_matches(chars: &[char], first_prefix: char) -> bool {
    if !chars[0].eq_ignore_ascii_case(&first_prefix) {
        return false;
    }

    match chars[1].to_ascii_lowercase() {
        'x' => segment_suffix_matches(&chars[2..4]),
        'y' | 'z' => chars[2..4].iter().all(char::is_ascii_alphabetic),
        _ => false,
    }
}

fn v1_segment_extension_matches(chars: &[char], first_prefix: char) -> bool {
    let candidate_prefix = chars[0].to_ascii_uppercase();
    let first_prefix = first_prefix.to_ascii_uppercase();

    if candidate_prefix == first_prefix {
        return segment_suffix_matches(&chars[1..3]);
    }

    first_prefix.is_ascii_uppercase()
        && candidate_prefix > first_prefix
        && candidate_prefix <= 'Z'
        && chars[1..3].iter().all(char::is_ascii_alphabetic)
}

fn expected_segment_signature(prefix: char, is_v2: bool) -> [u8; 8] {
    if is_v2 {
        if prefix.eq_ignore_ascii_case(&'L') {
            ewf2::LEF2_SIGNATURE
        } else {
            ewf2::EX01_SIGNATURE
        }
    } else if prefix.eq_ignore_ascii_case(&'L') {
        ewf1::LVF_SIGNATURE
    } else {
        ewf1::EVF_SIGNATURE
    }
}

fn segment_suffix_matches(chars: &[char]) -> bool {
    chars.len() == 2
        && (chars.iter().all(char::is_ascii_digit) || chars.iter().all(char::is_ascii_alphabetic))
}

fn is_discoverable_segment(
    requested_name: Option<&std::ffi::OsStr>,
    candidate: &Path,
    expected_signature: [u8; 8],
) -> Result<bool> {
    if candidate.file_name() == requested_name {
        return Ok(true);
    }

    let mut file = File::open(candidate)?;
    let mut signature = [0; 8];
    file.read_exact(&mut signature)?;

    Ok(signature == expected_signature)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};

    use tempfile::TempDir;

    use super::*;
    use crate::format::ewf1::{EVF_SIGNATURE, LVF_SIGNATURE};
    use crate::format::ewf2::{EX01_SIGNATURE, LEF2_SIGNATURE};

    fn current_dir_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct CurrentDirGuard {
        original: PathBuf,
    }

    impl CurrentDirGuard {
        fn enter(path: &Path) -> Self {
            let original = std::env::current_dir().unwrap();
            std::env::set_current_dir(path).unwrap();
            Self { original }
        }
    }

    impl Drop for CurrentDirGuard {
        fn drop(&mut self) {
            std::env::set_current_dir(&self.original).unwrap();
        }
    }

    fn write_file(path: &Path, bytes: &[u8]) {
        let mut file = File::create(path).unwrap();
        file.write_all(bytes).unwrap();
    }

    fn write_signature(path: &Path, signature: [u8; 8]) {
        let mut bytes = signature.to_vec();
        bytes.extend_from_slice(b"segment data");
        write_file(path, &bytes);
    }

    #[test]
    fn segment_dir_maps_bare_filename_to_current_directory() {
        assert_eq!(segment_dir(Path::new("image.E01")), Path::new("."));
        assert_eq!(segment_dir(Path::new("case/image.E01")), Path::new("case"));
    }

    #[test]
    fn discovers_v1_segments_sorted_and_filters_false_positive_extensions() {
        let dir = TempDir::new().unwrap();
        let first = dir.path().join("image.E01");
        write_signature(&first, EVF_SIGNATURE);
        write_signature(&dir.path().join("image.E02"), EVF_SIGNATURE);
        write_signature(&dir.path().join("image.EAA"), EVF_SIGNATURE);
        write_file(&dir.path().join("image.EXE"), b"MZnot ewf");
        write_signature(&dir.path().join("other.E03"), EVF_SIGNATURE);

        let segments = discover_segments(&first).unwrap();
        let names: Vec<_> = segments
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();

        assert_eq!(names, ["image.E01", "image.E02", "image.EAA"]);
    }

    #[test]
    fn discovers_v1_continuation_extension_after_ezz() {
        let dir = TempDir::new().unwrap();
        let first = dir.path().join("image.EZZ");
        write_signature(&first, EVF_SIGNATURE);
        write_signature(&dir.path().join("image.F01"), EVF_SIGNATURE);
        write_signature(&dir.path().join("image.FAA"), EVF_SIGNATURE);

        let segments = discover_segments(&first).unwrap();
        let names: Vec<_> = segments
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();

        assert_eq!(names, ["image.EZZ", "image.FAA"]);
    }

    #[test]
    fn discovers_v1_logical_lvf_segments() {
        let dir = TempDir::new().unwrap();
        let first = dir.path().join("logical.L01");
        write_signature(&first, LVF_SIGNATURE);
        write_signature(&dir.path().join("logical.L02"), LVF_SIGNATURE);

        let segments = discover_segments(&first).unwrap();

        assert_eq!(segments.len(), 2);
    }

    #[test]
    fn discovers_v1_logical_continuation_extension_after_lzz() {
        let dir = TempDir::new().unwrap();
        let first = dir.path().join("logical.LZZ");
        write_signature(&first, LVF_SIGNATURE);
        write_signature(&dir.path().join("logical.MAA"), LVF_SIGNATURE);
        write_signature(&dir.path().join("logical.MAB"), EVF_SIGNATURE);

        let segments = discover_segments(&first).unwrap();
        let names: Vec<_> = segments
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();

        assert_eq!(names, ["logical.LZZ", "logical.MAA"]);
    }

    #[test]
    fn discovers_v1_smart_continuation_extension_after_szz() {
        let dir = TempDir::new().unwrap();
        let first = dir.path().join("smart.sZZ");
        write_signature(&first, EVF_SIGNATURE);
        write_signature(&dir.path().join("smart.t01"), EVF_SIGNATURE);
        write_signature(&dir.path().join("smart.taa"), EVF_SIGNATURE);

        let segments = discover_segments(&first).unwrap();
        let names: Vec<_> = segments
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();

        assert_eq!(names, ["smart.sZZ", "smart.taa"]);
    }

    #[test]
    fn discovers_v2_physical_and_logical_segments() {
        let dir = TempDir::new().unwrap();
        let physical = dir.path().join("physical.Ex01");
        write_signature(&physical, EX01_SIGNATURE);
        write_signature(&dir.path().join("physical.Ex02"), EX01_SIGNATURE);

        let logical = dir.path().join("logical.Lx01");
        write_signature(&logical, LEF2_SIGNATURE);
        write_signature(&dir.path().join("logical.Lx02"), LEF2_SIGNATURE);

        assert_eq!(discover_segments(&physical).unwrap().len(), 2);
        assert_eq!(discover_segments(&logical).unwrap().len(), 2);
    }

    #[test]
    fn discovers_v2_continuation_extension_after_exzz() {
        let dir = TempDir::new().unwrap();
        let first = dir.path().join("image.ExZZ");
        write_signature(&first, EX01_SIGNATURE);
        write_signature(&dir.path().join("image.Ey01"), EX01_SIGNATURE);
        write_signature(&dir.path().join("image.EyAA"), EX01_SIGNATURE);

        let segments = discover_segments(&first).unwrap();
        let names: Vec<_> = segments
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();

        assert_eq!(names, ["image.ExZZ", "image.EyAA"]);
    }

    #[test]
    fn discovers_v2_logical_continuation_extension_after_lxzz() {
        let dir = TempDir::new().unwrap();
        let first = dir.path().join("logical.LxZZ");
        write_signature(&first, LEF2_SIGNATURE);
        write_signature(&dir.path().join("logical.Ly01"), LEF2_SIGNATURE);
        write_signature(&dir.path().join("logical.LyAA"), LEF2_SIGNATURE);

        let segments = discover_segments(&first).unwrap();
        let names: Vec<_> = segments
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();

        assert_eq!(names, ["logical.LxZZ", "logical.LyAA"]);
    }

    #[test]
    fn handles_parent_paths_with_glob_metacharacters_literally() {
        let dir = TempDir::new().unwrap();
        let evidence_dir = dir.path().join("case[abc]");
        fs::create_dir(&evidence_dir).unwrap();
        let first = evidence_dir.join("image.E01");
        write_signature(&first, EVF_SIGNATURE);

        let segments = discover_segments(&first).unwrap();

        assert_eq!(segments, [first]);
    }

    #[test]
    fn bare_filename_discovers_current_directory_segment() {
        let _lock = current_dir_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        write_signature(&dir.path().join("image.E01"), EVF_SIGNATURE);
        let _guard = CurrentDirGuard::enter(dir.path());

        let segments = discover_segments(Path::new("image.E01")).unwrap();

        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].file_name().unwrap(), "image.E01");
    }

    #[test]
    fn reports_unreadable_matching_segment_candidate() {
        let dir = TempDir::new().unwrap();
        let first = dir.path().join("image.E01");
        write_signature(&first, EVF_SIGNATURE);
        fs::create_dir(dir.path().join("image.E02")).unwrap();

        let err = discover_segments(&first).unwrap_err();

        assert!(matches!(err, EwfError::Io(_)));
    }
}

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

//! Recoverable publication of one or two file-backed segment sets.
//!
//! Backups are retained until every set has been published. The primary journal
//! holds the decision; cleanup removes the secondary journal before the primary.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::{EwfError, Result};

pub(crate) struct Publication {
    sets: Vec<Set>,
    prepared: bool,
    allow_replace: bool,
    #[cfg(test)]
    fail_after: Option<usize>,
}

struct Set {
    first: PathBuf,
    journal: PathBuf,
    // A persistent lock file avoids unlink/recreate races between processes.
    _lock: OutputLock,
}

impl Publication {
    pub(crate) fn begin(
        first: &Path,
        secondary: Option<&Path>,
        allow_replace: bool,
    ) -> Result<Self> {
        let mut publication = Self {
            sets: Vec::new(),
            prepared: false,
            allow_replace,
            #[cfg(test)]
            fail_after: None,
        };
        let paths = normalized_paths(first, secondary)?;
        for path in &paths {
            let set = Set::lock(path)?;
            ensure_no_acquisition(path)?;
            fs::create_dir(&set.journal).map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    EwfError::Unsupported(
                        "unfinished output publication; call EwfWriter::recover_output first"
                            .into(),
                    )
                } else {
                    error.into()
                }
            })?;
            publication.sets.push(set);
        }
        let identity = identity(&paths);
        for set in &publication.sets {
            for name in ["new", "old", "absent", "restore"] {
                fs::create_dir(set.journal.join(name))?;
            }
            write_synced(&set.journal.join("identity"), &identity)?;
            sync_dir(&set.journal)?;
            sync_dir(crate::segment::segment_dir(&set.first))?;
        }
        Ok(publication)
    }

    pub(crate) fn stage(&self, set: usize, target: &Path) -> Result<PathBuf> {
        self.sets[set].child("new", target)
    }

    pub(crate) fn publish(
        &mut self,
        destinations: &[Vec<PathBuf>],
        written_count: usize,
    ) -> Result<()> {
        self.prepare(destinations, written_count)?;
        let result = self.install(destinations, written_count);
        if result.is_err() {
            // Keep journals if rollback itself fails. Explicit recovery is idempotent.
            self.rollback()?;
        }
        result?;
        write_synced(&self.sets[0].journal.join("committed"), &[])?;
        sync_dir(&self.sets[0].journal)?;
        self.cleanup()
    }

    fn prepare(&mut self, destinations: &[Vec<PathBuf>], written_count: usize) -> Result<()> {
        // Every staged file is complete before taking backups or modifying output.
        for (set, paths) in self.sets.iter().zip(destinations) {
            for path in paths.iter().take(written_count) {
                if !fs::symlink_metadata(set.child("new", path)?)?
                    .file_type()
                    .is_file()
                {
                    return Err(EwfError::Malformed(
                        "staged segment is not a regular file".into(),
                    ));
                }
            }
            for path in paths {
                let old = set.child("old", path)?;
                match fs::symlink_metadata(path) {
                    Ok(metadata) if metadata.file_type().is_file() => {
                        if !self.allow_replace {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::AlreadyExists,
                                "output exists; enable overwrite_existing to replace it",
                            )
                            .into());
                        }
                        fs::copy(path, &old)?;
                        OpenOptions::new().write(true).open(&old)?.sync_all()?;
                    }
                    Ok(_) => {
                        return Err(EwfError::Unsupported(
                            "output segment is not a regular file".into(),
                        ));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        write_synced(&set.child("absent", path)?, &[])?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            for directory in ["new", "old", "absent"] {
                sync_dir(&set.journal.join(directory))?;
            }
        }
        write_synced(&self.sets[0].journal.join("ready"), &[])?;
        sync_dir(&self.sets[0].journal)?;
        self.prepared = true;
        Ok(())
    }

    fn install(&self, destinations: &[Vec<PathBuf>], written_count: usize) -> Result<()> {
        #[cfg(test)]
        let mut installed = 0;
        for (set, paths) in self.sets.iter().zip(destinations) {
            for (index, path) in paths.iter().enumerate() {
                #[cfg(test)]
                {
                    if self.fail_after == Some(installed) {
                        return Err(
                            std::io::Error::other("injected publication write failure").into()
                        );
                    }
                    installed += 1;
                }
                let staged = set.child("new", path)?;
                if index < written_count {
                    fs::rename(staged, path)?;
                } else {
                    remove_if_present(path)?;
                }
            }
            sync_dir(crate::segment::segment_dir(&set.first))?;
        }
        Ok(())
    }

    fn rollback(&self) -> Result<()> {
        for set in &self.sets {
            for old in files(&set.journal.join("old"))? {
                let target = set.target(&old)?;
                let restore = set.child("restore", &target)?;
                fs::copy(old, &restore)?;
                OpenOptions::new().write(true).open(&restore)?.sync_all()?;
                fs::rename(restore, target)?;
            }
            for absent in files(&set.journal.join("absent"))? {
                remove_if_present(&set.target(&absent)?)?;
            }
            sync_dir(crate::segment::segment_dir(&set.first))?;
        }
        write_synced(&self.sets[0].journal.join("rolled-back"), &[])?;
        sync_dir(&self.sets[0].journal)?;
        self.cleanup()
    }

    fn cleanup(&self) -> Result<()> {
        for set in self.sets.iter().rev() {
            if set.journal.try_exists()? {
                // Removing the journal from its well-known name is the cleanup
                // commit point. Interrupted deletion can only leave inert garbage.
                let garbage = tempfile::Builder::new()
                    .prefix(".ewf-cleanup-")
                    .tempdir_in(crate::segment::segment_dir(&set.first))?;
                let retired = garbage.path().join("retired");
                fs::rename(&set.journal, &retired)?;
                sync_dir(crate::segment::segment_dir(&set.first))?;
                garbage.close()?;
            }
        }
        Ok(())
    }

    pub(crate) fn recover(first: &Path, secondary: Option<&Path>) -> Result<bool> {
        let paths = normalized_paths(first, secondary)?;
        let expected = identity(&paths);
        let mut sets = Vec::new();
        for path in &paths {
            sets.push(Set::lock(path)?);
        }
        let primary = &sets[0].journal;
        if !primary.try_exists()? {
            if sets.iter().skip(1).any(|set| set.journal.exists()) {
                return Err(EwfError::Malformed(
                    "secondary journal exists without its primary".into(),
                ));
            }
            return Ok(false);
        }
        validate_directory(primary)?;
        let decided =
            primary.join("committed").try_exists()? || primary.join("rolled-back").try_exists()?;
        let ready = primary.join("ready").try_exists()?;
        for set in &sets {
            if !set.journal.try_exists()? && (decided || !ready) {
                continue;
            }
            let identity_path = set.journal.join("identity");
            if !identity_path.try_exists()? && !ready {
                continue;
            }
            validate_directory(&set.journal)?;
            let metadata = fs::symlink_metadata(&identity_path)?;
            if !metadata.file_type().is_file() || metadata.len() != 32 {
                return Err(EwfError::Malformed("invalid publication identity".into()));
            }
            if fs::read(identity_path)? != expected {
                return Err(EwfError::Malformed(
                    "publication recovery requires the original primary and secondary paths".into(),
                ));
            }
            if ready && !decided {
                for name in ["new", "old", "absent", "restore"] {
                    validate_directory(&set.journal.join(name))?;
                }
                for name in ["old", "absent"] {
                    for entry in files(&set.journal.join(name))? {
                        set.target(&entry)?;
                    }
                }
            }
        }
        let publication = Self {
            sets,
            prepared: true,
            allow_replace: true,
            #[cfg(test)]
            fail_after: None,
        };
        if decided || !ready {
            publication.cleanup()?;
        } else {
            publication.rollback()?;
        }
        Ok(true)
    }
}

impl Drop for Publication {
    fn drop(&mut self) {
        if !self.prepared {
            let _ = self.cleanup();
        }
    }
}

impl Set {
    fn lock(first: &Path) -> Result<Self> {
        let journal = journal_path(first)?;
        Ok(Self {
            first: first.into(),
            journal,
            _lock: OutputLock::acquire(first)?,
        })
    }

    fn child(&self, directory: &str, target: &Path) -> Result<PathBuf> {
        let name = target
            .file_name()
            .ok_or_else(|| EwfError::Malformed("missing segment filename".into()))?;
        let child = self.journal.join(directory).join(name);
        self.target(&child)?;
        Ok(child)
    }

    fn target(&self, entry: &Path) -> Result<PathBuf> {
        let name = entry
            .file_name()
            .ok_or_else(|| EwfError::Malformed("missing journal filename".into()))?;
        let target = crate::segment::segment_dir(&self.first).join(name);
        let extension = target
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        let first_extension = self
            .first
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        let prefix = first_extension.chars().next().unwrap_or('E');
        if target.file_stem() != self.first.file_stem()
            || !crate::segment::is_segment_extension(extension, prefix, first_extension.len() == 4)
        {
            return Err(EwfError::Malformed(
                "invalid segment filename in publication journal".into(),
            ));
        }
        Ok(target)
    }
}

pub(crate) struct OutputLock(File);

impl OutputLock {
    pub(crate) fn acquire(first: &Path) -> Result<Self> {
        let lock_path = journal_path(first)?.with_extension("lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        lock.try_lock().map_err(|error| {
            EwfError::Unsupported(format!("output publication is busy: {error}"))
        })?;
        Ok(Self(lock))
    }
}

impl Drop for OutputLock {
    fn drop(&mut self) {
        // Explicit unlock also releases an inherited flock description during
        // a concurrent fork/exec, rather than waiting for the child to close it.
        let _ = self.0.unlock();
    }
}

fn journal_path(first: &Path) -> Result<PathBuf> {
    let mut name = std::ffi::OsString::from(".");
    name.push(
        first
            .file_name()
            .ok_or_else(|| EwfError::Malformed("missing output filename".into()))?,
    );
    name.push(".ewf-publication");
    Ok(first.with_file_name(name))
}

pub(crate) fn ensure_no_pending(first: &Path) -> Result<()> {
    ensure_no_acquisition(first)?;
    ensure_no_publication(first)
}

pub(crate) fn acquisition_path(first: &Path) -> Result<PathBuf> {
    Ok(journal_path(first)?.with_extension("ewf-acquisition"))
}

fn ensure_no_acquisition(first: &Path) -> Result<()> {
    if acquisition_path(first)?.try_exists()? {
        return Err(EwfError::Unsupported(
            "unfinished acquisition; resume it with AcquisitionWriter::resume".into(),
        ));
    }
    Ok(())
}

pub(crate) fn ensure_no_publication(first: &Path) -> Result<()> {
    if journal_path(first)?.try_exists()? {
        return Err(EwfError::Unsupported(
            "unfinished output publication; call EwfWriter::recover_output before opening".into(),
        ));
    }
    Ok(())
}

fn normalized_paths(first: &Path, secondary: Option<&Path>) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for path in std::iter::once(first).chain(secondary) {
        let parent = crate::segment::segment_dir(path).canonicalize()?;
        let name = path
            .file_name()
            .ok_or_else(|| EwfError::Malformed("missing output filename".into()))?;
        paths.push(parent.join(name));
    }
    if paths.len() == 2 && paths[0] == paths[1] {
        return Err(EwfError::Unsupported("overlapping output sets".into()));
    }
    Ok(paths)
}

fn identity(paths: &[PathBuf]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"ewf-image-publication-v1");
    for path in paths {
        let bytes = path.as_os_str().as_encoded_bytes();
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    hash.finalize().to_vec()
}

fn files(directory: &Path) -> Result<Vec<PathBuf>> {
    fs::read_dir(directory)?
        .map(|entry| {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                return Err(EwfError::Malformed(
                    "non-file publication journal entry".into(),
                ));
            }
            Ok(entry.path())
        })
        .collect()
}

fn validate_directory(path: &Path) -> Result<()> {
    if !fs::symlink_metadata(path)?.file_type().is_dir() {
        return Err(EwfError::Malformed(
            "invalid publication journal directory".into(),
        ));
    }
    Ok(())
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[allow(clippy::unnecessary_wraps)] // Unix synchronizes directory entries; other platforms retain the fallible interface.
pub(crate) fn sync_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_worker() {
        let Some(root) = std::env::var_os("EWF_PUBLICATION_TEST_ROOT") else {
            return;
        };
        let first = PathBuf::from(root).join("crash.E01");
        let mut publication = Publication::begin(&first, None, true).unwrap();
        write_synced(&publication.stage(0, &first).unwrap(), b"new").unwrap();
        let destinations = vec![vec![first]];
        publication.prepare(&destinations, 1).unwrap();
        publication.install(&destinations, 1).unwrap();
        std::process::exit(77); // Simulate process loss before the commit decision.
    }

    #[test]
    fn process_exit_without_destructors_leaves_recoverable_output() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("crash.E01");
        fs::write(&first, b"original").unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "publication::tests::crash_worker", "--nocapture"])
            .env("EWF_PUBLICATION_TEST_ROOT", dir.path())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(77));
        assert!(ensure_no_pending(&first).is_err());
        assert_eq!(fs::read(&first).unwrap(), b"new");
        assert!(Publication::recover(&first, None).unwrap());
        assert_eq!(fs::read(&first).unwrap(), b"original");
        ensure_no_pending(&first).unwrap();
    }

    #[test]
    fn interruption_at_each_segment_restores_both_sets_and_stale_segments() {
        for stop_after in 0..=5 {
            let dir = tempfile::tempdir().unwrap();
            let primary = dir.path().join("primary.E01");
            let secondary = dir.path().join("secondary.E01");
            let destinations = vec![
                vec![
                    primary.clone(),
                    primary.with_extension("E02"),
                    primary.with_extension("E03"),
                ],
                vec![secondary.clone(), secondary.with_extension("E02")],
            ];
            fs::write(&primary, b"old-primary").unwrap();
            fs::write(&destinations[0][2], b"old-stale").unwrap();
            fs::write(&secondary, b"old-secondary").unwrap();
            let mut publication = Publication::begin(&primary, Some(&secondary), true).unwrap();
            for (set, paths) in destinations.iter().enumerate() {
                for target in &paths[..2] {
                    write_synced(&publication.stage(set, target).unwrap(), b"new").unwrap();
                }
            }
            publication.prepare(&destinations, 2).unwrap();
            let mut installed = 0;
            for (set, paths) in destinations.iter().enumerate() {
                for target in paths {
                    if installed == stop_after {
                        break;
                    }
                    let stage = publication.stage(set, target).unwrap();
                    if stage.exists() {
                        fs::rename(stage, target).unwrap();
                    } else {
                        remove_if_present(target).unwrap();
                    }
                    installed += 1;
                }
            }
            drop(publication); // No rollback in Drop once a journal is prepared.
            assert!(Publication::recover(&primary, Some(&secondary)).unwrap());
            assert_eq!(fs::read(&primary).unwrap(), b"old-primary");
            assert_eq!(fs::read(&secondary).unwrap(), b"old-secondary");
            assert_eq!(fs::read(&destinations[0][2]).unwrap(), b"old-stale");
            assert!(!destinations[0][1].exists());
            assert!(!destinations[1][1].exists());
            assert!(!Publication::recover(&primary, Some(&secondary)).unwrap());
        }
    }

    #[test]
    fn committed_publication_survives_interrupted_secondary_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("primary.Ex01");
        let secondary = dir.path().join("secondary.Ex01");
        let destinations = vec![vec![primary.clone()], vec![secondary.clone()]];
        let mut publication = Publication::begin(&primary, Some(&secondary), true).unwrap();
        for (set, paths) in destinations.iter().enumerate() {
            write_synced(&publication.stage(set, &paths[0]).unwrap(), b"complete").unwrap();
        }
        publication.prepare(&destinations, 1).unwrap();
        publication.install(&destinations, 1).unwrap();
        write_synced(&publication.sets[0].journal.join("committed"), &[]).unwrap();
        fs::remove_dir_all(&publication.sets[1].journal).unwrap();
        drop(publication);
        assert!(Publication::recover(&primary, Some(&secondary)).unwrap());
        assert_eq!(fs::read(primary).unwrap(), b"complete");
        assert_eq!(fs::read(secondary).unwrap(), b"complete");
    }

    #[test]
    fn recovery_rejects_live_writer_and_wrong_secondary_without_modifying_output() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("primary.E01");
        let secondary = dir.path().join("secondary.E01");
        fs::write(&primary, b"original").unwrap();
        let mut publication = Publication::begin(&primary, Some(&secondary), true).unwrap();
        assert!(Publication::recover(&primary, Some(&secondary)).is_err());
        publication
            .prepare(&[vec![primary.clone()], vec![secondary.clone()]], 0)
            .unwrap();
        drop(publication);
        assert!(Publication::recover(&primary, None).is_err());
        assert_eq!(fs::read(&primary).unwrap(), b"original");
        assert!(Publication::recover(&primary, Some(&secondary)).unwrap());
    }

    #[test]
    fn failed_installation_rolls_back_and_failure_before_prepare_preserves_output() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("image.E01");
        let second = dir.path().join("image.E02");
        fs::write(&first, b"old").unwrap();
        {
            let publication = Publication::begin(&first, None, true).unwrap();
            write_synced(&publication.stage(0, &first).unwrap(), b"partial").unwrap();
        }
        assert_eq!(fs::read(&first).unwrap(), b"old");
        let mut publication = Publication::begin(&first, None, true).unwrap();
        write_synced(&publication.stage(0, &first).unwrap(), b"new").unwrap();
        fs::write(&second, b"old-second").unwrap();
        write_synced(&publication.stage(0, &second).unwrap(), b"new-second").unwrap();
        publication.fail_after = Some(1);
        assert!(
            publication
                .publish(&[vec![first.clone(), second.clone()]], 2)
                .is_err()
        );
        assert_eq!(fs::read(first).unwrap(), b"old");
        assert_eq!(fs::read(second).unwrap(), b"old-second");
    }
}

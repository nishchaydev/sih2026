//! Module 2 — Secure File & Folder Eraser.
//!
//! Parallel in structure to `sanitize`/`verify`: content overwrite reuses
//! the existing pattern engine (`sanitize::patterns`), just applied to file
//! handles instead of a raw disk handle. See the per-submodule docs for the
//! two pieces of NTFS metadata (`$LogFile`, `$MFT` slack) that genuinely
//! cannot be safely/fully addressed from user mode.

pub mod freespace;
pub mod streams;
pub mod usn;
pub mod walker;
pub mod wipe;

use crate::sanitize::patterns::SanitizeMethod;
use anyhow::Result;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub(crate) fn random_name(len: usize) -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

pub struct FileEraseOptions {
    pub method: SanitizeMethod,
    pub wipe_free_space: bool,
    pub delete_usn_journal: bool,
}

pub struct FileEraseSummary {
    pub file_records: Vec<wipe::FileWipeRecord>,
    pub dirs_removed: Vec<String>,
    pub free_space_results: Vec<freespace::FreeSpaceWipeResult>,
    pub usn_journal_results: Vec<(String, usn::UsnJournalOutcome)>,
    pub total_duration: Duration,
}

/// Expands `input_paths` (files and/or folders, recursively), securely
/// deletes every file found, removes now-empty directories bottom-up, then
/// runs the two opt-in volume-wide steps (free-space wipe, USN journal
/// deletion) once per distinct volume touched by the *original* input
/// paths. Per-file failures never abort the batch — see
/// `wipe::secure_delete_file`.
pub fn erase_paths(
    input_paths: &[PathBuf],
    options: FileEraseOptions,
    progress_cb: impl Fn(u64, u64),
) -> Result<FileEraseSummary> {
    let start = Instant::now();
    let expanded = walker::expand_paths(input_paths)?;

    let total_bytes: u64 = expanded
        .files
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum();

    let mut bytes_done: u64 = 0;
    let mut file_records = Vec::new();
    for file in &expanded.files {
        let size = std::fs::metadata(file).map(|m| m.len()).unwrap_or(0);
        let record = wipe::secure_delete_file(file, options.method);
        bytes_done += size;
        progress_cb(bytes_done, total_bytes.max(1));
        file_records.push(record);
    }

    let mut dirs_removed = Vec::new();
    for dir in &expanded.dirs_to_remove {
        match rename_and_remove_dir(dir) {
            Ok(()) => dirs_removed.push(dir.to_string_lossy().to_string()),
            Err(e) => tracing::warn!("Failed to remove directory {}: {}", dir.display(), e),
        }
    }

    // Volume-wide opt-ins run once per distinct volume touched by the
    // original (pre-expansion) input paths.
    let mut volumes: HashSet<PathBuf> = HashSet::new();
    for p in input_paths {
        if let Some(root) = volume_root_of(p) {
            volumes.insert(root);
        }
    }

    let mut free_space_results = Vec::new();
    if options.wipe_free_space {
        for vol in &volumes {
            match freespace::wipe_free_space(vol, options.method, |_, _| {}) {
                Ok(r) => free_space_results.push(r),
                Err(e) => tracing::warn!("Free-space wipe failed for {}: {}", vol.display(), e),
            }
        }
    }

    let mut usn_journal_results = Vec::new();
    if options.delete_usn_journal {
        for vol in &volumes {
            match usn::delete_usn_journal(vol) {
                Ok(outcome) => usn_journal_results.push((vol.to_string_lossy().to_string(), outcome)),
                Err(e) => tracing::warn!("USN journal delete failed for {}: {}", vol.display(), e),
            }
        }
    }

    Ok(FileEraseSummary {
        file_records,
        dirs_removed,
        free_space_results,
        usn_journal_results,
        total_duration: start.elapsed(),
    })
}

fn rename_and_remove_dir(dir: &Path) -> Result<()> {
    let parent = dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("No parent for {}", dir.display()))?;
    let random_path = parent.join(random_name(12));
    std::fs::rename(dir, &random_path).map_err(|e| anyhow::anyhow!("rename failed: {}", e))?;
    std::fs::remove_dir(&random_path).map_err(|e| anyhow::anyhow!("remove_dir failed: {}", e))?;
    Ok(())
}

fn volume_root_of(path: &Path) -> Option<PathBuf> {
    let s = path.to_string_lossy();
    let mut chars = s.chars();
    let drive = chars.next()?;
    if chars.next() == Some(':') && drive.is_ascii_alphabetic() {
        Some(PathBuf::from(format!("{}:\\", drive)))
    } else {
        None
    }
}

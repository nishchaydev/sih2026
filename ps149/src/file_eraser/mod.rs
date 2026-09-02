pub mod overwrite;
pub mod streams;
pub mod metadata;
pub mod slack;
pub mod free_space;
pub mod batch;

use crate::sanitize::patterns::SanitizeMethod;
use anyhow::Result;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
pub struct FileEraseResult {
    pub path: PathBuf,
    pub original_size: u64,
    pub method: SanitizeMethod,
    pub passes_completed: usize,
    pub bytes_overwritten: u64,
    pub streams_erased: usize,
    pub slack_bytes_wiped: u64,
    pub metadata_cleansed: bool,
    pub filename_obfuscated: bool,
    pub deleted: bool,
    pub duration: Duration,
    pub errors: Vec<String>,
}

impl FileEraseResult {
    pub fn success(&self) -> bool {
        self.deleted && self.errors.is_empty()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FreeSpaceWipeResult {
    pub volume: String,
    pub bytes_wiped: u64,
    pub method: SanitizeMethod,
    pub duration: Duration,
}

/// Securely erase a single file: overwrite data + ADS + slack, cleanse metadata, delete.
pub fn secure_erase_file(
    path: &Path,
    method: SanitizeMethod,
    progress_callback: &impl Fn(&str, f64),
) -> Result<FileEraseResult> {
    let start = std::time::Instant::now();
    let mut errors = Vec::new();

    let original_size = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(e) => {
            return Err(anyhow::anyhow!("Cannot access file {:?}: {}", path, e));
        }
    };

    // Phase 1: Enumerate and overwrite Alternate Data Streams
    progress_callback("Enumerating data streams...", 0.0);
    let stream_list = streams::enumerate_streams(path).unwrap_or_default();
    let streams_count = stream_list.len();

    for (i, stream) in stream_list.iter().enumerate() {
        let stream_path = if stream.name == "::$DATA" {
            path.to_path_buf()
        } else {
            let stream_suffix = stream.name.trim_start_matches(':');
            let stream_suffix = stream_suffix.trim_end_matches(":$DATA");
            PathBuf::from(format!("{}:{}", path.display(), stream_suffix))
        };
        let pct = (i as f64) / (streams_count.max(1) as f64) * 0.3;
        progress_callback(
            &format!("Overwriting stream {} ({}/{})", stream.name, i + 1, streams_count),
            pct,
        );
        if let Err(e) = overwrite::overwrite_file(&stream_path, method) {
            errors.push(format!("Stream '{}': {}", stream.name, e));
        }
    }

    // Phase 2: Overwrite primary file data (if not already done via streams)
    if stream_list.is_empty() || !stream_list.iter().any(|s| s.name == "::$DATA") {
        progress_callback("Overwriting file data...", 0.3);
        if let Err(e) = overwrite::overwrite_file(path, method) {
            errors.push(format!("Primary data: {}", e));
        }
    }

    // Phase 3: Wipe file slack space
    progress_callback("Wiping slack space...", 0.6);
    let slack_bytes = match slack::wipe_file_slack(path) {
        Ok(b) => b,
        Err(e) => {
            errors.push(format!("Slack wipe: {}", e));
            0
        }
    };

    // Phase 4: Cleanse metadata (timestamps, attributes, filename obfuscation)
    progress_callback("Cleansing metadata...", 0.8);
    let (meta_ok, name_ok) = match metadata::cleanse_and_delete(path) {
        Ok(r) => (r.timestamps_zeroed, r.filename_obfuscated),
        Err(e) => {
            errors.push(format!("Metadata cleanse: {}", e));
            // Fallback: try simple delete
            let _ = std::fs::remove_file(path);
            (false, false)
        }
    };

    let deleted = !path.exists();
    progress_callback("Complete", 1.0);

    Ok(FileEraseResult {
        path: path.to_path_buf(),
        original_size,
        method,
        passes_completed: method.pass_count(),
        bytes_overwritten: original_size * method.pass_count() as u64,
        streams_erased: streams_count,
        slack_bytes_wiped: slack_bytes,
        metadata_cleansed: meta_ok,
        filename_obfuscated: name_ok,
        deleted,
        duration: start.elapsed(),
        errors,
    })
}

/// Securely erase a folder and all its contents recursively.
#[allow(dead_code)]
pub fn secure_erase_folder(
    path: &Path,
    method: SanitizeMethod,
    progress_callback: &impl Fn(&str, f64),
) -> Result<Vec<FileEraseResult>> {
    if !path.is_dir() {
        return Err(anyhow::anyhow!("{:?} is not a directory", path));
    }

    let mut all_files = Vec::new();
    collect_files_recursive(path, &mut all_files)?;

    let total = all_files.len();
    let mut results = Vec::with_capacity(total);

    for (i, file_path) in all_files.iter().enumerate() {
        let pct = i as f64 / total.max(1) as f64;
        progress_callback(
            &format!("Erasing file {}/{}: {}", i + 1, total, file_path.display()),
            pct,
        );
        match secure_erase_file(file_path, method, &|_msg, _p| {}) {
            Ok(r) => results.push(r),
            Err(e) => {
                results.push(FileEraseResult {
                    path: file_path.clone(),
                    original_size: 0,
                    method,
                    passes_completed: 0,
                    bytes_overwritten: 0,
                    streams_erased: 0,
                    slack_bytes_wiped: 0,
                    metadata_cleansed: false,
                    filename_obfuscated: false,
                    deleted: false,
                    duration: Duration::ZERO,
                    errors: vec![e.to_string()],
                });
            }
        }
    }

    // Remove empty directories bottom-up
    remove_empty_dirs_recursive(path);
    progress_callback("Folder erasure complete", 1.0);

    Ok(results)
}

fn collect_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files_recursive(&path, files)?;
        } else {
            files.push(path);
        }
    }
    Ok(())
}

fn remove_empty_dirs_recursive(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                remove_empty_dirs_recursive(&p);
            }
        }
    }
    let _ = std::fs::remove_dir(dir);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_secure_erase_single_file() {
        let temp_dir = std::env::temp_dir();
        let target = temp_dir.join("ps149_shred_test_single.txt");

        // Create file with sensitive sample content
        {
            let mut f = std::fs::File::create(&target).unwrap();
            f.write_all(b"CONFIDENTIAL_BANK_STATEMENT_ACCOUNT_12345").unwrap();
        }
        assert!(target.exists());

        // Securely erase using DoD 3-Pass
        let result = secure_erase_file(&target, SanitizeMethod::Dod3Pass, &|_msg, _pct| {});
        assert!(result.is_ok());

        let res = result.unwrap();
        assert_eq!(res.passes_completed, 3);
        assert!(!target.exists(), "Target file must be physically removed");
        assert!(res.deleted);
    }

    #[test]
    fn test_batch_erase_directory() {
        let temp_dir = std::env::temp_dir().join("ps149_test_batch_folder");
        let _ = std::fs::create_dir_all(&temp_dir);

        let file1 = temp_dir.join("file1.dat");
        let file2 = temp_dir.join("file2.dat");

        std::fs::write(&file1, b"Payload 1 content").unwrap();
        std::fs::write(&file2, b"Payload 2 content").unwrap();

        let targets = vec![temp_dir.clone()];
        let expanded = batch::expand_targets(&targets);
        assert_eq!(expanded.len(), 2);

        let batch_res = batch::batch_erase(&expanded, SanitizeMethod::NistClear, &|_msg, _pct| {}).unwrap();
        assert_eq!(batch_res.files_succeeded, 2);
        assert_eq!(batch_res.files_failed, 0);
        assert!(!file1.exists());
        assert!(!file2.exists());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}

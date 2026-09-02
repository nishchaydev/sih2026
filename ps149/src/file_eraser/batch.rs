use crate::sanitize::patterns::SanitizeMethod;
use anyhow::Result;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::info;

use super::{secure_erase_file, FileEraseResult};

#[derive(Debug, Clone, Serialize)]
pub struct BatchEraseResult {
    pub total_files: usize,
    pub files_succeeded: usize,
    pub files_failed: usize,
    pub total_bytes_erased: u64,
    pub duration: Duration,
    pub results: Vec<FileEraseResult>,
}

impl BatchEraseResult {
    pub fn success_rate(&self) -> f64 {
        if self.total_files == 0 {
            return 100.0;
        }
        (self.files_succeeded as f64 / self.total_files as f64) * 100.0
    }
}

/// Erase a batch of files with progress reporting.
/// Processes files sequentially (parallel not safe for disk I/O bound work).
pub fn batch_erase(
    paths: &[PathBuf],
    method: SanitizeMethod,
    progress_callback: &impl Fn(&str, f64),
) -> Result<BatchEraseResult> {
    let start = Instant::now();
    let total = paths.len();
    let mut results = Vec::with_capacity(total);
    let mut succeeded = 0usize;
    let mut failed = 0usize;
    let mut total_bytes = 0u64;

    for (i, path) in paths.iter().enumerate() {
        let pct = i as f64 / total.max(1) as f64;
        let name = path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.display().to_string());
        progress_callback(
            &format!("[{}/{}] Erasing: {}", i + 1, total, name),
            pct,
        );

        match secure_erase_file(path, method, &|_msg, _p| {}) {
            Ok(r) => {
                total_bytes += r.original_size;
                if r.success() {
                    succeeded += 1;
                } else {
                    failed += 1;
                }
                results.push(r);
            }
            Err(e) => {
                failed += 1;
                results.push(FileEraseResult {
                    path: path.clone(),
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

    progress_callback("Batch erase complete", 1.0);

    info!(
        "Batch erase: {}/{} succeeded, {} bytes erased in {:?}",
        succeeded, total, total_bytes, start.elapsed()
    );

    Ok(BatchEraseResult {
        total_files: total,
        files_succeeded: succeeded,
        files_failed: failed,
        total_bytes_erased: total_bytes,
        duration: start.elapsed(),
        results,
    })
}

/// Collect all file paths from a list of targets (files + directories).
/// Directories are expanded recursively.
pub fn expand_targets(targets: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for target in targets {
        if target.is_dir() {
            collect_recursive(target, &mut files);
        } else if target.is_file() {
            files.push(target.clone());
        }
    }
    files
}

fn collect_recursive(dir: &Path, files: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                collect_recursive(&p, files);
            } else {
                files.push(p);
            }
        }
    }
}

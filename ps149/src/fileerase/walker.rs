//! Expands a mix of file/folder paths into a flat file list plus an ordered
//! directory-removal list, and flags well-known protected system paths.

use anyhow::Result;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

pub struct ExpandedTargets {
    pub files: Vec<PathBuf>,
    /// Ordered deepest-first so `remove_dir` succeeds bottom-up.
    pub dirs_to_remove: Vec<PathBuf>,
}

/// Expands a mix of file and folder paths into a flat file list plus an
/// ordered (deepest-first) list of directories to remove afterward.
/// Iterative, not recursive, so it doesn't blow the stack on deep trees.
pub fn expand_paths(input_paths: &[PathBuf]) -> Result<ExpandedTargets> {
    let mut files = Vec::new();
    let mut dirs_by_depth: Vec<(usize, PathBuf)> = Vec::new();

    for input in input_paths {
        let metadata = std::fs::symlink_metadata(input)
            .map_err(|e| anyhow::anyhow!("Cannot access {}: {}", input.display(), e))?;

        if metadata.is_dir() {
            walk_dir(input, &mut files, &mut dirs_by_depth)?;
        } else {
            files.push(input.clone());
        }
    }

    // Deepest directories first so `remove_dir` succeeds bottom-up.
    dirs_by_depth.sort_by(|a, b| b.0.cmp(&a.0));
    let dirs_to_remove = dirs_by_depth.into_iter().map(|(_, p)| p).collect();

    Ok(ExpandedTargets { files, dirs_to_remove })
}

fn walk_dir(
    root: &Path,
    files: &mut Vec<PathBuf>,
    dirs_by_depth: &mut Vec<(usize, PathBuf)>,
) -> Result<()> {
    let mut queue: VecDeque<(usize, PathBuf)> = VecDeque::new();
    queue.push_back((0, root.to_path_buf()));

    while let Some((depth, dir)) = queue.pop_front() {
        dirs_by_depth.push((depth, dir.clone()));
        let entries = std::fs::read_dir(&dir)
            .map_err(|e| anyhow::anyhow!("Cannot read directory {}: {}", dir.display(), e))?;
        for entry in entries {
            let entry = entry.map_err(|e| anyhow::anyhow!("Directory entry error: {}", e))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|e| anyhow::anyhow!("Cannot stat {}: {}", path.display(), e))?;
            if file_type.is_dir() {
                queue.push_back((depth + 1, path));
            } else {
                files.push(path);
            }
        }
    }

    Ok(())
}

/// Returns a human-readable reason if `path` looks like it's under a
/// well-known protected root (drive root, Windows system directory, Program
/// Files, or the user profile root) — used to require a stronger
/// confirmation phrase, not to block outright (a user may legitimately want
/// to wipe a folder *under* their profile, e.g. Documents).
///
/// This is a soft UX guard against honest typos/mistakes (e.g. pointing the
/// tool at `C:\` by accident), not a hard security boundary — it works on
/// the path as given, without canonicalizing (canonicalizing on Windows
/// produces `\\?\`-prefixed paths that would break these plain string
/// comparisons against unprefixed environment variables).
pub fn is_protected_path(path: &Path) -> Option<&'static str> {
    let s = path.to_string_lossy().to_ascii_lowercase();

    // Roots where the path itself AND any subfolder are protected.
    let subtree_roots: [(Option<String>, &'static str); 3] = [
        (std::env::var("SystemRoot").ok(), "Windows system directory"),
        (std::env::var("ProgramFiles").ok(), "Program Files"),
        (std::env::var("ProgramFiles(x86)").ok(), "Program Files (x86)"),
    ];
    for (root, label) in &subtree_roots {
        if let Some(root) = root {
            let root_lower = root.to_ascii_lowercase();
            if s == root_lower || s.starts_with(&format!("{}\\", root_lower)) {
                return Some(label);
            }
        }
    }

    // The profile root itself is protected; subfolders (Documents, Desktop,
    // Downloads, ...) are normal, expected erase targets and are NOT flagged.
    if let Ok(profile) = std::env::var("USERPROFILE") {
        if s == profile.to_ascii_lowercase() {
            return Some("user profile root");
        }
    }

    // A bare drive root, e.g. "c:\".
    if s.len() <= 3 && s.ends_with(":\\") {
        return Some("drive root");
    }

    None
}

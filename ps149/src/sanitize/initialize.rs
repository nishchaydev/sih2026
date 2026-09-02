#![allow(dead_code)]

use anyhow::{Context, Result};
use std::fs;
use std::process::Command;
use tracing::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetFileSystem {
    Fat32,
    ExFat,
    Ntfs,
}

impl TargetFileSystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fat32 => "fat32",
            Self::ExFat => "exfat",
            Self::Ntfs => "ntfs",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Fat32 => "FAT32 (Universal Compatibility)",
            Self::ExFat => "exFAT (Modern Cross-Platform, >4GB Files)",
            Self::Ntfs => "NTFS (Windows Optimized)",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FormatResult {
    pub filesystem: TargetFileSystem,
    pub volume_label: String,
    pub output_summary: String,
}

/// Re-initializes a raw, erased disk with an MBR partition table,
/// creates a primary partition, formats it with the chosen filesystem,
/// and assigns a drive letter so Windows Explorer can use it immediately.
pub fn reinitialize_and_format_disk(
    disk_index: u32,
    filesystem: TargetFileSystem,
    label: &str,
) -> Result<FormatResult> {
    info!(
        "Re-initializing Disk {} with {} and label '{}'...",
        disk_index,
        filesystem.as_str(),
        label
    );

    // Sanitize label: letters, numbers, underscores, max 11 chars for FAT32
    let clean_label: String = label
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(11)
        .collect();
    let clean_label = if clean_label.is_empty() {
        "CLEAN_DRIVE".to_string()
    } else {
        clean_label
    };

    let fs_param = filesystem.as_str();

    // Build the diskpart automation script
    let script_content = format!(
        "select disk {disk_index}\n\
         clean\n\
         convert mbr\n\
         create partition primary\n\
         format fs={fs_param} quick label=\"{clean_label}\"\n\
         assign\n\
         exit\n"
    );

    let temp_file = std::env::temp_dir().join(format!("ps149_init_disk_{}.txt", disk_index));
    fs::write(&temp_file, script_content)
        .with_context(|| format!("Failed to create temporary diskpart script at {:?}", temp_file))?;

    let output = Command::new("diskpart")
        .arg("/s")
        .arg(&temp_file)
        .output()
        .with_context(|| "Failed to execute diskpart. Ensure you are running as Administrator.")?;

    let _ = fs::remove_file(&temp_file);

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() || stdout_str.contains("DiskPart has encountered an error") {
        let err_detail = if !stderr_str.trim().is_empty() {
            stderr_str.to_string()
        } else {
            stdout_str
                .lines()
                .filter(|l| l.contains("Error") || l.contains("error") || l.contains("Virtual Disk Service"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        return Err(anyhow::anyhow!(
            "DiskPart formatting failed (Disk {}): {}",
            disk_index,
            if err_detail.is_empty() { stdout_str.to_string() } else { err_detail }
        ));
    }

    Ok(FormatResult {
        filesystem,
        volume_label: clean_label,
        output_summary: format!(
            "Successfully initialized Disk {} with MBR partition and {} filesystem",
            disk_index,
            filesystem.as_str().to_uppercase()
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filesystem_strings() {
        assert_eq!(TargetFileSystem::Fat32.as_str(), "fat32");
        assert_eq!(TargetFileSystem::ExFat.as_str(), "exfat");
        assert_eq!(TargetFileSystem::Ntfs.as_str(), "ntfs");
    }
}

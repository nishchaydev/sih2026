use anyhow::Result;
use chrono::{DateTime, Local};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

use crate::fileerase::{wipe::FileWipeRecord, FileEraseSummary};
use crate::report::audit_log::{AuditEvent, AuditLog};
use crate::report::certificate::HostInfo;
use crate::sanitize::patterns::SanitizeMethod;

#[derive(Debug, Serialize)]
pub struct FileRecordInfo {
    pub path: String,
    pub size_bytes: u64,
    pub streams_wiped: usize,
    pub passes: usize,
    pub deleted: bool,
    pub errors: Vec<String>,
}

impl From<&FileWipeRecord> for FileRecordInfo {
    fn from(r: &FileWipeRecord) -> Self {
        Self {
            path: r.original_path.clone(),
            size_bytes: r.size_bytes,
            streams_wiped: r.streams_wiped,
            passes: r.passes,
            deleted: r.deleted,
            errors: r.errors.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct FreeSpaceWipeInfo {
    pub volume: String,
    pub bytes_written: u64,
    pub duration_secs: f64,
}

#[derive(Debug, Serialize)]
pub struct FileErasureSummaryInfo {
    pub total_files: usize,
    pub files_deleted: usize,
    pub files_failed: usize,
    pub total_bytes: u64,
    pub directories_removed: usize,
}

/// The overall summary certificate of a file/folder erasure operation.
/// Parallel to `SanitizationCertificate`, but file-shaped rather than
/// disk-shaped — a batch of files doesn't fit `DeviceInfo`'s
/// disk-index/sector-count fields, so this is its own struct rather than
/// forcing files through the disk-erase schema.
#[derive(Debug, Serialize)]
pub struct FileErasureCertificate {
    pub tool_name: String,
    pub tool_version: String,
    pub timestamp_start: DateTime<Local>,
    pub timestamp_end: DateTime<Local>,
    pub host_info: HostInfo,
    pub method: String,
    pub standard: String,
    pub files: Vec<FileRecordInfo>,
    pub directories_removed: Vec<String>,
    pub free_space_wipe: Vec<FreeSpaceWipeInfo>,
    pub usn_journals_cleared: Vec<String>,
    pub summary: FileErasureSummaryInfo,
    pub audit_events: Vec<AuditEvent>,
    pub ai_narrative: Option<String>,
    pub compliance_note: String,
}

impl FileErasureCertificate {
    pub fn build(
        start: DateTime<Local>,
        end: DateTime<Local>,
        method: SanitizeMethod,
        summary: &FileEraseSummary,
        audit: AuditLog,
    ) -> Self {
        let files: Vec<FileRecordInfo> = summary.file_records.iter().map(FileRecordInfo::from).collect();
        let files_deleted = files.iter().filter(|f| f.deleted).count();
        let files_failed = files.len() - files_deleted;
        let total_bytes = files.iter().map(|f| f.size_bytes).sum();

        let usn_journals_cleared = summary
            .usn_journal_results
            .iter()
            .filter(|(_, outcome)| matches!(outcome, crate::fileerase::usn::UsnJournalOutcome::Deleted))
            .map(|(vol, _)| vol.clone())
            .collect();

        let free_space_wipe = summary
            .free_space_results
            .iter()
            .map(|r| FreeSpaceWipeInfo {
                volume: r.volume.clone(),
                bytes_written: r.bytes_written,
                duration_secs: r.duration.as_secs_f64(),
            })
            .collect();

        Self {
            tool_name: "PS149 Secure File & Folder Eraser".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp_start: start,
            timestamp_end: end,
            host_info: HostInfo {
                hostname: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Unknown".into()),
                os: std::env::var("OS").unwrap_or_else(|_| "Unknown".into()),
            },
            method: method.display_name().to_string(),
            standard: method.standard_name().to_string(),
            directories_removed: summary.dirs_removed.clone(),
            summary: FileErasureSummaryInfo {
                total_files: files.len(),
                files_deleted,
                files_failed,
                total_bytes,
                directories_removed: summary.dirs_removed.len(),
            },
            files,
            free_space_wipe,
            usn_journals_cleared,
            audit_events: audit.events().to_vec(),
            ai_narrative: None,
            compliance_note: "Each file's data streams (including NTFS alternate data \
                streams) were overwritten before deletion; the file was then renamed to a \
                random name and removed, stripping the original name from the directory \
                entry. This does NOT clear the NTFS $LogFile — no safe user-mode API exists \
                for this — and does not guarantee removal of $MFT slack space; the optional \
                free-space wipe reduces but does not eliminate this residual risk. USN \
                journal clearing, if enabled, is a separate volume-wide operation (see \
                usn_journals_cleared) and is not scoped to any individual file."
                .to_string(),
        }
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn to_text_summary(&self) -> String {
        let mut text = String::new();
        text.push_str("========================================================\n");
        text.push_str("           FILE & FOLDER ERASURE CERTIFICATE            \n");
        text.push_str("========================================================\n\n");

        if let Some(narrative) = &self.ai_narrative {
            text.push_str("[ AI Forensic Narrative ]\n");
            text.push_str(narrative);
            text.push_str("\n\n");
        }

        text.push_str(&format!("Tool: {} v{}\n", self.tool_name, self.tool_version));
        text.push_str(&format!("Started: {}\n", self.timestamp_start.format("%Y-%m-%d %H:%M:%S")));
        text.push_str(&format!("Ended:   {}\n", self.timestamp_end.format("%Y-%m-%d %H:%M:%S")));

        text.push_str("\n[ Host System ]\n");
        text.push_str(&format!("Hostname: {}\n", self.host_info.hostname));
        text.push_str(&format!("OS: {}\n", self.host_info.os));

        text.push_str("\n[ Method ]\n");
        text.push_str(&format!("Method: {}\n", self.method));
        text.push_str(&format!("Standard: {}\n", self.standard));

        text.push_str("\n[ Summary ]\n");
        text.push_str(&format!("Files processed: {}\n", self.summary.total_files));
        text.push_str(&format!("Files deleted: {}\n", self.summary.files_deleted));
        text.push_str(&format!("Files failed: {}\n", self.summary.files_failed));
        text.push_str(&format!("Total bytes overwritten: {}\n", self.summary.total_bytes));
        text.push_str(&format!("Directories removed: {}\n", self.summary.directories_removed));

        if !self.free_space_wipe.is_empty() {
            text.push_str("\n[ Free-Space Wipe ]\n");
            for r in &self.free_space_wipe {
                text.push_str(&format!("  {} — {} bytes in {:.2}s\n", r.volume, r.bytes_written, r.duration_secs));
            }
        }

        if !self.usn_journals_cleared.is_empty() {
            text.push_str("\n[ USN Journals Cleared (volume-wide) ]\n");
            for v in &self.usn_journals_cleared {
                text.push_str(&format!("  {}\n", v));
            }
        }

        if !self.files.is_empty() {
            text.push_str("\n[ Files ]\n");
            for f in &self.files {
                let status = if f.deleted { "OK" } else { "FAILED" };
                text.push_str(&format!(
                    "  [{}] {} — {} bytes, {} stream(s), {} pass(es)\n",
                    status, f.path, f.size_bytes, f.streams_wiped, f.passes
                ));
                for e in &f.errors {
                    text.push_str(&format!("        ! {}\n", e));
                }
            }
        }

        text.push_str("\n[ Compliance Note ]\n");
        text.push_str(&self.compliance_note);
        text.push('\n');

        text
    }

    /// Save both JSON and text reports to the specified output directory.
    /// Distinct filename prefix from `SanitizationCertificate::save` so
    /// disk-erase and file-erase reports never collide in `reports/`.
    pub fn save(&self, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
        let timestamp = self.timestamp_end.format("%Y%m%d_%H%M%S").to_string();

        let json_path = output_dir.join(format!("ps149_fileerase_report_{}.json", timestamp));
        let txt_path = output_dir.join(format!("ps149_fileerase_report_{}.txt", timestamp));

        fs::write(&json_path, self.to_json()?)?;
        fs::write(&txt_path, self.to_text_summary())?;

        Ok((json_path, txt_path))
    }
}

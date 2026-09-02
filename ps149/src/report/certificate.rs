use anyhow::Result;
use chrono::{DateTime, Local};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use crate::model::device::PhysicalDisk;
use crate::report::audit_log::{AuditLog, AuditEvent};
use crate::sanitize::patterns::SanitizeMethod;
use crate::sanitize::SanitizeResult;
use crate::verify::readback::VerifyResult;

/// Details about the host system performing the sanitization.
#[derive(Debug, Serialize)]
pub struct HostInfo {
    pub hostname: String,
    pub os: String,
}

/// Details about the device being sanitized.
#[derive(Debug, Serialize)]
pub struct DeviceInfo {
    pub disk_index: u32,
    pub model: String,
    pub serial_number: String,
    pub capacity_bytes: u64,
    pub capacity_display: String,
    pub device_type: String,
    pub interface_type: String,
    pub bytes_per_sector: u32,
    pub total_sectors: u64,
}

/// Details of the sanitization method and timing.
#[derive(Debug, Serialize)]
pub struct SanitizationInfo {
    pub method: String,
    pub standard: String,
    pub passes: Vec<PassInfo>,
    pub total_duration_secs: f64,
}

/// Details of a single sanitization pass.
#[derive(Debug, Serialize)]
pub struct PassInfo {
    pub index: usize,
    pub pattern: String,
    pub sectors_written: u64,
    pub duration_secs: f64,
}

/// Result details from the verification phase.
#[derive(Debug, Serialize)]
pub struct VerificationInfo {
    pub result: String,
    pub sectors_verified: u64,
    pub sectors_failed: u64,
    pub disk_hash_sha256: String,
    pub duration_secs: f64,
}

/// The overall summary certificate of a sanitization operation.
#[derive(Debug, Serialize)]
pub struct SanitizationCertificate {
    pub tool_name: String,
    pub tool_version: String,
    pub timestamp_start: DateTime<Local>,
    pub timestamp_end: DateTime<Local>,
    pub host_info: HostInfo,
    pub device_info: DeviceInfo,
    pub sanitization: SanitizationInfo,
    pub verification: VerificationInfo,
    pub audit_events: Vec<AuditEvent>,
    pub ai_narrative: Option<String>,
    pub compliance_note: String,
}

impl SanitizationCertificate {
    /// Assembles a certificate from all collected results.
    pub fn build(
        start: DateTime<Local>,
        end: DateTime<Local>,
        disk: &PhysicalDisk,
        sanitize_result: &SanitizeResult,
        verify_result: &VerifyResult,
        method: SanitizeMethod,
        audit: AuditLog,
    ) -> Self {
        let passes = sanitize_result
            .passes
            .iter()
            .map(|p| PassInfo {
                index: p.pass_index,
                pattern: p.pattern_description.clone(),
                sectors_written: p.sectors_written,
                duration_secs: p.duration.as_secs_f64(),
            })
            .collect();

        Self {
            tool_name: "PS149 Secure Drive Eraser".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp_start: start,
            timestamp_end: end,
            host_info: HostInfo {
                hostname: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Unknown".into()),
                os: std::env::var("OS").unwrap_or_else(|_| "Unknown".into()),
            },
            device_info: DeviceInfo {
                disk_index: disk.index,
                model: disk.model.clone().unwrap_or_else(|| "Unknown".into()),
                serial_number: disk.serial_number.clone().unwrap_or_else(|| "Unknown".into()),
                capacity_bytes: disk.capacity,
                capacity_display: disk.capacity_display(),
                device_type: disk.device_type.to_string(),
                interface_type: disk.interface_type.clone().unwrap_or_else(|| "Unknown".into()),
                bytes_per_sector: disk.bytes_per_sector,
                total_sectors: disk.total_sectors,
            },
            sanitization: SanitizationInfo {
                method: method.display_name().to_string(),
                standard: method.standard_name().to_string(),
                passes,
                total_duration_secs: sanitize_result.total_duration.as_secs_f64(),
            },
            verification: VerificationInfo {
                result: if verify_result.passed { "PASS".into() } else { "FAIL".into() },
                sectors_verified: verify_result.sectors_verified,
                sectors_failed: verify_result.sectors_failed,
                disk_hash_sha256: verify_result.disk_hash.clone(),
                duration_secs: verify_result.duration.as_secs_f64(),
            },
            audit_events: audit.events().to_vec(),
            ai_narrative: None,
            compliance_note: "This sanitization meets NIST SP 800-88 Clear level for \
                user-addressable logical blocks. Software-based overwrite cannot guarantee \
                erasure of data in flash controller-managed areas including over-provisioned \
                space, wear-leveled spare pages, and retired bad blocks."
                .to_string(),
        }
    }

    /// Generate the JSON report string.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Generate a human-readable text summary of the certificate.
    pub fn to_text_summary(&self) -> String {
        let mut text = String::new();
        text.push_str("========================================================\n");
        text.push_str("               SANITIZATION CERTIFICATE                 \n");
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

        text.push_str("\n[ Device Information ]\n");
        text.push_str(&format!("Disk Index: {}\n", self.device_info.disk_index));
        text.push_str(&format!("Model: {}\n", self.device_info.model));
        text.push_str(&format!("Serial Number: {}\n", self.device_info.serial_number));
        text.push_str(&format!("Capacity: {} ({} bytes)\n", self.device_info.capacity_display, self.device_info.capacity_bytes));
        text.push_str(&format!("Type: {} / {}\n", self.device_info.device_type, self.device_info.interface_type));
        text.push_str(&format!("Sector Size: {} bytes\n", self.device_info.bytes_per_sector));
        text.push_str(&format!("Total Sectors: {}\n", self.device_info.total_sectors));

        text.push_str("\n[ Sanitization Details ]\n");
        text.push_str(&format!("Method: {}\n", self.sanitization.method));
        text.push_str(&format!("Standard: {}\n", self.sanitization.standard));
        text.push_str(&format!("Duration: {:.2} seconds\n", self.sanitization.total_duration_secs));
        for pass in &self.sanitization.passes {
            text.push_str(&format!("  Pass {}: {} — {} sectors in {:.2}s\n",
                pass.index + 1, pass.pattern, pass.sectors_written, pass.duration_secs));
        }

        text.push_str("\n[ Verification Details ]\n");
        text.push_str(&format!("Result: {}\n", self.verification.result));
        text.push_str(&format!("Sectors Verified: {}\n", self.verification.sectors_verified));
        text.push_str(&format!("Sectors Failed: {}\n", self.verification.sectors_failed));
        text.push_str(&format!("Disk Hash (SHA-256): {}\n", self.verification.disk_hash_sha256));
        text.push_str(&format!("Verification Duration: {:.2} seconds\n", self.verification.duration_secs));

        text.push_str("\n[ Compliance Note ]\n");
        text.push_str(&self.compliance_note);
        text.push('\n');

        text
    }

    /// Save both JSON and text reports to the specified output directory.
    pub fn save(&self, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
        let timestamp = self.timestamp_end.format("%Y%m%d_%H%M%S").to_string();

        let json_path = output_dir.join(format!("ps149_report_{}.json", timestamp));
        let txt_path = output_dir.join(format!("ps149_report_{}.txt", timestamp));

        fs::write(&json_path, self.to_json()?)?;
        fs::write(&txt_path, self.to_text_summary())?;

        Ok((json_path, txt_path))
    }
}

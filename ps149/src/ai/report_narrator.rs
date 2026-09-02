use super::groq::GroqClient;
use crate::model::PhysicalDisk;
use crate::sanitize::SanitizeResult;
use crate::verify::readback::VerifyResult;
use anyhow::Result;

const SYSTEM_PROMPT: &str = "\
You are a digital forensics expert writing official sanitization certificates. \
Write a professional, court-admissible forensic narrative based on the provided data. \
Use precise technical language. Include all relevant details: device identifiers, \
timestamps, methods used, sector counts, and verification results. \
Keep it under 200 words. Do not add disclaimers or caveats. \
Format as a single professional paragraph.";

/// Generates an AI-powered forensic narrative from sanitization results.
pub fn generate_narrative(
    groq: &GroqClient,
    disk: &PhysicalDisk,
    sanitize_result: &SanitizeResult,
    verify_result: &VerifyResult,
    start_time: &str,
    end_time: &str,
) -> Result<String> {
    let verify_status = if verify_result.passed {
        "PASSED — 100% sector match confirmed"
    } else {
        &format!(
            "FAILED — {} sectors mismatched",
            verify_result.sectors_failed
        )
    };

    let user_prompt = format!(
        "Generate a forensic sanitization narrative for this operation:\n\
         \n\
         Device: {} ({})\n\
         Serial Number: {}\n\
         Device Type: {}\n\
         Capacity: {} ({} sectors × {} bytes/sector)\n\
         Interface: {}\n\
         \n\
         Sanitization Method: {} ({})\n\
         Total Passes: {}\n\
         Total Sectors Written: {}\n\
         Duration: {:.1} seconds\n\
         \n\
         Verification: {}\n\
         Sectors Verified: {}\n\
         SHA-256 Disk Hash: {}\n\
         \n\
         Start Time: {}\n\
         End Time: {}",
        disk.model.as_deref().unwrap_or("Unknown"),
        disk.device_id,
        disk.serial_number.as_deref().unwrap_or("N/A"),
        disk.device_type,
        disk.capacity_display(),
        disk.total_sectors,
        disk.bytes_per_sector,
        disk.interface_type.as_deref().unwrap_or("Unknown"),
        sanitize_result.method.display_name(),
        sanitize_result.method.standard_name(),
        sanitize_result.passes.len(),
        sanitize_result
            .passes
            .iter()
            .map(|p| p.sectors_written)
            .sum::<u64>(),
        sanitize_result.total_duration.as_secs_f64(),
        verify_status,
        verify_result.sectors_verified,
        verify_result.disk_hash,
        start_time,
        end_time,
    );

    groq.chat(SYSTEM_PROMPT, &user_prompt)
}

use super::groq::GroqClient;
use crate::file_eraser::batch::BatchEraseResult;
use crate::file_eraser::FileEraseResult;
use crate::sanitize::patterns::SanitizeMethod;
use anyhow::Result;

const SYSTEM_PROMPT: &str = "\
You are an expert digital forensics investigator providing official statements \
of non-recoverability for sanitization and forensic data destruction certificates. \
Summarize the file destruction operation with rigorous technical precision. \
Detail the forensic techniques applied: multi-pass pattern overwrites, NTFS Alternate Data Stream \
destruction, cluster slack space wiping, and MFT directory entry obfuscation via rename chains. \
Affirm that the targeted files have been permanently neutralized and cannot be recovered by \
commercial or forensic carvers (Autopsy, FTK Imager, Scalpel, PhotoRec). \
Keep it concise, under 180 words, in an authoritative forensic tone.";

/// Generates an AI-powered forensic narrative for a single file erasure.
pub fn generate_file_narrative(
    groq: &GroqClient,
    result: &FileEraseResult,
    start_time: &str,
    end_time: &str,
) -> Result<String> {
    let filename = result
        .path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| result.path.display().to_string());

    let user_prompt = format!(
        "Generate a forensic non-recoverability narrative for this file erasure:\n\
         \n\
         Target File: {}\n\
         Original Size: {} bytes\n\
         Sanitization Method: {} ({})\n\
         Passes Completed: {}\n\
         Bytes Overwritten: {}\n\
         Alternate Data Streams (ADS) Purged: {}\n\
         Cluster Slack Bytes Wiped: {}\n\
         MFT Metadata Cleansed: {}\n\
         MFT Filename Obfuscated: {}\n\
         Deletion Confirmed: {}\n\
         Errors Encountered: {}\n\
         Duration: {:.2}s\n\
         Start: {}\n\
         End: {}",
        filename,
        result.original_size,
        result.method.display_name(),
        result.method.standard_name(),
        result.passes_completed,
        result.bytes_overwritten,
        result.streams_erased,
        result.slack_bytes_wiped,
        if result.metadata_cleansed { "YES" } else { "NO" },
        if result.filename_obfuscated { "YES (5 iterations)" } else { "NO" },
        if result.deleted { "YES" } else { "NO" },
        if result.errors.is_empty() { "None" } else { "Errors noted" },
        result.duration.as_secs_f64(),
        start_time,
        end_time,
    );

    groq.chat(SYSTEM_PROMPT, &user_prompt)
}

/// Generates an AI-powered forensic narrative for a batch file erasure operation.
pub fn generate_batch_narrative(
    groq: &GroqClient,
    result: &BatchEraseResult,
    method: SanitizeMethod,
    target_summary: &str,
    start_time: &str,
    end_time: &str,
) -> Result<String> {
    let user_prompt = format!(
        "Generate a forensic batch destruction certificate narrative:\n\
         \n\
         Batch Scope: {}\n\
         Total Files Processed: {}\n\
         Files Succeeded: {}\n\
         Files Failed: {}\n\
         Success Rate: {:.1}%\n\
         Total Bytes Erased: {} ({:.2} MB)\n\
         Sanitization Method: {} ({})\n\
         Overwriting Passes: {}\n\
         Techniques Applied: Multi-pass pattern write, NTFS ADS destruction, cluster slack wiping, MFT filename scrambling\n\
         Total Duration: {:.2}s\n\
         Start: {}\n\
         End: {}",
        target_summary,
        result.total_files,
        result.files_succeeded,
        result.files_failed,
        result.success_rate(),
        result.total_bytes_erased,
        result.total_bytes_erased as f64 / 1_048_576.0,
        method.display_name(),
        method.standard_name(),
        method.pass_count(),
        result.duration.as_secs_f64(),
        start_time,
        end_time,
    );

    groq.chat(SYSTEM_PROMPT, &user_prompt)
}

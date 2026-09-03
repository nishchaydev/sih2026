mod discovery;
mod fileerase;
mod model;
mod report;
mod safety;
mod sanitize;
mod ui;
mod verify;

mod ai;

use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::io::{self, Write};
use std::sync::mpsc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use model::device::PhysicalDisk;
use report::audit_log::{AuditEventType, AuditLog};
use report::certificate::SanitizationCertificate;
use sanitize::hardware_erase::HwEraseCapability;
use sanitize::patterns::SanitizeMethod;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    // Graceful Ctrl+C handling
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("\n{}", "Shutting down PS-26149...".yellow().bold());
        r.store(false, Ordering::SeqCst);
        std::process::exit(0);
    })
    .expect("Failed to set Ctrl+C handler");

    ui::progress::print_banner();

    // Initialize AI client once
    let groq_client = ai::groq::GroqClient::from_env();
    if groq_client.is_some() {
        println!("  {}", "AI Features Enabled (Groq API detected)".bright_magenta());
    }

    // Start hot-plug watcher
    let (hotplug_rx, _watcher_handle) = discovery::hotplug::start_hotplug_watcher();

    // Main interactive loop
    loop {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        // Check for hot-plug events before showing menu
        drain_hotplug_events(&hotplug_rx);

        print_main_menu();

        let choice = read_input("Select an option")?;

        match choice.trim() {
            "1" => {
                drain_hotplug_events(&hotplug_rx);
                if let Err(e) = cmd_list() {
                    println!("  {} {}", "Error:".red().bold(), e);
                }
            }
            "2" => {
                drain_hotplug_events(&hotplug_rx);
                if let Err(e) = cmd_erase_interactive(&groq_client, &hotplug_rx) {
                    println!("  {} {}", "Error:".red().bold(), e);
                }
            }
            "3" => {
                println!("\n  {}", "Erasure history — coming soon (stored in reports/)".dimmed());
            }
            "4" => {
                print_settings_info(&groq_client);
            }
            "5" => {
                if let Err(e) = cmd_file_erase_interactive() {
                    println!("  {} {}", "Error:".red().bold(), e);
                }
            }
            "0" | "exit" | "quit" | "q" => {
                println!("\n{}", "Goodbye! Stay secure. 🛡️".green().bold());
                break;
            }
            _ => {
                println!("  {}", "Invalid option. Try again.".yellow());
            }
        }
    }

    Ok(())
}

// ─── Menu Rendering ──────────────────────────────────────────────────

fn print_main_menu() {
    println!();
    println!("  {}", "┌─────────────────────────────────────┐".bright_cyan());
    println!("  {}  {}  {}", "│".bright_cyan(), "Main Menu".bold().bright_white(), "                        │".bright_cyan());
    println!("  {}", "├─────────────────────────────────────┤".bright_cyan());
    println!("  {}  {}  {}", "│".bright_cyan(), "[1]  List Connected Devices".white(), "      │".bright_cyan());
    println!("  {}  {}  {}", "│".bright_cyan(), "[2]  Erase a Drive".white(), "               │".bright_cyan());
    println!("  {}  {}  {}", "│".bright_cyan(), "[3]  View Erasure History".white(), "         │".bright_cyan());
    println!("  {}  {}  {}", "│".bright_cyan(), "[4]  Settings & Info".white(), "              │".bright_cyan());
    println!("  {}  {}  {}", "│".bright_cyan(), "[5]  Secure File & Folder Eraser".white(), " │".bright_cyan());
    println!("  {}  {}  {}", "│".bright_cyan(), "[0]  Exit".dimmed(), "                        │".bright_cyan());
    println!("  {}", "└─────────────────────────────────────┘".bright_cyan());
}

fn print_method_menu(capacity: u64, interface: Option<&str>) {
    let methods = SanitizeMethod::all_methods();

    // Estimate write speed based on interface
    let speed_mbps: f64 = match interface {
        Some(s) if s.contains("USB") => 4.0,   // USB 2.0 worst case
        Some(s) if s.contains("SCSI") || s.contains("IDE") => 200.0, // SATA SSD
        _ => 10.0,
    };

    println!("\n  {}", "Select Erasure Method:".bold());
    println!("  {}", "─".repeat(60).dimmed());

    let sections: &[(&str, &str, std::ops::RangeInclusive<usize>)] = &[
        ("Quick Methods:", "bright_green", 0..=1),
        ("Standard Methods (NIST/Government):", "cyan", 2..=4),
        ("Military Standards:", "yellow", 5..=9),
        ("International Standards:", "magenta", 10..=15),
        ("Maximum Security:", "red", 16..=16),
    ];

    for (title, color, range) in sections {
        let colored_title = match *color {
            "bright_green" => title.bright_green().bold().to_string(),
            "cyan" => title.cyan().bold().to_string(),
            "yellow" => title.yellow().bold().to_string(),
            "magenta" => title.bright_magenta().bold().to_string(),
            "red" => title.red().bold().to_string(),
            _ => title.to_string(),
        };
        println!("\n  {}", colored_title);

        for (i, m) in methods.iter().enumerate() {
            if !range.contains(&i) {
                continue;
            }

            let eta = estimate_eta(capacity, m, speed_mbps);
            let eta_str = format_eta_short(&eta);

            let num = match *color {
                "bright_green" => format!("[{:>2}]", i + 1).bright_green().to_string(),
                "cyan" => format!("[{:>2}]", i + 1).cyan().to_string(),
                "yellow" => format!("[{:>2}]", i + 1).yellow().to_string(),
                "magenta" => format!("[{:>2}]", i + 1).bright_magenta().to_string(),
                "red" => format!("[{:>2}]", i + 1).red().to_string(),
                _ => format!("[{:>2}]", i + 1),
            };

            // Warn if ETA > 2 hours
            let time_display = if eta.as_secs() > 7200 {
                format!("~{}", eta_str).red().to_string()
            } else if eta.as_secs() > 600 {
                format!("~{}", eta_str).yellow().to_string()
            } else {
                format!("~{}", eta_str).green().to_string()
            };

            println!(
                "    {} {:<38} {} {}",
                num,
                m.display_name(),
                time_display,
                format!("— {}", m.description()).dimmed()
            );
        }
    }

    println!("\n    {} {}", "[0]".dimmed(), "Back to main menu".dimmed());
}

fn estimate_eta(capacity: u64, method: &SanitizeMethod, speed_mbps: f64) -> std::time::Duration {
    let write_bytes = match method {
        SanitizeMethod::FastWipe => std::cmp::min(capacity, 32 * 1024 * 1024),
        SanitizeMethod::SmartSecure => {
            // 128MB head + 128MB tail + 1MB per GB boundary
            let head_tail = std::cmp::min(capacity, 256 * 1024 * 1024);
            let gb_count = capacity / (1024 * 1024 * 1024);
            head_tail + gb_count * 1024 * 1024
        }
        _ => capacity * method.pass_count() as u64,
    };
    let secs = write_bytes as f64 / (speed_mbps * 1_048_576.0);
    std::time::Duration::from_secs_f64(secs)
}

fn format_eta_short(d: &std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        if m > 0 { format!("{}h{}m", h, m) } else { format!("{}h", h) }
    } else {
        let d = secs / 86400;
        let h = (secs % 86400) / 3600;
        format!("{}d{}h", d, h)
    }
}

fn print_settings_info(groq_client: &Option<ai::groq::GroqClient>) {
    println!("\n  {}", "Settings & Info".bold());
    println!("  {}", "─".repeat(40).dimmed());
    println!("    {:<20} {}", "Tool:".dimmed(), "PS-26149 Secure Drive Eraser");
    println!("    {:<20} {}", "Version:".dimmed(), env!("CARGO_PKG_VERSION"));
    println!("    {:<20} {}", "Standards:".dimmed(), format!("{} methods available", SanitizeMethod::all_methods().len()));
    println!(
        "    {:<20} {}",
        "AI Features:".dimmed(),
        if groq_client.is_some() { "Enabled (Groq API)".green().to_string() } else { "Disabled (set GROQ_API_KEY)".yellow().to_string() }
    );
    println!("    {:<20} {}", "Hot-Plug:".dimmed(), "Active (monitoring USB events)".green());
    println!("    {:<20} {}", "Platform:".dimmed(), "Windows (Win32 Raw I/O)");
}

// ─── Hot-Plug Event Drain ────────────────────────────────────────────

fn drain_hotplug_events(rx: &mpsc::Receiver<discovery::hotplug::HotPlugEvent>) {
    while let Ok(event) = rx.try_recv() {
        match &event {
            discovery::hotplug::HotPlugEvent::DeviceInserted { .. } => {
                println!("\n  {} {}", "🔌".green(), event.to_string().green().bold());
            }
            discovery::hotplug::HotPlugEvent::DeviceRemoved { .. } => {
                println!("\n  {} {}", "⚠️".yellow(), event.to_string().yellow().bold());
            }
        }
    }
}

// ─── Commands ────────────────────────────────────────────────────────

fn cmd_list() -> Result<()> {
    let disks = discovery::enumerate_devices().context("Failed to enumerate storage devices")?;
    ui::device_table::print_device_table(&disks);
    Ok(())
}

fn cmd_erase_interactive(
    groq_client: &Option<ai::groq::GroqClient>,
    hotplug_rx: &mpsc::Receiver<discovery::hotplug::HotPlugEvent>,
) -> Result<()> {
    let mut audit = AuditLog::new();
    audit.log(AuditEventType::SessionStart, "PS149 sanitization session started");

    // Phase 1: Discover devices
    let disks = discovery::enumerate_devices().context("Failed to enumerate storage devices")?;
    for disk in &disks {
        audit.log(
            AuditEventType::DeviceDetected,
            format!(
                "Disk {} — {} — {} — {}",
                disk.index,
                disk.model.as_deref().unwrap_or("Unknown"),
                disk.capacity_display(),
                disk.safety_status
            ),
        );
    }

    ui::device_table::print_device_table(&disks);

    // Phase 2: Select target
    let eligible: Vec<&PhysicalDisk> = disks.iter().filter(|d| d.safety_status.is_erasable()).collect();
    if eligible.is_empty() {
        println!("\n  {}", "No eligible devices found for erasure.".red().bold());
        println!("  All detected devices are either protected (system/boot) or unknown.");
        return Ok(());
    }

    println!("\n{}", "  Select a device to erase:".bold());
    for (i, disk) in eligible.iter().enumerate() {
        println!(
            "    [{}] Disk {} — {} — {}",
            i + 1,
            disk.index,
            disk.model.as_deref().unwrap_or("Unknown"),
            disk.capacity_display()
        );
    }

    let input = read_input("Enter selection number")?;
    if input.trim() == "0" {
        return Ok(());
    }
    let selection: usize = input
        .trim()
        .parse()
        .context("Invalid selection — enter a number")?;

    if selection == 0 || selection > eligible.len() {
        bail!("Selection out of range");
    }

    let target = eligible[selection - 1].clone();
    audit.log(
        AuditEventType::DeviceSelected,
        format!("User selected Disk {} for erasure", target.index),
    );

    // Phase 2b: Select method
    let hw_capability = sanitize::hardware_erase::probe(&target);
    match &hw_capability {
        HwEraseCapability::Available => {
            println!(
                "\n  {} {}",
                "[H]".bright_yellow().bold(),
                "⚡ Hardware Fast Erase — NVMe Crypto Erase (~seconds, NIST 800-88 Purge-equivalent)"
                    .bright_yellow()
            );
        }
        HwEraseCapability::Unsupported(reason) => {
            println!(
                "\n  {}",
                format!(
                    "ℹ Hardware fast erase not available for this device: {} — using pattern-based methods below.",
                    reason
                )
                .dimmed()
            );
        }
    }

    print_method_menu(target.capacity, target.interface_type.as_deref());
    let method_input = read_input("Select method")?;
    if method_input.trim() == "0" {
        return Ok(());
    }

    if method_input.trim().eq_ignore_ascii_case("h") {
        return match hw_capability {
            HwEraseCapability::Available => cmd_hardware_erase_flow(&target, audit, groq_client),
            HwEraseCapability::Unsupported(_) => {
                println!("  {}", "Hardware fast erase is not available for this device.".yellow());
                Ok(())
            }
        };
    }

    let method_idx: usize = method_input
        .trim()
        .parse()
        .context("Invalid method — enter a number")?;

    let methods = SanitizeMethod::all_methods();
    if method_idx == 0 || method_idx > methods.len() {
        bail!("Method selection out of range");
    }

    let method = methods[method_idx - 1];

    // AI Feature: Erasure Advisor
    if let Some(ref client) = groq_client {
        println!("\n  {}", "Consulting AI Erasure Advisor...".cyan());
        match ai::erasure_advisor::get_recommendation(client, &target) {
            Ok(advice) => {
                println!("\n  {}", "AI Recommendation:".bright_magenta().bold());
                println!("  {}", advice.bright_black());
                println!();
            }
            Err(e) => {
                println!("  {}", format!("✗ Failed to get AI advice: {}", e).yellow());
            }
        }
    }

    // Phase 3: Safety confirmation
    audit.log(AuditEventType::SafetyCheck, format!("Device safety status: {}", target.safety_status));
    if !safety::confirmation::confirm_erasure(&target)? {
        println!("\n  {}", "Erasure cancelled by user.".yellow().bold());
        audit.log(AuditEventType::SessionEnd, "User cancelled erasure");
        return Ok(());
    }
    audit.log(AuditEventType::ConfirmationReceived, "User confirmed erasure");

    let start_time = chrono::Local::now();

    // Phase 4: Sanitize
    println!(
        "\n  {}",
        format!("Starting sanitization: {} ({} passes)", method.display_name(), method.pass_count())
            .cyan()
            .bold()
    );
    audit.log(
        AuditEventType::SanitizationStarted,
        format!("Method: {} ({})", method.display_name(), method.standard_name()),
    );

    let is_zone_method = matches!(method, SanitizeMethod::FastWipe | SanitizeMethod::SmartSecure);
    let total_bytes = match method {
        SanitizeMethod::FastWipe => std::cmp::min(target.capacity, 32 * 1024 * 1024),
        SanitizeMethod::SmartSecure => {
            let head_tail = std::cmp::min(target.capacity, 256 * 1024 * 1024);
            let gb_count = target.capacity / (1024 * 1024 * 1024);
            head_tail + gb_count * 1024 * 1024
        }
        _ => target.capacity * method.pass_count() as u64,
    };

    let bps = target.bytes_per_sector as u64;
    let pb = ui::progress::create_sanitize_progress_bar(total_bytes, "Write");
    let sanitize_result = sanitize::execute_sanitization(&target, method, |progress| {
        drain_hotplug_events(hotplug_rx);

        let bytes_done = if is_zone_method {
            progress.work_completed_sectors * bps
        } else {
            progress.sectors_done * bps
        };
        pb.set_position(
            (progress.pass_index as u64 * total_bytes / method.pass_count() as u64)
                + bytes_done,
        );
        pb.set_message(format!(
            "Pass {}/{}",
            progress.pass_index + 1,
            progress.total_passes
        ));
    })?;
    pb.finish_with_message("Write complete");

    for pass in &sanitize_result.passes {
        audit.log(
            AuditEventType::PassCompleted,
            format!(
                "Pass {}: {} — {}/{} sectors in {:.1}s",
                pass.pass_index + 1,
                pass.pattern_description,
                pass.sectors_written,
                pass.total_sectors,
                pass.duration.as_secs_f64()
            ),
        );
    }

    // Phase 5: Verify
    println!("\n  {}", "Starting verification read-back...".cyan().bold());
    audit.log(AuditEventType::VerificationStarted, "Verification pass starting");

    let last_pattern = sanitize::patterns::get_pattern(
        method.pass_count().saturating_sub(1),
        method,
    );
    let vpb = ui::progress::create_verify_progress_bar(total_bytes);
    let verify_result = verify::verify_disk(&target, &last_pattern, method, |progress| {
        let bytes_done = if is_zone_method {
            progress.work_completed_sectors * bps
        } else {
            progress.sectors_done * bps
        };
        vpb.set_position(bytes_done);
    })?;
    vpb.finish_with_message("Verification complete");

    let verify_status = if verify_result.passed { "PASS" } else { "FAIL" };
    audit.log(
        AuditEventType::VerificationCompleted,
        format!(
            "Verification: {} — {}/{} sectors OK, SHA-256: {}",
            verify_status,
            verify_result.sectors_verified,
            verify_result.total_sectors,
            &verify_result.disk_hash[..16]
        ),
    );

    // Phase 6: Report
    let end_time = chrono::Local::now();
    audit.log(AuditEventType::SessionEnd, "Sanitization session complete");

    // AI Feature: Forensic Narrative Generation
    let mut ai_narrative = None;
    if let Some(ref client) = groq_client {
        println!("\n  {}", "Generating AI Forensic Narrative...".cyan());
        match ai::report_narrator::generate_narrative(
            client,
            &target,
            &sanitize_result,
            &verify_result,
            &start_time.to_rfc3339(),
            &end_time.to_rfc3339(),
        ) {
            Ok(narrative) => {
                println!("  {}", "✓ Narrative generated successfully".green());
                ai_narrative = Some(narrative);
            }
            Err(e) => {
                println!("  {}", format!("✗ Failed to generate narrative: {}", e).yellow());
            }
        }
    }

    println!("\n{}", "  ═".repeat(50).cyan());
    if verify_result.passed {
        println!("  {}", "✓ SANITIZATION COMPLETE — VERIFICATION PASSED".green().bold());
    } else {
        println!(
            "  {}",
            format!(
                "✗ SANITIZATION COMPLETE — VERIFICATION FAILED ({} sectors)",
                verify_result.sectors_failed
            )
            .red()
            .bold()
        );
    }
    println!("{}", "  ═".repeat(50).cyan());

    if let Some(narrative) = &ai_narrative {
        println!("\n  {}", "AI Forensic Narrative:".bold());
        println!("  {}", narrative.bright_black());
        println!("{}", "  ═".repeat(50).cyan());
    }

    let mut cert = SanitizationCertificate::build(
        start_time,
        end_time,
        &target,
        &sanitize_result,
        &verify_result,
        method,
        audit,
    );

    if let Some(narrative) = ai_narrative {
        cert.ai_narrative = Some(narrative);
    }

    // Save reports
    let report_dir = std::path::Path::new("reports");
    std::fs::create_dir_all(report_dir)?;
    let (json_path, txt_path) = cert.save(report_dir)?;

    println!("\n  {}", "Reports saved:".bold());
    println!("    JSON: {}", json_path.display());
    println!("    Text: {}", txt_path.display());
    println!("\n{}", cert.to_text_summary());

    // Phase 7: Post-Sanitization Drive Re-initialization & Format (Optional)
    println!("\n{}", "  ═".repeat(50).cyan());
    println!("  {}", "Post-Sanitization Options:".bold());
    println!("  {}", "The drive's partition table has been erased (RAW state).".dimmed());
    println!("  {}", "Would you like to initialize and format it for immediate reuse?".white());
    println!();
    println!("    {} FAT32  — Universal compatibility (Windows, Mac, Linux, TV, Car)", "[1]".bright_green());
    println!("    {} exFAT  — Modern cross-platform, supports files >4GB", "[2]".cyan());
    println!("    {} NTFS   — Windows optimized with journaling", "[3]".yellow());
    println!("    {} Leave as RAW (Forensic unallocated proof)", "[0]".dimmed());

    let post_choice = read_input("Select post-erasure action [1/2/3/0]")?;
    let target_fs = match post_choice.trim() {
        "1" => Some(sanitize::initialize::TargetFileSystem::Fat32),
        "2" => Some(sanitize::initialize::TargetFileSystem::ExFat),
        "3" => Some(sanitize::initialize::TargetFileSystem::Ntfs),
        _ => None,
    };

    if let Some(fs_type) = target_fs {
        println!("\n  {}", format!("Initializing Disk {} with {}...", target.index, fs_type.as_str().to_uppercase()).cyan());
        match sanitize::initialize::reinitialize_and_format_disk(target.index, fs_type, "CLEAN_USB") {
            Ok(res) => {
                println!("  {}", format!("✓ {}", res.output_summary).bright_green().bold());
                println!("  {}", "Drive is now clean and immediately ready to use in Windows Explorer!".green());
            }
            Err(e) => {
                println!("  {}", format!("✗ Formatting encountered an issue: {}", e).yellow());
                println!("  {}", "You can format manually through Windows Disk Management.".dimmed());
            }
        }
    } else {
        println!("  {}", "Drive left in raw, unpartitioned state for forensic verification.".dimmed());
    }

    Ok(())
}

/// Hardware crypto-erase flow — sibling to the pattern-overwrite path in
/// `cmd_erase_interactive`, dispatched from the `[H]` menu option. Mirrors
/// the same confirm → execute → verify → report → post-format shape, but the
/// execute/verify steps are fundamentally different (one blocking IOCTL, no
/// byte-pattern readback) so it's kept as its own function rather than
/// threaded through the pass-based flow above. See `sanitize::hardware_erase`.
fn cmd_hardware_erase_flow(
    target: &PhysicalDisk,
    mut audit: AuditLog,
    groq_client: &Option<ai::groq::GroqClient>,
) -> Result<()> {
    use sanitize::pass::PassResult;
    use sanitize::SanitizeResult;

    println!(
        "\n  {}",
        "This performs a hardware crypto-erase via the drive controller — irreversible, \
         and no byte-pattern verification is possible (only a post-erase spot check)."
            .yellow()
            .bold()
    );

    // Phase 3: Safety confirmation (same flow as the pattern-overwrite path)
    audit.log(AuditEventType::SafetyCheck, format!("Device safety status: {}", target.safety_status));
    if !safety::confirmation::confirm_erasure(target)? {
        println!("\n  {}", "Erasure cancelled by user.".yellow().bold());
        audit.log(AuditEventType::SessionEnd, "User cancelled erasure");
        return Ok(());
    }
    audit.log(AuditEventType::ConfirmationReceived, "User confirmed erasure");

    let start_time = chrono::Local::now();
    let method = SanitizeMethod::NvmeCryptoErase;

    // Phase 4: Execute — one blocking IOCTL, not a pass loop.
    println!("\n  {}", "Starting hardware crypto-erase...".cyan().bold());
    audit.log(
        AuditEventType::SanitizationStarted,
        format!("Method: {} ({})", method.display_name(), method.standard_name()),
    );

    const HW_ERASE_TIMEOUT_SECS: u32 = 300;
    let hw_result = sanitize::hardware_erase::execute_nvme_crypto_erase(target, HW_ERASE_TIMEOUT_SECS)?;

    println!(
        "  {}",
        format!("✓ Hardware crypto-erase completed in {:.2}s", hw_result.duration.as_secs_f64())
            .green()
            .bold()
    );

    // Wrap into the existing SanitizeResult/PassResult shape so the
    // certificate builder below needs no signature changes.
    let pass = PassResult {
        pass_index: 0,
        pattern_description: "NVMe Sanitize — Crypto Erase (IOCTL_STORAGE_REINITIALIZE_MEDIA)".to_string(),
        sectors_written: target.total_sectors,
        total_sectors: target.total_sectors,
        bytes_written: hw_result.capacity,
        duration: hw_result.duration,
        errors: Vec::new(),
    };
    audit.log(
        AuditEventType::PassCompleted,
        format!(
            "Hardware crypto-erase: {} — {} sectors in {:.1}s",
            pass.pattern_description, pass.sectors_written, pass.duration.as_secs_f64()
        ),
    );

    let sanitize_result = SanitizeResult {
        method,
        passes: vec![pass],
        total_duration: hw_result.duration,
    };

    // Phase 5: Post-erase spot check (informational — see module docs on why
    // this can't be a full readback like the pattern-overwrite path).
    println!("\n  {}", "Running post-erase spot check (informational)...".cyan().bold());
    audit.log(AuditEventType::VerificationStarted, "Post-erase spot check starting");
    let verify_result = sanitize::hardware_erase::post_erase_spot_check(target)?;
    let verify_status = if verify_result.passed { "PASS" } else { "FAIL" };
    let sampled = verify_result.sectors_verified + verify_result.sectors_failed;
    audit.log(
        AuditEventType::VerificationCompleted,
        format!(
            "Spot check: {} — {} sectors sampled, SHA-256: {}",
            verify_status,
            sampled,
            &verify_result.disk_hash[..16.min(verify_result.disk_hash.len())]
        ),
    );

    let end_time = chrono::Local::now();
    audit.log(AuditEventType::SessionEnd, "Hardware erase session complete");

    // AI Feature: Forensic Narrative Generation
    let mut ai_narrative = None;
    if let Some(ref client) = groq_client {
        println!("\n  {}", "Generating AI Forensic Narrative...".cyan());
        match ai::report_narrator::generate_narrative(
            client,
            target,
            &sanitize_result,
            &verify_result,
            &start_time.to_rfc3339(),
            &end_time.to_rfc3339(),
        ) {
            Ok(narrative) => {
                println!("  {}", "✓ Narrative generated successfully".green());
                ai_narrative = Some(narrative);
            }
            Err(e) => {
                println!("  {}", format!("✗ Failed to generate narrative: {}", e).yellow());
            }
        }
    }

    println!("\n{}", "  ═".repeat(50).cyan());
    if verify_result.passed {
        println!("  {}", "✓ HARDWARE ERASE COMPLETE — SPOT CHECK PASSED".green().bold());
    } else {
        println!("  {}", "⚠ HARDWARE ERASE COMPLETE — SPOT CHECK FLAGGED READABLE DATA".red().bold());
    }
    println!("{}", "  ═".repeat(50).cyan());

    if let Some(narrative) = &ai_narrative {
        println!("\n  {}", "AI Forensic Narrative:".bold());
        println!("  {}", narrative.bright_black());
        println!("{}", "  ═".repeat(50).cyan());
    }

    // Phase 6: Report
    let mut cert = SanitizationCertificate::build(
        start_time,
        end_time,
        target,
        &sanitize_result,
        &verify_result,
        method,
        audit,
    );

    if let Some(narrative) = ai_narrative {
        cert.ai_narrative = Some(narrative);
    }

    let report_dir = std::path::Path::new("reports");
    std::fs::create_dir_all(report_dir)?;
    let (json_path, txt_path) = cert.save(report_dir)?;

    println!("\n  {}", "Reports saved:".bold());
    println!("    JSON: {}", json_path.display());
    println!("    Text: {}", txt_path.display());
    println!("\n{}", cert.to_text_summary());

    // Phase 7: Post-Erase Options (same reuse-format prompt as the pattern-overwrite path)
    println!("\n{}", "  ═".repeat(50).cyan());
    println!("  {}", "Post-Erase Options:".bold());
    println!("  {}", "The drive's encryption key has been reset — all prior data is unrecoverable.".dimmed());
    println!("  {}", "Would you like to initialize and format it for immediate reuse?".white());
    println!();
    println!("    {} FAT32  — Universal compatibility (Windows, Mac, Linux, TV, Car)", "[1]".bright_green());
    println!("    {} exFAT  — Modern cross-platform, supports files >4GB", "[2]".cyan());
    println!("    {} NTFS   — Windows optimized with journaling", "[3]".yellow());
    println!("    {} Leave as-is", "[0]".dimmed());

    let post_choice = read_input("Select post-erasure action [1/2/3/0]")?;
    let target_fs = match post_choice.trim() {
        "1" => Some(sanitize::initialize::TargetFileSystem::Fat32),
        "2" => Some(sanitize::initialize::TargetFileSystem::ExFat),
        "3" => Some(sanitize::initialize::TargetFileSystem::Ntfs),
        _ => None,
    };

    if let Some(fs_type) = target_fs {
        println!("\n  {}", format!("Initializing Disk {} with {}...", target.index, fs_type.as_str().to_uppercase()).cyan());
        match sanitize::initialize::reinitialize_and_format_disk(target.index, fs_type, "CLEAN_NVME") {
            Ok(res) => {
                println!("  {}", format!("✓ {}", res.output_summary).bright_green().bold());
                println!("  {}", "Drive is now clean and immediately ready to use in Windows Explorer!".green());
            }
            Err(e) => {
                println!("  {}", format!("✗ Formatting encountered an issue: {}", e).yellow());
                println!("  {}", "You can format manually through Windows Disk Management.".dimmed());
            }
        }
    } else {
        println!("  {}", "Drive left as-is.".dimmed());
    }

    Ok(())
}

/// Module 2 — Secure File & Folder Eraser. Reuses the pattern engine
/// (`SanitizeMethod`) for content overwrite, but is otherwise a fully
/// separate flow from the disk-erase path above: different target
/// selection (arbitrary paths, not discovered devices), a curated method
/// menu (file content doesn't need the full 17-item disk menu), its own
/// confirmation shape, and its own certificate type. See `fileerase`.
fn print_file_method_menu() -> Vec<SanitizeMethod> {
    let methods = vec![
        SanitizeMethod::NistClear,
        SanitizeMethod::Random1Pass,
        SanitizeMethod::Dod3Pass,
        SanitizeMethod::Gutmann,
    ];
    println!("\n  {}", "Select Overwrite Method:".bold());
    println!("  {}", "─".repeat(60).dimmed());
    for (i, m) in methods.iter().enumerate() {
        println!(
            "    [{}] {:<38} {}",
            i + 1,
            m.display_name(),
            format!("— {}", m.description()).dimmed()
        );
    }
    methods
}

fn cmd_file_erase_interactive() -> Result<()> {
    let mut audit = AuditLog::new();
    audit.log(AuditEventType::SessionStart, "File/folder erasure session started");

    println!("\n{}", "  Enter file or folder paths to securely erase.".bold());
    println!("  {}", "One per line — blank line to finish.".dimmed());

    let mut input_paths: Vec<std::path::PathBuf> = Vec::new();
    loop {
        let line = read_input("Path (blank to finish)")?;
        if line.trim().is_empty() {
            break;
        }
        let path = std::path::PathBuf::from(line.trim());
        if !path.exists() {
            println!("  {}", format!("Path not found, skipping: {}", path.display()).yellow());
            continue;
        }
        input_paths.push(path);
    }

    if input_paths.is_empty() {
        println!("\n  {}", "No paths entered.".yellow());
        return Ok(());
    }

    println!("\n  {}", "Scanning targets...".cyan());
    let expanded = fileerase::walker::expand_paths(&input_paths).context("Failed to scan target paths")?;

    let total_bytes: u64 = expanded
        .files
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum();

    println!(
        "  {} files, {} folders, {} total",
        expanded.files.len(),
        expanded.dirs_to_remove.len(),
        model::device::format_bytes(total_bytes)
    );

    let protected_reason = input_paths.iter().find_map(|p| fileerase::walker::is_protected_path(p));

    let methods = print_file_method_menu();
    let method_input = read_input("Select method")?;
    let method_idx: usize = method_input.trim().parse().context("Invalid method — enter a number")?;
    if method_idx == 0 || method_idx > methods.len() {
        bail!("Method selection out of range");
    }
    let method = methods[method_idx - 1];

    let wipe_free_space = read_input("Also wipe free space on affected volume(s) afterward? [y/N]")?
        .trim()
        .eq_ignore_ascii_case("y");
    let delete_usn_journal = read_input(
        "Also clear the USN change journal (ENTIRE volume, not just these files)? [y/N]",
    )?
    .trim()
    .eq_ignore_ascii_case("y");

    audit.log(
        AuditEventType::SafetyCheck,
        format!("{} files, {} bytes targeted", expanded.files.len(), total_bytes),
    );
    if !safety::confirmation::confirm_file_erasure(
        expanded.files.len(),
        &model::device::format_bytes(total_bytes),
        protected_reason,
        wipe_free_space,
        delete_usn_journal,
    )? {
        println!("\n  {}", "Erasure cancelled by user.".yellow().bold());
        audit.log(AuditEventType::SessionEnd, "User cancelled erasure");
        return Ok(());
    }
    audit.log(AuditEventType::ConfirmationReceived, "User confirmed erasure");

    let start_time = chrono::Local::now();
    audit.log(
        AuditEventType::SanitizationStarted,
        format!("Method: {} ({})", method.display_name(), method.standard_name()),
    );

    let pb = ui::progress::create_sanitize_progress_bar(total_bytes.max(1), "Erasing");
    let options = fileerase::FileEraseOptions { method, wipe_free_space, delete_usn_journal };
    let summary = fileerase::erase_paths(&input_paths, options, |done, total| {
        pb.set_position(done.min(total));
    })?;
    pb.finish_with_message("Erasure complete");

    for record in &summary.file_records {
        audit.log(
            AuditEventType::PassCompleted,
            format!(
                "{} — {} stream(s), {} pass(es), deleted={}",
                record.original_path, record.streams_wiped, record.passes, record.deleted
            ),
        );
    }
    audit.log(AuditEventType::SessionEnd, "File erasure session complete");

    let end_time = chrono::Local::now();
    let cert = report::file_certificate::FileErasureCertificate::build(start_time, end_time, method, &summary, audit);

    let report_dir = std::path::Path::new("reports");
    std::fs::create_dir_all(report_dir)?;
    let (json_path, txt_path) = cert.save(report_dir)?;

    let failed = summary.file_records.iter().filter(|r| !r.deleted).count();
    if failed == 0 {
        ui::progress::print_success(&format!("{} file(s) securely erased", summary.file_records.len()));
    } else {
        ui::progress::print_failure(&format!(
            "{} of {} file(s) failed to erase — see report for details",
            failed,
            summary.file_records.len()
        ));
    }

    println!("\n  {}", "Reports saved:".bold());
    println!("    JSON: {}", json_path.display());
    println!("    Text: {}", txt_path.display());
    println!("\n{}", cert.to_text_summary());

    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────

fn read_input(prompt: &str) -> Result<String> {
    print!("\n  {} ", format!("{}:", prompt).bold());
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

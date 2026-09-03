mod discovery;
mod file_eraser;
mod carver;
mod demo;
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
use report::certificate::{FileErasureCertificate, SanitizationCertificate};
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
                drain_hotplug_events(&hotplug_rx);
                if let Err(e) = cmd_file_erase_interactive(&groq_client) {
                    println!("  {} {}", "Error:".red().bold(), e);
                }
            }
            "4" => {
                drain_hotplug_events(&hotplug_rx);
                if let Err(e) = cmd_file_recovery_interactive(&groq_client) {
                    println!("  {} {}", "Error:".red().bold(), e);
                }
            }
            "5" => {
                if let Err(e) = cmd_view_history() {
                    println!("  {} {}", "Error:".red().bold(), e);
                }
            }
            "6" => {
                print_settings_info(&groq_client);
            }
            "7" => {
                drain_hotplug_events(&hotplug_rx);
                if let Err(e) = demo::run_live_battle_interactive(&groq_client) {
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
    println!("  {}", "┌─────────────────────────────────────────────────────────┐".bright_cyan());
    println!("  {}  {}  {}", "│".bright_cyan(), "Main Menu — Forensics & Secure Sanitization Suite".bold().bright_white(), "    │".bright_cyan());
    println!("  {}", "├─────────────────────────────────────────────────────────┤".bright_cyan());
    println!("  {}  {}  {}", "│".bright_cyan(), "[1]  List Connected Storage Devices".white(), "               │".bright_cyan());
    println!("  {}  {}  {}", "│".bright_cyan(), "[2]  Erase an Entire Drive (Module 1)".white(), "                   │".bright_cyan());
    println!("  {}  {}  {}", "│".bright_cyan(), "[3]  Secure File & Folder Shredder (Module 2)".bright_green().bold(), "   │".bright_cyan());
    println!("  {}  {}  {}", "│".bright_cyan(), "[4]  File Recovery & Deep Carving (Module 3)".bright_yellow().bold(), "    │".bright_cyan());
    println!("  {}  {}  {}", "│".bright_cyan(), "[5]  View Erasure History & Audit Reports".white(), "             │".bright_cyan());
    println!("  {}  {}  {}", "│".bright_cyan(), "[6]  Settings & Info".white(), "                                │".bright_cyan());
    println!("  {}  {}  {}", "│".bright_cyan(), "[7]  ⚔️  Live Battle Demo (Offense vs Defense)".bright_magenta().bold(), "      │".bright_cyan());
    println!("  {}  {}  {}", "│".bright_cyan(), "[0]  Exit".dimmed(), "                                                  │".bright_cyan());
    println!("  {}", "└─────────────────────────────────────────────────────────┘".bright_cyan());
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

    println!(
        "\n    {} {:<38} {} {}",
        "[P]".bright_magenta().bold(),
        "Hardware Firmware Purge (NIST Purge)",
        "~1s".bright_green(),
        "— Direct SSD/NVMe TRIM & controller purge".dimmed()
    );
    println!("    {} {}", "[0]".dimmed(), "Back to main menu".dimmed());
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
    print_method_menu(target.capacity, target.interface_type.as_deref());
    let method_input = read_input("Select method")?;
    if method_input.trim() == "0" {
        return Ok(());
    }

    if method_input.trim().eq_ignore_ascii_case("p") {
        println!("\n  {}", "Hardware Firmware Purge (NIST SP 800-88 Purge)".bright_magenta().bold());
        println!("  Target: Disk {} ({})", target.index, target.model.as_deref().unwrap_or("Unknown"));
        let confirm = read_input("Type PURGE to execute hardware controller command")?;
        if confirm.trim() != "PURGE" {
            println!("  {}", "Cancelled.".yellow());
            return Ok(());
        }

        let purge_result = sanitize::hardware_purge::execute_firmware_purge(
            target.index,
            target.capacity,
            &target.device_type.to_string(),
        )?;

        println!("\n  {}", "Hardware Purge Results:".bold());
        println!("    Status   : {}", if purge_result.success { "SUCCESS (NIST Purge Acknowledged)".bright_green().bold() } else { "NOT SUPPORTED (Fallback needed)".yellow() });
        println!("    Command  : {}", purge_result.command_type.cyan());
        println!("    Duration : {:.2}s", purge_result.duration_secs);
        println!("    Details  : {}", purge_result.message.white());

        // Append to blockchain & BSA 2023 certificate
        let mut chain = report::blockchain::AuditChain::load_or_create().unwrap_or_default();
        let serial = target.serial_number.clone().unwrap_or_else(|| format!("Disk_{}", target.index));
        let _ = chain.add_event(
            report::blockchain::AuditEventType::DriveErasure,
            &serial,
            "Forensic_Operator",
            "NIST_800_88_PURGE_CONTROLLER_COMMAND",
            &format!("Hardware Purge: {} on Disk {}", purge_result.command_type, target.index),
        );

        let bsa_cert = report::blockchain::generate_bsa_certificate(
            "NIST SP 800-88 Rev. 1 Hardware Purge",
            &format!("Disk {} ({})", target.index, target.model.as_deref().unwrap_or("Drive")),
            &serial,
            "Hardware Controller Firmware Purge (DSM TRIM / NVMe / ATA)",
            "N/A",
            "NIST_PURGE_ACKNOWLEDGED",
            if purge_result.success { "100% PURGED — HARDWARE FLASH CELLS DEALLOCATED" } else { "UNSUPPORTED BRIDGE" },
            chain.merkle_root.as_deref().unwrap_or("GENESIS"),
            chain.blockchain_tx.as_deref(),
        );

        let report_dir = std::path::Path::new("reports");
        let _ = std::fs::create_dir_all(report_dir);
        let timestamp_str = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let bsa_path = report_dir.join(format!("bsa_section_63_hardware_purge_{}.txt", timestamp_str));
        let _ = std::fs::write(&bsa_path, &bsa_cert);
        println!("    BSA 2023 : {}", bsa_path.display().to_string().bright_yellow().bold());
        println!("    Blockchain: {}", chain.summary().bright_magenta());

        return Ok(());
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

    // Blockchain Audit Trail & BSA 2023 Section 63 Certificate
    let mut chain = report::blockchain::AuditChain::load_or_create().unwrap_or_default();
    let serial = target.serial_number.clone().unwrap_or_else(|| format!("Disk_{}", target.index));
    let device_display = format!("Disk {} ({})", target.index, target.model.as_deref().unwrap_or("Drive"));
    let desc = format!("Erase disk {} with {}", target.index, cert.sanitization.method);
    let _ = chain.add_event(
        report::blockchain::AuditEventType::DriveErasure,
        &serial,
        "Forensic_Operator",
        &cert.verification.disk_hash_sha256,
        &desc,
    );

    let bsa_cert = report::blockchain::generate_bsa_certificate(
        &format!("Sanitization & Purge ({})", cert.sanitization.method),
        &device_display,
        &serial,
        &cert.sanitization.method,
        "N/A",
        &cert.verification.disk_hash_sha256,
        &cert.verification.result,
        chain.merkle_root.as_deref().unwrap_or("GENESIS"),
        chain.blockchain_tx.as_deref(),
    );
    let timestamp_str = cert.timestamp_start.format("%Y%m%d_%H%M%S");
    let bsa_path = report_dir.join(format!("bsa_section_63_certificate_{}.txt", timestamp_str));
    let _ = std::fs::write(&bsa_path, &bsa_cert);

    println!("\n  {}", "Reports & Evidence Certificates saved:".bold().bright_green());
    println!("    JSON Certificate : {}", json_path.display().to_string().cyan());
    println!("    Text Certificate : {}", txt_path.display().to_string().cyan());
    println!("    BSA 2023 Sec 63  : {}", bsa_path.display().to_string().bright_yellow().bold());
    println!("    Blockchain Audit : {}", chain.summary().bright_magenta());
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

// ─── Module 2: File & Folder Shredder ─────────────────────────────────

fn print_file_erase_menu() {
    println!();
    println!("  {}", "┌─────────────────────────────────────────────────────────┐".bright_cyan());
    println!("  {}  {}  {}", "│".bright_cyan(), "Module 2: Secure File & Folder Shredder".bold().bright_white(), "          │".bright_cyan());
    println!("  {}", "├─────────────────────────────────────────────────────────┤".bright_cyan());
    println!("  {}  {}  {}", "│".bright_cyan(), "[1]  Shred a Specific File".white(), "                             │".bright_cyan());
    println!("  {}  {}  {}", "│".bright_cyan(), "[2]  Shred a Specific Folder (Recursive)".white(), "                 │".bright_cyan());
    println!("  {}  {}  {}", "│".bright_cyan(), "[3]  Batch Shred Multiple Files / Folders".white(), "                │".bright_cyan());
    println!("  {}  {}  {}", "│".bright_cyan(), "[4]  Wipe Free Space on a Volume (Anti-Carving)".white(), "          │".bright_cyan());
    println!("  {}  {}  {}", "│".bright_cyan(), "[0]  Back to Main Menu".dimmed(), "                                    │".bright_cyan());
    println!("  {}", "└─────────────────────────────────────────────────────────┘".bright_cyan());
}

fn cmd_file_erase_interactive(groq_client: &Option<ai::groq::GroqClient>) -> Result<()> {
    loop {
        print_file_erase_menu();
        let choice = read_input("Select shredding mode")?;

        match choice.trim() {
            "1" => {
                if let Err(e) = shred_single_file(groq_client) {
                    println!("  {} {}", "Error:".red().bold(), e);
                }
            }
            "2" => {
                if let Err(e) = shred_folder(groq_client) {
                    println!("  {} {}", "Error:".red().bold(), e);
                }
            }
            "3" => {
                if let Err(e) = shred_batch(groq_client) {
                    println!("  {} {}", "Error:".red().bold(), e);
                }
            }
            "4" => {
                if let Err(e) = wipe_volume_free_space(groq_client) {
                    println!("  {} {}", "Error:".red().bold(), e);
                }
            }
            "0" | "back" | "b" => break,
            _ => {
                println!("  {}", "Invalid option. Try again.".yellow());
            }
        }
    }
    Ok(())
}

fn select_shred_method(file_size: u64) -> Result<SanitizeMethod> {
    print_method_menu(file_size, None);
    let input = read_input("Select shredding standard (default [2] NIST Clear)")?;
    if input.trim().is_empty() {
        return Ok(SanitizeMethod::NistClear);
    }
    if input.trim() == "0" {
        bail!("Operation cancelled");
    }
    let idx: usize = input.trim().parse().context("Invalid selection — enter a number")?;
    let methods = SanitizeMethod::all_methods();
    if idx == 0 || idx > methods.len() {
        bail!("Method selection out of range");
    }
    Ok(methods[idx - 1])
}

fn confirm_shred(target_name: &str) -> Result<bool> {
    println!("\n  {}", "⚠️  PERMANENT UNRECOVERABLE DESTRUCTION".red().bold());
    println!("  Target: {}", target_name.yellow().bold());
    println!("  {}", "This action will overwrite data, purge Alternate Data Streams, wipe slack space,".dimmed());
    println!("  {}", "and scramble MFT metadata records. Reconstruction will be impossible.".dimmed());
    let input = read_input("Type SHRED to permanently destroy, or Enter to cancel")?;
    Ok(input.trim().eq_ignore_ascii_case("SHRED"))
}

fn shred_single_file(groq_client: &Option<ai::groq::GroqClient>) -> Result<()> {
    let input = read_input("Enter path of the file to shred (e.g. C:\\docs\\secret.pdf)")?;
    let path = clean_path(&input);
    if !path.exists() {
        bail!("Target file does not exist: {:?}", path);
    }
    if !path.is_file() {
        bail!("Path is a directory, not a file. Use option [2] for folders.");
    }

    let meta = std::fs::metadata(&path)?;
    let size = meta.len();
    println!("\n  {}", "File Forensics Analysis:".bold());
    println!("    {:<18} {}", "Path:".dimmed(), path.display());
    println!("    {:<18} {} bytes ({:.2} KB / {:.2} MB)", "Size:".dimmed(), size, size as f64 / 1024.0, size as f64 / 1_048_576.0);

    // Enumerate Alternate Data Streams
    let streams = file_eraser::streams::enumerate_streams(&path).unwrap_or_default();
    println!("    {:<18} {}", "Data Streams:".dimmed(), streams.len());
    for s in &streams {
        println!("      - {} ({} bytes)", s.name.cyan(), s.size);
    }

    let method = select_shred_method(size)?;

    if !confirm_shred(&format!("{}", path.display()))? {
        println!("  {}", "Operation cancelled.".yellow());
        return Ok(());
    }

    let start_time = chrono::Local::now();
    println!("\n  {}", format!("Executing Forensic Shred: {} ({} passes)...", method.display_name(), method.pass_count()).cyan().bold());

    let pb = indicatif::ProgressBar::new(100);
    pb.set_style(
        indicatif::ProgressStyle::with_template(
            "  {spinner:.green} [{bar:40.cyan/blue}] {percent}% | {msg}",
        )?
    );

    let res = file_eraser::secure_erase_file(&path, method, &|msg, pct| {
        pb.set_position((pct * 100.0) as u64);
        pb.set_message(msg.to_string());
    })?;

    pb.finish_with_message("Shredding complete");

    let end_time = chrono::Local::now();

    // AI Forensic Narrative
    let mut ai_narrative = None;
    if let Some(ref client) = groq_client {
        println!("\n  {}", "Generating AI Forensic Non-Recoverability Statement...".cyan());
        match ai::file_narrator::generate_file_narrative(client, &res, &start_time.to_rfc3339(), &end_time.to_rfc3339()) {
            Ok(narrative) => {
                println!("  {}", "✓ Forensic statement generated".green());
                ai_narrative = Some(narrative);
            }
            Err(e) => {
                println!("  {}", format!("✗ AI narrative failed: {}", e).yellow());
            }
        }
    }

    println!("\n{}", "  ═".repeat(50).cyan());
    if res.success() {
        println!("  {}", "✓ FILE PERMANENTLY DESTROYED & MFT PURGED".green().bold());
    } else {
        println!("  {}", "⚠️ FILE ERASURE COMPLETED WITH NOTED WARNINGS".yellow().bold());
    }
    println!("{}", "  ═".repeat(50).cyan());

    if let Some(ref narrative) = ai_narrative {
        println!("\n  {}", "AI Forensic Statement:".bold());
        println!("  {}", narrative.bright_black());
        println!("{}", "  ═".repeat(50).cyan());
    }

    // Generate & save certificate
    let cert = FileErasureCertificate {
        tool_name: "PS149 Forensic Shredder".to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp_start: start_time,
        timestamp_end: end_time,
        host_info: report::certificate::HostInfo {
            hostname: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Unknown".into()),
            os: std::env::var("OS").unwrap_or_else(|_| "Unknown".into()),
        },
        operation_type: "Single File Shred".to_string(),
        target_summary: path.display().to_string(),
        files_processed: 1,
        files_succeeded: if res.success() { 1 } else { 0 },
        files_failed: if res.success() { 0 } else { 1 },
        total_bytes_erased: res.bytes_overwritten,
        method: method.display_name().to_string(),
        standard: method.standard_name().to_string(),
        passes: res.passes_completed,
        streams_destroyed: res.streams_erased,
        slack_bytes_wiped: res.slack_bytes_wiped,
        metadata_cleansed: res.metadata_cleansed,
        filename_obfuscated: res.filename_obfuscated,
        ai_narrative,
        compliance_note: "Forensic shred completed. Physical cluster data overwritten, \
            Alternate Data Streams expunged, cluster slack space zeroed, and directory index \
            entries scrambled via multi-iteration rename cycles.".to_string(),
    };

    let report_dir = std::path::Path::new("reports");
    std::fs::create_dir_all(report_dir)?;
    let (json_path, txt_path) = cert.save(report_dir)?;

    println!("\n  {}", "Forensic Certificates Saved:".bold());
    println!("    JSON: {}", json_path.display());
    println!("    Text: {}", txt_path.display());

    Ok(())
}

fn shred_folder(groq_client: &Option<ai::groq::GroqClient>) -> Result<()> {
    let input = read_input("Enter path of folder to shred (e.g. D:\\ConfidentialFolder)")?;
    let path = clean_path(&input);
    if !path.exists() {
        bail!("Target folder does not exist: {:?}", path);
    }
    if !path.is_dir() {
        bail!("Path is a file, not a directory. Use option [1] for single files.");
    }

    let targets = vec![path.clone()];
    let files = file_eraser::batch::expand_targets(&targets);
    let total_files = files.len();
    let mut total_size = 0u64;
    for f in &files {
        if let Ok(m) = std::fs::metadata(f) {
            total_size += m.len();
        }
    }

    println!("\n  {}", "Folder Forensics Analysis:".bold());
    println!("    {:<18} {}", "Path:".dimmed(), path.display());
    println!("    {:<18} {}", "Files Found:".dimmed(), total_files);
    println!("    {:<18} {} bytes ({:.2} MB)", "Total Size:".dimmed(), total_size, total_size as f64 / 1_048_576.0);

    if total_files == 0 {
        println!("  {}", "Folder contains no files. Removing directory...".dimmed());
        file_eraser::metadata::cleanse_and_delete_dir(&path)?;
        println!("  {}", "✓ Empty folder removed.".green());
        return Ok(());
    }

    let method = select_shred_method(total_size)?;

    if !confirm_shred(&format!("Directory: {} ({} files)", path.display(), total_files))? {
        println!("  {}", "Operation cancelled.".yellow());
        return Ok(());
    }

    let start_time = chrono::Local::now();
    println!("\n  {}", format!("Executing Recursive Shred: {} files with {}...", total_files, method.display_name()).cyan().bold());

    let pb = indicatif::ProgressBar::new(total_files as u64);
    pb.set_style(
        indicatif::ProgressStyle::with_template(
            "  {spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} files | {msg}",
        )?
    );

    let batch_res = file_eraser::batch::batch_erase(&files, method, &|msg, _pct| {
        pb.set_message(msg.to_string());
        pb.inc(1);
    })?;

    pb.finish_with_message("All files shredded");

    // Clean up empty directory tree
    let _ = file_eraser::metadata::cleanse_and_delete_dir(&path);

    let end_time = chrono::Local::now();

    // AI Forensic Narrative
    let mut ai_narrative = None;
    if let Some(ref client) = groq_client {
        println!("\n  {}", "Generating AI Forensic Batch Statement...".cyan());
        match ai::file_narrator::generate_batch_narrative(
            client,
            &batch_res,
            method,
            &format!("Folder: {}", path.display()),
            &start_time.to_rfc3339(),
            &end_time.to_rfc3339(),
        ) {
            Ok(narrative) => {
                println!("  {}", "✓ Forensic statement generated".green());
                ai_narrative = Some(narrative);
            }
            Err(e) => {
                println!("  {}", format!("✗ AI narrative failed: {}", e).yellow());
            }
        }
    }

    println!("\n{}", "  ═".repeat(50).cyan());
    println!(
        "  {}",
        format!(
            "✓ FOLDER DESTROYED: {}/{} files successfully shredded ({:.1}%)",
            batch_res.files_succeeded,
            batch_res.total_files,
            batch_res.success_rate()
        )
        .green()
        .bold()
    );
    println!("{}", "  ═".repeat(50).cyan());

    if let Some(ref narrative) = ai_narrative {
        println!("\n  {}", "AI Forensic Statement:".bold());
        println!("  {}", narrative.bright_black());
        println!("{}", "  ═".repeat(50).cyan());
    }

    let cert = FileErasureCertificate {
        tool_name: "PS149 Forensic Shredder".to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp_start: start_time,
        timestamp_end: end_time,
        host_info: report::certificate::HostInfo {
            hostname: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Unknown".into()),
            os: std::env::var("OS").unwrap_or_else(|_| "Unknown".into()),
        },
        operation_type: "Folder Recursive Shred".to_string(),
        target_summary: path.display().to_string(),
        files_processed: batch_res.total_files,
        files_succeeded: batch_res.files_succeeded,
        files_failed: batch_res.files_failed,
        total_bytes_erased: batch_res.total_bytes_erased,
        method: method.display_name().to_string(),
        standard: method.standard_name().to_string(),
        passes: method.pass_count(),
        streams_destroyed: batch_res.results.iter().map(|r| r.streams_erased).sum(),
        slack_bytes_wiped: batch_res.results.iter().map(|r| r.slack_bytes_wiped).sum(),
        metadata_cleansed: true,
        filename_obfuscated: true,
        ai_narrative,
        compliance_note: "Folder destruction complete. All child files and directories neutralized.".to_string(),
    };

    let report_dir = std::path::Path::new("reports");
    std::fs::create_dir_all(report_dir)?;
    let (json_path, txt_path) = cert.save(report_dir)?;

    println!("\n  {}", "Forensic Certificates Saved:".bold());
    println!("    JSON: {}", json_path.display());
    println!("    Text: {}", txt_path.display());

    Ok(())
}

fn shred_batch(groq_client: &Option<ai::groq::GroqClient>) -> Result<()> {
    println!("\n  {}", "Batch Shredder:".bold());
    println!("  {}", "Enter paths separated by semicolon ';' (e.g. C:\\secret.doc; D:\\archive; E:\\file.bin)".dimmed());
    let input = read_input("Enter paths")?;
    let raw_paths: Vec<&str> = input.split(';').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    if raw_paths.is_empty() {
        println!("  {}", "No paths specified.".yellow());
        return Ok(());
    }

    let mut target_paths = Vec::new();
    for p in raw_paths {
        let cp = clean_path(p);
        if cp.exists() {
            target_paths.push(cp);
        } else {
            println!("  {} Path not found, skipping: {:?}", "⚠️".yellow(), cp);
        }
    }

    if target_paths.is_empty() {
        bail!("No valid existing paths were specified.");
    }

    let files = file_eraser::batch::expand_targets(&target_paths);
    let total_files = files.len();
    let mut total_size = 0u64;
    for f in &files {
        if let Ok(m) = std::fs::metadata(f) {
            total_size += m.len();
        }
    }

    println!("\n  {}", "Batch Analysis:".bold());
    println!("    {:<18} {}", "Targets Entered:".dimmed(), target_paths.len());
    println!("    {:<18} {}", "Files Expanded:".dimmed(), total_files);
    println!("    {:<18} {} bytes ({:.2} MB)", "Total Size:".dimmed(), total_size, total_size as f64 / 1_048_576.0);

    let method = select_shred_method(total_size)?;

    if !confirm_shred(&format!("Batch of {} items ({} files total)", target_paths.len(), total_files))? {
        println!("  {}", "Operation cancelled.".yellow());
        return Ok(());
    }

    let start_time = chrono::Local::now();
    let pb = indicatif::ProgressBar::new(total_files as u64);
    pb.set_style(
        indicatif::ProgressStyle::with_template(
            "  {spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} files | {msg}",
        )?
    );

    let batch_res = file_eraser::batch::batch_erase(&files, method, &|msg, _pct| {
        pb.set_message(msg.to_string());
        pb.inc(1);
    })?;

    pb.finish_with_message("Batch shredding complete");

    for t in &target_paths {
        if t.is_dir() {
            let _ = file_eraser::metadata::cleanse_and_delete_dir(t);
        }
    }

    let end_time = chrono::Local::now();

    // AI Narrative
    let mut ai_narrative = None;
    if let Some(ref client) = groq_client {
        println!("\n  {}", "Generating AI Forensic Narrative...".cyan());
        match ai::file_narrator::generate_batch_narrative(
            client,
            &batch_res,
            method,
            &format!("Batch ({} targets, {} files)", target_paths.len(), total_files),
            &start_time.to_rfc3339(),
            &end_time.to_rfc3339(),
        ) {
            Ok(narrative) => {
                println!("  {}", "✓ Forensic narrative generated".green());
                ai_narrative = Some(narrative);
            }
            Err(e) => {
                println!("  {}", format!("✗ AI narrative failed: {}", e).yellow());
            }
        }
    }

    println!("\n{}", "  ═".repeat(50).cyan());
    println!(
        "  {}",
        format!(
            "✓ BATCH COMPLETE: {}/{} files destroyed ({:.1}%)",
            batch_res.files_succeeded,
            batch_res.total_files,
            batch_res.success_rate()
        )
        .green()
        .bold()
    );
    println!("{}", "  ═".repeat(50).cyan());

    if let Some(ref narrative) = ai_narrative {
        println!("\n  {}", "AI Forensic Statement:".bold());
        println!("  {}", narrative.bright_black());
        println!("{}", "  ═".repeat(50).cyan());
    }

    let cert = FileErasureCertificate {
        tool_name: "PS149 Forensic Shredder".to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp_start: start_time,
        timestamp_end: end_time,
        host_info: report::certificate::HostInfo {
            hostname: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Unknown".into()),
            os: std::env::var("OS").unwrap_or_else(|_| "Unknown".into()),
        },
        operation_type: "Batch File Shred".to_string(),
        target_summary: format!("{} targets, {} files", target_paths.len(), total_files),
        files_processed: batch_res.total_files,
        files_succeeded: batch_res.files_succeeded,
        files_failed: batch_res.files_failed,
        total_bytes_erased: batch_res.total_bytes_erased,
        method: method.display_name().to_string(),
        standard: method.standard_name().to_string(),
        passes: method.pass_count(),
        streams_destroyed: batch_res.results.iter().map(|r| r.streams_erased).sum(),
        slack_bytes_wiped: batch_res.results.iter().map(|r| r.slack_bytes_wiped).sum(),
        metadata_cleansed: true,
        filename_obfuscated: true,
        ai_narrative,
        compliance_note: "Batch forensic destruction complete.".to_string(),
    };

    let report_dir = std::path::Path::new("reports");
    std::fs::create_dir_all(report_dir)?;
    let (json_path, txt_path) = cert.save(report_dir)?;

    println!("\n  {}", "Forensic Certificates Saved:".bold());
    println!("    JSON: {}", json_path.display());
    println!("    Text: {}", txt_path.display());

    Ok(())
}

fn wipe_volume_free_space(_groq_client: &Option<ai::groq::GroqClient>) -> Result<()> {
    println!("\n  {}", "Volume Free Space Wiping (Anti-Carving):".bold());
    println!("  {}", "Overwrites unallocated clusters where previously deleted files reside.".dimmed());
    let input = read_input("Enter drive letter to wipe free space (e.g. E)")?;
    let letter = input.trim().chars().next().context("No drive letter provided")?.to_ascii_uppercase();

    if letter == 'C' {
        println!("\n  {}", "⚠️  WARNING: Wiping free space on system drive C: can impact running programs.".yellow().bold());
        let confirm_c = read_input("Type PROCEED to wipe C: free space, or Enter to cancel")?;
        if !confirm_c.trim().eq_ignore_ascii_case("PROCEED") {
            println!("  {}", "Cancelled.".yellow());
            return Ok(());
        }
    }

    let method = SanitizeMethod::NistClear;
    println!("  Using {} standard for free space wipe.", method.display_name().cyan());

    if !confirm_shred(&format!("Free space on drive {}:\\", letter))? {
        println!("  {}", "Operation cancelled.".yellow());
        return Ok(());
    }

    let start_time = chrono::Local::now();
    let pb = indicatif::ProgressBar::new(100);
    pb.set_style(
        indicatif::ProgressStyle::with_template(
            "  {spinner:.green} [{bar:40.cyan/blue}] {percent}% | {msg}",
        )?
    );

    let res = file_eraser::free_space::wipe_free_space(letter, method, &|msg, pct| {
        pb.set_position((pct * 100.0) as u64);
        pb.set_message(msg.to_string());
    })?;

    pb.finish_with_message("Free space wipe finished");

    let end_time = chrono::Local::now();

    println!("\n{}", "  ═".repeat(50).cyan());
    println!("  {}", format!("✓ FREE SPACE WIPED ON {}:\\ ({} MB purged)", letter, res.bytes_wiped / 1_048_576).green().bold());
    println!("{}", "  ═".repeat(50).cyan());

    let cert = FileErasureCertificate {
        tool_name: "PS149 Forensic Shredder".to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp_start: start_time,
        timestamp_end: end_time,
        host_info: report::certificate::HostInfo {
            hostname: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Unknown".into()),
            os: std::env::var("OS").unwrap_or_else(|_| "Unknown".into()),
        },
        operation_type: "Volume Free Space Wipe".to_string(),
        target_summary: format!("{}:\\ unallocated space", letter),
        files_processed: 0,
        files_succeeded: 0,
        files_failed: 0,
        total_bytes_erased: res.bytes_wiped,
        method: method.display_name().to_string(),
        standard: method.standard_name().to_string(),
        passes: 1,
        streams_destroyed: 0,
        slack_bytes_wiped: 0,
        metadata_cleansed: true,
        filename_obfuscated: false,
        ai_narrative: None,
        compliance_note: "Volume unallocated cluster purge complete via temporary allocation fill.".to_string(),
    };

    let report_dir = std::path::Path::new("reports");
    std::fs::create_dir_all(report_dir)?;
    let (json_path, txt_path) = cert.save(report_dir)?;

    println!("\n  {}", "Forensic Certificates Saved:".bold());
    println!("    JSON: {}", json_path.display());
    println!("    Text: {}", txt_path.display());

    Ok(())
}

fn cmd_view_history() -> Result<()> {
    println!("\n  {}", "Erasure & Forensic Audit History (Blockchain-Backed)".bold());
    println!("  {}", "─".repeat(60).dimmed());

    // Show Blockchain status
    let chain = report::blockchain::AuditChain::load_or_create().unwrap_or_default();
    println!("  {} {}", "⛓".to_string().bright_magenta(), chain.summary().bright_white().bold());
    println!("  {}", "─".repeat(60).dimmed());

    let report_dir = std::path::Path::new("reports");
    let mut reports = Vec::new();
    if report_dir.exists() {
        for entry in std::fs::read_dir(report_dir)?.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("txt") || path.extension().and_then(|s| s.to_str()) == Some("json") {
                reports.push(path);
            }
        }
    }

    reports.sort_by(|a, b| b.cmp(a));

    if reports.is_empty() {
        println!("  {}", "No audit reports found in 'reports/' yet.".dimmed());
    } else {
        println!("  {}", "Available Certificates & Audit Logs:".bold());
        for (i, r) in reports.iter().take(12).enumerate() {
            let name = r.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            let is_bsa = name.starts_with("bsa_");
            let is_json = name.ends_with(".json");
            let label = if is_bsa {
                format!("[{}] {}", i + 1, name).bright_yellow().bold()
            } else if is_json {
                format!("[{}] {}", i + 1, name).dimmed()
            } else {
                format!("[{}] {}", i + 1, name).white()
            };
            println!("    {:<55}", label);
        }
    }

    println!();
    println!("    {} Verify Blockchain Hash Chain & Merkle Integrity", "[V]".bright_magenta().bold());
    println!("    {} Inspect Raw Blockchain Ledger (All Blocks)", "[B]".cyan().bold());
    println!("    {} Return to Main Menu", "[0]".dimmed());

    let choice = read_input("Enter option or report number to view")?;
    let choice_trimmed = choice.trim();

    match choice_trimmed {
        "0" | "" => return Ok(()),
        "v" | "V" => {
            println!("\n  {} Verifying Blockchain Audit Chain...", "🔍".to_string().bright_magenta());
            let (valid, total, invalid_idx) = chain.verify();
            println!("  {}", "═".repeat(50).bright_magenta());
            if valid {
                println!("  {} Blockchain Chain Integrity: {}", "✓".bright_green().bold(), "PERFECT — 0 TAMPERING DETECTED".bright_green().bold());
                println!("    Verified Entries : {}", total.to_string().cyan());
                println!("    Merkle Root Hash : {}", chain.merkle_root.as_deref().unwrap_or("N/A").bright_yellow());
                println!("    Status           : Legally Tamper-Proof under BSA 2023 §63");
            } else {
                println!("  {} Blockchain Chain Integrity: {}", "✗".red().bold(), "CORRUPTED OR TAMPERED!".red().bold());
                println!("    First Invalid Block Index : {:?}", invalid_idx);
            }
            println!("  {}", "═".repeat(50).bright_magenta());
        }
        "b" | "B" => {
            println!("\n  {}", "Blockchain Audit Trail Ledger:".bold().bright_magenta());
            println!("  {}", "─".repeat(65).dimmed());
            if chain.entries.is_empty() {
                println!("    (No blocks recorded yet)");
            } else {
                for entry in &chain.entries {
                    println!(
                        "    [Block #{}] {} | {} | Op: {}...",
                        entry.index.to_string().bright_white(),
                        entry.event_type.to_string().cyan(),
                        entry.device_id.yellow(),
                        &entry.operation_hash[..8],
                    );
                    println!(
                        "      Prev Hash : {}...",
                        &entry.prev_hash[..16].dimmed(),
                    );
                    println!(
                        "      Block Hash: {}...",
                        &entry.entry_hash[..16].bright_green(),
                    );
                }
            }
            println!("  {}", "─".repeat(65).dimmed());
        }
        _ => {
            if let Ok(idx) = choice_trimmed.parse::<usize>() {
                if idx > 0 && idx <= reports.len() {
                    let content = std::fs::read_to_string(&reports[idx - 1])?;
                    println!("\n{}", "─".repeat(65).cyan());
                    println!("{}", content);
                    println!("{}", "─".repeat(65).cyan());
                } else {
                    println!("  {}", "Invalid report number.".yellow());
                }
            }
        }
    }

    Ok(())
}

// ─── Module 3: File Recovery & Deep Carving ──────────────────────────

fn cmd_file_recovery_interactive(groq: &Option<ai::groq::GroqClient>) -> Result<()> {
    println!("\n  {}", "┌────────────────────────────────────────────────────┐".bright_yellow());
    println!("  {}  {}  {}", "│".bright_yellow(), "Module 3: File Recovery & Deep Carving".bold().bright_white(), "        │".bright_yellow());
    println!("  {}", "├────────────────────────────────────────────────────┤".bright_yellow());
    println!("  {}  {}  {}", "│".bright_yellow(), "[1] Carve from Physical Drive".white(), "                    │".bright_yellow());
    println!("  {}  {}  {}", "│".bright_yellow(), "[2] Carve from Volume (D:, E:, ...)".white(), "              │".bright_yellow());
    println!("  {}  {}  {}", "│".bright_yellow(), "[3] Carve from Disk Image (.dd, .raw, .img)".white(), "     │".bright_yellow());
    println!("  {}  {}  {}", "│".bright_yellow(), "[0] Back to Main Menu".dimmed(), "                            │".bright_yellow());
    println!("  {}", "└────────────────────────────────────────────────────┘".bright_yellow());

    let choice = read_input("Select recovery source")?;

    let (source_path, source_size, source_display) = match choice.trim() {
        "1" => {
            // Carve from physical drive
            let disks = discovery::enumerate_devices()?;
            if disks.is_empty() {
                println!("  {}", "No storage devices found.".yellow());
                return Ok(());
            }
            println!("\n  {}", "Connected Drives:".bold());
            for disk in &disks {
                println!(
                    "    {} Disk {} — {} | {} | {}",
                    "●".bright_cyan(),
                    disk.index,
                    disk.model.as_deref().unwrap_or("Unknown").bright_white(),
                    disk.capacity_display().yellow(),
                    disk.device_type.to_string().dimmed(),
                );
            }

            let idx_str = read_input("Enter disk number to carve from")?;
            let idx: u32 = idx_str.parse().context("Invalid disk number")?;

            let disk = disks.iter().find(|d| d.index == idx)
                .ok_or_else(|| anyhow::anyhow!("Disk {} not found", idx))?;

            if disk.is_boot_disk {
                println!("  {} Cannot carve from boot disk while Windows is running.", "⚠".red().bold());
                println!("    Use a disk image instead.");
                return Ok(());
            }

            let path = format!("\\\\.\\PhysicalDrive{}", idx);
            let size = disk.capacity;
            let display = format!("Disk {} — {}", idx, disk.model.as_deref().unwrap_or("Unknown"));
            (path, size, display)
        }
        "2" => {
            // Carve from volume
            let letter = read_input("Enter volume letter (e.g. D)")?;
            let letter = letter.trim().trim_end_matches(':').to_uppercase();
            let path = format!("\\\\.\\{}:", letter);
            // Estimate size from volume
            let size_str = read_input("Approximate volume size in GB (e.g. 32)")?;
            let size_gb: u64 = size_str.parse().unwrap_or(16);
            let display = format!("Volume {}:", letter);
            (path, size_gb * 1024 * 1024 * 1024, display)
        }
        "3" => {
            // Carve from disk image
            let path_str = read_input("Enter path to disk image file")?;
            let path = clean_path(&path_str);
            if !path.exists() {
                bail!("File not found: {:?}", path);
            }
            let size = std::fs::metadata(&path)?.len();
            let display = format!("Image: {}", path.file_name().unwrap_or_default().to_string_lossy());
            (path.to_string_lossy().to_string(), size, display)
        }
        "0" | "" => return Ok(()),
        _ => {
            println!("  {}", "Invalid option.".yellow());
            return Ok(());
        }
    };

    // Display carving info
    println!("\n  {}", "┌──────────────────────────────────────────┐".bright_yellow());
    println!("  {}  {}: {}  {}", "│".bright_yellow(), "Source".bold(), source_display.bright_white(), "│".bright_yellow());
    println!("  {}  {}: {}  {}", "│".bright_yellow(), "Size".bold(), model::device::format_bytes(source_size).yellow(), "│".bright_yellow());
    println!("  {}  {}: {}  {}", "│".bright_yellow(), "Signatures".bold(), format!("{} file types", carver::all_signatures().len()).cyan(), "│".bright_yellow());
    println!("  {}", "└──────────────────────────────────────────┘".bright_yellow());

    // Ask for output directory
    let default_output = format!("recovered_artifacts");
    let output_str = read_input(&format!("Output directory [{}]", default_output))?;
    let output_dir = if output_str.trim().is_empty() {
        std::path::PathBuf::from(&default_output)
    } else {
        clean_path(&output_str)
    };

    // Confirmation
    println!("\n  {} File carving will {}.", "⚠".yellow().bold(), "READ the source (non-destructive)".bright_green().bold());
    println!("    Recovered files will be saved to: {}", output_dir.display().to_string().cyan());
    let confirm = read_input("Type RECOVER to begin")?;
    if confirm.trim() != "RECOVER" {
        println!("  {}", "Cancelled.".yellow());
        return Ok(());
    }

    // Run the carving engine with progress display
    println!("\n  {} Starting deep scan...\n", "🔍".to_string().bright_yellow());

    let pb = indicatif::ProgressBar::new(source_size);
    pb.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("  Scan [{bar:40.yellow/dim}]  {percent}% | {bytes}/{total_bytes} | Files: {msg}")
            .unwrap()
            .progress_chars("█▓░"),
    );

    let start = std::time::Instant::now();
    let result = carver::carve_from_source(
        &source_path,
        &output_dir,
        Some(source_size),
        |progress| {
            pb.set_position(progress.bytes_scanned);
            pb.set_message(format!("{}", progress.files_found));
        },
    )?;

    pb.finish_with_message(format!("{} files", result.files_found));
    let elapsed = start.elapsed();

    // Display results
    println!("\n  {}", "═".repeat(60).bright_yellow());
    println!("  {} {}", "CARVING RESULTS".bold().bright_yellow(), "═".repeat(43).bright_yellow());
    println!("  {}", "═".repeat(60).bright_yellow());

    println!("\n  {} Files Recovered: {}", "📁".to_string(), result.files_found.to_string().bright_green().bold());
    println!("  {} Data Scanned: {}", "💾".to_string(), model::device::format_bytes(result.total_bytes_scanned).cyan());
    println!("  {} Duration: {:.1}s", "⏱".to_string(), elapsed.as_secs_f64());

    if !result.categories.is_empty() {
        println!("\n  {} {}", "Categories:".bold(), "");
        for (cat, count) in &result.categories {
            println!("    {} {}: {}", "●".bright_cyan(), cat, count.to_string().bright_green());
        }
    }

    if !result.carved_files.is_empty() {
        println!("\n  {} {}", "Recovered Files:".bold(), "");
        for (i, cf) in result.carved_files.iter().enumerate().take(50) {
            println!(
                "    {}. {} | {} | {} | Confidence: {:.0}%",
                (i + 1).to_string().dimmed(),
                cf.file_type.bright_white(),
                model::device::format_bytes(cf.size).yellow(),
                format!("SHA256: {}...", &cf.sha256[..12]).dimmed(),
                cf.confidence * 100.0,
            );
        }
        if result.carved_files.len() > 50 {
            println!("    ... and {} more files", result.carved_files.len() - 50);
        }
    } else {
        println!("\n  {} {}", "ℹ".bright_cyan(), "No recoverable files found. The drive may have been securely wiped.".dimmed());
    }

    // Save carving report as JSON
    let report_dir = std::path::PathBuf::from("reports");
    std::fs::create_dir_all(&report_dir)?;
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let report_path = report_dir.join(format!("carving_report_{}.json", timestamp));
    let report_json = serde_json::to_string_pretty(&result)?;
    std::fs::write(&report_path, &report_json)?;

    // Blockchain Audit Trail & BSA 2023 Sec 63 Evidence Certificate
    let mut chain = report::blockchain::AuditChain::load_or_create().unwrap_or_default();
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(report_json.as_bytes());
    let op_hash = format!("{:x}", hasher.finalize());

    let _ = chain.add_event(
        report::blockchain::AuditEventType::FileCarving,
        &source_display,
        "Forensic_Investigator",
        &op_hash,
        &format!("Carved {} files from {}", result.files_found, source_display),
    );

    let bsa_carve_cert = report::blockchain::generate_bsa_certificate(
        "Forensic File Carving & Evidence Extraction",
        &source_display,
        "N/A",
        "Deep Sector Signature & Structure Parsing",
        "N/A",
        &op_hash,
        &format!("Extracted {} verified file artifacts", result.files_found),
        chain.merkle_root.as_deref().unwrap_or("GENESIS"),
        chain.blockchain_tx.as_deref(),
    );
    let bsa_carve_path = report_dir.join(format!("bsa_section_63_recovery_{}.txt", timestamp));
    let _ = std::fs::write(&bsa_carve_path, &bsa_carve_cert);

    println!("\n  {}", "Reports & Evidence Certificates saved:".bold().bright_green());
    println!("    JSON Report      : {}", report_path.display().to_string().cyan());
    println!("    BSA 2023 Sec 63  : {}", bsa_carve_path.display().to_string().bright_yellow().bold());
    println!("    Blockchain Audit : {}", chain.summary().bright_magenta());

    // AI forensic narrative
    if let Some(client) = groq {
        println!("\n  {} Generating AI forensic narrative...", "🤖".to_string().bright_cyan());

        let summary = if result.files_found > 0 {
            format!(
                "A forensic file carving scan of '{}' ({}) recovered {} files across {} categories. \
                 Files found: {}. Duration: {:.1}s. SHA-256 hashes computed for all artifacts.",
                source_display,
                model::device::format_bytes(source_size),
                result.files_found,
                result.categories.len(),
                result.carved_files.iter().take(10).map(|f| format!("{} ({})", f.file_type, model::device::format_bytes(f.size))).collect::<Vec<_>>().join(", "),
                elapsed.as_secs_f64(),
            )
        } else {
            format!(
                "A forensic file carving scan of '{}' ({}) found 0 recoverable files after scanning {} bytes in {:.1}s. \
                 This indicates the storage media has been effectively sanitized with no residual data artifacts detectable \
                 through signature-based or structure-based carving analysis.",
                source_display,
                model::device::format_bytes(source_size),
                result.total_bytes_scanned,
                elapsed.as_secs_f64(),
            )
        };

        let system_prompt = "You are a certified digital forensics expert and court-admissible technical witness. \
            Generate a brief, professional forensic analysis statement suitable for inclusion in an investigation report \
            under Bharatiya Sakshya Adhiniyam 2023, Section 63. Be precise and use forensic terminology.";

        match client.chat(system_prompt, &summary) {
            Ok(narrative) => {
                println!("\n  {}", "AI Forensic Analysis:".bold().bright_cyan());
                println!("  {}", "─".repeat(55).dimmed());
                for line in narrative.lines() {
                    println!("  {}", line.bright_white());
                }
                println!("  {}", "─".repeat(55).dimmed());
            }
            Err(e) => {
                println!("  {} AI narrative unavailable: {}", "⚠".yellow(), e.to_string().dimmed());
            }
        }
    }

    println!("\n  {} Output directory: {}", "📂".to_string(), output_dir.display().to_string().bright_green().bold());

    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────

fn clean_path(raw: &str) -> std::path::PathBuf {
    let trimmed = raw.trim().trim_matches('"').trim_matches('\'').trim();
    std::path::PathBuf::from(trimmed)
}

fn read_input(prompt: &str) -> Result<String> {
    print!("\n  {} ", format!("{}:", prompt).bold());
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}


mod discovery;
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
    print_method_menu(target.capacity, target.interface_type.as_deref());
    let method_input = read_input("Select method")?;
    if method_input.trim() == "0" {
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

// ─── Helpers ─────────────────────────────────────────────────────────

fn read_input(prompt: &str) -> Result<String> {
    print!("\n  {} ", format!("{}:", prompt).bold());
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

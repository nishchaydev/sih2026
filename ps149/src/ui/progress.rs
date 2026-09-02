use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};

/// Prints the application banner.
pub fn print_banner() {
    println!();
    println!("  {}", "╔════════════════════════════════════════════════╗".bright_cyan());
    println!("  {}  {:<44}  {}", "║".bright_cyan(), " ", "║".bright_cyan());
    println!("  {}  {:<44}  {}",
        "║".bright_cyan(),
        format!("[*]  PS-26149  Secure Drive Eraser").bold().bright_white(),
        "║".bright_cyan()
    );
    println!("  {}  {:<44}  {}",
        "║".bright_cyan(),
        format!("v{}  |  NIST SP 800-88 Compliant", env!("CARGO_PKG_VERSION")).dimmed(),
        "║".bright_cyan()
    );
    println!("  {}  {:<44}  {}",
        "║".bright_cyan(),
        "National Technical Research Organisation".dimmed(),
        "║".bright_cyan()
    );
    println!("  {}  {:<44}  {}", "║".bright_cyan(), " ", "║".bright_cyan());
    println!("  {}", "╚════════════════════════════════════════════════╝".bright_cyan());
    println!();
}

/// Prints a styled section header.
pub fn print_section(title: &str) {
    println!("  {} {}", "▸".bright_cyan(), title.bold());
    println!("  {}", "─".repeat(56).dimmed());
}

/// Prints a key-value row with consistent alignment.
pub fn print_row(key: &str, value: &str) {
    println!("    {:<15} {}", format!("{}:", key).dimmed(), value);
}

/// Prints a status badge (colored inline label).
pub fn badge(text: &str, color: &str) -> String {
    match color {
        "red" => format!(" {} ", text).on_red().white().bold().to_string(),
        "green" => format!(" {} ", text).on_green().black().bold().to_string(),
        "yellow" => format!(" {} ", text).on_yellow().black().bold().to_string(),
        "cyan" => format!(" {} ", text).on_cyan().black().bold().to_string(),
        "blue" => format!(" {} ", text).on_blue().white().bold().to_string(),
        _ => text.to_string(),
    }
}

/// Creates a styled progress bar for sanitization.
pub fn create_sanitize_progress_bar(total_sectors: u64, pass_label: &str) -> ProgressBar {
    let pb = ProgressBar::new(total_sectors);
    pb.set_style(
        ProgressStyle::with_template(
            "  {spinner:.green} {msg} [{bar:40.cyan/blue}] {percent:>3}% │ {binary_bytes}/{binary_total_bytes} │ ETA {eta}"
        )
        .unwrap()
        .progress_chars("━━╺")
    );
    pb.set_message(pass_label.to_string());
    pb
}

/// Creates a styled progress bar for verification.
pub fn create_verify_progress_bar(total_sectors: u64) -> ProgressBar {
    let pb = ProgressBar::new(total_sectors);
    pb.set_style(
        ProgressStyle::with_template(
            "  {spinner:.green} {msg} [{bar:40.green/blue}] {percent:>3}% │ {binary_bytes}/{binary_total_bytes} │ ETA {eta}"
        )
        .unwrap()
        .progress_chars("━━╺")
    );
    pb.set_message("Verifying".to_string());
    pb
}

/// Prints a success result box.
pub fn print_success(message: &str) {
    println!();
    println!("  {}", "╔══════════════════════════════════════════════════════════╗".green());
    println!("  {}  {}  {}", "║".green(), format!("✓ {}", message).green().bold(), "║".green());
    println!("  {}", "╚══════════════════════════════════════════════════════════╝".green());
}

/// Prints a failure result box.
pub fn print_failure(message: &str) {
    println!();
    println!("  {}", "╔══════════════════════════════════════════════════════════╗".red());
    println!("  {}  {}  {}", "║".red(), format!("✗ {}", message).red().bold(), "║".red());
    println!("  {}", "╚══════════════════════════════════════════════════════════╝".red());
}

/// Prints an info line.
pub fn print_info(message: &str) {
    println!("  {} {}", "ℹ".bright_cyan(), message);
}

/// Prints a warning line.
pub fn print_warn(message: &str) {
    println!("  {} {}", "⚠".yellow(), message.yellow());
}

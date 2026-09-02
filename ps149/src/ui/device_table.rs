use colored::Colorize;
use crate::model::{PhysicalDisk, SafetyStatus};

/// Prints a formatted table of all detected storage devices.
pub fn print_device_table(disks: &[PhysicalDisk]) {
    println!("\n{}", "PS149 Secure Drive Eraser".bold());
    println!("{}\n", "=".repeat(40));
    println!("{}\n", "Storage Devices Detected".bold());

    for (i, disk) in disks.iter().enumerate() {
        println!("[{}] Disk {}", i + 1, disk.index);

        println!("    {:<13}: {}", "Type", disk.device_type);
        println!("    {:<13}: {}", "Model", disk.model.as_deref().unwrap_or("Unknown"));
        println!("    {:<13}: {}", "Serial", disk.serial_number.as_deref().unwrap_or("N/A"));
        println!("    {:<13}: {}", "Capacity", disk.capacity_display());
        println!("    {:<13}: {} bytes", "Sector Size", disk.bytes_per_sector);

        // Show all volumes on this disk
        let volumes: Vec<String> = disk
            .partitions
            .iter()
            .flat_map(|p| p.volumes.iter())
            .filter_map(|v| {
                let letter = v.drive_letter.as_deref()?;
                let label = v.label.as_deref().unwrap_or("");
                let fs = v.filesystem.as_deref().unwrap_or("?");
                if label.is_empty() {
                    Some(format!("{} [{}]", letter, fs))
                } else {
                    Some(format!("{} \"{}\" [{}]", letter, label, fs))
                }
            })
            .collect();

        if volumes.is_empty() {
            println!("    {:<13}: {}", "Volumes", "None (raw/unpartitioned)".dimmed());
        } else {
            println!("    {:<13}: {}", "Volumes", volumes.join(", "));
        }

        // Show bootable flag (WMI BootPartition) — separate from OS protection
        let has_boot_flag = disk.partitions.iter().any(|p| p.is_boot);
        if has_boot_flag {
            println!("    {:<13}: {}", "Bootable", "YES".yellow());
        }

        // OS status — only TRUE if the running OS system drive is on this disk
        let os_str = if disk.is_boot_disk {
            format!("{} ({})", "YES".red(), "System drive is on this disk")
        } else {
            "NO".green().to_string()
        };
        println!("    {:<13}: {}", "Running OS", os_str);

        // Safety status with reason
        let status_str = match disk.safety_status {
            SafetyStatus::Protected => format!(
                "{} — {}",
                "PROTECTED".red().bold(),
                "Cannot erase: contains the running OS"
            ),
            SafetyStatus::Available => format!(
                "{} — {}",
                "AVAILABLE".green().bold(),
                "Can be erased (with confirmation)"
            ),
            SafetyStatus::Unknown => "UNKNOWN".yellow().to_string(),
        };
        println!("    {:<13}: {}", "Status", status_str);
        println!();
    }
}

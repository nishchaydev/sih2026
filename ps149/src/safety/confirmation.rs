use anyhow::Result;
use colored::Colorize;
use std::io::{self, Write};
use crate::model::PhysicalDisk;

/// Runs the interactive confirmation flow. Returns Ok(true) if the user confirmed.
pub fn confirm_erasure(disk: &PhysicalDisk) -> Result<bool> {
    let model = disk.model.as_deref().unwrap_or("Unknown");
    let capacity = disk.capacity_display();
    
    let mut drive_letters = Vec::new();
    for p in &disk.partitions {
        for v in &p.volumes {
            if let Some(dl) = &v.drive_letter {
                drive_letters.push(dl.clone());
            }
        }
    }
    
    let drive_letters_str = if drive_letters.is_empty() {
        "None".to_string()
    } else {
        drive_letters.join(", ")
    };

    let warning_box = format!(
        "╔══════════════════════════════════════════════════╗\n\
         ║  WARNING: IRREVERSIBLE DESTRUCTIVE OPERATION     ║\n\
         ╠══════════════════════════════════════════════════╣\n\
         ║  Target: Disk {} — {:<29}║\n\
         ║  Capacity: {:<37}║\n\
         ║  Volumes: {:<38}║\n\
         ║                                                  ║\n\
         ║  ALL DATA WILL BE PERMANENTLY DESTROYED.         ║\n\
         ╚══════════════════════════════════════════════════╝",
        disk.index,
        model,
        capacity,
        drive_letters_str
    );

    println!("{}", warning_box.bright_red().bold());

    print!("{}", "Type the disk number to confirm (e.g. \"1\"): ".yellow().bold());
    io::stdout().flush()?;
    let mut input1 = String::new();
    io::stdin().read_line(&mut input1)?;
    if input1.trim() != disk.index.to_string() {
        return Ok(false);
    }

    print!("{}", "Type ERASE to proceed: ".yellow().bold());
    io::stdout().flush()?;
    let mut input2 = String::new();
    io::stdin().read_line(&mut input2)?;
    if input2.trim() != "ERASE" {
        return Ok(false);
    }

    Ok(true)
}

/// Confirmation flow for file/folder erasure. Same shape as
/// `confirm_erasure`, but keyed on a file count/size instead of a disk, and
/// escalates to a longer confirmation phrase when any target resolves under
/// a protected system path (see `fileerase::walker::is_protected_path`).
pub fn confirm_file_erasure(
    file_count: usize,
    total_size_display: &str,
    protected_reason: Option<&str>,
    wipe_free_space: bool,
    delete_usn_journal: bool,
) -> Result<bool> {
    let warning_box = format!(
        "╔══════════════════════════════════════════════════╗\n\
         ║  WARNING: IRREVERSIBLE DESTRUCTIVE OPERATION     ║\n\
         ╠══════════════════════════════════════════════════╣\n\
         ║  Files: {:<43}║\n\
         ║  Total size: {:<38}║\n\
         ║                                                  ║\n\
         ║  ALL DATA WILL BE PERMANENTLY DESTROYED.         ║\n\
         ╚══════════════════════════════════════════════════╝",
        file_count, total_size_display
    );
    println!("{}", warning_box.bright_red().bold());

    if wipe_free_space {
        println!(
            "{}",
            "  Free-space wipe is ENABLED — will also fill remaining free space on affected volume(s)."
                .yellow()
        );
    }
    if delete_usn_journal {
        println!(
            "{}",
            "  USN journal clearing is ENABLED — this affects the ENTIRE volume, not just the selected files."
                .yellow()
        );
    }

    if let Some(reason) = protected_reason {
        let danger_box = format!(
            "╔══════════════════════════════════════════════════╗\n\
             ║  DANGER: TARGET INCLUDES A PROTECTED SYSTEM PATH ║\n\
             ╠══════════════════════════════════════════════════╣\n\
             ║  Reason: {:<42}║\n\
             ╚══════════════════════════════════════════════════╝",
            reason
        );
        println!("{}", danger_box.on_red().white().bold());

        print!("{}", "Type DELETE SYSTEM FILES to proceed: ".yellow().bold());
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        return Ok(input.trim() == "DELETE SYSTEM FILES");
    }

    print!("{}", "Type ERASE to proceed: ".yellow().bold());
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim() == "ERASE")
}

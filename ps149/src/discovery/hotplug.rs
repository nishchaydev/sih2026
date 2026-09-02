use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub enum HotPlugEvent {
    DeviceInserted {
        model: String,
        capacity: u64,
        disk_index: u32,
        interface: String,
    },
    DeviceRemoved {
        model: String,
        disk_index: u32,
    },
}

impl std::fmt::Display for HotPlugEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeviceInserted { model, capacity, disk_index, interface } => {
                let cap_gb = *capacity as f64 / 1_073_741_824.0;
                write!(f, "NEW DEVICE: {} ({:.1} GB) on {} as Disk {}", model, cap_gb, interface, disk_index)
            }
            Self::DeviceRemoved { model, disk_index } => {
                write!(f, "DEVICE REMOVED: {} (Disk {})", model, disk_index)
            }
        }
    }
}

/// Starts a background thread that watches for USB drive plug/unplug events.
/// Returns a channel receiver and the thread handle.
/// The watcher polls WMI every 2 seconds for changes.
pub fn start_hotplug_watcher() -> (mpsc::Receiver<HotPlugEvent>, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        info!("Hot-plug watcher started");
        if let Err(e) = watch_loop(&tx) {
            warn!("Hot-plug watcher error: {}", e);
        }
    });

    (rx, handle)
}

fn watch_loop(tx: &mpsc::Sender<HotPlugEvent>) -> anyhow::Result<()> {
    let com = wmi::COMLibrary::new()?;
    let wmi_con = wmi::WMIConnection::new(com)?;

    // Track known disk indices
    let mut known_disks: std::collections::HashMap<u32, String> = std::collections::HashMap::new();

    // Initial scan
    let initial: Vec<std::collections::HashMap<String, wmi::Variant>> =
        wmi_con.raw_query("SELECT Index, Model, Size, InterfaceType FROM Win32_DiskDrive")?;
    for disk in &initial {
        if let Some(wmi::Variant::UI4(idx)) = disk.get("Index") {
            let model = match disk.get("Model") {
                Some(wmi::Variant::String(s)) => s.clone(),
                _ => "Unknown".to_string(),
            };
            known_disks.insert(*idx, model);
        }
    }

    loop {
        thread::sleep(std::time::Duration::from_secs(2));

        let current: Vec<std::collections::HashMap<String, wmi::Variant>> =
            match wmi_con.raw_query("SELECT Index, Model, Size, InterfaceType FROM Win32_DiskDrive") {
                Ok(v) => v,
                Err(_) => continue,
            };

        let mut current_disks: std::collections::HashMap<u32, (String, u64, String)> =
            std::collections::HashMap::new();

        for disk in &current {
            let idx = match disk.get("Index") {
                Some(wmi::Variant::UI4(i)) => *i,
                _ => continue,
            };
            let model = match disk.get("Model") {
                Some(wmi::Variant::String(s)) => s.clone(),
                _ => "Unknown".to_string(),
            };
            let size = match disk.get("Size") {
                Some(wmi::Variant::String(s)) => s.parse::<u64>().unwrap_or(0),
                Some(wmi::Variant::UI8(n)) => *n,
                _ => 0,
            };
            let iface = match disk.get("InterfaceType") {
                Some(wmi::Variant::String(s)) => s.clone(),
                _ => "Unknown".to_string(),
            };
            current_disks.insert(idx, (model, size, iface));
        }

        // Detect insertions
        for (idx, (model, size, iface)) in &current_disks {
            if !known_disks.contains_key(idx) {
                let event = HotPlugEvent::DeviceInserted {
                    model: model.clone(),
                    capacity: *size,
                    disk_index: *idx,
                    interface: iface.clone(),
                };
                info!("{}", event);
                let _ = tx.send(event);
            }
        }

        // Detect removals
        for (idx, model) in &known_disks {
            if !current_disks.contains_key(idx) {
                let event = HotPlugEvent::DeviceRemoved {
                    model: model.clone(),
                    disk_index: *idx,
                };
                info!("{}", event);
                let _ = tx.send(event);
            }
        }

        // Update known set
        known_disks.clear();
        for (idx, (model, _, _)) in &current_disks {
            known_disks.insert(*idx, model.clone());
        }
    }
}

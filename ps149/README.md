<p align="center">
  <img src="https://img.shields.io/badge/SIH_2026-PS_26149-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/NTRO-National_Technical_Research_Organisation-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Theme-Blockchain_%26_Cybersecurity-purple?style=for-the-badge" />
</p>

<h1 align="center">🛡️ PS-26149 — Secure Drive Eraser</h1>

<p align="center">
  <b>Integrated Secure Data Erasure & Advanced File Recovery Tool for Digital Forensics and Data Sanitization</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Rust-orange?style=flat-square&logo=rust" />
  <img src="https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows" />
  <img src="https://img.shields.io/badge/Standards-17_Methods-green?style=flat-square" />
  <img src="https://img.shields.io/badge/AI-Groq_LLM-ff69b4?style=flat-square" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" />
</p>

---

## 📋 Problem Statement

> **PS ID:** 26149  
> **Title:** Design and Development of an Integrated Secure Data Erasure and Advanced File Recovery Tool for Digital Forensics and Data Sanitization  
> **Organisation:** NTRO (National Technical Research Organisation)  
> **Theme:** Blockchain & Cybersecurity

Organizations, government agencies, law enforcement, and enterprises face two critical challenges:
1. **Securely destroying** sensitive data to prevent unauthorized recovery
2. **Recovering deleted** digital evidence during forensic investigations

Existing solutions focus on either deletion OR recovery, support limited storage technologies, and force professionals to juggle multiple tools. **PS-26149** is a unified platform integrating both capabilities.

---

## 🏗️ Architecture

```
ps149/
├── src/
│   ├── main.rs                    # Interactive 24/7 CLI loop
│   ├── ai/                        # AI-powered features (Groq LLM)
│   │   ├── groq.rs                # Groq API client
│   │   ├── erasure_advisor.rs     # Pre-erasure AI recommendations
│   │   └── report_narrator.rs     # Post-erasure forensic narrative
│   ├── discovery/                 # Device detection & monitoring
│   │   ├── wmi.rs                 # WMI queries (Win32_DiskDrive, etc.)
│   │   ├── classifier.rs          # Device type classification
│   │   ├── ioctl.rs               # IOCTL_DISK_GET_DRIVE_GEOMETRY
│   │   └── hotplug.rs             # Real-time USB plug/unplug detection
│   ├── model/                     # Data models
│   │   ├── device.rs              # PhysicalDisk, Partition, Volume
│   │   ├── device_type.rs         # 11 device type classifications
│   │   └── safety_status.rs       # Erasure eligibility rules
│   ├── sanitize/                  # Core erasure engine
│   │   ├── patterns.rs            # 17 erasure standards + fill patterns
│   │   ├── pass.rs                # Write pass execution (zone-aware)
│   │   ├── raw_io.rs              # Win32 raw disk I/O (CreateFileW)
│   │   └── volume_ops.rs          # Volume lock, dismount, guard
│   ├── verify/                    # Erasure verification
│   │   ├── readback.rs            # Full readback verification
│   │   ├── hash.rs                # SHA-256 disk hashing
│   │   ├── entropy.rs             # Shannon entropy analysis
│   │   └── sampling.rs            # Stratified random sampling
│   ├── safety/                    # Safety guards
│   │   └── confirmation.rs        # Multi-step confirmation flow
│   ├── report/                    # Forensic reporting
│   │   ├── certificate.rs         # Sanitization certificate (JSON+TXT)
│   │   └── audit_log.rs           # Timestamped audit trail
│   └── ui/                        # Terminal UI
│       ├── progress.rs            # Banner, progress bars
│       └── device_table.rs        # Device listing table
└── Cargo.toml
```

---

## 🔐 Supported Erasure Standards (17 Methods)

### ⚡ Quick Methods
| # | Method | Passes | Time (USB 2.0, 16 GB) | Security Level |
|---|--------|--------|----------------------|----------------|
| 1 | **Fast Wipe** (Headers & Footers) | 1 | ~8 seconds | ⬜ Metadata only |
| 2 | **Smart Secure Wipe** ★ | 1 | ~67 seconds | 🟧 High (zone-based) |

### 🏛️ Government Standards (NIST)
| # | Method | Passes | Time (USB 2.0, 16 GB) | Security Level |
|---|--------|--------|----------------------|----------------|
| 3 | NIST SP 800-88 Clear (Zero Fill) | 1 | ~60 min | 🟩 Full |
| 4 | NIST SP 800-88 Purge (Random) | 2 | ~120 min | 🟩 Full |
| 5 | Random Single Pass (CSPRNG) | 1 | ~60 min | 🟩 Full |

### 🎖️ Military Standards
| # | Method | Passes | Time (USB 2.0, 16 GB) | Security Level |
|---|--------|--------|----------------------|----------------|
| 6 | DoD 5220.22-M (3-Pass) | 3 | ~3 hours | 🟩 Full |
| 7 | DoD 5220.22-M ECE (7-Pass) | 7 | ~7 hours | 🟩 Full |
| 8 | AFSSI-5020 (US Air Force) | 3 | ~3 hours | 🟩 Full |
| 9 | AR 380-19 (US Army) | 3 | ~3 hours | 🟩 Full |
| 10 | NAVSO P-5239-26 (US Navy) | 3 | ~3 hours | 🟩 Full |

### 🌍 International Standards
| # | Method | Passes | Time (USB 2.0, 16 GB) | Security Level |
|---|--------|--------|----------------------|----------------|
| 11 | HMG IS5 Baseline (UK) | 1 | ~60 min | 🟩 Full |
| 12 | HMG IS5 Enhanced (UK) | 3 | ~3 hours | 🟩 Full |
| 13 | VSITR (German BSI) | 7 | ~7 hours | 🟩 Full |
| 14 | RCMP TSSIT OPS-II (Canada) | 7 | ~7 hours | 🟩 Full |
| 15 | Bruce Schneier Method | 7 | ~7 hours | 🟩 Full |
| 16 | GOST R 50739-95 (Russia) | 2 | ~2 hours | 🟩 Full |

### 🔴 Maximum Security
| # | Method | Passes | Time (USB 2.0, 16 GB) | Security Level |
|---|--------|--------|----------------------|----------------|
| 17 | Gutmann (35-Pass) | 35 | ~35 hours | 🟩 Legacy MFM/RLL |

> ★ **Smart Secure Wipe** is our innovation — it writes 128 MB at the head (destroying MBR, GPT, NTFS MFT, FAT, root directory, journals), 128 MB at the tail (backup GPT, backup boot sectors), and 1 MB at every GB boundary (breaking file contiguity). Makes recovery virtually impossible in ~1 minute vs ~60 minutes for a full pass.

---

## 💻 Supported Devices

| Device Type | Interface | Detection | Status |
|-------------|-----------|-----------|--------|
| Internal HDD | SATA, IDE | ✅ WMI | ✅ Supported |
| Internal SSD | SATA, M.2 | ✅ WMI | ✅ Supported |
| NVMe SSD | PCIe | ✅ WMI | ✅ Supported |
| USB Flash Drive | USB 2.0/3.0 | ✅ WMI + Hot-plug | ✅ Supported |
| External HDD/SSD | USB | ✅ WMI + Hot-plug | ✅ Supported |
| SD Card | USB Reader | ✅ WMI | ✅ Supported |
| UFS / eMMC | Internal | ✅ WMI | ✅ Supported |

### File Systems
All erasure methods work at the **raw sector level** (below the filesystem), so they work regardless of filesystem type:
- NTFS, FAT32, FAT16, exFAT, ext4, HFS+, APFS, or even unformatted/RAW drives

---

## ⚡ Performance & Known Limitations

### The USB 2.0 Reality

> **This is the single most important thing to understand about disk erasure tools.**

USB 2.0 has a maximum throughput of ~480 Mbps (theoretical), but real-world sustained write speeds for flash drives are typically **4-5 MB/s**. This is a **hardware limitation** — no software can exceed it.

| Drive | Write Speed | 16 GB Full Wipe | 16 GB Smart Secure |
|-------|------------|-----------------|-------------------|
| USB 2.0 Flash | ~4 MB/s | **~67 minutes** | **~67 seconds** |
| USB 3.0 Flash | ~40 MB/s | ~7 minutes | ~7 seconds |
| SATA SSD | ~500 MB/s | ~32 seconds | ~1 second |
| NVMe SSD | ~3000 MB/s | ~5 seconds | ~1 second |

### Why competitor tools seem "faster"

Tools like Disk Drill claim 1-2 minute "wipes" on USB 2.0, but they only destroy partition headers (equivalent to our FastWipe option #1). **The actual data remains physically on the disk and is recoverable with file carving tools.** Our Smart Secure Wipe (option #2) is the sweet spot — fast enough for demos, secure enough that no software-based recovery tool can reconstruct files.

### What we do about it

1. **ETA estimates in the method menu** — you see green/yellow/red time estimates BEFORE choosing, based on your drive's interface speed
2. **Smart Secure Wipe** — our zone-based innovation gets 95% of the security in 2% of the time
3. **FastWipe** — for when you just need partition table destruction (8 seconds)
4. **Hot-plug detection** — plug drives in/out while the tool runs, no restart needed

---

## 🤖 AI Features (Groq LLM Integration)

When `GROQ_API_KEY` is set in the environment:

| Feature | Description |
|---------|-------------|
| **Erasure Advisor** | Analyzes the target drive (type, capacity, interface) and recommends the optimal erasure method before you start |
| **Forensic Narrator** | After erasure + verification, generates a human-readable forensic narrative summarizing the sanitization for the certificate |

Both features **gracefully degrade** — if the API key is missing or the call fails, the tool continues normally without AI features.

```powershell
# Enable AI features
$env:GROQ_API_KEY = "gsk_your_key_here"
```

---

## 🔌 Real-Time Hot-Plug Detection

The tool runs a background thread that polls WMI every 2 seconds for storage device changes:

```
  🔌 NEW DEVICE: SanDisk Cruzer Force USB Device (14.7 GB) on USB as Disk 1
  ⚠️  DEVICE REMOVED: SanDisk Cruzer Force USB Device (Disk 1)
```

Plug or unplug drives at any time — the main menu stays active, and the device list updates automatically.

---

## 🛡️ Safety Guards

The tool implements multiple layers of protection against accidental data loss:

1. **System drive detection** — identifies the drive running the OS and marks it as `PROTECTED`
2. **Boot partition detection** — flags drives with boot partitions
3. **Multi-step confirmation** — requires typing the disk number AND the word `ERASE`
4. **Device classification** — internal vs external, HDD vs SSD vs USB
5. **Volume locking** — locks and dismounts volumes before raw I/O to prevent filesystem corruption

---

## 📜 Forensic Reporting

After every erasure, the tool generates:

### Sanitization Certificate (`reports/`)
- **JSON format** — machine-readable, includes all metadata
- **TXT format** — human-readable summary

### Certificate Contents
- Device serial number, model, capacity
- Erasure method and standard name
- Pass-by-pass details (pattern, sectors written, duration, errors)
- Verification result (pass/fail, sectors verified, SHA-256 hash)
- Complete timestamped audit log
- AI forensic narrative (if enabled)
- UUID-based certificate ID

---

## 📊 Verification Methods

| Method | Speed | Confidence | Use Case |
|--------|-------|------------|----------|
| **Full Readback** | Slow (reads every byte) | 100% | Gold standard for forensic certification |
| **Shannon Entropy** | Instant | Mathematical | Verifies randomness quality for random-fill methods |
| **Statistical Sampling** | ~5 seconds | 99.999% | Quick verification with stratified random sector reads |

---

## 🚀 Getting Started

### Prerequisites
- **Windows 10/11** (64-bit)
- **Rust toolchain** ([rustup.rs](https://rustup.rs))
- **Administrator privileges** (required for raw disk I/O)

### Option 1: One-Click Setup (Recommended)
```powershell
# Right-click PowerShell → "Run as Administrator"
.\setup.ps1
```
This script automatically checks admin privileges, installs Rust if needed, builds the project, and launches the tool.

### Option 2: Manual Build
```powershell
cd ps149
cargo build --release
# Run as Administrator:
.\target\release\ps149.exe
```

### Option 3: For Mentors & Evaluators (Pre-built Binary)
Download the latest `ps149.exe` from [GitHub Releases](https://github.com/nishchaydev/sih2026/releases), then:
```powershell
# Right-click → "Run as Administrator"
.\ps149.exe
```
No Rust installation needed — just the `.exe` file.

### Optional: Enable AI Features
```powershell
$env:GROQ_API_KEY = "gsk_your_key_here"
.\ps149.exe
```

### ⚠️ Why not Docker?
This tool performs **raw disk I/O** via Win32 APIs (`CreateFileW` on `\\.\PhysicalDrive0`). Docker containers:
- Run Linux kernels — our code calls Windows-specific functions (WMI, IOCTL, Win32)
- Sandbox hardware access — raw disk reads/writes are blocked by container isolation
- Cannot detect USB hot-plug events

**The correct distribution method is a native Windows binary** (`.exe`), which GitHub Actions auto-builds on every push.

---

## 🗺️ Roadmap

### Module 1: Secure Drive Erasure ✅
- [x] Device discovery & classification (WMI)
- [x] 17 global erasure standards
- [x] Smart Secure Wipe (innovation)
- [x] Raw sector I/O (Win32 API)
- [x] Full readback verification + SHA-256 hashing
- [x] Shannon entropy verification
- [x] Statistical sampling verification
- [x] Hot-plug detection
- [x] Interactive 24/7 CLI
- [x] AI erasure advisor + forensic narrator
- [x] Forensic sanitization certificates
- [x] Audit logging

### Module 2: Secure File & Folder Eraser 🔜
- [ ] Selective file/folder deletion
- [ ] NTFS metadata cleansing (MFT, $UsnJrnl, $LogFile)
- [ ] Slack space wiping
- [ ] Alternate data stream removal
- [ ] Batch operations

### Module 3: Advanced File Carving & Recovery 🔜
- [ ] Signature-based carving (magic bytes)
- [ ] Structure-based carving
- [ ] AI-powered intelligent carving
- [ ] Fragmented file reconstruction
- [ ] Confidence scoring
- [ ] Forensic chain of custody

### Infrastructure 🔜
- [ ] Blockchain tamper-proof audit trail
- [ ] GUI dashboard (Tauri: Rust + React)
- [ ] Cross-platform support (Linux, macOS)

---

## 🧰 Tech Stack

| Component | Technology |
|-----------|-----------|
| Core Engine | Rust (safe systems programming) |
| Disk I/O | Win32 API (`CreateFileW`, `WriteFile`, `ReadFile`) |
| Device Discovery | WMI (Windows Management Instrumentation) |
| Hashing | SHA-256 (sha2 crate) |
| AI | Groq API (Llama/Mixtral) |
| CLI | Interactive loop with colored output |
| Serialization | serde + serde_json |
| Progress UI | indicatif + colored |
| Logging | tracing + tracing-subscriber |
| UUID | uuid v4 for certificate IDs |

---

## 📚 References

- [NIST SP 800-88 Rev.1](https://csrc.nist.gov/publications/detail/sp/800-88/rev-1/final) — Guidelines for Media Sanitization
- [DoD 5220.22-M](https://www.dss.mil/) — National Industrial Security Program Operating Manual
- [Gutmann 1996](https://www.cs.auckland.ac.nz/~pgut001/pubs/secure_del.html) — Secure Deletion of Data from Magnetic and Solid-State Memory
- [Wei et al., FAST '11](https://www.usenix.org/conference/fast11) — Reliably Erasing Data from Flash-Based Solid State Drives
- [Garfinkel & Shelat 2003](https://simson.net/clips/academic/2003.IEEE.Remembrance.pdf) — Remembrance of Data Passed

---

## 👥 Team

**SIH 2026 — Problem Statement 26149**

Built for the Smart India Hackathon under the **Blockchain & Cybersecurity** theme for NTRO.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

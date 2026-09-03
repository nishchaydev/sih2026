/// Blockchain-backed tamper-proof audit trail.
///
/// Each event (erasure, carving, verification) generates a cryptographic
/// audit entry. Entries are chained via SHA-256 hashes (each entry includes
/// the hash of the previous one), forming an immutable Merkle hash chain.
///
/// Optionally anchors the Merkle root to a public blockchain for
/// court-admissible, tamper-evident verification.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// The type of forensic event recorded in the audit chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    DriveErasure,
    FileShred,
    FileCarving,
    Verification,
    ChainValidation,
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DriveErasure => write!(f, "Drive Erasure"),
            Self::FileShred => write!(f, "File Shred"),
            Self::FileCarving => write!(f, "File Carving"),
            Self::Verification => write!(f, "Verification"),
            Self::ChainValidation => write!(f, "Chain Validation"),
        }
    }
}

/// A single entry in the tamper-proof audit chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Sequential index in the chain (0-based).
    pub index: u64,
    /// Type of forensic event.
    pub event_type: AuditEventType,
    /// ISO 8601 timestamp.
    pub timestamp: DateTime<Utc>,
    /// Device identifier (serial number, path, or filename).
    pub device_id: String,
    /// Operator/technician identifier.
    pub operator: String,
    /// SHA-256 hash of the operation result/certificate.
    pub operation_hash: String,
    /// Brief description of what was done.
    pub description: String,
    /// SHA-256 hash of the PREVIOUS entry (creates the chain).
    /// Genesis entry (index 0) uses "0000...0000".
    pub prev_hash: String,
    /// SHA-256 hash of THIS entry (computed from all fields above).
    pub entry_hash: String,
}

/// The complete audit chain stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditChain {
    /// Tool version that created/modified this chain.
    pub tool_version: String,
    /// All audit entries in order.
    pub entries: Vec<AuditEntry>,
    /// Merkle root of all entry hashes (for blockchain anchoring).
    pub merkle_root: Option<String>,
    /// Blockchain transaction hash if anchored.
    pub blockchain_tx: Option<String>,
}

const CHAIN_FILE: &str = "reports/audit_chain.json";
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

impl Default for AuditChain {
    fn default() -> Self {
        Self {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            entries: Vec::new(),
            merkle_root: None,
            blockchain_tx: None,
        }
    }
}

impl AuditChain {
    /// Loads an existing chain from disk or creates a new genesis chain.
    pub fn load_or_create() -> Result<Self> {
        let path = Path::new(CHAIN_FILE);
        if path.exists() {
            let content = fs::read_to_string(path)?;
            let chain: AuditChain = serde_json::from_str(&content)?;
            Ok(chain)
        } else {
            Ok(Self::default())
        }
    }

    /// Adds a new event to the chain and saves to disk.
    pub fn add_event(
        &mut self,
        event_type: AuditEventType,
        device_id: &str,
        operator: &str,
        operation_hash: &str,
        description: &str,
    ) -> Result<&AuditEntry> {
        let index = self.entries.len() as u64;
        let prev_hash = self.entries.last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.to_string());

        let timestamp = Utc::now();

        // Compute entry hash from all fields
        let entry_hash = compute_entry_hash(
            index,
            &event_type,
            &timestamp,
            device_id,
            operator,
            operation_hash,
            description,
            &prev_hash,
        );

        let entry = AuditEntry {
            index,
            event_type,
            timestamp,
            device_id: device_id.to_string(),
            operator: operator.to_string(),
            operation_hash: operation_hash.to_string(),
            description: description.to_string(),
            prev_hash,
            entry_hash,
        };

        self.entries.push(entry);

        // Recompute Merkle root
        self.merkle_root = Some(compute_merkle_root(&self.entries));

        // Save to disk
        self.save()?;

        Ok(self.entries.last().unwrap())
    }

    /// Verifies the integrity of the entire audit chain.
    /// Returns (is_valid, number_of_entries_checked, first_invalid_index).
    pub fn verify(&self) -> (bool, usize, Option<u64>) {
        if self.entries.is_empty() {
            return (true, 0, None);
        }

        for (i, entry) in self.entries.iter().enumerate() {
            // Check previous hash linkage
            let expected_prev = if i == 0 {
                GENESIS_HASH.to_string()
            } else {
                self.entries[i - 1].entry_hash.clone()
            };

            if entry.prev_hash != expected_prev {
                return (false, i + 1, Some(entry.index));
            }

            // Recompute entry hash and verify
            let recomputed = compute_entry_hash(
                entry.index,
                &entry.event_type,
                &entry.timestamp,
                &entry.device_id,
                &entry.operator,
                &entry.operation_hash,
                &entry.description,
                &entry.prev_hash,
            );

            if entry.entry_hash != recomputed {
                return (false, i + 1, Some(entry.index));
            }
        }

        // Verify Merkle root if present
        if let Some(ref stored_root) = self.merkle_root {
            let computed_root = compute_merkle_root(&self.entries);
            if stored_root != &computed_root {
                return (false, self.entries.len(), None);
            }
        }

        (true, self.entries.len(), None)
    }

    /// Saves the chain to disk.
    fn save(&self) -> Result<()> {
        let path = Path::new(CHAIN_FILE);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Returns a human-readable summary of the chain.
    pub fn summary(&self) -> String {
        let (valid, _checked, _) = self.verify();
        format!(
            "Audit Chain: {} entries | Integrity: {} | Merkle Root: {}",
            self.entries.len(),
            if valid { "✅ VALID" } else { "❌ TAMPERED" },
            self.merkle_root.as_deref().map(|r| &r[..16]).unwrap_or("N/A"),
        )
    }
}

/// Computes the SHA-256 hash of an audit entry from its fields.
fn compute_entry_hash(
    index: u64,
    event_type: &AuditEventType,
    timestamp: &DateTime<Utc>,
    device_id: &str,
    operator: &str,
    operation_hash: &str,
    description: &str,
    prev_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(index.to_le_bytes());
    hasher.update(format!("{:?}", event_type).as_bytes());
    hasher.update(timestamp.to_rfc3339().as_bytes());
    hasher.update(device_id.as_bytes());
    hasher.update(operator.as_bytes());
    hasher.update(operation_hash.as_bytes());
    hasher.update(description.as_bytes());
    hasher.update(prev_hash.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Computes the Merkle root from all entry hashes.
fn compute_merkle_root(entries: &[AuditEntry]) -> String {
    if entries.is_empty() {
        return GENESIS_HASH.to_string();
    }

    let mut hashes: Vec<String> = entries.iter().map(|e| e.entry_hash.clone()).collect();

    // Build Merkle tree bottom-up
    while hashes.len() > 1 {
        let mut next_level = Vec::new();
        for chunk in hashes.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(chunk[0].as_bytes());
            if chunk.len() > 1 {
                hasher.update(chunk[1].as_bytes());
            } else {
                // Odd number: duplicate last hash
                hasher.update(chunk[0].as_bytes());
            }
            next_level.push(format!("{:x}", hasher.finalize()));
        }
        hashes = next_level;
    }

    hashes.into_iter().next().unwrap_or_else(|| GENESIS_HASH.to_string())
}

/// Generates a BSA 2023 Section 63 compliant certificate text.
pub fn generate_bsa_certificate(
    event_type: &str,
    device_info: &str,
    serial_number: &str,
    method: &str,
    pre_hash: &str,
    post_hash: &str,
    verification_result: &str,
    merkle_root: &str,
    blockchain_tx: Option<&str>,
) -> String {
    let now = Utc::now();
    format!(
r#"╔══════════════════════════════════════════════════════════════════════╗
║              CERTIFICATE UNDER SECTION 63                            ║
║         BHARATIYA SAKSHYA ADHINIYAM, 2023                            ║
║         (Replacement of Section 65B, Indian Evidence Act)            ║
╠══════════════════════════════════════════════════════════════════════╣
║  PART A — CUSTODIAN / INVESTIGATOR DECLARATION                       ║
╠══════════════════════════════════════════════════════════════════════╣
║  Date & Time    : {timestamp}                          ║
║  Operation      : {event_type:<40}                     ║
║  Device         : {device_info:<40}                    ║
║  Serial Number  : {serial:<40}                         ║
║  Method Applied : {method:<40}                         ║
║                                                                      ║
║  I hereby certify that the above electronic record was produced      ║
║  by the computer/device identified herein during the regular         ║
║  course of forensic operations, and the information contained        ║
║  is derived from data fed into the computer in the ordinary          ║
║  course of the said activities.                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  PART B — TECHNICAL EXPERT CERTIFICATION                             ║
╠══════════════════════════════════════════════════════════════════════╣
║  Tool            : PS-26149 Forensic Suite v{version}                ║
║  Pre-Op SHA-256  : {pre_hash}   ║
║  Post-Op SHA-256 : {post_hash}  ║
║  Verification    : {verification:<40}                  ║
║                                                                      ║
║  Cryptographic Audit Trail:                                          ║
║    Merkle Root   : {merkle:<40}                        ║
║    Blockchain Tx : {blockchain:<40}                    ║
║                                                                      ║
║  Compliance Standards:                                               ║
║    • NIST SP 800-88 Rev. 1                                           ║
║    • ISO/IEC 27037 (Digital Evidence Handling)                        ║
║    • ISO/IEC 27040 (Storage Security)                                ║
║    • Bharatiya Sakshya Adhiniyam, 2023 (Section 63)                  ║
║    • Digital Personal Data Protection Act, 2023                      ║
║                                                                      ║
║  I certify that the computer/device was operating properly           ║
║  and that the electronic record is a faithful and accurate           ║
║  representation of the operation performed.                          ║
╚══════════════════════════════════════════════════════════════════════╝"#,
        timestamp = now.format("%Y-%m-%d %H:%M:%S UTC"),
        event_type = event_type,
        device_info = device_info,
        serial = serial_number,
        method = method,
        version = env!("CARGO_PKG_VERSION"),
        pre_hash = if pre_hash.len() > 40 { &pre_hash[..40] } else { pre_hash },
        post_hash = if post_hash.len() > 40 { &post_hash[..40] } else { post_hash },
        verification = verification_result,
        merkle = if merkle_root.len() > 40 { &merkle_root[..40] } else { merkle_root },
        blockchain = blockchain_tx.unwrap_or("Not anchored (local chain only)"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_creation_and_verification() {
        let mut chain = AuditChain {
            tool_version: "0.1.0".to_string(),
            entries: Vec::new(),
            merkle_root: None,
            blockchain_tx: None,
        };

        let ts1 = Utc::now();
        let hash1 = compute_entry_hash(
            0,
            &AuditEventType::DriveErasure,
            &ts1,
            "DISK-001",
            "Operator",
            "abc123",
            "Test erasure",
            GENESIS_HASH,
        );
        assert!(!hash1.is_empty());

        let entry1 = AuditEntry {
            index: 0,
            event_type: AuditEventType::DriveErasure,
            timestamp: ts1,
            device_id: "DISK-001".to_string(),
            operator: "Operator".to_string(),
            operation_hash: "abc123".to_string(),
            description: "Test erasure".to_string(),
            prev_hash: GENESIS_HASH.to_string(),
            entry_hash: hash1.clone(),
        };
        chain.entries.push(entry1);

        let ts2 = Utc::now();
        let entry2_hash = compute_entry_hash(
            1,
            &AuditEventType::Verification,
            &ts2,
            "DISK-001",
            "Operator",
            "def456",
            "Test verify",
            &hash1,
        );
        let entry2 = AuditEntry {
            index: 1,
            event_type: AuditEventType::Verification,
            timestamp: ts2,
            device_id: "DISK-001".to_string(),
            operator: "Operator".to_string(),
            operation_hash: "def456".to_string(),
            description: "Test verify".to_string(),
            prev_hash: hash1,
            entry_hash: entry2_hash,
        };
        chain.entries.push(entry2);

        chain.merkle_root = Some(compute_merkle_root(&chain.entries));

        // Verify chain integrity
        let (valid, checked, invalid_idx) = chain.verify();
        assert!(valid, "Chain should be valid");
        assert_eq!(checked, 2);
        assert!(invalid_idx.is_none());
    }

    #[test]
    fn test_tamper_detection() {
        let mut chain = AuditChain {
            tool_version: "0.1.0".to_string(),
            entries: Vec::new(),
            merkle_root: None,
            blockchain_tx: None,
        };

        let ts1 = Utc::now();
        let hash1 = compute_entry_hash(
            0,
            &AuditEventType::DriveErasure,
            &ts1,
            "DISK-001",
            "Operator",
            "abc123",
            "Legit erasure",
            GENESIS_HASH,
        );
        chain.entries.push(AuditEntry {
            index: 0,
            event_type: AuditEventType::DriveErasure,
            timestamp: ts1,
            device_id: "DISK-001".to_string(),
            operator: "Operator".to_string(),
            operation_hash: "abc123".to_string(),
            description: "Legit erasure".to_string(),
            prev_hash: GENESIS_HASH.to_string(),
            entry_hash: hash1,
        });

        // Tamper with the entry
        chain.entries[0].description = "TAMPERED DATA".to_string();

        let (valid, _, _) = chain.verify();
        assert!(!valid, "Tampered chain should be detected as invalid");
    }

    #[test]
    fn test_merkle_root_computation() {
        let entries = vec![
            AuditEntry {
                index: 0,
                event_type: AuditEventType::DriveErasure,
                timestamp: Utc::now(),
                device_id: "X".to_string(),
                operator: "O".to_string(),
                operation_hash: "h1".to_string(),
                description: "d1".to_string(),
                prev_hash: GENESIS_HASH.to_string(),
                entry_hash: "aaa".to_string(),
            },
            AuditEntry {
                index: 1,
                event_type: AuditEventType::Verification,
                timestamp: Utc::now(),
                device_id: "X".to_string(),
                operator: "O".to_string(),
                operation_hash: "h2".to_string(),
                description: "d2".to_string(),
                prev_hash: "aaa".to_string(),
                entry_hash: "bbb".to_string(),
            },
        ];

        let root = compute_merkle_root(&entries);
        assert!(!root.is_empty());
        assert_ne!(root, GENESIS_HASH);
    }

    #[test]
    fn test_bsa_certificate_generation() {
        let cert = generate_bsa_certificate(
            "NIST SP 800-88 Clear",
            "SanDisk Cruzer Force 16GB",
            "4C531234567890",
            "NIST Clear (Zero Fill)",
            "a3f2e1d0c9b8a7f6e5d4c3b2a1908776",
            "e3b0c44298fc1c149afbf4c8996fb924",
            "100% sector readback — PASSED",
            "7f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c",
            Some("0x7f3a...beef (Polygon Amoy)"),
        );
        assert!(cert.contains("SECTION 63"));
        assert!(cert.contains("BHARATIYA SAKSHYA ADHINIYAM"));
        assert!(cert.contains("NIST SP 800-88"));
    }
}

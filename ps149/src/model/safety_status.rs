use serde::Serialize;
use std::fmt;

/// Whether a device is eligible for destructive operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[allow(dead_code)]
pub enum SafetyStatus {
    /// Device contains boot/system partitions — erasure is blocked.
    Protected,
    /// Device is eligible for sanitization.
    Available,
    /// Could not determine safety status — treated as protected.
    Unknown,
}

impl fmt::Display for SafetyStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protected => write!(f, "PROTECTED"),
            Self::Available => write!(f, "AVAILABLE"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl SafetyStatus {
    /// Returns `true` if the device can be erased.
    pub fn is_erasable(&self) -> bool {
        matches!(self, Self::Available)
    }
}

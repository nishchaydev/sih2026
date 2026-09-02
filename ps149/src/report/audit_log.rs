use chrono::{DateTime, Local};
use serde::Serialize;

/// Types of events that can be recorded in the audit log.
#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub enum AuditEventType {
    SessionStart,
    DeviceDetected,
    DeviceSelected,
    SafetyCheck,
    ConfirmationReceived,
    SanitizationStarted,
    PassCompleted,
    VerificationStarted,
    VerificationCompleted,
    SessionEnd,
    Error,
}

/// A single recorded event in the sanitization session.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Local>,
    pub event_type: AuditEventType,
    pub message: String,
}

/// A sequential log of events during the sanitization session.
#[derive(Debug, Clone, Default)]
pub struct AuditLog {
    events: Vec<AuditEvent>,
}

impl AuditLog {
    /// Creates a new, empty audit log.
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Appends a new event to the audit log.
    pub fn log(&mut self, event_type: AuditEventType, message: impl Into<String>) {
        self.events.push(AuditEvent {
            timestamp: Local::now(),
            event_type,
            message: message.into(),
        });
    }

    /// Returns a slice of the recorded events.
    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }
}

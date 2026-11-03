//! Conservative decisions for a locally inspected transaction record.
//!
//! These decisions do not prove any filesystem operation and cannot reopen a
//! listener, authorize source deletion, or produce an authenticated receipt.

use crate::transfer::journal::JournalPhase;

/// Required local follow-up after exclusive ownership and record validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryDisposition {
    /// Revalidate protected staging and file identities before retrying.
    InspectStaging,
    /// Publication may have happened; preserve both stage and destination.
    InspectAmbiguousPublication,
    /// Revalidate published contents and any persisted receipt before replying.
    InspectPublished,
    /// Preserve data until identity-checked cleanup is authorized.
    InspectAborted,
}

#[must_use]
pub const fn recovery_disposition(phase: JournalPhase) -> RecoveryDisposition {
    match phase {
        JournalPhase::Approved | JournalPhase::Receiving | JournalPhase::Verified => {
            RecoveryDisposition::InspectStaging
        }
        JournalPhase::CommitIntent => RecoveryDisposition::InspectAmbiguousPublication,
        JournalPhase::Published | JournalPhase::ReceiptRecorded => {
            RecoveryDisposition::InspectPublished
        }
        JournalPhase::Aborted => RecoveryDisposition::InspectAborted,
    }
}

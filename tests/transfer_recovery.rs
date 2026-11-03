use teamy_mover::transfer::journal::JournalPhase;
use teamy_mover::transfer::recovery::RecoveryDisposition;
use teamy_mover::transfer::recovery::recovery_disposition;

#[test]
fn never_infers_success_or_serves_a_lost_receipt_from_journal_phase_alone() {
    for phase in [
        JournalPhase::Approved,
        JournalPhase::Receiving,
        JournalPhase::Verified,
    ] {
        assert_eq!(
            recovery_disposition(phase),
            RecoveryDisposition::InspectStaging
        );
    }
    assert_eq!(
        recovery_disposition(JournalPhase::CommitIntent),
        RecoveryDisposition::InspectAmbiguousPublication
    );
    for phase in [JournalPhase::Published, JournalPhase::ReceiptRecorded] {
        assert_eq!(
            recovery_disposition(phase),
            RecoveryDisposition::InspectPublished
        );
    }
    assert_eq!(
        recovery_disposition(JournalPhase::Aborted),
        RecoveryDisposition::InspectAborted
    );
}

use sha2::Digest;
use sha2::Sha256;
use teamy_mover::transfer::journal::JournalApproval;
use teamy_mover::transfer::journal::JournalBinding;
use teamy_mover::transfer::journal::JournalPhase;
use teamy_mover::transfer::journal::JournalRecord;
use teamy_mover::transfer::journal::ObjectIdentity;
use teamy_mover::transfer::journal::decode_log;
use teamy_mover::transfer::journal::encode_frame;

const ID: &str = "0123456789abcdef0123456789abcdef";
const HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const CLIENT: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SERVER: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn manifest() -> String {
    format!(
        r#"{{"aggregate_bytes":1,"expires_unix":100,"file_count":1,"files":[{{"id":"one","name":"a.bin","sha256":"{HASH}","size":1}}],"transaction_id":"{ID}","version":1}}"#
    )
}

fn binding(
    client_pin: &str,
    parent: ObjectIdentity,
    stage: ObjectIdentity,
    final_name: &str,
) -> eyre::Result<JournalBinding> {
    let raw = manifest();
    let digest = format!("{:x}", Sha256::digest(raw.as_bytes()));
    JournalBinding::from_approval(&JournalApproval {
        manifest_bytes: raw.as_bytes(),
        manifest_sha256: &digest,
        transaction_id: ID,
        client_pin,
        server_pin: SERVER,
        destination_parent: parent,
        stage_directory: stage,
        journal_file: ObjectIdentity {
            volume_serial: 5,
            file_index: 3,
        },
        final_name,
        now_unix: 1,
    })
}

fn good_binding() -> JournalBinding {
    binding(
        CLIENT,
        ObjectIdentity {
            volume_serial: 5,
            file_index: 1,
        },
        ObjectIdentity {
            volume_serial: 5,
            file_index: 2,
        },
        "recovered",
    )
    .unwrap()
}

fn replace_payload(frame: &[u8], before: &str, after: &str) -> Vec<u8> {
    let payload_end = frame.len() - 32;
    let payload = std::str::from_utf8(&frame[8..payload_end]).unwrap();
    assert!(payload.contains(before));
    let replacement = payload.replacen(before, after, 1);
    let mut changed = b"TMJ1".to_vec();
    changed.extend(u32::try_from(replacement.len()).unwrap().to_be_bytes());
    changed.extend(replacement.as_bytes());
    let checksum = Sha256::digest(&changed);
    changed.extend(checksum);
    changed
}

#[test]
fn records_roundtrip_with_strict_order_and_binding() {
    let binding = good_binding();
    let mut record = JournalRecord::initial(&binding);
    let mut bytes = encode_frame(&record).unwrap();
    for phase in [
        JournalPhase::Receiving,
        JournalPhase::Verified,
        JournalPhase::CommitIntent,
        JournalPhase::Published,
        JournalPhase::ReceiptRecorded,
    ] {
        record = record.next(phase).unwrap();
        bytes.extend(encode_frame(&record).unwrap());
    }
    let records = decode_log(&bytes, &binding, 1).unwrap();
    assert_eq!(records.len(), 6);
    assert_eq!(
        records.last().unwrap().phase(),
        JournalPhase::ReceiptRecorded
    );
    assert_eq!(records.last().unwrap().sequence(), 6);
}

#[test]
fn rejects_invalid_transitions_replays_and_reordered_frames() {
    let binding = good_binding();
    let start = JournalRecord::initial(&binding);
    let _error = start.next(JournalPhase::Published).unwrap_err();
    let receiving = start.next(JournalPhase::Receiving).unwrap();
    let verified = receiving.next(JournalPhase::Verified).unwrap();
    let intent = verified.next(JournalPhase::CommitIntent).unwrap();
    let _error = intent.next(JournalPhase::Aborted).unwrap_err();
    let start_frame = encode_frame(&start).unwrap();
    let receiving_frame = encode_frame(&receiving).unwrap();
    let mut replay = start_frame.clone();
    replay.extend(&receiving_frame);
    replay.extend(&receiving_frame);
    let _error = decode_log(&replay, &binding, 1).unwrap_err();
    let mut skipped = start_frame;
    skipped.extend(encode_frame(&verified).unwrap());
    let _error = decode_log(&skipped, &binding, 1).unwrap_err();
}

#[test]
fn rejects_corruption_truncation_expiry_and_conflicting_approval() {
    let approved = good_binding();
    let frame = encode_frame(&JournalRecord::initial(&approved)).unwrap();
    for index in [0, 8, frame.len() - 1] {
        let mut changed = frame.clone();
        changed[index] ^= 1;
        let _error = decode_log(&changed, &approved, 1).unwrap_err();
    }
    for length in [0, 1, 7, frame.len() - 1] {
        let _error = decode_log(&frame[..length], &approved, 1).unwrap_err();
    }
    let _error = decode_log(&frame, &approved, 100).unwrap_err();
    let other = binding(
        SERVER,
        ObjectIdentity {
            volume_serial: 5,
            file_index: 1,
        },
        ObjectIdentity {
            volume_serial: 5,
            file_index: 2,
        },
        "recovered",
    )
    .unwrap();
    let _error = decode_log(&frame, &other, 1).unwrap_err();
    let altered_binding = replace_payload(&frame, CLIENT, SERVER);
    let _error = decode_log(&altered_binding, &approved, 1).unwrap_err();
    let altered_phase =
        replace_payload(&frame, "\"phase\":\"approved\"", "\"phase\":\"published\"");
    let _error = decode_log(&altered_phase, &approved, 1).unwrap_err();
}

#[test]
fn rejects_unsafe_approval_bindings() {
    let parent = ObjectIdentity {
        volume_serial: 5,
        file_index: 1,
    };
    let stage = ObjectIdentity {
        volume_serial: 5,
        file_index: 2,
    };
    let _error = binding("not-a-pin", parent, stage, "recovered").unwrap_err();
    let _error = binding(CLIENT, parent, stage, "../outside").unwrap_err();
    let _error = binding(CLIENT, parent, parent, "recovered").unwrap_err();
    let _error = binding(
        CLIENT,
        parent,
        ObjectIdentity {
            volume_serial: 6,
            file_index: 2,
        },
        "recovered",
    )
    .unwrap_err();
}

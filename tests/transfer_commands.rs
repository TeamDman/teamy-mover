use sha2::Digest;
use sha2::Sha256;
use std::process::Command;

#[test]
fn transfer_placeholders_refuse_to_run_and_do_not_create_files() {
    let dir = tempfile::tempdir().unwrap();
    for operation in ["send", "receive"] {
        let output = Command::new(env!("CARGO_BIN_EXE_teamy-mover"))
            .current_dir(dir.path())
            .args(["transfer", operation])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("transfer is not yet available"));
        assert_eq!(output.stdout, []);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn sender_limit_check_runs_in_child_without_starting_transfer() {
    let dir = tempfile::tempdir().unwrap();
    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_teamy-mover"))
            .current_dir(dir.path())
            .args([
                "--output-format",
                "json",
                "transfer",
                "send",
                "--check-process-limit",
            ])
            .args(extra)
            .output()
            .unwrap()
    };
    let result = run(&[]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(output.contains("\"address_space_bytes\":"));
    assert!(output.contains("\"transfer_started\": false"));
    let combined = run(&["--verify-only"]);
    assert!(!combined.status.success());
    assert_eq!(combined.stdout, [0_u8; 0]);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn direct_sender_requires_local_approval_before_connecting() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("connection.json");
    std::fs::write(&config, b"{}").unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_teamy-mover"))
        .current_dir(dir.path())
        .args(["transfer", "send", "--connect-config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("manifest file required"));
    assert_eq!(result.stdout, []);
    assert_eq!(std::fs::read(&config).unwrap(), b"{}");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[cfg(windows)]
#[test]
fn receiver_limit_check_never_assigns_or_starts_a_process() {
    let dir = tempfile::tempdir().unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_teamy-mover"))
        .current_dir(dir.path())
        .args([
            "--output-format",
            "json",
            "transfer",
            "receive",
            "--check-process-limit",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(output.contains("\"job_configuration_verified\": true"));
    assert!(output.contains("\"process_assigned\": false"));
    assert!(output.contains("\"receiver_started\": false"));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn validate_manifest_checks_local_approval_without_modifying_input() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("manifest.json");
    let id = "0123456789abcdef0123456789abcdef";
    let hash = format!("{:x}", Sha256::digest(b"hello"));
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600;
    let raw = format!(
        r#"{{"aggregate_bytes":5,"expires_unix":{expires},"file_count":1,"files":[{{"id":"one","name":"a.bin","sha256":"{hash}","size":5}}],"transaction_id":"{id}","version":1}}"#
    );
    std::fs::write(&path, raw.as_bytes()).unwrap();
    let digest = format!("{:x}", Sha256::digest(raw.as_bytes()));
    let run = |expected: &str| {
        Command::new(env!("CARGO_BIN_EXE_teamy-mover"))
            .current_dir(dir.path())
            .args([
                "--output-format",
                "json",
                "transfer",
                "validate-manifest",
                "--manifest-file",
            ])
            .arg(&path)
            .args(["--manifest-sha256", expected, "--transaction-id", id])
            .output()
            .unwrap()
    };
    let good = run(&digest);
    assert!(
        good.status.success(),
        "{}",
        String::from_utf8_lossy(&good.stderr)
    );
    let output = String::from_utf8(good.stdout).unwrap();
    assert!(output.contains("\"valid\": true"));
    assert!(output.contains("\"aggregate_bytes\": 5"));
    let bad = run(&"0".repeat(64));
    assert!(!bad.status.success());
    assert_eq!(bad.stdout, []);
    assert_eq!(std::fs::read(&path).unwrap(), raw.as_bytes());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn send_verify_only_checks_sources_without_sending_or_modifying_them() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let manifest_path = root.join("manifest.json");
    let map_path = root.join("sources.json");
    let source_path = root.join("source.bin");
    let alias_path = root.join("alias.bin");
    let id = "0123456789abcdef0123456789abcdef";
    std::fs::write(&source_path, b"hello").unwrap();
    let hash = format!("{:x}", Sha256::digest(b"hello"));
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600;
    let manifest = format!(
        r#"{{"aggregate_bytes":5,"expires_unix":{expires},"file_count":1,"files":[{{"id":"one","name":"a.bin","sha256":"{hash}","size":5}}],"transaction_id":"{id}","version":1}}"#
    );
    std::fs::write(&manifest_path, manifest.as_bytes()).unwrap();
    let digest = format!("{:x}", Sha256::digest(manifest.as_bytes()));
    let write_map = |path: &std::path::Path, source_id: &str| {
        let path = path.to_str().unwrap();
        assert!(!path.contains(['"', '\\']));
        std::fs::write(
            &map_path,
            format!(r#"{{"version":1,"sources":[{{"id":"{source_id}","path":"{path}"}}]}}"#),
        )
        .unwrap();
    };
    let run = |digest: &str| {
        Command::new(env!("CARGO_BIN_EXE_teamy-mover"))
            .args([
                "--output-format",
                "json",
                "transfer",
                "send",
                "--verify-only",
                "--manifest-file",
            ])
            .arg(&manifest_path)
            .args([
                "--manifest-sha256",
                digest,
                "--transaction-id",
                id,
                "--source-map",
            ])
            .arg(&map_path)
            .output()
            .unwrap()
    };
    write_map(&source_path, "one");
    let good = run(&digest);
    assert!(
        good.status.success(),
        "{}",
        String::from_utf8_lossy(&good.stderr)
    );
    assert!(String::from_utf8_lossy(&good.stdout).contains("\"verified\": true"));
    assert!(!run(&"0".repeat(64)).status.success());
    write_map(&source_path, "wrong");
    assert!(!run(&digest).status.success());
    symlink(&source_path, &alias_path).unwrap();
    write_map(&alias_path, "one");
    assert!(!run(&digest).status.success());
    write_map(&source_path, "one");
    std::fs::write(&source_path, b"HELLO").unwrap();
    assert!(!run(&digest).status.success());
    assert_eq!(std::fs::read(&source_path).unwrap(), b"HELLO");
}

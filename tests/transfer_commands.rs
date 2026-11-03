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
        assert!(output.stdout.is_empty());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}

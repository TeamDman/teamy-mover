use std::fs;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use teamy_mover::planning;

#[derive(Debug)]
struct Fixture(PathBuf, PathBuf);

impl Fixture {
    fn new() -> Self {
        let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-fixtures");
        fs::create_dir_all(&parent).expect("fixture parent");
        let root = parent.join(format!(
            "output-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        fs::create_dir(&root).expect("new fixture");
        Self(
            fs::canonicalize(root).expect("fixture root"),
            fs::canonicalize(parent).expect("fixture parent"),
        )
    }

    fn create_plan(&self) -> String {
        let path = self
            .0
            .join("output.plan.json")
            .to_str()
            .expect("Unicode")
            .to_owned();
        planning::create_plan(
            &path,
            "output contract fixture",
            Some(self.0.to_str().expect("Unicode")),
            None,
        )
        .expect("create plan");
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        assert!(self.0.starts_with(&self.1) && self.0 != self.1);
        fs::remove_dir_all(&self.0).expect("remove only this synthetic fixture");
    }
}

#[test]
fn malformed_and_unsupported_input_fail_with_stderr_and_no_json_stdout() {
    let fixture = Fixture::new();
    let plan_path = fixture.create_plan();
    let mut unsupported = planning::read_plan_input(&plan_path).expect("plan");
    unsupported.version = 99;
    let unsupported = facet_json::to_string_pretty(&unsupported).expect("unsupported JSON");
    for (index, (json, expected)) in [
        ("this is not JSON", "invalid plan JSON"),
        (unsupported.as_str(), "unsupported plan version"),
    ]
    .into_iter()
    .enumerate()
    {
        let path = fixture.0.join(format!("invalid-{index}.plan.json"));
        fs::write(&path, json).expect("invalid input");
        let output = Command::new(env!("CARGO_BIN_EXE_teamy-mover"))
            .args([
                "--output-format",
                "json",
                "plan",
                "dry-run",
                "--plan-file",
                path.to_str().expect("Unicode"),
            ])
            .output()
            .expect("invalid plan subprocess");
        assert!(!output.status.success());
        assert!(
            output.stdout.is_empty(),
            "an unrecoverable error must not emit a partial result"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read_to_string(path).expect("input unchanged"), json);
    }
}

#[test]
fn genuine_parse_errors_keep_useful_diagnostics_on_stderr() {
    for (arguments, expected) in [
        (
            vec!["--output-format", "json", "plan", "action", "show"],
            "missing required command arguments",
        ),
        (
            vec!["--output-format", "json", "plan", "unexpected-command"],
            "unexpected-command",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_teamy-mover"))
            .args(arguments)
            .output()
            .expect("parser subprocess");
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn stdout_write_failure_propagates_as_an_unrecoverable_error() {
    let fixture = Fixture::new();
    let plan_path = fixture.create_plan();
    let previous = fs::read(&plan_path).expect("plan bytes");
    let mut child = Command::new(env!("CARGO_BIN_EXE_teamy-mover"))
        .args([
            "--output-format",
            "json",
            "plan",
            "show",
            "--plan-file",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("stdout failure subprocess");
    // The read-only command cannot produce its result until stdin reaches EOF.
    // Close the only stdout reader first, then supply the plan deterministically.
    drop(child.stdout.take().expect("stdout reader"));
    let mut stdin = child.stdin.take().expect("stdin writer");
    stdin.write_all(&previous).expect("input plan");
    drop(stdin);
    let output = child.wait_with_output().expect("failed write result");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("failed to write command output"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(plan_path).expect("plan unchanged"), previous);
}

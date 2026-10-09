use std::fs;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use teamy_mover::planning::DryRunReport;
use teamy_mover::planning::MovePlan;
use teamy_mover::planning::MoveRequest;
use teamy_mover::planning::{self};

static SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
struct Fixture {
    root: PathBuf,
    parent: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-fixtures");
        fs::create_dir_all(&parent).expect("fixture parent");
        let root = parent.join(format!(
            "{}-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("fresh fixture");
        Self {
            root: fs::canonicalize(root).expect("fixture canonical"),
            parent: fs::canonicalize(parent).expect("parent canonical"),
        }
    }

    fn plan(&self) -> PathBuf {
        self.root.join("moves.plan.json")
    }

    fn create(&self) {
        planning::create_plan(
            self.plan().to_str().expect("Unicode"),
            "synthetic moves",
            Some(self.root.to_str().expect("Unicode")),
            None,
        )
        .expect("create plan");
    }

    fn add(&self, source: &str, destination: &str) {
        planning::add_move(
            self.plan().to_str().expect("Unicode"),
            MoveRequest {
                source: source.to_owned(),
                destination: destination.to_owned(),
                reason: "synthetic fixture".to_owned(),
            },
        )
        .expect("add move");
    }

    fn report(&self) -> DryRunReport {
        planning::dry_run_input(self.plan().to_str().expect("Unicode")).expect("dry-run");
        planning::dry_run_input(self.plan().to_str().expect("Unicode"))
            .expect("repeat read-only dry-run")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        assert!(self.root.starts_with(&self.parent) && self.root != self.parent);
        fs::remove_dir_all(&self.root).expect("remove this synthetic fixture only");
    }
}

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_teamy-mover"))
        .args(args)
        .output()
        .expect("run CLI")
}

#[test]
fn ordered_chain_uses_future_sources_and_never_moves_real_objects() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("a.txt"), "valuable fixture content").expect("source");
    fixture.create();
    fixture.add("a.txt", "b.txt");
    fixture.add("b.txt", "c.txt");
    let plan_before = fs::read(fixture.plan()).expect("plan before");
    let report = fixture.report();
    assert!(report.ready && report.read_only && !report.execution_available);
    assert_eq!(report.actions[1].depends_on, vec![1]);
    assert_eq!(
        fs::read_to_string(fixture.root.join("a.txt")).expect("source retained"),
        "valuable fixture content"
    );
    assert!(!fixture.root.join("b.txt").exists());
    assert!(!fixture.root.join("c.txt").exists());
    assert_eq!(fs::read(fixture.plan()).expect("plan after"), plan_before);
    assert!(
        fixture
            .root
            .join("moves.plan.json.revision-1.json")
            .is_file()
    );
    assert!(
        fixture
            .root
            .join("moves.plan.json.revision-2.json")
            .is_file()
    );
}

#[test]
fn destination_collision_is_a_completed_json_result_with_stderr_diagnostics() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("a.txt"), "source").expect("source");
    fs::write(fixture.root.join("b.txt"), "occupied").expect("destination");
    fixture.create();
    fixture.add("a.txt", "b.txt");
    let output = cli(&[
        "--output-format",
        "json",
        "plan",
        "dry-run",
        "--plan-file",
        fixture.plan().to_str().expect("Unicode"),
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("dry-run completed with planning conflicts")
    );
    let report: DryRunReport =
        facet_json::from_str(&String::from_utf8(output.stdout).expect("UTF8"))
            .expect("JSON report");
    assert!(!report.ready);
    assert!(
        report.actions[0]
            .issues
            .iter()
            .any(|issue| issue.contains("already occupied"))
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("b.txt")).expect("occupied retained"),
        "occupied"
    );
}

#[test]
fn vacated_destination_and_moved_parent_are_simulated() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("a.txt"), "a").expect("a");
    fs::write(fixture.root.join("b.txt"), "b").expect("b");
    fs::create_dir(fixture.root.join("old-parent")).expect("parent");
    fixture.create();
    fixture.add("b.txt", "c.txt");
    fixture.add("a.txt", "b.txt");
    fixture.add("old-parent", "new-parent");
    fixture.add("b.txt", "new-parent/a.txt");
    let report = fixture.report();
    assert!(report.ready, "{report:?}");
    assert_eq!(report.actions[1].depends_on, vec![1]);
    assert!(report.actions[3].depends_on.contains(&3));
    assert!(!fixture.root.join("new-parent").exists());
}

#[test]
fn duplicates_missing_parent_and_nested_destinations_are_blocked() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.root.join("folder")).expect("folder");
    fs::write(fixture.root.join("a.txt"), "a").expect("a");
    fixture.create();
    fixture.add("a.txt", "b.txt");
    fixture.add("a.txt", "c.txt");
    fixture.add("b.txt", "missing-parent/file.txt");
    fixture.add("folder", "folder/child");
    let report = fixture.report();
    assert!(!report.ready);
    assert!(report.actions[0].valid);
    assert!(
        report.actions[1]
            .issues
            .iter()
            .any(|issue| issue.contains("source is absent"))
    );
    assert!(
        report.actions[2]
            .issues
            .iter()
            .any(|issue| issue.contains("destination parent"))
    );
    assert!(
        report.actions[3]
            .issues
            .iter()
            .any(|issue| issue.contains("overlap"))
    );
    assert!(!fixture.root.join("missing-parent").exists());
}

#[test]
fn parent_and_child_source_overlap_is_caught_in_order() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.root.join("folder")).expect("folder");
    fs::write(fixture.root.join("folder/child.txt"), "child").expect("child");
    fixture.create();
    fixture.add("folder", "relocated");
    fixture.add("folder/child.txt", "child.txt");
    let report = fixture.report();
    assert!(!report.ready && report.actions[0].valid && !report.actions[1].valid);
    assert!(fixture.root.join("folder/child.txt").is_file());
}

#[test]
fn schema_rejects_unknown_versions_fields_operations_and_duplicate_ids() {
    let fixture = Fixture::new();
    fixture.create();
    fixture.add("absent", "destination");
    let json = fs::read_to_string(fixture.plan()).expect("JSON");
    for invalid in [
        json.replace("\"version\": 1", "\"version\": 99"),
        json.replacen('{', "{\"unexpected\": true,", 1),
        json.replace("\"move\"", "\"delete\""),
    ] {
        fs::write(fixture.root.join("invalid.plan.json"), invalid).expect("invalid fixture");
        let _ = planning::read_plan_input(
            fixture
                .root
                .join("invalid.plan.json")
                .to_str()
                .expect("Unicode"),
        )
        .expect_err("invalid planning operation must fail");
    }
    let mut plan: MovePlan = facet_json::from_str(&json).expect("parse plan");
    plan.actions.push(plan.actions[0].clone());
    let _ = planning::dry_run(&plan, None).expect_err("invalid planning operation must fail");
}

#[test]
fn create_never_overwrites_and_add_requires_reason() {
    let fixture = Fixture::new();
    fixture.create();
    let previous = fs::read(fixture.plan()).expect("before");
    let _ = planning::create_plan(
        fixture.plan().to_str().expect("Unicode"),
        "other",
        Some(fixture.root.to_str().expect("Unicode")),
        None,
    )
    .expect_err("invalid planning operation must fail");
    let _ = planning::add_move(
        fixture.plan().to_str().expect("Unicode"),
        MoveRequest {
            source: "a".to_owned(),
            destination: "b".to_owned(),
            reason: " ".to_owned(),
        },
    )
    .expect_err("invalid planning operation must fail");
    assert_eq!(fs::read(fixture.plan()).expect("after"), previous);
}

#[test]
fn stdin_and_at_file_action_inputs_and_plan_input_work() {
    let fixture = Fixture::new();
    fixture.create();
    let request = "{\"source\":\"a.txt\",\"destination\":\"b.txt\",\"reason\":\"fixture\"}";
    let mut child = Command::new(env!("CARGO_BIN_EXE_teamy-mover"))
        .args([
            "plan",
            "action",
            "add",
            "--plan-file",
            fixture.plan().to_str().expect("Unicode"),
            "--input",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("stdin child");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(request.as_bytes())
        .expect("request");
    let output = child.wait_with_output().expect("output");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let request_file = fixture.root.join("request.json");
    fs::write(
        &request_file,
        request
            .replace("a.txt", "b.txt")
            .replace("b.txt\",\"reason", "c.txt\",\"reason"),
    )
    .expect("request file");
    let output = cli(&[
        "plan",
        "action",
        "add",
        "--plan-file",
        fixture.plan().to_str().expect("Unicode"),
        "--input",
        &format!("@{}", request_file.display()),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = cli(&[
        "plan",
        "show",
        "--plan-file",
        &format!("@{}", fixture.plan().display()),
    ]);
    assert!(output.status.success());
    let mut child = Command::new(env!("CARGO_BIN_EXE_teamy-mover"))
        .args(["plan", "show", "--plan-file", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("plan stdin child");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(&fs::read(fixture.plan()).expect("plan"))
        .expect("plan input");
    assert!(child.wait_with_output().expect("output").status.success());
}

#[test]
fn help_version_and_typos_cannot_be_interpreted_as_moves() {
    for args in [
        vec!["--help"],
        vec!["--version"],
        vec!["plan", "--help"],
        vec!["plan", "action", "add", "--help"],
        vec!["plan", "dry-run", "--help"],
    ] {
        let output = cli(&args);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    for args in [
        vec!["src.txt", "dest.txt"],
        vec!["plna", "list"],
        vec!["plan", "apply"],
        vec!["cache", "clean"],
        vec!["plan", "action", "add"],
        vec!["plan", "create"],
    ] {
        let output = cli(&args);
        assert!(
            !output.status.success(),
            "invalid command unexpectedly succeeded: {args:?}"
        );
    }
}

#[test]
fn html_output_escapes_untrusted_reason_and_plan_name() {
    let fixture = Fixture::new();
    planning::create_plan(
        fixture.plan().to_str().expect("Unicode"),
        "<script>alert(1)</script>",
        Some(fixture.root.to_str().expect("Unicode")),
        None,
    )
    .expect("plan");
    let output = cli(&[
        "--output-format",
        "html",
        "plan",
        "show",
        "--plan-file",
        fixture.plan().to_str().expect("Unicode"),
    ]);
    assert!(output.status.success());
    let html = String::from_utf8(output.stdout).expect("HTML");
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(!html.contains("<script>alert(1)</script>"));
}

#[test]
fn planning_commands_return_explicit_completion_budgets() {
    let fixture = Fixture::new();
    fixture.create();
    let path = fixture.plan().to_str().unwrap().to_owned();
    let output = teamy_mover::cli::plan::show::PlanShowArgs {
        plan_file: path.clone(),
    }
    .invoke()
    .unwrap();
    assert!(output.elapsed_duration_warn_threshold.unwrap() >= std::time::Duration::from_secs(3));
    let output = teamy_mover::cli::plan::dry_run::PlanDryRunArgs { plan_file: path }
        .invoke()
        .unwrap();
    assert!(output.elapsed_duration_warn_threshold.unwrap() >= std::time::Duration::from_secs(3));
}

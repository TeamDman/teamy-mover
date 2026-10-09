use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use teamy_mover::planning::MoveAction;
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
            "actions-{}-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("new fixture");
        let fixture = Self {
            root: fs::canonicalize(root).expect("fixture root"),
            parent: fs::canonicalize(parent).expect("fixture parent"),
        };
        fs::write(fixture.root.join("a.txt"), "valuable synthetic source").expect("source");
        planning::create_plan(
            &fixture.plan_file(),
            "action metadata",
            Some(fixture.root.to_str().expect("Unicode")),
            None,
        )
        .expect("create");
        fixture
    }

    fn plan_file(&self) -> String {
        self.root
            .join("actions.plan.json")
            .to_str()
            .expect("Unicode")
            .to_owned()
    }

    fn command(&self, command: &str, extra: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_teamy-mover"))
            .args([
                "--output-format",
                "json",
                "plan",
                "action",
                command,
                "--plan-file",
                &self.plan_file(),
            ])
            .args(extra)
            .output()
            .expect("run action command")
    }

    fn add(&self, source: &str, destination: &str) -> MovePlan {
        let output = self.command(
            "add",
            &[
                "--source",
                source,
                "--destination",
                destination,
                "--reason",
                "synthetic action",
            ],
        );
        parse_success(&output)
    }

    fn snapshot(&self) -> BTreeMap<String, Vec<u8>> {
        fs::read_dir(&self.root)
            .expect("fixture entries")
            .map(|entry| {
                let entry = entry.expect("entry");
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    fs::read(entry.path()).expect("fixture file"),
                )
            })
            .collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        assert!(self.root.starts_with(&self.parent) && self.root != self.parent);
        fs::remove_dir_all(&self.root).expect("remove only this synthetic fixture");
    }
}

fn parse_success<T: facet::Facet<'static>>(output: &Output) -> T {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    facet_json::from_str(&String::from_utf8_lossy(&output.stdout)).expect("structured stdout")
}

#[test]
fn action_hierarchy_has_help_and_flat_add_is_rejected() {
    for command in [
        vec!["plan", "action", "--help"],
        vec!["plan", "action", "add", "--help"],
        vec!["plan", "action", "list", "--help"],
        vec!["plan", "action", "show", "--help"],
        vec!["plan", "action", "remove", "--help"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_teamy-mover"))
            .args(&command)
            .output()
            .expect("help");
        assert!(
            output.status.success(),
            "{command:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("plan action"));
    }
    let fixture = Fixture::new();
    let before = fixture.snapshot();
    let output = Command::new(env!("CARGO_BIN_EXE_teamy-mover"))
        .args([
            "plan",
            "add",
            "--plan-file",
            &fixture.plan_file(),
            "--source",
            "a.txt",
            "--destination",
            "b.txt",
            "--reason",
            "obsolete form",
        ])
        .output()
        .expect("flat command");
    assert!(!output.status.success());
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn selection_removal_and_readd_keep_ids_history_and_source_bytes() {
    let fixture = Fixture::new();
    fixture.add("a.txt", "b.txt");
    fixture.add("b.txt", "c.txt");
    let original = fixture.add("c.txt", "d.txt");
    let original_json = fs::read(fixture.plan_file()).expect("original JSON");
    let before_reads = fixture.snapshot();
    let actions: Vec<MoveAction> = parse_success(&fixture.command("list", &[]));
    assert_eq!(
        actions
            .iter()
            .map(|action| action.action_id)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    let selected: MoveAction = parse_success(&fixture.command("show", &["--action-id", "3"]));
    assert_eq!(selected, original.actions[2]);
    assert_eq!(fixture.snapshot(), before_reads);

    let removed: MovePlan = parse_success(&fixture.command("remove", &["--action-id", "2"]));
    assert_eq!(
        removed
            .actions
            .iter()
            .map(|action| action.action_id)
            .collect::<Vec<_>>(),
        vec![1, 3]
    );
    assert!(removed.revision > original.revision);
    assert_eq!(
        fs::read(format!(
            "{}.revision-{}.json",
            fixture.plan_file(),
            original.revision
        ))
        .expect("retained original"),
        original_json
    );
    let selected: MoveAction = parse_success(&fixture.command("show", &["--action-id", "3"]));
    assert_eq!(selected, original.actions[2]);
    assert!(
        !planning::dry_run_input(&fixture.plan_file())
            .expect("dependency check")
            .ready
    );
    let updated = fixture.add("a.txt", "elsewhere.txt");
    let new_id = updated.actions.last().expect("new action").action_id;
    assert!(new_id > 3 && new_id != 2);
    let removed_last: MovePlan =
        parse_success(&fixture.command("remove", &["--action-id", &new_id.to_string()]));
    let updated_again = fixture.add("a.txt", "another.txt");
    assert!(updated_again.actions.last().expect("new ID").action_id > new_id);
    assert!(updated_again.revision > removed_last.revision);
    assert_eq!(updated_again.version, 1);
    assert_eq!(
        fs::read_to_string(fixture.root.join("a.txt")).expect("unchanged source"),
        "valuable synthetic source"
    );
    for path in ["b.txt", "c.txt", "d.txt", "elsewhere.txt", "another.txt"] {
        assert!(!fixture.root.join(path).exists());
    }
}

#[test]
fn invalid_ids_and_missing_selection_do_not_change_plan_or_history() {
    let fixture = Fixture::new();
    fixture.add("a.txt", "b.txt");
    let before = fixture.snapshot();
    for command in ["show", "remove"] {
        for extra in [
            vec![],
            vec!["--action-id", "0"],
            vec!["--action-id", "-1"],
            vec!["--action-id", "999"],
            vec!["--action-id", "not-a-number"],
        ] {
            let output = fixture.command(command, &extra);
            assert!(!output.status.success(), "{command}: {extra:?}");
            assert_eq!(fixture.snapshot(), before);
        }
    }
    let removed: MovePlan = parse_success(&fixture.command("remove", &["--action-id", "1"]));
    assert_eq!(removed.actions, [] as [MoveAction; 0]);
    let after_valid_removal = fixture.snapshot();
    assert!(
        !fixture
            .command("remove", &["--action-id", "1"])
            .status
            .success()
    );
    assert_eq!(fixture.snapshot(), after_valid_removal);
}

#[test]
fn imported_high_ids_remain_retired_without_schema_changes() {
    let fixture = Fixture::new();
    let mut imported = fixture.add("a.txt", "b.txt");
    imported.revision = 1;
    imported.actions[0].action_id = 1000;
    // The fixture's previous version-1 sidecar belongs to its pre-import identity.
    // Use an independent imported file to avoid overwriting that history.
    let imported_path = fixture.root.join("imported.plan.json");
    fs::write(
        &imported_path,
        facet_json::to_string_pretty(&imported).expect("JSON"),
    )
    .expect("import file");
    let removed = planning::remove_action(imported_path.to_str().expect("Unicode"), 1000)
        .expect("remove high ID");
    assert!(removed.actions.is_empty() && removed.revision > 1000);
    let added = planning::add_move(
        imported_path.to_str().expect("Unicode"),
        MoveRequest {
            source: "a.txt".to_owned(),
            destination: "new.txt".to_owned(),
            reason: "new action".to_owned(),
        },
    )
    .expect("new ID");
    assert!(added.actions[0].action_id > 1000);
    assert_eq!(added.version, 1);
}

#[test]
fn occupied_revision_sidecar_blocks_removal_without_overwriting_anything() {
    let fixture = Fixture::new();
    let plan = fixture.add("a.txt", "b.txt");
    fs::write(
        format!("{}.revision-{}.json", fixture.plan_file(), plan.revision),
        "sentinel history",
    )
    .expect("occupied sidecar");
    let before = fixture.snapshot();
    assert!(
        !fixture
            .command("remove", &["--action-id", "1"])
            .status
            .success()
    );
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn action_reads_accept_stdin_and_at_file_without_metadata_writes() {
    let fixture = Fixture::new();
    let plan = fixture.add("a.txt", "b.txt");
    let before = fixture.snapshot();
    let output = Command::new(env!("CARGO_BIN_EXE_teamy-mover"))
        .args([
            "--output-format",
            "json",
            "plan",
            "action",
            "show",
            "--plan-file",
            &format!("@{}", fixture.plan_file()),
            "--action-id",
            "1",
        ])
        .output()
        .expect("@file show");
    let selected: MoveAction = parse_success(&output);
    assert_eq!(selected, plan.actions[0]);
    let mut child = Command::new(env!("CARGO_BIN_EXE_teamy-mover"))
        .args([
            "--output-format",
            "json",
            "plan",
            "action",
            "list",
            "--plan-file",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("stdin list");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(&fs::read(fixture.plan_file()).expect("plan JSON"))
        .expect("input");
    let listed: Vec<MoveAction> = parse_success(&child.wait_with_output().expect("output"));
    assert_eq!(listed, plan.actions);
    assert_eq!(fixture.snapshot(), before);
}

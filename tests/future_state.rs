use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use teamy_mover::planning::MoveRequest;
use teamy_mover::planning::{self};

static SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
struct Fixture(PathBuf, PathBuf);

impl Fixture {
    fn new() -> Self {
        let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-fixtures");
        fs::create_dir_all(&parent).expect("fixture parent");
        let root = parent.join(format!(
            "future-{}-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("fixture");
        Self(
            fs::canonicalize(root).expect("root"),
            fs::canonicalize(parent).expect("parent"),
        )
    }

    fn plan(&self) -> String {
        self.0
            .join("future.plan.json")
            .to_str()
            .expect("Unicode")
            .to_owned()
    }

    fn add(&self, source: &str, destination: &str) {
        planning::add_move(
            &self.plan(),
            MoveRequest {
                source: source.to_owned(),
                destination: destination.to_owned(),
                reason: "future tree fixture".to_owned(),
            },
        )
        .expect("future add");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        assert!(self.0.starts_with(&self.1) && self.0 != self.1);
        fs::remove_dir_all(&self.0).expect("remove only this synthetic fixture");
    }
}

#[test]
fn future_file_to_directory_reuse_works_for_add_and_imported_plan() {
    let fixture = Fixture::new();
    fs::write(fixture.0.join("slot"), "original file").expect("slot");
    fs::create_dir(fixture.0.join("folder")).expect("folder");
    fs::write(fixture.0.join("folder/child.txt"), "child").expect("child");
    planning::create_plan(
        &fixture.plan(),
        "future directory",
        Some(fixture.0.to_str().expect("Unicode")),
        None,
    )
    .expect("create");
    fixture.add("slot", "spare.txt");
    fixture.add("folder", "slot");
    fixture.add("slot/child.txt", "final.txt");
    let report = planning::dry_run_input(&fixture.plan()).expect("dry-run");
    assert!(report.ready, "{report:?}");
    assert_eq!(report.actions[1].depends_on, vec![1]);
    assert!(report.actions[2].depends_on.contains(&2));
    let plan_json = fs::read_to_string(fixture.plan()).expect("JSON");
    let imported = fixture.0.join("imported.plan.json");
    fs::write(&imported, plan_json).expect("import");
    assert!(
        planning::dry_run_input(imported.to_str().expect("Unicode"))
            .expect("imported dry-run")
            .ready
    );
    assert_eq!(
        fs::read_to_string(fixture.0.join("slot")).expect("slot unchanged"),
        "original file"
    );
    assert_eq!(
        fs::read_to_string(fixture.0.join("folder/child.txt")).expect("child unchanged"),
        "child"
    );
    assert!(!fixture.0.join("spare.txt").exists() && !fixture.0.join("final.txt").exists());
}

#[test]
fn absolute_and_relative_future_sources_share_one_path_identity() {
    let fixture = Fixture::new();
    fs::write(fixture.0.join("a.txt"), "a").expect("a");
    planning::create_plan(
        &fixture.plan(),
        "mixed spellings",
        Some(fixture.0.to_str().expect("Unicode")),
        None,
    )
    .expect("create");
    let absolute_b = fixture
        .0
        .join("b.txt")
        .to_str()
        .expect("Unicode")
        .to_owned();
    #[cfg(windows)]
    let absolute_b = absolute_b
        .strip_prefix("\\\\?\\")
        .expect("canonical drive prefix")
        .to_owned();
    fixture.add("a.txt", &absolute_b);
    fixture.add("b.txt", "c.txt");
    let report = planning::dry_run_input(&fixture.plan()).expect("dry-run");
    assert!(report.ready, "{report:?}");
    assert_eq!(report.actions[1].depends_on, vec![1]);
}

#[cfg(windows)]
#[test]
fn ambiguous_and_device_namespace_action_paths_are_rejected() {
    let fixture = Fixture::new();
    planning::create_plan(
        &fixture.plan(),
        "path boundaries",
        Some(fixture.0.to_str().expect("Unicode")),
        None,
    )
    .expect("create");
    for source in [
        "../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../escape",
        "C:relative.txt",
        "\\root-relative.txt",
        "\\\\.\\PhysicalDrive0",
        "\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\file",
        "C:\\..\\escape",
    ] {
        assert!(
            planning::add_move(
                &fixture.plan(),
                MoveRequest {
                    source: source.to_owned(),
                    destination: "b.txt".to_owned(),
                    reason: "invalid path".to_owned()
                }
            )
            .is_err(),
            "accepted {source}"
        );
    }
    assert_eq!(
        planning::read_plan_input(&fixture.plan())
            .expect("plan")
            .actions,
        [] as [teamy_mover::planning::MoveAction; 0]
    );
}

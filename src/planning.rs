//! Versioned plan metadata and a read-only simulation of ordered moves.
//!
//! This module deliberately contains no operation that moves a source object.
//! Its writes create/update plan JSON and append-only prior revisions only.

use eyre::Context;
use eyre::Result;
use eyre::bail;
use facet::Facet;
use std::collections::HashSet;
use std::fs::File;
use std::fs::OpenOptions;
use std::fs::{self};
use std::io::Read;
use std::io::Write;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

const VERSION: u32 = 1;
const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;
static SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Facet, Clone, Debug, PartialEq)]
#[facet(deny_unknown_fields)]
pub struct MovePlan {
    pub version: u32,
    pub plan_id: String,
    pub revision: u64,
    pub name: String,
    pub base_directory: String,
    #[facet(default)]
    pub policy_reference: Option<String>,
    pub actions: Vec<MoveAction>,
}

#[derive(Facet, Clone, Debug, PartialEq, Eq)]
#[facet(rename_all = "kebab-case")]
#[repr(u8)]
pub enum Operation {
    Move,
}

#[derive(Facet, Clone, Debug, PartialEq)]
#[facet(deny_unknown_fields)]
pub struct MoveAction {
    pub action_id: u64,
    pub operation: Operation,
    pub source: String,
    pub destination: String,
    pub reason: String,
}

#[derive(Facet, Clone, Debug)]
#[facet(deny_unknown_fields)]
pub struct MoveRequest {
    pub source: String,
    pub destination: String,
    pub reason: String,
}

#[derive(Facet, Debug)]
pub struct PlanSummary {
    pub path: String,
    pub plan_id: Option<String>,
    pub revision: Option<u64>,
    pub name: Option<String>,
    pub actions: Option<usize>,
    pub error: Option<String>,
}

#[derive(Facet, Debug)]
pub struct DryRunReport {
    pub version: u32,
    pub plan_id: String,
    pub plan_revision: u64,
    pub ready: bool,
    pub read_only: bool,
    pub execution_available: bool,
    pub scope: String,
    pub actions: Vec<ActionCheck>,
    pub limitations: Vec<String>,
}

#[derive(Facet, Debug)]
pub struct ActionCheck {
    pub action_id: u64,
    pub source: String,
    pub destination: String,
    pub source_kind: Option<String>,
    pub depends_on: Vec<u64>,
    pub valid: bool,
    pub issues: Vec<String>,
}

#[derive(Debug)]
struct SimulatedMove {
    id: u64,
    source: PathBuf,
    destination: PathBuf,
}

#[derive(Debug)]
struct Observation {
    metadata: Option<fs::Metadata>,
    depends_on: Vec<u64>,
}

fn checked_text(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{field} must not be empty");
    }
    if value.contains(['\0', '\r', '\n']) {
        bail!("{field} must not contain NUL or newline characters");
    }
    Ok(())
}

fn path_text(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| eyre::eyre!("paths must be valid Unicode for JSON plans"))
}

fn is_reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn check_existing_components(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        // Windows drive/verbatim prefixes are not independently stat-able.
        if matches!(component, Component::Prefix(_)) || !current.is_absolute() {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if is_reparse(&metadata) => {
                bail!(
                    "symlinks and reparse points require a future explicit policy: {}",
                    current.display()
                );
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(error).wrap_err_with(|| {
                    format!("could not inspect path component {}", current.display())
                });
            }
        }
    }
    Ok(())
}

/// Resolve an exact path through its existing ancestor, retaining missing tails.
/// Wildcards are literal names; there is no shell expansion.
///
/// # Errors
/// Rejects ambiguous text, parent traversal beyond the root, and reparse points.
pub fn resolve_path(base: &Path, raw: &str) -> Result<PathBuf> {
    let lexical = lexical_path(base, raw)?;
    check_existing_components(&lexical)?;
    let mut ancestor = lexical.as_path();
    let mut missing = Vec::new();
    while !ancestor.try_exists()? {
        let name = ancestor
            .file_name()
            .ok_or_else(|| eyre::eyre!("no existing ancestor"))?;
        missing.push(name.to_owned());
        ancestor = ancestor
            .parent()
            .ok_or_else(|| eyre::eyre!("no existing ancestor"))?;
    }
    let mut resolved =
        fs::canonicalize(ancestor).wrap_err("could not canonicalize existing ancestor")?;
    for name in missing.into_iter().rev() {
        resolved.push(name);
    }
    Ok(resolved)
}

fn lexical_path(base: &Path, raw: &str) -> Result<PathBuf> {
    checked_text(raw, "path")?;
    let raw_path = Path::new(raw);
    #[cfg(windows)]
    if raw_path.has_root() != raw_path.is_absolute()
        || (matches!(raw_path.components().next(), Some(Component::Prefix(_)))
            && !raw_path.is_absolute())
    {
        bail!("Windows paths must be fully absolute or relative, not drive-relative/root-relative");
    }
    let components = if raw_path.is_absolute() {
        raw_path.components().collect::<Vec<_>>()
    } else {
        base.components().chain(raw_path.components()).collect()
    };
    let mut lexical = PathBuf::new();
    for component in components {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !matches!(lexical.components().next_back(), Some(Component::Normal(_)))
                    || !lexical.pop()
                {
                    bail!("path traverses above the filesystem root");
                }
            }
            _ => lexical.push(component.as_os_str()),
        }
    }
    if !lexical.is_absolute() {
        bail!("base directory must be absolute");
    }
    Ok(lexical)
}

// Actions describe a future tree. Do not stat physical ancestors before mapping
// through preceding moves: a physical file can become a virtual directory.
fn action_path(base: &Path, raw: &str) -> Result<PathBuf> {
    let lexical = lexical_path(base, raw)?;
    #[cfg(windows)]
    {
        use std::ffi::OsString;
        use std::path::Prefix;
        let mut parts = lexical.components();
        let Some(Component::Prefix(prefix)) = parts.next() else {
            bail!("Windows actions require a drive or UNC prefix");
        };
        let mut resolved = match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
                PathBuf::from(format!("\\\\?\\{}:\\", char::from(letter)))
            }
            Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
                let mut prefix = OsString::from("\\\\?\\UNC\\");
                prefix.push(server);
                prefix.push("\\");
                prefix.push(share);
                prefix.push("\\");
                PathBuf::from(prefix)
            }
            _ => {
                bail!("device and non-filesystem Windows namespace paths are unsupported");
            }
        };
        for part in parts {
            if !matches!(part, Component::RootDir) {
                resolved.push(part.as_os_str());
            }
        }
        Ok(resolved)
    }
    #[cfg(not(windows))]
    {
        Ok(lexical)
    }
}

fn plan_path(raw: &str) -> Result<PathBuf> {
    if raw == "-" || raw.starts_with('@') {
        bail!(
            "write commands require a literal --plan-file path; stdin/@file are read-only input forms"
        );
    }
    resolve_path(&std::env::current_dir()?, raw)
}

fn parse_plan(json: &str) -> Result<MovePlan> {
    let plan: MovePlan = facet_json::from_str(json).wrap_err("invalid plan JSON")?;
    validate_schema(&plan)?;
    Ok(plan)
}

fn validate_schema(plan: &MovePlan) -> Result<()> {
    if plan.version != VERSION {
        bail!(
            "unsupported plan version {}; supported version is {VERSION}",
            plan.version
        );
    }
    checked_text(&plan.plan_id, "plan_id")?;
    checked_text(&plan.name, "name")?;
    checked_text(&plan.base_directory, "base_directory")?;
    if plan.revision == 0 || !Path::new(&plan.base_directory).is_absolute() {
        bail!("plan revision must be positive and base_directory absolute");
    }
    let mut ids = HashSet::new();
    for action in &plan.actions {
        if action.action_id == 0 || !ids.insert(action.action_id) {
            bail!("action IDs must be unique positive integers");
        }
        checked_text(&action.source, "source")?;
        checked_text(&action.destination, "destination")?;
        checked_text(&action.reason, "reason")?;
        if !Path::new(&action.source).is_absolute() || !Path::new(&action.destination).is_absolute()
        {
            bail!("stored action paths must be absolute");
        }
    }
    Ok(())
}

fn read_bounded(mut reader: impl Read) -> Result<String> {
    let mut data = Vec::new();
    reader
        .by_ref()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut data)?;
    if data.len() as u64 > MAX_INPUT_BYTES {
        bail!("JSON input exceeds the 16 MiB limit");
    }
    String::from_utf8(data).wrap_err("JSON input must be UTF-8")
}

fn read_input(raw: &str, literal_json: bool) -> Result<String> {
    if raw == "-" {
        return read_bounded(std::io::stdin().lock());
    }
    if let Some(file) = raw.strip_prefix('@') {
        let path = resolve_path(&std::env::current_dir()?, file)?;
        return read_bounded(File::open(path).wrap_err("could not open @file input")?);
    }
    if literal_json {
        if raw.len() as u64 > MAX_INPUT_BYTES {
            bail!("JSON input exceeds the 16 MiB limit");
        }
        return Ok(raw.to_owned());
    }
    let path = resolve_path(&std::env::current_dir()?, raw)?;
    read_bounded(File::open(path).wrap_err("could not open plan file")?)
}

/// # Errors
/// Returns an error for unsupported or invalid plan JSON and unreadable input.
pub fn read_plan_input(raw: &str) -> Result<MovePlan> {
    parse_plan(&read_input(raw, false)?)
}

/// # Errors
/// Returns an error for invalid JSON or unreadable stdin/@file input.
pub fn read_request(raw: &str) -> Result<MoveRequest> {
    facet_json::from_str(&read_input(raw, true)?).wrap_err("invalid move request JSON")
}

fn write_new(path: &Path, content: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)
        .wrap_err("could not create new plan metadata file; existing files are never overwritten by create")?;
    file.write_all(content)?;
    file.sync_all()?;
    Ok(())
}

#[derive(Debug)]
struct PlanLock {
    path: PathBuf,
    _file: File,
}

impl Drop for PlanLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn lock_plan(path: &Path) -> Result<PlanLock> {
    let lock_path = PathBuf::from(format!("{}.lock", path.display()));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .wrap_err("plan is locked; inspect any stale .lock after interruption before retrying")?;
    Ok(PlanLock {
        path: lock_path,
        _file: file,
    })
}

/// # Errors
/// Returns an error for occupied plan paths or unavailable base directories.
pub fn create_plan(
    raw: &str,
    name: &str,
    base: Option<&str>,
    policy_reference: Option<String>,
) -> Result<MovePlan> {
    checked_text(name, "name")?;
    let path = plan_path(raw)?;
    let cwd = std::env::current_dir()?;
    let base = resolve_path(&cwd, base.unwrap_or("."))?;
    if !base.is_dir() {
        bail!("base directory must already exist");
    }
    let timestamp = chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default();
    let plan = MovePlan {
        version: VERSION,
        plan_id: format!(
            "plan-{timestamp}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ),
        revision: 1,
        name: name.to_owned(),
        base_directory: path_text(&base)?,
        policy_reference,
        actions: Vec::new(),
    };
    write_new(&path, facet_json::to_string_pretty(&plan)?.as_bytes())?;
    Ok(plan)
}

/// Append one action and retain the previous plan in a sidecar revision file.
///
/// # Errors
/// Returns an error for invalid paths, unsupported plans or failed writes.
pub fn add_move(raw: &str, request: MoveRequest) -> Result<MovePlan> {
    checked_text(&request.reason, "reason")?;
    let path = plan_path(raw)?;
    let _lock = lock_plan(&path)?;
    let previous = read_bounded(File::open(&path)?)?;
    let mut plan = parse_plan(&previous)?;
    let base = Path::new(&plan.base_directory);
    let source = action_path(base, &request.source)?;
    let destination = action_path(base, &request.destination)?;
    let id = plan
        .actions
        .iter()
        .map(|action| action.action_id)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| eyre::eyre!("action ID exhausted"))?
        .max(plan.revision);
    let previous_revision = plan.revision;
    plan.revision = id
        .checked_add(1)
        .ok_or_else(|| eyre::eyre!("plan revision exhausted"))?;
    plan.actions.push(MoveAction {
        action_id: id,
        operation: Operation::Move,
        source: path_text(&source)?,
        destination: path_text(&destination)?,
        reason: request.reason,
    });
    persist_plan_revision(&path, &previous, previous_revision, &plan)?;
    Ok(plan)
}

fn persist_plan_revision(
    path: &Path,
    previous: &str,
    previous_revision: u64,
    plan: &MovePlan,
) -> Result<()> {
    let revision_path = PathBuf::from(format!(
        "{}.revision-{}.json",
        path.display(),
        previous_revision
    ));
    let encoded = facet_json::to_string_pretty(plan)?;
    // A failed final replacement keeps both the old plan and recoverable files.
    let pending_path = PathBuf::from(format!(
        "{}.pending-{}-{}.json",
        path.display(),
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    write_new(&revision_path, previous.as_bytes())?;
    write_new(&pending_path, encoded.as_bytes())?;
    fs::rename(&pending_path, path)
        .wrap_err("could not replace plan; prior revision and pending JSON remain available")?;
    Ok(())
}

fn positive_action_id(action_id: u64) -> Result<()> {
    if action_id == 0 {
        bail!("action ID must be a positive integer");
    }
    Ok(())
}

/// # Errors
/// Returns an error for invalid or unreadable plan input. Does not inspect
/// source/destination objects or update plan metadata.
pub fn list_actions(raw: &str) -> Result<Vec<MoveAction>> {
    Ok(read_plan_input(raw)?.actions)
}

/// # Errors
/// Returns an error for a non-positive ID, unknown action or unreadable plan.
pub fn show_action(raw: &str, action_id: u64) -> Result<MoveAction> {
    positive_action_id(action_id)?;
    read_plan_input(raw)?
        .actions
        .into_iter()
        .find(|action| action.action_id == action_id)
        .ok_or_else(|| eyre::eyre!("action ID {action_id} does not exist in this plan"))
}

/// Remove one action from metadata without renumbering the remaining actions.
/// The revision acts as an allocation high-water mark, preserving version 1.
///
/// # Errors
/// Returns an error for invalid/missing IDs, unsupported plans or failed writes.
/// Invalid selection leaves the plan and revision history unchanged.
pub fn remove_action(raw: &str, action_id: u64) -> Result<MovePlan> {
    positive_action_id(action_id)?;
    let path = plan_path(raw)?;
    // Reject ordinary invalid selection before creating even a lock sidecar.
    show_action(&path_text(&path)?, action_id)?;
    let _lock = lock_plan(&path)?;
    let previous = read_bounded(File::open(&path)?)?;
    let mut plan = parse_plan(&previous)?;
    let index = plan
        .actions
        .iter()
        .position(|action| action.action_id == action_id)
        .ok_or_else(|| eyre::eyre!("action ID {action_id} no longer exists in this plan"))?;
    let previous_revision = plan.revision;
    // Include the removed ID before changing the list, including imported
    // version 1 plans whose existing IDs exceed their revision number.
    plan.revision = plan
        .actions
        .iter()
        .map(|action| action.action_id)
        .max()
        .unwrap_or(0)
        .max(previous_revision)
        .checked_add(1)
        .ok_or_else(|| eyre::eyre!("plan revision exhausted"))?;
    plan.actions.remove(index);
    persist_plan_revision(&path, &previous, previous_revision, &plan)?;
    Ok(plan)
}

/// # Errors
/// Returns an error if the explicit directory cannot be read. Individual
/// malformed plan files remain visible as summaries containing their errors.
pub fn list_plans(directory: Option<&str>) -> Result<Vec<PlanSummary>> {
    let cwd = std::env::current_dir()?;
    let directory = resolve_path(&cwd, directory.unwrap_or("."))?;
    let mut paths = fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.sort();
    let mut summaries = Vec::new();
    for path in paths {
        if !path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().ends_with(".plan.json"))
        {
            continue;
        }
        let text = path_text(&path)?;
        let mut summary = PlanSummary {
            path: text.clone(),
            plan_id: None,
            revision: None,
            name: None,
            actions: None,
            error: None,
        };
        match read_plan_input(&text) {
            Ok(plan) => {
                summary.plan_id = Some(plan.plan_id);
                summary.revision = Some(plan.revision);
                summary.name = Some(plan.name);
                summary.actions = Some(plan.actions.len());
            }
            Err(error) => summary.error = Some(error.to_string()),
        }
        summaries.push(summary);
    }
    Ok(summaries)
}

fn equivalent(left: &Path, right: &Path) -> bool {
    #[cfg(windows)]
    {
        left.as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

fn strip_path_prefix(path: &Path, prefix: &Path) -> Option<PathBuf> {
    let mut path_parts = path.components();
    for prefix_part in prefix.components() {
        let path_part = path_parts.next()?;
        if !equivalent(
            Path::new(path_part.as_os_str()),
            Path::new(prefix_part.as_os_str()),
        ) {
            return None;
        }
    }
    Some(path_parts.as_path().to_path_buf())
}

fn observe(path: &Path, moves: &[SimulatedMove]) -> Result<Observation> {
    let mut physical = path.to_path_buf();
    let mut depends_on = Vec::new();
    for movement in moves.iter().rev() {
        if let Some(tail) = strip_path_prefix(&physical, &movement.destination) {
            // Joining an empty tail adds a trailing separator, invalid for files on Unix.
            physical = if tail.as_os_str().is_empty() {
                movement.source.clone()
            } else {
                movement.source.join(tail)
            };
            depends_on.push(movement.id);
        } else if strip_path_prefix(&physical, &movement.source).is_some() {
            depends_on.push(movement.id);
            depends_on.sort_unstable();
            depends_on.dedup();
            return Ok(Observation {
                metadata: None,
                depends_on,
            });
        }
    }
    check_existing_components(&physical)?;
    let metadata = match fs::symlink_metadata(physical) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).wrap_err("could not inspect source/destination metadata"),
    };
    depends_on.sort_unstable();
    depends_on.dedup();
    Ok(Observation {
        metadata,
        depends_on,
    })
}

/// # Errors
/// Returns an error for malformed input. This only performs filesystem reads.
pub fn dry_run_input(raw: &str) -> Result<DryRunReport> {
    let plan = read_plan_input(raw)?;
    let plan_file = if raw == "-" {
        None
    } else {
        Some(resolve_path(
            &std::env::current_dir()?,
            raw.strip_prefix('@').unwrap_or(raw),
        )?)
    };
    dry_run(&plan, plan_file.as_deref())
}

/// Simulate actions in list order without touching source/destination objects.
///
/// # Errors
/// Returns an error for an unsupported plan schema.
pub fn dry_run(plan: &MovePlan, plan_file: Option<&Path>) -> Result<DryRunReport> {
    validate_schema(plan)?;
    let base = Path::new(&plan.base_directory);
    let mut moves = Vec::new();
    let mut checks = Vec::new();
    for action in &plan.actions {
        let mut check = ActionCheck {
            action_id: action.action_id,
            source: action.source.clone(),
            destination: action.destination.clone(),
            source_kind: None,
            depends_on: Vec::new(),
            valid: false,
            issues: Vec::new(),
        };
        let paths = action_path(base, &action.source).and_then(|source| {
            action_path(base, &action.destination).map(|destination| (source, destination))
        });
        let (source, destination) = match paths {
            Ok(paths) => paths,
            Err(error) => {
                check.issues.push(error.to_string());
                checks.push(check);
                continue;
            }
        };
        if equivalent(&source, &destination) {
            check
                .issues
                .push("source and destination are the same path".to_owned());
        }
        if source.parent().is_none() {
            check
                .issues
                .push("filesystem roots cannot be move sources".to_owned());
        }
        if plan_file.is_some_and(|path| strip_path_prefix(path, &source).is_some()) {
            check.issues.push(
                "move would contain its own plan file; keep plan metadata outside sources"
                    .to_owned(),
            );
        }
        check_observations(&source, &destination, &moves, &mut check);
        check.depends_on.sort_unstable();
        check.depends_on.dedup();
        check.valid = check.issues.is_empty();
        if check.valid {
            moves.push(SimulatedMove {
                id: action.action_id,
                source,
                destination,
            });
        }
        checks.push(check);
    }
    Ok(DryRunReport {
        version: VERSION,
        plan_id: plan.plan_id.clone(),
        plan_revision: plan.revision,
        ready: checks.iter().all(|check| check.valid),
        read_only: true,
        execution_available: false,
        scope: "ordered metadata simulation; exact destinations, no wildcard expansion".to_owned(),
        actions: checks,
        limitations: vec![
            "A successful dry-run is not approval and is not a guarantee that a later executor could succeed.".to_owned(),
            "Metadata can change after inspection. No files are locked or hashed; access rights, disk capacity, cross-volume moves, hard links and full tree contents are not validated.".to_owned(),
            "Symlinks and Windows reparse points are rejected. Windows comparisons use ASCII case folding; Unicode aliases, case-sensitive directories and short-name aliases need future handling.".to_owned(),
            "Action order is preserved. Cycles require explicit intermediate moves; destination parents must exist in the simulated state. Invalid actions are not simulated.".to_owned(),
            "policy_reference is descriptive metadata, not an authentication or permission boundary.".to_owned(),
        ],
    })
}

fn check_observations(
    source: &Path,
    destination: &Path,
    moves: &[SimulatedMove],
    check: &mut ActionCheck,
) {
    let observations = observe(source, moves).and_then(|source_state| {
        observe(destination, moves).map(|destination_state| (source_state, destination_state))
    });
    let (source_state, destination_state) = match observations {
        Ok(states) => states,
        Err(error) => {
            check.issues.push(error.to_string());
            return;
        }
    };
    check.depends_on.extend(source_state.depends_on);
    check.depends_on.extend(destination_state.depends_on);
    match source_state.metadata {
        None => check
            .issues
            .push("source is absent in the simulated state".to_owned()),
        Some(metadata) => {
            check.source_kind = Some(
                if metadata.is_dir() {
                    "directory"
                } else {
                    "file"
                }
                .to_owned(),
            );
            if is_reparse(&metadata) {
                check
                    .issues
                    .push("source is a symlink/reparse point".to_owned());
            }
            if metadata.is_dir()
                && (strip_path_prefix(destination, source).is_some()
                    || strip_path_prefix(source, destination).is_some())
            {
                check
                    .issues
                    .push("source and destination directory trees overlap".to_owned());
            }
        }
    }
    if destination_state.metadata.is_some() {
        check.issues.push("exact destination is already occupied in the simulated state; overwriting is unsupported".to_owned());
    }
    if let Some(parent) = destination.parent() {
        match observe(parent, moves) {
            Ok(state) => {
                check.depends_on.extend(state.depends_on);
                if !state.metadata.is_some_and(|metadata| metadata.is_dir()) {
                    check.issues.push(
                        "destination parent is not an existing directory in the simulated state"
                            .to_owned(),
                    );
                }
            }
            Err(error) => check.issues.push(error.to_string()),
        }
    } else {
        check
            .issues
            .push("destination must have an existing parent directory".to_owned());
    }
}

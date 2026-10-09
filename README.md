# Teamy Mover

Prepare a versioned move plan, inspect it, and check the proposed future structure.

This initial release is a planner. `plan create`, `plan action add`, and
`plan action remove` write plan metadata. The other commands read it. No command executes
moves, cleans caches, removes source files, or creates destination directories.

## Try the planner

```powershell
cargo run -- plan create --plan-file example.plan.json --name 'Reorganise synthetic files'
cargo run -- plan action add --plan-file example.plan.json --source src.txt --destination dest.txt --reason 'Put the sample in its intended location'
cargo run -- plan show --plan-file example.plan.json
cargo run -- --output-format html plan show --plan-file example.plan.json > example.html
cargo run -- plan dry-run --plan-file example.plan.json
```

The sample source must exist for dry-run to succeed. It is never moved. Relative
action paths resolve against the existing base directory stored by `plan create`;
use `--base-dir` to choose it explicitly. A destination means the exact new path,
including its filename. It never means 'place the source inside this directory'.
The destination parent must already exist or be present in the simulated future
state. There is no implicit folder creation or wildcard expansion.

List plans in one directory:

```powershell
cargo run -- plan list --directory .
```

Listing considers only `*.plan.json` files and does not recurse. Malformed or
unsupported files appear with an error instead of being silently skipped.

## Work with actions inside a plan

Plan creation and action editing have separate command paths. Use
`plan action add` to append one proposed move to an existing plan. Inspect or
remove a particular action through the same hierarchy:

```powershell
cargo run -- plan action list --plan-file example.plan.json
cargo run -- plan action show --plan-file example.plan.json --action-id 1
cargo run -- plan action remove --plan-file example.plan.json --action-id 1
```

`list` returns actions in their current order. `show` selects a stable positive
action ID, rather than a position in the list. `remove` edits plan metadata and
retains the preceding JSON revision; it never removes a source or destination
file. Invalid, missing, or already removed IDs fail without changing the plan or
its history. Removing an action can make later actions invalid: run dry-run again
to check their future-state dependencies.

Surviving action IDs remain unchanged. New actions never reuse a removed ID;
the monotonic plan revision supplies an allocation high-water mark without
changing version 1 of the schema. IDs and revisions may therefore have gaps.
This also handles imported plans with action IDs greater than their revision.
These guarantees assume plans are edited through the CLI; manually resetting a
revision or rewriting historical IDs can discard that history.

The old flat `plan add` command is rejected. There is no compatibility alias in
this initial planning version. Use `plan action --help` or help on any action
subcommand to inspect the supported arguments.

## JSON, files, and stdin

`plan action add` accepts either all three explicit `--source`, `--destination`, and
`--reason` values, or a JSON request through `--input`. Mixing forms is an error.

```powershell
cargo run -- plan action add --plan-file example.plan.json --input '@examples/move-request.json'
Get-Content -Raw examples/move-request.json | cargo run -- plan action add --plan-file example.plan.json --input -
cargo run -- plan show --plan-file '@example.plan.json'
Get-Content -Raw example.plan.json | cargo run -- plan dry-run --plan-file -
```

`--input` also accepts literal JSON. JSON input is UTF-8 and limited to 16 MiB.
Write commands require a literal plan path; stdin and `@file` only select read
inputs. All stored action paths are absolute. Unknown fields and operations,
unsupported versions, missing reasons and duplicate action IDs are rejected.
See [version 1 schema](schemas/move-plan-v1.schema.json).

## What dry-run checks

Dry-run checks filesystem metadata and then simulates each valid action in order.
It finds absent sources, occupied exact destinations, duplicate use of a source,
missing destination parents, unsafe directory containment, and actions containing
their own plan file. A chain `A -> B`, then `B -> C` is valid even when `B` does
not yet exist. Moving an occupied destination away first makes that path available
for a later action. The report lists earlier action IDs on which each action
relies. Invalid actions are not inserted into the simulated state.

Every completed dry-run emits its structured report and exits successfully,
including reports with `ready: false`. Read `ready` and each action's `issues`
to understand the planning outcome. Unrecoverable errors, including malformed
or unsupported plan JSON, command parsing failures, and failed output writes,
propagate through `eyre` and produce a nonzero exit. There is no domain-specific
exit-code taxonomy. Human diagnostics remain on stderr when stdout is JSON;
selecting JSON does not suppress them. Help and version exit successfully.
`teamy-mover src.txt dest.txt` and misspelled
subcommands are errors. There is no root positional shorthand.

Dry-run does not lock or hash source files, walk full directory contents, verify
available space or permissions, or guarantee a later move could succeed. Source
metadata can change immediately after inspection. Cross-volume moves, hard-link
identity, Windows case-sensitive directories, Unicode case aliases and short-name
aliases need further design before an executor is built. Symlinks and Windows
reparse points are conservatively rejected. `policy_reference` is descriptive
metadata; it does not authenticate a human or constrain an agent.

## Plan metadata durability

Creation uses exclusive create and never overwrites an existing plan. Action edits acquire
an exclusive sidecar `.lock`, retains the prior JSON as
`<plan-file>.revision-<revision>.json`, writes and syncs a same-directory pending
file, and replaces only the plan JSON. Concurrent action edits fail on the lock.

After an interruption, inspect any remaining `.lock`, `.pending-*.json`, and
revision files before retrying. A stale lock or occupied revision sidecar causes
an error. This version does not automatically recover them. Source and
destination data are unrelated to these metadata writes and are never changed.
Keep plan metadata outside source trees. Plan JSON can disclose private filenames
and paths: keep real plans outside public source control. This repository ignores
`.local-plans/` for that purpose. Do not place valuable scratch material in build
output or other disposable directories.

## Output and shared infrastructure

Output defaults to text in an interactive terminal and JSON when redirected.
Select `--output-format text`, `json`, `html`, or `csv` explicitly. HTML is a
self-contained escaped report; CSV is useful for simple summaries and may reject
nested plan structures. Logging goes to stderr. The inherited `--log-file` option is omitted so
read-only commands cannot create or overwrite log files. `--help`, nested `--help`,
`--version`, completions and cooperative cancellation are provided by the retained
template infrastructure. Version output includes package version, source URL,
branch, revision, worktree state and build timestamp.

This project retains the Facet/Figue cohort, tracing, Windows resources,
CLI roundtrip fuzz tests and cancellation from the
[teamy-rust-cli template](https://github.com/TeamDman/teamy-rust-cli). The example
home/cache/init command groups are replaced by the planning surface. Each completed
command returns an explicit runtime budget, separate from its serialized result;
see [completion budgets](docs/command-completion-budgets.md).

Cancellation uses the pinned `teamy-cancellation` library. Ctrl+C, an optional
`--stop-after-duration`, or a configured tracing trigger requests cancellation.
The CLI checks that request at command entry and before/after output. It does
not currently poll inside synchronous plan reads, filesystem metadata loops or
metadata updates, so these operations can finish before the request is noticed.
An update completed before cancellation is not rolled back. Repeated Ctrl+C can
force termination and bypass normal cleanup; inspect any remaining lock or
pending revision files before retrying. Cancellation is not resumable execution.

## Develop

```powershell
./check-all.ps1
```

The gate runs formatting, all-feature lint/build, and tests without activating
Tracy transport during tests. Profiling is opt-in through
`./run-profiler.ps1 plan list`. Build output goes to the ignored `target/` folder.
This project is MPL-2.0 licensed.

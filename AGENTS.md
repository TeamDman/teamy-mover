Each subcommand must have its own directory module.
Each subcommand implementation must live in a new `{}_{}_{}_cli.rs` file that `mod.rs` re-exports to ensure fuzzy finders can find the file easily.

This repository currently implements planning only. Do not add an executor,
source cleanup, implicit destination creation, positional move shorthand, or
arbitrary command actions without a separately reviewed design.

Dry-run must leave source/destination objects and plan JSON unchanged. Test with
synthetic fixtures only. Actual plans contain private absolute paths and belong
outside public source control. Every persisted plan starts with an explicit
version; unsupported versions and unknown fields must fail closed.

Keep earlier plan revisions when editing metadata. A successful dry-run is not
approval and is not an integrity, access-control, or recovery guarantee. The
policy reference field is descriptive and does not establish a human identity.

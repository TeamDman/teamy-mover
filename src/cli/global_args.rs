//! Global arguments that apply to all commands.

use crate::cli::output::OutputFormat;
use arbitrary::Arbitrary;
use facet::Facet;
use figue::{self as args};
use teamy_cancellation::StopAfterArgs;

/// Global arguments that apply to all commands.
#[derive(Facet, Arbitrary, Debug, Default, PartialEq)]
#[facet(rename_all = "kebab-case")]
pub struct GlobalArgs {
    /// Enable debug logging, including backtraces on panics.
    #[facet(args::named, default)]
    pub debug: bool,

    /// Log level filter directive.
    #[facet(args::named)]
    #[arbitrary(default)]
    pub log_filter: Option<String>,

    /// Request graceful cancellation from tracing/Tracy spans, log messages, or elapsed time.
    #[facet(flatten, default)]
    #[arbitrary(default)]
    pub stop_after: StopAfterArgs,

    /// Render command output as text, json, csv, or self-contained html.
    ///
    /// If omitted, the generated CLI uses `text` for interactive terminals and
    /// `json` when stdout is redirected.
    #[facet(args::named)]
    #[arbitrary(default)]
    pub output_format: Option<OutputFormat>,
}

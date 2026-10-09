#![deny(clippy::disallowed_methods)]
#![deny(clippy::disallowed_macros)]

pub mod cli;
mod elapsed_duration;
pub mod logging_init;
pub mod planning;
#[cfg(windows)]
mod windows_startup;

use crate::cli::Cli;
use chrono::DateTime;
use chrono::Local;
use chrono::Utc;
use teamy_cancellation::CtrlCHandler;

/// Version string combining package version, git repository metadata, and build time.
fn version() -> String {
    let built_at = option_env!("BUILD_TIMESTAMP_UNIX")
        .and_then(|value| value.parse::<i64>().ok())
        .and_then(|timestamp| DateTime::<Utc>::from_timestamp(timestamp, 0))
        .map_or_else(
            || "unknown build time".to_string(),
            |timestamp| {
                timestamp
                    .with_timezone(&Local)
                    .format("%Y-%m-%d %H:%M:%S %Z")
                    .to_string()
            },
        );

    format!(
        "{} (repo {}, branch {}, rev {}, worktree {}, built {})",
        env!("CARGO_PKG_VERSION"),
        env!("GIT_REPOSITORY_URL"),
        env!("GIT_BRANCH"),
        env!("GIT_REVISION"),
        env!("GIT_WORKTREE_STATUS"),
        built_at,
    )
}

/// Entrypoint for the program.
///
/// # Errors
///
/// This function will return an error if `color_eyre` installation, CLI parsing, logging initialization, command execution, or command output rendering fails.
///
pub fn main() -> eyre::Result<()> {
    // Install color_eyre for better error reports
    color_eyre::install()?;
    let cancellation_token = CtrlCHandler::default().install()?;

    #[cfg(windows)]
    {
        // Enable ANSI support on Windows
        // This fails in a pipe scenario, so we ignore the error
        let _ = windows_startup::enable_ansi_support();

        // Warn if UTF-8 is not enabled on Windows
        #[cfg(windows)]
        windows_startup::warn_if_utf8_not_enabled();
    };

    // Parse command line arguments using figue
    // This pinned Figue cohort labels missing required CLI arguments as Help.
    // Distinguish its corrected-usage suggestion from an explicit help request.
    let version = version();

    let outcome = figue::Driver::new(
        figue::builder::<Cli>()
            .map_err(|error| eyre::eyre!("failed to build CLI schema: {error}"))?
            .cli(move |cli| cli.args_os(std::env::args_os().skip(1)).strict())
            .help(move |help| {
                help.version(version)
                    .include_implementation_source_file(true)
            })
            .build(),
    )
    .run();
    let cli: Cli = match outcome.into_result() {
        Ok(output) => output.value,
        Err(figue::DriverError::Help {
            text,
            suggestion: Some(suggestion),
        }) => {
            return Err(eyre::eyre!(
                "missing required command arguments\n{text}\n{}",
                suggestion.render_pretty()
            ));
        }
        Err(figue::DriverError::Failed { report }) => {
            return Err(eyre::eyre!("{}", report.render_pretty()));
        }
        Err(error) if !error.is_success() => return Err(eyre::eyre!("{error}")),
        Err(error) => figue::DriverOutcome::err(error).unwrap(),
    };

    let _stop_after_duration_thread = cli
        .global_args
        .stop_after
        .start_stop_after_duration_thread(cancellation_token.clone())?;

    // Initialize logging
    logging_init::init_logging(&cli.global_args, cancellation_token.clone())?;

    // Invoke whatever command was requested and render its output once at the top level
    let requested_output_format = cli.global_args.output_format;
    let command_name = cli.command.name();
    tracing::debug!(command = command_name, "Dispatching command");
    let result = (|| -> eyre::Result<()> {
        let _command_span = tracing::info_span!("command", command = command_name).entered();
        let started = std::time::Instant::now();
        let output = cli.invoke(cancellation_token.clone())?;
        let threshold = output.elapsed_duration_warn_threshold;
        let emitted = cancellation_token
            .bail_if_cancelled()
            .and_then(|()| output.emit(requested_output_format));
        elapsed_duration::warn_if_exceeded(command_name, started.elapsed(), threshold);
        emitted?;
        cancellation_token.bail_if_cancelled()?;
        Ok(())
    })();
    tracing::debug!(
        command = command_name,
        success = result.is_ok(),
        "Command finished"
    );
    result
}

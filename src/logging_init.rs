use crate::cli::global_args::GlobalArgs;
use eyre::bail;
use teamy_cancellation::CancellationToken;
use tracing::Metadata;
use tracing::debug;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Registry;
use tracing_subscriber::filter::FilterExt;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::prelude::*;
use tracing_subscriber::util::SubscriberInitExt;

fn exclude_tracy_frame_mark(meta: &Metadata<'_>) -> bool {
    meta.fields().field("tracy.frame_mark").is_none()
}

fn default_log_filter(global_args: &GlobalArgs) -> eyre::Result<EnvFilter> {
    if let Some(filter) = global_args.log_filter.as_ref() {
        if global_args.debug {
            bail!("cannot specify log filter with --debug");
        }
        return EnvFilter::builder().parse(filter).map_err(Into::into);
    }

    let own_level = if global_args.debug { "debug" } else { "info" };
    EnvFilter::builder()
        .parse(format!("warn,teamy_mover={own_level}"))
        .map_err(Into::into)
}

#[cfg(any(feature = "tracy", test))]
fn tracy_log_filter_directives() -> [&'static str; 7] {
    [
        "trace",
        "cranelift_codegen=warn",
        "cranelift_frontend=warn",
        "cranelift_jit=warn",
        "cranelift_native=warn",
        "regalloc2=warn",
        "wasmtime=warn",
    ]
}

#[cfg(all(feature = "tracy", not(test)))]
fn tracy_log_filter() -> eyre::Result<EnvFilter> {
    EnvFilter::builder()
        .parse(tracy_log_filter_directives().join(","))
        .map_err(Into::into)
}

/// Initialize logging based on the provided configuration.
///
/// # Errors
///
/// This function will return an error if the tracing filter is invalid.
pub fn init_logging(
    global_args: &GlobalArgs,
    cancellation_token: CancellationToken,
) -> eyre::Result<()> {
    let subscriber = Registry::default();

    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_file(cfg!(debug_assertions))
        .with_line_number(cfg!(debug_assertions))
        .with_target(true)
        .with_writer(std::io::stderr)
        .pretty()
        .without_time()
        .with_filter(default_log_filter(global_args)?.and(filter_fn(exclude_tracy_frame_mark)));
    let subscriber = subscriber.with(stderr_layer);
    let subscriber = subscriber.with(
        global_args
            .stop_after
            .stop_after_span_layer(cancellation_token),
    );

    #[cfg(all(feature = "tracy", not(test)))]
    let subscriber =
        subscriber.with(tracing_tracy::TracyLayer::default().with_filter(tracy_log_filter()?));

    if let Err(error) = subscriber.try_init() {
        eprintln!(
            "Failed to initialize tracing subscriber - are you running `cargo test`? If so, multiple test entrypoints may be running from the same process. https://github.com/tokio-rs/console/issues/505 : {error}"
        );
        return Ok(());
    }

    #[cfg(all(feature = "tracy", not(test)))]
    tracing::info!(
        "Tracy profiling layer added, memory usage will increase until a client is connected"
    );

    debug!(debug = global_args.debug, "Tracing initialized");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_log_filter_does_not_change_tracy_trace_filter() {
        let global_args = GlobalArgs {
            log_filter: Some(String::from("error")),
            ..GlobalArgs::default()
        };

        default_log_filter(&global_args).expect("human log filter should parse");
        assert_eq!(tracy_log_filter_directives()[0], "trace");
    }
}

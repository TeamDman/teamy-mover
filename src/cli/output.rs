use arbitrary::Arbitrary;
use eyre::Context;
use facet::Facet;
use facet_pretty::ColorMode;
use facet_pretty::PrettyPrinter;
use std::io::IsTerminal;
use std::io::Write;
use std::io::{self};

#[derive(Arbitrary, Facet, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[facet(rename_all = "kebab-case")]
#[repr(u8)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Csv,
    Html,
}

pub struct CliOutput {
    value: Option<Box<dyn CliOutputValue>>,
    pub elapsed_duration_warn_threshold: Option<std::time::Duration>,
}

impl core::fmt::Debug for CliOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CliOutput")
            .field("has_value", &self.value.is_some())
            .field(
                "elapsed_duration_warn_threshold",
                &self.elapsed_duration_warn_threshold,
            )
            .finish()
    }
}

trait CliOutputValue {
    fn render(
        &self,
        format: OutputFormat,
        stdout_is_terminal: bool,
    ) -> eyre::Result<Option<String>>;
}

struct FacetCliOutput<T> {
    value: T,
}

impl CliOutput {
    #[must_use]
    pub const fn none(elapsed_duration_warn_threshold: Option<std::time::Duration>) -> Self {
        Self {
            value: None,
            elapsed_duration_warn_threshold,
        }
    }

    #[must_use]
    pub fn facet<T>(value: T, elapsed_duration_warn_threshold: Option<std::time::Duration>) -> Self
    where
        T: Facet<'static> + 'static,
    {
        Self {
            value: Some(Box::new(FacetCliOutput { value })),
            elapsed_duration_warn_threshold,
        }
    }

    /// # Errors
    ///
    /// This function will return an error if the selected output format cannot be rendered
    /// or if the rendered output cannot be written to stdout.
    pub fn emit(self, requested_format: Option<OutputFormat>) -> eyre::Result<()> {
        let Some(output) = self.value else {
            return Ok(());
        };

        let stdout_is_terminal = io::stdout().is_terminal();
        let format = requested_format.unwrap_or(if stdout_is_terminal {
            OutputFormat::Text
        } else {
            OutputFormat::Json
        });
        let Some(rendered) = output.render(format, stdout_is_terminal)? else {
            return Ok(());
        };

        let mut stdout = io::stdout().lock();
        stdout
            .write_all(rendered.as_bytes())
            .wrap_err("failed to write command output")?;
        if !rendered.ends_with('\n') {
            stdout
                .write_all(b"\n")
                .wrap_err("failed to terminate command output")?;
        }
        stdout.flush().wrap_err("failed to flush command output")?;
        Ok(())
    }
}

impl<T> CliOutputValue for FacetCliOutput<T>
where
    T: Facet<'static> + 'static,
{
    fn render(
        &self,
        format: OutputFormat,
        stdout_is_terminal: bool,
    ) -> eyre::Result<Option<String>> {
        let rendered = match format {
            OutputFormat::Text => PrettyPrinter::new()
                .with_colors(if stdout_is_terminal {
                    ColorMode::Always
                } else {
                    ColorMode::Never
                })
                .format(&self.value),
            OutputFormat::Json => facet_json::to_string_pretty(&self.value)
                .wrap_err("failed to serialize command output as JSON")?,
            OutputFormat::Csv => facet_csv::to_string(&self.value)
                .wrap_err("failed to serialize command output as CSV")?,
            OutputFormat::Html => {
                let json = facet_json::to_string_pretty(&self.value)
                    .wrap_err("failed to serialize HTML report")?;
                let escaped = json
                    .replace('&', "&amp;")
                    .replace('<', "&lt;")
                    .replace('>', "&gt;");
                format!(
                    "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>Teamy Mover planning report</title><style>body{{font:16px system-ui;max-width:1000px;margin:2rem auto;padding:0 1rem}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.5;background:#f3f5f7;padding:1rem}}h1{{font-size:1.7rem}}</style><h1>Teamy Mover planning report</h1><p>Planning output. No move has been executed.</p><pre>{escaped}</pre></html>"
                )
            }
        };
        Ok(Some(rendered))
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;
    #[derive(Facet)]
    struct Fixture {
        count: u32,
    }
    #[test]
    fn budget_is_not_serialized() {
        for threshold in [None, Some(std::time::Duration::from_secs(1))] {
            let output = CliOutput::facet(Fixture { count: 7 }, threshold);
            assert_eq!(output.elapsed_duration_warn_threshold, threshold);
            let json = output
                .value
                .unwrap()
                .render(OutputFormat::Json, false)
                .unwrap()
                .unwrap();
            assert_eq!(json, "{\n  \"count\": 7\n}");
        }
        assert!(CliOutput::none(None).value.is_none());
    }
}

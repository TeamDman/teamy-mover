use std::time::Duration;

/// Check a returned completion budget. This is not a watchdog and never changes the result.
pub fn warn_if_exceeded(command: &str, elapsed: Duration, threshold: Option<Duration>) {
    if let Some(threshold) = threshold.filter(|threshold| elapsed > *threshold) {
        tracing::warn!(
            command,
            elapsed_duration_ms = elapsed.as_secs_f64() * 1000.0,
            elapsed_duration_warn_threshold_ms = threshold.as_secs_f64() * 1000.0,
            "Command exceeded its elapsed duration budget"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Mutex;
    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn warns_only_above_the_budget_and_exemption_is_explicit() {
        for (elapsed, threshold, warned) in [
            (9, Some(10), false),
            (10, Some(10), false),
            (11, Some(10), true),
            (11, None, false),
        ] {
            let bytes = Arc::new(Mutex::new(Vec::new()));
            let writer = Capture(Arc::clone(&bytes));
            let subscriber = tracing_subscriber::fmt()
                .without_time()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, || {
                warn_if_exceeded(
                    "fixture",
                    Duration::from_millis(elapsed),
                    threshold.map(Duration::from_millis),
                );
            });
            let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
            assert_eq!(output.contains("Command exceeded"), warned);
            if warned {
                assert!(output.contains("elapsed_duration_ms=11"));
                assert!(output.contains("elapsed_duration_warn_threshold_ms=10"));
            }
        }
    }
}

/// Stdin is user-interactive; local plans allow parsing per KiB plus per-action work.
pub fn plan_budget(input: &str, units: usize, unit_ms: u64) -> Option<Duration> {
    if input == "-" {
        return None;
    }
    let bytes = std::fs::metadata(input.strip_prefix('@').unwrap_or(input)).map_or(0, |m| m.len());
    Some(
        Duration::from_secs(3)
            .saturating_add(Duration::from_millis(bytes / 1024))
            .saturating_add(
                Duration::from_millis(unit_ms).saturating_mul(units.try_into().unwrap_or(u32::MAX)),
            ),
    )
}

#[cfg(test)]
mod plan_budget_tests {
    use super::*;
    #[test]
    fn local_work_scales_and_stdin_is_interactive() {
        assert_eq!(plan_budget("-", 10, 20), None);
        assert_eq!(
            plan_budget("synthetic-missing-plan", 2, 20),
            Some(Duration::from_millis(3040))
        );
    }
}

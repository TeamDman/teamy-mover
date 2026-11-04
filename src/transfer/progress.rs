//! Rate-limit transfer progress without exposing paths, contents or credentials.

use std::time::{Duration, Instant};

const REPORT_INTERVAL: Duration = Duration::from_secs(5);

/// Counts only bytes explicitly acknowledged by the local caller. A report is
/// emitted on a subsequent advance, so this is not a stalled-I/O watchdog.
pub(super) struct Progress {
    bytes: u64,
    last_report: Instant,
}

impl Progress {
    pub(super) const fn new(now: Instant) -> Self {
        Self {
            bytes: 0,
            last_report: now,
        }
    }

    pub(super) fn advance(&mut self, bytes: u64, now: Instant) -> Option<u64> {
        self.bytes = self.bytes.saturating_add(bytes);
        if now.saturating_duration_since(self.last_report) < REPORT_INTERVAL {
            return None;
        }
        self.last_report = now;
        Some(self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_bytes_and_rate_limits_reports_without_fabricating_progress() {
        let start = Instant::now();
        let mut progress = Progress::new(start);
        assert_eq!(progress.advance(10, start + Duration::from_secs(4)), None);
        assert_eq!(
            progress.advance(20, start + Duration::from_secs(5)),
            Some(30)
        );
        assert_eq!(progress.advance(5, start + Duration::from_secs(9)), None);
        assert_eq!(
            progress.advance(7, start + Duration::from_secs(10)),
            Some(42)
        );
    }
}

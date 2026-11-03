//! A single-flight guard for blocking I/O with uncertain cancellation.
//!
//! Timing out cannot cancel a kernel call. The closure retains its owned
//! handles, and the gate becomes permanently poisoned so no second operation
//! can race it. Late completion must be recovered by a separate inspection.
//! The caller must retain one gate for the resource and ensure handles cannot
//! be used through another gate. This does not establish filesystem isolation.

use eyre::Result;
use eyre::ensure;
use std::sync::Arc;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;
use std::time::Duration;

const IDLE: u8 = 0;
const ACTIVE: u8 = 1;
const POISONED: u8 = 2;

/// Single-flight gate that requires recovery after an uncertain I/O outcome.
#[derive(Clone, Debug, Default)]
pub struct BlockingIoGate(Arc<AtomicU8>);

struct Flight {
    state: Arc<AtomicU8>,
    success: bool,
}

impl Drop for Flight {
    fn drop(&mut self) {
        self.state.store(
            if self.success { IDLE } else { POISONED },
            Ordering::Release,
        );
    }
}

impl BlockingIoGate {
    /// A worker checks this between blocking operations. Cancellation cannot
    /// interrupt an operation that already entered the operating system.
    pub(crate) fn ensure_active(&self) -> Result<()> {
        ensure!(
            self.0.load(Ordering::Acquire) == ACTIVE,
            "blocking I/O was cancelled or requires recovery"
        );
        Ok(())
    }

    /// Run one blocking operation. A timeout, cancellation, panic, or I/O error
    /// poisons the gate permanently; the closure may still own resources until
    /// its operating-system call returns. This does not cancel the kernel call.
    ///
    /// # Errors
    /// Returns an error if busy, poisoned, timed out, or the operation fails.
    pub async fn run<T, F>(&self, deadline: Duration, work: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        ensure!(!deadline.is_zero(), "blocking I/O deadline expired");
        let expires = std::time::Instant::now()
            .checked_add(deadline)
            .ok_or_else(|| eyre::eyre!("blocking I/O deadline overflow"))?;
        ensure!(
            self.0
                .compare_exchange(IDLE, ACTIVE, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            "blocking I/O is busy or requires recovery"
        );
        let mut flight = Flight {
            state: Arc::clone(&self.0),
            success: false,
        };
        let result = tokio::time::timeout(deadline, tokio::task::spawn_blocking(work)).await??;
        let value = result?;
        ensure!(
            std::time::Instant::now() < expires,
            "blocking I/O deadline expired"
        );
        flight.success = true;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn timed_out_work_keeps_its_handle_and_poisoned_gate() {
        let gate = BlockingIoGate::default();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synthetic");
        let file = std::fs::File::create(&path).unwrap();
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (started, started_rx) = tokio::sync::oneshot::channel::<()>();
        let (finished, finished_rx) = tokio::sync::oneshot::channel::<()>();
        let task_gate = gate.clone();
        let task = tokio::spawn(async move {
            task_gate
                .run(Duration::from_millis(200), move || {
                    let _sent = started.send(());
                    wait.recv()?;
                    file.sync_all()?;
                    let _sent = finished.send(());
                    Ok(())
                })
                .await
        });
        started_rx.await.unwrap();
        let result = task.await.unwrap();
        assert!(result.is_err());
        assert!(gate.run(Duration::from_secs(1), || Ok(())).await.is_err());
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), finished_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(gate.run(Duration::from_secs(1), || Ok(())).await.is_err());
    }

    #[tokio::test]
    async fn successful_work_releases_gate_but_failure_poisoning_is_sticky() {
        let gate = BlockingIoGate::default();
        assert_eq!(gate.run(Duration::from_secs(1), || Ok(7)).await.unwrap(), 7);
        assert!(
            gate.run(Duration::from_secs(1), || -> Result<()> {
                Err(eyre::eyre!("synthetic failure"))
            })
            .await
            .is_err()
        );
        assert!(gate.run(Duration::from_secs(1), || Ok(())).await.is_err());
    }

    #[tokio::test]
    async fn cancelled_waiter_poisoning_prevents_an_overlapping_operation() {
        let gate = BlockingIoGate::default();
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (started, started_rx) = tokio::sync::oneshot::channel::<()>();
        let (finished, finished_rx) = tokio::sync::oneshot::channel::<()>();
        let task_gate = gate.clone();
        let task = tokio::spawn(async move {
            task_gate
                .run(Duration::from_secs(5), move || {
                    let _sent = started.send(());
                    wait.recv()?;
                    let _sent = finished.send(());
                    Ok(())
                })
                .await
        });
        started_rx.await.unwrap();
        task.abort();
        let _cancelled = task.await.unwrap_err();
        assert!(gate.run(Duration::from_secs(1), || Ok(())).await.is_err());
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), finished_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(gate.run(Duration::from_secs(1), || Ok(())).await.is_err());
    }

    #[tokio::test]
    async fn concurrent_attempt_is_rejected_while_first_operation_is_active() {
        let gate = BlockingIoGate::default();
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (started, started_rx) = tokio::sync::oneshot::channel::<()>();
        let task_gate = gate.clone();
        let task = tokio::spawn(async move {
            task_gate
                .run(Duration::from_secs(5), move || {
                    let _sent = started.send(());
                    wait.recv()?;
                    Ok(())
                })
                .await
        });
        started_rx.await.unwrap();
        assert!(gate.run(Duration::from_secs(1), || Ok(())).await.is_err());
        release.send(()).unwrap();
        task.await.unwrap().unwrap();
        gate.run(Duration::from_secs(1), || Ok(())).await.unwrap();
    }
}

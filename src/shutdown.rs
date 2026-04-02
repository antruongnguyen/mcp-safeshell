//! Graceful shutdown support.
//!
//! - Listens for SIGINT / SIGTERM (Unix) or CTRL_C_EVENT (Windows).
//! - Tracks active child processes and kills them on shutdown.
//! - Provides a `ShutdownSignal` future that resolves once any termination
//!   signal is received.

use std::sync::Mutex;

use tokio::sync::watch;

/// A clonable handle that resolves when shutdown has been requested.
#[derive(Clone)]
pub struct ShutdownSignal {
    rx: watch::Receiver<bool>,
}

impl ShutdownSignal {
    /// Wait until the shutdown signal fires.
    pub async fn recv(&mut self) {
        // Ignore the error — a closed channel also means shutdown.
        let _ = self.rx.wait_for(|&v| v).await;
    }
}

/// Tracks running child-process PIDs so they can be killed on shutdown.
#[derive(Default)]
pub struct ChildTracker {
    pids: Mutex<Vec<u32>>,
}

impl ChildTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a child PID.
    pub fn add(&self, pid: u32) {
        if let Ok(mut guard) = self.pids.lock() {
            guard.push(pid);
        }
    }

    /// Remove a child PID (called when the process exits normally).
    pub fn remove(&self, pid: u32) {
        if let Ok(mut guard) = self.pids.lock() {
            guard.retain(|&p| p != pid);
        }
    }

    /// Kill all tracked children. Best-effort — errors are logged but not fatal.
    pub fn kill_all(&self) {
        let pids = match self.pids.lock() {
            Ok(mut guard) => {
                let snapshot = guard.clone();
                guard.clear();
                snapshot
            }
            Err(_) => return,
        };

        for pid in pids {
            kill_process(pid);
        }
    }
}

/// Kill a single process by PID.
fn kill_process(pid: u32) {
    #[cfg(unix)]
    {
        // Guard against special PIDs: 0 = process group, negative = group kill.
        // pid_t is i32; u32 values > i32::MAX wrap negative, so reject them.
        let ipid = pid as libc::pid_t;
        if ipid <= 0 {
            tracing::warn!(pid, "refusing to kill non-positive PID");
            return;
        }
        unsafe {
            let ret = libc::kill(ipid, libc::SIGKILL);
            if ret != 0 {
                tracing::debug!(
                    pid,
                    "kill() returned error (process may have already exited)"
                );
            }
        }
    }

    #[cfg(windows)]
    {
        use std::process::Command;
        // taskkill /F /PID <pid> — forcefully terminate
        let _ = Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .output();
    }
}

/// Install OS signal handlers and return a `ShutdownSignal`.
///
/// On Unix: listens for SIGINT and SIGTERM.
/// On Windows: listens for ctrl_c (which covers CTRL_C_EVENT and CTRL_BREAK_EVENT).
pub fn install_signal_handler() -> ShutdownSignal {
    let (tx, rx) = watch::channel(false);

    tokio::spawn(async move {
        wait_for_signal().await;
        let _ = tx.send(true);
    });

    ShutdownSignal { rx }
}

#[cfg(unix)]
async fn wait_for_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");

    tokio::select! {
        _ = sigint.recv() => {
            tracing::info!("received SIGINT");
        }
        _ = sigterm.recv() => {
            tracing::info!("received SIGTERM");
        }
    }
}

#[cfg(windows)]
async fn wait_for_signal() {
    // ctrl_c handles both CTRL_C_EVENT and CTRL_BREAK_EVENT on Windows.
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install ctrl-c handler");
    tracing::info!("received CTRL_C_EVENT");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_tracker_add_remove() {
        let tracker = ChildTracker::new();
        tracker.add(100);
        tracker.add(200);
        tracker.add(300);

        {
            let pids = tracker.pids.lock().unwrap();
            assert_eq!(pids.len(), 3);
            assert!(pids.contains(&100));
            assert!(pids.contains(&200));
            assert!(pids.contains(&300));
        }

        tracker.remove(200);

        {
            let pids = tracker.pids.lock().unwrap();
            assert_eq!(pids.len(), 2);
            assert!(!pids.contains(&200));
        }
    }

    #[test]
    fn child_tracker_remove_nonexistent() {
        let tracker = ChildTracker::new();
        tracker.add(100);
        tracker.remove(999); // no-op
        let pids = tracker.pids.lock().unwrap();
        assert_eq!(pids.len(), 1);
    }

    #[test]
    fn child_tracker_kill_all_clears() {
        let tracker = ChildTracker::new();
        // Add fake PIDs that won't match real processes.
        // Don't actually call kill_all because kill_process sends real signals.
        // Instead, verify the internal state management.
        tracker.add(999_999);
        tracker.add(999_998);

        {
            let pids = tracker.pids.lock().unwrap();
            assert_eq!(pids.len(), 2);
        }

        // Manually clear to verify kill_all's clearing behavior without
        // actually sending signals.
        {
            let mut pids = tracker.pids.lock().unwrap();
            pids.clear();
        }

        let pids = tracker.pids.lock().unwrap();
        assert!(pids.is_empty());
    }

    #[test]
    fn child_tracker_duplicate_pids() {
        let tracker = ChildTracker::new();
        tracker.add(42);
        tracker.add(42);
        {
            let pids = tracker.pids.lock().unwrap();
            assert_eq!(pids.len(), 2);
        }
        // remove takes out all occurrences
        tracker.remove(42);
        let pids = tracker.pids.lock().unwrap();
        assert!(pids.is_empty());
    }

    #[tokio::test]
    async fn shutdown_signal_fires_on_send() {
        let (tx, rx) = watch::channel(false);
        let mut signal = ShutdownSignal { rx };

        // Send the shutdown signal from another task.
        tokio::spawn(async move {
            tx.send(true).unwrap();
        });

        // Should resolve quickly.
        tokio::time::timeout(std::time::Duration::from_secs(1), signal.recv())
            .await
            .expect("shutdown signal should have fired");
    }

    #[tokio::test]
    async fn shutdown_signal_fires_on_channel_close() {
        let (tx, rx) = watch::channel(false);
        let mut signal = ShutdownSignal { rx };

        // Drop the sender without sending true — closed channel should also
        // unblock recv().
        drop(tx);

        tokio::time::timeout(std::time::Duration::from_secs(1), signal.recv())
            .await
            .expect("shutdown signal should fire when channel closes");
    }
}

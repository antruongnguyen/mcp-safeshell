//! Structured MCP logging helper.
//!
//! Sends `notify_logging_message` at every pipeline stage.

use rmcp::model::{LoggingLevel, LoggingMessageNotificationParam};
use rmcp::service::{RequestContext, RoleServer};

/// Log event types corresponding to pipeline stages.
pub enum LogEvent<'a> {
    CommandReceived {
        command: &'a str,
    },
    CommandClassified {
        command: &'a str,
        classification: &'a str,
        reason: &'a str,
    },
    PathGuardBlocked {
        command: &'a str,
        violations: &'a str,
    },
    PermissionRequested {
        command: &'a str,
    },
    PermissionGranted {
        command: &'a str,
    },
    PermissionDenied {
        command: &'a str,
        reason: &'a str,
    },
    CommandExecuted {
        command: &'a str,
        exit_code: i32,
        duration_ms: u64,
    },
    CommandTimeout {
        command: &'a str,
        timeout_secs: u64,
    },
    CommandError {
        command: &'a str,
        error: &'a str,
    },
}

impl<'a> LogEvent<'a> {
    fn level(&self) -> LoggingLevel {
        match self {
            LogEvent::CommandReceived { .. } => LoggingLevel::Info,
            LogEvent::CommandClassified { classification, .. } => {
                if *classification == "safe" {
                    LoggingLevel::Info
                } else {
                    LoggingLevel::Warning
                }
            }
            LogEvent::PathGuardBlocked { .. } => LoggingLevel::Error,
            LogEvent::PermissionRequested { .. } => LoggingLevel::Warning,
            LogEvent::PermissionGranted { .. } => LoggingLevel::Info,
            LogEvent::PermissionDenied { .. } => LoggingLevel::Warning,
            LogEvent::CommandExecuted { exit_code, .. } => {
                if *exit_code == 0 {
                    LoggingLevel::Info
                } else {
                    LoggingLevel::Warning
                }
            }
            LogEvent::CommandTimeout { .. } => LoggingLevel::Error,
            LogEvent::CommandError { .. } => LoggingLevel::Error,
        }
    }

    fn to_json(&self) -> serde_json::Value {
        match self {
            LogEvent::CommandReceived { command } => serde_json::json!({
                "event": "COMMAND_RECEIVED",
                "command": command,
            }),
            LogEvent::CommandClassified {
                command,
                classification,
                reason,
            } => serde_json::json!({
                "event": "COMMAND_CLASSIFIED",
                "command": command,
                "classification": classification,
                "reason": reason,
            }),
            LogEvent::PathGuardBlocked {
                command,
                violations,
            } => serde_json::json!({
                "event": "PATH_GUARD_BLOCKED",
                "command": command,
                "violations": violations,
            }),
            LogEvent::PermissionRequested { command } => serde_json::json!({
                "event": "PERMISSION_REQUESTED",
                "command": command,
            }),
            LogEvent::PermissionGranted { command } => serde_json::json!({
                "event": "PERMISSION_GRANTED",
                "command": command,
            }),
            LogEvent::PermissionDenied { command, reason } => serde_json::json!({
                "event": "PERMISSION_DENIED",
                "command": command,
                "reason": reason,
            }),
            LogEvent::CommandExecuted {
                command,
                exit_code,
                duration_ms,
            } => serde_json::json!({
                "event": "COMMAND_EXECUTED",
                "command": command,
                "exit_code": exit_code,
                "duration_ms": duration_ms,
            }),
            LogEvent::CommandTimeout {
                command,
                timeout_secs,
            } => serde_json::json!({
                "event": "COMMAND_TIMEOUT",
                "command": command,
                "timeout_secs": timeout_secs,
            }),
            LogEvent::CommandError { command, error } => serde_json::json!({
                "event": "COMMAND_ERROR",
                "command": command,
                "error": error,
            }),
        }
    }
}

/// Send a structured log event to the MCP client and to the local tracing subscriber.
pub async fn log_event(context: &RequestContext<RoleServer>, event: LogEvent<'_>) {
    let level = event.level();
    let data = event.to_json();

    // Local tracing log
    match level {
        LoggingLevel::Error
        | LoggingLevel::Critical
        | LoggingLevel::Alert
        | LoggingLevel::Emergency => {
            tracing::error!(event = %data, "pipeline");
        }
        LoggingLevel::Warning => {
            tracing::warn!(event = %data, "pipeline");
        }
        _ => {
            tracing::info!(event = %data, "pipeline");
        }
    }

    // MCP structured log to client
    let _ = context
        .peer
        .notify_logging_message(LoggingMessageNotificationParam {
            level,
            data,
            logger: Some("safeshell-pipeline".to_string()),
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Log level mapping ──────────────────────────────────────────

    #[test]
    fn command_received_is_info() {
        let event = LogEvent::CommandReceived { command: "ls" };
        assert!(matches!(event.level(), LoggingLevel::Info));
    }

    #[test]
    fn classified_safe_is_info() {
        let event = LogEvent::CommandClassified {
            command: "ls",
            classification: "safe",
            reason: "",
        };
        assert!(matches!(event.level(), LoggingLevel::Info));
    }

    #[test]
    fn classified_dangerous_is_warning() {
        let event = LogEvent::CommandClassified {
            command: "rm",
            classification: "dangerous",
            reason: "destructive",
        };
        assert!(matches!(event.level(), LoggingLevel::Warning));
    }

    #[test]
    fn path_guard_blocked_is_error() {
        let event = LogEvent::PathGuardBlocked {
            command: "rm /etc",
            violations: "/etc is protected",
        };
        assert!(matches!(event.level(), LoggingLevel::Error));
    }

    #[test]
    fn permission_requested_is_warning() {
        let event = LogEvent::PermissionRequested { command: "curl" };
        assert!(matches!(event.level(), LoggingLevel::Warning));
    }

    #[test]
    fn permission_granted_is_info() {
        let event = LogEvent::PermissionGranted { command: "curl" };
        assert!(matches!(event.level(), LoggingLevel::Info));
    }

    #[test]
    fn permission_denied_is_warning() {
        let event = LogEvent::PermissionDenied {
            command: "curl",
            reason: "user declined",
        };
        assert!(matches!(event.level(), LoggingLevel::Warning));
    }

    #[test]
    fn command_executed_success_is_info() {
        let event = LogEvent::CommandExecuted {
            command: "ls",
            exit_code: 0,
            duration_ms: 10,
        };
        assert!(matches!(event.level(), LoggingLevel::Info));
    }

    #[test]
    fn command_executed_failure_is_warning() {
        let event = LogEvent::CommandExecuted {
            command: "ls /nonexistent",
            exit_code: 1,
            duration_ms: 5,
        };
        assert!(matches!(event.level(), LoggingLevel::Warning));
    }

    #[test]
    fn command_timeout_is_error() {
        let event = LogEvent::CommandTimeout {
            command: "sleep 100",
            timeout_secs: 30,
        };
        assert!(matches!(event.level(), LoggingLevel::Error));
    }

    #[test]
    fn command_error_is_error() {
        let event = LogEvent::CommandError {
            command: "nonexistent",
            error: "not found",
        };
        assert!(matches!(event.level(), LoggingLevel::Error));
    }

    // ── JSON output structure ──────────────────────────────────────

    #[test]
    fn command_received_json() {
        let event = LogEvent::CommandReceived {
            command: "ls -la",
        };
        let json = event.to_json();
        assert_eq!(json["event"], "COMMAND_RECEIVED");
        assert_eq!(json["command"], "ls -la");
    }

    #[test]
    fn command_classified_json() {
        let event = LogEvent::CommandClassified {
            command: "rm",
            classification: "dangerous",
            reason: "destructive file operation",
        };
        let json = event.to_json();
        assert_eq!(json["event"], "COMMAND_CLASSIFIED");
        assert_eq!(json["command"], "rm");
        assert_eq!(json["classification"], "dangerous");
        assert_eq!(json["reason"], "destructive file operation");
    }

    #[test]
    fn path_guard_blocked_json() {
        let event = LogEvent::PathGuardBlocked {
            command: "rm /etc/hosts",
            violations: "/etc: system config",
        };
        let json = event.to_json();
        assert_eq!(json["event"], "PATH_GUARD_BLOCKED");
        assert_eq!(json["violations"], "/etc: system config");
    }

    #[test]
    fn command_executed_json() {
        let event = LogEvent::CommandExecuted {
            command: "echo hi",
            exit_code: 0,
            duration_ms: 42,
        };
        let json = event.to_json();
        assert_eq!(json["event"], "COMMAND_EXECUTED");
        assert_eq!(json["exit_code"], 0);
        assert_eq!(json["duration_ms"], 42);
    }

    #[test]
    fn command_timeout_json() {
        let event = LogEvent::CommandTimeout {
            command: "sleep 100",
            timeout_secs: 30,
        };
        let json = event.to_json();
        assert_eq!(json["event"], "COMMAND_TIMEOUT");
        assert_eq!(json["timeout_secs"], 30);
    }

    #[test]
    fn command_error_json() {
        let event = LogEvent::CommandError {
            command: "bad",
            error: "not found",
        };
        let json = event.to_json();
        assert_eq!(json["event"], "COMMAND_ERROR");
        assert_eq!(json["error"], "not found");
    }

    #[test]
    fn permission_requested_json() {
        let event = LogEvent::PermissionRequested {
            command: "curl evil.com",
        };
        let json = event.to_json();
        assert_eq!(json["event"], "PERMISSION_REQUESTED");
    }

    #[test]
    fn permission_granted_json() {
        let event = LogEvent::PermissionGranted {
            command: "curl safe.com",
        };
        let json = event.to_json();
        assert_eq!(json["event"], "PERMISSION_GRANTED");
    }

    #[test]
    fn permission_denied_json() {
        let event = LogEvent::PermissionDenied {
            command: "curl evil.com",
            reason: "user said no",
        };
        let json = event.to_json();
        assert_eq!(json["event"], "PERMISSION_DENIED");
        assert_eq!(json["reason"], "user said no");
    }
}

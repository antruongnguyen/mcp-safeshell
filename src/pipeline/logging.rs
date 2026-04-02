//! Structured MCP logging helper.
//!
//! Sends `notify_logging_message` at every pipeline stage.

use rmcp::model::{LoggingLevel, LoggingMessageNotificationParam};
use rmcp::service::{RequestContext, RoleServer};

/// Log event types corresponding to pipeline stages.
pub enum LogEvent<'a> {
    CommandReceived { command: &'a str },
    CommandClassified { command: &'a str, classification: &'a str, reason: &'a str },
    PathGuardBlocked { command: &'a str, violations: &'a str },
    PermissionRequested { command: &'a str },
    PermissionGranted { command: &'a str },
    PermissionDenied { command: &'a str, reason: &'a str },
    CommandExecuted { command: &'a str, exit_code: i32, duration_ms: u64 },
    CommandTimeout { command: &'a str, timeout_secs: u64 },
    CommandError { command: &'a str, error: &'a str },
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
            LogEvent::CommandClassified { command, classification, reason } => serde_json::json!({
                "event": "COMMAND_CLASSIFIED",
                "command": command,
                "classification": classification,
                "reason": reason,
            }),
            LogEvent::PathGuardBlocked { command, violations } => serde_json::json!({
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
            LogEvent::CommandExecuted { command, exit_code, duration_ms } => serde_json::json!({
                "event": "COMMAND_EXECUTED",
                "command": command,
                "exit_code": exit_code,
                "duration_ms": duration_ms,
            }),
            LogEvent::CommandTimeout { command, timeout_secs } => serde_json::json!({
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
        LoggingLevel::Error | LoggingLevel::Critical | LoggingLevel::Alert | LoggingLevel::Emergency => {
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

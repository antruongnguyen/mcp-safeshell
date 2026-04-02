//! SafeShell MCP Server
//!
//! Implements `ServerHandler` with tools:
//! - execute_command: run shell commands through the safety pipeline
//! - get_system_path: expose PATH environment
//! - list_safe_commands: show pre-approved commands for this OS
//! - list_protected_paths: show protected directories for this OS

use std::path::PathBuf;
use std::time::Instant;

use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars::{self, JsonSchema},
    service::{RequestContext, RoleServer},
    tool, tool_handler, tool_router,
};
use serde::Deserialize;

use crate::pipeline::logging::{self, LogEvent};
use crate::pipeline::{classifier, location_guard, parser, permission_gate};
use crate::platform;

// ── Tool input schemas ──────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExecuteCommandRequest {
    #[schemars(description = "The command to run")]
    pub command: String,

    #[schemars(description = "Command arguments")]
    #[serde(default)]
    pub args: Vec<String>,

    #[schemars(description = "Working directory for the command")]
    pub working_directory: Option<String>,

    #[schemars(description = "Maximum execution time in seconds (default: 30)")]
    pub timeout_seconds: Option<u64>,
}

// ── The server ──────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SafeShellServer {
    tool_router: ToolRouter<SafeShellServer>,
}

impl SafeShellServer {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_router]
impl SafeShellServer {
    /// Execute a shell command with safety checks.
    ///
    /// The command flows through the safety pipeline:
    /// Parse → Classify → Guard (Location) → Gate (Permission) → Execute
    #[tool(
        description = "Execute a shell command with safety checks. Commands are classified as safe or dangerous, protected paths are hard-blocked, and dangerous commands require user approval."
    )]
    async fn execute_command(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(req): Parameters<ExecuteCommandRequest>,
    ) -> Result<CallToolResult, McpError> {
        let timeout_secs = req.timeout_seconds.unwrap_or(30);
        let working_dir = req
            .working_directory
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")));

        // Build the full command string for parsing
        let full_command = if req.args.is_empty() {
            req.command.clone()
        } else {
            format!("{} {}", req.command, req.args.join(" "))
        };

        // ── Stage 1: Parse ──
        logging::log_event(
            &context,
            LogEvent::CommandReceived {
                command: &full_command,
            },
        )
        .await;

        let parsed = parser::parse(&full_command, &working_dir);

        // ── Stage 2: Classify ──
        let classification = classifier::classify_all(&parsed.commands);
        let (class_str, class_reason) = match &classification {
            classifier::Classification::Safe => ("safe", String::new()),
            classifier::Classification::Dangerous { reason } => ("dangerous", reason.clone()),
        };

        logging::log_event(
            &context,
            LogEvent::CommandClassified {
                command: &full_command,
                classification: class_str,
                reason: &class_reason,
            },
        )
        .await;

        // ── Stage 3: Location Guard ──
        let guard = location_guard::check_paths(&parsed.commands, &classification);
        if let location_guard::GuardVerdict::Blocked { violations } = &guard {
            let violation_desc: Vec<String> = violations
                .iter()
                .map(|v| {
                    format!(
                        "{} (protected: {}, reason: {})",
                        v.path.display(),
                        v.protected_prefix,
                        v.reason
                    )
                })
                .collect();
            let violations_str = violation_desc.join("; ");

            logging::log_event(
                &context,
                LogEvent::PathGuardBlocked {
                    command: &full_command,
                    violations: &violations_str,
                },
            )
            .await;

            return Ok(CallToolResult::error(vec![Content::text(format!(
                "BLOCKED: Command targets protected path(s):\n{}",
                violation_desc.join("\n")
            ))]));
        }

        // ── Stage 4: Permission Gate (only for dangerous commands) ──
        if let classifier::Classification::Dangerous { reason } = &classification {
            logging::log_event(
                &context,
                LogEvent::PermissionRequested {
                    command: &full_command,
                },
            )
            .await;

            let decision = permission_gate::gate(&context, &full_command, reason).await;

            match &decision {
                permission_gate::GateDecision::Approved => {
                    logging::log_event(
                        &context,
                        LogEvent::PermissionGranted {
                            command: &full_command,
                        },
                    )
                    .await;
                }
                permission_gate::GateDecision::Denied { reason } => {
                    logging::log_event(
                        &context,
                        LogEvent::PermissionDenied {
                            command: &full_command,
                            reason,
                        },
                    )
                    .await;

                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "DENIED: {reason}"
                    ))]));
                }
            }
        }

        // ── Stage 5: Execute ──
        let start = Instant::now();

        let shell = default_shell();
        let shell_flag = shell_flag();

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            tokio::process::Command::new(&shell)
                .arg(shell_flag)
                .arg(&full_command)
                .current_dir(&working_dir)
                .output(),
        )
        .await;

        let duration_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(Ok(output)) => {
                let exit_code = output.status.code().unwrap_or(-1);
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();

                logging::log_event(
                    &context,
                    LogEvent::CommandExecuted {
                        command: &full_command,
                        exit_code,
                        duration_ms,
                    },
                )
                .await;

                let mut parts = vec![Content::text(format!(
                    "Exit code: {exit_code}\nExecution time: {duration_ms}ms"
                ))];

                if !stdout.is_empty() {
                    parts.push(Content::text(format!("stdout:\n{stdout}")));
                }
                if !stderr.is_empty() {
                    parts.push(Content::text(format!("stderr:\n{stderr}")));
                }

                if exit_code == 0 {
                    Ok(CallToolResult::success(parts))
                } else {
                    Ok(CallToolResult::error(parts))
                }
            }
            Ok(Err(e)) => {
                let error_msg = format!("Failed to execute command: {e}");
                logging::log_event(
                    &context,
                    LogEvent::CommandError {
                        command: &full_command,
                        error: &error_msg,
                    },
                )
                .await;

                Ok(CallToolResult::error(vec![Content::text(error_msg)]))
            }
            Err(_) => {
                logging::log_event(
                    &context,
                    LogEvent::CommandTimeout {
                        command: &full_command,
                        timeout_secs,
                    },
                )
                .await;

                Ok(CallToolResult::error(vec![Content::text(format!(
                    "TIMEOUT: Command exceeded {timeout_secs}s limit"
                ))]))
            }
        }
    }

    /// Get the system PATH environment variable.
    #[tool(
        description = "Get the system PATH environment variable, listing all directories where executables are found"
    )]
    fn get_system_path(&self) -> Result<CallToolResult, McpError> {
        let separator = if cfg!(target_os = "windows") {
            ";"
        } else {
            ":"
        };
        let path_var = std::env::var("PATH").unwrap_or_default();
        let entries: Vec<&str> = path_var.split(separator).collect();

        let result = serde_json::json!({
            "path_entries": entries,
            "separator": separator,
            "os": platform::os_name(),
            "arch": platform::arch_name(),
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&result).unwrap_or_default(),
        )]))
    }

    /// List all commands that are pre-approved for the current OS.
    #[tool(
        description = "List all commands that are pre-approved as safe for the current OS. These commands execute without requiring user approval."
    )]
    fn list_safe_commands(&self) -> Result<CallToolResult, McpError> {
        let commands: Vec<serde_json::Value> = platform::safe_commands()
            .iter()
            .map(|sc| {
                serde_json::json!({
                    "name": sc.name,
                    "description": sc.description,
                })
            })
            .collect();

        let result = serde_json::json!({
            "commands": commands,
            "os": platform::os_name(),
            "count": commands.len(),
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&result).unwrap_or_default(),
        )]))
    }

    /// List directories protected from command execution.
    #[tool(
        description = "List directories that are protected from command execution on the current OS. Commands targeting these paths are hard-blocked."
    )]
    fn list_protected_paths(&self) -> Result<CallToolResult, McpError> {
        let paths: Vec<serde_json::Value> = platform::protected_paths()
            .iter()
            .map(|pp| {
                serde_json::json!({
                    "path": pp.path,
                    "read_allowed": pp.read_allowed,
                    "reason": pp.reason,
                })
            })
            .collect();

        let result = serde_json::json!({
            "paths": paths,
            "os": platform::os_name(),
            "count": paths.len(),
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&result).unwrap_or_default(),
        )]))
    }
}

#[tool_handler]
impl ServerHandler for SafeShellServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::default(),
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_logging()
                .build(),
            server_info: Implementation {
                name: "safeshell-mcp".to_string(),
                title: Some("SafeShell MCP Server".to_string()),
                version: env!("CARGO_PKG_VERSION").to_string(),
                description: Some("A safety-first shell command executor MCP server".to_string()),
                icons: None,
                website_url: None,
            },
            instructions: Some(
                "SafeShell MCP Server — a safety-first shell command executor. \
                 Commands are classified as safe or dangerous. Safe commands run immediately. \
                 Dangerous commands require user approval via elicitation. \
                 Protected system paths are hard-blocked and cannot be overridden."
                    .to_string(),
            ),
        }
    }
}

/// Returns the default shell for the current OS.
fn default_shell() -> String {
    #[cfg(target_os = "windows")]
    {
        std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".to_string())
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
    }
}

/// Returns the shell flag for executing a command string.
fn shell_flag() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "/C"
    }
    #[cfg(not(target_os = "windows"))]
    {
        "-c"
    }
}

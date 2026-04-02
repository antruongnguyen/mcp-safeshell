//! SafeShell MCP Server
//!
//! Implements `ServerHandler` with tools:
//! - execute_command: run shell commands through the safety pipeline
//! - get_system_path: expose PATH environment
//! - list_safe_commands: show pre-approved commands for this OS
//! - list_protected_paths: show protected directories for this OS

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
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
use tokio::sync::Semaphore;

use crate::config::Config;
use crate::pipeline::logging::{self, LogEvent};
use crate::pipeline::{classifier, location_guard, parser, permission_gate};
use crate::platform;
use crate::sanitizer::Sanitizer;
use crate::shutdown::ChildTracker;

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
    config: Arc<Config>,
    sanitizer: Arc<Sanitizer>,
    concurrency: Arc<Semaphore>,
    child_tracker: Arc<ChildTracker>,
    tool_router: ToolRouter<SafeShellServer>,
}

impl SafeShellServer {
    #[allow(dead_code)] // Used in tests; main.rs uses with_child_tracker directly
    pub fn new(config: Config) -> Self {
        Self::with_child_tracker(config, Arc::new(ChildTracker::new()))
    }

    pub fn with_child_tracker(config: Config, child_tracker: Arc<ChildTracker>) -> Self {
        let max_conc = config.max_concurrency.max(1);
        let sanitizer = Sanitizer::new(&config.redact_env_patterns);
        Self {
            config: Arc::new(config),
            sanitizer: Arc::new(sanitizer),
            concurrency: Arc::new(Semaphore::new(max_conc)),
            child_tracker,
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_router]
impl SafeShellServer {
    #[tool(
        description = "Execute a shell command with safety checks. Commands are classified as safe or dangerous, protected paths are hard-blocked, and dangerous commands require user approval."
    )]
    async fn execute_command(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(req): Parameters<ExecuteCommandRequest>,
    ) -> Result<CallToolResult, McpError> {
        // ── Concurrency guard (Phase 3.7) ──
        let _permit = match self.concurrency.try_acquire() {
            Ok(p) => p,
            Err(_) => {
                return Ok(CallToolResult::error(vec![Content::text(
                    "Too many concurrent commands. Please wait for the current command to finish.",
                )]));
            }
        };

        let timeout_secs = req
            .timeout_seconds
            .unwrap_or(self.config.default_timeout_seconds);
        let working_dir = req
            .working_directory
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")));

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

        // ── Stage 2: Classify (per sub-command, Phase 3.2) ──
        let chain_result = classifier::classify_chain(
            &parsed.commands,
            &self.config.additional_safe_commands,
            parsed.is_chained,
        );
        let classification = chain_result.aggregate.clone();
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

        // Build per-sub-command detail string for chained commands
        let chain_detail = if chain_result.is_chained {
            let details: Vec<String> = chain_result
                .details
                .iter()
                .map(|d| {
                    let status = match &d.classification {
                        classifier::Classification::Safe => "safe".to_string(),
                        classifier::Classification::Dangerous { reason } => {
                            format!("DANGEROUS ({reason})")
                        }
                    };
                    format!("  [{}] `{}` → {}", d.index + 1, d.command, status)
                })
                .collect();
            Some(format!("Chain analysis:\n{}", details.join("\n")))
        } else {
            None
        };

        // ── Stage 3: Location Guard (with symlink resolution, Phase 3.5) ──
        let guard = location_guard::check_paths(
            &parsed.commands,
            &classification,
            &self.config.additional_protected_paths,
        );
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

            let mut blocked_msg = format!(
                "BLOCKED: Command targets protected path(s):\n{}",
                violation_desc.join("\n")
            );
            if let Some(ref detail) = chain_detail {
                blocked_msg.push_str(&format!("\n\n{detail}"));
            }

            return Ok(CallToolResult::error(vec![Content::text(blocked_msg)]));
        }

        // ── Stage 4: Permission Gate (only for dangerous commands) ──
        if let classifier::Classification::Dangerous { reason } = &classification {
            // Enrich reason with chain analysis details when available
            let gate_reason = if let Some(ref detail) = chain_detail {
                format!("{reason}\n\n{detail}")
            } else {
                reason.clone()
            };

            logging::log_event(
                &context,
                LogEvent::PermissionRequested {
                    command: &full_command,
                },
            )
            .await;

            let decision = permission_gate::gate(&context, &full_command, &gate_reason).await;

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

        // ── Stage 5: Execute (shell selection, output limits, sanitization) ──
        let start = Instant::now();

        let (shell, shell_flag) = resolve_shell(&self.config);

        let result = tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), async {
            let child = tokio::process::Command::new(&shell)
                .arg(&shell_flag)
                .arg(&full_command)
                .current_dir(&working_dir)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .stdin(Stdio::null())
                .spawn()?;

            // Track the child PID so it can be killed on shutdown.
            let pid = child.id();
            if let Some(pid) = pid {
                self.child_tracker.add(pid);
            }

            let output = child.wait_with_output().await;

            // Untrack after the process exits.
            if let Some(pid) = pid {
                self.child_tracker.remove(pid);
            }

            output
        })
        .await;

        let duration_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(Ok(output)) => {
                let exit_code = output.status.code().unwrap_or(-1);

                let max_bytes = self.config.max_output_bytes;
                let (stdout, stdout_truncated) = truncate_output(&output.stdout, max_bytes);
                let (stderr, stderr_truncated) = truncate_output(&output.stderr, max_bytes);

                let stdout = self.sanitizer.redact(&stdout);
                let stderr = self.sanitizer.redact(&stderr);

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
                    let mut text = format!("stdout:\n{stdout}");
                    if stdout_truncated {
                        text.push_str("\n[OUTPUT TRUNCATED]");
                    }
                    parts.push(Content::text(text));
                }
                if !stderr.is_empty() {
                    let mut text = format!("stderr:\n{stderr}");
                    if stderr_truncated {
                        text.push_str("\n[OUTPUT TRUNCATED]");
                    }
                    parts.push(Content::text(text));
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

        let additional: &[String] = &self.config.additional_safe_commands;

        let result = serde_json::json!({
            "commands": commands,
            "additional_safe_commands": additional,
            "os": platform::os_name(),
            "count": commands.len() + additional.len(),
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&result).unwrap_or_default(),
        )]))
    }

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

        let additional: Vec<serde_json::Value> = self
            .config
            .additional_protected_paths
            .iter()
            .map(|pp| {
                serde_json::json!({
                    "path": pp.path,
                    "read_allowed": pp.read_allowed,
                })
            })
            .collect();

        let result = serde_json::json!({
            "paths": paths,
            "additional_protected_paths": additional,
            "os": platform::os_name(),
            "count": paths.len() + additional.len(),
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&result).unwrap_or_default(),
        )]))
    }
}

#[tool_handler]
impl ServerHandler for SafeShellServer {
    fn get_info(&self) -> ServerInfo {
        let mut impl_info = Implementation::default();
        impl_info.name = "safeshell-mcp".to_string();
        impl_info.title = Some("SafeShell MCP Server".to_string());
        impl_info.version = env!("CARGO_PKG_VERSION").to_string();
        impl_info.description =
            Some("A safety-first shell command executor MCP server".to_string());

        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder()
            .enable_tools()
            .enable_logging()
            .build();
        info.server_info = impl_info;
        info.instructions = Some(
            "SafeShell MCP Server — a safety-first shell command executor. \
             Commands are classified as safe or dangerous. Safe commands run immediately. \
             Dangerous commands require user approval via elicitation. \
             Protected system paths are hard-blocked and cannot be overridden."
                .to_string(),
        );
        info
    }
}

fn resolve_shell(config: &Config) -> (String, String) {
    if let Some(ref shell) = config.shell {
        if !std::path::Path::new(shell).exists() {
            tracing::warn!(
                shell = %shell,
                "configured shell not found on disk, using it anyway"
            );
        }
        let result = shell_with_flag(shell);
        tracing::debug!(shell = %result.0, flag = %result.1, source = "config", "resolved shell");
        return result;
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(shell) = std::env::var("SHELL") {
            if std::path::Path::new(&shell).exists() {
                let result = shell_with_flag(&shell);
                tracing::debug!(
                    shell = %result.0, flag = %result.1, source = "$SHELL", "resolved shell"
                );
                return result;
            }
            tracing::debug!(
                shell = %shell,
                "SHELL env var set but path does not exist, falling back"
            );
        }
        tracing::debug!(
            shell = "/bin/sh",
            flag = "-c",
            source = "fallback",
            "resolved shell"
        );
        ("/bin/sh".to_string(), "-c".to_string())
    }

    #[cfg(target_os = "windows")]
    {
        let comspec = std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".to_string());
        let result = shell_with_flag(&comspec);
        tracing::debug!(
            shell = %result.0, flag = %result.1, source = "COMSPEC", "resolved shell"
        );
        result
    }
}

fn shell_with_flag(shell: &str) -> (String, String) {
    let lower = shell.to_lowercase();
    if lower.contains("powershell") || lower.contains("pwsh") {
        (shell.to_string(), "-Command".to_string())
    } else if lower.contains("cmd") {
        (shell.to_string(), "/C".to_string())
    } else if lower.contains("fish") {
        (shell.to_string(), "-c".to_string())
    } else {
        // POSIX shells: bash, sh, zsh, dash, ksh, etc.
        (shell.to_string(), "-c".to_string())
    }
}

fn truncate_output(raw: &[u8], max_bytes: usize) -> (String, bool) {
    let truncated = raw.len() > max_bytes;
    let bytes = if truncated { &raw[..max_bytes] } else { raw };
    let text = String::from_utf8_lossy(bytes).into_owned();
    (text, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── shell_with_flag tests ──────────────────────────────────────

    #[test]
    fn shell_with_flag_posix_shells() {
        assert_eq!(
            shell_with_flag("/bin/bash"),
            ("/bin/bash".to_string(), "-c".to_string())
        );
        assert_eq!(
            shell_with_flag("/bin/sh"),
            ("/bin/sh".to_string(), "-c".to_string())
        );
        assert_eq!(
            shell_with_flag("/bin/zsh"),
            ("/bin/zsh".to_string(), "-c".to_string())
        );
        assert_eq!(
            shell_with_flag("/usr/bin/dash"),
            ("/usr/bin/dash".to_string(), "-c".to_string())
        );
    }

    #[test]
    fn shell_with_flag_ksh() {
        assert_eq!(
            shell_with_flag("/bin/ksh"),
            ("/bin/ksh".to_string(), "-c".to_string())
        );
    }

    #[test]
    fn shell_with_flag_fish() {
        assert_eq!(
            shell_with_flag("/usr/bin/fish"),
            ("/usr/bin/fish".to_string(), "-c".to_string())
        );
    }

    #[test]
    fn shell_with_flag_powershell() {
        assert_eq!(
            shell_with_flag("powershell.exe"),
            ("powershell.exe".to_string(), "-Command".to_string())
        );
        assert_eq!(
            shell_with_flag("/usr/bin/pwsh"),
            ("/usr/bin/pwsh".to_string(), "-Command".to_string())
        );
        assert_eq!(
            shell_with_flag("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            (
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string(),
                "-Command".to_string()
            )
        );
    }

    #[test]
    fn shell_with_flag_powershell_case_insensitive() {
        assert_eq!(
            shell_with_flag("PowerShell.exe"),
            ("PowerShell.exe".to_string(), "-Command".to_string())
        );
        assert_eq!(
            shell_with_flag("PWSH"),
            ("PWSH".to_string(), "-Command".to_string())
        );
    }

    #[test]
    fn shell_with_flag_cmd() {
        assert_eq!(
            shell_with_flag("cmd.exe"),
            ("cmd.exe".to_string(), "/C".to_string())
        );
        assert_eq!(
            shell_with_flag("C:\\Windows\\System32\\cmd.exe"),
            (
                "C:\\Windows\\System32\\cmd.exe".to_string(),
                "/C".to_string()
            )
        );
    }

    #[test]
    fn shell_with_flag_cmd_case_insensitive() {
        assert_eq!(
            shell_with_flag("CMD.EXE"),
            ("CMD.EXE".to_string(), "/C".to_string())
        );
    }

    #[test]
    fn shell_with_flag_unknown_shell() {
        // Unknown shell should default to POSIX -c
        assert_eq!(
            shell_with_flag("/usr/local/bin/custom_shell"),
            ("/usr/local/bin/custom_shell".to_string(), "-c".to_string())
        );
    }

    // ── resolve_shell tests ────────────────────────────────────────

    #[test]
    fn resolve_shell_config_override() {
        let config = Config {
            shell: Some("/usr/local/bin/bash".to_string()),
            ..Config::default()
        };
        let (shell, flag) = resolve_shell(&config);
        assert_eq!(shell, "/usr/local/bin/bash");
        assert_eq!(flag, "-c");
    }

    #[test]
    fn resolve_shell_config_powershell_override() {
        let config = Config {
            shell: Some("pwsh".to_string()),
            ..Config::default()
        };
        let (shell, flag) = resolve_shell(&config);
        assert_eq!(shell, "pwsh");
        assert_eq!(flag, "-Command");
    }

    #[test]
    fn resolve_shell_config_cmd_override() {
        let config = Config {
            shell: Some("cmd.exe".to_string()),
            ..Config::default()
        };
        let (shell, flag) = resolve_shell(&config);
        assert_eq!(shell, "cmd.exe");
        assert_eq!(flag, "/C");
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn resolve_shell_unix_fallback() {
        let config = Config {
            shell: None,
            ..Config::default()
        };
        let (shell, flag) = resolve_shell(&config);
        assert!(!shell.is_empty());
        assert!(flag == "-c" || flag == "-Command");
    }

    // ── truncate_output tests ──────────────────────────────────────

    #[test]
    fn truncate_output_within_limit() {
        let data = b"hello world";
        let (text, truncated) = truncate_output(data, 100);
        assert_eq!(text, "hello world");
        assert!(!truncated);
    }

    #[test]
    fn truncate_output_exactly_at_limit() {
        let data = b"12345";
        let (text, truncated) = truncate_output(data, 5);
        assert_eq!(text, "12345");
        assert!(!truncated);
    }

    #[test]
    fn truncate_output_exceeds_limit() {
        let data = b"hello world, this is a long string";
        let (text, truncated) = truncate_output(data, 5);
        assert_eq!(text, "hello");
        assert!(truncated);
    }

    #[test]
    fn truncate_output_empty() {
        let data = b"";
        let (text, truncated) = truncate_output(data, 100);
        assert_eq!(text, "");
        assert!(!truncated);
    }

    #[test]
    fn truncate_output_zero_limit() {
        let data = b"hello";
        let (text, truncated) = truncate_output(data, 0);
        assert_eq!(text, "");
        assert!(truncated);
    }

    #[test]
    fn truncate_output_invalid_utf8_handled() {
        // Invalid UTF-8 bytes should be handled with lossy conversion
        let data = &[0xff, 0xfe, 0xfd, 0x48, 0x65, 0x6c, 0x6c, 0x6f];
        let (text, truncated) = truncate_output(data, 100);
        assert!(!truncated);
        // Should contain lossy-converted output
        assert!(text.contains("Hello"));
    }

    // ── SafeShellServer construction ───────────────────────────────

    #[test]
    fn server_new_default_config() {
        let server = SafeShellServer::new(Config::default());
        assert_eq!(server.config.default_timeout_seconds, 30);
        assert_eq!(server.config.max_concurrency, 1);
    }

    #[test]
    fn server_new_custom_config() {
        let config = Config {
            default_timeout_seconds: 60,
            max_concurrency: 4,
            max_output_bytes: 200_000,
            additional_safe_commands: vec!["git".to_string()],
            ..Config::default()
        };
        let server = SafeShellServer::new(config);
        assert_eq!(server.config.default_timeout_seconds, 60);
        assert_eq!(server.config.max_concurrency, 4);
        assert_eq!(server.config.max_output_bytes, 200_000);
    }

    #[test]
    fn server_concurrency_min_one() {
        // max_concurrency of 0 should be coerced to at least 1
        let config = Config {
            max_concurrency: 0,
            ..Config::default()
        };
        let server = SafeShellServer::new(config);
        // The semaphore should allow at least one permit
        assert!(server.concurrency.try_acquire().is_ok());
    }

    // ── ServerInfo ─────────────────────────────────────────────────

    #[test]
    fn server_info_has_correct_name() {
        let server = SafeShellServer::new(Config::default());
        let info = server.get_info();
        assert_eq!(info.server_info.name, "safeshell-mcp");
        assert!(info.server_info.title.is_some());
        assert!(info.instructions.is_some());
    }

    #[test]
    fn server_info_version_matches_cargo() {
        let server = SafeShellServer::new(Config::default());
        let info = server.get_info();
        assert_eq!(info.server_info.version, env!("CARGO_PKG_VERSION"));
    }
}

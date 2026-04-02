# Changelog

All notable changes to SafeShell MCP Server are documented in this file.

## [1.0.0] - 2026-04-02

### Added

- **Core MCP server** with `ServerHandler` implementation using the `rmcp` SDK
- **Dual transport support**: stdio (default) and HTTP (Streamable HTTP/SSE) via `--transport` flag
- **`execute_command` tool**: execute shell commands with safety checks, timeout enforcement, and structured output (stdout, stderr, exit code, execution time)
- **`get_system_path` tool**: expose the system PATH environment variable with OS/architecture info
- **`list_safe_commands` tool**: list all pre-approved commands for the current OS
- **`list_protected_paths` tool**: list directories protected from command execution
- **Full command pipeline**: parse & normalize -> classify (safe/dangerous) -> location guard -> permission gate (MCP elicitation) -> execute
- **Per-OS safe command allowlists** for macOS, Linux, and Windows (echo, ls, cat, whoami, pwd, date, hostname, etc.)
- **Per-OS protected directory deny lists** (e.g., /System, /usr/bin on macOS; /boot, /proc on Linux; C:\Windows on Windows)
- **Two-tier dangerous command classification**:
  - Tier 1 (catastrophic, never whitelistable): `sudo`, `su`, `dd`, `mkfs`, `shutdown`, `reboot`, etc.
  - Tier 2 (whitelistable via config): `rm`, `curl`, `npm`, `cargo`, `bash`, `python`, `kill`, etc.
- **`additional_safe_commands` configuration**: users can pre-approve Tier 2 dangerous commands when MCP clients lack elicitation support
- **Permission elicitation** (human-in-the-loop): dangerous commands prompt user approval via MCP elicitation protocol; defaults to DENY when unsupported
- **Symlink and path traversal protection**: all paths resolved via `canonicalize()` before checking against protected directories
- **Chained command analysis**: piped/chained commands (`&&`, `||`, `;`, `|`) classified independently; chain is dangerous if any sub-command is dangerous
- **Configuration file** (`safeshell.toml`): configurable timeout, max output size, max concurrency, additional safe commands, additional protected paths, redact patterns, shell override, HTTP bind address, log level, log file
- **Environment variable overrides** (`SAFESHELL_*` prefix): all config fields overridable via env vars (precedence: env vars > config file > defaults)
- **Environment variable sanitization**: redact sensitive values (AWS keys, DATABASE_URL, API keys, etc.) from command output via configurable regex patterns
- **Concurrent execution guard**: semaphore-based limit on simultaneous command executions (default: 1)
- **Graceful shutdown**: handles SIGINT/SIGTERM, kills running child processes, flushes logs
- **Shell selection logic**: auto-detects `$SHELL` with fallback to `/bin/sh` (Unix) or `cmd.exe` (Windows); supports PowerShell; configurable via `shell` config
- **Output size limits**: truncate stdout/stderr to configurable max (default: 100KB) with truncation reporting
- **Structured MCP logging**: real-time log events sent to MCP client via `notify_logging_message`
- **Local audit logging**: `tracing` with structured JSON output to stderr and optional log file
- **Cross-platform CI**: GitHub Actions for macOS ARM64, Linux x86_64, Linux ARM64, Windows x86, Windows x86_64
- **Release pipeline**: automated binary builds on tag push with GitHub Releases
- **MCP Inspector compatibility**: validated and documented testing flow
- **Comprehensive test suite**: 281 tests covering classifier, location guard, parser, config, sanitizer, server, and shutdown modules
- **Documentation**: README with quick start, configuration reference, security model, architecture diagrams; SECURITY.md with threat model; CONTRIBUTING.md; MCP client integration examples for Claude Desktop, Cursor, and VS Code

### Security

- Protected system directories are hardcoded and cannot be removed via configuration (only additive)
- Tier 1 catastrophic commands (privilege escalation, disk destruction, system control) cannot be whitelisted under any configuration
- Symlink resolution prevents path traversal attacks against protected directories
- Sensitive environment variable values are redacted from command output by default
- Default-deny: all unknown commands require explicit approval

[1.0.0]: https://github.com/nicholasgriffintn/safeshell-mcp/releases/tag/v1.0.0

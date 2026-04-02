# SafeShell MCP Server

A safety-first shell command executor for the [Model Context Protocol](https://modelcontextprotocol.io). Built in Rust with the [`rmcp`](https://github.com/modelcontextprotocol/rust-sdk) SDK.

SafeShell lets AI assistants run shell commands while enforcing safety guardrails: commands are classified, protected paths are hard-blocked, dangerous operations require human approval, and sensitive environment variables are automatically redacted from output.

## Features

- **Command classification** — commands are categorized as safe (auto-execute) or dangerous (requires approval)
- **Protected path enforcement** — hard-blocks writes to system directories (`/etc`, `/boot`, `C:\Windows`, etc.)
- **Human-in-the-loop** — dangerous commands prompt for approval via MCP elicitation
- **Chained command analysis** — each sub-command in pipes/chains is classified independently
- **Symlink protection** — paths are canonicalized before guard checks
- **Output limits** — configurable max output size with truncation reporting
- **Secret redaction** — sensitive env var values are replaced with `[REDACTED]` in output
- **Concurrency control** — semaphore-based limit on simultaneous executions
- **Dual transport** — supports both stdio and streamable HTTP (SSE)
- **Graceful shutdown** — signal handling with child process cleanup
- **Cross-platform** — macOS, Linux, Windows

## Architecture

```
                    ┌──────────────────────────────────────────────┐
                    │              MCP Client                      │
                    │  (Claude Desktop, Cursor, VS Code, etc.)     │
                    └────────────────┬─────────────────────────────┘
                                     │
                          stdio or HTTP/SSE
                                     │
                    ┌────────────────▼─────────────────────────────┐
                    │         SafeShell MCP Server                 │
                    │                                              │
                    │  Tools:                                      │
                    │   • execute_command                          │
                    │   • get_system_path                          │
                    │   • list_safe_commands                       │
                    │   • list_protected_paths                     │
                    │                                              │
                    │  ┌────────────────────────────────────────┐  │
                    │  │        Safety Pipeline                 │  │
                    │  │                                        │  │
                    │  │  1. Parse ─► Tokenize, resolve paths   │  │
                    │  │       │                                │  │
                    │  │  2. Classify ─► Safe or Dangerous      │  │
                    │  │       │                                │  │
                    │  │  3. Location Guard ─► Protected paths  │  │
                    │  │       │               (hard block)     │  │
                    │  │       │                                │  │
                    │  │  4. Permission Gate ─► User approval   │  │
                    │  │       │               (elicitation)    │  │
                    │  │       │                                │  │
                    │  │  5. Execute ─► Run, sanitize output    │  │
                    │  │                                        │  │
                    │  └────────────────────────────────────────┘  │
                    │                                              │
                    │  Platform Layer (macOS / Linux / Windows)    │
                    │   • Safe command allowlists                  │
                    │   • Protected path definitions               │
                    └──────────────────────────────────────────────┘
```

## Installation

### Pre-built binaries

Download from [GitHub Releases](https://github.com/anthropics/safeshell-mcp/releases):

| Platform | Binary |
|----------|--------|
| macOS (Apple Silicon) | `safeshell-mcp-macos-arm64` |
| Linux (x86_64) | `safeshell-mcp-linux-x86_64` |
| Linux (ARM64) | `safeshell-mcp-linux-arm64` |
| Windows (x86_64) | `safeshell-mcp-windows-x86_64.exe` |
| Windows (x86) | `safeshell-mcp-windows-x86.exe` |

### Build from source

Requires Rust 1.85+ (edition 2024).

```bash
cargo install --path .
```

Or build a release binary (optimized for size):

```bash
cargo build --release
# Binary at target/release/safeshell-mcp
```

## Quick start

### 1. Run with stdio transport (default)

```bash
safeshell-mcp
```

The server reads MCP messages from stdin and writes to stdout. This is the standard transport for MCP client integrations.

### 2. Run with HTTP transport

```bash
safeshell-mcp --transport http
```

By default, listens on `127.0.0.1:3456`. Override with `--bind`:

```bash
safeshell-mcp --transport http --bind 0.0.0.0:8080
```

### 3. Connect an MCP client

See [MCP Client Integration](#mcp-client-integration) below for Claude Desktop, Claude Code, Cursor, and VS Code configuration.

## Tools

SafeShell exposes four MCP tools:

### `execute_command`

Run a shell command through the safety pipeline.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `command` | string | yes | — | The command to run |
| `args` | string[] | no | `[]` | Command arguments |
| `working_directory` | string | no | cwd | Working directory for the command |
| `timeout_seconds` | integer | no | 30 | Maximum execution time in seconds |

**Example:**

```json
{
  "command": "ls",
  "args": ["-la", "/tmp"],
  "working_directory": "/home/user",
  "timeout_seconds": 60
}
```

**Pipeline:** the command passes through five stages before execution:

1. **Parse** — tokenize the command, split chains (`&&`, `||`, `|`, `;`), resolve `~` and relative paths to absolute paths
2. **Classify** — categorize each sub-command as safe or dangerous; if any sub-command is dangerous, the whole chain is dangerous
3. **Location Guard** — check resolved paths (including redirection targets like `> /etc/shadow`) against protected directories; canonicalize symlinks before checking; hard-block violations
4. **Permission Gate** — for dangerous commands, prompt the user for approval via MCP elicitation; if the client does not support elicitation, default to DENY
5. **Execute** — run via the configured shell, enforce timeout, truncate output to `max_output_bytes`, redact sensitive env var values

### `get_system_path`

List all directories in the `PATH` environment variable.

Returns: `path_entries` (array of directory paths), `os`, `arch`.

### `list_safe_commands`

Show all commands pre-approved as safe for the current OS, plus any `additional_safe_commands` from config.

Returns: `commands` (array with `name` and `description`), `additional_safe_commands`, `os`, `count`.

### `list_protected_paths`

Show all directories protected from command execution on the current OS, plus any `additional_protected_paths` from config.

Returns: `paths` (array with `path`, `read_allowed`, `reason`), `additional_protected_paths`, `os`, `count`.

## Security model

SafeShell implements defense-in-depth with multiple independent layers:

### Command classification

Every command is classified against a built-in allowlist. Commands explicitly listed as safe execute immediately. Everything else — including unknown commands — is classified as **dangerous** and requires user approval.

Dangerous commands are further divided into two tiers:

#### Tier 1: Catastrophic (NEVER whitelistable)

These commands are too destructive to ever be auto-approved. Even if added to `additional_safe_commands`, they are **ignored** and a warning is logged.

| Category | Commands |
|----------|----------|
| Privilege escalation | `sudo`, `su`, `doas`, `pkexec`, `runas` |
| Disk destruction | `mkfs`, `dd`, `shred`, `fdisk`, `parted`, `lvm` |
| System control | `shutdown`, `reboot`, `halt`, `poweroff`, `init` |

#### Tier 2: Whitelistable dangerous

These are dangerous but legitimate developer tools. They can be pre-approved via `additional_safe_commands` in config or `SAFESHELL_SAFE_COMMANDS` env var. This is useful when your MCP client does not support elicitation.

| Category | Commands |
|----------|----------|
| File operations | `rm`, `rmdir`, `chmod`, `chown`, `chgrp`, `truncate` |
| Network commands | `curl`, `wget`, `nc`, `ncat`, `netcat`, `ssh`, `scp`, `sftp`, `rsync`, `ftp` |
| Package managers | `apt`, `apt-get`, `yum`, `dnf`, `pacman`, `brew`, `choco`, `pip`, `npm`, `cargo` |
| System services | `systemctl`, `launchctl`, `kill`, `killall`, `pkill`, `mount`, `umount` |
| Shell interpreters | `bash`, `sh`, `zsh`, `fish`, `csh`, `tcsh`, `dash`, `ksh`, `python`, `python3`, `perl`, `ruby`, `node` |

When a whitelisted Tier 2 command executes, the tool response includes an annotation:

> ⚠️ Pre-approved via additional_safe_commands configuration. No interactive approval was requested.

When a non-whitelisted dangerous command is denied because elicitation is unavailable, the denial message includes instructions on how to pre-approve it.

For chained commands (`ls | grep foo && rm file`), each sub-command is classified independently. If **any** sub-command is dangerous, the entire chain requires approval. The approval prompt shows per-sub-command classification details.

### Protected path enforcement

The location guard checks all resolved path arguments (including redirection targets like `> /etc/shadow`) against OS-specific protected directories.

- **Safe commands** (read-only): allowed to access protected paths where `read_allowed: true` (e.g., `cat /etc/hosts` is allowed)
- **Dangerous commands** (write): blocked from all protected paths regardless of `read_allowed`
- **Symlink resolution**: paths are canonicalized via `fs::canonicalize()` before checking, preventing symlink bypass attacks (e.g., `/tmp/link → /etc/shadow`)
- **Null byte injection**: paths containing `\0` are rejected
- **`/proc/self/root` traversal** (Linux): paths through `/proc/self/root` or `/proc/<pid>/root` are blocked to prevent chroot escapes

Protected path violations are **hard-blocked** — they cannot be overridden by user approval.

### Human-in-the-loop approval

Dangerous commands that pass the location guard are presented to the user via MCP [elicitation](https://modelcontextprotocol.io/specification/2025-03-26/server/elicitation). The user sees the full command and the reason it was flagged, and must explicitly approve execution.

If the MCP client does not support elicitation, the command is **denied by default**.

### Output sanitization

After execution, stdout and stderr are:

1. **Truncated** to `max_output_bytes` per stream (default: 100 KB), with a `[OUTPUT TRUNCATED]` marker
2. **Redacted** — environment variable values matching sensitive name patterns are replaced with `[REDACTED]`

Built-in sensitive patterns match: `SECRET`, `PASSWORD`, `PASSWD`, `TOKEN`, `API_KEY`, `PRIVATE_KEY`, `ACCESS_KEY`, `AUTH`, `CREDENTIAL`, `DATABASE_URL`, `CONNECTION_STRING`, `SMTP`. Values shorter than 4 characters are skipped to avoid false positives. Additional patterns can be added via `redact_env_patterns` in config.

### Concurrency control

A semaphore limits simultaneous command executions to `max_concurrency` (default: 1). Excess requests receive an immediate error rather than queueing.

### Graceful shutdown

Signal handlers (SIGINT/SIGTERM on Unix, CTRL_C on Windows) trigger graceful shutdown. All tracked child processes are terminated before the server exits.

## Configuration

SafeShell is configured via a TOML file. All fields are optional — sensible defaults apply.

### Config file search order

| Priority | Location |
|----------|----------|
| 1 | Path in `$SAFESHELL_CONFIG` environment variable |
| 2 | `./safeshell.toml` (current working directory) |
| 3 | `~/.config/safeshell/config.toml` |

If no config file is found, all defaults are used.

### Full configuration reference

```toml
# Command timeout (seconds)
default_timeout_seconds = 30

# Max output per stream in bytes (stdout/stderr each)
max_output_bytes = 102400

# Max concurrent command executions
max_concurrency = 1

# Additional commands treated as safe (beyond built-in list)
additional_safe_commands = ["make", "just", "nx"]

# Additional regex patterns for env var names to redact
redact_env_patterns = ["(?i)MY_COMPANY_.*"]

# Override shell (auto-detected if unset)
# shell = "/bin/bash"

# HTTP bind address (used with --transport http when --bind is not set)
# http_bind = "127.0.0.1:3456"

# Log level filter (e.g. "debug", "info", "warn", "safeshell_mcp=debug")
# log_level = "info"

# Path to an additional log file (logs always go to stderr too)
# log_file = "/var/log/safeshell.log"

# Additional protected paths
[[additional_protected_paths]]
path = "/data/production"
read_allowed = true

[[additional_protected_paths]]
path = "/secrets"
read_allowed = false
```

### Configuration defaults

| Setting | Default | Description |
|---------|---------|-------------|
| `default_timeout_seconds` | `30` | Max execution time per command |
| `max_output_bytes` | `102400` (100 KB) | Max bytes per output stream before truncation |
| `max_concurrency` | `1` | Max simultaneous command executions |
| `additional_safe_commands` | `[]` | Extra commands to treat as safe (Tier 1 catastrophic commands like `sudo`, `dd`, `shutdown` cannot be overridden; Tier 2 commands like `rm`, `curl`, `npm` can be whitelisted) |
| `additional_protected_paths` | `[]` | Extra directories to protect |
| `redact_env_patterns` | `[]` | Extra regex patterns for sensitive env var names |
| `shell` | auto-detect | Shell binary for execution |
| `http_bind` | `"127.0.0.1:3456"` | HTTP listen address (when using `--transport http`) |
| `log_level` | `"info"` | Log filter (via `RUST_LOG` env or config) |
| `log_file` | none | Optional file path for log output |

### Environment variables

Individual config fields can be overridden via `SAFESHELL_*` environment variables. These take precedence over config file values.

| Variable | Config field | Description |
|----------|-------------|-------------|
| `SAFESHELL_CONFIG` | — | Path to config file (highest priority for file location) |
| `SAFESHELL_TIMEOUT` | `default_timeout_seconds` | Command timeout in seconds |
| `SAFESHELL_MAX_OUTPUT` | `max_output_bytes` | Max output per stream in bytes |
| `SAFESHELL_MAX_CONCURRENCY` | `max_concurrency` | Max simultaneous executions |
| `SAFESHELL_SHELL` | `shell` | Shell binary path |
| `SAFESHELL_HTTP_BIND` | `http_bind` | HTTP listen address |
| `SAFESHELL_LOG_LEVEL` | `log_level` | Log filter string |
| `SAFESHELL_LOG_FILE` | `log_file` | Log file path |
| `SAFESHELL_SAFE_COMMANDS` | `additional_safe_commands` | Comma-separated list of additional safe commands (Tier 1 catastrophic commands cannot be overridden) |
| `SAFESHELL_REDACT_PATTERNS` | `redact_env_patterns` | Comma-separated list of regex patterns for env var redaction |
| `RUST_LOG` | — | Log level filter (overridden by `log_level` / `SAFESHELL_LOG_LEVEL`) |
| `SHELL` (Unix) | — | Default shell when `shell` is not set |
| `COMSPEC` (Windows) | — | Default shell when `shell` is not set |

**Precedence:** environment variables > config file > defaults.

Invalid numeric values (for `SAFESHELL_TIMEOUT`, `SAFESHELL_MAX_OUTPUT`, `SAFESHELL_MAX_CONCURRENCY`) are logged as warnings and ignored.

**Example — configure via environment in an MCP client:**

```json
{
  "mcpServers": {
    "safeshell": {
      "command": "/path/to/safeshell-mcp",
      "env": {
        "SAFESHELL_TIMEOUT": "120",
        "SAFESHELL_SAFE_COMMANDS": "make,just,nx",
        "SAFESHELL_LOG_LEVEL": "debug"
      }
    }
  }
}
```

### Shell auto-detection

When `shell` is not set in config:

| Platform | Detection order |
|----------|----------------|
| Unix | `$SHELL` env var → `/bin/sh` fallback |
| Windows | `%COMSPEC%` env var → `cmd.exe` fallback |

Shell flags are auto-detected: `-c` for POSIX shells and fish, `-Command` for PowerShell/pwsh, `/C` for cmd.exe.

## MCP Client Integration

> Ready-to-copy configuration files for all supported MCP hosts are available in the [examples/](examples/) directory.

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "safeshell": {
      "command": "/path/to/safeshell-mcp"
    }
  }
}
```

### Claude Code

Add to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "safeshell": {
      "command": "/path/to/safeshell-mcp"
    }
  }
}
```

Or use HTTP transport:

```json
{
  "mcpServers": {
    "safeshell": {
      "type": "http",
      "url": "http://127.0.0.1:3456/mcp"
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json` in your project:

```json
{
  "mcpServers": {
    "safeshell": {
      "command": "/path/to/safeshell-mcp"
    }
  }
}
```

### VS Code (Copilot)

Add to `.vscode/mcp.json`:

```json
{
  "servers": {
    "safeshell": {
      "command": "/path/to/safeshell-mcp"
    }
  }
}
```

### With custom configuration

Point to a config file via environment variable:

```json
{
  "mcpServers": {
    "safeshell": {
      "command": "/path/to/safeshell-mcp",
      "env": {
        "SAFESHELL_CONFIG": "/path/to/safeshell.toml"
      }
    }
  }
}
```

## Safe commands

Built-in safe commands vary by OS. Use the `list_safe_commands` tool to see the full list for your platform.

**Common safe commands (all platforms):** `echo`, `date`, `whoami`, `hostname`

**Unix (macOS + Linux):** `cat`, `ls`, `head`, `tail`, `wc`, `pwd`, `uname`, `which`, `printenv`, `df`, `uptime`

**Windows:** `dir`, `type`, `where`, `ver`, `set`, `cd`

Commands not on the safe allowlist are classified as dangerous by default and require user approval.

## License

MIT

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
- **Cross-platform** — macOS, Linux, Windows

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

```bash
cargo install --path .
```

Or build a release binary:

```bash
cargo build --release
# Binary at target/release/safeshell-mcp
```

## Quick start

### stdio transport (default)

```bash
safeshell-mcp
```

### HTTP transport

```bash
safeshell-mcp --transport http
# or with custom bind address
safeshell-mcp --transport http --bind 0.0.0.0:8080
```

## Tools

SafeShell exposes four MCP tools:

| Tool | Description |
|------|-------------|
| `execute_command` | Run a shell command through the safety pipeline |
| `get_system_path` | List PATH directories |
| `list_safe_commands` | Show pre-approved commands for this OS |
| `list_protected_paths` | Show protected directories |

### `execute_command`

```json
{
  "command": "ls",
  "args": ["-la", "/tmp"],
  "working_directory": "/home/user",
  "timeout_seconds": 60
}
```

**Pipeline**: Parse → Classify → Location Guard → Permission Gate → Execute

- **Safe commands** (e.g., `ls`, `cat`, `echo`, `git status`) execute immediately
- **Dangerous commands** (e.g., `rm`, `curl`, `sudo`, `pip`) trigger an approval prompt
- **Protected paths** (e.g., `/etc`, `/boot`, `/System`) are hard-blocked for writes

## Configuration

Create a `safeshell.toml` file. Search order:

1. `$SAFESHELL_CONFIG` environment variable
2. `./safeshell.toml` (current directory)
3. `~/.config/safeshell/config.toml`

### Example config

```toml
# Command timeout (seconds)
default_timeout_seconds = 60

# Max output per stream in bytes (stdout/stderr each)
max_output_bytes = 204800  # 200KB

# Max concurrent command executions
max_concurrency = 4

# Additional commands treated as safe (beyond built-in list)
additional_safe_commands = ["make", "just", "nx"]

# Additional regex patterns for env var names to redact
redact_env_patterns = ["(?i)MY_COMPANY_.*"]

# Override shell (auto-detected if unset)
shell = "/bin/bash"

# HTTP bind address (used when --transport http, no --bind flag)
http_bind = "127.0.0.1:3456"

# Log level filter
log_level = "info"

# Additional protected paths
[[additional_protected_paths]]
path = "/data/production"
read_allowed = true

[[additional_protected_paths]]
path = "/secrets"
read_allowed = false
```

### Defaults

| Setting | Default |
|---------|---------|
| `default_timeout_seconds` | 30 |
| `max_output_bytes` | 102400 (100KB) |
| `max_concurrency` | 1 |
| `shell` | `$SHELL` → `/bin/sh` (Unix), `%COMSPEC%` (Windows) |

## MCP Client Integration

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

## Safe commands

Built-in safe commands vary by OS. Use the `list_safe_commands` tool to see the full list. Common safe commands include:

`ls`, `cat`, `head`, `tail`, `grep`, `find`, `wc`, `sort`, `uniq`, `diff`, `echo`, `pwd`, `whoami`, `date`, `env`, `which`, `file`, `stat`, `du`, `df`, `uname`, `hostname`, `ps`, `top`, `git` (read-only subcommands), `tree`, `less`, `more`

## Dangerous command categories

| Category | Examples |
|----------|----------|
| Privilege escalation | `sudo`, `doas`, `su`, `pkexec` |
| Destructive file ops | `rm`, `chmod`, `chown`, `dd`, `shred` |
| Network commands | `curl`, `wget`, `ssh`, `nc`, `rsync` |
| Package managers | `apt`, `brew`, `pip`, `npm`, `cargo` |
| System control | `shutdown`, `reboot`, `kill`, `systemctl` |
| Shell interpreters | `bash`, `python`, `node`, `perl` |

Any command not in the safe allowlist is classified as dangerous by default.

## License

MIT

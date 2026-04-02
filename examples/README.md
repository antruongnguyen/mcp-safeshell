# MCP Client Integration Examples

Example configuration files for connecting SafeShell MCP Server to various MCP hosts.

## Prerequisites

Install SafeShell MCP Server using one of these methods:

```bash
# From crates.io
cargo install safeshell-mcp

# From source
git clone https://github.com/anthropics/safeshell-mcp.git
cd safeshell-mcp
cargo install --path .

# Or download a pre-built binary from GitHub Releases
```

## Transport Modes

SafeShell supports two transport modes:

- **stdio** (default) — the MCP host launches the binary and communicates via stdin/stdout
- **HTTP** — the server runs as a persistent HTTP service at `http://127.0.0.1:3456/mcp`

For HTTP mode, start the server first:

```bash
safeshell-mcp --transport http

# Or with a custom bind address:
safeshell-mcp --transport http --bind 0.0.0.0:8080
```

## Claude Desktop

Copy to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows).

| File | Transport | Description |
|------|-----------|-------------|
| [claude-desktop-config.json](claude-desktop-config.json) | stdio | Standard setup — Claude launches the binary directly |
| [claude-desktop-http-config.json](claude-desktop-http-config.json) | HTTP | Connects to a running SafeShell HTTP server |
| [claude-desktop-custom-config.json](claude-desktop-custom-config.json) | stdio | With custom config file and environment overrides |

**Windows users:** Replace `safeshell-mcp` with the full path to `safeshell-mcp.exe`, using double backslashes:

```json
{
  "mcpServers": {
    "safeshell": {
      "command": "C:\\Users\\you\\.cargo\\bin\\safeshell-mcp.exe"
    }
  }
}
```

## Claude Code

Copy to `.mcp.json` in your project root.

| File | Transport | Description |
|------|-----------|-------------|
| [claude-code-mcp.json](claude-code-mcp.json) | stdio | Standard project-level setup |
| [claude-code-http-mcp.json](claude-code-http-mcp.json) | HTTP | Connects to a running SafeShell HTTP server |

## Cursor

Copy to `.cursor/mcp.json` in your project root (create the `.cursor/` directory if it doesn't exist).

| File | Transport | Description |
|------|-----------|-------------|
| [cursor-mcp.json](cursor-mcp.json) | stdio | Standard project-level setup |

## VS Code (Copilot / Continue)

Copy to `.vscode/mcp.json` in your project root.

| File | Transport | Description |
|------|-----------|-------------|
| [vscode-mcp.json](vscode-mcp.json) | stdio | Standard project-level setup |

> **Note:** VS Code uses `"servers"` as the top-level key instead of `"mcpServers"`.

## Windsurf

Copy to `.windsurf/mcp.json` in your project root (create the `.windsurf/` directory if it doesn't exist).

| File | Transport | Description |
|------|-----------|-------------|
| [windsurf-mcp.json](windsurf-mcp.json) | stdio | Standard project-level setup |

## Other MCP Hosts

Most MCP-compatible hosts follow one of these patterns:

**stdio transport** — the host launches the binary:

```json
{
  "mcpServers": {
    "safeshell": {
      "command": "safeshell-mcp"
    }
  }
}
```

**HTTP transport** — connect to a running server:

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

Consult your MCP host's documentation for the exact config file location and format.

## Configuration

SafeShell can be customized with a TOML configuration file. See [safeshell.example.toml](../safeshell.example.toml) for all available options.

Pass the config file path via the `SAFESHELL_CONFIG` environment variable in your MCP host config:

```json
{
  "mcpServers": {
    "safeshell": {
      "command": "safeshell-mcp",
      "env": {
        "SAFESHELL_CONFIG": "/path/to/safeshell.toml"
      }
    }
  }
}
```

Individual settings can also be overridden with environment variables:

| Variable | Description |
|----------|-------------|
| `SAFESHELL_CONFIG` | Path to config file |
| `SAFESHELL_TIMEOUT` | Default command timeout in seconds |
| `SAFESHELL_MAX_OUTPUT` | Max output bytes per stream |
| `SAFESHELL_MAX_CONCURRENCY` | Max simultaneous commands |

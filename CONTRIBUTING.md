# Contributing to SafeShell MCP Server

## Prerequisites

- **Rust toolchain**: stable (tested with 1.85+)
  ```sh
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- **Git**

## Getting Started

```sh
git clone <repo-url>
cd mcp-safeshell
cargo build
```

## Running Locally

```sh
# Run with stdio transport (default for MCP hosts)
cargo run

# Run tests
cargo test

# Run clippy lints
cargo clippy -- -D warnings

# Check formatting
cargo fmt --check
```

## Testing with MCP Inspector

The [MCP Inspector](https://github.com/modelcontextprotocol/inspector) validates that the server correctly implements the MCP protocol and that tool schemas are well-formed.

### Prerequisites

- Node.js 18+ with `npx`

### Quick validation (CLI mode)

Build the server first, then use the Inspector CLI with a config file:

```bash
cargo build

# Create an inspector config (or use the example below)
cat > /tmp/inspector-config.json <<'EOF'
{
  "mcpServers": {
    "safeshell": {
      "command": "./target/debug/safeshell-mcp",
      "args": []
    }
  }
}
EOF

# List all tools and verify schemas
npx @modelcontextprotocol/inspector --cli \
  --config /tmp/inspector-config.json \
  --server safeshell \
  --method tools/list

# Call a safe command
npx @modelcontextprotocol/inspector --cli \
  --config /tmp/inspector-config.json \
  --server safeshell \
  --method tools/call \
  --tool-name execute_command \
  --tool-arg command=echo

# Call a no-argument tool
npx @modelcontextprotocol/inspector --cli \
  --config /tmp/inspector-config.json \
  --server safeshell \
  --method tools/call \
  --tool-name get_system_path
```

### Interactive web UI

```bash
npx @modelcontextprotocol/inspector
```

Then configure the server command as `./target/debug/safeshell-mcp` (or `cargo run`) in the Inspector web UI.

### What to verify

- `tools/list` returns all 4 tools with valid `inputSchema`
- `execute_command` schema includes `command` (required), `args`, `working_directory`, `timeout_seconds`
- No-argument tools (`get_system_path`, `list_safe_commands`, `list_protected_paths`) return valid JSON content
- `resources/list` and `prompts/list` return empty arrays (server does not advertise these capabilities)
- Server info reports name `safeshell-mcp` with correct version

## Project Structure

```
src/
  main.rs          Entry point and transport setup
docs/
  brainstorm.md    Design document and feature spec
```

## CI

Every push and PR runs:
- `cargo check` — compilation
- `cargo clippy` — lints (warnings are errors)
- `cargo test` — test suite
- `cargo fmt --check` — formatting

All four must pass before merge.

## Code Style

- Follow `rustfmt.toml` defaults (run `cargo fmt` before committing)
- No clippy warnings allowed
- Edition 2024

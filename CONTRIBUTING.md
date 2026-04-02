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

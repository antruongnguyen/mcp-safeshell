# 🛡️ SafeShell MCP Server — Brainstorm Document

> A "safety-first" shell command executor MCP server built in Rust with the `rmcp` SDK. Supports both **stdio** and **HTTP (SSE/Streamable HTTP)** transports, with built-in permission gating, sensitive-location protection, activity logging, and cross-platform support.

> **Status**: Active development (Phases 0–2 complete). Team: Iron Man (CEO), Spider-Man, Black Panther, Hawkeye (all fullstack engineers — shared workload, no phase-specific ownership).
> **Last revised**: 2026-04-02

---

## 📋 Table of Contents

1. [Goals](#-goals)
2. [Features](#-features)
3. [Development Phases](#-development-phases)

---

## 🎯 Goals

### G1 — Safe Command Execution with Human-in-the-Loop
Execute shell commands requested by LLM agents **only after classifying** them as safe or dangerous, and **eliciting explicit user permission** (via MCP's `elicitation` protocol) for any command deemed potentially dangerous. This aligns with the MCP spec's core principle: *"For trust and safety, a human should be in the loop to deny tool invocations."*

### G2 — Cross-Platform First-Class Support
Run natively (no interpreters, no VMs) on:
| Platform | Architecture |
|----------|-------------|
| macOS | ARM64 (Apple Silicon) |
| Linux | x86_64 |
| Linux | ARM64 (aarch64) |
| Windows | x86 (32-bit) |
| Windows | x86_64 (64-bit) |

Rust's cross-compilation with `cargo` + `cross` makes this achievable from a single codebase.

### G3 — OS-Sensitive Location Protection
Internally prevent commands from touching **protected system directories** on each OS. These are hardcoded deny-lists that **cannot be overridden** by the LLM or the user at runtime — the server itself enforces the boundary.

### G4 — Safe Command Allowlisting
Maintain a per-OS allowlist of "known-safe" commands (e.g., `echo`, `date`, `whoami`, `pwd`) that are executed **without prompting the user**, reducing friction for benign operations.

### G5 — Comprehensive Activity Logging
Log **every** activity — command classification, permission requests, user decisions, execution results, and errors — using:
- MCP's structured `logging` capability (sent to the MCP client)
- Local file/stderr logging via `tracing` (for server-side audit trails)

### G6 — Full PATH Environment Visibility
Expose the system's full `PATH` environment variable as a readable resource/tool so the LLM can understand what executables are available on the current machine.

### G7 — Dual Transport: Stdio + HTTP
Support both:
- **stdio** transport (launched as a subprocess by the MCP host) for local integrations — minimal attack surface.
- **HTTP transport** (`Streamable HTTP` / SSE) for remote/network integrations and multi-client scenarios (e.g., shared dev environments).

The transport is selected at startup via CLI flag or config: `--transport stdio|http`. HTTP mode binds to a configurable address (default `127.0.0.1:3456`). Security controls (TLS, auth token, IP allowlist) are available in HTTP mode.

### G8 — Agent-Team Aware Logging
Emit structured log events that include the requesting agent's identity (when passed via MCP metadata) so multi-agent setups produce traceable, per-agent audit logs.

---

## 🧩 Features

### F1 — Core Tool: `execute_command`
The primary tool exposed to the LLM.

```
Tool: execute_command
Description: Execute a shell command with safety checks
Input Schema:
  - command: string (required) — the command to run
  - args: string[] (optional) — command arguments
  - working_directory: string (optional) — cwd for the command
  - timeout_seconds: u64 (optional, default: 30) — max execution time
Annotations:
  - destructiveHint: true
  - readOnlyHint: false
  - openWorldHint: true
Output:
  - stdout: string
  - stderr: string
  - exit_code: i32
  - execution_time_ms: u64
```

Internally this tool flows through the **Command Pipeline** (see F3).

### F2 — Tool: `get_system_path`
Exposes the full `PATH` environment of the running server process.

```
Tool: get_system_path
Description: Get the system PATH environment variable, listing all directories where executables are found
Annotations:
  - readOnlyHint: true
  - destructiveHint: false
Output:
  - path_entries: string[] — each directory in PATH
  - separator: string — ":" on Unix, ";" on Windows
  - os: string — current OS name
  - arch: string — current architecture
```

### F3 — Command Pipeline (Internal Engine)
Every command flows through a multi-stage pipeline:

```
┌─────────────┐     ┌──────────────┐     ┌────────────────┐     ┌──────────────┐     ┌───────────┐
│  1. PARSE   │────▶│ 2. CLASSIFY  │────▶│ 3. GUARD       │────▶│ 4. GATE      │────▶│ 5. EXECUTE│
│  & Normalize│     │  Safe/Danger │     │  Path/Location │     │  Permission  │     │  & Return │
└─────────────┘     └──────────────┘     └────────────────┘     └──────────────┘     └───────────┘
```

| Stage | Description |
|-------|-------------|
| **Parse & Normalize** | Tokenize the command, resolve shell expansions (`~`, `$HOME`), normalize paths to absolute, detect piped/chained commands (`&&`, `\|\|`, `;`, `\|`) |
| **Classify** | Check against the per-OS allowlist → `Safe`. Otherwise → `Dangerous`. Classification also considers: if the command writes/deletes/modifies, if it accesses network, if it elevates privileges |
| **Guard (Location)** | Resolve all path arguments. If any path falls within a **protected directory**, **hard-reject** the command. No user override possible |
| **Gate (Permission)** | For `Dangerous` commands: use MCP **elicitation** (`context.peer.elicit(...)`) to ask the user: *"Allow command `rm -rf ./build`? [Accept/Decline/Cancel]"*. For `Safe` commands: skip this step |
| **Execute** | Spawn the process via `tokio::process::Command`, capture stdout/stderr, enforce timeout, return structured result |

### F4 — Per-OS Safe Command Allowlist

| macOS | Linux | Windows |
|-------|-------|---------|
| `echo` | `echo` | `echo` |
| `date` | `date` | `date /t` |
| `whoami` | `whoami` | `whoami` |
| `pwd` | `pwd` | `cd` (no args) |
| `uname` | `uname` | `ver` |
| `hostname` | `hostname` | `hostname` |
| `cat` (read-only) | `cat` (read-only) | `type` (read-only) |
| `ls` | `ls` | `dir` |
| `which` | `which` | `where` |
| `printenv` | `printenv` | `set` (no args) |
| `head` | `head` | — |
| `tail` | `tail` | — |
| `wc` | `wc` | — |
| `df` | `df` | — |
| `uptime` | `uptime` | — |

> **Note**: Even safe commands are still subject to the **Location Guard** — `cat /etc/shadow` would be blocked.

### F5 — Per-OS Protected Directory Deny List

| macOS | Linux | Windows |
|-------|-------|---------|
| `/System` | `/boot` | `C:\Windows` |
| `/usr/bin` | `/usr/bin` | `C:\Windows\System32` |
| `/usr/sbin` | `/usr/sbin` | `C:\Windows\SysWOW64` |
| `/usr/lib` | `/lib`, `/lib64` | `C:\Program Files` |
| `/sbin` | `/sbin` | `C:\Program Files (x86)` |
| `/var/db` | `/etc` (write only) | `C:\ProgramData` |
| `/Library/LaunchDaemons` | `/proc` | `C:\Users\<user>\AppData` |
| `/Library/LaunchAgents` | `/sys` | — |
| `/private/var` | `/root` | — |
| `/etc` (write only) | `/var/log` (write only) | — |

> **Rule**: Any command whose resolved path arguments *start with* any protected directory prefix is **hard-blocked** (returns an error, no elicitation). Read access to some locations (like `/etc` for `cat /etc/hostname`) can be controlled with a `read_allowed` flag per entry.

### F6 — Permission Elicitation (Human-in-the-Loop)
Using the `rmcp` SDK's elicitation support (as seen in `elicitation_stdio.rs`):

```rust
// Define the elicitation schema
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CommandPermission {
    #[schemars(description = "Do you approve this command execution?")]
    pub approved: bool,
}
elicit_safe!(CommandPermission);

// In the tool handler:
let result = context.peer.elicit::<CommandPermission>(
    format!(
        "⚠️ DANGEROUS COMMAND DETECTED\n\
         Command: {} {}\n\
         Working Dir: {}\n\
         Reason: {}\n\
         \n\
         Do you approve execution?",
        command, args.join(" "), cwd, classification_reason
    )
).await;
```

If the client doesn't support elicitation (older MCP clients), the server **defaults to DENY** for dangerous commands and logs a warning.

### F7 — Structured MCP Logging + Local Audit Log
Two logging channels:

| Channel | Target | Purpose |
|---------|--------|---------|
| **MCP Logging** | Client (via `notify_logging_message`) | Real-time visibility for the LLM host; severity-filtered |
| **File/Stderr** | Local filesystem via `tracing` | Persistent audit trail; always captures everything |

Log events include:
- `COMMAND_RECEIVED` — raw command input
- `COMMAND_CLASSIFIED` — safe/dangerous + reason
- `PATH_GUARD_BLOCKED` — rejected due to protected location
- `PERMISSION_REQUESTED` — elicitation sent to user
- `PERMISSION_GRANTED` / `PERMISSION_DENIED` / `PERMISSION_CANCELLED`
- `COMMAND_EXECUTED` — exit code, duration, truncated output
- `COMMAND_TIMEOUT` — execution exceeded time limit
- `COMMAND_ERROR` — internal error during execution

### F8 — Tool: `list_safe_commands`
Lets the LLM discover what commands are pre-approved:

```
Tool: list_safe_commands
Description: List all commands that are pre-approved for the current OS
Annotations:
  - readOnlyHint: true
Output:
  - commands: { name: string, description: string }[]
  - os: string
```

### F9 — Tool: `list_protected_paths`
Transparency tool so the LLM knows what's off-limits:

```
Tool: list_protected_paths
Description: List directories protected from command execution
Annotations:
  - readOnlyHint: true
Output:
  - paths: { path: string, read_allowed: bool, reason: string }[]
  - os: string
```

### F10 — Configuration (Optional, Phase 3)
A TOML/JSON config file for:
- Additional safe commands
- Additional protected paths
- Default timeout
- Log file path
- Log verbosity

### F11 — Graceful Error Handling & Timeout
- Commands exceeding `timeout_seconds` are killed (`SIGKILL` / `TerminateProcess`)
- If the shell itself isn't found, return a descriptive error
- All errors are structured MCP tool errors (not panics)

---

## 🏗️ Development Phases

### Phase 0: Repository & Tooling Setup (Day 1)

**Goal**: Working repo skeleton before any feature work begins.

| Task | Details |
|------|---------|
| **0.1** Repository initialization | `cargo init --name safeshell-mcp`, `.gitignore`, `rustfmt.toml`, `clippy.toml` |
| **0.2** CI skeleton | GitHub Actions: `cargo check`, `cargo clippy`, `cargo test` on push |
| **0.3** Dev environment doc | `CONTRIBUTING.md`: toolchain version, how to run locally, how to run tests |

**Deliverable**: Clean repo, CI passing, team can clone and build in < 5 minutes.

---

### Phase 1: Foundation & Core Loop (Weeks 1–2)

**Goal**: Get a working MCP server that can receive a command and execute it over stdio, with basic logging.

| Task | Details |
|------|---------|
| **1.1** Project scaffolding | `cargo init --name safeshell-mcp`, add `rmcp` with `server` feature, `tokio`, `serde`, `schemars`, `tracing`, `tracing-subscriber` |
| **1.2** Implement `ServerHandler` | Basic struct `SafeShellServer`, implement `get_info()` with `enable_tools()` + `enable_logging()` capabilities |
| **1.3** Dual transport main | Support `--transport stdio` (default) and `--transport http [--bind 127.0.0.1:3456]`. Stdio: `SafeShellServer::new().serve(stdio()).await`. HTTP: bind SSE/Streamable HTTP listener. |
| **1.4** `execute_command` tool (naive) | Use `#[tool_router]` + `#[tool]` macros. Spawn `tokio::process::Command`, capture stdout/stderr, enforce timeout with `tokio::time::timeout` |
| **1.5** `get_system_path` tool | Read `std::env::var("PATH")`, split by OS-appropriate separator, return as structured content |
| **1.6** Basic `tracing` setup | `tracing_subscriber::fmt()` → stderr, structured JSON format, env filter |
| **1.7** Cross-compilation CI | GitHub Actions workflow with targets: `aarch64-apple-darwin`, `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `i686-pc-windows-msvc`, `x86_64-pc-windows-msvc`. Use `cross` for Linux ARM64 |

**Deliverable**: A working MCP server that executes any command — no safety checks yet. Compiles for all 5 targets.

---

### Phase 2: Safety Engine (Weeks 3–4)

**Goal**: Implement the full command pipeline — classify, guard, gate.

| Task | Details |
|------|---------|
| **2.1** Command Parser module | Parse raw command string → tokenized struct. Handle pipes, chains (`&&`, `\|\|`, `;`). Detect redirection (`>`, `>>`). Resolve `~`, `$HOME`, env vars. Normalize to absolute paths |
| **2.2** OS-detection layer | `cfg(target_os)` based modules: `platform::macos`, `platform::linux`, `platform::windows`. Each provides `fn safe_commands() -> Vec<SafeCommand>` and `fn protected_paths() -> Vec<ProtectedPath>` |
| **2.3** Classifier module | Match command name against allowlist. If not in allowlist, classify as `Dangerous`. Additional heuristics: `sudo`/`doas`/runas → always dangerous; `rm`, `chmod`, `chown`, `mkfs`, `dd` → always dangerous; network commands (`curl`, `wget`, `nc`) → dangerous; package managers (`apt`, `brew`, `choco`) → dangerous |
| **2.4** Location Guard module | For each argument that looks like a path, resolve to absolute. Check against protected path prefixes. Differentiate read vs write operations. **Hard-block** violations with descriptive error |
| **2.5** Permission Gate (Elicitation) | Integrate `elicit::<CommandPermission>(...)` from the `rmcp` SDK. Define the `CommandPermission` schema. Handle `Accept`, `Decline`, `Cancel` actions. Fallback: if elicitation not supported → DENY |
| **2.6** `list_safe_commands` tool | Return the current OS's safe command list |
| **2.7** `list_protected_paths` tool | Return the current OS's protected path list |
| **2.8** Structured MCP logging | On every pipeline stage, send `notify_logging_message` with appropriate severity level (`Info` for safe, `Warning` for dangerous, `Error` for blocked) |

**Deliverable**: Full safety pipeline. Dangerous commands require user approval. Protected paths are hard-blocked. Every action is logged.

---

### Phase 3: Hardening & Polish (Weeks 5–6)

**Goal**: Production-readiness — edge cases, configuration, testing, documentation.

| Task | Details |
|------|---------|
| **3.1** Shell selection logic | macOS/Linux: try `$SHELL`, fallback to `/bin/sh`. Windows: try `cmd.exe`, detect PowerShell. Make configurable |
| **3.2** Chained command analysis | For `cmd1 && cmd2 \| cmd3`, classify **each sub-command** independently. If **any** sub-command is dangerous, the whole chain requires permission. If **any** sub-command is path-blocked, the whole chain is blocked |
| **3.3** Output size limits | Truncate stdout/stderr to configurable max (default: 100KB). Report truncation in response |
| **3.4** Configuration file | Load optional `safeshell.toml` from well-known paths (`./safeshell.toml`, `~/.config/safeshell/config.toml`, or env var `SAFESHELL_CONFIG`). Schema: additional safe commands, additional protected paths, default timeout, max output size, log file path, log level. Validate on startup, warn on invalid entries, never crash |
| **3.5** Symlink & path traversal protection | Before executing, resolve all paths through `std::fs::canonicalize()` to defeat symlink attacks. E.g., `cat /tmp/innocent_link` where the symlink points to `/etc/shadow` → resolve first, then check against protected paths |
| **3.6** Environment variable sanitization | Strip or redact sensitive env vars (`AWS_SECRET_ACCESS_KEY`, `DATABASE_URL`, `API_KEY`, etc.) from command output. Configurable redaction patterns via regex |
| **3.7** Concurrent execution guard | Limit simultaneous command executions (default: 1). Queue or reject excess requests. Prevents resource exhaustion from parallel tool invocations by the LLM |
| **3.8** Graceful shutdown | Handle `SIGINT`/`SIGTERM` (Unix) and `CTRL_C_EVENT` (Windows). Kill any running child processes. Flush all logs. Return clean exit code |
| **3.9** Comprehensive test suite | **Unit tests**: classifier, location guard, path resolution, parser for each OS. **Integration tests**: spin up the server in-process using `tokio::io::duplex` (as shown in the `rmcp` counter test pattern), send `tools/call` requests, verify behavior. **Platform-specific tests**: gated with `#[cfg(target_os = "...")]` |
| **3.10** MCP Inspector compatibility | Validate the server works with `npx @modelcontextprotocol/inspector`. Document the testing flow. Ensure all tool schemas are properly generated |

**Deliverable**: Hardened, configurable, thoroughly tested server ready for real-world usage.

---

### Phase 4: Distribution & Documentation (Week 7)

**Goal**: Ship it — binaries, documentation, and ecosystem integration.

| Task | Details |
|------|---------|
| **4.1** CI/CD release pipeline | GitHub Actions: on tag push → build for all 5 targets → create GitHub Release with pre-built binaries. Use `cargo-cross` for cross-compilation. Binary naming convention: `safeshell-mcp-{os}-{arch}[.exe]` |
| **4.2** Binary size optimization | `Cargo.toml` release profile: `opt-level = "z"`, `lto = true`, `codegen-units = 1`, `strip = true`, `panic = "abort"`. Target < 5MB per binary |
| **4.3** README & usage documentation | Quick start guide, configuration reference, tool API documentation, security model explanation, architecture diagram |
| **4.4** MCP client integration examples | Example `claude_desktop_config.json` for Claude Desktop. Example configurations for Cursor, VS Code with Continue, and other MCP hosts |
| **4.5** `SECURITY.md` | Threat model documentation. Known limitations (e.g., command injection via unchecked shell expansion). Responsible disclosure policy |
| **4.6** Crate publishing (optional) | Publish to `crates.io` as `safeshell-mcp` if desired. Ensure `Cargo.toml` metadata is complete |

**Deliverable**: Downloadable binaries for all platforms, comprehensive docs, and ready-to-use MCP configuration snippets.

---

## 📐 Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                        MCP Host (e.g., Claude Desktop)               │
│                                                                      │
│   ┌──────────┐     stdio (stdin/stdout)       ┌────────────────────┐ │
│   │MCP Client│◄════════════════════════════►  │  safeshell-mcp     │ │
│   └──────────┘                                │  (subprocess)      │ │
│        │                                      │                    │ │
│        │  elicitation/create                  │  ┌──────────────┐  │ │
│        │◄─────────────────────────────────────│──│ Permission   │  │ │
│        │  "Allow `rm -rf ./build`?"           │  │ Gate         │  │ │
│        │                                      │  └──────┬───────┘  │ │
│        │  {action: "accept"}                  │         │          │ │
│        │─────────────────────────────────────►│         ▼          │ │
│        │                                      │  ┌──────────────┐  │ │
│        │  notifications/message (logs)        │  │ Command      │  │ │
│        │◄─────────────────────────────────────│──│ Pipeline     │  │ │
│        │                                      │  └──────────────┘  │ │
│        │                                      │                    │ │
└────────┼──────────────────────────────────────┼────────────────────┘ │
         │                                      │                      │
         │                                      │  stderr ──► tracing  │
         │                                      │            audit log │
         │                                      └──────────────────────┘
```

```
                    ┌──────────────────────────────────────────────┐
                    │           Command Pipeline Internals         │
                    │                                              │
                    │  ┌────────┐   ┌──────────┐   ┌───────────┐   │
 tools/call ──────► │  │ Parse  │──►│ Classify │──►│ Location  │   │
 execute_command    │  │& Norm. │   │Safe/Dang.│   │  Guard    │   │
                    │  └────────┘   └──────────┘   └─────┬─────┘   │
                    │                                    │         │
                    │                              ┌─────▼─────┐   │
                    │                              │ Blocked?  │   │
                    │                              │ YES → Err │   │
                    │                              │ NO  ↓     │   │
                    │                              └─────┬─────┘   │
                    │                                    │         │
                    │              ┌─────────────────────▼──────┐  │
                    │              │ Safe?                      │  │
                    │              │ YES → Execute immediately  │  │
                    │              │ NO  → Elicit permission    │  │
                    │              └─────────────┬──────────────┘  │
                    │                            │                 │
                    │                     ┌──────▼──────┐          │
                    │                     │  Execute    │          │
                    │                     │  (tokio     │          │
                    │                     │  ::process) │          │
                    │                     └──────┬──────┘          │
                    │                            │                 │
                    │                     ┌──────▼──────┐          │
                    │                     │  Return     │          │
                    │                     │  Result     │──────►   │
                    │                     └─────────────┘          │
                    └──────────────────────────────────────────────┘
```

---

## 📦 Projected `Cargo.toml` Dependencies

```toml
[package]
name = "safeshell-mcp"
version = "0.1.0"
edition = "2024"
authors = ["An Nguyen <annguyen.apss@gmail.com>"]
description = "A safety-first shell command executor MCP server"
license = "MIT"

[dependencies]
rmcp = { version = "0.16", features = ["server"] }
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
schemars = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
toml = "0.8"                    # Config file parsing
dirs = "6"                      # Cross-platform path resolution (~, config dirs)
regex = "1"                     # Pattern matching for sensitive env vars
thiserror = "2"                 # Ergonomic error types

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
strip = true
panic = "abort"
```

---

## 🎯 CI Cross-Compilation Matrix

```yaml
# .github/workflows/release.yml (simplified)
strategy:
  matrix:
    include:
      - target: aarch64-apple-darwin
        os: macos-14             # Apple Silicon runner
        binary: safeshell-mcp-macos-arm64

      - target: x86_64-unknown-linux-gnu
        os: ubuntu-latest
        binary: safeshell-mcp-linux-x86_64

      - target: aarch64-unknown-linux-gnu
        os: ubuntu-latest
        use_cross: true
        binary: safeshell-mcp-linux-arm64

      - target: i686-pc-windows-msvc
        os: windows-latest
        binary: safeshell-mcp-windows-x86.exe

      - target: x86_64-pc-windows-msvc
        os: windows-latest
        binary: safeshell-mcp-windows-x86_64.exe
```

---

## 🔐 Security Model Summary

| Layer | Mechanism | Override Possible? |
|-------|-----------|-------------------|
| **Safe Allowlist** | Per-OS curated list of read-only/benign commands | Yes (via config) |
| **Dangerous Classification** | Everything not in allowlist + heuristic patterns | No (always gated) |
| **Protected Paths** | Hardcoded OS system directories | Additive only via config (cannot remove builtins) |
| **Symlink Resolution** | `canonicalize()` before path checking | No |
| **Permission Elicitation** | MCP elicitation → user must Accept | No (deny if unsupported) |
| **Execution Timeout** | `tokio::time::timeout` → `SIGKILL`/`TerminateProcess` | Yes (via config, capped) |
| **Output Redaction** | Regex-based sensitive env var stripping | Yes (via config) |
| **Concurrency Limit** | Semaphore-gated max parallel executions | Yes (via config) |

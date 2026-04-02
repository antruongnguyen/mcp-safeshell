# Security Policy

## Threat Model

SafeShell MCP Server is designed to let AI assistants execute shell commands while mitigating the risks of uncontrolled command execution. It is **not** a sandbox — it is a safety layer that reduces the attack surface.

### What SafeShell protects against

| Threat | Mitigation |
|--------|------------|
| **Accidental destructive commands** | Commands like `rm -rf /`, `chmod 777`, `dd` are classified as dangerous and require human approval via MCP elicitation |
| **Writes to system directories** | Protected path guard hard-blocks writes to `/etc`, `/boot`, `/System`, `C:\Windows`, etc. This cannot be overridden by the AI |
| **Symlink traversal** | Paths are canonicalized (resolved through symlinks) before guard checks, preventing bypass via `/tmp/link → /etc` |
| **Secret leakage in output** | Environment variables matching sensitive patterns (TOKEN, SECRET, API_KEY, PASSWORD, etc.) are automatically redacted from command output |
| **Runaway commands** | Configurable timeout (default 30s) kills long-running processes |
| **Resource exhaustion** | Semaphore-based concurrency limit (default 1), output size cap (default 100KB) |
| **Privilege escalation** | `sudo`, `doas`, `su`, `pkexec` are always classified as dangerous |
| **Chained command bypass** | Piped and chained commands (`cmd1 && cmd2`, `cmd1 | cmd2`) are analyzed per sub-command — if any sub-command is dangerous, the entire chain requires approval |

### What SafeShell does NOT protect against

| Non-threat | Explanation |
|------------|-------------|
| **Malicious user with shell access** | SafeShell guards AI-initiated commands. A user who can already run arbitrary commands doesn't need SafeShell |
| **Kernel exploits** | SafeShell runs in userspace. It cannot prevent kernel-level attacks |
| **Safe command misuse** | A command classified as "safe" (e.g., `cat`) can still read sensitive files if they aren't in a protected path. Configure `additional_protected_paths` for sensitive directories |
| **Environment variable names** | SafeShell redacts env var *values* from output, not the variable names themselves |
| **Network-level exfiltration** | If a safe command somehow sends data over the network, SafeShell won't block it. Network commands (`curl`, `wget`, etc.) are classified as dangerous |
| **Side-channel attacks** | Timing attacks, covert channels, etc. are out of scope |

### Trust boundaries

```
┌─────────────────────────────────────────┐
│  AI Assistant (MCP Client)              │
│  - Can request command execution        │
│  - Cannot bypass classification         │
│  - Cannot override protected paths      │
└──────────────┬──────────────────────────┘
               │ MCP Protocol (stdio/HTTP)
┌──────────────▼──────────────────────────┐
│  SafeShell MCP Server                   │
│  ┌─────────────────────────────────┐    │
│  │ Parse → Classify → Guard → Gate │    │
│  └─────────────┬───────────────────┘    │
│                │ (approved only)         │
│  ┌─────────────▼───────────────────┐    │
│  │ Execute (shell subprocess)      │    │
│  │ - Timeout enforced              │    │
│  │ - Output truncated & sanitized  │    │
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│  Operating System                       │
│  - File system, processes, network      │
│  - Standard OS-level permissions apply  │
└─────────────────────────────────────────┘
```

### Design principles

1. **Deny by default** — any command not in the safe allowlist is classified as dangerous
2. **Hard blocks can't be overridden** — protected path violations are rejected, not prompted
3. **Human approval for risk** — dangerous commands use MCP elicitation to get user consent
4. **Defense in depth** — multiple independent checks (classification + path guard + permission gate)
5. **Minimal trust in AI** — the server doesn't trust the AI client to self-police

## Configuration hardening

For production use, consider:

```toml
# Restrict concurrency
max_concurrency = 1

# Shorter timeout
default_timeout_seconds = 15

# Smaller output limit
max_output_bytes = 51200

# Protect application data
[[additional_protected_paths]]
path = "/var/lib/myapp/data"
read_allowed = true

[[additional_protected_paths]]
path = "/etc/myapp"
read_allowed = false
```

## Reporting vulnerabilities

If you discover a security vulnerability in SafeShell, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email the maintainers with details of the vulnerability
3. Include steps to reproduce if possible
4. Allow reasonable time for a fix before public disclosure

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

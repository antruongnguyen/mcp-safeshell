# Security Policy

## Overview

SafeShell MCP Server is a safety layer that interposes between AI assistants (MCP clients) and the host operating system's shell. It is **not** a sandbox, container, or privilege-boundary enforcer. Its purpose is to reduce the attack surface of AI-initiated command execution through classification, path guarding, and human-in-the-loop approval.

## Threat Model

### Actors

| Actor | Trust Level | Description |
|-------|-------------|-------------|
| **AI assistant (MCP client)** | Untrusted | Can request arbitrary commands. SafeShell assumes the AI may be jailbroken, confused, or deliberately adversarial. |
| **Human operator** | Trusted | Reviews dangerous command prompts and makes approval decisions. The security model depends on the human exercising good judgment. |
| **SafeShell server** | Trusted (TCB) | Part of the trusted computing base. A bug here breaks the security model. |
| **Host OS** | Out of scope | Standard OS permissions apply. SafeShell runs with the same privileges as the user who launched it. |

### What SafeShell protects against

| Threat | Mitigation | Pipeline Stage |
|--------|------------|----------------|
| **Accidental destructive commands** | `rm -rf /`, `chmod 777`, `dd`, `shred`, `truncate`, etc. are classified as dangerous and require human approval via MCP elicitation | Classifier (Stage 2) |
| **Writes to system directories** | Hard-blocks writes to `/etc`, `/boot`, `/System`, `/usr/bin`, `/sbin`, `/Library/LaunchDaemons`, `C:\Windows`, `C:\Program Files`, etc. This cannot be overridden by the AI | Location Guard (Stage 3) |
| **Symlink traversal** | Paths are canonicalized (resolved through symlinks) before guard checks, preventing bypass via `/tmp/link -> /etc` | Location Guard (Stage 3) |
| **Chained symlink traversal** | Multi-hop symlink chains (link1 -> link2 -> /etc/hosts) are resolved through full `fs::canonicalize` | Location Guard (Stage 3) |
| **Null byte injection** | Paths containing `\0` are rejected outright, preventing C-string truncation attacks | Location Guard (Stage 3) |
| **`/proc/self/root` traversal** (Linux) | Paths matching `/proc/self/root/...` or `/proc/<pid>/root/...` are blocked, preventing chroot/container escapes | Location Guard (Stage 3) |
| **Secret leakage in output** | Environment variables matching sensitive patterns (`TOKEN`, `SECRET`, `API_KEY`, `PASSWORD`, `CREDENTIAL`, `DATABASE_URL`, `CONNECTION_STRING`, `SMTP`, etc.) are automatically redacted from command output | Sanitizer |
| **Redirection to protected paths** | Redirection targets (`> /etc/shadow`, `2> /var/log/auth.log`) are extracted during parsing and checked by the location guard | Parser (Stage 1) + Location Guard (Stage 3) |
| **Runaway commands** | Configurable timeout (default 30s) kills long-running processes | Execution (Stage 5) |
| **Resource exhaustion** | Semaphore-based concurrency limit (default 1), per-stream output size cap (default 100KB) | Concurrency Guard + Execution |
| **Privilege escalation** | `sudo`, `doas`, `su`, `pkexec`, `runas` are always classified as dangerous | Classifier (Stage 2) |
| **Chained command bypass** | Piped and chained commands (`cmd1 && cmd2`, `cmd1 | cmd2`, `cmd1 ; cmd2`, `cmd1 || cmd2`) are split and classified per sub-command. If any sub-command is dangerous, the entire chain requires approval | Parser (Stage 1) + Classifier (Stage 2) |
| **Shell interpreter invocation** | `bash`, `sh`, `zsh`, `python`, `node`, `ruby`, `perl`, etc. are classified as dangerous, preventing escape-to-shell attacks | Classifier (Stage 2) |
| **Orphaned child processes** | Tracked via `ChildTracker`; all children are killed on graceful shutdown (SIGINT/SIGTERM) | Shutdown handler |

### What SafeShell does NOT protect against

| Non-threat | Explanation |
|------------|-------------|
| **Malicious user with shell access** | SafeShell guards AI-initiated commands. A user who can already run arbitrary commands doesn't need SafeShell. |
| **Kernel exploits** | SafeShell runs in userspace. It cannot prevent kernel-level attacks. |
| **Safe command misuse** | A command classified as "safe" (e.g., `cat`) can still read sensitive files if they aren't in a protected path. Configure `additional_protected_paths` for sensitive directories. |
| **Environment variable names** | SafeShell redacts env var *values* from output, not the variable names themselves. |
| **Network exfiltration via safe commands** | If a safe command sends data over the network through an unexpected mechanism, SafeShell won't block it. Network commands (`curl`, `wget`, `ssh`, etc.) are classified as dangerous. |
| **Side-channel attacks** | Timing attacks, covert channels, power analysis, etc. are out of scope. |
| **Subshell expansion in arguments** | See [Known Limitations](#known-limitations) below. |
| **Process-level isolation** | SafeShell does not use namespaces, seccomp, or containers. The child process inherits the server's full environment and privileges. |
| **stdin injection** | Child processes have stdin connected to `/dev/null`, but this only prevents interactive input — it does not prevent all forms of input-based attacks. |
| **Signal-based attacks** | If an attacker can send signals to the SafeShell process or its children, SafeShell has no special defenses beyond standard OS protections. |

### Trust boundaries

```
+----------------------------------------------+
|  AI Assistant (MCP Client)                   |
|  - Can request command execution             |
|  - Cannot bypass classification              |
|  - Cannot override protected paths           |
|  - Cannot suppress elicitation prompts       |
+-----------------+----------------------------+
                  | MCP Protocol (stdio or HTTP)
+-----------------v----------------------------+
|  SafeShell MCP Server                        |
|  +----------------------------------------+  |
|  | Stage 1: Parser                        |  |
|  |   Split chains, tokenize, resolve ~,   |  |
|  |   extract redirection targets          |  |
|  +--------------------+-------------------+  |
|                       v                      |
|  +----------------------------------------+  |
|  | Stage 2: Classifier                    |  |
|  |   Per-command: safe allowlist check,   |  |
|  |   always-dangerous categories,         |  |
|  |   deny-by-default for unknowns        |  |
|  +--------------------+-------------------+  |
|                       v                      |
|  +----------------------------------------+  |
|  | Stage 3: Location Guard                |  |
|  |   Canonicalize paths (symlink resolve),|  |
|  |   null byte check, /proc/*/root check, |  |
|  |   prefix match against protected list  |  |
|  |   HARD BLOCK (no override)             |  |
|  +--------------------+-------------------+  |
|                       v                      |
|  +----------------------------------------+  |
|  | Stage 4: Permission Gate               |  |
|  |   MCP elicitation for dangerous cmds   |  |
|  |   Default: DENY if unsupported         |  |
|  +--------------------+-------------------+  |
|                       v (approved only)      |
|  +----------------------------------------+  |
|  | Stage 5: Execute                       |  |
|  |   Shell subprocess with:               |  |
|  |   - Timeout enforcement                |  |
|  |   - Output truncation (per-stream cap) |  |
|  |   - Secret redaction (env var values)  |  |
|  |   - Child PID tracking                 |  |
|  +----------------------------------------+  |
+----------------------------------------------+
                  |
+-----------------v----------------------------+
|  Operating System                            |
|  - File system, processes, network           |
|  - Standard OS-level permissions apply       |
+----------------------------------------------+
```

### Design principles

1. **Deny by default** -- any command not in the safe allowlist is classified as dangerous
2. **Hard blocks can't be overridden** -- protected path violations are rejected, not prompted
3. **Human approval for risk** -- dangerous commands use MCP elicitation to get user consent; if elicitation is unavailable, the default is DENY
4. **Defense in depth** -- multiple independent checks (classification + path guard + permission gate) form a layered defense
5. **Minimal trust in AI** -- the server assumes the AI client is untrusted and may be adversarial
6. **Fail closed** -- on error (elicitation failure, timeout, concurrency exhaustion), the safe default is to reject

## Known Limitations

### 1. Shell expansion and command substitution

SafeShell parses commands with a simplified tokenizer, not the shell's actual parser. This means:

- **Command substitution** (`$(...)` and backtick syntax) is not evaluated by SafeShell's parser. The substituted content is only resolved at shell execution time, after SafeShell's safety checks have already passed.
  - Example: `cat $(echo /etc/shadow)` -- SafeShell sees the literal string `$(echo /etc/shadow)` as an argument, not `/etc/shadow`. The path guard cannot catch this.
- **Variable expansion** (`$VAR`, `${VAR}`) is similarly opaque to SafeShell. A command like `rm $TARGET` bypasses path checking because the variable is only expanded by the shell at runtime.
- **Glob expansion** (`*`, `?`, `[...]`) is handled by the shell, not SafeShell. The parser sees literal glob characters.
- **Brace expansion** (`{a,b,c}`, `{1..10}`) is handled by the shell.
- **Process substitution** (`<(cmd)`, `>(cmd)`) is handled by the shell.

**Mitigation**: The deny-by-default classifier means most commands that could be weaponized through expansion (e.g., `rm`, `chmod`, `dd`) already require human approval. However, a safe command like `cat` could be tricked into reading sensitive files via substitution if those files are not in a protected path.

### 2. Parser vs. shell divergence

SafeShell's tokenizer handles single/double quotes and common operators (`&&`, `||`, `|`, `;`, `>`, `>>`, `<`, `2>`), but it does not replicate the full POSIX shell grammar. Edge cases include:

- **Heredocs** (`<<EOF ... EOF`) are not parsed
- **Nested quoting** (e.g., `"$(echo 'inner')"`) may not be fully resolved
- **Escape sequences** (`\"`, `\\`, `\n`) are not processed
- **Arithmetic expansion** (`$((1+1))`) is opaque

### 3. Path detection heuristics

SafeShell identifies path-like arguments using heuristics (contains `/` or `\`, starts with `.` or `~`, or is absolute). Arguments that are actually paths but don't match these patterns (e.g., passed via `--file=target`) are not checked by the location guard.

### 4. Safe command misuse

Commands classified as "safe" (read-only utilities like `cat`, `head`, `tail`, `ls`) can still read sensitive files. The safe classification means "does not modify system state," not "cannot access sensitive data." Use `additional_protected_paths` with `read_allowed: false` to restrict read access to sensitive directories.

### 5. Output redaction is value-based

The sanitizer redacts environment variable *values* found in command output. This has limitations:

- Values shorter than 4 characters are skipped to avoid false positives
- If a secret value is a common word or substring, there may be false-positive redactions
- The redaction is based on the server's environment at startup; secrets set afterward are not covered
- Variable *names* are not redacted, only their values
- Partial matches within longer strings will still be redacted (longest-first ordering)

### 6. No network-level controls

SafeShell classifies network commands (`curl`, `wget`, `ssh`, etc.) as dangerous, but it does not enforce network-level restrictions. If a safe command somehow initiates network activity, SafeShell will not detect or block it.

### 7. Single-user trust model

SafeShell assumes a single human operator. It does not support multi-user access control, per-user policies, or audit trails tied to user identity.

### 8. Race conditions (TOCTOU)

There is an inherent time-of-check-to-time-of-use gap between when SafeShell checks paths and when the shell actually accesses them. A symlink could theoretically be swapped between the check and the execution. This is a fundamental limitation of any userspace safety layer that delegates execution to a subprocess.

## Configuration Hardening

For production use, consider:

```toml
# Restrict concurrency to prevent parallel abuse
max_concurrency = 1

# Shorter timeout to limit blast radius
default_timeout_seconds = 15

# Smaller output limit
max_output_bytes = 51200

# Add custom redaction patterns
redact_env_patterns = ["(?i)MY_APP_.*"]

# Protect application data directories
[[additional_protected_paths]]
path = "/var/lib/myapp/data"
read_allowed = true

[[additional_protected_paths]]
path = "/etc/myapp"
read_allowed = false

# Protect credentials
[[additional_protected_paths]]
path = "/home/deploy/.ssh"
read_allowed = false

[[additional_protected_paths]]
path = "/home/deploy/.aws"
read_allowed = false
```

### Transport security

- **stdio transport**: Suitable for local use where the MCP client and server run on the same machine. No network exposure.
- **HTTP transport**: Binds to `127.0.0.1:3456` by default. For remote access, use a TLS-terminating reverse proxy. SafeShell does not implement TLS natively. Do not bind to `0.0.0.0` without additional authentication and encryption.

## Reporting Vulnerabilities

If you discover a security vulnerability in SafeShell, please report it responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities
2. Email the maintainers at the address listed in `Cargo.toml` with:
   - Description of the vulnerability
   - Steps to reproduce
   - Impact assessment
   - Suggested fix (if any)
3. You will receive an acknowledgment within 48 hours
4. We aim to release a fix within 7 days for critical vulnerabilities
5. Please allow 90 days before public disclosure to give users time to upgrade
6. We will credit reporters in the release notes (unless anonymity is requested)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes (current) |

Only the latest release receives security patches. We recommend always running the latest version.

## Security Audit Status

SafeShell has not undergone a formal third-party security audit. The threat model and mitigations described above represent the development team's best-effort analysis. Community review is welcome and encouraged.

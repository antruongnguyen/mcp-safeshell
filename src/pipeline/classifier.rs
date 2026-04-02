//! Stage 2: Command Classifier
//!
//! Determines whether each sub-command is Safe or Dangerous.
//! For chained commands, classifies each independently and aggregates:
//! if any sub-command is dangerous, the whole chain is dangerous.

use super::parser::ParsedCommand;
use crate::platform;

/// Classification result for a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classification {
    Safe,
    Dangerous { reason: String },
}

/// Per-sub-command classification detail (used for chain analysis reporting).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SubCommandClassification {
    /// The command name.
    pub command: String,
    /// Index of this sub-command within the chain (0-based).
    pub index: usize,
    /// The raw text of this sub-command.
    pub raw: String,
    /// Classification result.
    pub classification: Classification,
}

/// Aggregate result of classifying a chain of commands.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ChainClassification {
    /// The aggregate classification (dangerous if any sub-command is dangerous).
    pub aggregate: Classification,
    /// Per-sub-command details.
    pub details: Vec<SubCommandClassification>,
    /// Whether this was a chained command (more than one sub-command).
    pub is_chained: bool,
    /// Commands that were pre-approved via `additional_safe_commands` (Tier 2
    /// dangerous commands that the user has whitelisted).
    pub preapproved_commands: Vec<String>,
}

/// Returns `true` if the command is **catastrophic** (Tier 1) — too destructive
/// to ever be auto-approved via `additional_safe_commands`.
///
/// Tier 1 commands: privilege escalation, disk destruction, system control.
pub fn is_catastrophic(name: &str) -> bool {
    // Privilege escalation
    if matches!(name, "sudo" | "su" | "doas" | "pkexec" | "runas") {
        return true;
    }
    // Disk destruction
    if matches!(name, "mkfs" | "dd" | "shred" | "fdisk" | "parted" | "lvm") {
        return true;
    }
    // System control
    if matches!(name, "shutdown" | "reboot" | "halt" | "poweroff" | "init") {
        return true;
    }
    false
}

/// Returns `true` if the command name belongs to a hardcoded always-dangerous
/// category (privilege escalation, destructive file ops, network, package
/// managers, system control, disk ops, shell interpreters).
///
/// This covers both Tier 1 (catastrophic) and Tier 2 (whitelistable) commands.
/// Use `is_catastrophic()` to check only Tier 1.
#[allow(dead_code)]
pub fn is_always_dangerous(name: &str) -> bool {
    // Tier 1: catastrophic (never whitelistable)
    if is_catastrophic(name) {
        return true;
    }
    // Tier 2: whitelistable dangerous commands
    // Destructive file operations
    if matches!(
        name,
        "rm" | "rmdir" | "chmod" | "chown" | "chgrp" | "truncate"
    ) {
        return true;
    }
    // Network commands
    if matches!(
        name,
        "curl" | "wget" | "nc" | "ncat" | "netcat" | "ssh" | "scp" | "sftp" | "rsync" | "ftp"
    ) {
        return true;
    }
    // Package managers
    if matches!(
        name,
        "apt" | "apt-get" | "yum" | "dnf" | "pacman" | "brew" | "choco" | "pip" | "npm" | "cargo"
    ) {
        return true;
    }
    // System services and process control
    if matches!(
        name,
        "systemctl" | "launchctl" | "kill" | "killall" | "pkill" | "mount" | "umount"
    ) {
        return true;
    }
    // Shell interpreters
    if matches!(
        name,
        "bash"
            | "sh"
            | "zsh"
            | "fish"
            | "csh"
            | "tcsh"
            | "dash"
            | "ksh"
            | "python"
            | "python3"
            | "perl"
            | "ruby"
            | "node"
    ) {
        return true;
    }
    false
}

/// Classify a parsed command.
pub fn classify(cmd: &ParsedCommand) -> Classification {
    let name = cmd.command.as_str();

    // Always-dangerous: privilege escalation
    if matches!(name, "sudo" | "doas" | "su" | "runas" | "pkexec") {
        return Classification::Dangerous {
            reason: format!("Privilege escalation command: {name}"),
        };
    }

    // Always-dangerous: destructive file operations
    if matches!(
        name,
        "rm" | "rmdir" | "chmod" | "chown" | "chgrp" | "mkfs" | "dd" | "shred" | "truncate"
    ) {
        return Classification::Dangerous {
            reason: format!("Destructive file operation: {name}"),
        };
    }

    // Always-dangerous: network commands
    if matches!(
        name,
        "curl" | "wget" | "nc" | "ncat" | "netcat" | "ssh" | "scp" | "sftp" | "rsync" | "ftp"
    ) {
        return Classification::Dangerous {
            reason: format!("Network command: {name}"),
        };
    }

    // Always-dangerous: package managers
    if matches!(
        name,
        "apt" | "apt-get" | "yum" | "dnf" | "pacman" | "brew" | "choco" | "pip" | "npm" | "cargo"
    ) {
        return Classification::Dangerous {
            reason: format!("Package manager: {name}"),
        };
    }

    // Always-dangerous: system control
    if matches!(
        name,
        "shutdown"
            | "reboot"
            | "halt"
            | "poweroff"
            | "init"
            | "systemctl"
            | "launchctl"
            | "kill"
            | "killall"
            | "pkill"
    ) {
        return Classification::Dangerous {
            reason: format!("System control command: {name}"),
        };
    }

    // Always-dangerous: disk/mount operations
    if matches!(name, "mount" | "umount" | "fdisk" | "parted" | "lvm") {
        return Classification::Dangerous {
            reason: format!("Disk operation: {name}"),
        };
    }

    // Always-dangerous: shell interpreters (can run anything)
    if matches!(
        name,
        "bash"
            | "sh"
            | "zsh"
            | "fish"
            | "csh"
            | "tcsh"
            | "dash"
            | "ksh"
            | "python"
            | "python3"
            | "perl"
            | "ruby"
            | "node"
    ) {
        return Classification::Dangerous {
            reason: format!("Shell/interpreter: {name}"),
        };
    }

    // Check against safe allowlist
    if platform::is_safe_command(name) {
        return Classification::Safe;
    }

    // Default: anything not explicitly safe is dangerous
    Classification::Dangerous {
        reason: format!("Command '{name}' is not in the safe allowlist"),
    }
}

/// Classify all sub-commands independently, producing per-command details
/// and an aggregate result.
///
/// If any sub-command is Dangerous (and not overridden by `additional_safe`),
/// the whole chain is classified as Dangerous.
///
/// `additional_safe` lists extra command names (from config) that should be
/// treated as safe beyond the built-in platform allowlist.
pub fn classify_chain(
    cmds: &[ParsedCommand],
    additional_safe: &[String],
    is_chained: bool,
) -> ChainClassification {
    let mut details = Vec::with_capacity(cmds.len());
    let mut aggregate_reasons = Vec::new();
    let mut preapproved_commands = Vec::new();

    for (index, cmd) in cmds.iter().enumerate() {
        let mut classification = classify(cmd);

        // Override if command is in the additional safe list, but NEVER
        // override Tier 1 (catastrophic) commands.
        if matches!(classification, Classification::Dangerous { .. })
            && additional_safe.iter().any(|s| s == &cmd.command)
        {
            if is_catastrophic(&cmd.command) {
                tracing::warn!(
                    command = %cmd.command,
                    "ignoring additional_safe_commands override for catastrophic command \
                     (Tier 1: privilege escalation, disk destruction, or system control)"
                );
            } else {
                preapproved_commands.push(cmd.command.clone());
                classification = Classification::Safe;
            }
        }

        if let Classification::Dangerous { ref reason } = classification {
            aggregate_reasons.push(format!("[{}] {}: {}", index + 1, cmd.command, reason));
        }

        details.push(SubCommandClassification {
            command: cmd.command.clone(),
            index,
            raw: cmd.raw.clone(),
            classification,
        });
    }

    let aggregate = if aggregate_reasons.is_empty() {
        Classification::Safe
    } else {
        Classification::Dangerous {
            reason: aggregate_reasons.join("; "),
        }
    };

    ChainClassification {
        aggregate,
        details,
        is_chained,
        preapproved_commands,
    }
}

/// Classify all sub-commands. Returns the most restrictive classification
/// (if any is Dangerous, the whole chain is Dangerous).
///
/// `additional_safe` lists extra command names (from config) that should be
/// treated as safe beyond the built-in platform allowlist.
#[allow(dead_code)]
pub fn classify_all(cmds: &[ParsedCommand], additional_safe: &[String]) -> Classification {
    classify_chain(cmds, additional_safe, cmds.len() > 1).aggregate
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::parser::ParsedCommand;

    fn cmd(name: &str, args: &[&str]) -> ParsedCommand {
        ParsedCommand {
            command: name.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            resolved_paths: Vec::new(),
            raw: format!("{} {}", name, args.join(" ")),
        }
    }

    // ── Safe commands ──────────────────────────────────────────────

    #[test]
    fn safe_echo() {
        assert_eq!(classify(&cmd("echo", &["hello"])), Classification::Safe);
    }

    #[test]
    fn safe_ls() {
        assert_eq!(classify(&cmd("ls", &["-la"])), Classification::Safe);
    }

    #[test]
    fn safe_cat() {
        assert_eq!(classify(&cmd("cat", &["file.txt"])), Classification::Safe);
    }

    #[test]
    fn safe_whoami() {
        assert_eq!(classify(&cmd("whoami", &[])), Classification::Safe);
    }

    #[test]
    fn safe_pwd() {
        assert_eq!(classify(&cmd("pwd", &[])), Classification::Safe);
    }

    #[test]
    fn safe_uname() {
        assert_eq!(classify(&cmd("uname", &["-a"])), Classification::Safe);
    }

    #[test]
    fn safe_hostname() {
        assert_eq!(classify(&cmd("hostname", &[])), Classification::Safe);
    }

    #[test]
    fn safe_which() {
        assert_eq!(classify(&cmd("which", &["bash"])), Classification::Safe);
    }

    #[test]
    fn safe_printenv() {
        assert_eq!(classify(&cmd("printenv", &[])), Classification::Safe);
    }

    #[test]
    fn safe_head() {
        assert_eq!(classify(&cmd("head", &["-n", "10"])), Classification::Safe);
    }

    #[test]
    fn safe_tail() {
        assert_eq!(classify(&cmd("tail", &["-f"])), Classification::Safe);
    }

    #[test]
    fn safe_wc() {
        assert_eq!(classify(&cmd("wc", &["-l"])), Classification::Safe);
    }

    #[test]
    fn safe_df() {
        assert_eq!(classify(&cmd("df", &["-h"])), Classification::Safe);
    }

    #[test]
    fn safe_uptime() {
        assert_eq!(classify(&cmd("uptime", &[])), Classification::Safe);
    }

    #[test]
    fn safe_date() {
        assert_eq!(classify(&cmd("date", &[])), Classification::Safe);
    }

    // ── Privilege escalation (always dangerous) ────────────────────

    #[test]
    fn dangerous_sudo() {
        let c = classify(&cmd("sudo", &["rm", "-rf", "/"]));
        assert!(matches!(c, Classification::Dangerous { .. }));
        if let Classification::Dangerous { reason } = c {
            assert!(reason.contains("Privilege escalation"));
        }
    }

    #[test]
    fn dangerous_doas() {
        assert!(matches!(
            classify(&cmd("doas", &["ls"])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn dangerous_su() {
        assert!(matches!(
            classify(&cmd("su", &["-"])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn dangerous_pkexec() {
        assert!(matches!(
            classify(&cmd("pkexec", &["vim"])),
            Classification::Dangerous { .. }
        ));
    }

    // ── Destructive file operations ────────────────────────────────

    #[test]
    fn dangerous_rm() {
        let c = classify(&cmd("rm", &["-rf", "/"]));
        assert!(matches!(c, Classification::Dangerous { .. }));
        if let Classification::Dangerous { reason } = c {
            assert!(reason.contains("Destructive file operation"));
        }
    }

    #[test]
    fn dangerous_rmdir() {
        assert!(matches!(
            classify(&cmd("rmdir", &["/tmp/dir"])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn dangerous_chmod() {
        assert!(matches!(
            classify(&cmd("chmod", &["777", "file"])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn dangerous_chown() {
        assert!(matches!(
            classify(&cmd("chown", &["root", "file"])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn dangerous_dd() {
        assert!(matches!(
            classify(&cmd("dd", &["if=/dev/zero", "of=/dev/sda"])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn dangerous_shred() {
        assert!(matches!(
            classify(&cmd("shred", &["file"])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn dangerous_truncate() {
        assert!(matches!(
            classify(&cmd("truncate", &["-s", "0", "file"])),
            Classification::Dangerous { .. }
        ));
    }

    // ── Network commands ───────────────────────────────────────────

    #[test]
    fn dangerous_curl() {
        let c = classify(&cmd("curl", &["evil.com"]));
        assert!(matches!(c, Classification::Dangerous { .. }));
        if let Classification::Dangerous { reason } = c {
            assert!(reason.contains("Network"));
        }
    }

    #[test]
    fn dangerous_wget() {
        assert!(matches!(
            classify(&cmd("wget", &["evil.com"])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn dangerous_nc() {
        assert!(matches!(
            classify(&cmd("nc", &["-l", "4444"])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn dangerous_ssh() {
        assert!(matches!(
            classify(&cmd("ssh", &["user@host"])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn dangerous_scp() {
        assert!(matches!(
            classify(&cmd("scp", &["file", "user@host:/path"])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn dangerous_rsync() {
        assert!(matches!(
            classify(&cmd("rsync", &["-avz", "src/", "dest/"])),
            Classification::Dangerous { .. }
        ));
    }

    // ── Package managers ───────────────────────────────────────────

    #[test]
    fn dangerous_apt() {
        let c = classify(&cmd("apt", &["install", "vim"]));
        assert!(matches!(c, Classification::Dangerous { .. }));
        if let Classification::Dangerous { reason } = c {
            assert!(reason.contains("Package manager"));
        }
    }

    #[test]
    fn dangerous_brew() {
        assert!(matches!(
            classify(&cmd("brew", &["install", "node"])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn dangerous_pip() {
        assert!(matches!(
            classify(&cmd("pip", &["install", "requests"])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn dangerous_npm() {
        assert!(matches!(
            classify(&cmd("npm", &["install"])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn dangerous_cargo() {
        assert!(matches!(
            classify(&cmd("cargo", &["build"])),
            Classification::Dangerous { .. }
        ));
    }

    // ── System control ─────────────────────────────────────────────

    #[test]
    fn dangerous_shutdown() {
        let c = classify(&cmd("shutdown", &["-h", "now"]));
        assert!(matches!(c, Classification::Dangerous { .. }));
        if let Classification::Dangerous { reason } = c {
            assert!(reason.contains("System control"));
        }
    }

    #[test]
    fn dangerous_kill() {
        assert!(matches!(
            classify(&cmd("kill", &["-9", "1234"])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn dangerous_systemctl() {
        assert!(matches!(
            classify(&cmd("systemctl", &["restart", "nginx"])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn dangerous_launchctl() {
        assert!(matches!(
            classify(&cmd("launchctl", &["load"])),
            Classification::Dangerous { .. }
        ));
    }

    // ── Disk/mount operations ──────────────────────────────────────

    #[test]
    fn dangerous_mount() {
        let c = classify(&cmd("mount", &["/dev/sda1", "/mnt"]));
        assert!(matches!(c, Classification::Dangerous { .. }));
        if let Classification::Dangerous { reason } = c {
            assert!(reason.contains("Disk"));
        }
    }

    #[test]
    fn dangerous_fdisk() {
        assert!(matches!(
            classify(&cmd("fdisk", &["/dev/sda"])),
            Classification::Dangerous { .. }
        ));
    }

    // ── Shell interpreters ─────────────────────────────────────────

    #[test]
    fn dangerous_bash() {
        let c = classify(&cmd("bash", &["-c", "echo hi"]));
        assert!(matches!(c, Classification::Dangerous { .. }));
        if let Classification::Dangerous { reason } = c {
            assert!(reason.contains("Shell/interpreter"));
        }
    }

    #[test]
    fn dangerous_sh() {
        assert!(matches!(
            classify(&cmd("sh", &["-c", "echo hi"])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn dangerous_python() {
        assert!(matches!(
            classify(&cmd("python", &["-c", "print('hi')"])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn dangerous_python3() {
        assert!(matches!(
            classify(&cmd("python3", &["script.py"])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn dangerous_node() {
        assert!(matches!(
            classify(&cmd("node", &["app.js"])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn dangerous_ruby() {
        assert!(matches!(
            classify(&cmd("ruby", &["-e", "puts 'hi'"])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn dangerous_perl() {
        assert!(matches!(
            classify(&cmd("perl", &["-e", "print 'hi'"])),
            Classification::Dangerous { .. }
        ));
    }

    // ── Unknown commands default to dangerous ──────────────────────

    #[test]
    fn unknown_is_dangerous() {
        let c = classify(&cmd("my_custom_script", &[]));
        assert!(matches!(c, Classification::Dangerous { .. }));
        if let Classification::Dangerous { reason } = c {
            assert!(reason.contains("not in the safe allowlist"));
        }
    }

    #[test]
    fn unknown_with_path_like_name() {
        assert!(matches!(
            classify(&cmd("./run.sh", &[])),
            Classification::Dangerous { .. }
        ));
    }

    // ── classify_all ───────────────────────────────────────────────

    #[test]
    fn classify_all_mixed_is_dangerous() {
        let cmds = vec![cmd("echo", &["hello"]), cmd("rm", &["-rf", "/tmp/x"])];
        assert!(matches!(
            classify_all(&cmds, &[]),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn classify_all_all_safe() {
        let cmds = vec![cmd("echo", &["hello"]), cmd("ls", &["-la"])];
        assert_eq!(classify_all(&cmds, &[]), Classification::Safe);
    }

    #[test]
    fn classify_all_additional_safe_overrides() {
        let cmds = vec![cmd("my_custom_script", &["--flag"])];
        assert!(matches!(
            classify_all(&cmds, &[]),
            Classification::Dangerous { .. }
        ));

        let additional = vec!["my_custom_script".to_string()];
        assert_eq!(classify_all(&cmds, &additional), Classification::Safe);
    }

    #[test]
    fn classify_all_empty_commands() {
        let cmds: Vec<ParsedCommand> = Vec::new();
        assert_eq!(classify_all(&cmds, &[]), Classification::Safe);
    }

    #[test]
    fn classify_all_single_safe() {
        let cmds = vec![cmd("whoami", &[])];
        assert_eq!(classify_all(&cmds, &[]), Classification::Safe);
    }

    #[test]
    fn classify_all_single_dangerous() {
        let cmds = vec![cmd("rm", &["-rf", "/"])];
        assert!(matches!(
            classify_all(&cmds, &[]),
            Classification::Dangerous { .. }
        ));
    }

    // ── classify_chain details ─────────────────────────────────────

    #[test]
    fn chain_classification_details() {
        let cmds = vec![
            cmd("echo", &["hello"]),
            cmd("rm", &["-rf", "/tmp/x"]),
            cmd("ls", &["-la"]),
        ];
        let result = classify_chain(&cmds, &[], true);

        assert!(result.is_chained);
        assert!(matches!(result.aggregate, Classification::Dangerous { .. }));
        assert_eq!(result.details.len(), 3);

        assert_eq!(result.details[0].command, "echo");
        assert_eq!(result.details[0].index, 0);
        assert!(matches!(
            result.details[0].classification,
            Classification::Safe
        ));

        assert_eq!(result.details[1].command, "rm");
        assert_eq!(result.details[1].index, 1);
        assert!(matches!(
            result.details[1].classification,
            Classification::Dangerous { .. }
        ));

        assert_eq!(result.details[2].command, "ls");
        assert_eq!(result.details[2].index, 2);
        assert!(matches!(
            result.details[2].classification,
            Classification::Safe
        ));
    }

    #[test]
    fn chain_all_safe() {
        let cmds = vec![cmd("echo", &["a"]), cmd("ls", &["-la"]), cmd("cat", &["f"])];
        let result = classify_chain(&cmds, &[], true);

        assert!(matches!(result.aggregate, Classification::Safe));
        assert!(
            result
                .details
                .iter()
                .all(|d| matches!(d.classification, Classification::Safe))
        );
    }

    #[test]
    fn chain_multiple_dangerous() {
        let cmds = vec![
            cmd("rm", &["-rf", "/"]),
            cmd("curl", &["evil.com"]),
            cmd("echo", &["done"]),
        ];
        let result = classify_chain(&cmds, &[], true);

        assert!(matches!(result.aggregate, Classification::Dangerous { .. }));

        let dangerous_count = result
            .details
            .iter()
            .filter(|d| matches!(d.classification, Classification::Dangerous { .. }))
            .count();
        assert_eq!(dangerous_count, 2);
    }

    #[test]
    fn chain_additional_safe_override() {
        let cmds = vec![cmd("echo", &["hello"]), cmd("my_tool", &["--flag"])];
        let additional = vec!["my_tool".to_string()];
        let result = classify_chain(&cmds, &additional, true);

        assert!(matches!(result.aggregate, Classification::Safe));
        assert!(matches!(
            result.details[1].classification,
            Classification::Safe
        ));
    }

    #[test]
    fn chain_reason_includes_index() {
        let cmds = vec![cmd("echo", &["hello"]), cmd("rm", &["-rf", "/"])];
        let result = classify_chain(&cmds, &[], true);
        if let Classification::Dangerous { reason } = &result.aggregate {
            assert!(reason.contains("[2]"));
            assert!(reason.contains("rm"));
        } else {
            panic!("Expected dangerous classification");
        }
    }

    #[test]
    fn chain_multiple_dangerous_reason_semicolon_separated() {
        let cmds = vec![cmd("rm", &["file"]), cmd("curl", &["evil.com"])];
        let result = classify_chain(&cmds, &[], true);
        if let Classification::Dangerous { reason } = &result.aggregate {
            assert!(reason.contains("; "));
            assert!(reason.contains("[1]"));
            assert!(reason.contains("[2]"));
        } else {
            panic!("Expected dangerous classification");
        }
    }

    #[test]
    fn single_command_not_chained() {
        let cmds = vec![cmd("echo", &["hello"])];
        let result = classify_chain(&cmds, &[], false);
        assert!(!result.is_chained);
        assert_eq!(result.details.len(), 1);
    }

    #[test]
    fn additional_safe_does_not_override_catastrophic() {
        // Catastrophic (Tier 1) commands cannot be overridden even when in additional_safe
        let cmds = vec![cmd("sudo", &["ls"]), cmd("dd", &["if=/dev/zero"])];
        let additional = vec!["sudo".to_string(), "dd".to_string()];
        let result = classify_chain(&cmds, &additional, true);
        assert!(matches!(result.aggregate, Classification::Dangerous { .. }));
        // sudo is catastrophic — must stay dangerous
        assert!(matches!(
            result.details[0].classification,
            Classification::Dangerous { .. }
        ));
        // dd is catastrophic — must stay dangerous
        assert!(matches!(
            result.details[1].classification,
            Classification::Dangerous { .. }
        ));
        // No pre-approved commands
        assert!(result.preapproved_commands.is_empty());
    }

    #[test]
    fn tier2_commands_overridable_via_additional_safe() {
        // Tier 2 (whitelistable) dangerous commands CAN be overridden
        let cmds = vec![cmd("curl", &["url"]), cmd("rm", &["file"])];
        let additional = vec!["curl".to_string(), "rm".to_string()];
        let result = classify_chain(&cmds, &additional, true);
        assert!(matches!(result.aggregate, Classification::Safe));
        assert!(matches!(
            result.details[0].classification,
            Classification::Safe
        ));
        assert!(matches!(
            result.details[1].classification,
            Classification::Safe
        ));
        assert_eq!(result.preapproved_commands, vec!["curl", "rm"]);
    }

    #[test]
    fn raw_preserved_in_detail() {
        let cmds = vec![cmd("echo", &["hello", "world"])];
        let result = classify_chain(&cmds, &[], false);
        assert_eq!(result.details[0].raw, "echo hello world");
    }

    // ── Tier 1 (catastrophic) commands cannot be overridden ─────

    #[test]
    fn catastrophic_sudo_not_overridable() {
        let cmds = vec![cmd("sudo", &["ls"])];
        let additional = vec!["sudo".to_string()];
        let result = classify_chain(&cmds, &additional, false);
        assert!(matches!(result.aggregate, Classification::Dangerous { .. }));
        assert!(result.preapproved_commands.is_empty());
    }

    #[test]
    fn catastrophic_dd_not_overridable() {
        let cmds = vec![cmd("dd", &["if=/dev/zero", "of=/dev/sda"])];
        let additional = vec!["dd".to_string()];
        let result = classify_chain(&cmds, &additional, false);
        assert!(matches!(result.aggregate, Classification::Dangerous { .. }));
        assert!(result.preapproved_commands.is_empty());
    }

    #[test]
    fn catastrophic_mkfs_not_overridable() {
        let cmds = vec![cmd("mkfs", &["/dev/sda1"])];
        let additional = vec!["mkfs".to_string()];
        let result = classify_chain(&cmds, &additional, false);
        assert!(matches!(result.aggregate, Classification::Dangerous { .. }));
    }

    #[test]
    fn catastrophic_shutdown_not_overridable() {
        let cmds = vec![cmd("shutdown", &["-h", "now"])];
        let additional = vec!["shutdown".to_string()];
        let result = classify_chain(&cmds, &additional, false);
        assert!(matches!(result.aggregate, Classification::Dangerous { .. }));
    }

    #[test]
    fn catastrophic_shred_not_overridable() {
        let cmds = vec![cmd("shred", &["file"])];
        let additional = vec!["shred".to_string()];
        let result = classify_chain(&cmds, &additional, false);
        assert!(matches!(result.aggregate, Classification::Dangerous { .. }));
    }

    #[test]
    fn catastrophic_fdisk_not_overridable() {
        let cmds = vec![cmd("fdisk", &["/dev/sda"])];
        let additional = vec!["fdisk".to_string()];
        let result = classify_chain(&cmds, &additional, false);
        assert!(matches!(result.aggregate, Classification::Dangerous { .. }));
    }

    #[test]
    fn catastrophic_reboot_not_overridable() {
        let cmds = vec![cmd("reboot", &[])];
        let additional = vec!["reboot".to_string()];
        let result = classify_chain(&cmds, &additional, false);
        assert!(matches!(result.aggregate, Classification::Dangerous { .. }));
    }

    // ── Tier 2 (whitelistable) commands CAN be overridden ─────

    #[test]
    fn tier2_rm_overridable() {
        let cmds = vec![cmd("rm", &["-rf", "/tmp/x"])];
        let additional = vec!["rm".to_string()];
        let result = classify_chain(&cmds, &additional, false);
        assert!(matches!(result.aggregate, Classification::Safe));
        assert_eq!(result.preapproved_commands, vec!["rm"]);
    }

    #[test]
    fn tier2_curl_overridable() {
        let cmds = vec![cmd("curl", &["example.com"])];
        let additional = vec!["curl".to_string()];
        let result = classify_chain(&cmds, &additional, false);
        assert!(matches!(result.aggregate, Classification::Safe));
        assert_eq!(result.preapproved_commands, vec!["curl"]);
    }

    #[test]
    fn tier2_kill_overridable() {
        let cmds = vec![cmd("kill", &["-9", "1234"])];
        let additional = vec!["kill".to_string()];
        let result = classify_chain(&cmds, &additional, false);
        assert!(matches!(result.aggregate, Classification::Safe));
        assert_eq!(result.preapproved_commands, vec!["kill"]);
    }

    #[test]
    fn tier2_bash_overridable() {
        let cmds = vec![cmd("bash", &["-c", "echo hi"])];
        let additional = vec!["bash".to_string()];
        let result = classify_chain(&cmds, &additional, false);
        assert!(matches!(result.aggregate, Classification::Safe));
        assert_eq!(result.preapproved_commands, vec!["bash"]);
    }

    #[test]
    fn tier2_npm_overridable() {
        let cmds = vec![cmd("npm", &["install"])];
        let additional = vec!["npm".to_string()];
        let result = classify_chain(&cmds, &additional, false);
        assert!(matches!(result.aggregate, Classification::Safe));
        assert_eq!(result.preapproved_commands, vec!["npm"]);
    }

    #[test]
    fn tier2_mount_overridable() {
        let cmds = vec![cmd("mount", &["/dev/sda1", "/mnt"])];
        let additional = vec!["mount".to_string()];
        let result = classify_chain(&cmds, &additional, false);
        assert!(matches!(result.aggregate, Classification::Safe));
        assert_eq!(result.preapproved_commands, vec!["mount"]);
    }

    #[test]
    fn tier2_python3_overridable() {
        let cmds = vec![cmd("python3", &["script.py"])];
        let additional = vec!["python3".to_string()];
        let result = classify_chain(&cmds, &additional, false);
        assert!(matches!(result.aggregate, Classification::Safe));
        assert_eq!(result.preapproved_commands, vec!["python3"]);
    }

    #[test]
    fn tier2_cargo_overridable() {
        let cmds = vec![cmd("cargo", &["build"])];
        let additional = vec!["cargo".to_string()];
        let result = classify_chain(&cmds, &additional, false);
        assert!(matches!(result.aggregate, Classification::Safe));
        assert_eq!(result.preapproved_commands, vec!["cargo"]);
    }

    #[test]
    fn not_in_allowlist_still_overridable() {
        // Custom unknown commands should still be overridable
        let cmds = vec![cmd("my_custom_tool", &["--flag"])];
        let additional = vec!["my_custom_tool".to_string()];
        let result = classify_chain(&cmds, &additional, false);
        assert!(matches!(result.aggregate, Classification::Safe));
    }

    #[test]
    fn mixed_catastrophic_and_tier2_overridable() {
        // Chain with one catastrophic (sudo) and one Tier 2 overridable (rm)
        let cmds = vec![cmd("rm", &["file"]), cmd("sudo", &["ls"])];
        let additional = vec!["rm".to_string(), "sudo".to_string()];
        let result = classify_chain(&cmds, &additional, true);
        // rm is Tier 2, gets overridden to safe
        assert!(matches!(
            result.details[0].classification,
            Classification::Safe
        ));
        // sudo is catastrophic, stays dangerous
        assert!(matches!(
            result.details[1].classification,
            Classification::Dangerous { .. }
        ));
        // aggregate is dangerous because of sudo
        assert!(matches!(result.aggregate, Classification::Dangerous { .. }));
        // only rm was pre-approved
        assert_eq!(result.preapproved_commands, vec!["rm"]);
    }

    // ── is_catastrophic (Tier 1) ───────────────────────────────

    #[test]
    fn is_catastrophic_privilege_escalation() {
        assert!(is_catastrophic("sudo"));
        assert!(is_catastrophic("su"));
        assert!(is_catastrophic("doas"));
        assert!(is_catastrophic("pkexec"));
        assert!(is_catastrophic("runas"));
    }

    #[test]
    fn is_catastrophic_disk_destruction() {
        assert!(is_catastrophic("mkfs"));
        assert!(is_catastrophic("dd"));
        assert!(is_catastrophic("shred"));
        assert!(is_catastrophic("fdisk"));
        assert!(is_catastrophic("parted"));
        assert!(is_catastrophic("lvm"));
    }

    #[test]
    fn is_catastrophic_system_control() {
        assert!(is_catastrophic("shutdown"));
        assert!(is_catastrophic("reboot"));
        assert!(is_catastrophic("halt"));
        assert!(is_catastrophic("poweroff"));
        assert!(is_catastrophic("init"));
    }

    #[test]
    fn is_catastrophic_false_for_tier2() {
        // Tier 2 commands are NOT catastrophic
        assert!(!is_catastrophic("rm"));
        assert!(!is_catastrophic("curl"));
        assert!(!is_catastrophic("npm"));
        assert!(!is_catastrophic("bash"));
        assert!(!is_catastrophic("kill"));
        assert!(!is_catastrophic("mount"));
        assert!(!is_catastrophic("python3"));
        assert!(!is_catastrophic("cargo"));
        assert!(!is_catastrophic("chmod"));
        assert!(!is_catastrophic("wget"));
        assert!(!is_catastrophic("systemctl"));
    }

    #[test]
    fn is_catastrophic_false_for_safe_and_unknown() {
        assert!(!is_catastrophic("echo"));
        assert!(!is_catastrophic("ls"));
        assert!(!is_catastrophic("cat"));
        assert!(!is_catastrophic("my_custom_tool"));
        assert!(!is_catastrophic("git"));
    }

    // ── is_always_dangerous (both tiers) ─────────────────────

    #[test]
    fn is_always_dangerous_covers_all_categories() {
        // Tier 1: catastrophic
        assert!(is_always_dangerous("sudo"));
        assert!(is_always_dangerous("doas"));
        assert!(is_always_dangerous("su"));
        assert!(is_always_dangerous("dd"));
        assert!(is_always_dangerous("shred"));
        assert!(is_always_dangerous("mkfs"));
        assert!(is_always_dangerous("shutdown"));
        assert!(is_always_dangerous("reboot"));
        assert!(is_always_dangerous("fdisk"));
        // Tier 2: whitelistable
        assert!(is_always_dangerous("rm"));
        assert!(is_always_dangerous("curl"));
        assert!(is_always_dangerous("wget"));
        assert!(is_always_dangerous("ssh"));
        assert!(is_always_dangerous("apt"));
        assert!(is_always_dangerous("brew"));
        assert!(is_always_dangerous("cargo"));
        assert!(is_always_dangerous("kill"));
        assert!(is_always_dangerous("systemctl"));
        assert!(is_always_dangerous("mount"));
        assert!(is_always_dangerous("bash"));
        assert!(is_always_dangerous("python3"));
        assert!(is_always_dangerous("node"));
    }

    #[test]
    fn is_always_dangerous_false_for_safe_and_unknown() {
        assert!(!is_always_dangerous("echo"));
        assert!(!is_always_dangerous("ls"));
        assert!(!is_always_dangerous("cat"));
        assert!(!is_always_dangerous("my_custom_tool"));
        assert!(!is_always_dangerous("git"));
    }

    // ── preapproved_commands tracking ────────────────────────

    #[test]
    fn preapproved_commands_empty_when_no_overrides() {
        let cmds = vec![cmd("echo", &["hello"]), cmd("rm", &["file"])];
        let result = classify_chain(&cmds, &[], true);
        assert!(result.preapproved_commands.is_empty());
    }

    #[test]
    fn preapproved_commands_tracks_overridden_unknown() {
        let cmds = vec![cmd("my_tool", &["--flag"])];
        let additional = vec!["my_tool".to_string()];
        let result = classify_chain(&cmds, &additional, false);
        assert_eq!(result.preapproved_commands, vec!["my_tool"]);
    }

    #[test]
    fn preapproved_commands_not_set_for_catastrophic() {
        let cmds = vec![cmd("sudo", &["ls"])];
        let additional = vec!["sudo".to_string()];
        let result = classify_chain(&cmds, &additional, false);
        assert!(result.preapproved_commands.is_empty());
    }
}

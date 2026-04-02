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

    for (index, cmd) in cmds.iter().enumerate() {
        let mut classification = classify(cmd);

        // Override if command is in the additional safe list
        if matches!(classification, Classification::Dangerous { .. })
            && additional_safe.iter().any(|s| s == &cmd.command)
        {
            classification = Classification::Safe;
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

    #[test]
    fn test_safe_command() {
        assert_eq!(classify(&cmd("echo", &["hello"])), Classification::Safe);
        assert_eq!(classify(&cmd("ls", &["-la"])), Classification::Safe);
    }

    #[test]
    fn test_dangerous_rm() {
        assert!(matches!(
            classify(&cmd("rm", &["-rf", "/"])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn test_dangerous_sudo() {
        assert!(matches!(
            classify(&cmd("sudo", &["rm", "-rf", "/"])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn test_unknown_is_dangerous() {
        assert!(matches!(
            classify(&cmd("my_custom_script", &[])),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn test_classify_all_mixed() {
        let cmds = vec![cmd("echo", &["hello"]), cmd("rm", &["-rf", "/tmp/x"])];
        assert!(matches!(
            classify_all(&cmds, &[]),
            Classification::Dangerous { .. }
        ));
    }

    #[test]
    fn test_classify_all_additional_safe() {
        // "my_custom_script" is normally dangerous (not in allowlist)
        let cmds = vec![cmd("my_custom_script", &["--flag"])];
        assert!(matches!(
            classify_all(&cmds, &[]),
            Classification::Dangerous { .. }
        ));

        // But if it's in additional_safe, the chain becomes safe
        let additional = vec!["my_custom_script".to_string()];
        assert_eq!(classify_all(&cmds, &additional), Classification::Safe);
    }

    #[test]
    fn test_classify_all_all_safe() {
        let cmds = vec![cmd("echo", &["hello"]), cmd("ls", &["-la"])];
        assert_eq!(classify_all(&cmds, &[]), Classification::Safe);
    }

    // ── Chain analysis tests ──

    #[test]
    fn test_chain_classification_details() {
        let cmds = vec![
            cmd("echo", &["hello"]),
            cmd("rm", &["-rf", "/tmp/x"]),
            cmd("ls", &["-la"]),
        ];
        let result = classify_chain(&cmds, &[], true);

        assert!(result.is_chained);
        assert!(matches!(result.aggregate, Classification::Dangerous { .. }));
        assert_eq!(result.details.len(), 3);

        // echo is safe
        assert_eq!(result.details[0].command, "echo");
        assert_eq!(result.details[0].index, 0);
        assert!(matches!(
            result.details[0].classification,
            Classification::Safe
        ));

        // rm is dangerous
        assert_eq!(result.details[1].command, "rm");
        assert_eq!(result.details[1].index, 1);
        assert!(matches!(
            result.details[1].classification,
            Classification::Dangerous { .. }
        ));

        // ls is safe
        assert_eq!(result.details[2].command, "ls");
        assert_eq!(result.details[2].index, 2);
        assert!(matches!(
            result.details[2].classification,
            Classification::Safe
        ));
    }

    #[test]
    fn test_chain_all_safe() {
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
    fn test_chain_multiple_dangerous() {
        let cmds = vec![
            cmd("rm", &["-rf", "/"]),
            cmd("curl", &["evil.com"]),
            cmd("echo", &["done"]),
        ];
        let result = classify_chain(&cmds, &[], true);

        assert!(matches!(result.aggregate, Classification::Dangerous { .. }));

        // Both rm and curl should be dangerous
        let dangerous_count = result
            .details
            .iter()
            .filter(|d| matches!(d.classification, Classification::Dangerous { .. }))
            .count();
        assert_eq!(dangerous_count, 2);
    }

    #[test]
    fn test_chain_additional_safe_override() {
        let cmds = vec![cmd("echo", &["hello"]), cmd("my_tool", &["--flag"])];
        let additional = vec!["my_tool".to_string()];
        let result = classify_chain(&cmds, &additional, true);

        assert!(matches!(result.aggregate, Classification::Safe));
        // my_tool should be classified as safe after override
        assert!(matches!(
            result.details[1].classification,
            Classification::Safe
        ));
    }

    #[test]
    fn test_chain_reason_includes_index() {
        let cmds = vec![cmd("echo", &["hello"]), cmd("rm", &["-rf", "/"])];
        let result = classify_chain(&cmds, &[], true);
        if let Classification::Dangerous { reason } = &result.aggregate {
            // Reason should reference command index
            assert!(reason.contains("[2]"));
            assert!(reason.contains("rm"));
        } else {
            panic!("Expected dangerous classification");
        }
    }

    #[test]
    fn test_single_command_not_chained() {
        let cmds = vec![cmd("echo", &["hello"])];
        let result = classify_chain(&cmds, &[], false);
        assert!(!result.is_chained);
        assert_eq!(result.details.len(), 1);
    }
}

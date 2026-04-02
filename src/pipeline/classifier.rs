//! Stage 2: Command Classifier
//!
//! Determines whether each sub-command is Safe or Dangerous.

use super::parser::ParsedCommand;
use crate::platform;

/// Classification result for a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classification {
    Safe,
    Dangerous { reason: String },
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
    if matches!(name, "rm" | "rmdir" | "chmod" | "chown" | "chgrp" | "mkfs" | "dd" | "shred" | "truncate") {
        return Classification::Dangerous {
            reason: format!("Destructive file operation: {name}"),
        };
    }

    // Always-dangerous: network commands
    if matches!(name, "curl" | "wget" | "nc" | "ncat" | "netcat" | "ssh" | "scp" | "sftp" | "rsync" | "ftp") {
        return Classification::Dangerous {
            reason: format!("Network command: {name}"),
        };
    }

    // Always-dangerous: package managers
    if matches!(name, "apt" | "apt-get" | "yum" | "dnf" | "pacman" | "brew" | "choco" | "pip" | "npm" | "cargo") {
        return Classification::Dangerous {
            reason: format!("Package manager: {name}"),
        };
    }

    // Always-dangerous: system control
    if matches!(name, "shutdown" | "reboot" | "halt" | "poweroff" | "init" | "systemctl" | "launchctl" | "kill" | "killall" | "pkill") {
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
    if matches!(name, "bash" | "sh" | "zsh" | "fish" | "csh" | "tcsh" | "dash" | "ksh" | "python" | "python3" | "perl" | "ruby" | "node") {
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

/// Classify all sub-commands. Returns the most restrictive classification
/// (if any is Dangerous, the whole chain is Dangerous).
pub fn classify_all(cmds: &[ParsedCommand]) -> Classification {
    let mut reasons = Vec::new();

    for cmd in cmds {
        if let Classification::Dangerous { reason } = classify(cmd) {
            reasons.push(reason);
        }
    }

    if reasons.is_empty() {
        Classification::Safe
    } else {
        Classification::Dangerous {
            reason: reasons.join("; "),
        }
    }
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
        assert!(matches!(classify_all(&cmds), Classification::Dangerous { .. }));
    }
}

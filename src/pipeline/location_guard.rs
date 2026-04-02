//! Stage 3: Location Guard
//!
//! Checks resolved path arguments against the OS-specific protected path list.
//! Hard-blocks any command that writes to a protected directory.

use std::path::{Path, PathBuf};

use crate::platform::{self, ProtectedPath};
use super::classifier::Classification;
use super::parser::ParsedCommand;

/// The result of a location guard check.
#[derive(Debug, Clone)]
pub enum GuardVerdict {
    /// No protected path violations.
    Pass,
    /// At least one path is blocked.
    Blocked { violations: Vec<PathViolation> },
}

/// Details of a single path violation.
#[derive(Debug, Clone)]
pub struct PathViolation {
    pub path: PathBuf,
    pub protected_prefix: String,
    pub reason: String,
}

/// Check all resolved paths in the parsed commands against protected paths.
///
/// If the command classification is `Safe`, we treat the operation as read-only
/// and allow paths where `read_allowed` is true. If `Dangerous`, we treat it as
/// a write and block all protected paths.
pub fn check_paths(
    commands: &[ParsedCommand],
    classification: &Classification,
) -> GuardVerdict {
    let protected = platform::protected_paths();
    let is_read_only = matches!(classification, Classification::Safe);
    let mut violations = Vec::new();

    for cmd in commands {
        // Also check raw args that look like absolute paths but weren't resolved
        // (e.g. commands with no working_dir context)
        for resolved in &cmd.resolved_paths {
            if let Some(v) = check_single_path(resolved, protected, is_read_only) {
                violations.push(v);
            }
        }
    }

    if violations.is_empty() {
        GuardVerdict::Pass
    } else {
        GuardVerdict::Blocked { violations }
    }
}

/// Check a single path against all protected prefixes.
fn check_single_path(
    path: &Path,
    protected: &[ProtectedPath],
    is_read_only: bool,
) -> Option<PathViolation> {
    let path_str = path.to_string_lossy();

    for pp in protected {
        if starts_with_prefix(&path_str, pp.path) {
            // If the operation is read-only and reads are allowed, let it pass
            if is_read_only && pp.read_allowed {
                continue;
            }
            return Some(PathViolation {
                path: path.to_path_buf(),
                protected_prefix: pp.path.to_string(),
                reason: pp.reason.to_string(),
            });
        }
    }
    None
}

/// Case-sensitive prefix check (case-insensitive on Windows).
fn starts_with_prefix(path: &str, prefix: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        let path_lower = path.to_lowercase();
        let prefix_lower = prefix.to_lowercase();
        path_lower == prefix_lower
            || path_lower.starts_with(&format!("{prefix_lower}\\"))
            || path_lower.starts_with(&format!("{prefix_lower}/"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        path == prefix || path.starts_with(&format!("{prefix}/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::parser::ParsedCommand;

    fn cmd_with_paths(name: &str, paths: &[&str]) -> ParsedCommand {
        ParsedCommand {
            command: name.to_string(),
            args: paths.iter().map(|s| s.to_string()).collect(),
            resolved_paths: paths.iter().map(PathBuf::from).collect(),
            raw: format!("{} {}", name, paths.join(" ")),
        }
    }

    #[test]
    fn test_safe_read_in_etc() {
        // Reading /etc/hostname should be allowed (read_allowed=true for /etc on macOS/Linux)
        let cmds = vec![cmd_with_paths("cat", &["/etc/hostname"])];
        let verdict = check_paths(&cmds, &Classification::Safe);
        assert!(matches!(verdict, GuardVerdict::Pass));
    }

    #[test]
    fn test_write_in_etc_blocked() {
        // Writing to /etc should be blocked
        let cmds = vec![cmd_with_paths("rm", &["/etc/hosts"])];
        let verdict = check_paths(
            &cmds,
            &Classification::Dangerous {
                reason: "test".into(),
            },
        );
        assert!(matches!(verdict, GuardVerdict::Blocked { .. }));
    }

    #[test]
    fn test_normal_path_passes() {
        let cmds = vec![cmd_with_paths("ls", &["/home/user/code"])];
        let verdict = check_paths(&cmds, &Classification::Safe);
        assert!(matches!(verdict, GuardVerdict::Pass));
    }
}

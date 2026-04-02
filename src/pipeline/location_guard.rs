//! Stage 3: Location Guard
//!
//! Checks resolved path arguments against the OS-specific protected path list.
//! Hard-blocks any command that writes to a protected directory.

use std::path::{Path, PathBuf};

use super::classifier::Classification;
use super::parser::ParsedCommand;
use crate::config::ProtectedPathEntry;
use crate::platform::{self, ProtectedPath};

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
///
/// `additional_protected` are extra entries from the config file.
pub fn check_paths(
    commands: &[ParsedCommand],
    classification: &Classification,
    additional_protected: &[ProtectedPathEntry],
) -> GuardVerdict {
    let builtin = platform::protected_paths();
    let is_read_only = matches!(classification, Classification::Safe);
    let mut violations = Vec::new();

    for cmd in commands {
        for resolved in &cmd.resolved_paths {
            // Canonicalize to resolve symlinks (Phase 3.5)
            let canonical = canonicalize_or_keep(resolved);
            if let Some(v) =
                check_single_path(&canonical, builtin, additional_protected, is_read_only)
            {
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

/// Attempt to canonicalize a path, falling back to the original if it fails
/// (e.g. the path doesn't exist yet).
fn canonicalize_or_keep(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Check a single path against all protected prefixes (builtin + additional).
/// Both the path and the prefix are compared in their canonical forms
/// to handle symlinks (e.g., /etc → /private/etc on macOS).
fn check_single_path(
    path: &Path,
    builtin: &[ProtectedPath],
    additional: &[ProtectedPathEntry],
    is_read_only: bool,
) -> Option<PathViolation> {
    let path_str = path.to_string_lossy();

    for pp in builtin {
        let canonical_prefix = canonicalize_or_keep(Path::new(pp.path));
        let canonical_prefix_str = canonical_prefix.to_string_lossy();
        if starts_with_prefix(&path_str, &canonical_prefix_str)
            || starts_with_prefix(&path_str, pp.path)
        {
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

    for pp in additional {
        let canonical_prefix = canonicalize_or_keep(Path::new(&pp.path));
        let canonical_prefix_str = canonical_prefix.to_string_lossy();
        if starts_with_prefix(&path_str, &canonical_prefix_str)
            || starts_with_prefix(&path_str, &pp.path)
        {
            if is_read_only && pp.read_allowed {
                continue;
            }
            return Some(PathViolation {
                path: path.to_path_buf(),
                protected_prefix: pp.path.clone(),
                reason: format!("Config-protected path: {}", pp.path),
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
        let verdict = check_paths(&cmds, &Classification::Safe, &[]);
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
            &[],
        );
        assert!(matches!(verdict, GuardVerdict::Blocked { .. }));
    }

    #[test]
    fn test_normal_path_passes() {
        let cmds = vec![cmd_with_paths("ls", &["/home/user/code"])];
        let verdict = check_paths(&cmds, &Classification::Safe, &[]);
        assert!(matches!(verdict, GuardVerdict::Pass));
    }

    #[test]
    fn test_additional_protected_path_blocked() {
        let cmds = vec![cmd_with_paths("rm", &["/my/secret/file.txt"])];
        let additional = vec![ProtectedPathEntry {
            path: "/my/secret".to_string(),
            read_allowed: false,
        }];
        let verdict = check_paths(
            &cmds,
            &Classification::Dangerous {
                reason: "test".into(),
            },
            &additional,
        );
        assert!(matches!(verdict, GuardVerdict::Blocked { .. }));
    }

    #[test]
    fn test_additional_protected_read_allowed() {
        let cmds = vec![cmd_with_paths("cat", &["/my/secret/file.txt"])];
        let additional = vec![ProtectedPathEntry {
            path: "/my/secret".to_string(),
            read_allowed: true,
        }];
        let verdict = check_paths(&cmds, &Classification::Safe, &additional);
        assert!(matches!(verdict, GuardVerdict::Pass));
    }
}

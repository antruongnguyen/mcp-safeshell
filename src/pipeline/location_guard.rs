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
            // Reject paths containing null bytes (potential injection)
            if let Some(v) = reject_null_bytes(resolved) {
                violations.push(v);
                continue;
            }

            // Canonicalize to resolve symlinks (Phase 3.5)
            let canonical = canonicalize_or_keep(resolved);

            // Check for /proc/self/root traversal (Linux)
            if let Some(v) = reject_proc_self_root(&canonical) {
                violations.push(v);
                continue;
            }

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

/// Reject paths containing null bytes which could be used to truncate
/// the path string at the OS level.
fn reject_null_bytes(path: &Path) -> Option<PathViolation> {
    let path_str = path.to_string_lossy();
    if path_str.contains('\0') {
        return Some(PathViolation {
            path: path.to_path_buf(),
            protected_prefix: "(null byte)".to_string(),
            reason: "Path contains null byte (potential injection attack)".to_string(),
        });
    }
    None
}

/// Reject paths that traverse through /proc/self/root (or /proc/<pid>/root)
/// which allows escaping chroot and accessing the real filesystem root.
#[cfg(target_os = "linux")]
fn reject_proc_self_root(path: &Path) -> Option<PathViolation> {
    let path_str = path.to_string_lossy();
    // Match /proc/self/root or /proc/<number>/root
    if path_str.starts_with("/proc/self/root/")
        || path_str == "/proc/self/root"
        || proc_pid_root_pattern(&path_str)
    {
        return Some(PathViolation {
            path: path.to_path_buf(),
            protected_prefix: "/proc/*/root".to_string(),
            reason: "Path traversal via /proc/*/root (filesystem root escape)".to_string(),
        });
    }
    None
}

#[cfg(target_os = "linux")]
fn proc_pid_root_pattern(path: &str) -> bool {
    // Match /proc/<digits>/root or /proc/<digits>/root/...
    if let Some(rest) = path.strip_prefix("/proc/") {
        if let Some(slash_pos) = rest.find('/') {
            let pid_part = &rest[..slash_pos];
            let after_pid = &rest[slash_pos..];
            if pid_part.chars().all(|c| c.is_ascii_digit())
                && (after_pid == "/root" || after_pid.starts_with("/root/"))
            {
                return true;
            }
        }
    }
    false
}

#[cfg(not(target_os = "linux"))]
fn reject_proc_self_root(_path: &Path) -> Option<PathViolation> {
    None
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

    fn cmd_no_paths(name: &str) -> ParsedCommand {
        ParsedCommand {
            command: name.to_string(),
            args: Vec::new(),
            resolved_paths: Vec::new(),
            raw: name.to_string(),
        }
    }

    // ── Built-in protected paths (read-only access) ────────────────

    #[test]
    fn safe_read_in_etc() {
        let cmds = vec![cmd_with_paths("cat", &["/etc/hostname"])];
        let verdict = check_paths(&cmds, &Classification::Safe, &[]);
        assert!(matches!(verdict, GuardVerdict::Pass));
    }

    #[test]
    fn safe_read_in_usr_bin() {
        let cmds = vec![cmd_with_paths("ls", &["/usr/bin"])];
        let verdict = check_paths(&cmds, &Classification::Safe, &[]);
        assert!(matches!(verdict, GuardVerdict::Pass));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn safe_read_in_system() {
        let cmds = vec![cmd_with_paths("cat", &["/System/Library/file"])];
        let verdict = check_paths(&cmds, &Classification::Safe, &[]);
        assert!(matches!(verdict, GuardVerdict::Pass));
    }

    // ── Built-in protected paths (write access blocked) ────────────

    #[test]
    fn write_in_etc_blocked() {
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
    fn write_in_usr_bin_blocked() {
        let cmds = vec![cmd_with_paths("rm", &["/usr/bin/ls"])];
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
    fn write_in_sbin_blocked() {
        let cmds = vec![cmd_with_paths("chmod", &["/sbin/something"])];
        let verdict = check_paths(
            &cmds,
            &Classification::Dangerous {
                reason: "test".into(),
            },
            &[],
        );
        assert!(matches!(verdict, GuardVerdict::Blocked { .. }));
    }

    // ── Read-disallowed paths blocked even for safe commands ───────

    #[cfg(target_os = "macos")]
    #[test]
    fn read_in_var_db_blocked() {
        // /var/db has read_allowed: false on macOS
        let cmds = vec![cmd_with_paths("cat", &["/var/db/something"])];
        let verdict = check_paths(&cmds, &Classification::Safe, &[]);
        // On macOS /var → /private/var, and /private/var has read_allowed: false
        // This should be blocked
        assert!(matches!(verdict, GuardVerdict::Blocked { .. }));
    }

    // ── Normal (non-protected) paths pass ──────────────────────────

    #[test]
    fn normal_path_passes() {
        let cmds = vec![cmd_with_paths("ls", &["/home/user/code"])];
        let verdict = check_paths(&cmds, &Classification::Safe, &[]);
        assert!(matches!(verdict, GuardVerdict::Pass));
    }

    #[test]
    fn tmp_path_passes() {
        let cmds = vec![cmd_with_paths("rm", &["/tmp/scratch"])];
        let verdict = check_paths(
            &cmds,
            &Classification::Dangerous {
                reason: "test".into(),
            },
            &[],
        );
        assert!(matches!(verdict, GuardVerdict::Pass));
    }

    #[test]
    fn home_path_passes() {
        let cmds = vec![cmd_with_paths("cat", &["/Users/someone/file.txt"])];
        let verdict = check_paths(&cmds, &Classification::Safe, &[]);
        assert!(matches!(verdict, GuardVerdict::Pass));
    }

    // ── Additional protected paths (config-supplied) ───────────────

    #[test]
    fn additional_protected_path_blocked() {
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
    fn additional_protected_read_allowed() {
        let cmds = vec![cmd_with_paths("cat", &["/my/secret/file.txt"])];
        let additional = vec![ProtectedPathEntry {
            path: "/my/secret".to_string(),
            read_allowed: true,
        }];
        let verdict = check_paths(&cmds, &Classification::Safe, &additional);
        assert!(matches!(verdict, GuardVerdict::Pass));
    }

    #[test]
    fn additional_protected_read_disallowed_blocks_safe() {
        let cmds = vec![cmd_with_paths("cat", &["/my/secret/file.txt"])];
        let additional = vec![ProtectedPathEntry {
            path: "/my/secret".to_string(),
            read_allowed: false,
        }];
        let verdict = check_paths(&cmds, &Classification::Safe, &additional);
        assert!(matches!(verdict, GuardVerdict::Blocked { .. }));
    }

    #[test]
    fn additional_protected_write_to_read_allowed_blocked() {
        // Even if read_allowed, write (dangerous) should be blocked
        let cmds = vec![cmd_with_paths("rm", &["/my/secret/file.txt"])];
        let additional = vec![ProtectedPathEntry {
            path: "/my/secret".to_string(),
            read_allowed: true,
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

    // ── No resolved paths → always pass ────────────────────────────

    #[test]
    fn no_paths_always_passes() {
        let cmds = vec![cmd_no_paths("echo")];
        let verdict = check_paths(
            &cmds,
            &Classification::Dangerous {
                reason: "test".into(),
            },
            &[],
        );
        assert!(matches!(verdict, GuardVerdict::Pass));
    }

    #[test]
    fn empty_commands_pass() {
        let cmds: Vec<ParsedCommand> = Vec::new();
        let verdict = check_paths(&cmds, &Classification::Safe, &[]);
        assert!(matches!(verdict, GuardVerdict::Pass));
    }

    // ── Multiple commands in chain ─────────────────────────────────

    #[test]
    fn multiple_commands_one_violation() {
        let cmds = vec![
            cmd_with_paths("ls", &["/tmp/ok"]),
            cmd_with_paths("rm", &["/etc/hosts"]),
        ];
        let verdict = check_paths(
            &cmds,
            &Classification::Dangerous {
                reason: "test".into(),
            },
            &[],
        );
        assert!(matches!(verdict, GuardVerdict::Blocked { .. }));
        if let GuardVerdict::Blocked { violations } = verdict {
            assert_eq!(violations.len(), 1);
            // On macOS, /etc/hosts canonicalizes to /private/etc/hosts
            let path_str = violations[0].path.to_string_lossy();
            assert!(
                path_str.ends_with("etc/hosts"),
                "expected path ending in etc/hosts, got {path_str}"
            );
        }
    }

    #[test]
    fn multiple_commands_multiple_violations() {
        let cmds = vec![
            cmd_with_paths("rm", &["/etc/hosts"]),
            cmd_with_paths("rm", &["/usr/bin/ls"]),
        ];
        let verdict = check_paths(
            &cmds,
            &Classification::Dangerous {
                reason: "test".into(),
            },
            &[],
        );
        if let GuardVerdict::Blocked { violations } = verdict {
            assert!(violations.len() >= 2);
        } else {
            panic!("Expected blocked verdict");
        }
    }

    // ── Violation details ──────────────────────────────────────────

    #[test]
    fn violation_contains_path_and_prefix() {
        let cmds = vec![cmd_with_paths("rm", &["/etc/shadow"])];
        let verdict = check_paths(
            &cmds,
            &Classification::Dangerous {
                reason: "test".into(),
            },
            &[],
        );
        if let GuardVerdict::Blocked { violations } = verdict {
            assert_eq!(violations[0].path, PathBuf::from("/etc/shadow"));
            assert!(!violations[0].protected_prefix.is_empty());
            assert!(!violations[0].reason.is_empty());
        } else {
            panic!("Expected blocked verdict");
        }
    }

    // ── Prefix matching edge cases ─────────────────────────────────

    #[test]
    fn exact_path_match_blocked() {
        let additional = vec![ProtectedPathEntry {
            path: "/exact/path".to_string(),
            read_allowed: false,
        }];
        let cmds = vec![cmd_with_paths("rm", &["/exact/path"])];
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
    fn partial_name_not_blocked() {
        // /etcetera should NOT match /etc prefix (no slash separator)
        let cmds = vec![cmd_with_paths("cat", &["/etcetera/file"])];
        let verdict = check_paths(&cmds, &Classification::Safe, &[]);
        assert!(matches!(verdict, GuardVerdict::Pass));
    }

    // ── starts_with_prefix unit tests ──────────────────────────────

    #[test]
    fn prefix_match_exact() {
        assert!(starts_with_prefix("/etc", "/etc"));
    }

    #[test]
    fn prefix_match_subdir() {
        assert!(starts_with_prefix("/etc/hosts", "/etc"));
    }

    #[test]
    fn prefix_no_match_partial() {
        assert!(!starts_with_prefix("/etcetera", "/etc"));
    }

    #[test]
    fn prefix_no_match_different_dir() {
        assert!(!starts_with_prefix("/home/user", "/etc"));
    }

    // ── Symlink resolution ─────────────────────────────────────────

    #[test]
    fn canonicalize_or_keep_nonexistent() {
        let path = Path::new("/nonexistent/path/that/does/not/exist");
        let result = canonicalize_or_keep(path);
        assert_eq!(result, path.to_path_buf());
    }

    #[test]
    fn canonicalize_or_keep_existing_path() {
        // /tmp should exist on all test platforms
        let path = Path::new("/tmp");
        let result = canonicalize_or_keep(path);
        // It should be a valid path (may resolve symlinks)
        assert!(result.is_absolute());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_etc_symlink_resolution() {
        // On macOS, /etc → /private/etc
        // Writing to /private/etc/hosts should be blocked because /etc is protected
        let cmds = vec![cmd_with_paths("rm", &["/private/etc/hosts"])];
        let verdict = check_paths(
            &cmds,
            &Classification::Dangerous {
                reason: "test".into(),
            },
            &[],
        );
        assert!(matches!(verdict, GuardVerdict::Blocked { .. }));
    }

    // ── Null byte injection ───────────────────────────────────────

    #[test]
    fn null_byte_in_path_rejected() {
        let path = PathBuf::from("/etc/hosts\0.txt");
        let result = reject_null_bytes(&path);
        assert!(result.is_some());
        let violation = result.unwrap();
        assert!(violation.reason.contains("null byte"));
    }

    #[test]
    fn no_null_byte_passes() {
        let path = PathBuf::from("/etc/hosts");
        let result = reject_null_bytes(&path);
        assert!(result.is_none());
    }

    #[test]
    fn null_byte_blocked_via_check_paths() {
        let mut cmd = cmd_with_paths("cat", &["/tmp/safe"]);
        cmd.resolved_paths
            .push(PathBuf::from("/tmp/evil\0/etc/shadow"));
        let verdict = check_paths(&[cmd], &Classification::Safe, &[]);
        assert!(matches!(verdict, GuardVerdict::Blocked { .. }));
    }

    // ── /proc/self/root traversal (Linux only) ────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_self_root_blocked() {
        let path = PathBuf::from("/proc/self/root/etc/shadow");
        let result = reject_proc_self_root(&path);
        assert!(result.is_some());
        assert!(result.unwrap().reason.contains("proc"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_pid_root_blocked() {
        let path = PathBuf::from("/proc/1/root/etc/passwd");
        let result = reject_proc_self_root(&path);
        assert!(result.is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_self_non_root_passes() {
        let path = PathBuf::from("/proc/self/status");
        let result = reject_proc_self_root(&path);
        assert!(result.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_pid_root_pattern_matches() {
        assert!(proc_pid_root_pattern("/proc/123/root"));
        assert!(proc_pid_root_pattern("/proc/123/root/etc"));
        assert!(proc_pid_root_pattern("/proc/1/root/"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_pid_root_pattern_no_match() {
        assert!(!proc_pid_root_pattern("/proc/abc/root"));
        assert!(!proc_pid_root_pattern("/proc/123/status"));
        assert!(!proc_pid_root_pattern("/proc/self/root"));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_proc_self_root_no_op() {
        let path = PathBuf::from("/proc/self/root/etc/shadow");
        let result = reject_proc_self_root(&path);
        assert!(result.is_none());
    }

    // ── Real filesystem symlink tests ─────────────────────────────

    #[cfg(unix)]
    #[test]
    fn symlink_to_protected_path_blocked() {
        use std::os::unix::fs::symlink;
        let tmp = std::env::temp_dir().join("safeshell_test_symlink_blocked");
        let _ = std::fs::remove_file(&tmp);
        // Create a symlink: tmp → /etc/hosts
        if symlink("/etc/hosts", &tmp).is_ok() {
            let cmds = vec![ParsedCommand {
                command: "rm".to_string(),
                args: vec![tmp.to_string_lossy().to_string()],
                resolved_paths: vec![tmp.clone()],
                raw: format!("rm {}", tmp.display()),
            }];
            let verdict = check_paths(
                &cmds,
                &Classification::Dangerous {
                    reason: "test".into(),
                },
                &[],
            );
            let _ = std::fs::remove_file(&tmp);
            assert!(
                matches!(verdict, GuardVerdict::Blocked { .. }),
                "symlink to /etc/hosts should be blocked for dangerous commands"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_to_safe_path_passes() {
        use std::os::unix::fs::symlink;
        // Use a directory outside protected paths.
        // On macOS, /tmp → /private/tmp which is under /private/var (protected).
        // Use home directory instead.
        let base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        let target = base.join("safeshell_test_symlink_target");
        let link = base.join("safeshell_test_symlink_safe");
        let _ = std::fs::remove_file(&target);
        let _ = std::fs::remove_file(&link);
        std::fs::write(&target, "test").ok();
        if symlink(&target, &link).is_ok() {
            let cmds = vec![ParsedCommand {
                command: "cat".to_string(),
                args: vec![link.to_string_lossy().to_string()],
                resolved_paths: vec![link.clone()],
                raw: format!("cat {}", link.display()),
            }];
            let verdict = check_paths(&cmds, &Classification::Safe, &[]);
            let _ = std::fs::remove_file(&link);
            let _ = std::fs::remove_file(&target);
            assert!(
                matches!(verdict, GuardVerdict::Pass),
                "symlink to home directory file should pass for safe commands"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_chain_to_protected_path_blocked() {
        use std::os::unix::fs::symlink;
        // Create a chain: link1 → link2 → /etc/hosts
        let link2 = std::env::temp_dir().join("safeshell_test_chain_link2");
        let link1 = std::env::temp_dir().join("safeshell_test_chain_link1");
        let _ = std::fs::remove_file(&link1);
        let _ = std::fs::remove_file(&link2);
        if symlink("/etc/hosts", &link2).is_ok() {
            if symlink(&link2, &link1).is_ok() {
                let cmds = vec![ParsedCommand {
                    command: "rm".to_string(),
                    args: vec![link1.to_string_lossy().to_string()],
                    resolved_paths: vec![link1.clone()],
                    raw: format!("rm {}", link1.display()),
                }];
                let verdict = check_paths(
                    &cmds,
                    &Classification::Dangerous {
                        reason: "test".into(),
                    },
                    &[],
                );
                let _ = std::fs::remove_file(&link1);
                let _ = std::fs::remove_file(&link2);
                assert!(
                    matches!(verdict, GuardVerdict::Blocked { .. }),
                    "chained symlink to /etc/hosts should be blocked"
                );
            } else {
                let _ = std::fs::remove_file(&link2);
            }
        }
    }
}

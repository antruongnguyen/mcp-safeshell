//! Platform-specific safe commands and protected paths.
//!
//! Each sub-module provides `safe_commands()` and `protected_paths()` for the target OS.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

use serde::Serialize;

/// A command that is pre-approved on this OS.
#[derive(Debug, Clone, Serialize)]
pub struct SafeCommand {
    pub name: &'static str,
    pub description: &'static str,
}

/// A directory that is protected from write (and optionally read) access.
#[derive(Debug, Clone, Serialize)]
pub struct ProtectedPath {
    pub path: &'static str,
    pub read_allowed: bool,
    pub reason: &'static str,
}

/// Returns the safe command list for the current OS.
pub fn safe_commands() -> &'static [SafeCommand] {
    #[cfg(target_os = "macos")]
    {
        macos::SAFE_COMMANDS
    }
    #[cfg(target_os = "linux")]
    {
        linux::SAFE_COMMANDS
    }
    #[cfg(target_os = "windows")]
    {
        windows::SAFE_COMMANDS
    }
}

/// Returns the protected path list for the current OS.
pub fn protected_paths() -> &'static [ProtectedPath] {
    #[cfg(target_os = "macos")]
    {
        macos::PROTECTED_PATHS
    }
    #[cfg(target_os = "linux")]
    {
        linux::PROTECTED_PATHS
    }
    #[cfg(target_os = "windows")]
    {
        windows::PROTECTED_PATHS
    }
}

/// Returns the OS name string.
pub fn os_name() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "macos"
    }
    #[cfg(target_os = "linux")]
    {
        "linux"
    }
    #[cfg(target_os = "windows")]
    {
        "windows"
    }
}

/// Returns the architecture string.
pub fn arch_name() -> &'static str {
    std::env::consts::ARCH
}

/// Checks whether a given command name is in the safe allowlist.
pub fn is_safe_command(cmd: &str) -> bool {
    safe_commands().iter().any(|sc| sc.name == cmd)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── os_name ────────────────────────────────────────────────────

    #[test]
    fn os_name_is_known() {
        let name = os_name();
        assert!(
            ["macos", "linux", "windows"].contains(&name),
            "unexpected os_name: {name}"
        );
    }

    // ── arch_name ──────────────────────────────────────────────────

    #[test]
    fn arch_name_is_nonempty() {
        let arch = arch_name();
        assert!(!arch.is_empty());
    }

    // ── safe_commands ──────────────────────────────────────────────

    #[test]
    fn safe_commands_is_nonempty() {
        assert!(!safe_commands().is_empty());
    }

    #[test]
    fn safe_commands_have_names_and_descriptions() {
        for sc in safe_commands() {
            assert!(!sc.name.is_empty(), "safe command has empty name");
            assert!(
                !sc.description.is_empty(),
                "safe command {} has empty description",
                sc.name
            );
        }
    }

    #[test]
    fn common_safe_commands_present() {
        // These should be present on all platforms
        assert!(is_safe_command("echo"));
        assert!(is_safe_command("hostname"));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn unix_safe_commands_present() {
        assert!(is_safe_command("cat"));
        assert!(is_safe_command("ls"));
        assert!(is_safe_command("whoami"));
        assert!(is_safe_command("pwd"));
        assert!(is_safe_command("uname"));
        assert!(is_safe_command("which"));
        assert!(is_safe_command("printenv"));
        assert!(is_safe_command("head"));
        assert!(is_safe_command("tail"));
        assert!(is_safe_command("wc"));
        assert!(is_safe_command("df"));
        assert!(is_safe_command("uptime"));
        assert!(is_safe_command("date"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_safe_commands_present() {
        assert!(is_safe_command("dir"));
        assert!(is_safe_command("type"));
        assert!(is_safe_command("where"));
        assert!(is_safe_command("ver"));
        assert!(is_safe_command("set"));
    }

    #[test]
    fn dangerous_commands_not_safe() {
        assert!(!is_safe_command("rm"));
        assert!(!is_safe_command("sudo"));
        assert!(!is_safe_command("curl"));
        assert!(!is_safe_command("bash"));
        assert!(!is_safe_command("python"));
    }

    #[test]
    fn unknown_command_not_safe() {
        assert!(!is_safe_command("totally_unknown_command_xyz"));
    }

    // ── protected_paths ────────────────────────────────────────────

    #[test]
    fn protected_paths_is_nonempty() {
        assert!(!protected_paths().is_empty());
    }

    #[test]
    fn protected_paths_have_valid_fields() {
        for pp in protected_paths() {
            assert!(!pp.path.is_empty(), "protected path has empty path");
            assert!(
                !pp.reason.is_empty(),
                "protected path {} has empty reason",
                pp.path
            );
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn etc_is_protected() {
        let has_etc = protected_paths().iter().any(|pp| pp.path == "/etc");
        assert!(has_etc, "/etc should be in the protected paths list");
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn usr_bin_is_protected() {
        let has_usr_bin = protected_paths().iter().any(|pp| pp.path == "/usr/bin");
        assert!(has_usr_bin, "/usr/bin should be in the protected paths list");
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn system_paths_read_allowed() {
        // /etc, /usr/bin should have read_allowed=true
        for pp in protected_paths() {
            if pp.path == "/etc" || pp.path == "/usr/bin" {
                assert!(
                    pp.read_allowed,
                    "{} should have read_allowed=true",
                    pp.path
                );
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_specific_paths() {
        let paths: Vec<&str> = protected_paths().iter().map(|p| p.path).collect();
        assert!(paths.contains(&"/System"));
        assert!(paths.contains(&"/Library/LaunchDaemons"));
    }
}

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

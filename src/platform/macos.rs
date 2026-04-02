use super::{ProtectedPath, SafeCommand};

pub static SAFE_COMMANDS: &[SafeCommand] = &[
    SafeCommand {
        name: "echo",
        description: "Print text to stdout",
    },
    SafeCommand {
        name: "date",
        description: "Display current date and time",
    },
    SafeCommand {
        name: "whoami",
        description: "Print current username",
    },
    SafeCommand {
        name: "pwd",
        description: "Print working directory",
    },
    SafeCommand {
        name: "uname",
        description: "Print system information",
    },
    SafeCommand {
        name: "hostname",
        description: "Print system hostname",
    },
    SafeCommand {
        name: "cat",
        description: "Read file contents (read-only)",
    },
    SafeCommand {
        name: "ls",
        description: "List directory contents",
    },
    SafeCommand {
        name: "which",
        description: "Locate a command",
    },
    SafeCommand {
        name: "printenv",
        description: "Print environment variables",
    },
    SafeCommand {
        name: "head",
        description: "Display beginning of file",
    },
    SafeCommand {
        name: "tail",
        description: "Display end of file",
    },
    SafeCommand {
        name: "wc",
        description: "Count lines, words, bytes",
    },
    SafeCommand {
        name: "df",
        description: "Display disk space usage",
    },
    SafeCommand {
        name: "uptime",
        description: "Show system uptime",
    },
];

pub static PROTECTED_PATHS: &[ProtectedPath] = &[
    ProtectedPath {
        path: "/System",
        read_allowed: true,
        reason: "macOS system directory",
    },
    ProtectedPath {
        path: "/usr/bin",
        read_allowed: true,
        reason: "System binaries",
    },
    ProtectedPath {
        path: "/usr/sbin",
        read_allowed: true,
        reason: "System admin binaries",
    },
    ProtectedPath {
        path: "/usr/lib",
        read_allowed: true,
        reason: "System libraries",
    },
    ProtectedPath {
        path: "/sbin",
        read_allowed: true,
        reason: "System binaries",
    },
    ProtectedPath {
        path: "/var/db",
        read_allowed: false,
        reason: "System databases",
    },
    ProtectedPath {
        path: "/Library/LaunchDaemons",
        read_allowed: true,
        reason: "System launch daemons",
    },
    ProtectedPath {
        path: "/Library/LaunchAgents",
        read_allowed: true,
        reason: "System launch agents",
    },
    ProtectedPath {
        path: "/private/var",
        read_allowed: false,
        reason: "System private variable data",
    },
    ProtectedPath {
        path: "/etc",
        read_allowed: true,
        reason: "System configuration (write-protected)",
    },
];

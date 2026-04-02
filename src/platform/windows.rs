use super::{ProtectedPath, SafeCommand};

pub static SAFE_COMMANDS: &[SafeCommand] = &[
    SafeCommand { name: "echo", description: "Print text to stdout" },
    SafeCommand { name: "date", description: "Display current date and time (date /t)" },
    SafeCommand { name: "whoami", description: "Print current username" },
    SafeCommand { name: "cd", description: "Print working directory (no args)" },
    SafeCommand { name: "ver", description: "Display Windows version" },
    SafeCommand { name: "hostname", description: "Print system hostname" },
    SafeCommand { name: "type", description: "Read file contents (read-only)" },
    SafeCommand { name: "dir", description: "List directory contents" },
    SafeCommand { name: "where", description: "Locate a command" },
    SafeCommand { name: "set", description: "Print environment variables (no args)" },
];

pub static PROTECTED_PATHS: &[ProtectedPath] = &[
    ProtectedPath { path: "C:\\Windows", read_allowed: true, reason: "Windows system directory" },
    ProtectedPath { path: "C:\\Windows\\System32", read_allowed: true, reason: "Windows System32" },
    ProtectedPath { path: "C:\\Windows\\SysWOW64", read_allowed: true, reason: "Windows SysWOW64" },
    ProtectedPath { path: "C:\\Program Files", read_allowed: true, reason: "Program Files" },
    ProtectedPath { path: "C:\\Program Files (x86)", read_allowed: true, reason: "Program Files (x86)" },
    ProtectedPath { path: "C:\\ProgramData", read_allowed: false, reason: "Program data directory" },
];

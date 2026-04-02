/// Configuration loaded from `safeshell.toml`.
///
/// Search order:
/// 1. `$SAFESHELL_CONFIG` env var
/// 2. `./safeshell.toml`
/// 3. `~/.config/safeshell/config.toml`
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Default command timeout in seconds.
    pub default_timeout_seconds: u64,
    /// Maximum output size in bytes per stream (stdout/stderr each).
    pub max_output_bytes: usize,
    /// Maximum concurrent command executions.
    pub max_concurrency: usize,
    /// Additional commands treated as safe (beyond built-in list).
    #[serde(default)]
    pub additional_safe_commands: Vec<String>,
    /// Additional protected paths.
    #[serde(default)]
    pub additional_protected_paths: Vec<ProtectedPathEntry>,
    /// Regex patterns for env var names whose values should be redacted from output.
    #[serde(default)]
    pub redact_env_patterns: Vec<String>,
    /// Override shell path. If unset, auto-detects ($SHELL → /bin/sh).
    pub shell: Option<String>,
    /// HTTP bind address for streamable HTTP transport.
    pub http_bind: Option<String>,
    /// Log level filter string.
    pub log_level: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProtectedPathEntry {
    pub path: String,
    #[serde(default)]
    pub read_allowed: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default_timeout_seconds: 30,
            max_output_bytes: 100 * 1024, // 100 KB
            max_concurrency: 1,
            additional_safe_commands: Vec::new(),
            additional_protected_paths: Vec::new(),
            redact_env_patterns: Vec::new(),
            shell: None,
            http_bind: None,
            log_level: None,
        }
    }
}

impl Config {
    /// Load config from well-known paths, falling back to defaults.
    pub fn load() -> Self {
        let candidates: Vec<PathBuf> = [
            std::env::var("SAFESHELL_CONFIG").ok().map(PathBuf::from),
            Some(PathBuf::from("./safeshell.toml")),
            dirs::config_dir().map(|d| d.join("safeshell").join("config.toml")),
        ]
        .into_iter()
        .flatten()
        .collect();

        for path in &candidates {
            if let Some(config) = Self::try_load(path) {
                tracing::info!(?path, "loaded configuration");
                return config;
            }
        }

        tracing::debug!("no config file found, using defaults");
        Self::default()
    }

    fn try_load(path: &Path) -> Option<Self> {
        let content = std::fs::read_to_string(path).ok()?;
        match toml::from_str::<Config>(&content) {
            Ok(config) => Some(config),
            Err(e) => {
                tracing::warn!(?path, %e, "invalid config file, skipping");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values() {
        let c = Config::default();
        assert_eq!(c.default_timeout_seconds, 30);
        assert_eq!(c.max_output_bytes, 100 * 1024);
        assert_eq!(c.max_concurrency, 1);
        assert!(c.additional_safe_commands.is_empty());
    }

    #[test]
    fn parse_minimal_toml() {
        let toml_str = r#"
            default_timeout_seconds = 60
            max_output_bytes = 200000
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.default_timeout_seconds, 60);
        assert_eq!(config.max_output_bytes, 200_000);
        // defaults for unset fields
        assert_eq!(config.max_concurrency, 1);
    }

    #[test]
    fn parse_full_toml() {
        let toml_str = r#"
            default_timeout_seconds = 10
            max_output_bytes = 50000
            max_concurrency = 4
            additional_safe_commands = ["git", "make"]
            redact_env_patterns = ["(?i)MY_SECRET"]
            shell = "/bin/bash"
            http_bind = "0.0.0.0:8080"
            log_level = "debug"

            [[additional_protected_paths]]
            path = "/my/secret"
            read_allowed = false
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.max_concurrency, 4);
        assert_eq!(config.additional_safe_commands, vec!["git", "make"]);
        assert_eq!(config.additional_protected_paths.len(), 1);
        assert_eq!(config.additional_protected_paths[0].path, "/my/secret");
        assert!(!config.additional_protected_paths[0].read_allowed);
        assert_eq!(config.shell.as_deref(), Some("/bin/bash"));
    }

    #[test]
    fn load_returns_default_when_no_file() {
        // Ensure no config file interferes
        let prev = std::env::var("SAFESHELL_CONFIG").ok();
        unsafe { std::env::set_var("SAFESHELL_CONFIG", "/nonexistent/path/safeshell.toml") };
        let config = Config::load();
        assert_eq!(config.default_timeout_seconds, 30);
        if let Some(val) = prev {
            unsafe { std::env::set_var("SAFESHELL_CONFIG", val) };
        } else {
            unsafe { std::env::remove_var("SAFESHELL_CONFIG") };
        }
    }
}

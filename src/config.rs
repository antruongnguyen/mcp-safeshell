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
    /// Path to a log file. When set, logs are also written here.
    pub log_file: Option<String>,
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
            log_file: None,
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
        assert!(c.additional_protected_paths.is_empty());
        assert!(c.redact_env_patterns.is_empty());
        assert!(c.shell.is_none());
        assert!(c.http_bind.is_none());
        assert!(c.log_level.is_none());
        assert!(c.log_file.is_none());
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
        assert_eq!(config.max_concurrency, 1);
        assert!(config.shell.is_none());
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
            log_file = "/var/log/safeshell.log"

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
        assert_eq!(config.http_bind.as_deref(), Some("0.0.0.0:8080"));
        assert_eq!(config.log_level.as_deref(), Some("debug"));
        assert_eq!(config.log_file.as_deref(), Some("/var/log/safeshell.log"));
    }

    #[test]
    fn parse_empty_toml() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(config.default_timeout_seconds, 30);
        assert_eq!(config.max_output_bytes, 100 * 1024);
    }

    #[test]
    fn parse_multiple_protected_paths() {
        let toml_str = r#"
            [[additional_protected_paths]]
            path = "/data/prod"
            read_allowed = true

            [[additional_protected_paths]]
            path = "/secrets"
            read_allowed = false
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.additional_protected_paths.len(), 2);
        assert!(config.additional_protected_paths[0].read_allowed);
        assert!(!config.additional_protected_paths[1].read_allowed);
    }

    #[test]
    fn protected_path_read_allowed_defaults_false() {
        let toml_str = r#"
            [[additional_protected_paths]]
            path = "/no-read-allowed-field"
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(!config.additional_protected_paths[0].read_allowed);
    }

    #[test]
    fn parse_multiple_safe_commands() {
        let toml_str = r#"
            additional_safe_commands = ["git", "make", "just", "nx", "pnpm"]
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.additional_safe_commands.len(), 5);
        assert!(config.additional_safe_commands.contains(&"git".to_string()));
        assert!(config.additional_safe_commands.contains(&"pnpm".to_string()));
    }

    #[test]
    fn parse_multiple_redact_patterns() {
        let toml_str = r#"
            redact_env_patterns = ["(?i)MY_.*", "CUSTOM_TOKEN"]
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.redact_env_patterns.len(), 2);
    }

    #[test]
    fn load_returns_default_when_no_file() {
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

    #[test]
    fn try_load_nonexistent_returns_none() {
        assert!(Config::try_load(Path::new("/nonexistent/safeshell.toml")).is_none());
    }

    #[test]
    fn invalid_toml_returns_none() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("safeshell_test_invalid");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("invalid.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "this is not [valid toml {{{{").unwrap();
        assert!(Config::try_load(&path).is_none());
        let _ = std::fs::remove_file(&path);
    }
}

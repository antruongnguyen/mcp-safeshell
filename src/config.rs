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
    ///
    /// After loading from file (or defaults), environment variables with the
    /// `SAFESHELL_` prefix override individual fields. See [`apply_env_overrides`].
    pub fn load() -> Self {
        let candidates: Vec<PathBuf> = [
            std::env::var("SAFESHELL_CONFIG").ok().map(PathBuf::from),
            Some(PathBuf::from("./safeshell.toml")),
            dirs::config_dir().map(|d| d.join("safeshell").join("config.toml")),
        ]
        .into_iter()
        .flatten()
        .collect();

        let mut config = None;
        for path in &candidates {
            if let Some(c) = Self::try_load(path) {
                tracing::info!(?path, "loaded configuration");
                config = Some(c);
                break;
            }
        }

        let mut config = config.unwrap_or_else(|| {
            tracing::debug!("no config file found, using defaults");
            Self::default()
        });
        config.apply_env_overrides();
        config
    }

    /// Override config fields from `SAFESHELL_*` environment variables.
    ///
    /// Mapping:
    /// - `SAFESHELL_TIMEOUT`         → `default_timeout_seconds`
    /// - `SAFESHELL_MAX_OUTPUT`      → `max_output_bytes`
    /// - `SAFESHELL_MAX_CONCURRENCY` → `max_concurrency`
    /// - `SAFESHELL_SHELL`           → `shell`
    /// - `SAFESHELL_HTTP_BIND`       → `http_bind`
    /// - `SAFESHELL_LOG_LEVEL`       → `log_level`
    /// - `SAFESHELL_LOG_FILE`        → `log_file`
    /// - `SAFESHELL_SAFE_COMMANDS`   → `additional_safe_commands` (comma-separated)
    /// - `SAFESHELL_REDACT_PATTERNS` → `redact_env_patterns` (comma-separated)
    fn apply_env_overrides(&mut self) {
        if let Ok(val) = std::env::var("SAFESHELL_TIMEOUT") {
            if let Ok(v) = val.parse::<u64>() {
                tracing::debug!(SAFESHELL_TIMEOUT = %val, "env override");
                self.default_timeout_seconds = v;
            } else {
                tracing::warn!(SAFESHELL_TIMEOUT = %val, "ignoring non-numeric value");
            }
        }
        if let Ok(val) = std::env::var("SAFESHELL_MAX_OUTPUT") {
            if let Ok(v) = val.parse::<usize>() {
                tracing::debug!(SAFESHELL_MAX_OUTPUT = %val, "env override");
                self.max_output_bytes = v;
            } else {
                tracing::warn!(SAFESHELL_MAX_OUTPUT = %val, "ignoring non-numeric value");
            }
        }
        if let Ok(val) = std::env::var("SAFESHELL_MAX_CONCURRENCY") {
            if let Ok(v) = val.parse::<usize>() {
                tracing::debug!(SAFESHELL_MAX_CONCURRENCY = %val, "env override");
                self.max_concurrency = v;
            } else {
                tracing::warn!(SAFESHELL_MAX_CONCURRENCY = %val, "ignoring non-numeric value");
            }
        }
        if let Ok(val) = std::env::var("SAFESHELL_SHELL") {
            tracing::debug!(SAFESHELL_SHELL = %val, "env override");
            self.shell = Some(val);
        }
        if let Ok(val) = std::env::var("SAFESHELL_HTTP_BIND") {
            tracing::debug!(SAFESHELL_HTTP_BIND = %val, "env override");
            self.http_bind = Some(val);
        }
        if let Ok(val) = std::env::var("SAFESHELL_LOG_LEVEL") {
            tracing::debug!(SAFESHELL_LOG_LEVEL = %val, "env override");
            self.log_level = Some(val);
        }
        if let Ok(val) = std::env::var("SAFESHELL_LOG_FILE") {
            tracing::debug!(SAFESHELL_LOG_FILE = %val, "env override");
            self.log_file = Some(val);
        }
        if let Ok(val) = std::env::var("SAFESHELL_SAFE_COMMANDS") {
            tracing::debug!(SAFESHELL_SAFE_COMMANDS = %val, "env override");
            self.additional_safe_commands = val
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Ok(val) = std::env::var("SAFESHELL_REDACT_PATTERNS") {
            tracing::debug!(SAFESHELL_REDACT_PATTERNS = %val, "env override");
            self.redact_env_patterns = val
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
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
        assert!(
            config
                .additional_safe_commands
                .contains(&"pnpm".to_string())
        );
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
    fn env_override_numeric_fields() {
        let mut config = Config::default();
        unsafe {
            std::env::set_var("SAFESHELL_TIMEOUT", "120");
            std::env::set_var("SAFESHELL_MAX_OUTPUT", "512000");
            std::env::set_var("SAFESHELL_MAX_CONCURRENCY", "8");
        }
        config.apply_env_overrides();
        unsafe {
            std::env::remove_var("SAFESHELL_TIMEOUT");
            std::env::remove_var("SAFESHELL_MAX_OUTPUT");
            std::env::remove_var("SAFESHELL_MAX_CONCURRENCY");
        }
        assert_eq!(config.default_timeout_seconds, 120);
        assert_eq!(config.max_output_bytes, 512_000);
        assert_eq!(config.max_concurrency, 8);
    }

    #[test]
    fn env_override_string_fields() {
        let mut config = Config::default();
        unsafe {
            std::env::set_var("SAFESHELL_SHELL", "/bin/zsh");
            std::env::set_var("SAFESHELL_HTTP_BIND", "0.0.0.0:9090");
            std::env::set_var("SAFESHELL_LOG_LEVEL", "trace");
            std::env::set_var("SAFESHELL_LOG_FILE", "/tmp/ss.log");
        }
        config.apply_env_overrides();
        unsafe {
            std::env::remove_var("SAFESHELL_SHELL");
            std::env::remove_var("SAFESHELL_HTTP_BIND");
            std::env::remove_var("SAFESHELL_LOG_LEVEL");
            std::env::remove_var("SAFESHELL_LOG_FILE");
        }
        assert_eq!(config.shell.as_deref(), Some("/bin/zsh"));
        assert_eq!(config.http_bind.as_deref(), Some("0.0.0.0:9090"));
        assert_eq!(config.log_level.as_deref(), Some("trace"));
        assert_eq!(config.log_file.as_deref(), Some("/tmp/ss.log"));
    }

    #[test]
    fn env_override_comma_separated_lists() {
        let mut config = Config::default();
        unsafe {
            std::env::set_var("SAFESHELL_SAFE_COMMANDS", "git, make, cargo");
            std::env::set_var("SAFESHELL_REDACT_PATTERNS", "(?i)SECRET,TOKEN_.*");
        }
        config.apply_env_overrides();
        unsafe {
            std::env::remove_var("SAFESHELL_SAFE_COMMANDS");
            std::env::remove_var("SAFESHELL_REDACT_PATTERNS");
        }
        assert_eq!(
            config.additional_safe_commands,
            vec!["git", "make", "cargo"]
        );
        assert_eq!(config.redact_env_patterns, vec!["(?i)SECRET", "TOKEN_.*"]);
    }

    #[test]
    fn env_override_invalid_numeric_ignored() {
        let mut config = Config::default();
        let original_timeout = config.default_timeout_seconds;
        unsafe {
            std::env::set_var("SAFESHELL_TIMEOUT", "not_a_number");
        }
        config.apply_env_overrides();
        unsafe {
            std::env::remove_var("SAFESHELL_TIMEOUT");
        }
        assert_eq!(config.default_timeout_seconds, original_timeout);
    }

    #[test]
    fn env_override_replaces_config_file_values() {
        let toml_str = r#"
            default_timeout_seconds = 60
            shell = "/bin/bash"
            additional_safe_commands = ["old_cmd"]
        "#;
        let mut config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.default_timeout_seconds, 60);
        assert_eq!(config.shell.as_deref(), Some("/bin/bash"));

        unsafe {
            std::env::set_var("SAFESHELL_TIMEOUT", "90");
            std::env::set_var("SAFESHELL_SHELL", "/bin/fish");
            std::env::set_var("SAFESHELL_SAFE_COMMANDS", "new_cmd1,new_cmd2");
        }
        config.apply_env_overrides();
        unsafe {
            std::env::remove_var("SAFESHELL_TIMEOUT");
            std::env::remove_var("SAFESHELL_SHELL");
            std::env::remove_var("SAFESHELL_SAFE_COMMANDS");
        }
        assert_eq!(config.default_timeout_seconds, 90);
        assert_eq!(config.shell.as_deref(), Some("/bin/fish"));
        assert_eq!(
            config.additional_safe_commands,
            vec!["new_cmd1", "new_cmd2"]
        );
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

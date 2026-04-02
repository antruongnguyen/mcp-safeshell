/// Environment variable sanitization — redact sensitive values from command output.
use regex::Regex;

/// Default patterns matching sensitive env var names.
static DEFAULT_SENSITIVE_PATTERNS: &[&str] = &[
    "(?i).*SECRET.*",
    "(?i).*PASSWORD.*",
    "(?i).*PASSWD.*",
    "(?i).*TOKEN.*",
    "(?i).*API[_-]?KEY.*",
    "(?i).*PRIVATE[_-]?KEY.*",
    "(?i).*ACCESS[_-]?KEY.*",
    "(?i).*AUTH.*",
    "(?i).*CREDENTIAL.*",
    "(?i).*DATABASE[_-]?URL.*",
    "(?i).*CONNECTION[_-]?STRING.*",
    "(?i).*SMTP.*",
];

pub struct Sanitizer {
    sensitive_values: Vec<String>,
}

impl Sanitizer {
    /// Build a sanitizer by scanning the current environment for values matching
    /// the default + extra patterns.
    pub fn new(extra_patterns: &[String]) -> Self {
        let mut patterns: Vec<Regex> = DEFAULT_SENSITIVE_PATTERNS
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect();

        for p in extra_patterns {
            match Regex::new(p) {
                Ok(re) => patterns.push(re),
                Err(e) => tracing::warn!(pattern = %p, %e, "invalid redaction regex, skipping"),
            }
        }

        let mut sensitive_values = Vec::new();
        for (key, value) in std::env::vars() {
            if value.len() < 4 {
                continue; // skip very short values — too many false positives
            }
            if patterns.iter().any(|re| re.is_match(&key)) {
                sensitive_values.push(value);
            }
        }

        // Sort by length descending so longer values are replaced first
        sensitive_values.sort_by(|a, b| b.len().cmp(&a.len()));

        Self { sensitive_values }
    }

    /// Replace any sensitive env var values found in the text with `[REDACTED]`.
    pub fn redact(&self, text: &str) -> String {
        let mut result = text.to_string();
        for val in &self.sensitive_values {
            result = result.replace(val.as_str(), "[REDACTED]");
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_known_sensitive_values() {
        unsafe { std::env::set_var("TEST_API_KEY_SS", "supersecret42xyz") };
        let sanitizer = Sanitizer::new(&[]);
        let output = "the key is supersecret42xyz here";
        let redacted = sanitizer.redact(output);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("supersecret42xyz"));
        unsafe { std::env::remove_var("TEST_API_KEY_SS") };
    }

    #[test]
    fn does_not_redact_normal_text() {
        let sanitizer = Sanitizer::new(&[]);
        let output = "hello world, normal text";
        assert_eq!(sanitizer.redact(output), output);
    }

    #[test]
    fn custom_extra_patterns() {
        unsafe { std::env::set_var("MY_CUSTOM_SS", "myval42test") };
        let sanitizer = Sanitizer::new(&["(?i).*CUSTOM_SS.*".to_string()]);
        let output = "found myval42test in output";
        let redacted = sanitizer.redact(output);
        assert!(redacted.contains("[REDACTED]"));
        unsafe { std::env::remove_var("MY_CUSTOM_SS") };
    }
}

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
        sensitive_values.sort_by_key(|b| std::cmp::Reverse(b.len()));

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

    #[test]
    fn short_values_not_redacted() {
        // Values shorter than 4 chars should be skipped
        unsafe { std::env::set_var("TEST_SECRET_SHORT_SS", "abc") };
        let sanitizer = Sanitizer::new(&[]);
        let output = "the value is abc here";
        let redacted = sanitizer.redact(output);
        // "abc" is only 3 chars, should NOT be redacted
        assert_eq!(redacted, output);
        unsafe { std::env::remove_var("TEST_SECRET_SHORT_SS") };
    }

    #[test]
    fn exactly_four_chars_redacted() {
        unsafe { std::env::set_var("TEST_TOKEN_4CHAR_SS", "abcd") };
        let sanitizer = Sanitizer::new(&[]);
        let output = "token is abcd end";
        let redacted = sanitizer.redact(output);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("abcd"));
        unsafe { std::env::remove_var("TEST_TOKEN_4CHAR_SS") };
    }

    #[test]
    fn multiple_occurrences_all_redacted() {
        unsafe { std::env::set_var("TEST_PASSWORD_MULTI_SS", "mypassword123") };
        let sanitizer = Sanitizer::new(&[]);
        let output = "pass=mypassword123 and again mypassword123";
        let redacted = sanitizer.redact(output);
        assert!(!redacted.contains("mypassword123"));
        // Should have two [REDACTED] occurrences
        assert_eq!(redacted.matches("[REDACTED]").count(), 2);
        unsafe { std::env::remove_var("TEST_PASSWORD_MULTI_SS") };
    }

    #[test]
    fn empty_input_returns_empty() {
        let sanitizer = Sanitizer::new(&[]);
        assert_eq!(sanitizer.redact(""), "");
    }

    #[test]
    fn invalid_extra_pattern_skipped() {
        // Invalid regex pattern should be silently skipped, not panic
        let sanitizer = Sanitizer::new(&["[invalid regex".to_string()]);
        let output = "normal text";
        assert_eq!(sanitizer.redact(output), output);
    }

    #[test]
    fn default_patterns_match_common_sensitive_names() {
        // Test that the default patterns match expected env var name patterns
        let default_patterns: Vec<Regex> = DEFAULT_SENSITIVE_PATTERNS
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect();

        let matches = |name: &str| default_patterns.iter().any(|re| re.is_match(name));

        assert!(matches("MY_SECRET"));
        assert!(matches("DATABASE_PASSWORD"));
        assert!(matches("GITHUB_TOKEN"));
        assert!(matches("AWS_API_KEY"));
        assert!(matches("PRIVATE_KEY_BASE64"));
        assert!(matches("ACCESS_KEY_ID"));
        assert!(matches("AUTH_HEADER"));
        assert!(matches("DB_CREDENTIAL"));
        assert!(matches("DATABASE_URL"));
        assert!(matches("CONNECTION_STRING"));
        assert!(matches("SMTP_PASSWORD"));

        // Should NOT match normal env vars
        assert!(!matches("HOME"));
        assert!(!matches("PATH"));
        assert!(!matches("SHELL"));
        assert!(!matches("USER"));
    }

    #[test]
    fn longer_values_replaced_first() {
        // If two sensitive values overlap (e.g., "secret" and "supersecret"),
        // the longer one should be replaced first to prevent partial replacements
        unsafe {
            std::env::set_var("TEST_TOKEN_LONG_SS", "supersecretvalue");
            std::env::set_var("TEST_AUTH_SHORT_SS", "secret");
        };
        let sanitizer = Sanitizer::new(&[]);
        // "secret" < 4 chars check doesn't apply (it's 6 chars)
        // but "supersecretvalue" is longer and should be replaced first
        let output = "value=supersecretvalue";
        let redacted = sanitizer.redact(output);
        assert!(!redacted.contains("supersecretvalue"));
        unsafe {
            std::env::remove_var("TEST_TOKEN_LONG_SS");
            std::env::remove_var("TEST_AUTH_SHORT_SS");
        };
    }
}

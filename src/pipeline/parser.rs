//! Stage 1: Command Parser
//!
//! Tokenizes a raw command string, detects pipes/chains/redirections,
//! resolves `~` and normalizes path-like arguments to absolute paths.

use std::path::{Path, PathBuf};

/// A single parsed sub-command within a pipeline or chain.
#[derive(Debug, Clone)]
pub struct ParsedCommand {
    /// The base command name (e.g. "rm", "ls").
    pub command: String,
    /// All arguments.
    pub args: Vec<String>,
    /// Any path-like arguments resolved to absolute paths.
    pub resolved_paths: Vec<PathBuf>,
    /// The raw input that produced this sub-command.
    pub raw: String,
}

/// Result of parsing: one or more sub-commands.
#[derive(Debug, Clone)]
pub struct ParseResult {
    pub commands: Vec<ParsedCommand>,
}

/// Parse a raw command string into sub-commands.
///
/// Splits on `&&`, `||`, `;`, and `|` to extract individual commands.
/// For each, resolves `~` in arguments and identifies path-like arguments.
pub fn parse(raw_command: &str, working_dir: &Path) -> ParseResult {
    let raw = raw_command.trim();
    let segments = split_chain(raw);

    let commands = segments
        .into_iter()
        .map(|seg| parse_single(seg.trim(), working_dir))
        .collect();

    ParseResult { commands }
}

/// Split a command string on chain operators: `&&`, `||`, `;`, `|`.
fn split_chain(input: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut start = 0;
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    while i < len {
        let ch = bytes[i];

        if ch == b'\'' && !in_double_quote {
            in_single_quote = !in_single_quote;
            i += 1;
            continue;
        }
        if ch == b'"' && !in_single_quote {
            in_double_quote = !in_double_quote;
            i += 1;
            continue;
        }

        if in_single_quote || in_double_quote {
            i += 1;
            continue;
        }

        // Check for `&&` or `||`
        if i + 1 < len && ((ch == b'&' && bytes[i + 1] == b'&') || (ch == b'|' && bytes[i + 1] == b'|')) {
            segments.push(&input[start..i]);
            i += 2;
            start = i;
            continue;
        }

        // Single `|` (pipe) or `;`
        if ch == b'|' || ch == b';' {
            segments.push(&input[start..i]);
            i += 1;
            start = i;
            continue;
        }

        i += 1;
    }

    if start < len {
        segments.push(&input[start..]);
    }

    segments
}

/// Parse a single command (no chain operators).
fn parse_single(segment: &str, working_dir: &Path) -> ParsedCommand {
    let tokens = tokenize(segment);

    let command = tokens.first().cloned().unwrap_or_default();
    let args: Vec<String> = tokens.iter().skip(1).cloned().collect();

    // Resolve path-like arguments
    let resolved_paths = args
        .iter()
        .filter_map(|arg| resolve_if_path(arg, working_dir))
        .collect();

    ParsedCommand {
        command,
        args,
        resolved_paths,
        raw: segment.to_string(),
    }
}

/// Simple shell-like tokenizer. Handles single and double quotes.
/// Strips redirections (>, >>, <, 2>) but does not execute them.
fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\'' && !in_double {
            in_single = !in_single;
            continue;
        }
        if ch == '"' && !in_single {
            in_double = !in_double;
            continue;
        }
        if !in_single && !in_double {
            // Skip redirection operators and their targets
            if ch == '>' || ch == '<' {
                // Consume >> if present
                if ch == '>' {
                    if chars.peek() == Some(&'>') {
                        chars.next();
                    }
                }
                // Skip whitespace after redirection
                while chars.peek() == Some(&' ') {
                    chars.next();
                }
                // Skip the target filename
                let mut in_sq = false;
                let mut in_dq = false;
                loop {
                    match chars.peek() {
                        None => break,
                        Some(&'\'') if !in_dq => { in_sq = !in_sq; chars.next(); }
                        Some(&'"') if !in_sq => { in_dq = !in_dq; chars.next(); }
                        Some(&' ') if !in_sq && !in_dq => break,
                        _ => { chars.next(); }
                    }
                }
                continue;
            }
            // Handle 2> (stderr redirect)
            if ch == '2' && chars.peek() == Some(&'>') {
                chars.next(); // consume >
                if chars.peek() == Some(&'>') {
                    chars.next(); // consume second >
                }
                while chars.peek() == Some(&' ') {
                    chars.next();
                }
                loop {
                    match chars.peek() {
                        None => break,
                        Some(&' ') => break,
                        _ => { chars.next(); }
                    }
                }
                continue;
            }

            if ch == ' ' || ch == '\t' {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
                continue;
            }
        }
        current.push(ch);
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Resolve `~` to home directory, then make path absolute relative to working_dir.
/// Returns `None` if the argument doesn't look like a path.
fn resolve_if_path(arg: &str, working_dir: &Path) -> Option<PathBuf> {
    // Heuristic: it's a path if it contains `/`, `\`, starts with `.`, `~`, or is an absolute path
    let looks_like_path = arg.contains('/')
        || arg.contains('\\')
        || arg.starts_with('.')
        || arg.starts_with('~')
        || Path::new(arg).is_absolute();

    if !looks_like_path {
        return None;
    }

    let expanded = if arg.starts_with('~') {
        if let Some(home) = dirs::home_dir() {
            if arg == "~" {
                home
            } else {
                home.join(&arg[2..]) // skip "~/"
            }
        } else {
            PathBuf::from(arg)
        }
    } else {
        PathBuf::from(arg)
    };

    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        working_dir.join(expanded)
    };

    // Normalize without requiring the path to exist (no canonicalize here — that's for the guard)
    Some(normalize_path(&absolute))
}

/// Normalize a path by resolving `.` and `..` components lexically.
fn normalize_path(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                components.pop();
            }
            std::path::Component::CurDir => {}
            other => components.push(other),
        }
    }
    components.iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_command() {
        let result = parse("ls -la", Path::new("/tmp"));
        assert_eq!(result.commands.len(), 1);
        assert_eq!(result.commands[0].command, "ls");
        assert_eq!(result.commands[0].args, vec!["-la"]);
    }

    #[test]
    fn test_chained_commands() {
        let result = parse("echo hello && rm -rf /tmp/build", Path::new("/tmp"));
        assert_eq!(result.commands.len(), 2);
        assert_eq!(result.commands[0].command, "echo");
        assert_eq!(result.commands[1].command, "rm");
    }

    #[test]
    fn test_piped_commands() {
        let result = parse("cat /etc/hosts | grep localhost", Path::new("/"));
        assert_eq!(result.commands.len(), 2);
        assert_eq!(result.commands[0].command, "cat");
        assert_eq!(result.commands[1].command, "grep");
    }

    #[test]
    fn test_path_resolution() {
        let result = parse("cat ./file.txt", Path::new("/home/user"));
        assert_eq!(result.commands[0].resolved_paths.len(), 1);
        assert_eq!(
            result.commands[0].resolved_paths[0],
            PathBuf::from("/home/user/file.txt")
        );
    }

    #[test]
    fn test_tilde_expansion() {
        let result = parse("cat ~/test.txt", Path::new("/tmp"));
        assert_eq!(result.commands[0].resolved_paths.len(), 1);
        // Should start with the home directory
        assert!(result.commands[0].resolved_paths[0].is_absolute());
    }
}

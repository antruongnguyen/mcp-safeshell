//! Stage 1: Command Parser
//!
//! Tokenizes a raw command string, detects pipes/chains/redirections,
//! resolves `~` and normalizes path-like arguments to absolute paths.

use std::path::{Path, PathBuf};

/// The operator connecting two sub-commands in a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainOperator {
    /// `&&` — run next only if previous succeeded.
    And,
    /// `||` — run next only if previous failed.
    Or,
    /// `|` — pipe stdout to next command's stdin.
    Pipe,
    /// `;` — unconditional sequencing.
    Semicolon,
}

/// A single parsed sub-command within a pipeline or chain.
#[derive(Debug, Clone)]
#[allow(dead_code)]
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
#[allow(dead_code)]
pub struct ParseResult {
    pub commands: Vec<ParsedCommand>,
    /// Operators between consecutive sub-commands.
    /// Length is always `commands.len() - 1` (empty for single commands).
    pub operators: Vec<ChainOperator>,
    /// Whether the input contained chain operators (more than one sub-command).
    pub is_chained: bool,
}

/// Parse a raw command string into sub-commands.
///
/// Splits on `&&`, `||`, `;`, and `|` to extract individual commands.
/// For each, resolves `~` in arguments and identifies path-like arguments.
pub fn parse(raw_command: &str, working_dir: &Path) -> ParseResult {
    let raw = raw_command.trim();
    let (segments, operators) = split_chain(raw);
    let is_chained = segments.len() > 1;

    let commands = segments
        .into_iter()
        .map(|seg| parse_single(seg.trim(), working_dir))
        .collect();

    ParseResult {
        commands,
        operators,
        is_chained,
    }
}

/// Split a command string on chain operators: `&&`, `||`, `;`, `|`.
/// Returns the segments and the operators between them.
fn split_chain(input: &str) -> (Vec<&str>, Vec<ChainOperator>) {
    let mut segments = Vec::new();
    let mut operators = Vec::new();
    let mut start = 0;
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    // Handle empty input: return a single empty segment
    if len == 0 {
        return (vec![input], operators);
    }

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
        if i + 1 < len {
            if ch == b'&' && bytes[i + 1] == b'&' {
                segments.push(&input[start..i]);
                operators.push(ChainOperator::And);
                i += 2;
                start = i;
                continue;
            }
            if ch == b'|' && bytes[i + 1] == b'|' {
                segments.push(&input[start..i]);
                operators.push(ChainOperator::Or);
                i += 2;
                start = i;
                continue;
            }
        }

        // Single `|` (pipe)
        if ch == b'|' {
            segments.push(&input[start..i]);
            operators.push(ChainOperator::Pipe);
            i += 1;
            start = i;
            continue;
        }

        // `;` (semicolon)
        if ch == b';' {
            segments.push(&input[start..i]);
            operators.push(ChainOperator::Semicolon);
            i += 1;
            start = i;
            continue;
        }

        i += 1;
    }

    // Always push the trailing segment so even empty input produces one entry
    segments.push(&input[start..]);

    (segments, operators)
}

/// Parse a single command (no chain operators).
fn parse_single(segment: &str, working_dir: &Path) -> ParsedCommand {
    let TokenizeResult {
        tokens,
        redirection_targets,
    } = tokenize(segment);

    let command = tokens.first().cloned().unwrap_or_default();
    let args: Vec<String> = tokens.iter().skip(1).cloned().collect();

    // Resolve path-like arguments AND redirection targets (e.g., `> /etc/shadow`)
    let mut resolved_paths: Vec<PathBuf> = args
        .iter()
        .filter_map(|arg| resolve_if_path(arg, working_dir))
        .collect();

    for target in &redirection_targets {
        if let Some(p) = resolve_if_path(target, working_dir) {
            resolved_paths.push(p);
        }
    }

    ParsedCommand {
        command,
        args,
        resolved_paths,
        raw: segment.to_string(),
    }
}

/// Result of tokenizing: the command tokens plus any redirection target paths.
struct TokenizeResult {
    tokens: Vec<String>,
    /// File paths that appeared as redirection targets (e.g., `> /etc/shadow`).
    /// These are NOT included in `tokens` but must be checked by the location guard.
    redirection_targets: Vec<String>,
}

/// Simple shell-like tokenizer. Handles single and double quotes.
/// Strips redirections (>, >>, <, 2>) from tokens but captures their targets
/// so the location guard can check them.
fn tokenize(input: &str) -> TokenizeResult {
    let mut tokens = Vec::new();
    let mut redirection_targets = Vec::new();
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
            // Capture redirection operators and their targets
            if ch == '>' || ch == '<' {
                // Push any pending token first
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
                // Consume >> if present
                if ch == '>' && chars.peek() == Some(&'>') {
                    chars.next();
                }
                // Skip whitespace after redirection
                while chars.peek() == Some(&' ') {
                    chars.next();
                }
                // Collect the target filename
                let mut target = String::new();
                let mut in_sq = false;
                let mut in_dq = false;
                loop {
                    match chars.peek() {
                        None => break,
                        Some(&'\'') if !in_dq => {
                            in_sq = !in_sq;
                            chars.next();
                        }
                        Some(&'"') if !in_sq => {
                            in_dq = !in_dq;
                            chars.next();
                        }
                        Some(&' ') if !in_sq && !in_dq => break,
                        _ => {
                            target.push(*chars.peek().unwrap());
                            chars.next();
                        }
                    }
                }
                if !target.is_empty() {
                    redirection_targets.push(target);
                }
                continue;
            }
            // Handle 2> (stderr redirect)
            if ch == '2' && chars.peek() == Some(&'>') {
                // Push any pending token first
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
                chars.next(); // consume >
                if chars.peek() == Some(&'>') {
                    chars.next(); // consume second >
                }
                while chars.peek() == Some(&' ') {
                    chars.next();
                }
                let mut target = String::new();
                loop {
                    match chars.peek() {
                        None => break,
                        Some(&' ') => break,
                        _ => {
                            target.push(*chars.peek().unwrap());
                            chars.next();
                        }
                    }
                }
                if !target.is_empty() {
                    redirection_targets.push(target);
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
    TokenizeResult {
        tokens,
        redirection_targets,
    }
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

    // ── Basic command parsing ──────────────────────────────────────

    #[test]
    fn simple_command() {
        let result = parse("ls -la", Path::new("/tmp"));
        assert_eq!(result.commands.len(), 1);
        assert_eq!(result.commands[0].command, "ls");
        assert_eq!(result.commands[0].args, vec!["-la"]);
        assert!(!result.is_chained);
        assert!(result.operators.is_empty());
    }

    #[test]
    fn command_no_args() {
        let result = parse("whoami", Path::new("/tmp"));
        assert_eq!(result.commands.len(), 1);
        assert_eq!(result.commands[0].command, "whoami");
        assert!(result.commands[0].args.is_empty());
    }

    #[test]
    fn command_multiple_args() {
        let result = parse("grep -rn pattern src/", Path::new("/project"));
        assert_eq!(result.commands[0].command, "grep");
        assert_eq!(result.commands[0].args, vec!["-rn", "pattern", "src/"]);
    }

    #[test]
    fn empty_input() {
        let result = parse("", Path::new("/tmp"));
        assert_eq!(result.commands.len(), 1);
        assert_eq!(result.commands[0].command, "");
    }

    #[test]
    fn whitespace_only() {
        let result = parse("   ", Path::new("/tmp"));
        assert_eq!(result.commands.len(), 1);
        assert_eq!(result.commands[0].command, "");
    }

    #[test]
    fn leading_trailing_whitespace() {
        let result = parse("  ls -la  ", Path::new("/tmp"));
        assert_eq!(result.commands[0].command, "ls");
        assert_eq!(result.commands[0].args, vec!["-la"]);
    }

    // ── Chain operator splitting ───────────────────────────────────

    #[test]
    fn and_chain() {
        let result = parse("echo hello && rm -rf /tmp/build", Path::new("/tmp"));
        assert_eq!(result.commands.len(), 2);
        assert_eq!(result.commands[0].command, "echo");
        assert_eq!(result.commands[1].command, "rm");
        assert!(result.is_chained);
        assert_eq!(result.operators, vec![ChainOperator::And]);
    }

    #[test]
    fn pipe_chain() {
        let result = parse("cat /etc/hosts | grep localhost", Path::new("/"));
        assert_eq!(result.commands.len(), 2);
        assert_eq!(result.commands[0].command, "cat");
        assert_eq!(result.commands[1].command, "grep");
        assert!(result.is_chained);
        assert_eq!(result.operators, vec![ChainOperator::Pipe]);
    }

    #[test]
    fn or_chain() {
        let result = parse("test -f file.txt || echo missing", Path::new("/tmp"));
        assert_eq!(result.commands.len(), 2);
        assert_eq!(result.commands[0].command, "test");
        assert_eq!(result.commands[1].command, "echo");
        assert_eq!(result.operators, vec![ChainOperator::Or]);
    }

    #[test]
    fn semicolon_chain() {
        let result = parse("echo start; ls; echo done", Path::new("/tmp"));
        assert_eq!(result.commands.len(), 3);
        assert_eq!(result.commands[0].command, "echo");
        assert_eq!(result.commands[1].command, "ls");
        assert_eq!(result.commands[2].command, "echo");
        assert_eq!(
            result.operators,
            vec![ChainOperator::Semicolon, ChainOperator::Semicolon]
        );
    }

    #[test]
    fn mixed_operators() {
        let result = parse(
            "echo a && echo b | grep b || echo c; echo d",
            Path::new("/tmp"),
        );
        assert_eq!(result.commands.len(), 5);
        assert_eq!(
            result.operators,
            vec![
                ChainOperator::And,
                ChainOperator::Pipe,
                ChainOperator::Or,
                ChainOperator::Semicolon,
            ]
        );
    }

    #[test]
    fn multiple_pipes() {
        let result = parse("cat file | grep foo | wc -l", Path::new("/tmp"));
        assert_eq!(result.commands.len(), 3);
        assert_eq!(result.operators, vec![ChainOperator::Pipe, ChainOperator::Pipe]);
        assert_eq!(result.commands[0].command, "cat");
        assert_eq!(result.commands[1].command, "grep");
        assert_eq!(result.commands[2].command, "wc");
    }

    #[test]
    fn consecutive_and_operators() {
        let result = parse("cmd1 && cmd2 && cmd3", Path::new("/tmp"));
        assert_eq!(result.commands.len(), 3);
        assert_eq!(result.operators, vec![ChainOperator::And, ChainOperator::And]);
    }

    // ── Quote handling ─────────────────────────────────────────────

    #[test]
    fn single_quoted_operators_not_split() {
        let result = parse("echo 'hello && world'", Path::new("/tmp"));
        assert_eq!(result.commands.len(), 1);
        assert_eq!(result.commands[0].command, "echo");
        assert!(!result.is_chained);
    }

    #[test]
    fn double_quoted_operators_not_split() {
        let result = parse("echo \"hello | world\"", Path::new("/tmp"));
        assert_eq!(result.commands.len(), 1);
        assert_eq!(result.commands[0].command, "echo");
        assert_eq!(result.commands[0].args, vec!["hello | world"]);
    }

    #[test]
    fn single_quotes_preserve_semicolons() {
        let result = parse("echo 'foo; bar'", Path::new("/tmp"));
        assert_eq!(result.commands.len(), 1);
        assert!(!result.is_chained);
    }

    #[test]
    fn double_quotes_preserve_or_operator() {
        let result = parse("echo \"a || b\"", Path::new("/tmp"));
        assert_eq!(result.commands.len(), 1);
    }

    #[test]
    fn mixed_quotes_in_args() {
        let result = parse("echo 'hello' \"world\"", Path::new("/tmp"));
        assert_eq!(result.commands[0].command, "echo");
        assert_eq!(result.commands[0].args, vec!["hello", "world"]);
    }

    #[test]
    fn empty_quoted_string() {
        let result = parse("echo '' \"\"", Path::new("/tmp"));
        assert_eq!(result.commands[0].command, "echo");
        // Empty quotes produce empty tokens which are not emitted
    }

    // ── Redirection stripping ──────────────────────────────────────

    #[test]
    fn stdout_redirect_stripped() {
        let result = parse("echo hello > output.txt", Path::new("/tmp"));
        assert_eq!(result.commands[0].command, "echo");
        assert_eq!(result.commands[0].args, vec!["hello"]);
    }

    #[test]
    fn stdout_append_redirect_stripped() {
        let result = parse("echo hello >> output.txt", Path::new("/tmp"));
        assert_eq!(result.commands[0].command, "echo");
        assert_eq!(result.commands[0].args, vec!["hello"]);
    }

    #[test]
    fn stdin_redirect_stripped() {
        let result = parse("sort < input.txt", Path::new("/tmp"));
        assert_eq!(result.commands[0].command, "sort");
        assert!(result.commands[0].args.is_empty());
    }

    #[test]
    fn stderr_redirect_stripped() {
        let result = parse("make build 2> errors.log", Path::new("/tmp"));
        assert_eq!(result.commands[0].command, "make");
        assert_eq!(result.commands[0].args, vec!["build"]);
    }

    #[test]
    fn multiple_redirections_stripped() {
        let result = parse("cmd arg1 > out.txt 2> err.txt", Path::new("/tmp"));
        assert_eq!(result.commands[0].command, "cmd");
        assert_eq!(result.commands[0].args, vec!["arg1"]);
    }

    // ── Path resolution ────────────────────────────────────────────

    #[test]
    fn relative_path_resolved_to_absolute() {
        let result = parse("cat ./file.txt", Path::new("/home/user"));
        assert_eq!(result.commands[0].resolved_paths.len(), 1);
        assert_eq!(
            result.commands[0].resolved_paths[0],
            PathBuf::from("/home/user/file.txt")
        );
    }

    #[test]
    fn tilde_expansion() {
        let result = parse("cat ~/test.txt", Path::new("/tmp"));
        assert_eq!(result.commands[0].resolved_paths.len(), 1);
        assert!(result.commands[0].resolved_paths[0].is_absolute());
        assert!(result.commands[0].resolved_paths[0]
            .to_string_lossy()
            .contains("test.txt"));
    }

    #[test]
    fn tilde_alone_expands_to_home() {
        let result = parse("ls ~", Path::new("/tmp"));
        assert_eq!(result.commands[0].resolved_paths.len(), 1);
        if let Some(home) = dirs::home_dir() {
            assert_eq!(result.commands[0].resolved_paths[0], home);
        }
    }

    #[test]
    fn absolute_path_preserved() {
        let result = parse("cat /etc/hosts", Path::new("/tmp"));
        assert_eq!(result.commands[0].resolved_paths.len(), 1);
        assert_eq!(
            result.commands[0].resolved_paths[0],
            PathBuf::from("/etc/hosts")
        );
    }

    #[test]
    fn parent_dir_normalized() {
        let result = parse("cat /home/user/../shared/file.txt", Path::new("/tmp"));
        assert_eq!(result.commands[0].resolved_paths.len(), 1);
        assert_eq!(
            result.commands[0].resolved_paths[0],
            PathBuf::from("/home/shared/file.txt")
        );
    }

    #[test]
    fn current_dir_dot_normalized() {
        let result = parse("cat /home/./user/./file.txt", Path::new("/tmp"));
        assert_eq!(result.commands[0].resolved_paths.len(), 1);
        assert_eq!(
            result.commands[0].resolved_paths[0],
            PathBuf::from("/home/user/file.txt")
        );
    }

    #[test]
    fn non_path_args_not_resolved() {
        let result = parse("echo hello world", Path::new("/tmp"));
        assert!(result.commands[0].resolved_paths.is_empty());
    }

    #[test]
    fn flag_args_not_resolved() {
        let result = parse("ls -la --color=auto", Path::new("/tmp"));
        assert!(result.commands[0].resolved_paths.is_empty());
    }

    #[test]
    fn multiple_paths_resolved() {
        let result = parse("diff ./a.txt ./b.txt", Path::new("/home/user"));
        assert_eq!(result.commands[0].resolved_paths.len(), 2);
        assert_eq!(
            result.commands[0].resolved_paths[0],
            PathBuf::from("/home/user/a.txt")
        );
        assert_eq!(
            result.commands[0].resolved_paths[1],
            PathBuf::from("/home/user/b.txt")
        );
    }

    #[test]
    fn path_with_slash_in_name_detected() {
        let result = parse("cat src/main.rs", Path::new("/project"));
        assert_eq!(result.commands[0].resolved_paths.len(), 1);
        assert_eq!(
            result.commands[0].resolved_paths[0],
            PathBuf::from("/project/src/main.rs")
        );
    }

    #[test]
    fn deeply_nested_parent_dirs() {
        let result = parse("cat /a/b/c/../../d", Path::new("/tmp"));
        assert_eq!(
            result.commands[0].resolved_paths[0],
            PathBuf::from("/a/d")
        );
    }

    // ── normalize_path unit tests ──────────────────────────────────

    #[test]
    fn normalize_removes_dot() {
        assert_eq!(normalize_path(Path::new("/a/./b/c")), PathBuf::from("/a/b/c"));
    }

    #[test]
    fn normalize_resolves_dotdot() {
        assert_eq!(
            normalize_path(Path::new("/a/b/../c")),
            PathBuf::from("/a/c")
        );
    }

    #[test]
    fn normalize_multiple_dotdot() {
        assert_eq!(
            normalize_path(Path::new("/a/b/c/../../d")),
            PathBuf::from("/a/d")
        );
    }

    #[test]
    fn normalize_already_clean() {
        assert_eq!(
            normalize_path(Path::new("/usr/bin/ls")),
            PathBuf::from("/usr/bin/ls")
        );
    }

    // ── Tokenizer edge cases ───────────────────────────────────────

    #[test]
    fn tokenize_tabs_as_whitespace() {
        let result = tokenize("ls\t-la\t/tmp");
        assert_eq!(result.tokens, vec!["ls", "-la", "/tmp"]);
    }

    #[test]
    fn tokenize_multiple_spaces() {
        let result = tokenize("echo    hello    world");
        assert_eq!(result.tokens, vec!["echo", "hello", "world"]);
    }

    #[test]
    fn tokenize_single_quotes() {
        let result = tokenize("echo 'hello world'");
        assert_eq!(result.tokens, vec!["echo", "hello world"]);
    }

    #[test]
    fn tokenize_double_quotes() {
        let result = tokenize("echo \"hello world\"");
        assert_eq!(result.tokens, vec!["echo", "hello world"]);
    }

    #[test]
    fn tokenize_nested_quote_inside_other() {
        // Single quote inside double quotes
        let result = tokenize("echo \"it's fine\"");
        assert_eq!(result.tokens, vec!["echo", "it's fine"]);
    }

    #[test]
    fn tokenize_redirect_with_quoted_target() {
        let result = tokenize("echo hello > 'out file.txt'");
        assert_eq!(result.tokens, vec!["echo", "hello"]);
        assert_eq!(result.redirection_targets, vec!["out file.txt"]);
    }

    // ── split_chain edge cases ─────────────────────────────────────

    #[test]
    fn split_chain_single_command() {
        let (segs, ops) = split_chain("echo hello");
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0], "echo hello");
        assert!(ops.is_empty());
    }

    #[test]
    fn split_chain_empty() {
        let (segs, ops) = split_chain("");
        assert!(segs.is_empty() || segs == vec![""]);
        assert!(ops.is_empty());
    }

    #[test]
    fn split_chain_quoted_and_unquoted_mixed() {
        let (segs, ops) = split_chain("echo 'a && b' && echo c");
        assert_eq!(segs.len(), 2);
        assert_eq!(ops, vec![ChainOperator::And]);
        assert!(segs[0].contains("'a && b'"));
        assert!(segs[1].trim() == "echo c");
    }

    // ── Chained commands with path resolution ──────────────────────

    #[test]
    fn chained_commands_paths_resolved_independently() {
        let result = parse("cat ./a.txt | grep foo > /dev/null", Path::new("/work"));
        assert_eq!(result.commands.len(), 2);
        assert_eq!(
            result.commands[0].resolved_paths[0],
            PathBuf::from("/work/a.txt")
        );
        // grep foo has no path args; > /dev/null is a redirection target now resolved
        assert_eq!(
            result.commands[1].resolved_paths,
            vec![PathBuf::from("/dev/null")]
        );
    }

    #[test]
    fn raw_preserves_original_text() {
        let result = parse("echo hello", Path::new("/tmp"));
        assert_eq!(result.commands[0].raw, "echo hello");
    }

    #[test]
    fn raw_preserves_chain_segments() {
        let result = parse("echo a && echo b", Path::new("/tmp"));
        assert_eq!(result.commands[0].raw.trim(), "echo a");
        assert_eq!(result.commands[1].raw.trim(), "echo b");
    }

    // ── Redirection target path resolution ────────────────────────

    #[test]
    fn redirect_stdout_target_resolved() {
        let result = parse("echo evil > /etc/shadow", Path::new("/tmp"));
        assert!(result.commands[0]
            .resolved_paths
            .contains(&PathBuf::from("/etc/shadow")));
    }

    #[test]
    fn redirect_append_target_resolved() {
        let result = parse("echo data >> /var/log/auth.log", Path::new("/tmp"));
        assert!(result.commands[0]
            .resolved_paths
            .contains(&PathBuf::from("/var/log/auth.log")));
    }

    #[test]
    fn redirect_stderr_target_resolved() {
        let result = parse("cmd 2> /etc/passwd", Path::new("/tmp"));
        assert!(result.commands[0]
            .resolved_paths
            .contains(&PathBuf::from("/etc/passwd")));
    }

    #[test]
    fn redirect_relative_target_resolved_to_absolute() {
        let result = parse("echo x > ./output.txt", Path::new("/home/user"));
        assert!(result.commands[0]
            .resolved_paths
            .contains(&PathBuf::from("/home/user/output.txt")));
    }

    #[test]
    fn multiple_redirections_all_resolved() {
        let result = parse("cmd > /tmp/out.txt 2> /tmp/err.txt", Path::new("/tmp"));
        let paths = &result.commands[0].resolved_paths;
        assert!(paths.contains(&PathBuf::from("/tmp/out.txt")));
        assert!(paths.contains(&PathBuf::from("/tmp/err.txt")));
    }
}

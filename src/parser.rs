//! Bash command parser using tree-sitter-bash for AST parsing.

use crate::models::CommandInfo;
use std::sync::{LazyLock, Mutex};
use tree_sitter::{Parser, Tree, TreeCursor};
use tree_sitter_bash::LANGUAGE;

static PARSER: LazyLock<Mutex<Parser>> = LazyLock::new(|| {
    let mut parser = Parser::new();
    parser
        .set_language(&LANGUAGE.into())
        .expect("Failed to set language");
    std::sync::Mutex::new(parser)
});

/// Extract all commands from a bash command string.
///
/// Handles:
/// - Simple commands: `gh pr list`
/// - Chained commands: `gh pr list && gh pr create`
/// - Pipelines: `gh pr list | head`
/// - Subshells: `$(gh pr create)`
/// - Quoted strings: `echo "gh pr create"` (not treated as gh command)
pub fn extract_commands(command_string: &str) -> Vec<CommandInfo> {
    if command_string.trim().is_empty() {
        return Vec::new();
    }

    let tree = {
        let mut parser = PARSER.lock().unwrap_or_else(|e| e.into_inner());
        match parser.parse(command_string, None) {
            Some(tree) => tree,
            None => return fallback_parse(command_string),
        }
    };

    let mut commands = Vec::new();
    extract_from_tree(&tree, command_string, &mut commands);

    if commands.is_empty() {
        return fallback_parse(command_string);
    }

    commands
}

fn extract_from_tree(tree: &Tree, source: &str, commands: &mut Vec<CommandInfo>) {
    let mut cursor = tree.walk();
    visit_node(&mut cursor, source, commands);
}

fn visit_node(cursor: &mut TreeCursor, source: &str, commands: &mut Vec<CommandInfo>) {
    let node = cursor.node();
    let kind = node.kind();

    match kind {
        "command" => {
            if let Some(cmd) = extract_command(cursor, source) {
                commands.push(cmd);
            }
            // Also check for nested substitutions within command arguments
            if cursor.goto_first_child() {
                loop {
                    let child = cursor.node();
                    if matches!(
                        child.kind(),
                        "command_substitution" | "process_substitution"
                    ) {
                        visit_node(cursor, source, commands);
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
                cursor.goto_parent();
            }
        }
        "pipeline" => {
            // Visit each command in the pipeline
            if cursor.goto_first_child() {
                loop {
                    let child = cursor.node();
                    if child.kind() == "command" {
                        if let Some(cmd) = extract_command(cursor, source) {
                            commands.push(cmd);
                        }
                    } else if child.kind() != "|" {
                        // Recurse into non-pipe children
                        visit_node(cursor, source, commands);
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
                cursor.goto_parent();
            }
        }
        "list"
        | "program"
        | "subshell"
        | "command_substitution"
        | "process_substitution" // <(...) and >(...) - must inspect contents
        | "if_statement"
        | "while_statement"
        | "for_statement"
        | "case_statement"
        | "compound_statement" => {
            // Visit all children
            if cursor.goto_first_child() {
                loop {
                    visit_node(cursor, source, commands);
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
                cursor.goto_parent();
            }
        }
        "function_definition" => {
            // Visit function body
            if cursor.goto_first_child() {
                loop {
                    let child = cursor.node();
                    if child.kind() == "compound_statement" {
                        visit_node(cursor, source, commands);
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
                cursor.goto_parent();
            }
        }
        _ => {
            // For other node types, try to visit children
            if cursor.goto_first_child() {
                loop {
                    visit_node(cursor, source, commands);
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
                cursor.goto_parent();
            }
        }
    }
}

fn extract_command(cursor: &mut TreeCursor, source: &str) -> Option<CommandInfo> {
    let node = cursor.node();
    let raw = node.utf8_text(source.as_bytes()).ok()?.to_string();

    let mut parts: Vec<String> = Vec::new();

    // Walk through command children to get words
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            match child.kind() {
                "word" | "simple_expansion" | "expansion" | "number" => {
                    if let Ok(text) = child.utf8_text(source.as_bytes()) {
                        parts.push(text.to_string());
                    }
                }
                "string" | "raw_string" => {
                    // Handle quoted strings - extract the content without quotes
                    if let Ok(text) = child.utf8_text(source.as_bytes()) {
                        let unquoted = unquote(text);
                        parts.push(unquoted);
                    }
                }
                "concatenation" => {
                    // Handle concatenated strings (e.g., "foo"bar)
                    if let Some(text) = extract_concatenation(cursor, source) {
                        parts.push(text);
                    }
                }
                "command_name"
                    // Command name can contain word or string
                    if cursor.goto_first_child() => {
                        let name_node = cursor.node();
                        if let Ok(text) = name_node.utf8_text(source.as_bytes()) {
                            parts.push(unquote(text));
                        }
                        cursor.goto_parent();
                    }
                _ => {}
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }

    if parts.is_empty() {
        return None;
    }

    let program = parts.remove(0);
    let args = parts;

    let (program, args) = strip_transparent_wrappers(program, args);

    Some(CommandInfo { raw, program, args })
}

/// Known transparent wrapper commands that just execute their arguments.
/// Does NOT include `sudo`/`doas` (handled separately due to flag-value pairs like `-u root`),
/// `env` (handles `VAR=value`), or `timeout` (has a positional duration arg).
const SIMPLE_WRAPPERS: &[&str] = &[
    "time", "exec", "nice", "nohup", "strace", "ltrace", "ionice", "taskset", "command", "builtin",
];

/// Flags for sudo/doas that consume the next argument as a value.
const SUDO_VALUE_FLAGS: &[&str] = &["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"];

/// Check if an argument looks like a numeric value (flag argument, not a command name).
///
/// Matches integers (`10`), floats (`3.14`), and duration-like values (`5s`, `30m`).
fn is_numeric_arg(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    // Strip trailing duration suffix (s, m, h, d) for values like "5s", "30m"
    let s = s.trim_end_matches(|c: char| "smhd".contains(c));
    if s.is_empty() {
        return false;
    }
    // Check if remaining is numeric (integer or float)
    s.parse::<f64>().is_ok()
}

/// Strip transparent wrapper commands so the inner command is exposed to gates.
///
/// Handles these cases recursively:
/// - Simple wrappers (`time`, `exec`, `nice`, etc.): skip flags, first non-flag arg becomes program
/// - `env`: skip `-flags` and `VAR=value` args to find the real command
/// - `timeout`: skip flags, then skip the duration arg, then the next arg is the command
///
/// Preserves the original `raw` field (the caller keeps it from the AST node).
/// If no inner command is found (e.g., `env` alone), keeps the wrapper as the program.
fn strip_transparent_wrappers(program: String, args: Vec<String>) -> (String, Vec<String>) {
    strip_wrapper_recursive(program, args)
}

fn strip_wrapper_recursive(program: String, args: Vec<String>) -> (String, Vec<String>) {
    if args.is_empty() {
        return (program, args);
    }

    if SIMPLE_WRAPPERS.contains(&program.as_str()) {
        // Skip flags and numeric flag values (e.g., `nice -n 10 rm`, where 10 is a flag value).
        // The first arg that doesn't start with `-` and isn't purely numeric is the command.
        if let Some(idx) = args
            .iter()
            .position(|a| !a.starts_with('-') && !is_numeric_arg(a))
        {
            let new_program = args[idx].clone();
            let new_args = args[idx + 1..].to_vec();
            return strip_wrapper_recursive(new_program, new_args);
        }
        // All args are flags or numeric values (e.g., `sudo -l`), keep as-is
        return (program, args);
    }

    if program == "sudo" || program == "doas" {
        // sudo/doas have flags that consume the next arg (e.g., `-u root`).
        // Walk through args, skipping flags and their values, to find the command.
        let mut i = 0;
        while i < args.len() {
            if args[i].starts_with('-') {
                // Check if this flag consumes the next argument
                if SUDO_VALUE_FLAGS.contains(&args[i].as_str()) {
                    i += 1; // skip the flag's value
                }
                i += 1;
                continue;
            }
            // First non-flag, non-value arg is the command
            let new_program = args[i].clone();
            let new_args = args[i + 1..].to_vec();
            return strip_wrapper_recursive(new_program, new_args);
        }
        // All args are flags/values (e.g., `sudo -l`), keep as-is
        return (program, args);
    }

    if program == "env" {
        // `env` can have -flags and VAR=value before the actual command
        if let Some(idx) = args
            .iter()
            .position(|a| !a.starts_with('-') && !a.contains('='))
        {
            let new_program = args[idx].clone();
            let new_args = args[idx + 1..].to_vec();
            return strip_wrapper_recursive(new_program, new_args);
        }
        // No real command found (e.g., `env` or `env VAR=val`), keep as-is
        return (program, args);
    }

    if program == "timeout" {
        // `timeout` takes: [flags...] duration command [args...]
        // Find first non-flag (duration), then next non-flag (command)
        let mut i = 0;
        // Skip flags
        while i < args.len() && args[i].starts_with('-') {
            i += 1;
        }
        // Skip duration
        if i < args.len() {
            i += 1;
        }
        // Next arg is the command
        if i < args.len() {
            let new_program = args[i].clone();
            let new_args = args[i + 1..].to_vec();
            return strip_wrapper_recursive(new_program, new_args);
        }
        // No command found, keep as-is
        return (program, args);
    }

    (program, args)
}

fn extract_concatenation(cursor: &mut TreeCursor, source: &str) -> Option<String> {
    let mut result = String::new();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if let Ok(text) = child.utf8_text(source.as_bytes()) {
                result.push_str(&unquote(text));
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Remove quotes from a string
fn unquote(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Fallback parser using simple tokenization when tree-sitter fails
fn fallback_parse(command_string: &str) -> Vec<CommandInfo> {
    let mut commands = Vec::new();

    // Split on compound operators (&&, ||, ;, |) before tokenizing each part
    let parts = split_on_operators(command_string);

    for part in &parts {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }

        let tokens = tokenize(trimmed);
        if tokens.is_empty() {
            continue;
        }

        let program = tokens[0].clone();
        let args = tokens[1..].to_vec();

        commands.push(CommandInfo {
            raw: command_string.to_string(),
            program,
            args,
        });
    }

    commands
}

/// Split a command string on compound operators (`&&`, `||`, `;`, `|`) while
/// respecting single- and double-quoted strings.  `||` is consumed as a single
/// two-character operator so it is never mistaken for two pipes.
fn split_on_operators(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escape_next = false;
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let c = chars[i];

        if escape_next {
            current.push(c);
            escape_next = false;
            i += 1;
            continue;
        }

        if c == '\\' && !in_single_quote {
            escape_next = true;
            current.push(c);
            i += 1;
            continue;
        }

        if c == '\'' && !in_double_quote {
            in_single_quote = !in_single_quote;
            current.push(c);
            i += 1;
            continue;
        }

        if c == '"' && !in_single_quote {
            in_double_quote = !in_double_quote;
            current.push(c);
            i += 1;
            continue;
        }

        // Only split when outside quotes
        if !in_single_quote && !in_double_quote {
            // Check two-character operators first: && and ||
            if i + 1 < len {
                let next = chars[i + 1];
                if (c == '&' && next == '&') || (c == '|' && next == '|') {
                    parts.push(current.clone());
                    current.clear();
                    i += 2;
                    continue;
                }
            }
            // Single-character operators: ; and | (single pipe)
            if c == ';' || c == '|' {
                parts.push(current.clone());
                current.clear();
                i += 1;
                continue;
            }
        }

        current.push(c);
        i += 1;
    }

    // Push the last segment
    if !current.is_empty() {
        parts.push(current);
    }

    parts
}

/// Simple tokenizer that handles quoted strings
fn tokenize(s: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escape_next = false;

    for c in s.chars() {
        if escape_next {
            current.push(c);
            escape_next = false;
            continue;
        }

        match c {
            '\\' if !in_single_quote => {
                escape_next = true;
            }
            '\'' if !in_double_quote => {
                in_single_quote = !in_single_quote;
            }
            '"' if !in_single_quote => {
                in_double_quote = !in_double_quote;
            }
            ' ' | '\t' if !in_single_quote && !in_double_quote => {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
            }
            _ => {
                current.push(c);
            }
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_command() {
        let cmds = extract_commands("gh pr list");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "gh");
        assert_eq!(cmds[0].args, vec!["pr", "list"]);
    }

    #[test]
    fn test_chained_commands() {
        let cmds = extract_commands("git status && git add .");
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].program, "git");
        assert_eq!(cmds[1].program, "git");
    }

    #[test]
    fn test_pipeline() {
        let cmds = extract_commands("gh pr list | head");
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].program, "gh");
        assert_eq!(cmds[1].program, "head");
    }

    #[test]
    fn test_quoted_string_not_command() {
        let cmds = extract_commands(r#"echo "gh pr create""#);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "echo");
        // The quoted string should be an argument, not parsed as a command
    }

    #[test]
    fn test_subshell() {
        let cmds = extract_commands("echo $(git status)");
        assert!(!cmds.is_empty());
        // Should detect commands in subshell
    }

    #[test]
    fn test_empty_command() {
        let cmds = extract_commands("");
        assert!(cmds.is_empty());
        let cmds = extract_commands("   ");
        assert!(cmds.is_empty());
    }

    #[test]
    fn test_tokenize() {
        let tokens = tokenize("git commit -m 'hello world'");
        assert_eq!(tokens, vec!["git", "commit", "-m", "hello world"]);
    }

    // === Edge Case Tests ===

    #[test]
    fn test_malformed_quotes_no_panic() {
        // Should not panic on unterminated quotes
        let cmds = extract_commands("echo 'unterminated");
        // Parser should either return something or empty, but not panic
        assert!(cmds.len() <= 1);
    }

    #[test]
    fn test_unicode_command() {
        let cmds = extract_commands("echo '测试' && git status");
        assert!(!cmds.is_empty(), "Should handle unicode");
    }

    #[test]
    fn test_very_long_argument() {
        let long_arg = "x".repeat(10000);
        let cmd = format!("echo {long_arg}");
        let cmds = extract_commands(&cmd);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "echo");
    }

    #[test]
    fn test_many_arguments() {
        let args: Vec<String> = (0..100).map(|i| format!("arg{i}")).collect();
        let cmd = format!("echo {}", args.join(" "));
        let cmds = extract_commands(&cmd);
        assert_eq!(cmds.len(), 1);
    }

    #[test]
    fn test_nested_subshell() {
        let cmds = extract_commands("echo $(echo $(git status))");
        assert!(!cmds.is_empty());
    }

    #[test]
    fn test_process_substitution() {
        // Process substitution <(...) should extract inner commands
        let cmds = extract_commands("diff <(cat file1) <(cat file2)");
        // Should find: diff, cat (twice)
        let programs: Vec<_> = cmds.iter().map(|c| c.program.as_str()).collect();
        assert!(
            programs.contains(&"diff") && programs.contains(&"cat"),
            "Expected diff and cat, got: {:?}",
            programs
        );
    }

    #[test]
    fn test_process_substitution_dangerous() {
        // Process substitution with dangerous command should be extracted
        let cmds = extract_commands("echo <(rm -rf /)");
        // Should find both echo and rm
        let programs: Vec<_> = cmds.iter().map(|c| c.program.as_str()).collect();
        assert!(
            programs.contains(&"rm"),
            "Expected rm to be extracted from process substitution, got: {:?}",
            programs
        );
    }

    #[test]
    fn test_escaped_quotes() {
        let cmds = extract_commands(r#"echo "hello\"world""#);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "echo");
    }

    #[test]
    fn test_mixed_quotes() {
        let cmds = extract_commands(r#"echo "it's" 'a "test"'"#);
        assert_eq!(cmds.len(), 1);
    }

    #[test]
    fn test_empty_args() {
        let cmds = extract_commands("echo '' \"\"");
        assert_eq!(cmds.len(), 1);
    }

    #[test]
    fn test_just_operators() {
        // Edge case: just operators, no commands
        let cmds = extract_commands("&& || ;");
        // Should handle gracefully, might be empty
        assert!(
            cmds.is_empty()
                || cmds
                    .iter()
                    .all(|c| c.program.is_empty() || c.program == "&&" || c.program == "||")
        );
    }

    #[test]
    fn test_newlines_in_command() {
        let cmds = extract_commands("echo hello\ngit status");
        assert!(!cmds.is_empty(), "Should handle newlines");
    }

    #[test]
    fn test_tabs_in_command() {
        let cmds = extract_commands("echo\thello\tworld");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "echo");
    }

    #[test]
    fn test_comments_ignored() {
        let cmds = extract_commands("echo hello # this is a comment");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "echo");
    }

    #[test]
    fn test_numeric_arguments_preserved_head() {
        let cmds = extract_commands("head -n 10 file.txt");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "head");
        assert_eq!(cmds[0].args, vec!["-n", "10", "file.txt"]);
    }

    #[test]
    fn test_numeric_arguments_preserved_tail() {
        let cmds = extract_commands("tail -n 20 file.txt");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "tail");
        assert_eq!(cmds[0].args, vec!["-n", "20", "file.txt"]);
    }

    #[test]
    fn test_background_operator() {
        let cmds = extract_commands("sleep 10 &");
        assert!(!cmds.is_empty());
    }

    #[test]
    fn test_heredoc() {
        let cmds = extract_commands("cat <<EOF\nhello\nEOF");
        assert!(!cmds.is_empty());
    }

    // === Transparent Wrapper Stripping Tests ===

    #[test]
    fn test_time_strips_to_inner_command() {
        let cmds = extract_commands("time rm -rf /");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "rm");
        assert_eq!(cmds[0].args, vec!["-rf", "/"]);
        assert_eq!(cmds[0].raw, "time rm -rf /");
    }

    #[test]
    fn test_env_strips_to_inner_command() {
        let cmds = extract_commands("env rm -rf /");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "rm");
        assert_eq!(cmds[0].args, vec!["-rf", "/"]);
    }

    #[test]
    fn test_env_with_var_assignment_strips() {
        let cmds = extract_commands("env VAR=val rm -rf /");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "rm");
        assert_eq!(cmds[0].args, vec!["-rf", "/"]);
    }

    #[test]
    fn test_env_with_flags_and_vars_strips() {
        let cmds = extract_commands("env -i PATH=/usr/bin HOME=/tmp rm -rf /");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "rm");
        assert_eq!(cmds[0].args, vec!["-rf", "/"]);
    }

    #[test]
    fn test_env_alone_keeps_program() {
        let cmds = extract_commands("env");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "env");
    }

    #[test]
    fn test_env_only_vars_keeps_program() {
        let cmds = extract_commands("env VAR=val");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "env");
    }

    #[test]
    fn test_nice_with_flags_strips() {
        let cmds = extract_commands("nice -n 10 rm -rf /");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "rm");
        assert_eq!(cmds[0].args, vec!["-rf", "/"]);
    }

    #[test]
    fn test_timeout_strips_duration_and_command() {
        let cmds = extract_commands("timeout 5 rm -rf /");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "rm");
        assert_eq!(cmds[0].args, vec!["-rf", "/"]);
    }

    #[test]
    fn test_timeout_with_flags_strips() {
        let cmds = extract_commands("timeout --signal=KILL 30 rm -rf /");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "rm");
        assert_eq!(cmds[0].args, vec!["-rf", "/"]);
    }

    #[test]
    fn test_nohup_strips() {
        let cmds = extract_commands("nohup rm -rf /");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "rm");
        assert_eq!(cmds[0].args, vec!["-rf", "/"]);
    }

    #[test]
    fn test_nohup_alone_keeps_program() {
        let cmds = extract_commands("nohup");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "nohup");
    }

    #[test]
    fn test_exec_strips() {
        let cmds = extract_commands("exec rm -rf /");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "rm");
        assert_eq!(cmds[0].args, vec!["-rf", "/"]);
    }

    #[test]
    fn test_sudo_strips_to_inner_command() {
        let cmds = extract_commands("sudo rm -rf /");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "rm");
        assert_eq!(cmds[0].args, vec!["-rf", "/"]);
    }

    #[test]
    fn test_sudo_with_flags_strips() {
        let cmds = extract_commands("sudo -u root rm -rf /");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "rm");
        assert_eq!(cmds[0].args, vec!["-rf", "/"]);
    }

    #[test]
    fn test_sudo_only_flags_keeps_program() {
        // sudo -l lists permissions, no inner command
        let cmds = extract_commands("sudo -l");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "sudo");
        assert_eq!(cmds[0].args, vec!["-l"]);
    }

    #[test]
    fn test_command_builtin_strips() {
        let cmds = extract_commands("command rm -rf /");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "rm");
        assert_eq!(cmds[0].args, vec!["-rf", "/"]);
    }

    #[test]
    fn test_recursive_stripping() {
        // time env rm -rf / -> env rm -rf / -> rm -rf /
        let cmds = extract_commands("time env rm -rf /");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "rm");
        assert_eq!(cmds[0].args, vec!["-rf", "/"]);
    }

    #[test]
    fn test_recursive_stripping_triple() {
        let cmds = extract_commands("time nice -n 5 env VAR=x git status");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "git");
        assert_eq!(cmds[0].args, vec!["status"]);
    }

    #[test]
    fn test_time_safe_command_passes_through() {
        let cmds = extract_commands("time git status");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "git");
        assert_eq!(cmds[0].args, vec!["status"]);
    }

    #[test]
    fn test_strace_strips() {
        let cmds = extract_commands("strace -f rm -rf /");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "rm");
        assert_eq!(cmds[0].args, vec!["-rf", "/"]);
    }

    #[test]
    fn test_doas_strips() {
        let cmds = extract_commands("doas rm -rf /");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "rm");
        assert_eq!(cmds[0].args, vec!["-rf", "/"]);
    }

    #[test]
    fn test_ionice_strips() {
        let cmds = extract_commands("ionice -c 3 rm -rf /");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "rm");
        assert_eq!(cmds[0].args, vec!["-rf", "/"]);
    }

    #[test]
    fn test_taskset_strips() {
        let cmds = extract_commands("taskset -c 0 rm -rf /");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "rm");
        assert_eq!(cmds[0].args, vec!["-rf", "/"]);
    }

    // === Property-based Fuzz Tests ===
    // These ensure the parser handles various inputs correctly.
    // Note: Some arbitrary inputs can crash tree-sitter-bash (C library),
    // so we focus on shell-realistic inputs.

    mod fuzz {
        use super::*;
        use proptest::prelude::*;

        // Shell keywords that tree-sitter parses as statements, not commands
        const SHELL_KEYWORDS: &[&str] = &[
            "if", "then", "else", "elif", "fi", "case", "esac", "for", "while", "until", "do",
            "done", "in", "function", "select", "time", "coproc",
        ];

        // Transparent wrappers are stripped at parse time, changing the program name.
        // Exclude them so `valid_commands_parse_correctly` doesn't fail on the
        // `program == cmds[0].program` assertion.
        const TRANSPARENT_WRAPPERS: &[&str] = &[
            "time", "exec", "env", "nice", "nohup", "strace", "ltrace", "ionice", "taskset",
            "timeout", "sudo", "doas", "command", "builtin",
        ];

        #[allow(clippy::ptr_arg)]
        fn is_not_shell_keyword(s: &String) -> bool {
            !SHELL_KEYWORDS.contains(&s.as_str()) && !TRANSPARENT_WRAPPERS.contains(&s.as_str())
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(500))]

            #[test]
            fn tokenize_never_panics(s in "[[:print:]]{0,200}") {
                // Tokenizer is pure Rust, should never panic
                let _ = tokenize(&s);
            }

            #[test]
            fn valid_commands_parse_correctly(
                program in "[a-z]{1,10}".prop_filter("not a shell keyword", is_not_shell_keyword),
                args in prop::collection::vec("[a-zA-Z0-9_\\-]{1,20}", 0..10)
            ) {
                let cmd = if args.is_empty() {
                    program.clone()
                } else {
                    format!("{} {}", program, args.join(" "))
                };
                let cmds = extract_commands(&cmd);
                prop_assert!(!cmds.is_empty());
                prop_assert_eq!(&cmds[0].program, &program);
            }

            #[test]
            fn handles_repeated_operators(
                op in prop::sample::select(vec!["&&", "||", ";", "|"]),
                count in 1usize..20
            ) {
                let cmd = format!("echo a {} echo b",
                    std::iter::repeat_n(op, count).collect::<Vec<_>>().join(" echo x "));
                let _ = extract_commands(&cmd);
            }

            #[test]
            fn handles_nested_quotes(depth in 1usize..5) {
                let mut cmd = "echo hello".to_string();
                for _ in 0..depth {
                    cmd = format!("echo \"{cmd}\"");
                }
                let _ = extract_commands(&cmd);
            }

            #[test]
            fn handles_nested_subshells(depth in 1usize..5) {
                let mut cmd = "echo x".to_string();
                for _ in 0..depth {
                    cmd = format!("echo $({cmd})");
                }
                let _ = extract_commands(&cmd);
            }

            #[test]
            fn handles_chained_commands(
                count in 1usize..10,
                sep in prop::sample::select(vec![" && ", " || ", " ; ", " | "])
            ) {
                let cmd = (0..count)
                    .map(|i| format!("cmd{i} arg{i}"))
                    .collect::<Vec<_>>()
                    .join(sep);
                let cmds = extract_commands(&cmd);
                // Should parse without crashing
                prop_assert!(!cmds.is_empty());
            }

            #[test]
            fn handles_various_quoting(
                content in "[a-zA-Z0-9 ]{0,20}",
                quote in prop::sample::select(vec!["'", "\""])
            ) {
                let cmd = format!("echo {quote}{content}{quote}");
                let cmds = extract_commands(&cmd);
                prop_assert_eq!(cmds.len(), 1);
                prop_assert_eq!(&cmds[0].program, "echo");
            }
        }
    }

    // fallback_parse compound-operator splitting

    #[test]
    fn test_fallback_splits_and_and() {
        let cmds = fallback_parse("echo hello && rm -rf /");
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].program, "echo");
        assert_eq!(cmds[0].args, vec!["hello"]);
        assert_eq!(cmds[1].program, "rm");
        assert_eq!(cmds[1].args, vec!["-rf", "/"]);
    }

    #[test]
    fn test_fallback_splits_or_or() {
        let cmds = fallback_parse("echo hello || rm -rf /");
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].program, "echo");
        assert_eq!(cmds[0].args, vec!["hello"]);
        assert_eq!(cmds[1].program, "rm");
        assert_eq!(cmds[1].args, vec!["-rf", "/"]);
    }

    #[test]
    fn test_fallback_splits_semicolons() {
        let cmds = fallback_parse("a ; b ; c");
        assert_eq!(cmds.len(), 3);
        assert_eq!(cmds[0].program, "a");
        assert_eq!(cmds[1].program, "b");
        assert_eq!(cmds[2].program, "c");
    }

    #[test]
    fn test_fallback_splits_pipe() {
        let cmds = fallback_parse("a | b");
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].program, "a");
        assert_eq!(cmds[1].program, "b");
    }

    #[test]
    fn test_fallback_no_split_inside_quotes() {
        let cmds = fallback_parse("echo 'a && b'");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "echo");
        assert_eq!(cmds[0].args, vec!["a && b"]);
    }
}

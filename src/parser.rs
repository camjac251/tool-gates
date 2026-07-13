//! Bash command parser using tree-sitter-bash for AST parsing.

use crate::models::CommandInfo;
use std::sync::{LazyLock, Mutex};
use tree_sitter::{Node, Parser, Tree, TreeCursor};
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

    // Attach the command's top-level scratch-variable assignments to every
    // sub-command, so a write target reached through a variable resolves the
    // same as an inline one. Shared (not per-sub-command) because the
    // assignments live at the whole-command level.
    let scratch_vars = scratch_var_map_from_tree(&tree, command_string);
    if !scratch_vars.is_empty() {
        for cmd in &mut commands {
            cmd.scratch_vars = scratch_vars.clone();
        }
    }

    commands
}

fn extract_from_tree(tree: &Tree, source: &str, commands: &mut Vec<CommandInfo>) {
    let mut cursor = tree.walk();
    visit_node(&mut cursor, source, commands);
}

/// Extract top-level shell variable assignments that are safe to resolve when
/// deciding whether a write target is under the scratch base.
///
/// Only a SINGLE, UNCONDITIONAL, TOP-LEVEL, non-append `NAME=value` assignment
/// per name is tracked: the `variable_assignment` must be a direct child of the
/// root `program` node. That structural rule alone excludes the shapes a naive
/// tracker would mis-resolve: command-prefix (`S=v cmd`, nested in a `command`),
/// `export`/`declare`/`local` (nested in `declaration_command`), conditional
/// `&&`/`||` (nested in a `list`), `if`/`case`, subshell, brace group, and loop
/// assignments. Append (`+=`) and values containing a command/process
/// substitution or arithmetic are rejected, and a name assigned more than once
/// at top level is dropped (its live value is ambiguous).
///
/// The recorded value keeps its parameter expansions verbatim; the caller
/// substitutes `$NAME`/`${NAME}` then runs the existing canonicalize-then-prefix
/// check, so a tracked value can only promote a write to allow when the final
/// path is genuinely under the scratch base.
pub fn extract_scratch_var_map(command_string: &str) -> std::collections::HashMap<String, String> {
    if command_string.trim().is_empty() {
        return std::collections::HashMap::new();
    }
    let tree = {
        let mut parser = PARSER.lock().unwrap_or_else(|e| e.into_inner());
        match parser.parse(command_string, None) {
            Some(t) => t,
            None => return std::collections::HashMap::new(),
        }
    };
    scratch_var_map_from_tree(&tree, command_string)
}

fn scratch_var_map_from_tree(
    tree: &Tree,
    source: &str,
) -> std::collections::HashMap<String, String> {
    use std::collections::HashMap;

    let src = source.as_bytes();
    let root = tree.root_node();

    // Gather every direct-program-child assignment with its name and (if a
    // static, non-append value) its text. Count names so a reassignment drops
    // the name entirely rather than resolving to a stale first value.
    let mut counts: HashMap<String, u32> = HashMap::new();
    let mut candidates: Vec<(String, Option<String>)> = Vec::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() != "variable_assignment" {
            continue;
        }
        let Some(name) = child
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(src).ok())
        else {
            continue;
        };
        let name = name.to_string();
        *counts.entry(name.clone()).or_insert(0) += 1;

        let is_append = {
            let mut ac = child.walk();
            child.children(&mut ac).any(|c| c.kind() == "+=")
        };
        let value = if is_append {
            None
        } else {
            match child.child_by_field_name("value") {
                Some(val) if value_is_static(&val) => val.utf8_text(src).ok().map(unquote),
                _ => None,
            }
        };
        candidates.push((name, value));
    }

    let mut map = HashMap::new();
    for (name, value) in candidates {
        if counts.get(&name).copied() != Some(1) {
            continue; // reassigned at top level: live value is ambiguous
        }
        if let Some(v) = value {
            map.insert(name, v);
        }
    }
    map
}

/// True when a value node is a static path expression: literal text plus
/// parameter expansions only, with no command/process substitution or
/// arithmetic. Such a value is safe to record because its expansions stay
/// literal in the recorded text, so the only way a substituted use can match
/// the scratch base is the base tokens the gate already resolves.
fn value_is_static(value: &Node) -> bool {
    let mut stack = vec![*value];
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "command_substitution" | "process_substitution" | "arithmetic_expansion"
        ) {
            return false;
        }
        let mut c = node.walk();
        for ch in node.children(&mut c) {
            stack.push(ch);
        }
    }
    true
}

/// Neutralize heredoc body text so security checks (raw-string regexes,
/// settings deny matching) don't scan data that is fed to a command's stdin
/// rather than executed as shell.
///
/// Returns the command string with quoted-heredoc body content blanked to
/// spaces (newlines preserved, so byte offsets and line boundaries stay
/// identical). Returns `None` when there is nothing to neutralize, so callers
/// keep using the original string without an allocation.
///
/// Quoting follows bash: the delimiter quote decides expansion.
/// - Quoted delimiter (`<<'EOF'`, `<<"EOF"`, `<<-'EOF'`): the body is pure
///   literal data with no expansion, so the whole body is blanked.
/// - Unquoted delimiter (`<<EOF`, `<<-EOF`): the shell expands `$(...)` /
///   backtick substitutions inside the body, so the body is left untouched
///   and still scanned. Those substitutions are a real execution path the
///   checks must keep catching.
pub fn neutralize_heredoc_bodies(command_string: &str) -> Option<String> {
    let tree = {
        let mut parser = PARSER.lock().unwrap_or_else(|e| e.into_inner());
        parser.parse(command_string, None)?
    };

    let mut blank_ranges: Vec<(usize, usize)> = Vec::new();
    let mut cursor = tree.walk();
    collect_quoted_heredoc_body_ranges(&mut cursor, command_string, &mut blank_ranges);

    if blank_ranges.is_empty() {
        return None;
    }

    // Blank in place: swap every non-newline byte in the range for an ASCII
    // space. Length, byte offsets, and line boundaries are preserved, and the
    // result stays valid UTF-8 (any multi-byte char lies fully inside a body
    // range and each of its bytes becomes a space).
    let mut bytes = command_string.as_bytes().to_vec();
    for (start, end) in blank_ranges {
        for b in &mut bytes[start..end] {
            if *b != b'\n' {
                *b = b' ';
            }
        }
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Collect byte ranges of `heredoc_body` nodes whose delimiter is quoted.
fn collect_quoted_heredoc_body_ranges(
    cursor: &mut TreeCursor,
    source: &str,
    ranges: &mut Vec<(usize, usize)>,
) {
    let node = cursor.node();

    if node.kind() == "heredoc_redirect" {
        let mut quoted = false;
        let mut body: Option<tree_sitter::Node> = None;
        let mut child_cursor = node.walk();
        for child in node.children(&mut child_cursor) {
            match child.kind() {
                "heredoc_start" => {
                    if let Ok(text) = child.utf8_text(source.as_bytes()) {
                        let t = text.trim_start();
                        quoted = t.starts_with('\'') || t.starts_with('"');
                    }
                }
                "heredoc_body" => body = Some(child),
                _ => {}
            }
        }
        if quoted {
            if let Some(body) = body {
                ranges.push((body.start_byte(), body.end_byte()));
            }
        }
    }

    if cursor.goto_first_child() {
        loop {
            collect_quoted_heredoc_body_ranges(cursor, source, ranges);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

fn visit_node(cursor: &mut TreeCursor, source: &str, commands: &mut Vec<CommandInfo>) {
    let node = cursor.node();
    let kind = node.kind();

    match kind {
        "command" => {
            if let Some(cmd) = extract_command(cursor, source) {
                commands.push(cmd);
            }
            visit_nested_substitutions(cursor, source, commands);
        }
        "pipeline" => {
            // Visit each command in the pipeline
            if cursor.goto_first_child() {
                loop {
                    let child = cursor.node();
                    if child.kind() == "command" {
                        visit_node(cursor, source, commands);
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

/// Find executable substitutions anywhere inside a command argument tree.
///
/// Tree-sitter nests substitutions below `string`, `concatenation`, and
/// arithmetic nodes. Stop descending once a substitution is found because
/// `visit_node` owns traversal of that executable subtree, including any
/// further nested substitutions.
fn visit_nested_substitutions(
    cursor: &mut TreeCursor,
    source: &str,
    commands: &mut Vec<CommandInfo>,
) {
    if cursor.goto_first_child() {
        loop {
            if matches!(
                cursor.node().kind(),
                "command_substitution" | "process_substitution"
            ) {
                visit_node(cursor, source, commands);
            } else {
                visit_nested_substitutions(cursor, source, commands);
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
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

    Some(CommandInfo {
        raw,
        program,
        args,
        scratch_vars: std::collections::HashMap::new(),
    })
}

/// Known transparent wrapper commands that just execute their arguments.
/// Does NOT include `sudo`/`doas` (their approval floor is composed in the system gate),
/// `env` (handles `VAR=value`), or `timeout` (has a positional duration arg).
const SIMPLE_WRAPPERS: &[&str] = &[
    "time", "exec", "nice", "nohup", "strace", "ltrace", "ionice", "taskset", "command", "builtin",
];

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
/// - `env`: parse options, assignments, and conservative split strings to find the real command
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

    if program == "env" {
        if let Some((new_program, new_args)) = parse_env_inner_command(&args) {
            return strip_wrapper_recursive(new_program, new_args);
        }
        // No concrete command found. Keep `env` and its original arguments so
        // the gate can distinguish display-only use from an ambiguous split string.
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

const ENV_OPTIONS_WITH_VALUES: &[&str] = &["-u", "--unset", "-C", "--chdir", "-a", "--argv0"];
const MAX_ENV_SPLIT_EXPANSIONS: usize = 16;

/// Resolve the command executed by `env` without invoking the host utility.
///
/// GNU `env -S` inserts the tokenized split string back into its argument list,
/// where those tokens may themselves be options, assignments, or the command.
/// Only static split strings with ordinary quoting are accepted. Expansion and
/// escape syntax is left unresolved so the caller retains `env` for manual
/// review instead of classifying a potentially different executable as safe.
fn parse_env_inner_command(args: &[String]) -> Option<(String, Vec<String>)> {
    let mut expanded = args.to_vec();
    let mut split_expansions = 0;
    let mut options_done = false;
    let mut i = 0;

    while i < expanded.len() {
        let arg = expanded[i].clone();

        if !options_done && arg == "--" {
            options_done = true;
            i += 1;
            continue;
        }

        if !options_done {
            let split_value = if arg == "-S" || arg == "--split-string" {
                let value = expanded.get(i + 1)?.clone();
                Some((value, 2))
            } else if let Some(value) = arg.strip_prefix("--split-string=") {
                Some((value.to_string(), 1))
            } else {
                arg.strip_prefix("-S")
                    .filter(|value| !value.is_empty())
                    .map(|value| (value.to_string(), 1))
            };

            if let Some((value, consumed)) = split_value {
                split_expansions += 1;
                if split_expansions > MAX_ENV_SPLIT_EXPANSIONS {
                    return None;
                }
                let tokens = tokenize_env_split_string(&value)?;
                expanded.splice(i..i + consumed, tokens);
                continue;
            }

            if ENV_OPTIONS_WITH_VALUES.contains(&arg.as_str()) {
                if i + 1 >= expanded.len() {
                    return None;
                }
                i += 2;
                continue;
            }

            if arg.starts_with('-') {
                i += 1;
                continue;
            }
        }

        if arg.contains('=') {
            i += 1;
            continue;
        }

        return Some((arg, expanded[i + 1..].to_vec()));
    }

    None
}

fn tokenize_env_split_string(value: &str) -> Option<Vec<String>> {
    if value
        .chars()
        .any(|ch| matches!(ch, '\\' | '$' | '\n' | '\r' | '\0'))
    {
        return None;
    }

    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut token_started = false;

    for ch in value.chars() {
        match ch {
            '\'' if !in_double_quote => {
                in_single_quote = !in_single_quote;
                token_started = true;
            }
            '"' if !in_single_quote => {
                in_double_quote = !in_double_quote;
                token_started = true;
            }
            ' ' | '\t' if !in_single_quote && !in_double_quote => {
                if token_started {
                    tokens.push(std::mem::take(&mut current));
                    token_started = false;
                }
            }
            _ => {
                current.push(ch);
                token_started = true;
            }
        }
    }

    if in_single_quote || in_double_quote {
        return None;
    }
    if token_started {
        tokens.push(current);
    }
    Some(tokens)
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
            scratch_vars: Default::default(),
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
    fn test_quoted_substitution_extracts_inner_command() {
        let cmds = extract_commands(r#"echo "$(mytool --check)""#);
        let programs = cmds
            .iter()
            .map(|cmd| cmd.program.as_str())
            .collect::<Vec<_>>();
        assert_eq!(programs, vec!["echo", "mytool"]);
        assert_eq!(cmds[1].args, vec!["--check"]);
    }

    #[test]
    fn test_quoted_substitution_extracts_deeply_nested_command_once() {
        let cmds = extract_commands(r#"echo "$(printf '%s' "$(mytool --check)")""#);
        let programs = cmds
            .iter()
            .map(|cmd| cmd.program.as_str())
            .collect::<Vec<_>>();
        assert_eq!(programs, vec!["echo", "printf", "mytool"]);
    }

    #[test]
    fn test_quoted_substitution_handles_backticks_concatenation_and_arithmetic() {
        for command in [
            r#"echo "`mytool --check`""#,
            r#"echo prefix"$(mytool --check)"suffix"#,
            r#"echo "$((1 + $(mytool --check)))""#,
        ] {
            let programs = extract_commands(command)
                .into_iter()
                .map(|cmd| cmd.program)
                .collect::<Vec<_>>();
            assert_eq!(
                programs,
                vec!["echo", "mytool"],
                "nested executable was missed in {command}"
            );
        }
    }

    #[test]
    fn test_quoted_substitution_literals_are_not_executed() {
        for command in [
            r#"echo '$(mytool --check)'"#,
            r#"echo "\$(mytool --check)""#,
        ] {
            let programs = extract_commands(command)
                .into_iter()
                .map(|cmd| cmd.program)
                .collect::<Vec<_>>();
            assert_eq!(programs, vec!["echo"], "literal was executed in {command}");
        }
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

    #[test]
    fn test_extract_scratch_var_map() {
        let get = extract_scratch_var_map;

        // A single, top-level, static assignment is tracked, value kept verbatim.
        assert_eq!(
            get("S=$TOOL_GATES_SCRATCH/x; mkdir \"$S\"")
                .get("S")
                .map(String::as_str),
            Some("$TOOL_GATES_SCRATCH/x")
        );
        // A quoted value is unquoted.
        assert_eq!(
            get("S=\"$TOOL_GATES_SCRATCH/y\"")
                .get("S")
                .map(String::as_str),
            Some("$TOOL_GATES_SCRATCH/y")
        );

        // Opaque shapes are never tracked.
        assert!(!get("S=a; S=b").contains_key("S"), "reassignment");
        assert!(!get("S=a cmd").contains_key("S"), "command-prefix");
        assert!(!get("export S=a").contains_key("S"), "declaration-wrapped");
        assert!(!get("S+=a").contains_key("S"), "append");
        assert!(!get("S=$(pwd)").contains_key("S"), "command-sub value");
        assert!(!get("cd / && S=a").contains_key("S"), "conditional &&");
    }

    // === Heredoc Body Neutralization Tests ===

    #[test]
    fn test_neutralize_single_quoted_delimiter_blanks_body() {
        let src = "cat <<'EOF'\n| head danger\nEOF";
        let out = neutralize_heredoc_bodies(src).expect("single-quoted body blanked");
        assert_eq!(out.len(), src.len());
        assert!(!out.contains("head"));
        // Newlines and the surrounding command structure are preserved.
        assert_eq!(out.matches('\n').count(), src.matches('\n').count());
        assert!(out.starts_with("cat <<'EOF'"));
        assert!(out.trim_end().ends_with("EOF"));
    }

    #[test]
    fn test_neutralize_double_quoted_delimiter_blanks_body() {
        let src = "cat <<\"EOF\"\neval risky text\nEOF";
        let out = neutralize_heredoc_bodies(src).expect("double-quoted body blanked");
        assert_eq!(out.len(), src.len());
        assert!(!out.contains("eval"));
    }

    #[test]
    fn test_neutralize_dash_quoted_delimiter_blanks_body() {
        // `<<-` strips leading tabs; the delimiter quote still decides expansion.
        let src = "cat <<-'EOF'\n\teval risky text\n\tEOF";
        let out = neutralize_heredoc_bodies(src).expect("dash-quoted body blanked");
        assert_eq!(out.len(), src.len());
        assert!(!out.contains("eval"));
    }

    #[test]
    fn test_neutralize_unquoted_delimiter_left_intact() {
        // Unquoted bodies expand, so they must be returned untouched (None).
        for src in [
            "cat <<EOF\n$(rm -rf x)\nEOF",
            "cat <<-EOF\n\tplain text\n\tEOF",
        ] {
            assert!(
                neutralize_heredoc_bodies(src).is_none(),
                "unquoted heredoc must be left intact: {src:?}"
            );
        }
    }

    #[test]
    fn test_neutralize_no_heredoc_returns_none() {
        for src in ["git status", "echo hi | head -5", "rg '<<EOF' file.txt"] {
            assert!(
                neutralize_heredoc_bodies(src).is_none(),
                "no heredoc must return None: {src:?}"
            );
        }
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
    fn test_env_split_string_extracts_inner_command() {
        for command in [
            "env -S 'mytool --check'",
            "env --split-string='mytool --check'",
            "env -Smytool --check",
            "env -u PATH -C /tmp -S 'mytool --check'",
        ] {
            let cmds = extract_commands(command);
            assert_eq!(cmds.len(), 1, "unexpected extraction for {command}");
            assert_eq!(cmds[0].program, "mytool", "wrong program for {command}");
            assert_eq!(cmds[0].args, vec!["--check"], "wrong args for {command}");
        }
    }

    #[test]
    fn test_env_split_string_preserves_trailing_arguments() {
        let cmds = extract_commands("env -S 'mytool --check' extra");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "mytool");
        assert_eq!(cmds[0].args, vec!["--check", "extra"]);
    }

    #[test]
    fn test_env_split_string_ambiguous_input_keeps_env_for_review() {
        let (program, args) = strip_transparent_wrappers(
            "env".to_string(),
            vec!["--split-string=$COMMAND --check".to_string()],
        );
        assert_eq!(program, "env");
        assert_eq!(args, vec!["--split-string=$COMMAND --check"]);
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
    fn test_sudo_preserves_wrapper_for_gate_composition() {
        let cmds = extract_commands("sudo rm -rf /");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "sudo");
        assert_eq!(cmds[0].args, vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn test_sudo_with_flags_preserves_wrapper_for_gate_composition() {
        let cmds = extract_commands("sudo -u root rm -rf /");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "sudo");
        assert_eq!(cmds[0].args, vec!["-u", "root", "rm", "-rf", "/"]);
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
    fn test_doas_preserves_wrapper_for_gate_composition() {
        let cmds = extract_commands("doas rm -rf /");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "doas");
        assert_eq!(cmds[0].args, vec!["rm", "-rf", "/"]);
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
            "timeout", "command", "builtin",
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

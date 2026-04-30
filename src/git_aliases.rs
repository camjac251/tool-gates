//! Resolve user-defined git aliases for the git gate.
//!
//! Reads `~/.gitconfig` once per process via [`LazyLock`], parses `[alias]`
//! entries, and lets [`crate::gates::git`] rewrite alias-based invocations to
//! their underlying subcommand so existing rules apply without per-alias
//! settings entries.
//!
//! Repo-local aliases (`$REPO/.git/config`) are opt-in via
//! `[git_aliases].include_local_repo = true` in `~/.config/tool-gates/config.toml`.
//! A malicious alias in a third-party repo should not silently inherit alias
//! trust on first checkout.
//!
//! Shell-prefixed aliases (`!cmd`) are never resolved; the gate asks the user
//! instead. Resolving them would require running the alias body through the
//! gate engine again, with all the failure modes that implies.
//!
//! Built-ins win over aliases (matches git's own behavior). The git gate
//! checks the TOML's known-subcommand set before consulting the alias map,
//! so `alias.status = log` does not shadow real `status` runs.

use crate::gates::git::{GLOBAL_FLAGS, GLOBAL_OPTS_WITH_VALUE};
use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::sync::LazyLock;

/// Result of resolving an alias name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// Alias body resolved cleanly to a real git subcommand.
    /// `tokens[0]` is the canonical subcommand; the rest are alias body args.
    Tokens(Vec<String>),
    /// Shell-prefixed (`!cmd`), exotic flag-only body, or chain limit hit.
    /// Caller should ask the user.
    Shell,
}

/// Maximum alias-chain depth, matching the spirit of git's own infinite-loop
/// guard. Five levels is well above any realistic alias chain.
const MAX_DEPTH: usize = 5;

/// Globally cached alias map, populated on first access.
pub(crate) static GLOBAL_ALIASES: LazyLock<HashMap<String, String>> =
    LazyLock::new(load_global_aliases);

fn load_global_aliases() -> HashMap<String, String> {
    run_git_alias_query(&["config", "--global", "--get-regexp", r"^alias\."])
}

/// Read repo-local aliases from `$REPO/.git/config`. Empty map if not in a
/// git repo or git fails. Only called when the user opts in.
pub fn load_local_aliases(cwd: &str) -> HashMap<String, String> {
    let in_repo = Command::new("git")
        .args(["-C", cwd, "rev-parse", "--git-dir"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !in_repo {
        return HashMap::new();
    }
    let mut local = HashMap::new();
    let output = Command::new("git")
        .args(["-C", cwd, "config", "--local", "--get-regexp", r"^alias\."])
        .output();
    if let Ok(output) = output
        && output.status.success()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        local = parse_alias_output(&stdout);
    }
    local
}

fn run_git_alias_query(args: &[&str]) -> HashMap<String, String> {
    let Ok(output) = Command::new("git").args(args).output() else {
        return HashMap::new();
    };
    if !output.status.success() {
        return HashMap::new();
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_alias_output(&stdout)
}

/// Parse `git config --get-regexp '^alias\.'` output. Each line is
/// `alias.<name> <value>`.
pub(crate) fn parse_alias_output(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let Some(rest) = line.strip_prefix("alias.") else {
            continue;
        };
        let Some(space_idx) = rest.find(' ') else {
            continue;
        };
        let name = &rest[..space_idx];
        let value = rest[space_idx + 1..].trim();
        if name.is_empty() || value.is_empty() {
            continue;
        }
        map.insert(name.to_string(), value.to_string());
    }
    map
}

/// Resolve `subcommand` against the cached global alias map.
pub fn resolve(subcommand: &str) -> Option<Resolved> {
    resolve_with_map(subcommand, &GLOBAL_ALIASES)
}

/// Resolve against a caller-provided map. Used by the git gate when
/// repo-local aliases are opted in (the local map shadows the global).
pub fn resolve_with_map(subcommand: &str, map: &HashMap<String, String>) -> Option<Resolved> {
    let mut visited = HashSet::new();
    resolve_with_depth(subcommand, &mut visited, 0, map)
}

fn resolve_with_depth(
    subcommand: &str,
    visited: &mut HashSet<String>,
    depth: usize,
    map: &HashMap<String, String>,
) -> Option<Resolved> {
    if depth >= MAX_DEPTH {
        return Some(Resolved::Shell);
    }
    if !visited.insert(subcommand.to_string()) {
        return Some(Resolved::Shell);
    }
    let value = map.get(subcommand)?;

    if value.starts_with('!') {
        return Some(Resolved::Shell);
    }

    let tokens = shell_tokenize(value);
    if tokens.is_empty() {
        return None;
    }

    let stripped = strip_global_flags(&tokens);
    if stripped.is_empty() {
        return None;
    }

    let first = stripped[0].as_str();
    if first.starts_with('-') {
        return Some(Resolved::Shell);
    }

    if map.contains_key(first) {
        match resolve_with_depth(first, visited, depth + 1, map)? {
            Resolved::Tokens(mut inner) => {
                inner.extend_from_slice(&stripped[1..]);
                return Some(Resolved::Tokens(inner));
            }
            Resolved::Shell => return Some(Resolved::Shell),
        }
    }

    Some(Resolved::Tokens(stripped))
}

/// Tokenize an alias value with shell-style quoting. Single quotes are
/// literal; double quotes allow `\"` and `\\` escapes; bare `\` escapes the
/// next character. No variable or glob expansion is performed: the alias
/// body should resolve to a static git invocation.
fn shell_tokenize(s: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = s.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;

    while let Some(c) = chars.next() {
        if in_single {
            if c == '\'' {
                in_single = false;
            } else {
                current.push(c);
            }
        } else if in_double {
            if c == '"' {
                in_double = false;
            } else if c == '\\' {
                if let Some(&next) = chars.peek() {
                    if next == '"' || next == '\\' {
                        current.push(chars.next().unwrap());
                    } else {
                        current.push(c);
                    }
                }
            } else {
                current.push(c);
            }
        } else if c == '\'' {
            in_single = true;
        } else if c == '"' {
            in_double = true;
        } else if c == '\\' {
            if let Some(next) = chars.next() {
                current.push(next);
            }
        } else if c.is_whitespace() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Strip leading git global flags from an alias body. Mirrors the logic in
/// [`crate::gates::git::extract_subcommand`]; centralizing the flag set keeps
/// `astatus = -c color.ui=false status --short` resolving to `status`.
fn strip_global_flags(tokens: &[String]) -> Vec<String> {
    let mut i = 0;
    while i < tokens.len() {
        let arg = tokens[i].as_str();
        if GLOBAL_OPTS_WITH_VALUE.contains(arg) {
            i += 2;
            continue;
        }
        if GLOBAL_OPTS_WITH_VALUE
            .iter()
            .any(|opt| arg.starts_with(&format!("{opt}=")))
        {
            i += 1;
            continue;
        }
        if arg.starts_with("-C") && arg.len() > 2 {
            i += 1;
            continue;
        }
        if GLOBAL_FLAGS.contains(arg) {
            i += 1;
            continue;
        }
        return tokens[i..].to_vec();
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // === parse_alias_output ===

    #[test]
    fn test_parse_simple_aliases() {
        let text = "alias.st status\nalias.lg log --oneline\n";
        let m = parse_alias_output(text);
        assert_eq!(m.get("st"), Some(&"status".to_string()));
        assert_eq!(m.get("lg"), Some(&"log --oneline".to_string()));
    }

    #[test]
    fn test_parse_alias_with_c_prefix() {
        let text = "alias.astatus -c color.ui=false status --short\n";
        let m = parse_alias_output(text);
        assert_eq!(
            m.get("astatus"),
            Some(&"-c color.ui=false status --short".to_string())
        );
    }

    #[test]
    fn test_parse_shell_alias() {
        let text = "alias.deploy !./deploy.sh\n";
        let m = parse_alias_output(text);
        assert_eq!(m.get("deploy"), Some(&"!./deploy.sh".to_string()));
    }

    #[test]
    fn test_parse_skips_malformed_lines() {
        let text = "garbage line\nalias.\nalias.foo\nalias.bar status\n";
        let m = parse_alias_output(text);
        assert_eq!(m.len(), 1);
        assert_eq!(m.get("bar"), Some(&"status".to_string()));
    }

    #[test]
    fn test_parse_empty_input() {
        let m = parse_alias_output("");
        assert!(m.is_empty());
    }

    // === shell_tokenize ===

    #[test]
    fn test_tokenize_simple() {
        assert_eq!(shell_tokenize("log --oneline"), vec!["log", "--oneline"]);
    }

    #[test]
    fn test_tokenize_with_single_quotes() {
        assert_eq!(
            shell_tokenize("log --pretty='format:%h %s'"),
            vec!["log", "--pretty=format:%h %s"]
        );
    }

    #[test]
    fn test_tokenize_with_double_quotes_and_escapes() {
        assert_eq!(
            shell_tokenize(r#"log --pretty="hello \"world\"""#),
            vec!["log", r#"--pretty=hello "world""#]
        );
    }

    #[test]
    fn test_tokenize_with_backslash_escape() {
        assert_eq!(shell_tokenize(r"log\ entry"), vec!["log entry"]);
    }

    #[test]
    fn test_tokenize_empty() {
        assert!(shell_tokenize("").is_empty());
        assert!(shell_tokenize("   ").is_empty());
    }

    // === strip_global_flags ===

    #[test]
    fn test_strip_c_key_value() {
        let toks = vec![
            "-c".to_string(),
            "color.ui=false".to_string(),
            "status".to_string(),
            "--short".to_string(),
        ];
        assert_eq!(strip_global_flags(&toks), vec!["status", "--short"]);
    }

    #[test]
    fn test_strip_combined_c_form() {
        let toks = vec!["-C/path".to_string(), "log".to_string()];
        assert_eq!(strip_global_flags(&toks), vec!["log"]);
    }

    #[test]
    fn test_strip_eq_form() {
        let toks = vec!["--git-dir=/path/.git".to_string(), "log".to_string()];
        assert_eq!(strip_global_flags(&toks), vec!["log"]);
    }

    #[test]
    fn test_strip_paginate_flag() {
        let toks = vec!["--no-pager".to_string(), "log".to_string()];
        assert_eq!(strip_global_flags(&toks), vec!["log"]);
    }

    #[test]
    fn test_strip_only_flags_returns_empty() {
        let toks = vec!["-c".to_string(), "x=y".to_string()];
        assert!(strip_global_flags(&toks).is_empty());
    }

    // === resolve ===

    #[test]
    fn test_resolve_simple_alias() {
        let m = map(&[("st", "status")]);
        let r = resolve_with_map("st", &m);
        assert_eq!(r, Some(Resolved::Tokens(vec!["status".to_string()])));
    }

    #[test]
    fn test_resolve_alias_with_args() {
        let m = map(&[("lg", "log --oneline -10")]);
        let r = resolve_with_map("lg", &m);
        assert_eq!(
            r,
            Some(Resolved::Tokens(vec![
                "log".to_string(),
                "--oneline".to_string(),
                "-10".to_string()
            ]))
        );
    }

    #[test]
    fn test_resolve_alias_strips_c_prefix() {
        let m = map(&[("astatus", "-c color.ui=false status --short")]);
        let r = resolve_with_map("astatus", &m);
        assert_eq!(
            r,
            Some(Resolved::Tokens(vec![
                "status".to_string(),
                "--short".to_string()
            ]))
        );
    }

    #[test]
    fn test_resolve_shell_alias() {
        let m = map(&[("deploy", "!./deploy.sh")]);
        let r = resolve_with_map("deploy", &m);
        assert_eq!(r, Some(Resolved::Shell));
    }

    #[test]
    fn test_resolve_chained_alias() {
        let m = map(&[("a", "b"), ("b", "status")]);
        let r = resolve_with_map("a", &m);
        assert_eq!(r, Some(Resolved::Tokens(vec!["status".to_string()])));
    }

    #[test]
    fn test_resolve_chain_appends_args() {
        let m = map(&[("a", "b --foo"), ("b", "log")]);
        let r = resolve_with_map("a", &m);
        assert_eq!(
            r,
            Some(Resolved::Tokens(vec![
                "log".to_string(),
                "--foo".to_string()
            ]))
        );
    }

    #[test]
    fn test_resolve_cycle_returns_shell() {
        let m = map(&[("a", "b"), ("b", "a")]);
        let r = resolve_with_map("a", &m);
        assert_eq!(r, Some(Resolved::Shell));
    }

    #[test]
    fn test_resolve_unknown_returns_none() {
        let m = map(&[("st", "status")]);
        assert_eq!(resolve_with_map("nope", &m), None);
    }

    #[test]
    fn test_resolve_alias_to_only_flags_returns_none() {
        let m = map(&[("foo", "-c x=y")]);
        assert_eq!(resolve_with_map("foo", &m), None);
    }

    #[test]
    fn test_resolve_alias_first_token_starts_with_dash() {
        let m = map(&[("foo", "--exec something")]);
        assert_eq!(resolve_with_map("foo", &m), Some(Resolved::Shell));
    }

    #[test]
    fn test_resolve_alias_with_quoted_value() {
        let m = map(&[("msg", "commit -m 'hello world'")]);
        let r = resolve_with_map("msg", &m);
        assert_eq!(
            r,
            Some(Resolved::Tokens(vec![
                "commit".to_string(),
                "-m".to_string(),
                "hello world".to_string()
            ]))
        );
    }
}

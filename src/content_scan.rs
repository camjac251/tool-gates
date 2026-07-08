//! Shared content-scan engine for the write/edit content gates.
//!
//! Both [`crate::security_reminders`] and [`crate::design_lint`] scan file-edit
//! bodies against a static table of `{id, matcher, message}` rules. This module
//! owns the machinery they share: extracting the writable `(path, content)`
//! pairs from a tool payload, the [`Matcher`] vocabulary, one compiled-regex
//! cache, and the generic [`scan`] loop that walks a rule table in order.
//!
//! Each scanner keeps its own rule table, tags, and policy (which files to skip,
//! whether the gate is opt-in, how matches are deduped and emitted). The engine
//! is deliberately policy-free: it reports which rules a `(path, content)` pair
//! matches, in table order, and nothing more.

use regex::Regex;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Extract all writable (file_path, content) pairs from a tool_input map.
/// Shared by the security and design-lint content gates.
///
/// Handles all tool types:
/// - Claude `Write` / Gemini `write_file`: top-level `file_path` + `content`.
/// - Claude `Edit` / Gemini `replace`: top-level `file_path` + `new_string`,
///   plus the batch `edits[].new_string` form.
/// - Codex `apply_patch`: parse the unified-diff body in `command` and emit
///   one `(path, added_lines)` pair per Add/Update section. Delete sections
///   are skipped (no content to scan).
/// - Antigravity `write_to_file` / `replace_file_content` /
///   `multi_replace_file_content`: top-level `file_path` + `content`, populated
///   by main()'s Antigravity payload normalization.
pub(crate) fn extract_content(
    tool_name: &str,
    map: &serde_json::Map<String, serde_json::Value>,
) -> Vec<(String, String)> {
    let mut results = Vec::new();

    if tool_name == "apply_patch" {
        let command = map.get("command").and_then(|v| v.as_str()).unwrap_or("");
        if command.is_empty() {
            return results;
        }
        for file in crate::apply_patch_parser::parse_patch(command) {
            if file.op == crate::apply_patch_parser::PatchOp::Delete {
                continue;
            }
            let content = file.added_content();
            if content.is_empty() {
                continue;
            }
            // The destination path matters for "is this a doc/.env file" checks;
            // when there's a rename we use the move target since that's where
            // the bytes actually land.
            let path = file
                .move_to
                .as_ref()
                .unwrap_or(&file.path)
                .display()
                .to_string();
            results.push((path, content));
        }
        return results;
    }

    let top_file_path = map
        .get("file_path")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Match tool names from both Claude (Write/Edit) and Gemini (write_file/replace).
    // Field names (file_path, content, old_string, new_string) are the same in both CLIs.
    match tool_name {
        "Write" | "write_file" => {
            if let Some(content) = map.get("content").and_then(|v| v.as_str()) {
                if !content.is_empty() {
                    results.push((top_file_path, content.to_string()));
                }
            }
        }
        "Edit" | "replace" => {
            // Classic: single new_string
            if let Some(new_string) = map.get("new_string").and_then(|v| v.as_str()) {
                if !new_string.is_empty() {
                    results.push((top_file_path.clone(), new_string.to_string()));
                }
            }
            // Batch: edits[].new_string
            if let Some(edits) = map.get("edits").and_then(|v| v.as_array()) {
                for edit in edits {
                    if let Some(ns) = edit.get("new_string").and_then(|v| v.as_str()) {
                        if !ns.is_empty() {
                            results.push((top_file_path.clone(), ns.to_string()));
                        }
                    }
                }
            }
        }
        // Antigravity write/edit tools. main()'s payload normalization flattens
        // the PascalCase args (CodeContent / ReplacementContent / chunked
        // ReplacementChunks[].ReplacementContent) into the canonical `content`
        // key before this runs, so a single content read covers all three.
        "write_to_file" | "replace_file_content" | "multi_replace_file_content" => {
            if let Some(content) = map.get("content").and_then(|v| v.as_str()) {
                if !content.is_empty() {
                    results.push((top_file_path, content.to_string()));
                }
            }
        }
        _ => {}
    }

    results
}

/// How a rule decides whether a `(path, content)` pair is in violation.
///
/// The first four variants are pure content or path tests. [`Matcher::Custom`]
/// is the whole-content escape hatch for detectors that a `{pattern}` table
/// cannot express (a hue-based gradient check, a cross-line focus-outline
/// check).
pub enum Matcher {
    /// Fires when the content contains any of these substrings.
    Substring { patterns: &'static [&'static str] },
    /// Fires on any `patterns` substring unless an `unless` substring also
    /// appears (e.g. `yaml.load(` unless `SafeLoader`).
    SubstringUnless {
        patterns: &'static [&'static str],
        unless: &'static [&'static str],
    },
    /// Fires when the content matches this regex.
    Regex { pattern: &'static str },
    /// Fires when any single line matches `pattern`. A line that also matches
    /// `skip_if` is exempt (e.g. a CSS custom-property token definition).
    LineRegex {
        pattern: &'static str,
        skip_if: Option<&'static str>,
    },
    /// Fires when `path_fn` returns true for the file path. Content is ignored;
    /// a caller needing an additional content gate applies it in its policy
    /// layer.
    Path { path_fn: fn(&str) -> bool },
    /// Whole-content predicate for detectors the table cannot express.
    Custom(fn(&str) -> bool),
}

/// One scannable rule. `T` is the caller's tag carried straight through to the
/// [`Hit`] (its tier struct, its rule reference, or `()`).
pub struct ScanRule<T: 'static> {
    pub id: &'static str,
    pub tag: T,
    pub message: &'static str,
    pub matcher: Matcher,
}

/// A rule that matched, carrying the caller's `tag` back for policy routing.
pub struct Hit<T> {
    pub id: &'static str,
    pub tag: T,
    pub message: &'static str,
}

/// A compiled matcher regex, keyed by rule id in the per-table cache.
enum Compiled {
    Regex(Regex),
    Line { re: Regex, skip: Option<Regex> },
}

/// A compiled rule table: `(rule id, compiled matcher)` pairs, leaked to
/// `'static` so it can live in the shared cache and be returned past the lock.
type CompiledTable = &'static [(&'static str, Compiled)];

/// Compile (and memoize) the [`Matcher::Regex`] / [`Matcher::LineRegex`] regexes
/// for a rule table. Keyed by the table's data pointer: rule tables are
/// `'static` and stable, so each distinct table compiles exactly once. The
/// compiled slice is leaked to `'static` so it can be returned past the lock.
fn compiled_regexes<T>(rules: &'static [ScanRule<T>]) -> CompiledTable {
    static CACHE: OnceLock<Mutex<HashMap<usize, CompiledTable>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key = rules.as_ptr() as usize;
    let mut guard = cache.lock().expect("content_scan regex cache poisoned");
    if let Some(v) = guard.get(&key) {
        return v;
    }
    let compiled: Vec<(&'static str, Compiled)> = rules
        .iter()
        .filter_map(|rule| match &rule.matcher {
            Matcher::Regex { pattern } => Some((
                rule.id,
                Compiled::Regex(Regex::new(pattern).expect("invalid content-scan regex")),
            )),
            Matcher::LineRegex { pattern, skip_if } => Some((
                rule.id,
                Compiled::Line {
                    re: Regex::new(pattern).expect("invalid content-scan regex"),
                    skip: skip_if.map(|s| Regex::new(s).expect("invalid content-scan skip regex")),
                },
            )),
            _ => None,
        })
        .collect();
    let leaked: CompiledTable = Box::leak(compiled.into_boxed_slice());
    guard.insert(key, leaked);
    leaked
}

fn lookup<'a>(compiled: &'a [(&'static str, Compiled)], id: &str) -> Option<&'a Compiled> {
    compiled
        .iter()
        .find(|(name, _)| *name == id)
        .map(|(_, c)| c)
}

/// Scan a `(path, content)` pair against a rule table, returning one [`Hit`] per
/// matching rule in table order. Pure: applies no file-skip, opt-in, or dedup
/// policy. Callers layer their own policy on the returned hits.
pub fn scan<T: Copy>(rules: &'static [ScanRule<T>], path: &str, content: &str) -> Vec<Hit<T>> {
    let compiled = compiled_regexes(rules);
    let mut hits = Vec::new();
    for rule in rules {
        let matched = match &rule.matcher {
            Matcher::Substring { patterns } => patterns.iter().any(|p| content.contains(p)),
            Matcher::SubstringUnless { patterns, unless } => {
                patterns.iter().any(|p| content.contains(p))
                    && !unless.iter().any(|u| content.contains(u))
            }
            Matcher::Regex { .. } => {
                matches!(lookup(compiled, rule.id), Some(Compiled::Regex(re)) if re.is_match(content))
            }
            Matcher::LineRegex { .. } => match lookup(compiled, rule.id) {
                Some(Compiled::Line { re, skip }) => content.lines().any(|line| {
                    re.is_match(line) && !skip.as_ref().is_some_and(|s| s.is_match(line))
                }),
                _ => false,
            },
            Matcher::Path { path_fn } => path_fn(path),
            Matcher::Custom(f) => f(content),
        };
        if matched {
            hits.push(Hit {
                id: rule.id,
                tag: rule.tag,
                message: rule.message,
            });
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_map(json: &str) -> serde_json::Map<String, serde_json::Value> {
        match serde_json::from_str::<serde_json::Value>(json).unwrap() {
            serde_json::Value::Object(m) => m,
            _ => panic!("expected object"),
        }
    }

    #[test]
    fn test_extract_write_content() {
        let map = make_map(r#"{"file_path": "/tmp/f.ts", "content": "eval(input)"}"#);
        let results = extract_content("Write", &map);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "/tmp/f.ts");
        assert_eq!(results[0].1, "eval(input)");
    }

    #[test]
    fn test_extract_edit_classic() {
        let map = make_map(
            r#"{"file_path": "/tmp/f.ts", "old_string": "foo", "new_string": "eval(bar)"}"#,
        );
        let results = extract_content("Edit", &map);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, "eval(bar)");
    }

    #[test]
    fn test_extract_edit_batch() {
        let map = make_map(
            r#"{"file_path": "/tmp/f.ts", "edits": [
            {"old_string": "a", "new_string": "eval(x)"},
            {"old_string": "b", "new_string": "safe()"}
        ]}"#,
        );
        let results = extract_content("Edit", &map);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].1, "eval(x)");
        assert_eq!(results[1].1, "safe()");
    }

    #[test]
    fn test_extract_empty_content_skipped() {
        let map = make_map(r#"{"file_path": "/tmp/f.ts", "content": ""}"#);
        let results = extract_content("Write", &map);
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_read_returns_nothing() {
        let map = make_map(r#"{"file_path": "/tmp/f.ts"}"#);
        let results = extract_content("Read", &map);
        assert!(results.is_empty());
    }

    // --- Generic scan engine ---

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Tag(u8);

    fn is_yaml(path: &str) -> bool {
        path.ends_with(".yml") || path.ends_with(".yaml")
    }

    fn rules() -> &'static [ScanRule<Tag>] {
        static R: OnceLock<Vec<ScanRule<Tag>>> = OnceLock::new();
        R.get_or_init(|| {
            vec![
                ScanRule {
                    id: "substr",
                    tag: Tag(1),
                    message: "substr",
                    matcher: Matcher::Substring {
                        patterns: &["eval("],
                    },
                },
                ScanRule {
                    id: "unless",
                    tag: Tag(2),
                    message: "unless",
                    matcher: Matcher::SubstringUnless {
                        patterns: &["yaml.load("],
                        unless: &["SafeLoader"],
                    },
                },
                ScanRule {
                    id: "regex",
                    tag: Tag(3),
                    message: "regex",
                    matcher: Matcher::Regex {
                        pattern: r"AKIA[0-9A-Z]{16}",
                    },
                },
                ScanRule {
                    id: "line",
                    tag: Tag(4),
                    message: "line",
                    matcher: Matcher::LineRegex {
                        pattern: r"#6366f1",
                        skip_if: Some(r"--[\w-]+\s*:"),
                    },
                },
                ScanRule {
                    id: "path",
                    tag: Tag(5),
                    message: "path",
                    matcher: Matcher::Path { path_fn: is_yaml },
                },
            ]
        })
    }

    fn ids(hits: &[Hit<Tag>]) -> Vec<&'static str> {
        hits.iter().map(|h| h.id).collect()
    }

    #[test]
    fn scan_matches_in_table_order() {
        let hits = scan(rules(), "a.txt", "x = eval(y)\ndata = yaml.load(f)");
        assert_eq!(ids(&hits), vec!["substr", "unless"]);
    }

    #[test]
    fn substring_unless_exemption() {
        let hits = scan(rules(), "a.txt", "yaml.load(f, Loader=yaml.SafeLoader)");
        assert!(!ids(&hits).contains(&"unless"));
    }

    #[test]
    fn regex_matches_whole_content() {
        // Build the key at runtime so the literal never appears in source
        // (tool-gates blocks writing files that contain a real-looking key).
        let key = format!("key = AKI{}OSFODNN7EXAMPLE", "AI");
        let hits = scan(rules(), "a.txt", &key);
        assert!(ids(&hits).contains(&"regex"));
    }

    #[test]
    fn line_regex_skip_if_exempts_token_def() {
        let markup = scan(rules(), "a.css", "background:#6366f1;");
        assert!(ids(&markup).contains(&"line"), "markup line flagged");
        let token = scan(rules(), "a.css", "  --accent: #6366f1;");
        assert!(!ids(&token).contains(&"line"), "token def exempt");
    }

    #[test]
    fn path_matcher_ignores_content() {
        let yaml = scan(rules(), "ci.yml", "nothing interesting");
        assert!(ids(&yaml).contains(&"path"));
        let other = scan(rules(), "notes.txt", "nothing interesting");
        assert!(!ids(&other).contains(&"path"));
    }

    #[test]
    fn tag_is_carried_through() {
        let hits = scan(rules(), "ci.yml", "x = eval(y)");
        let substr = hits.iter().find(|h| h.id == "substr").unwrap();
        assert_eq!(substr.tag, Tag(1));
        let path = hits.iter().find(|h| h.id == "path").unwrap();
        assert_eq!(path.tag, Tag(5));
    }
}

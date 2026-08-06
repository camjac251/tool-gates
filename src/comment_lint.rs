//! Comment-volume linting for Write/Edit content (PostToolUse).
//!
//! Measures how much narrative commentary an edit adds relative to the code it
//! adds, and how long a single comment runs, then surfaces the result as
//! PostToolUse `additionalContext` so the assistant can trim before moving on.
//! Existing prompt guidance says *whether* to write a comment; nothing bounds
//! *how many* or *how long*, which is the gap this gate covers.
//!
//! Doc comments are exempt: `///`, `//!`, `/** */`, and Python docstrings are
//! API documentation, and penalizing them would push toward undocumented public
//! surfaces. The gate targets free-floating narration only. Tooling directives
//! (`# noqa`, `//nolint`, `eslint-disable`, `@ts-expect-error`) are exempt for
//! the same reason: they are machine instructions, not prose.
//!
//! Only own-line comments count. A comment trailing code on the same line is
//! left alone: it cannot form a block, it is a small share of what gets written,
//! and distinguishing it from a `#` inside a shell expansion or a `//` inside a
//! string literal costs more accuracy than it buys.
//!
//! Opt-in via `features.comment_lint` (default off), and deliberately tuned to
//! the tail rather than the median. Every PostToolUse `additionalContext`
//! injection costs tokens and disturbs the prompt cache, so a gate that fires
//! on a typical edit costs more than it saves. The defaults are set high enough
//! that an ordinarily commented edit stays quiet; lower them per project to
//! tighten the house style.

use crate::config::CommentLintConfig;
use crate::models::PostToolUseOutput;

/// Comment syntax family for a file extension.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Syntax {
    /// C-like: `//` line comments, `/* */` blocks, `///` and `//!` docs.
    Slash,
    /// `#` line comments. Also covers Python, which adds docstrings.
    Hash,
    /// Python: `#` line comments plus triple-quoted docstrings.
    Python,
    /// `--` line comments (SQL, Lua, Haskell).
    Dash,
    /// `/* */` blocks only (CSS and friends).
    Block,
    /// `<!-- -->` markup comments.
    Markup,
}

/// Map a path to its comment syntax. Files that are not code, or whose comment
/// syntax is not modeled here, return `None` and are skipped entirely.
fn syntax_for(path: &str) -> Option<Syntax> {
    let lower = path.to_ascii_lowercase();
    let base = lower.rsplit('/').next().unwrap_or(&lower);
    for name in ["makefile", "dockerfile", "justfile", "brewfile"] {
        if base == name || base.starts_with(&format!("{name}.")) {
            return Some(Syntax::Hash);
        }
    }
    let ext = base.rsplit_once('.').map(|(_, e)| e)?;
    Some(match ext {
        "py" | "pyi" | "pyx" => Syntax::Python,
        "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts" | "go" | "rs" | "java"
        | "c" | "h" | "cc" | "cpp" | "hpp" | "cs" | "swift" | "kt" | "kts" | "scala" | "dart"
        | "php" | "zig" | "groovy" | "gradle" | "proto" => Syntax::Slash,
        "sh" | "bash" | "zsh" | "fish" | "rb" | "pl" | "pm" | "jl" | "toml" | "yaml" | "yml"
        | "ini" | "cfg" | "conf" | "tf" | "tfvars" | "hcl" | "nix" | "mk" | "ps1" | "psm1"
        | "ex" | "exs" => Syntax::Hash,
        "lua" | "sql" | "hs" | "elm" => Syntax::Dash,
        "css" | "scss" | "sass" | "less" | "styl" => Syntax::Block,
        "html" | "htm" | "vue" | "svelte" | "astro" => Syntax::Markup,
        _ => return None,
    })
}

/// Comment bodies that are machine directives rather than prose. Matched as a
/// lowercase prefix of the comment text with its marker already stripped.
const DIRECTIVE_PREFIXES: &[&str] = &[
    "noqa",
    "nolint",
    "lint:",
    "type:",
    "pyright:",
    "pylint:",
    "ruff:",
    "flake8:",
    "mypy:",
    "fmt:",
    "isort:",
    "black:",
    "shellcheck",
    "eslint-disable",
    "eslint-enable",
    "eslint ",
    "prettier-ignore",
    "@ts-",
    "biome-ignore",
    "codespell",
    "cspell",
    "nosec",
    "gosec",
    "revive:",
    "staticcheck",
    "deadcode",
    "coverage:",
    "c8 ignore",
    "istanbul ignore",
    "v8 ignore",
    "swiftlint:",
    "clippy::",
    "allow(",
    "expect(",
    "spdx-",
    "-*-",
    "vim:",
    "region",
    "endregion",
    "sourcemappingurl",
    "@flow",
    "@jsx",
];

fn is_directive(body: &str) -> bool {
    let lower = body.trim_start().to_ascii_lowercase();
    DIRECTIVE_PREFIXES.iter().any(|p| lower.starts_with(p))
}

/// What one scanned line contributes.
#[derive(PartialEq, Eq, Clone, Copy)]
enum LineKind {
    /// A line of code (possibly with a trailing comment).
    Code,
    /// A line that is nothing but narrative comment.
    Comment,
    /// Blank, a doc comment, or a tooling directive: counted as neither.
    Ignored,
}

/// Measured comment volume for one written chunk.
struct Stats {
    code_lines: usize,
    comment_lines: usize,
    longest_block: usize,
}

/// True when `token` appears on any line after `from`. A diff fragment often
/// splits a multi-line comment, so an opener with no closer in the chunk is
/// treated as a single line rather than swallowing the rest of the edit.
fn closes_later(lines: &[&str], from: usize, token: &str) -> bool {
    lines.iter().skip(from + 1).any(|line| line.contains(token))
}

/// Scan a written chunk and measure its comment volume.
fn scan(content: &str, syntax: Syntax) -> Stats {
    let lines: Vec<&str> = content.lines().collect();
    let mut kinds: Vec<LineKind> = Vec::with_capacity(lines.len());
    // Multi-line state: `Some(true)` inside narrative, `Some(false)` inside doc.
    let mut in_block: Option<bool> = None;
    let mut in_docstring: Option<&str> = None;

    for (i, raw) in lines.iter().enumerate() {
        let s = raw.trim();

        if let Some(narrative) = in_block {
            if s.contains("*/") || (syntax == Syntax::Markup && s.contains("-->")) {
                in_block = None;
            }
            kinds.push(if narrative {
                LineKind::Comment
            } else {
                LineKind::Ignored
            });
            continue;
        }
        if let Some(quote) = in_docstring {
            if s.contains(quote) {
                in_docstring = None;
            }
            kinds.push(LineKind::Ignored);
            continue;
        }
        if s.is_empty() {
            kinds.push(LineKind::Ignored);
            continue;
        }

        kinds.push(classify(
            &lines,
            i,
            s,
            syntax,
            &mut in_block,
            &mut in_docstring,
        ));
    }

    let code_lines = kinds.iter().filter(|k| **k == LineKind::Code).count();
    let comment_lines = kinds.iter().filter(|k| **k == LineKind::Comment).count();
    let mut longest_block = 0;
    let mut run = 0;
    for k in &kinds {
        if *k == LineKind::Comment {
            run += 1;
            longest_block = longest_block.max(run);
        } else {
            run = 0;
        }
    }
    Stats {
        code_lines,
        comment_lines,
        longest_block,
    }
}

/// Classify one non-blank line, updating multi-line state when it opens a block.
fn classify<'a>(
    lines: &[&'a str],
    i: usize,
    s: &'a str,
    syntax: Syntax,
    in_block: &mut Option<bool>,
    in_docstring: &mut Option<&'a str>,
) -> LineKind {
    let own_line = |body: &str| {
        if is_directive(body) {
            LineKind::Ignored
        } else {
            LineKind::Comment
        }
    };

    match syntax {
        Syntax::Python | Syntax::Hash => {
            if syntax == Syntax::Python {
                for quote in ["\"\"\"", "'''"] {
                    if s.starts_with(quote)
                        || s.starts_with(&format!("r{quote}"))
                        || s.starts_with(&format!("f{quote}"))
                    {
                        if s.matches(quote).count() < 2 && closes_later(lines, i, quote) {
                            *in_docstring = Some(quote);
                        }
                        return LineKind::Ignored;
                    }
                }
            }
            if s.starts_with("#!") {
                return LineKind::Ignored;
            }
            if let Some(body) = s.strip_prefix('#') {
                return own_line(body);
            }
            LineKind::Code
        }
        Syntax::Slash => {
            if let Some(rest) = s.strip_prefix("/**") {
                if !rest.contains("*/") && closes_later(lines, i, "*/") {
                    *in_block = Some(false);
                }
                return LineKind::Ignored;
            }
            if s.starts_with("///") || s.starts_with("//!") {
                return LineKind::Ignored;
            }
            if let Some(rest) = s.strip_prefix("/*") {
                if !rest.contains("*/") && closes_later(lines, i, "*/") {
                    *in_block = Some(true);
                }
                return own_line(rest);
            }
            if let Some(body) = s.strip_prefix("//") {
                return own_line(body);
            }
            LineKind::Code
        }
        Syntax::Dash => {
            if let Some(body) = s.strip_prefix("--") {
                return own_line(body);
            }
            LineKind::Code
        }
        Syntax::Block => {
            if let Some(rest) = s.strip_prefix("/**") {
                if !rest.contains("*/") && closes_later(lines, i, "*/") {
                    *in_block = Some(false);
                }
                return LineKind::Ignored;
            }
            if let Some(rest) = s.strip_prefix("/*") {
                if !rest.contains("*/") && closes_later(lines, i, "*/") {
                    *in_block = Some(true);
                }
                return own_line(rest);
            }
            LineKind::Code
        }
        Syntax::Markup => {
            if let Some(body) = s.strip_prefix("<!--") {
                if !s.contains("-->") && closes_later(lines, i, "-->") {
                    *in_block = Some(true);
                }
                return own_line(body);
            }
            LineKind::Code
        }
    }
}

/// A comment-lint rule. `id` is a stable `category/name` slug.
pub struct LintRule {
    pub id: &'static str,
    pub message: &'static str,
}

pub(crate) fn rules() -> &'static [LintRule] {
    &[
        LintRule {
            id: "volume/comment-heavy",
            message: "Keep the ones a reader could not infer from the code and delete the rest.",
        },
        LintRule {
            id: "volume/long-block",
            message: "State the constraint in one or two lines, or move the explanation to a doc comment on the item it describes.",
        },
    ]
}

/// PostToolUse: measure written content and return findings as additionalContext.
pub fn check_comment_lint_post_for_content(
    content_pairs: &[(String, String)],
    config: &CommentLintConfig,
) -> Option<PostToolUseOutput> {
    let mut findings: Vec<String> = Vec::new();
    let mut seen: Vec<&'static str> = Vec::new();
    let disabled = |id: &str| config.disable_rules.iter().any(|r| r == id);

    for (path, content) in content_pairs {
        let Some(syntax) = syntax_for(path) else {
            continue;
        };
        let stats = scan(content, syntax);
        let name = path.rsplit('/').next().unwrap_or(path);

        let rule = &rules()[0];
        if !disabled(rule.id)
            && !seen.contains(&rule.id)
            && stats.code_lines >= config.min_code_lines
            && stats.comment_lines * 100 > stats.code_lines * config.max_per_100
        {
            seen.push(rule.id);
            findings.push(format!(
                "**{}**: {} adds {} comment lines to {} lines of code. {}",
                rule.id, name, stats.comment_lines, stats.code_lines, rule.message
            ));
        }

        let rule = &rules()[1];
        if !disabled(rule.id)
            && !seen.contains(&rule.id)
            && stats.longest_block > config.max_block_lines
        {
            seen.push(rule.id);
            findings.push(format!(
                "**{}**: {} contains a {}-line comment block. {}",
                rule.id, name, stats.longest_block, rule.message
            ));
        }
    }

    if findings.is_empty() {
        return None;
    }
    let context = format!(
        "Comment volume review of written code:\n\n{}\n\nTrim what restates the code, or note why the detail has to stay.",
        findings.join("\n\n")
    );
    Some(PostToolUseOutput::with_context(&context))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> CommentLintConfig {
        CommentLintConfig::default()
    }

    fn pairs(path: &str, content: &str) -> Vec<(String, String)> {
        vec![(path.to_string(), content.to_string())]
    }

    fn context(out: &PostToolUseOutput) -> String {
        out.hook_specific_output
            .as_ref()
            .and_then(|h| h.additional_context.clone())
            .unwrap_or_default()
    }

    #[test]
    fn syntax_mapping_covers_code_and_skips_prose() {
        assert!(syntax_for("/a/b.rs").is_some());
        assert!(syntax_for("/a/b.py").is_some());
        assert!(syntax_for("/a/Makefile").is_some());
        assert!(syntax_for("/a/README.md").is_none());
        assert!(syntax_for("/a/data.json").is_none());
        assert!(syntax_for("/a/noext").is_none());
    }

    #[test]
    fn counts_own_line_comments_and_code() {
        let stats = scan("// explain\nlet a = 1;\nlet b = 2;\n", Syntax::Slash);
        assert_eq!(stats.comment_lines, 1);
        assert_eq!(stats.code_lines, 2);
        assert_eq!(stats.longest_block, 1);
    }

    #[test]
    fn doc_comments_are_exempt() {
        let stats = scan("/// API doc\n//! Module doc\nlet a = 1;\n", Syntax::Slash);
        assert_eq!(stats.comment_lines, 0);
        assert_eq!(stats.code_lines, 1);
    }

    #[test]
    fn python_docstrings_are_exempt() {
        let src = "def f():\n    \"\"\"Doc line.\n    More doc.\n    \"\"\"\n    return 1\n";
        let stats = scan(src, Syntax::Python);
        assert_eq!(stats.comment_lines, 0);
        assert_eq!(stats.code_lines, 2);
    }

    #[test]
    fn tooling_directives_are_exempt() {
        let stats = scan("# noqa: E402\n# type: ignore\nx = 1\n", Syntax::Python);
        assert_eq!(stats.comment_lines, 0);
        assert_eq!(stats.code_lines, 1);
    }

    #[test]
    fn shell_expansion_is_not_a_comment() {
        let stats = scan(
            "if (( ${#items[@]} == 0 )); then\n  run\nfi\n",
            Syntax::Hash,
        );
        assert_eq!(stats.comment_lines, 0);
        assert_eq!(stats.code_lines, 3);
    }

    #[test]
    fn unterminated_block_does_not_swallow_code() {
        let stats = scan(
            "/* opener with no closer\nlet a = 1;\nlet b = 2;\n",
            Syntax::Slash,
        );
        assert_eq!(stats.comment_lines, 1);
        assert_eq!(stats.code_lines, 2);
    }

    #[test]
    fn longest_block_counts_consecutive_lines() {
        let src = "// one\n// two\n// three\nlet a = 1;\n// alone\n";
        assert_eq!(scan(src, Syntax::Slash).longest_block, 3);
    }

    #[test]
    fn density_rule_fires_above_threshold() {
        let mut src = String::new();
        for i in 0..12 {
            src.push_str(&format!("// narration {i}\n"));
        }
        for i in 0..16 {
            src.push_str(&format!("let v{i} = {i};\n"));
        }
        let out = check_comment_lint_post_for_content(&pairs("/a/b.rs", &src), &cfg())
            .expect("density rule fires");
        assert!(context(&out).contains("volume/comment-heavy"));
    }

    #[test]
    fn density_rule_quiet_on_normal_edits() {
        let mut src = String::from("// one explanation\n");
        for i in 0..20 {
            src.push_str(&format!("let v{i} = {i};\n"));
        }
        assert!(check_comment_lint_post_for_content(&pairs("/a/b.rs", &src), &cfg()).is_none());
    }

    #[test]
    fn density_rule_needs_minimum_code_lines() {
        let src = "// a\n// b\n// c\nlet x = 1;\n";
        assert!(check_comment_lint_post_for_content(&pairs("/a/b.rs", src), &cfg()).is_none());
    }

    #[test]
    fn long_block_rule_fires() {
        let mut src = String::new();
        for i in 0..7 {
            src.push_str(&format!("// paragraph line {i}\n"));
        }
        for i in 0..40 {
            src.push_str(&format!("let v{i} = {i};\n"));
        }
        let out = check_comment_lint_post_for_content(&pairs("/a/b.rs", &src), &cfg())
            .expect("long-block rule fires");
        let ctx = context(&out);
        assert!(ctx.contains("volume/long-block"));
        assert!(ctx.contains("7-line"));
    }

    #[test]
    fn disable_rules_silences_a_rule() {
        let mut src = String::new();
        for i in 0..7 {
            src.push_str(&format!("// paragraph line {i}\n"));
        }
        for i in 0..40 {
            src.push_str(&format!("let v{i} = {i};\n"));
        }
        let config = CommentLintConfig {
            disable_rules: vec!["volume/long-block".to_string()],
            ..CommentLintConfig::default()
        };
        assert!(check_comment_lint_post_for_content(&pairs("/a/b.rs", &src), &config).is_none());
    }

    #[test]
    fn non_code_files_are_skipped() {
        let mut src = String::new();
        for i in 0..12 {
            src.push_str(&format!("<!-- note {i} -->\n"));
        }
        assert!(check_comment_lint_post_for_content(&pairs("/a/notes.md", &src), &cfg()).is_none());
    }

    #[test]
    fn empty_content_is_quiet() {
        assert!(check_comment_lint_post_for_content(&[], &cfg()).is_none());
    }
}

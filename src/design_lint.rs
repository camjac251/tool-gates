//! Frontend design linting for Write/Edit content (PostToolUse).
//!
//! Scans written UI files for generic, templated design patterns and missing
//! UI-quality basics, then surfaces the findings as PostToolUse
//! `additionalContext` so the assistant can self-correct. It catches things a
//! competent designer would not ship by default: overused gradients and
//! palettes, the default sans font, placeholder/stock content, em-dashes in
//! rendered copy, hardcoded palette colors instead of theme tokens, and
//! interactive elements with no visible focus style.
//!
//! Opt-in via `features.design_lint` (default off). Unlike security scanning,
//! these are design-quality conventions, not a universal safety floor, so the
//! gate stays quiet unless a project asks for it.
//!
//! Detection is intentionally conservative: every rule matches a specific,
//! high-confidence signal, and raw color values inside `:root` token
//! *definitions* are exempt (that is the one legitimate place a literal brand
//! value lives). The catalog below is the floor, not the ceiling.

use crate::config::DesignLintConfig;
use crate::models::PostToolUseOutput;
use crate::security_reminders::extract_content;
use regex::Regex;
use std::sync::OnceLock;

/// UI file extensions this linter scans. Everything else is ignored.
const UI_EXTENSIONS: &[&str] = &[
    ".tsx", ".jsx", ".vue", ".svelte", ".astro", ".html", ".htm", ".css", ".scss", ".sass",
    ".less", ".styl", ".mdx",
];

fn is_ui_file(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    UI_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

/// How a rule decides whether content is in violation.
enum Kind {
    /// Regex tested per line. A line that also matches `skip_if` is exempt: a
    /// CSS custom-property definition (`--brand: #6366f1`) is the one legit
    /// place a literal brand value lives, so token definitions are not flagged
    /// while the same value used in markup still is.
    Line {
        pattern: &'static str,
        skip_if: Option<&'static str>,
    },
    /// Violet/purple/indigo gradient detected by hue rather than by literal
    /// hex, so arbitrary violets (`#8a7bff`, `rgba(138, 123, 255, ...)`) are
    /// caught too. Token-definition lines are exempt, same as `Line`.
    PurpleGradient,
    /// Whole-file: `outline: none` / `outline-none` with no `focus-visible`
    /// replacement anywhere in the file.
    OutlineWithoutFocusVisible,
}

/// A design-lint rule. `id` is a stable `category/name` slug.
pub struct LintRule {
    pub id: &'static str,
    pub message: &'static str,
    kind: Kind,
}

/// Skip-pattern for a CSS custom-property definition line.
const TOKEN_DEF_SKIP: &str = r"--[\w-]+\s*:";

fn rules() -> &'static [LintRule] {
    static RULES: OnceLock<Vec<LintRule>> = OnceLock::new();
    RULES.get_or_init(|| {
        vec![
            LintRule {
                id: "color/cliche-gradient",
                message: "Overused #667eea / #764ba2 'tech' gradient. Use a solid color or a narrow-band gradient.",
                kind: Kind::Line { pattern: r"linear-gradient[^;]*(667eea|764ba2)", skip_if: None },
            },
            LintRule {
                id: "color/purple-gradient",
                message: "Purple, violet, or indigo gradient. Favor a flat surface with intentional typography; if the brand truly uses violet, define it as a token and reference it via var().",
                kind: Kind::PurpleGradient,
            },
            LintRule {
                id: "color/overused-palette",
                message: "Overused beige / brass / espresso 'premium' palette. Choose colors that reflect the actual brand.",
                kind: Kind::Line {
                    pattern: r"(?i)#(f5f1ea|f7f5f1|fbf8f1|efeae0|ece6db|faf7f1|e8dfcb|b08947|b6553a|9a2436|9c6e2a|bc7c3a|7d5621|1a1714|1a1814|1b1814)\b",
                    skip_if: Some(TOKEN_DEF_SKIP),
                },
            },
            LintRule {
                id: "color/default-indigo",
                message: "Default Tailwind indigo accent. Use a theme token; define indigo in the theme if the brand genuinely calls for it.",
                kind: Kind::Line {
                    pattern: r"(?i)#(6366f1|4f46e5|4338ca|3730a3|8b5cf6|7c3aed|a855f7)\b",
                    skip_if: Some(TOKEN_DEF_SKIP),
                },
            },
            LintRule {
                id: "layout/accent-stripe",
                message: "Card with a 4px left accent stripe. Use a tonal background or a thin bottom border instead.",
                kind: Kind::Line { pattern: r"border-left:\s*4px\s+solid", skip_if: None },
            },
            LintRule {
                id: "typography/default-font",
                message: "Inter as the display font. Choose a typeface suited to the product's character.",
                kind: Kind::Line { pattern: r#"font-family[^;}]*["']Inter["']"#, skip_if: None },
            },
            LintRule {
                id: "content/placeholder-name",
                message: "Placeholder or stock person/company name. Use real content or an explicit [placeholder].",
                kind: Kind::Line {
                    pattern: r"Sarah J\.|John Doe|Jack Su|Sarah Chan|\bTechCorp\b|\bSmartFlow\b|\bQuantumFlow\b|\bProSync\b",
                    skip_if: None,
                },
            },
            LintRule {
                id: "content/fabricated-stat",
                message: "Round, unsourced statistic. Use a real measured number or remove it.",
                kind: Kind::Line { pattern: r"10,000\+|99\.9%", skip_if: None },
            },
            LintRule {
                id: "content/filler-copy",
                message: "Generic marketing filler ('Elevate', 'Seamless', 'Unleash', ...). State a concrete outcome instead.",
                kind: Kind::Line {
                    pattern: r"Elevate your|Seamless integration|Unleash the|Next-Gen|Revolutionize|Unlock the potential",
                    skip_if: None,
                },
            },
            LintRule {
                id: "content/dash",
                message: "Em or en dash in rendered text. Use a period, comma, colon, or parentheses.",
                kind: Kind::Line {
                    pattern: r"—|–|&mdash;|&ndash;|&#8212;|&#8211;|&#x2014;|&#x2013;",
                    skip_if: None,
                },
            },
            LintRule {
                id: "behavior/scroll-into-view",
                message: "scrollIntoView mutates ancestor scroll position in embedded contexts. Use scrollTo with a computed offset.",
                kind: Kind::Line { pattern: r"scrollIntoView", skip_if: None },
            },
            LintRule {
                id: "assets/hotlinked-image",
                message: "Hotlinked external image. Download and self-host the asset.",
                kind: Kind::Line { pattern: r"unsplash\.com", skip_if: None },
            },
            LintRule {
                id: "color/hardcoded-palette",
                message: "Hardcoded Tailwind palette color. Use semantic theme tokens (bg-background, text-foreground, ...).",
                kind: Kind::Line {
                    pattern: r"\b(bg|text|border|ring|from|via|to|fill|stroke)-(gray|slate|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-\d{2,3}\b",
                    skip_if: None,
                },
            },
            LintRule {
                id: "color/raw-hex",
                message: "Raw hex in an inline style. Use a theme token.",
                kind: Kind::Line {
                    pattern: r#"style=("[^"]*#[0-9a-fA-F]{3,8}|\{\{[^}]*#[0-9a-fA-F]{3,8})"#,
                    skip_if: None,
                },
            },
            LintRule {
                id: "color/theme-accessor",
                message: "theme(colors.*) in raw CSS. Reference the CSS variable directly, e.g. var(--color-muted).",
                kind: Kind::Line { pattern: r"theme\(\s*colors\.", skip_if: None },
            },
            LintRule {
                id: "typography/small-body-text",
                message: "text-xs / text-sm on a <p>. Body text should be 16px or larger; reserve smaller sizes for metadata.",
                kind: Kind::Line { pattern: r#"<p[^>]*(class|className)="[^"]*text-(xs|sm)\b"#, skip_if: None },
            },
            LintRule {
                id: "a11y/focus-visible",
                message: "Focus outline removed with no focus-visible replacement. Add a visible focus style.",
                kind: Kind::OutlineWithoutFocusVisible,
            },
        ]
    })
}

/// Compiled (main regex, optional skip_if regex) for each `Kind::Line` rule,
/// keyed by id. Compiled once.
fn line_cache() -> &'static Vec<(&'static str, Regex, Option<Regex>)> {
    static CACHE: OnceLock<Vec<(&'static str, Regex, Option<Regex>)>> = OnceLock::new();
    CACHE.get_or_init(|| {
        rules()
            .iter()
            .filter_map(|rule| match &rule.kind {
                Kind::Line { pattern, skip_if } => Some((
                    rule.id,
                    Regex::new(pattern).expect("invalid design-lint regex"),
                    skip_if.map(|s| Regex::new(s).expect("invalid skip_if regex")),
                )),
                _ => None,
            })
            .collect()
    })
}

fn compiled_line(id: &str) -> (&'static Regex, Option<&'static Regex>) {
    let (_, re, skip) = line_cache()
        .iter()
        .find(|(name, _, _)| *name == id)
        .expect("line rule must be compiled");
    (re, skip.as_ref())
}

fn token_def_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(TOKEN_DEF_SKIP).unwrap())
}

fn outline_without_focus_visible(content: &str) -> bool {
    static OUTLINE: OnceLock<Regex> = OnceLock::new();
    let re = OUTLINE.get_or_init(|| Regex::new(r"outline:\s*none|\boutline-none\b").unwrap());
    re.is_match(content) && !content.contains("focus-visible")
}

/// Parse a raw CSS color (`#hex` or `rgb()/rgba()`) to its OKLCH hue (degrees)
/// and chroma. Uses the Bjorn Ottosson OKLab conversion. Returns `None` for
/// shapes that are not a plain hex or numeric `rgb()`.
fn parse_hue_chroma(token: &str) -> Option<(f64, f64)> {
    let (r, g, b) = if let Some(hex) = token.strip_prefix('#') {
        let full = match hex.len() {
            3 => hex.chars().flat_map(|c| [c, c]).collect::<String>(),
            6 => hex.to_string(),
            _ => return None,
        };
        let comp = |i: usize| {
            u8::from_str_radix(&full[i..i + 2], 16)
                .ok()
                .map(|v| f64::from(v) / 255.0)
        };
        (comp(0)?, comp(2)?, comp(4)?)
    } else {
        let inner = token.split_once('(')?.1;
        let nums: Vec<f64> = inner
            .trim_end_matches(')')
            .split([',', ' ', '/'])
            .filter_map(|s| {
                let t = s.trim();
                if t.is_empty() {
                    None
                } else {
                    t.parse::<f64>().ok()
                }
            })
            .collect();
        if nums.len() < 3 {
            return None;
        }
        (nums[0] / 255.0, nums[1] / 255.0, nums[2] / 255.0)
    };

    let to_linear = |c: f64| {
        if c <= 0.04045 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    let (lr, lg, lb) = (to_linear(r), to_linear(g), to_linear(b));
    let l = (0.4122214708 * lr + 0.5363325363 * lg + 0.0514459929 * lb).cbrt();
    let m = (0.2119034982 * lr + 0.6806995451 * lg + 0.1073969566 * lb).cbrt();
    let s = (0.0883024619 * lr + 0.2817188376 * lg + 0.6299787005 * lb).cbrt();
    let a = 1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s;
    let bb = 0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s;
    let mut hue = bb.atan2(a).to_degrees();
    if hue < 0.0 {
        hue += 360.0;
    }
    Some((hue, a.hypot(bb)))
}

/// True when a line declares a gradient that pulls toward violet/purple/indigo.
/// Gated to gradient context and raw color values (var()-driven gradients pass).
/// The violet hue band deliberately stops short of pure blue (~250 deg) so
/// legitimate blue gradients do not trip it.
fn is_purple_gradient(line: &str) -> bool {
    static GRADIENT: OnceLock<Regex> = OnceLock::new();
    static KEYWORD: OnceLock<Regex> = OnceLock::new();
    static COLOR_TOKEN: OnceLock<Regex> = OnceLock::new();
    let gradient = GRADIENT.get_or_init(|| Regex::new(r"(?i)gradient").unwrap());
    if !gradient.is_match(line) {
        return false;
    }
    let keyword = KEYWORD.get_or_init(|| Regex::new(r"(?i)\b(purple|violet|indigo)\b").unwrap());
    if keyword.is_match(line) {
        return true;
    }
    let color_token =
        COLOR_TOKEN.get_or_init(|| Regex::new(r"(?i)#[0-9a-f]{3,6}\b|rgba?\([^)]*\)").unwrap());
    color_token.find_iter(line).any(|t| {
        matches!(parse_hue_chroma(t.as_str()), Some((hue, chroma)) if chroma > 0.09 && (265.0..=330.0).contains(&hue))
    })
}

/// Scan UI file content, returning the rules it violates (each at most once).
/// Returns empty for non-UI files.
pub fn scan_content(file_path: &str, content: &str) -> Vec<&'static LintRule> {
    if !is_ui_file(file_path) {
        return Vec::new();
    }
    rules()
        .iter()
        .filter(|rule| match &rule.kind {
            Kind::Line { .. } => {
                let (re, skip) = compiled_line(rule.id);
                content
                    .lines()
                    .any(|line| re.is_match(line) && !skip.is_some_and(|s| s.is_match(line)))
            }
            Kind::PurpleGradient => content
                .lines()
                .any(|line| is_purple_gradient(line) && !token_def_re().is_match(line)),
            Kind::OutlineWithoutFocusVisible => outline_without_focus_visible(content),
        })
        .collect()
}

/// PostToolUse: scan written UI content and return findings as additionalContext.
///
/// Fires whenever violations exist (no per-session dedup): the value is a
/// fix-it nudge on every write that introduces one.
pub fn check_design_lint_post(
    tool_name: &str,
    tool_input_map: &serde_json::Map<String, serde_json::Value>,
    config: &DesignLintConfig,
) -> Option<PostToolUseOutput> {
    if crate::models::Client::is_read_tool(tool_name) {
        return None;
    }

    let content_pairs = extract_content(tool_name, tool_input_map);
    if content_pairs.is_empty() {
        return None;
    }

    let mut findings: Vec<String> = Vec::new();
    let mut seen: Vec<&'static str> = Vec::new();
    for (file_path, content) in &content_pairs {
        for rule in scan_content(file_path, content) {
            if config.disable_rules.iter().any(|r| r == rule.id) {
                continue;
            }
            if seen.contains(&rule.id) {
                continue;
            }
            seen.push(rule.id);
            findings.push(format!("**{}**: {}", rule.id, rule.message));
        }
    }

    if findings.is_empty() {
        return None;
    }

    let context = format!(
        "Frontend design review of written UI:\n\n{}\n\nAddress these, or if a flagged value is real data or an intentional theme-token definition, note why it stays.",
        findings.join("\n\n")
    );
    Some(PostToolUseOutput::with_context(&context))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(matches: &[&'static LintRule]) -> Vec<&'static str> {
        matches.iter().map(|r| r.id).collect()
    }

    fn make_map(json: &str) -> serde_json::Map<String, serde_json::Value> {
        match serde_json::from_str::<serde_json::Value>(json).unwrap() {
            serde_json::Value::Object(m) => m,
            _ => panic!("expected object"),
        }
    }

    #[test]
    fn test_non_ui_file_skipped() {
        let matches = scan_content("/tmp/app.py", "font-family: 'Inter'; eval(x); #6366f1");
        assert!(matches.is_empty(), "non-UI files are not scanned");
    }

    #[test]
    fn test_clean_ui_is_silent() {
        let content = r#"<nav class="bg-background text-foreground">
  <p class="text-base">Fast, reliable, and beautiful.</p>
  <button class="focus-visible:ring-2" aria-label="Go">Go</button>
</nav>"#;
        let matches = scan_content("/tmp/clean.tsx", content);
        assert!(
            ids(&matches).is_empty(),
            "clean UI should not flag: {:?}",
            ids(&matches)
        );
    }

    #[test]
    fn test_dirty_ui_flags_expected_rules() {
        let content = r#"<div style="background: linear-gradient(135deg, #667eea, #764ba2)">
  <p class="text-sm">Fast, reliable — and beautiful</p>
  <span class="bg-blue-500">Sarah Chan, CEO at TechCorp</span>
  <button>Elevate your workflow</button>
</div>"#;
        let got = ids(&scan_content("/tmp/dirty.tsx", content));
        for expected in [
            "color/cliche-gradient",
            "content/dash",
            "content/placeholder-name",
            "content/filler-copy",
            "color/hardcoded-palette",
            "color/raw-hex",
            "typography/small-body-text",
        ] {
            assert!(got.contains(&expected), "expected {expected} in {got:?}");
        }
    }

    #[test]
    fn test_token_definition_is_exempt() {
        // :root token DEFINITIONS of these colors are intentional, not flags.
        let content = ":root {\n  --paper: #f5f1ea;\n  --accent: #6366f1;\n}";
        let got = ids(&scan_content("/tmp/tokens.css", content));
        assert!(
            !got.contains(&"color/overused-palette"),
            "token def exempt: {got:?}"
        );
        assert!(
            !got.contains(&"color/default-indigo"),
            "token def exempt: {got:?}"
        );
    }

    #[test]
    fn test_indigo_used_in_markup_is_flagged() {
        let content = r#"<div style="background:#6366f1">x</div>"#;
        let got = ids(&scan_content("/tmp/x.tsx", content));
        assert!(
            got.contains(&"color/default-indigo"),
            "indigo usage flagged: {got:?}"
        );
    }

    #[test]
    fn test_purple_gradient_hue_catches_arbitrary_violet() {
        let hex = scan_content(
            "/tmp/a.css",
            ".a{background:linear-gradient(90deg,#8a7bff,#fff)}",
        );
        assert!(
            ids(&hex).contains(&"color/purple-gradient"),
            "violet hex gradient flagged"
        );

        let rgba = scan_content(
            "/tmp/b.css",
            ".b{background:radial-gradient(rgba(138,123,255,0.3),transparent)}",
        );
        assert!(
            ids(&rgba).contains(&"color/purple-gradient"),
            "violet rgba gradient flagged"
        );
    }

    #[test]
    fn test_purple_gradient_no_false_positive_on_blue_or_var() {
        let blue = scan_content(
            "/tmp/c.css",
            ".c{background:linear-gradient(90deg,#3b82f6,#06b6d4)}",
        );
        assert!(
            !ids(&blue).contains(&"color/purple-gradient"),
            "blue to cyan must not flag"
        );

        let var = scan_content(
            "/tmp/d.css",
            ".d{background:linear-gradient(var(--a),var(--b))}",
        );
        assert!(
            !ids(&var).contains(&"color/purple-gradient"),
            "var() gradient must not flag"
        );
    }

    #[test]
    fn test_outline_without_focus_visible() {
        let bad = scan_content("/tmp/e.css", "button { outline: none; }");
        assert!(ids(&bad).contains(&"a11y/focus-visible"));

        let ok = scan_content(
            "/tmp/f.css",
            "button { outline: none; }\nbutton:focus-visible { outline: 2px solid; }",
        );
        assert!(
            !ids(&ok).contains(&"a11y/focus-visible"),
            "replacement present"
        );
    }

    // --- check_design_lint_post ---

    #[test]
    fn test_post_emits_context_on_dirty_write() {
        let map = make_map(
            r#"{"file_path": "/tmp/x.tsx", "content": "<p class=\"text-sm\">Fast — clean</p>"}"#,
        );
        let config = DesignLintConfig::default();
        let out = check_design_lint_post("Write", &map, &config);
        assert!(out.is_some());
        let json = serde_json::to_string(&out.unwrap()).unwrap();
        assert!(
            json.contains("additionalContext"),
            "should inject context: {json}"
        );
        assert!(
            json.contains("content/dash"),
            "should name the rule: {json}"
        );
    }

    #[test]
    fn test_post_silent_on_clean_write() {
        let map = make_map(
            r#"{"file_path": "/tmp/x.tsx", "content": "<p class=\"text-base\">Hello.</p>"}"#,
        );
        let out = check_design_lint_post("Write", &map, &DesignLintConfig::default());
        assert!(out.is_none(), "clean write should be silent");
    }

    #[test]
    fn test_post_skips_read_tool() {
        let map = make_map(r#"{"file_path": "/tmp/x.tsx"}"#);
        let out = check_design_lint_post("Read", &map, &DesignLintConfig::default());
        assert!(out.is_none());
    }

    #[test]
    fn test_post_skips_non_ui_file() {
        let map =
            make_map(r#"{"file_path": "/tmp/app.py", "content": "x = 'Elevate your workflow'"}"#);
        let out = check_design_lint_post("Write", &map, &DesignLintConfig::default());
        assert!(out.is_none(), "non-UI file should not be scanned");
    }

    #[test]
    fn test_post_disable_rule() {
        let map = make_map(r#"{"file_path": "/tmp/x.tsx", "content": "<p>Fast — clean</p>"}"#);
        let config = DesignLintConfig {
            disable_rules: vec!["content/dash".to_string()],
        };
        let out = check_design_lint_post("Write", &map, &config);
        assert!(
            out.is_none(),
            "disabling the only matched rule yields no output"
        );
    }
}

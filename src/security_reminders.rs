//! Security anti-pattern scanning for Write/Edit content.
//!
//! Scans file edit content for common vulnerability patterns (command injection,
//! XSS, hardcoded secrets, unsafe deserialization, etc.) and returns deny/warn
//! decisions. Warnings are deduped per (file, rule) per session.
//!
//! Patterns are organized into tiers:
//! - **Tier 1 (deny):** High confidence, near-zero false positives (secrets, keys)
//! - **Tier 2 (ask-once):** User prompted first time per session, then silent (eval, exec, XSS)
//! - **Tier 3 (warn):** Informational context injected, no block (weak crypto, chmod 777)

use crate::config::SecurityRemindersConfig;
use crate::models::{HookOutput, PostToolUseOutput};
use regex::Regex;
use std::sync::OnceLock;

/// Extract all writable (file_path, content) pairs from a tool_input map.
///
/// Handles all tool types:
/// - Claude `Write` / Gemini `write_file`: top-level `file_path` + `content`.
/// - Claude `Edit` / Gemini `replace`: top-level `file_path` + `new_string`,
///   plus the batch `edits[].new_string` form.
/// - Codex `apply_patch`: parse the unified-diff body in `command` and emit
///   one `(path, added_lines)` pair per Add/Update section. Delete sections
///   are skipped (no content to scan).
fn extract_content(
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
        _ => {}
    }

    results
}

/// Pattern severity tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Hard deny. Always blocked (secrets, keys).
    Deny,
    /// Ask once per (file, rule) per session, then silent.
    AskOnce,
    /// Allow but inject warning into additionalContext.
    Warn,
}

/// A matched security pattern.
#[derive(Debug)]
pub struct PatternMatch {
    pub rule_name: &'static str,
    pub tier: Tier,
    pub message: &'static str,
}

/// Whether a rule checks path, content, or both.
enum CheckType {
    /// Only fires if file path matches (e.g., GHA workflows).
    PathBased { path_fn: fn(&str) -> bool },
    /// Fires on content substrings (skips doc files).
    Substring { patterns: &'static [&'static str] },
    /// Fires on content substrings unless exclusion also matches (skips doc files).
    SubstringUnless {
        patterns: &'static [&'static str],
        unless: &'static [&'static str],
    },
    /// Fires on content regex (skips doc files).
    ContentRegex { pattern: &'static str },
}

struct SecurityRule {
    name: &'static str,
    tier: Tier,
    message: &'static str,
    check: CheckType,
    /// If true, Tier 1 secret check that fires even on doc files.
    always_check: bool,
}

/// Doc file extensions. Content-based checks are skipped for these.
const DOC_EXTENSIONS: &[&str] = &[".md", ".txt", ".rst", ".adoc", ".asciidoc", ".html", ".htm"];

fn is_doc_file(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    DOC_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

/// Files designed to hold secrets. Tier 1 secret detection is skipped for these.
fn is_secret_file(path: &str) -> bool {
    let lower = path.to_ascii_lowercase().replace('\\', "/");
    let basename = lower.rsplit('/').next().unwrap_or(&lower);
    if basename == ".env" || basename == ".envrc" {
        return true;
    }
    if let Some(suffix) = basename.strip_prefix(".env.") {
        // Template files are meant to be committed. Secrets in them are a real problem
        return !matches!(suffix, "example" | "sample" | "template" | "dist");
    }
    false
}

fn is_gha_workflow(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    normalized.contains(".github/workflows/")
        && (normalized.ends_with(".yml") || normalized.ends_with(".yaml"))
}

/// Compiled regex cache (compiled once, reused).
static REGEX_CACHE: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();

fn get_compiled_regexes(rules: &[SecurityRule]) -> &'static Vec<(&'static str, Regex)> {
    REGEX_CACHE.get_or_init(|| {
        rules
            .iter()
            .filter_map(|rule| {
                if let CheckType::ContentRegex { pattern } = &rule.check {
                    Some((
                        rule.name,
                        Regex::new(pattern).expect("invalid security regex"),
                    ))
                } else {
                    None
                }
            })
            .collect()
    })
}

/// All security rules (static definition).
fn rules() -> &'static [SecurityRule] {
    static RULES: OnceLock<Vec<SecurityRule>> = OnceLock::new();
    RULES.get_or_init(|| {
        vec![
            // === Tier 1: Hard deny ===
            SecurityRule {
                name: "hardcoded_aws_key",
                tier: Tier::Deny,
                message: "Hardcoded AWS access key detected. Use environment variables or a secrets manager instead. Never commit AWS keys to source code.",
                check: CheckType::ContentRegex { pattern: r"AKIA[0-9A-Z]{16}" },
                always_check: true,
            },
            SecurityRule {
                name: "hardcoded_private_key",
                tier: Tier::Deny,
                message: "Private key detected in file content. Private keys must never be committed to source code. Use environment variables, a secrets manager, or file references outside the repo.",
                check: CheckType::Substring {
                    patterns: &[
                        "-----BEGIN RSA PRIVATE KEY",
                        "-----BEGIN EC PRIVATE KEY",
                        "-----BEGIN DSA PRIVATE KEY",
                        "-----BEGIN PRIVATE KEY",
                        "-----BEGIN OPENSSH PRIVATE KEY",
                    ],
                },
                always_check: true,
            },
            SecurityRule {
                name: "hardcoded_github_token",
                tier: Tier::Deny,
                message: "GitHub token detected in file content. Use GITHUB_TOKEN environment variable or gh auth instead. Revoke this token if it was ever committed.",
                check: CheckType::ContentRegex { pattern: r"(ghp|ghs|ghu|gho|ghr)_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,}" },
                always_check: true,
            },
            SecurityRule {
                name: "hardcoded_generic_secret",
                tier: Tier::Deny,
                message: "API key or token detected in file content. Use environment variables or a secrets manager. Never hardcode secrets in source code.",
                check: CheckType::ContentRegex {
                    pattern: r"(sk-[A-Za-z0-9]{20,}|sk_(live|test)_[A-Za-z0-9]{20,}|xox[bporas]-[A-Za-z0-9\-]{10,}|AIza[A-Za-z0-9_\-]{35})",
                },
                always_check: true,
            },
            SecurityRule {
                name: "github_actions_injection",
                tier: Tier::Deny,
                message: "GitHub Actions workflow injection risk. Untrusted input (issue title, PR body, commit message, head_ref) used directly in a run: block can lead to command injection.\n\nUNSAFE:\n  run: echo \"${{ github.event.issue.title }}\"\n\nSAFE:\n  env:\n    TITLE: ${{ github.event.issue.title }}\n  run: echo \"$TITLE\"\n\nSee: https://github.blog/security/vulnerability-research/how-to-catch-github-actions-workflow-injections-before-attackers-do/",
                check: CheckType::PathBased { path_fn: is_gha_workflow },
                always_check: false, // Content check happens separately via GHA-specific regex
            },

            // === Tier 2: Ask once per session ===
            SecurityRule {
                name: "child_process_exec",
                tier: Tier::AskOnce,
                message: "child_process.exec() can lead to command injection. Use child_process.execFile() or child_process.spawn() instead. They don't invoke a shell and prevent argument injection.",
                check: CheckType::Substring { patterns: &["child_process.exec", "execSync("] },
                always_check: false,
            },
            SecurityRule {
                name: "new_function_injection",
                tier: Tier::AskOnce,
                message: "new Function() with dynamic strings can lead to code injection. Consider alternative approaches that don't evaluate arbitrary code.",
                check: CheckType::Substring { patterns: &["new Function("] },
                always_check: false,
            },
            SecurityRule {
                name: "eval_injection",
                tier: Tier::AskOnce,
                message: "eval() executes arbitrary code and is a major security risk. Use JSON.parse() for data parsing, or alternative design patterns that don't require code evaluation.",
                check: CheckType::Substring { patterns: &["eval("] },
                always_check: false,
            },
            SecurityRule {
                name: "os_system_injection",
                tier: Tier::AskOnce,
                message: "os.system() passes commands through the shell and is vulnerable to injection. Use subprocess.run() with a list of arguments (no shell=True) instead.",
                check: CheckType::Substring { patterns: &["os.system(", "from os import system"] },
                always_check: false,
            },
            SecurityRule {
                name: "pickle_deserialization",
                tier: Tier::AskOnce,
                message: "pickle can execute arbitrary code during deserialization. Use JSON, msgpack, or other safe serialization formats for untrusted data. Only use pickle with data you fully trust.",
                check: CheckType::Substring { patterns: &["pickle.load", "pickle.loads"] },
                always_check: false,
            },
            SecurityRule {
                name: "dangerous_inner_html",
                tier: Tier::AskOnce,
                message: "dangerouslySetInnerHTML can lead to XSS if used with untrusted content. Sanitize all content with DOMPurify or use safe alternatives like textContent.",
                check: CheckType::Substring { patterns: &["dangerouslySetInnerHTML"] },
                always_check: false,
            },
            SecurityRule {
                name: "document_write_xss",
                tier: Tier::AskOnce,
                message: "document.write() can be exploited for XSS attacks. Use DOM manipulation methods like createElement() and appendChild() instead.",
                check: CheckType::Substring { patterns: &["document.write("] },
                always_check: false,
            },
            SecurityRule {
                name: "inner_html_assignment",
                tier: Tier::AskOnce,
                message: "Setting innerHTML with untrusted content can lead to XSS. Use textContent for plain text, or sanitize HTML content with DOMPurify.",
                check: CheckType::Substring { patterns: &[".innerHTML =", ".innerHTML="] },
                always_check: false,
            },
            SecurityRule {
                name: "unsafe_yaml_load",
                tier: Tier::AskOnce,
                message: "yaml.load() without SafeLoader can execute arbitrary Python code. Use yaml.safe_load() or yaml.load(f, Loader=yaml.SafeLoader) instead.",
                check: CheckType::SubstringUnless {
                    patterns: &["yaml.load("],
                    unless: &["SafeLoader", "safe_load"],
                },
                always_check: false,
            },
            SecurityRule {
                name: "sql_string_interpolation",
                tier: Tier::AskOnce,
                message: "SQL query built with string interpolation is vulnerable to SQL injection. Use parameterized queries (?, %s, :param) instead of f-strings or .format().",
                check: CheckType::ContentRegex {
                    pattern: r#"(?i)f["'](?:SELECT|INSERT|UPDATE|DELETE)|\.execute\(f["']"#,
                },
                always_check: false,
            },
            SecurityRule {
                name: "subprocess_shell_true",
                tier: Tier::AskOnce,
                message: "subprocess with shell=True is vulnerable to command injection. Pass a list of arguments instead: subprocess.run([\"cmd\", \"arg1\", \"arg2\"]).",
                check: CheckType::ContentRegex {
                    pattern: r"subprocess\.(call|run|Popen)\(.*shell\s*=\s*True",
                },
                always_check: false,
            },
            SecurityRule {
                name: "flask_ssti",
                tier: Tier::AskOnce,
                message: "render_template_string() with user input can lead to server-side template injection (SSTI). Use render_template() with a file instead, or sanitize all dynamic content.",
                check: CheckType::Substring { patterns: &["render_template_string("] },
                always_check: false,
            },
            SecurityRule {
                name: "marshal_deserialization",
                tier: Tier::AskOnce,
                message: "marshal can execute arbitrary code during deserialization. Use JSON or other safe serialization formats for untrusted data.",
                check: CheckType::Substring { patterns: &["marshal.load(", "marshal.loads(", "shelve.open("] },
                always_check: false,
            },
            SecurityRule {
                name: "python_dynamic_import",
                tier: Tier::AskOnce,
                message: "__import__() with dynamic strings can load arbitrary modules. Use static imports or importlib with validated module names.",
                check: CheckType::Substring { patterns: &["__import__("] },
                always_check: false,
            },
            SecurityRule {
                name: "php_unserialize",
                tier: Tier::AskOnce,
                message: "unserialize() with untrusted data can lead to arbitrary code execution via PHP object injection. Use json_decode() instead.",
                check: CheckType::Substring { patterns: &["unserialize("] },
                always_check: false,
            },

            // === Tier 3: Warn (allow with context) ===
            SecurityRule {
                name: "ssl_verification_disabled",
                tier: Tier::Warn,
                message: "SSL/TLS verification is disabled. This makes the connection vulnerable to man-in-the-middle attacks. Only disable for local development with self-signed certs.",
                check: CheckType::Substring {
                    patterns: &["verify=False", "verify = False", "rejectUnauthorized: false", "NODE_TLS_REJECT_UNAUTHORIZED"],
                },
                always_check: false,
            },
            SecurityRule {
                name: "chmod_777",
                tier: Tier::Warn,
                message: "chmod 777 / 0o777 grants read+write+execute to all users. Use more restrictive permissions (e.g., 0o755 for dirs, 0o644 for files).",
                check: CheckType::Substring { patterns: &["chmod 777", "0o777", "0777"] },
                always_check: false,
            },
            SecurityRule {
                name: "weak_crypto_hash",
                tier: Tier::Warn,
                message: "MD5/SHA1 are cryptographically broken for security purposes. Use SHA-256+ for integrity checks, bcrypt/argon2 for passwords.",
                check: CheckType::Substring {
                    patterns: &["hashlib.md5(", "hashlib.sha1(", "MD5.new(", "SHA1.new("],
                },
                always_check: false,
            },
            SecurityRule {
                name: "vue_v_html",
                tier: Tier::Warn,
                message: "v-html renders raw HTML and is vulnerable to XSS with untrusted content. Sanitize content with DOMPurify or use text interpolation {{ }} instead.",
                check: CheckType::Substring { patterns: &["v-html="] },
                always_check: false,
            },
            SecurityRule {
                name: "template_autoescape_disabled",
                tier: Tier::Warn,
                message: "Disabling autoescape removes XSS protection from template output. Only disable for content you have already sanitized.",
                check: CheckType::Substring { patterns: &["autoescape=False", "autoescape: false", "autoescape=false"] },
                always_check: false,
            },
            SecurityRule {
                name: "cors_wildcard",
                tier: Tier::Warn,
                message: "CORS wildcard origin (*) allows any website to make requests. Restrict to specific trusted origins in production.",
                check: CheckType::Substring {
                    patterns: &[
                        "Access-Control-Allow-Origin: *",
                        r#"origins=["*"]"#,
                        r#"origin: "*""#,
                        r#"origin: '*'"#,
                    ],
                },
                always_check: false,
            },
            SecurityRule {
                name: "math_random_security",
                tier: Tier::Warn,
                message: "Math.random() is not cryptographically secure. Use crypto.getRandomValues() or crypto.randomUUID() for security-sensitive values (tokens, session IDs, nonces).",
                check: CheckType::Substring { patterns: &["Math.random()"] },
                always_check: false,
            },
            SecurityRule {
                name: "js_weak_crypto_hash",
                tier: Tier::Warn,
                message: "MD5/SHA1 are cryptographically broken for security purposes. Use SHA-256+ for integrity checks, bcrypt/scrypt/argon2 for passwords.",
                check: CheckType::Substring {
                    patterns: &[
                        "createHash('md5')",
                        "createHash(\"md5\")",
                        "createHash('sha1')",
                        "createHash(\"sha1\")",
                    ],
                },
                always_check: false,
            },
        ]
    })
}

/// GHA-specific content check: does the workflow content reference dangerous inputs in run: blocks?
fn has_gha_injection(content: &str) -> bool {
    static GHA_REGEX: OnceLock<Regex> = OnceLock::new();
    let re = GHA_REGEX.get_or_init(|| {
        Regex::new(r"\$\{\{\s*github\.(event\.(pull_request|issue|comment|discussion|review|review_comment|pages)\.(title|body|head\.ref|label)|head_ref|event\.head_commit\.(message|author\.(email|name)))").unwrap()
    });
    re.is_match(content)
}

/// Scan content against all rules, returning all matches.
pub fn scan_content(file_path: &str, content: &str) -> Vec<PatternMatch> {
    let all_rules = rules();
    let compiled = get_compiled_regexes(all_rules);
    let is_doc = is_doc_file(file_path);
    let is_secret = is_secret_file(file_path);
    let mut matches = Vec::new();

    for rule in all_rules {
        // Secret files (.env, .envrc) exist to hold secrets. Skip Tier 1 secret detection
        if is_secret && rule.always_check && rule.tier == Tier::Deny {
            continue;
        }

        // Skip content-based checks on doc files (unless always_check for secrets)
        let skip_content = is_doc && !rule.always_check;

        match &rule.check {
            CheckType::PathBased { path_fn }
                if path_fn(file_path) && has_gha_injection(content) =>
            {
                matches.push(PatternMatch {
                    rule_name: rule.name,
                    tier: rule.tier,
                    message: rule.message,
                });
            }
            CheckType::Substring { patterns }
                if !skip_content && patterns.iter().any(|p| content.contains(p)) =>
            {
                matches.push(PatternMatch {
                    rule_name: rule.name,
                    tier: rule.tier,
                    message: rule.message,
                });
            }
            CheckType::SubstringUnless { patterns, unless }
                if !skip_content
                    && patterns.iter().any(|p| content.contains(p))
                    && !unless.iter().any(|u| content.contains(u)) =>
            {
                matches.push(PatternMatch {
                    rule_name: rule.name,
                    tier: rule.tier,
                    message: rule.message,
                });
            }
            CheckType::ContentRegex { pattern: _ } if !skip_content => {
                if let Some((_, re)) = compiled.iter().find(|(name, _)| *name == rule.name) {
                    if re.is_match(content) {
                        matches.push(PatternMatch {
                            rule_name: rule.name,
                            tier: rule.tier,
                            message: rule.message,
                        });
                    }
                }
            }
            _ => {} // skip_content was true
        }
    }

    matches
}

/// PreToolUse: Check content for Tier 1 (deny) and Tier 3 (warn) patterns.
///
/// Tier 2 (anti-patterns) is handled by PostToolUse instead, so the write lands
/// and Claude gets a nudge to fix it. No wasted edits from re-prompting.
///
/// - Tier 1 (secrets) in source code: Always deny, never deduped
/// - Tier 1 (secrets) in doc files: skipped, handled by PostToolUse warn instead
/// - Tier 3 (informational): Allow with additionalContext, deduped per session
pub fn check_security_reminders(
    tool_name: &str,
    tool_input_map: &serde_json::Map<String, serde_json::Value>,
    config: &SecurityRemindersConfig,
    session_id: &str,
) -> Option<HookOutput> {
    if crate::models::Client::is_read_tool(tool_name) {
        return None;
    }

    let content_pairs = extract_content(tool_name, tool_input_map);
    if content_pairs.is_empty() {
        return None;
    }

    for (file_path, content) in &content_pairs {
        let matches = scan_content(file_path, content);

        for m in &matches {
            if config.disable_rules.iter().any(|r| r == m.rule_name) {
                continue;
            }

            match m.tier {
                Tier::Deny => {
                    if !config.secrets {
                        continue;
                    }
                    // Doc files get a PostToolUse nudge instead of a hard block,
                    // since docs commonly reference example keys/tokens.
                    if is_doc_file(file_path) {
                        continue;
                    }
                    return Some(HookOutput::deny_with_context(
                        &format!("Security: {}", m.rule_name),
                        m.message,
                    ));
                }
                Tier::AskOnce => {
                    // Handled by PostToolUse. Skip in PreToolUse
                    continue;
                }
                Tier::Warn => {
                    if !config.warnings {
                        continue;
                    }
                    let dedup_key = format!("warn-{}", m.rule_name);
                    if !crate::hint_tracker::is_security_warning_new(session_id, &dedup_key) {
                        continue;
                    }
                    return Some(HookOutput::allow_with_context(
                        None,
                        &format!("Security reminder: {}", m.message),
                    ));
                }
            }
        }
    }

    None
}

/// PostToolUse: Check content for Tier 2 (anti-pattern) and doc-file Tier 1 (secret)
/// matches after the write succeeds.
///
/// For Codex specifically, also emits Tier 3 (warn) findings here. Codex's
/// PreToolUse parser rejects `additionalContext`, so the warnings can't ride
/// on Pre. Without including them on Post, Codex users get strictly less
/// security feedback than Claude users on the same anti-patterns. Pass the
/// active client so the dominator knows to include Tier-3 for Codex only.
///
/// Returns `Some(PostToolUseOutput)` with additionalContext containing the security
/// warning. Claude sees this as a `<system-reminder>` and can self-correct.
/// Deduped per (file, rule) per session via hint_tracker.
pub fn check_security_reminders_post(
    tool_name: &str,
    tool_input_map: &serde_json::Map<String, serde_json::Value>,
    config: &SecurityRemindersConfig,
    session_id: &str,
    client: crate::models::Client,
) -> Option<PostToolUseOutput> {
    if crate::models::Client::is_read_tool(tool_name) {
        return None;
    }
    // Tier 3 emission depends on client; the early bail must consider it too.
    let tier3_active = client == crate::models::Client::Codex && config.warnings;
    if !config.anti_patterns && !config.secrets && !tier3_active {
        return None;
    }

    let content_pairs = extract_content(tool_name, tool_input_map);
    if content_pairs.is_empty() {
        return None;
    }

    // Collect all warnings (multiple patterns can match)
    let mut warnings = Vec::new();

    for (file_path, content) in &content_pairs {
        let matches = scan_content(file_path, content);

        for m in &matches {
            // PostToolUse handles Tier 2 (all files) + Tier 1 (doc files only).
            // For Codex, also Tier 3 (warn) since it can't ride on Pre.
            let dominated = match m.tier {
                Tier::AskOnce => !config.anti_patterns,
                Tier::Deny => {
                    if !config.secrets {
                        true
                    } else {
                        // Only handle Tier 1 here for doc files. Source code
                        // secrets are blocked by PreToolUse before reaching this point
                        !is_doc_file(file_path)
                    }
                }
                Tier::Warn => {
                    // Tier 3: Claude/Gemini handle on Pre. For Codex, emit
                    // here because additionalContext is rejected on Pre.
                    !(tier3_active)
                }
            };
            if dominated {
                continue;
            }
            if config.disable_rules.iter().any(|r| r == m.rule_name) {
                continue;
            }

            let dedup_key = format!("{}-{}", file_path, m.rule_name);
            if !crate::hint_tracker::is_security_warning_new(session_id, &dedup_key) {
                continue;
            }

            warnings.push(format!("**{}**: {}", m.rule_name, m.message));
        }
    }

    if warnings.is_empty() {
        return None;
    }

    let context = format!(
        "Security review of written content:\n\n{}",
        warnings.join("\n\n")
    );
    Some(PostToolUseOutput::with_context(&context))
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

    // --- Content extraction tests ---

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

    // --- Pattern matching tests ---

    #[test]
    fn test_tier1_aws_key_detected() {
        let content = r#"aws_key = "AKIAIOSFODNN7EXAMPLE""#;
        let matches = scan_content("/tmp/config.py", content);
        assert!(matches.iter().any(|m| m.rule_name == "hardcoded_aws_key"));
        assert!(matches.iter().any(|m| m.tier == Tier::Deny));
    }

    #[test]
    fn test_tier1_private_key_detected() {
        let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...";
        let matches = scan_content("/tmp/deploy.sh", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "hardcoded_private_key")
        );
    }

    #[test]
    fn test_tier1_github_token_detected() {
        let content = r#"token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij""#;
        let matches = scan_content("/tmp/config.ts", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "hardcoded_github_token")
        );
    }

    #[test]
    fn test_tier1_github_fine_grained_pat_detected() {
        let content = r#"token = "github_pat_11ABCDEFG0abcdefghijkl_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs""#;
        let matches = scan_content("/tmp/config.ts", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "hardcoded_github_token")
        );
    }

    #[test]
    fn test_tier1_gha_injection_detected() {
        let content = r#"
name: CI
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
"#;
        let matches = scan_content("/project/.github/workflows/ci.yml", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "github_actions_injection")
        );
    }

    #[test]
    fn test_tier1_gha_only_in_workflow_path() {
        // Same content but NOT in .github/workflows/. Should not match
        let content = r#"run: echo "${{ github.event.pull_request.title }}""#;
        let matches = scan_content("/tmp/notes.txt", content);
        assert!(
            !matches
                .iter()
                .any(|m| m.rule_name == "github_actions_injection")
        );
    }

    #[test]
    fn test_tier2_eval_detected() {
        let content = "const result = eval(userInput);";
        let matches = scan_content("/tmp/app.js", content);
        assert!(matches.iter().any(|m| m.rule_name == "eval_injection"));
        assert!(matches.iter().any(|m| m.tier == Tier::AskOnce));
    }

    #[test]
    fn test_tier2_pickle_detected() {
        let content = "data = pickle.load(open('model.pkl', 'rb'))";
        let matches = scan_content("/tmp/ml.py", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "pickle_deserialization")
        );
    }

    #[test]
    fn test_tier2_sql_injection_detected() {
        let content = r#"cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")"#;
        let matches = scan_content("/tmp/db.py", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "sql_string_interpolation")
        );
    }

    #[test]
    fn test_tier2_subprocess_shell_true() {
        let content = "subprocess.run(cmd, shell=True)";
        let matches = scan_content("/tmp/deploy.py", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "subprocess_shell_true")
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_tier2_innerHTML_detected() {
        let content = "element.innerHTML = userContent;";
        let matches = scan_content("/tmp/app.js", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "inner_html_assignment")
        );
    }

    #[test]
    fn test_tier2_dangerously_set_detected() {
        let content = r#"<div dangerouslySetInnerHTML={{__html: data}} />"#;
        let matches = scan_content("/tmp/App.tsx", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "dangerous_inner_html")
        );
    }

    #[test]
    fn test_tier2_yaml_load_unsafe() {
        let content = "data = yaml.load(f)";
        let matches = scan_content("/tmp/parser.py", content);
        assert!(matches.iter().any(|m| m.rule_name == "unsafe_yaml_load"));
    }

    #[test]
    fn test_tier2_yaml_load_safe_loader_ok() {
        let content = "data = yaml.load(f, Loader=yaml.SafeLoader)";
        let matches = scan_content("/tmp/parser.py", content);
        assert!(!matches.iter().any(|m| m.rule_name == "unsafe_yaml_load"));
    }

    #[test]
    fn test_tier3_ssl_verify_false() {
        let content = "requests.get(url, verify=False)";
        let matches = scan_content("/tmp/api.py", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "ssl_verification_disabled")
        );
        assert!(matches.iter().any(|m| m.tier == Tier::Warn));
    }

    #[test]
    fn test_tier3_chmod_777() {
        let content = "os.chmod(path, 0o777)";
        let matches = scan_content("/tmp/setup.py", content);
        assert!(matches.iter().any(|m| m.rule_name == "chmod_777"));
    }

    #[test]
    fn test_doc_files_skip_content_checks() {
        let content = "eval(dangerous_stuff); pickle.load(f); .innerHTML = x;";
        let matches = scan_content("/tmp/README.md", content);
        // Content-based rules should NOT fire on .md files
        assert!(matches.is_empty());
    }

    #[test]
    fn test_doc_files_still_get_secret_checks() {
        // Tier 1 secrets should fire even in doc files (they should never appear anywhere)
        let content = r#"Use this key: AKIAIOSFODNN7EXAMPLE"#;
        let matches = scan_content("/tmp/README.md", content);
        assert!(matches.iter().any(|m| m.rule_name == "hardcoded_aws_key"));
    }

    #[test]
    fn test_no_false_positive_on_safe_code() {
        let content = r#"
import subprocess
result = subprocess.run(["git", "status"], capture_output=True)
print(result.stdout)
"#;
        let matches = scan_content("/tmp/safe.py", content);
        assert!(
            matches.is_empty(),
            "Safe subprocess usage should not trigger: {:?}",
            matches
        );
    }

    #[test]
    fn test_generic_secret_patterns() {
        // Stripe key
        let content = r#"stripe_key = "sk-1234567890abcdefghijklmnop""#;
        let matches = scan_content("/tmp/config.py", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "hardcoded_generic_secret")
        );

        // Slack token
        let content2 = r#"slack_token = "xoxb-1234567890-abcdefgh""#;
        let matches2 = scan_content("/tmp/config.py", content2);
        assert!(
            matches2
                .iter()
                .any(|m| m.rule_name == "hardcoded_generic_secret")
        );
    }

    #[test]
    fn test_stripe_secret_key_patterns() {
        // Build test keys at runtime to avoid GitHub push protection
        let live_key = format!("stripe_key = \"sk_{}_abc123def456ghi789jkl012mno\"", "live");
        let matches = scan_content("/tmp/config.py", &live_key);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "hardcoded_generic_secret"),
            "sk_live_ key should be caught as hardcoded_generic_secret: {:?}",
            matches
        );

        let test_key = format!("stripe_key = \"sk_{}_abc123def456ghi789jkl012mno\"", "test");
        let matches2 = scan_content("/tmp/config.py", &test_key);
        assert!(
            matches2
                .iter()
                .any(|m| m.rule_name == "hardcoded_generic_secret"),
            "sk_test_ key should be caught as hardcoded_generic_secret: {:?}",
            matches2
        );
    }

    #[test]
    fn test_tier2_flask_ssti() {
        let content = "return render_template_string(user_input)";
        let matches = scan_content("/tmp/app.py", content);
        assert!(matches.iter().any(|m| m.rule_name == "flask_ssti"));
    }

    #[test]
    fn test_tier2_marshal_deserialization() {
        let content = "data = marshal.load(f)";
        let matches = scan_content("/tmp/loader.py", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "marshal_deserialization")
        );
    }

    #[test]
    fn test_tier2_shelve_deserialization() {
        let content = "db = shelve.open('data.db')";
        let matches = scan_content("/tmp/store.py", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "marshal_deserialization")
        );
    }

    #[test]
    fn test_tier2_dynamic_import() {
        let content = "mod = __import__(user_module)";
        let matches = scan_content("/tmp/plugin.py", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "python_dynamic_import")
        );
    }

    #[test]
    fn test_tier2_php_unserialize() {
        let content = "$obj = unserialize($data);";
        let matches = scan_content("/tmp/handler.php", content);
        assert!(matches.iter().any(|m| m.rule_name == "php_unserialize"));
    }

    #[test]
    fn test_tier3_vue_v_html() {
        let content = r#"<div v-html="userContent"></div>"#;
        let matches = scan_content("/tmp/Component.vue", content);
        assert!(matches.iter().any(|m| m.rule_name == "vue_v_html"));
    }

    #[test]
    fn test_tier3_autoescape_disabled_python() {
        let content = "env = Environment(autoescape=False)";
        let matches = scan_content("/tmp/app.py", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "template_autoescape_disabled")
        );
    }

    #[test]
    fn test_tier3_autoescape_disabled_yaml() {
        let content = "autoescape: false";
        let matches = scan_content("/tmp/config.yml", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "template_autoescape_disabled")
        );
    }

    // --- Public API tests ---
    //
    // NOTE: Tests that exercise dedup via check_security_reminders use unique
    // session IDs per run. The hint_tracker persists dedup state to disk
    // (~/.cache/tool-gates/hint-tracker.json), so reusing fixed session IDs
    // across cargo test invocations causes state leakage between runs.

    /// Generate a unique session ID for test isolation across runs.
    fn unique_session(base: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{base}-{nanos}")
    }

    #[test]
    fn test_check_security_reminders_deny_on_secret() {
        let map = make_map(
            r#"{"file_path": "/tmp/config.py", "content": "key = \"AKIAIOSFODNN7EXAMPLE\""}"#,
        );
        let config = SecurityRemindersConfig::default();
        let session = unique_session("deny-secret");
        let result = check_security_reminders("Write", &map, &config, &session);
        assert!(result.is_some());
        let json = serde_json::to_string(&result.unwrap().serialize(crate::models::Client::Claude))
            .unwrap();
        assert!(json.contains("deny"), "Secrets should deny: {json}");
    }

    #[test]
    fn test_tier2_skipped_in_pre_tool_use() {
        // Tier 2 patterns should NOT trigger in PreToolUse (handled by PostToolUse)
        let map = make_map(r#"{"file_path": "/tmp/app.js", "content": "eval(input)"}"#);
        let config = SecurityRemindersConfig::default();
        let session = unique_session("pre-skip");
        let result = check_security_reminders("Write", &map, &config, &session);
        assert!(result.is_none(), "Tier 2 should be skipped in PreToolUse");
    }

    #[test]
    fn test_post_tool_use_catches_tier2() {
        let session = unique_session("post-eval");
        let path = format!("/tmp/post-eval-{}.js", session);
        let json_str = format!(r#"{{"file_path": "{path}", "content": "eval(input)"}}"#);
        let map = make_map(&json_str);
        let config = SecurityRemindersConfig::default();
        let result = check_security_reminders_post(
            "Write",
            &map,
            &config,
            &session,
            crate::models::Client::Claude,
        );
        assert!(result.is_some(), "PostToolUse should catch eval");
        let json = serde_json::to_string(&result.unwrap()).unwrap();
        assert!(
            json.contains("additionalContext"),
            "Should have context: {json}"
        );
        assert!(
            json.contains("eval_injection"),
            "Should mention eval: {json}"
        );
    }

    #[test]
    fn test_post_tool_use_dedup() {
        let session = unique_session("post-dedup");
        let path = format!("/tmp/post-dedup-{}.js", session);
        let json_str = format!(r#"{{"file_path": "{path}", "content": "eval(input)"}}"#);
        let map = make_map(&json_str);
        let config = SecurityRemindersConfig::default();

        let r1 = check_security_reminders_post(
            "Write",
            &map,
            &config,
            &session,
            crate::models::Client::Claude,
        );
        assert!(r1.is_some(), "First PostToolUse call should warn");

        let r2 = check_security_reminders_post(
            "Write",
            &map,
            &config,
            &session,
            crate::models::Client::Claude,
        );
        assert!(r2.is_none(), "Second call should be deduped");
    }

    #[test]
    fn test_post_tool_use_collects_multiple_warnings() {
        let session = unique_session("post-multi");
        let path = format!("/tmp/post-multi-{}.js", session);
        let json_str = format!(
            r#"{{"file_path": "{path}", "content": "eval(input); document.write(html);"}}"#
        );
        let map = make_map(&json_str);
        let config = SecurityRemindersConfig::default();
        let result = check_security_reminders_post(
            "Write",
            &map,
            &config,
            &session,
            crate::models::Client::Claude,
        );
        assert!(result.is_some());
        let json = serde_json::to_string(&result.unwrap()).unwrap();
        assert!(json.contains("eval_injection"), "Should have eval: {json}");
        assert!(
            json.contains("document_write_xss"),
            "Should have document.write: {json}"
        );
    }

    #[test]
    fn test_post_tool_use_ignores_tier1_and_tier3() {
        // Tier 1 secrets and Tier 3 warns should NOT appear in PostToolUse
        let map = make_map(
            r#"{"file_path": "/tmp/api.py", "content": "requests.get(url, verify=False)"}"#,
        );
        let config = SecurityRemindersConfig::default();
        let session = unique_session("post-tier3");
        let result = check_security_reminders_post(
            "Write",
            &map,
            &config,
            &session,
            crate::models::Client::Claude,
        );
        assert!(result.is_none(), "Tier 3 should not fire in PostToolUse");
    }

    #[test]
    fn test_post_tool_use_disabled_rule() {
        let map = make_map(r#"{"file_path": "/tmp/app.js", "content": "eval(input)"}"#);
        let config = SecurityRemindersConfig {
            disable_rules: vec!["eval_injection".to_string()],
            ..Default::default()
        };
        let session = unique_session("post-disabled");
        let result = check_security_reminders_post(
            "Write",
            &map,
            &config,
            &session,
            crate::models::Client::Claude,
        );
        assert!(
            result.is_none(),
            "Disabled rule should not fire in PostToolUse"
        );
    }

    #[test]
    fn test_tier3_produces_allow_with_context() {
        // Test the scan_content output directly (no global tracker involvement)
        let content = "requests.get(url, verify=False)";
        let matches = scan_content("/tmp/api.py", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "ssl_verification_disabled" && m.tier == Tier::Warn),
            "Should detect SSL verification disabled as Warn tier"
        );
    }

    #[test]
    fn test_check_security_reminders_disabled_tier1_skipped() {
        let map = make_map(
            r#"{"file_path": "/tmp/config.py", "content": "key = \"AKIAIOSFODNN7EXAMPLE\""}"#,
        );
        let config = SecurityRemindersConfig {
            disable_rules: vec!["hardcoded_aws_key".to_string()],
            ..Default::default()
        };
        let session = unique_session("disabled");
        let result = check_security_reminders("Write", &map, &config, &session);
        assert!(result.is_none(), "Disabled Tier 1 rule should not fire");
    }

    #[test]
    fn test_check_security_reminders_safe_content_passes() {
        let map = make_map(r#"{"file_path": "/tmp/app.ts", "content": "const x = 1 + 2;"}"#);
        let config = SecurityRemindersConfig::default();
        let session = unique_session("safe");
        let result = check_security_reminders("Write", &map, &config, &session);
        assert!(result.is_none());
    }

    #[test]
    fn test_check_security_reminders_read_skipped() {
        let map = make_map(r#"{"file_path": "/tmp/config.py", "content": "AKIAIOSFODNN7EXAMPLE"}"#);
        let config = SecurityRemindersConfig::default();
        let session = unique_session("read");
        let result = check_security_reminders("Read", &map, &config, &session);
        assert!(result.is_none(), "Read tool should be skipped entirely");
    }

    #[test]
    fn test_tier1_secrets_never_deduped() {
        let map = make_map(r#"{"file_path": "/tmp/config.py", "content": "AKIAIOSFODNN7EXAMPLE"}"#);
        let config = SecurityRemindersConfig::default();
        let session = unique_session("secret-dedup");

        let r1 = check_security_reminders("Write", &map, &config, &session);
        assert!(r1.is_some(), "First secret call should deny");

        let r2 = check_security_reminders("Write", &map, &config, &session);
        assert!(
            r2.is_some(),
            "Second secret call should ALSO deny (never deduped)"
        );
    }
}

#[cfg(test)]
mod new_tests {
    use super::*;

    // --- Secret file (.env) tests ---

    #[test]
    fn test_env_file_allows_secrets() {
        let content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let matches = scan_content("/project/.env", content);
        assert!(
            !matches.iter().any(|m| m.rule_name == "hardcoded_aws_key"),
            ".env files should not trigger secret detection"
        );
    }

    #[test]
    fn test_env_local_allows_secrets() {
        let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...";
        let matches = scan_content("/project/.env.local", content);
        assert!(
            !matches
                .iter()
                .any(|m| m.rule_name == "hardcoded_private_key"),
            ".env.local should not trigger secret detection"
        );
    }

    #[test]
    fn test_envrc_allows_secrets() {
        let content = "export GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let matches = scan_content("/project/.envrc", content);
        assert!(
            !matches
                .iter()
                .any(|m| m.rule_name == "hardcoded_github_token"),
            ".envrc should not trigger secret detection"
        );
    }

    #[test]
    fn test_env_production_allows_secrets() {
        let content = "STRIPE_KEY=sk-1234567890abcdefghijklmnop";
        let matches = scan_content("/project/.env.production", content);
        assert!(
            !matches
                .iter()
                .any(|m| m.rule_name == "hardcoded_generic_secret"),
            ".env.production should not trigger secret detection"
        );
    }

    #[test]
    fn test_env_still_gets_non_secret_checks() {
        let content = "eval(something)";
        let matches = scan_content("/project/.env", content);
        assert!(
            matches.iter().any(|m| m.rule_name == "eval_injection"),
            "Non-secret checks should still fire on .env files"
        );
    }

    #[test]
    fn test_non_env_still_blocks_secrets() {
        let content = "key = \"AKIAIOSFODNN7EXAMPLE\"";
        let matches = scan_content("/project/config.py", content);
        assert!(
            matches.iter().any(|m| m.rule_name == "hardcoded_aws_key"),
            "Regular files should still detect secrets"
        );
    }

    // --- New Tier 3 pattern tests ---

    #[test]
    fn test_tier3_math_random() {
        let content = "const token = Math.random().toString(36);";
        let matches = scan_content("/tmp/auth.js", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "math_random_security" && m.tier == Tier::Warn),
            "Math.random() should trigger warn"
        );
    }

    #[test]
    fn test_tier3_js_weak_crypto_md5() {
        let content = "const hash = crypto.createHash('md5').update(data).digest('hex');";
        let matches = scan_content("/tmp/utils.js", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "js_weak_crypto_hash" && m.tier == Tier::Warn),
            "createHash('md5') should trigger warn"
        );
    }

    #[test]
    fn test_tier3_js_weak_crypto_sha1_double_quotes() {
        let content = "const hash = crypto.createHash(\"sha1\").update(data).digest('hex');";
        let matches = scan_content("/tmp/utils.ts", content);
        assert!(
            matches.iter().any(|m| m.rule_name == "js_weak_crypto_hash"),
            "createHash(\"sha1\") should trigger warn"
        );
    }

    #[test]
    fn test_tier3_js_strong_crypto_no_match() {
        let content = "const hash = crypto.createHash('sha256').update(data).digest('hex');";
        let matches = scan_content("/tmp/utils.js", content);
        assert!(
            !matches.iter().any(|m| m.rule_name == "js_weak_crypto_hash"),
            "createHash('sha256') should NOT trigger"
        );
    }
}

#[cfg(test)]
mod coverage_gap_tests {
    use super::*;

    // Construct sensitive test strings at runtime so the literal patterns
    // don't appear in source (tool-gates blocks edits containing them).
    fn fake_aws_content() -> String {
        format!("AWS_ACCESS_KEY_ID=AKI{}OSFODNN7EXAMPLE", "AI")
    }
    fn fake_private_key_content() -> String {
        format!("-----BEGIN RSA PRIVAT{} KEY-----\nMIIE...", "E")
    }
    fn fake_gh_token_content() -> String {
        format!(
            "export GITHUB_TOKEN=gh{}ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
            "p_"
        )
    }

    fn make_map(json: &str) -> serde_json::Map<String, serde_json::Value> {
        match serde_json::from_str::<serde_json::Value>(json).unwrap() {
            serde_json::Value::Object(m) => m,
            _ => panic!("expected object"),
        }
    }

    fn unique_session(base: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{base}-{nanos}")
    }

    // ========================================================================
    // is_secret_file() edge cases
    // ========================================================================

    #[test]
    fn test_secret_file_windows_backslash_path() {
        let content = fake_aws_content();
        let matches = scan_content("C:\\Users\\dev\\project\\.env", &content);
        assert!(
            !matches.iter().any(|m| m.rule_name == "hardcoded_aws_key"),
            "Windows backslash path to .env should skip Tier 1"
        );
    }

    #[test]
    fn test_secret_file_bare_env_no_directory() {
        let content = fake_aws_content();
        let matches = scan_content(".env", &content);
        assert!(
            !matches.iter().any(|m| m.rule_name == "hardcoded_aws_key"),
            "Bare .env (no directory) should skip Tier 1"
        );
    }

    #[test]
    fn test_secret_file_uppercase_env() {
        let content = fake_aws_content();
        let matches = scan_content("/project/.ENV", &content);
        assert!(
            !matches.iter().any(|m| m.rule_name == "hardcoded_aws_key"),
            "Uppercase .ENV should skip Tier 1 (case-insensitive)"
        );
    }

    #[test]
    fn test_secret_file_mixed_case_env_local() {
        let content = fake_private_key_content();
        let matches = scan_content("/project/.Env.Local", &content);
        assert!(
            !matches
                .iter()
                .any(|m| m.rule_name == "hardcoded_private_key"),
            "Mixed case .Env.Local should skip Tier 1"
        );
    }

    #[test]
    fn test_not_secret_file_similar_name_not_env() {
        let content = fake_aws_content();
        let matches = scan_content("/project/not.env", &content);
        assert!(
            matches.iter().any(|m| m.rule_name == "hardcoded_aws_key"),
            "not.env is not a secret file. Tier 1 should fire"
        );
    }

    #[test]
    fn test_not_secret_file_envrc_suffix() {
        let content = fake_gh_token_content();
        let matches = scan_content("/project/myapp.envrc", &content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "hardcoded_github_token"),
            "myapp.envrc is not a secret file. Tier 1 should fire"
        );
    }

    #[test]
    fn test_not_secret_file_bare_env_without_dot() {
        let content = fake_aws_content();
        let matches = scan_content("/project/env", &content);
        assert!(
            matches.iter().any(|m| m.rule_name == "hardcoded_aws_key"),
            "'env' without dot prefix is not a secret file"
        );
    }

    #[test]
    fn test_not_secret_file_env_directory_child() {
        let content = fake_aws_content();
        let matches = scan_content("/project/.env/config.py", &content);
        assert!(
            matches.iter().any(|m| m.rule_name == "hardcoded_aws_key"),
            "config.py inside .env/ directory is not a secret file"
        );
    }

    // ========================================================================
    // Public API integration with .env skip
    // ========================================================================

    #[test]
    fn test_check_security_reminders_env_file_no_deny() {
        let key = format!("AKI{}OSFODNN7EXAMPLE", "AI");
        let json_str = format!(r#"{{"file_path": "/project/.env", "content": "AWS_KEY={key}"}}"#);
        let map = make_map(&json_str);
        let config = SecurityRemindersConfig::default();
        let session = unique_session("env-no-deny");
        let result = check_security_reminders("Write", &map, &config, &session);
        assert!(
            result.is_none(),
            "Writing secrets to .env should not deny: {result:?}"
        );
    }

    #[test]
    fn test_check_security_reminders_post_env_file_tier2_still_fires() {
        let session = unique_session("env-post-tier2");
        let path = format!("/project/.env.{session}");
        let json_str = format!(r#"{{"file_path": "{path}", "content": "eval(something)"}}"#);
        let map = make_map(&json_str);
        let config = SecurityRemindersConfig::default();
        let result = check_security_reminders_post(
            "Write",
            &map,
            &config,
            &session,
            crate::models::Client::Claude,
        );
        assert!(
            result.is_some(),
            "Tier 2 should still fire on .env in PostToolUse"
        );
    }

    #[test]
    fn test_check_security_reminders_env_file_tier3_still_fires() {
        // Test via scan_content directly to avoid global dedup tracker state.
        // The full check_security_reminders path deduplicates Tier 3 warnings
        // per rule name globally, so this test verifies the rule matches .env files.
        let matches = scan_content("/project/.env", "Math.random()");
        assert!(
            matches.iter().any(|m| m.tier == Tier::Warn),
            "Tier 3 warns should still fire on .env files"
        );
    }

    // ========================================================================
    // Additional Tier 3 negative tests
    // ========================================================================

    #[test]
    fn test_math_random_no_parens_no_match() {
        let content = "// Don't use Math.random for crypto";
        let matches = scan_content("/tmp/notes.js", content);
        assert!(
            !matches
                .iter()
                .any(|m| m.rule_name == "math_random_security"),
            "Math.random without parens should not trigger"
        );
    }

    #[test]
    fn test_crypto_get_random_values_no_match() {
        let content = "const arr = crypto.getRandomValues(new Uint8Array(16));";
        let matches = scan_content("/tmp/auth.js", content);
        assert!(
            !matches
                .iter()
                .any(|m| m.rule_name == "math_random_security"),
            "crypto.getRandomValues should not trigger math_random_security"
        );
    }

    #[test]
    fn test_weak_crypto_sha1_single_quotes() {
        let content = "const hash = crypto.createHash('sha1').update(data).digest('hex');";
        let matches = scan_content("/tmp/utils.js", content);
        assert!(
            matches.iter().any(|m| m.rule_name == "js_weak_crypto_hash"),
            "createHash('sha1') with single quotes should trigger"
        );
    }

    #[test]
    fn test_weak_crypto_md5_double_quotes() {
        let content = r#"const hash = crypto.createHash("md5").update(data).digest('hex');"#;
        let matches = scan_content("/tmp/utils.js", content);
        assert!(
            matches.iter().any(|m| m.rule_name == "js_weak_crypto_hash"),
            r#"createHash("md5") with double quotes should trigger"#
        );
    }

    #[test]
    fn test_strong_crypto_sha384_no_match() {
        let content = "const hash = crypto.createHash('sha384').update(data).digest('hex');";
        let matches = scan_content("/tmp/utils.js", content);
        assert!(
            !matches.iter().any(|m| m.rule_name == "js_weak_crypto_hash"),
            "createHash('sha384') should NOT trigger"
        );
    }

    #[test]
    fn test_strong_crypto_sha512_no_match() {
        let content = "const hash = crypto.createHash('sha512').update(data).digest('hex');";
        let matches = scan_content("/tmp/utils.js", content);
        assert!(
            !matches.iter().any(|m| m.rule_name == "js_weak_crypto_hash"),
            "createHash('sha512') should NOT trigger"
        );
    }
}

#[cfg(test)]
mod template_file_tests {
    use super::*;

    fn fake_aws_content() -> String {
        format!("AWS_ACCESS_KEY_ID=AKI{}OSFODNN7EXAMPLE", "AI")
    }

    #[test]
    fn test_env_example_still_blocks_secrets() {
        let content = fake_aws_content();
        let matches = scan_content("/project/.env.example", &content);
        assert!(
            matches.iter().any(|m| m.rule_name == "hardcoded_aws_key"),
            ".env.example is a template. Secrets should still be detected"
        );
    }

    #[test]
    fn test_env_sample_still_blocks_secrets() {
        let content = fake_aws_content();
        let matches = scan_content("/project/.env.sample", &content);
        assert!(
            matches.iter().any(|m| m.rule_name == "hardcoded_aws_key"),
            ".env.sample is a template. Secrets should still be detected"
        );
    }

    #[test]
    fn test_env_template_still_blocks_secrets() {
        let content = fake_aws_content();
        let matches = scan_content("/project/.env.template", &content);
        assert!(
            matches.iter().any(|m| m.rule_name == "hardcoded_aws_key"),
            ".env.template is a template. Secrets should still be detected"
        );
    }

    #[test]
    fn test_env_dist_still_blocks_secrets() {
        let content = fake_aws_content();
        let matches = scan_content("/project/.env.dist", &content);
        assert!(
            matches.iter().any(|m| m.rule_name == "hardcoded_aws_key"),
            ".env.dist is a template. Secrets should still be detected"
        );
    }

    #[test]
    fn test_env_local_still_skips_secrets() {
        let content = fake_aws_content();
        let matches = scan_content("/project/.env.local", &content);
        assert!(
            !matches.iter().any(|m| m.rule_name == "hardcoded_aws_key"),
            ".env.local is a real secret file. Should skip Tier 1"
        );
    }

    #[test]
    fn test_env_production_still_skips_secrets() {
        let content = fake_aws_content();
        let matches = scan_content("/project/.env.production", &content);
        assert!(
            !matches.iter().any(|m| m.rule_name == "hardcoded_aws_key"),
            ".env.production is a real secret file. Should skip Tier 1"
        );
    }
}

#[cfg(test)]
mod doc_file_secret_tests {
    use super::*;

    fn fake_aws_content() -> String {
        format!("Use this key: AKI{}OSFODNN7EXAMPLE", "AI")
    }

    fn make_map(json: &str) -> serde_json::Map<String, serde_json::Value> {
        match serde_json::from_str::<serde_json::Value>(json).unwrap() {
            serde_json::Value::Object(m) => m,
            _ => panic!("expected object"),
        }
    }

    fn unique_session(base: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{base}-{nanos}")
    }

    #[test]
    fn test_pre_tool_use_skips_tier1_for_doc_files() {
        let content = fake_aws_content();
        let json_str = format!(r#"{{"file_path": "/project/README.md", "content": "{content}"}}"#);
        let map = make_map(&json_str);
        let config = SecurityRemindersConfig::default();
        let session = unique_session("doc-pre-skip");
        let result = check_security_reminders("Write", &map, &config, &session);
        assert!(
            result.is_none(),
            "PreToolUse should NOT deny secrets in doc files: {result:?}"
        );
    }

    #[test]
    fn test_post_tool_use_warns_tier1_for_doc_files() {
        let content = fake_aws_content();
        let session = unique_session("doc-post-warn");
        let path = format!("/project/README-{session}.md");
        let json_str = format!(r#"{{"file_path": "{path}", "content": "{content}"}}"#);
        let map = make_map(&json_str);
        let config = SecurityRemindersConfig::default();
        let result = check_security_reminders_post(
            "Write",
            &map,
            &config,
            &session,
            crate::models::Client::Claude,
        );
        assert!(
            result.is_some(),
            "PostToolUse should warn about secrets in doc files"
        );
        let json = serde_json::to_string(&result.unwrap()).unwrap();
        assert!(
            json.contains("hardcoded_aws_key"),
            "Should mention the rule name: {json}"
        );
    }

    #[test]
    fn test_pre_tool_use_still_denies_tier1_for_source() {
        let content = fake_aws_content();
        let json_str = format!(r#"{{"file_path": "/project/config.py", "content": "{content}"}}"#);
        let map = make_map(&json_str);
        let config = SecurityRemindersConfig::default();
        let session = unique_session("source-deny");
        let result = check_security_reminders("Write", &map, &config, &session);
        assert!(
            result.is_some(),
            "PreToolUse should still deny secrets in source files"
        );
        let json = serde_json::to_string(&result.unwrap().serialize(crate::models::Client::Claude))
            .unwrap();
        assert!(json.contains("deny"), "Should be a deny: {json}");
    }

    #[test]
    fn test_post_tool_use_skips_tier1_for_source() {
        let content = fake_aws_content();
        let json_str = format!(r#"{{"file_path": "/project/config.py", "content": "{content}"}}"#);
        let map = make_map(&json_str);
        let config = SecurityRemindersConfig::default();
        let session = unique_session("source-post-skip");
        let result = check_security_reminders_post(
            "Write",
            &map,
            &config,
            &session,
            crate::models::Client::Claude,
        );
        assert!(
            result.is_none(),
            "PostToolUse should NOT warn about secrets in source files (PreToolUse blocks them)"
        );
    }

    #[test]
    fn test_doc_file_secret_warn_deduped() {
        let content = fake_aws_content();
        let session = unique_session("doc-dedup");
        let path = format!("/project/docs-{session}.txt");
        let json_str = format!(r#"{{"file_path": "{path}", "content": "{content}"}}"#);
        let map = make_map(&json_str);
        let config = SecurityRemindersConfig::default();

        let r1 = check_security_reminders_post(
            "Write",
            &map,
            &config,
            &session,
            crate::models::Client::Claude,
        );
        assert!(r1.is_some(), "First doc secret should warn");

        let r2 = check_security_reminders_post(
            "Write",
            &map,
            &config,
            &session,
            crate::models::Client::Claude,
        );
        assert!(r2.is_none(), "Second doc secret should be deduped");
    }

    #[test]
    fn test_html_doc_file_secret_warns_not_denies() {
        let content = fake_aws_content();
        let session = unique_session("html-doc");
        let path = format!("/project/guide-{session}.html");
        let json_str = format!(r#"{{"file_path": "{path}", "content": "{content}"}}"#);
        let map = make_map(&json_str);
        let config = SecurityRemindersConfig::default();
        let pre = check_security_reminders("Write", &map, &config, &session);
        assert!(pre.is_none(), "PreToolUse should skip for .html doc files");

        let post = check_security_reminders_post(
            "Write",
            &map,
            &config,
            &session,
            crate::models::Client::Claude,
        );
        assert!(
            post.is_some(),
            "PostToolUse should warn for .html doc files"
        );
    }
}

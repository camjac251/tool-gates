//! Head/tail (and sed/awk/rg) output-truncation pipe blocking: a
//! producer-aware hard-deny steering callers to source-native output caps.

use crate::models::HookOutput;
use crate::security_floor::{strip_comments, strip_quoted_strings};
use regex::Regex;
use std::sync::LazyLock;

/// `| head` / `| tail` pipe pattern (hard deny).
/// Captures the offending segment up to the next pipe/and/or/semicolon/newline boundary so
/// the deny message can echo just the triggering pipe instead of every subsequent line
/// of a multi-line script. Streaming `tail -f` / `-F` is handled by a secondary check
/// before denying. The optional `&` after `|` catches bash's stderr-combining `|&` form
/// (equivalent to `2>&1 |`) so it can't bypass the rule.
static HEAD_TAIL_PIPE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\|&?\s*(head|tail)\b[^|&;\n]*").expect("HEAD_TAIL_PIPE_RE must compile")
});

/// Streaming-tail exception: `| tail -f` / `| tail -F` (and the `|&` variant)
/// watches a growing file. Legitimate through the Monitor tool, so not denied.
static TAIL_STREAM_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\|&?\s*tail\s+-[fF]\b").expect("TAIL_STREAM_RE must compile"));

/// `| sed`/`| awk` first-N truncation pipe, the backstop sibling of head/tail.
/// Captures the offending pipe segment up to the next boundary. Matches the
/// FROM-THE-TOP forms only: `sed -n '1,Np'`, `sed -n 'Nq'`/`sed Nq`, bare
/// `sed -n Np` (single early line), and `awk 'NR<=N'` / `awk 'NR==N'` /
/// `awk 'FNR<=N'`. A mid-file range read like `sed -n '2000,2050p'` starts
/// above line 1 and is NOT matched (it is a line-range view, not a cap).
static SED_AWK_TRUNC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\|&?\s*(?:sed\s+(?:-n\s+)?'?(?:1\s*,\s*\d+\s*p|\d+\s*q)|awk\s+'?(?:F?NR\s*(?:<=|==)\s*\d+))[^|&;\n]*"#,
    )
    .expect("SED_AWK_TRUNC_RE must compile")
});

/// `| rg .` / `| rg -m N .` bare-catch-all "fake filter", the backstop sibling
/// of head/tail. The agent pipes to rg with a match-anything pattern purely to
/// cap volume, which silently drops everything past the cap. Matches ONLY the
/// catch-all forms (`.`, `.*`, `''`, `""`, `'.'`, `'.*'`) after optional flags
/// (incl. `-m N`), anchored to the end of the pipe segment. Pure `-c` /
/// `--count` output is exempted below because it consumes the complete stream.
/// A real content filter like `rg 'FAILED'`, `rg error`, or `rg -m 5 '.rs'` is
/// NOT matched, so legitimate filtering is untouched; only the no-op pattern
/// is caught.
static RG_COUNTER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\|&?\s*rg\s+(?:-{1,2}[A-Za-z-]+\s+(?:\d+\s+)?)*(?:\.|\.\*|''|""|'\.'|'\.\*'|"\."|"\.\*")\s*(?:$|[|;&])"#,
    )
    .expect("RG_COUNTER_RE must compile")
});

/// Full-stream count output is aggregation, not truncation. This exception is
/// intentionally limited to a lone count flag followed by a catch-all pattern.
/// Combining count output with `-m` / `--max-count` remains denied.
static RG_FULL_COUNT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^\|&?\s*rg\s+(?:-c|--count(?:-matches)?)\s+(?:\.|\.\*|''|""|'\.'|'\.\*'|"\."|"\.\*")\s*(?:$|[|;&])"#,
    )
    .expect("RG_FULL_COUNT_RE must compile")
});

/// Hard-deny raw-string patterns: no ask tier, no settings override, no mode carve-out.
///
/// These patterns have no legitimate shell use because tool-gates (and its host
/// harness) already expose safer alternatives. Toggle off via
/// `[features] head_tail_pipe_block = false` in `~/.config/tool-gates/config.toml`
/// for users who want the old ask-or-allow behavior.
pub(crate) fn check_hard_deny_patterns(command_string: &str) -> Option<HookOutput> {
    check_hard_deny_patterns_with_features(command_string, &crate::config::get().features)
}

/// Feature-injected variant of `check_hard_deny_patterns`. Lets tests exercise
/// the toggle path without touching the process-global `OnceLock<Config>`.
pub(crate) fn check_hard_deny_patterns_with_features(
    command_string: &str,
    features: &crate::config::Features,
) -> Option<HookOutput> {
    if features.head_tail_pipe_block {
        if let Some(output) = check_head_tail_pipe(command_string) {
            return Some(output);
        }
    }

    None
}

/// Build/test/package-manager producers whose piped output carries diagnostics
/// that head/tail would truncate away. Used only to tailor the deny *message*;
/// the deny decision is producer-agnostic (deny-by-default), so a build tool
/// missing from this list still denies, just with the neutral message.
const BUILD_PRODUCERS: &[&str] = &[
    "mise", "cargo", "npm", "pnpm", "bun", "yarn", "go", "make", "ninja", "ctest", "gradle",
    "gradlew", "mvn", "mvnw", "tsc", "deno", "uv", "pip", "pip3", "poetry", "pytest", "jest",
    "vitest", "tox", "rake", "rspec",
];

/// Launcher wrappers that prefix the real command (`timeout 60 npm test`,
/// `nice -n10 cargo build`, `sudo make`). Producer detection sees through them
/// so a wrapped build/`gh` is still hard-denied, not mistaken for the wrapper.
const PRODUCER_WRAPPERS: &[&str] = &[
    "timeout", "nice", "nohup", "stdbuf", "time", "command", "setsid", "ionice", "chrt",
    "unbuffer", "sudo", "doas", "env",
];

/// Normalize a token to a bare program name: strip a leading `(` and any path
/// prefix, so `/usr/bin/sort` and `./gradlew` reduce to `sort` / `gradlew`.
fn normalize_token(tok: &str) -> &str {
    let t = tok.trim_start_matches('(');
    t.rsplit('/').next().unwrap_or(t)
}

/// True for a token that is a leading `VAR=value` env assignment or a
/// redirection operator, neither of which is the command program.
fn is_assignment_or_redirect(tok: &str) -> bool {
    if let Some((key, _)) = tok.split_once('=') {
        if !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return true;
        }
    }
    tok.starts_with('>') || tok.starts_with('<') || tok.starts_with("2>") || tok.starts_with("&>")
}

/// First real program word of a pipe stage (skips leading assignments and
/// redirections). Does not see through wrappers; used for the `prior` stage
/// (sort detection), where wrapping is irrelevant.
fn stage_program(stage: &str) -> String {
    for tok in stage.split_whitespace() {
        if tok.trim_start_matches('(').is_empty() || is_assignment_or_redirect(tok) {
            continue;
        }
        return normalize_token(tok).to_string();
    }
    String::new()
}

/// Effective producer of a pipe stage: like `stage_program` but skips leading
/// launcher wrappers and their option / duration args, so `timeout 60 npm test`
/// resolves to `npm` and `nice -n10 cargo build` to `cargo`.
fn effective_producer(stage: &str) -> String {
    let mut toks = stage.split_whitespace().peekable();
    while let Some(tok) = toks.next() {
        if tok.trim_start_matches('(').is_empty() || is_assignment_or_redirect(tok) {
            continue;
        }
        let base = normalize_token(tok);
        if PRODUCER_WRAPPERS.contains(&base) {
            // Consume the wrapper's option flags and a single numeric/duration
            // arg (e.g. `timeout 60`, `nice -n 10`), then fall through to the
            // real producer on the next iteration.
            while let Some(next) = toks.peek() {
                let starts_digit = next.chars().next().is_some_and(|c| c.is_ascii_digit());
                if next.starts_with('-') || starts_digit {
                    toks.next();
                } else {
                    break;
                }
            }
            continue;
        }
        return base.to_string();
    }
    String::new()
}

/// True when the byte at `offset` lies inside a `$(...)` or backtick command
/// substitution. head/tail there feeds a variable (e.g.
/// `newest=$(... | sort -V | tail -1)`), not the model's context window.
fn inside_command_substitution(unquoted: &str, offset: usize) -> bool {
    let bytes = unquoted.as_bytes();
    let mut depth: i32 = 0;
    let mut backtick = false;
    let mut i = 0;
    while i < offset && i < bytes.len() {
        match bytes[i] {
            b'`' => backtick = !backtick,
            b'$' if i + 1 < bytes.len() && bytes[i + 1] == b'(' => {
                depth += 1;
                i += 2;
                continue;
            }
            b')' if depth > 0 => depth -= 1,
            _ => {}
        }
        i += 1;
    }
    depth > 0 || backtick
}

/// Producer (first stage) and the program of the stage immediately feeding the
/// head/tail at `offset`, within the enclosing statement (bounded by `;`,
/// `&&`, `||`, `(`, newline). Operates on the quote-stripped string, so every
/// boundary char is ASCII and byte offsets are valid char boundaries.
fn pipeline_context(unquoted: &str, offset: usize) -> (String, Option<String>) {
    let bytes = unquoted.as_bytes();
    let mut stmt_start = 0usize;
    let mut i = offset;
    while i > 0 {
        i -= 1;
        let c = bytes[i];
        if c == b'\n' || c == b';' || c == b'(' {
            stmt_start = i + 1;
            break;
        }
        if c == b'&' && i > 0 && bytes[i - 1] == b'&' {
            stmt_start = i + 1;
            break;
        }
        if c == b'|' && i > 0 && bytes[i - 1] == b'|' {
            stmt_start = i + 1;
            break;
        }
    }
    let head = &unquoted[stmt_start..offset];
    let stages: Vec<&str> = head.split('|').filter(|s| !s.trim().is_empty()).collect();
    let producer = stages
        .first()
        .map(|s| effective_producer(s))
        .unwrap_or_default();
    let prior = stages.last().map(|s| stage_program(s));
    (producer, prior)
}

/// Deny message for a non-exempt truncation cap. Always producer-native: never
/// references `max_output` / `output_tail`, which are not stock Bash tool
/// params (a public tool-gates install may not be on a patched build). The
/// producer only selects the wording: `gh` and build/test runners get tailored
/// guidance; every other producer gets the neutral cap-at-the-source message.
fn head_tail_message(producer: &str, segment: &str) -> String {
    let trimmed = segment.trim();
    if producer == "gh" {
        return format!(
            "`{trimmed}` blocked: this consumer-side cap truncates `gh` output and can drop rows or \
             cut JSON. Keep the full response; if the task needs a subset, use `gh`'s native options."
        );
    }
    if BUILD_PRODUCERS.contains(&producer) {
        return format!(
            "`{trimmed}` blocked: this consumer-side cap truncates `{producer}` output and can hide \
             diagnostics. Run it uncapped; if the task needs matching lines, filter by a real pattern \
             without limiting the stream."
        );
    }
    // Any other producer (ls, fd, rg, find, git log, cat, custom scripts).
    format!(
        "`{trimmed}` blocked: a consumer-side cap truncates unseen output. If the task needs a bounded \
         result, use the producer's native limit; otherwise run uncapped and inspect the persisted \
         output. Use Read or a bat range for files."
    )
}

/// Decide head/tail-pipe handling. Three exemptions pass through silently:
/// streaming `tail -f`/`-F`; top-N `... | sort ... | head/tail -N` (sort must
/// consume all input, so the slice is the selection, not a cap); and head/tail
/// inside `$(...)` / backticks (a programmatic pick feeding a variable). Every
/// other non-exempt cap is denied regardless of producer; the producer only
/// selects the deny message (build/`gh` get tailored wording).
fn check_head_tail_pipe(command_string: &str) -> Option<HookOutput> {
    // Strip comments and quoted strings so `rg 'foo | head bar' file.txt` is safe.
    let stripped = strip_comments(command_string);
    let unquoted = strip_quoted_strings(&stripped);

    if !unquoted.contains('|') {
        return None;
    }

    for cap in HEAD_TAIL_PIPE_RE.find_iter(&unquoted) {
        let segment = cap.as_str();
        // Streaming tail -f/-F: log watching via the Monitor tool.
        if TAIL_STREAM_RE.is_match(segment) {
            continue;
        }
        let offset = cap.start();
        // Programmatic pick inside $() / backticks: feeds a variable, not output.
        if inside_command_substitution(&unquoted, offset) {
            continue;
        }
        // Top-N ranking: `... | sort ... | head/tail -N`.
        let (producer, prior) = pipeline_context(&unquoted, offset);
        if prior.as_deref() == Some("sort") {
            continue;
        }
        // Every non-exempt cap is denied; `producer` only selects the message.
        return Some(HookOutput::deny(&head_tail_message(&producer, segment)));
    }

    // Backstop: `| sed -n '1,Np'` / `| awk 'NR<=N'` first-N truncation, denied
    // for every producer (mirrors head/tail). Mid-file range reads like
    // `sed -n '2000,2050p'` don't match SED_AWK_TRUNC_RE, so file viewing is
    // unaffected.
    //
    // The sed/awk SCRIPT is quoted (`'1,40p'`), so `unquoted` has blanked it to
    // `_`. Scan `comment_stripped` (quotes intact) for the script content.
    // `strip_quoted_strings` is length-preserving, so a match offset is valid in
    // both strings; reuse it for the producer/substitution/sort checks against
    // `unquoted`. Guard: the matched `sed`/`awk` keyword must be un-blanked in
    // `unquoted` (a real pipe stage), else it's literal text inside a quote
    // (e.g. `rg 'foo | sed -n 1,5p'`) and must not fire.
    for cap in SED_AWK_TRUNC_RE.find_iter(&stripped) {
        let offset = cap.start();
        let end = cap.end().min(unquoted.len());
        // `cap` was found in `stripped`; `strip_quoted_strings` is char- but not
        // byte-length preserving, so a multibyte char inside quotes shifts these
        // offsets away from `unquoted`. Skip the cap instead of panicking.
        let Some(unquoted_span) = unquoted.get(offset..end) else {
            continue;
        };
        if !unquoted_span.contains("sed") && !unquoted_span.contains("awk") {
            continue; // keyword was inside a quote: literal text, not a pipe
            // stage
        }
        if inside_command_substitution(&unquoted, offset) {
            continue;
        }
        let (producer, prior) = pipeline_context(&unquoted, offset);
        if prior.as_deref() == Some("sort") {
            continue;
        }
        return Some(HookOutput::deny(&head_tail_message(
            &producer,
            cap.as_str(),
        )));
    }

    // Backstop: `| rg .` / `| rg -m N .` bare-catch-all fake filter, denied for
    // every producer (mirrors head/tail). Scan `stripped` because the catch-all
    // pattern may be quoted (`rg ''`); the offset is valid in `unquoted` too
    // (length-preserving strip). Pure count output consumes the entire stream
    // and is exempted. A real `rg 'pattern'` content filter does not match
    // RG_COUNTER_RE, so legitimate filtering passes.
    for cap in RG_COUNTER_RE.find_iter(&stripped) {
        if RG_FULL_COUNT_RE.is_match(cap.as_str()) {
            continue;
        }
        let offset = cap.start();
        // Offset is from `stripped`; skip if it does not map to a valid char
        // boundary in `unquoted` (multibyte-in-quotes divergence).
        // `is_char_boundary` returns false for any index past the end, so this
        // also bounds it.
        if !unquoted.is_char_boundary(offset) {
            continue;
        }
        if inside_command_substitution(&unquoted, offset) {
            continue;
        }
        let (producer, _prior) = pipeline_context(&unquoted, offset);
        return Some(HookOutput::deny(&head_tail_message(
            &producer,
            cap.as_str(),
        )));
    }
    None
}

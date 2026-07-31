//! Head/tail (and sed/awk/rg) output-truncation pipe blocking: a
//! producer-aware hard-deny steering callers to source-native output caps.

use crate::models::HookOutput;
use crate::parser::extract_commands;
use crate::recovery::{FileSelection, RecoveryAction};
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
/// that head/tail would truncate away. Used to tailor the denial cause and
/// recovery actions; the deny decision is producer-agnostic (deny-by-default),
/// so a build tool missing from this list still denies with neutral recovery.
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

/// Stable denial cause for a non-exempt truncation cap. Never references
/// `max_output` / `output_tail`, which are not stock Bash tool params (a public
/// tool-gates install may not be on a patched build). The producer only selects
/// the cause wording; semantic recovery actions are attached separately.
fn head_tail_reason(producer: &str, segment: &str) -> String {
    let trimmed = segment.trim();
    if producer == "gh" {
        return format!(
            "`{trimmed}` blocked: this consumer-side cap truncates `gh` output and can drop rows or \
             cut JSON."
        );
    }
    if BUILD_PRODUCERS.contains(&producer) {
        return format!(
            "`{trimmed}` blocked: this consumer-side cap truncates `{producer}` output and can hide \
             diagnostics."
        );
    }
    format!("`{trimmed}` blocked: a consumer-side cap truncates unseen output.")
}

fn cap_stage(segment: &str) -> &str {
    segment
        .trim()
        .strip_prefix("|&")
        .or_else(|| segment.trim().strip_prefix('|'))
        .unwrap_or(segment)
        .trim()
        .trim_end_matches(['|', '&', ';'])
        .trim()
}

fn safe_source_path(arg: &str) -> bool {
    !arg.is_empty()
        && arg != "-"
        && !arg.starts_with('-')
        && !arg
            .chars()
            .any(|c| matches!(c, '*' | '?' | '[' | ']' | '{' | '}' | '$' | '`'))
}

fn reads_one_source_file(program: &str, args: &[String]) -> bool {
    match normalize_token(program) {
        "cat" => {
            if args.iter().any(|arg| arg == "-") {
                return false;
            }
            let paths: Vec<&str> = args
                .iter()
                .map(String::as_str)
                .filter(|arg| *arg != "--" && !arg.starts_with('-'))
                .collect();
            paths.len() == 1 && safe_source_path(paths[0])
        }
        "bat" => match args {
            [arg] => safe_source_path(arg),
            [separator, arg] if separator == "--" => safe_source_path(arg),
            _ => false,
        },
        _ => false,
    }
}

fn unsigned_decimal(value: &str) -> Option<u64> {
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        value.parse().ok()
    } else {
        None
    }
}

fn numeric_line_count(args: &[String]) -> Option<u64> {
    let mut count = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "-c" || arg == "--bytes" || arg.starts_with("--bytes=") {
            return None;
        }
        if arg == "-n" || arg == "--lines" {
            let value = args.get(index + 1)?;
            count = Some(unsigned_decimal(value)?);
            index += 2;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--lines=") {
            count = Some(unsigned_decimal(value)?);
        } else if let Some(value) = arg.strip_prefix('-') {
            if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
                count = unsigned_decimal(value);
            }
        }
        index += 1;
    }
    count.or(Some(10))
}

fn signed_decimal(value: &str) -> bool {
    let digits = value
        .strip_prefix('+')
        .or_else(|| value.strip_prefix('-'))
        .unwrap_or(value);
    unsigned_decimal(digits).is_some()
}

fn head_tail_reads_stdin(args: &[String]) -> bool {
    match args {
        [] => true,
        [arg] => {
            let legacy_count = arg
                .strip_prefix('-')
                .is_some_and(|value| unsigned_decimal(value).is_some());
            let attached_count = ["-n", "-c", "--lines=", "--bytes="]
                .iter()
                .find_map(|prefix| arg.strip_prefix(prefix))
                .is_some_and(signed_decimal);
            legacy_count || attached_count
        }
        [flag, value] if matches!(flag.as_str(), "-n" | "--lines" | "-c" | "--bytes") => {
            signed_decimal(value)
        }
        _ => false,
    }
}

fn cap_reads_only_stdin(program: &str, args: &[String], raw: &str) -> bool {
    if strip_quoted_strings(raw).contains('<') {
        return false;
    }
    match normalize_token(program) {
        "head" | "tail" => head_tail_reads_stdin(args),
        "sed" => {
            matches!(args, [script] if !script.is_empty())
                || matches!(args, [flag, script] if flag == "-n" && !script.is_empty())
        }
        "awk" => matches!(args, [script] if !script.is_empty()),
        // RG_COUNTER_RE is anchored after the catch-all pattern, so a matched
        // stage cannot carry a path operand after it.
        "rg" => true,
        _ => false,
    }
}

fn last_number(text: &str) -> Option<u64> {
    static NUMBER_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\d+").expect("NUMBER_RE must compile"));
    NUMBER_RE
        .find_iter(text)
        .last()
        .and_then(|value| value.as_str().parse().ok())
}

fn selection_for_cap(program: &str, args: &[String], raw: &str) -> FileSelection {
    match normalize_token(program) {
        "head" => numeric_line_count(args)
            .map(FileSelection::First)
            .unwrap_or(FileSelection::Whole),
        "tail" => numeric_line_count(args)
            .map(FileSelection::Last)
            .unwrap_or(FileSelection::Whole),
        "sed" | "awk" => last_number(raw)
            .map(FileSelection::First)
            .unwrap_or(FileSelection::Whole),
        "rg" => {
            let mut count = None;
            let mut index = 0;
            while index < args.len() {
                if args[index] == "-m" || args[index] == "--max-count" {
                    count = args.get(index + 1).and_then(|value| value.parse().ok());
                    break;
                }
                if let Some(value) = args[index].strip_prefix("--max-count=") {
                    count = value.parse().ok();
                    break;
                }
                index += 1;
            }
            count
                .map(FileSelection::First)
                .unwrap_or(FileSelection::Whole)
        }
        _ => FileSelection::Whole,
    }
}

fn source_file_selection(
    command_string: &str,
    segment: &str,
    prior_program: Option<&str>,
) -> Option<FileSelection> {
    let prior_program = prior_program?;
    if !matches!(prior_program, "cat" | "bat") {
        return None;
    }
    let stage = cap_stage(segment);
    let commands = extract_commands(command_string);
    let matches: Vec<usize> = commands
        .iter()
        .enumerate()
        .filter_map(|(index, command)| (command.raw.trim() == stage).then_some(index))
        .collect();
    let [cap_index] = matches.as_slice() else {
        return None;
    };
    let source_index = cap_index.checked_sub(1)?;
    let source = &commands[source_index];
    if normalize_token(&source.program) != prior_program
        || !reads_one_source_file(&source.program, &source.args)
    {
        return None;
    }
    let cap = &commands[*cap_index];
    if !cap_reads_only_stdin(&cap.program, &cap.args, &cap.raw) {
        return None;
    }
    Some(selection_for_cap(&cap.program, &cap.args, &cap.raw))
}

fn head_tail_denial(
    producer: &str,
    segment: &str,
    command_string: &str,
    prior_program: Option<&str>,
) -> HookOutput {
    let output = HookOutput::deny(&head_tail_reason(producer, segment));
    if producer == "gh" {
        return output
            .with_recovery(RecoveryAction::KeepCompleteOutput)
            .with_recovery(RecoveryAction::UseProducerNativeLimit {
                producer: Some("gh".to_string()),
            });
    }
    if BUILD_PRODUCERS.contains(&producer) {
        return output
            .with_recovery(RecoveryAction::RunUncapped)
            .with_recovery(RecoveryAction::FilterByRealPattern);
    }

    let output = output
        .with_recovery(RecoveryAction::UseProducerNativeLimit { producer: None })
        .with_recovery(RecoveryAction::RunUncappedAndPersist);
    match source_file_selection(command_string, segment, prior_program) {
        Some(selection) => output.with_recovery(RecoveryAction::ReadSourceFile { selection }),
        None => output,
    }
}

/// Decide head/tail-pipe handling. Three exemptions pass through silently:
/// streaming `tail -f`/`-F`; top-N `... | sort ... | head/tail -N` (sort must
/// consume all input, so the slice is the selection, not a cap); and head/tail
/// inside `$(...)` / backticks (a programmatic pick feeding a variable). Every
/// other non-exempt cap is denied regardless of producer; the producer only
/// selects the cause and recovery (build/`gh` get tailored guidance).
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
        return Some(head_tail_denial(
            &producer,
            segment,
            command_string,
            prior.as_deref(),
        ));
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
        return Some(head_tail_denial(
            &producer,
            cap.as_str(),
            command_string,
            prior.as_deref(),
        ));
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
        let (producer, prior) = pipeline_context(&unquoted, offset);
        return Some(head_tail_denial(
            &producer,
            cap.as_str(),
            command_string,
            prior.as_deref(),
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Client;

    #[test]
    fn file_head_recovery_uses_client_reader() {
        let output =
            check_head_tail_pipe("cat report.txt | head -n 12").expect("cap must be denied");

        assert_eq!(
            output.reason.as_deref(),
            Some("`| head -n 12` blocked: a consumer-side cap truncates unseen output.")
        );

        let claude = output.serialize(Client::Claude);
        assert_eq!(
            claude["hookSpecificOutput"]["additionalContext"],
            "Use the producer's native limit when the task needs a bounded result. \
             Otherwise run uncapped and persist the complete output for range inspection. \
             Use the `Read` tool to inspect the first 12 lines of the source file directly."
        );

        let codex = output.serialize(Client::Codex);
        assert_eq!(
            codex["hookSpecificOutput"]["permissionDecisionReason"],
            "`| head -n 12` blocked: a consumer-side cap truncates unseen output."
        );
        assert_eq!(
            codex["hookSpecificOutput"]["additionalContext"],
            "Use the producer's native limit when the task needs a bounded result. \
             Otherwise run uncapped and persist the complete output for range inspection. \
             Inspect the first 12 lines directly from the source file. If `bat` is available, \
             use `bat -r :12 <file>`."
        );
    }

    #[test]
    fn streamed_output_does_not_invent_file_reader_recovery() {
        let output = check_head_tail_pipe("git log | sed -n '1,10p'").expect("cap must be denied");

        assert_eq!(
            output.reason.as_deref(),
            Some("`| sed -n '1,10p'` blocked: a consumer-side cap truncates unseen output.")
        );
        assert_eq!(
            output.recovery_actions,
            vec![
                RecoveryAction::UseProducerNativeLimit { producer: None },
                RecoveryAction::RunUncappedAndPersist,
            ]
        );

        for client in [
            Client::Claude,
            Client::Gemini,
            Client::Codex,
            Client::Antigravity,
        ] {
            let wire = output.serialize(client).to_string();
            assert!(
                !wire.contains("`Read`")
                    && !wire.contains("`read_file`")
                    && !wire.contains("`view_file`")
                    && !wire.contains("`bat"),
                "{client:?} invented file-reader guidance: {wire}"
            );
            assert!(
                wire.contains("producer's native limit")
                    && wire.contains("persist the complete output"),
                "{client:?} omitted stream recovery: {wire}"
            );
        }
    }

    #[test]
    fn nested_reader_is_not_mistaken_for_the_pipeline_source() {
        let output = check_head_tail_pipe("printf '%s\\n' \"$(cat report.txt)\" | head -n 3")
            .expect("cap must be denied");

        assert!(
            !output
                .recovery_actions
                .iter()
                .any(|action| matches!(action, RecoveryAction::ReadSourceFile { .. })),
            "nested reader was treated as the direct source: {:?}",
            output.recovery_actions
        );
    }

    #[test]
    fn ambiguous_reader_inputs_do_not_receive_file_recovery() {
        for command in [
            "cat first.txt second.txt | head -n 3",
            "cat report.txt - | head -n 3",
            "cat | head -n 3",
            "cat \"$REPORT\" | head -n 3",
            "bat first.txt second.txt | head -n 3",
        ] {
            let output = check_head_tail_pipe(command).expect("cap must be denied");
            assert!(
                !output
                    .recovery_actions
                    .iter()
                    .any(|action| matches!(action, RecoveryAction::ReadSourceFile { .. })),
                "ambiguous reader received file recovery: {command}\n{:?}",
                output.recovery_actions
            );
        }
    }

    #[test]
    fn cap_with_its_own_file_operand_does_not_receive_source_file_recovery() {
        for command in [
            "cat report.txt | head -n 3 other.txt",
            "cat report.txt | tail -n 3 other.txt",
            "cat report.txt | sed -n '1,3p' other.txt",
            "cat report.txt | awk 'NR<=3' other.txt",
            "cat report.txt | head -n 3 < other.txt",
            "cat report.txt | sed -n '1,3p' < other.txt",
        ] {
            let output = check_head_tail_pipe(command).expect("cap must be denied");
            assert!(
                !output
                    .recovery_actions
                    .iter()
                    .any(|action| matches!(action, RecoveryAction::ReadSourceFile { .. })),
                "cap file operand received source-file recovery: {command}\n{:?}",
                output.recovery_actions
            );
        }
    }

    #[test]
    fn relative_line_modes_do_not_claim_a_first_or_last_count() {
        for command in [
            "cat report.txt | head -n -12",
            "cat report.txt | tail -n +7",
        ] {
            let output = check_head_tail_pipe(command).expect("cap must be denied");
            assert!(
                output
                    .recovery_actions
                    .contains(&RecoveryAction::ReadSourceFile {
                        selection: FileSelection::Whole,
                    }),
                "relative line mode was misrepresented: {command}\n{:?}",
                output.recovery_actions
            );
        }
    }

    #[test]
    fn file_caps_preserve_the_requested_selection() {
        for (command, selection) in [
            ("cat report.txt | head", FileSelection::First(10)),
            ("cat report.txt | tail -7", FileSelection::Last(7)),
            ("cat report.txt | sed -n '1,20p'", FileSelection::First(20)),
            ("cat report.txt | awk 'NR<=8'", FileSelection::First(8)),
            ("cat report.txt | rg -m 5 .", FileSelection::First(5)),
            ("bat report.txt | rg .", FileSelection::Whole),
        ] {
            let output = check_head_tail_pipe(command).expect("cap must be denied");
            assert!(
                output
                    .recovery_actions
                    .contains(&RecoveryAction::ReadSourceFile { selection }),
                "selection was not preserved: {command}\n{:?}",
                output.recovery_actions
            );
        }
    }
}

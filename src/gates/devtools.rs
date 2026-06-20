//! Developer tools permission gate.
//!
//! Mostly declarative via rules/devtools.toml.
//!
//! Custom handler for `sd`: without file args it's a stdin→stdout pipe
//! filter (safe), with file args it modifies files in-place (ask).

use crate::gates::helpers::{path_args, upgrade_to_scratch_allow};
use crate::generated::rules::check_devtools_gate;
use crate::models::{CommandInfo, Decision, GateResult};

/// Check if `sd` is being used as a pipe filter (no file args) or in-place editor.
///
/// Note: tree-sitter-bash drops bare numbers from args (e.g., `sd -n 5 old new`
/// becomes args=["-n", "old", "new"]), so we can't reliably track value-consuming
/// flags. Instead we simply skip all dash-prefixed args and count the rest.
fn check_sd(cmd: &CommandInfo) -> GateResult {
    // --preview/-p is always safe (dry run)
    if cmd.args.iter().any(|a| a == "-p" || a == "--preview") {
        return GateResult::allow();
    }

    // Count positional args, skipping flags.
    // After "--", all remaining args are positional.
    let mut positional = 0;
    let mut seen_double_dash = false;
    for arg in &cmd.args {
        if !seen_double_dash && arg == "--" {
            seen_double_dash = true;
            continue;
        }
        if !seen_double_dash && arg.starts_with('-') {
            continue;
        }
        positional += 1;
    }

    // sd FIND REPLACE [FILES...]: 2 positional = pipe mode, 3+ = file mode
    if positional <= 2 {
        GateResult::allow()
    } else {
        // File mode: FIND and REPLACE are the first two positionals; the rest are
        // the files edited in place. Editing only scratch files is friction-free.
        let files: Vec<&str> = path_args(cmd).into_iter().skip(2).collect();
        let under = !files.is_empty() && files.iter().all(|p| crate::router::is_under_scratch(p));
        upgrade_to_scratch_allow(
            GateResult::ask("sd: In-place text replacement"),
            under,
            "sd on scratch file(s)",
        )
    }
}

/// Shell-tokenize `raw` into `(unquoted_text, exposed_dynamic)` pairs. A token
/// is "dynamic" when it contains a `$` or backtick the shell would expand, i.e.
/// one outside single quotes. Single-quoted spans are literal, so awk field refs
/// like `$1`/`$NF` (which live inside the single-quoted program) are NOT dynamic.
fn shell_tokens(raw: &str) -> Vec<(String, bool)> {
    let mut toks = Vec::new();
    let mut cur = String::new();
    let mut started = false;
    let mut dynamic = false;
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
                started = true;
            }
            '"' if !in_single => {
                in_double = !in_double;
                started = true;
            }
            '\\' if !in_single => {
                started = true;
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            '$' | '`' if !in_single => {
                dynamic = true;
                started = true;
                cur.push(c);
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if started {
                    toks.push((std::mem::take(&mut cur), dynamic));
                    dynamic = false;
                    started = false;
                }
            }
            other => {
                started = true;
                cur.push(other);
            }
        }
    }
    if started {
        toks.push((cur, dynamic));
    }
    toks
}

/// True if the awk PROGRAM source is produced by shell expansion/substitution
/// (`awk "$PROG"`, `awk "$(...)"`, backticks, ANSI-C `awk $'...'`) and therefore
/// cannot be statically inspected. Only the program counts as code: a dynamic
/// filename or `-v`/`-F` value (which awk never executes) does not, so those
/// still allow. This closes the obfuscation path where a hidden program would
/// pass the marker scan because the markers are not visible pre-expansion.
///
/// gawk concatenates EVERY `-e`/`--source` chunk into one program, so a dynamic
/// chunk anywhere (not just the first) makes the whole program opaque. Once any
/// `-e`/`--source` supplies the program, a trailing bare positional is a data
/// FILE, not program source, so its dynamism does not count.
fn awk_program_is_opaque(raw: &str) -> bool {
    let toks = shell_tokens(raw);
    let mut i = 1; // skip the program name (awk/gawk/mawk)
    let mut program_from_source_flag = false;
    while i < toks.len() {
        let t = toks[i].0.as_str();
        let dynamic = toks[i].1;
        // -e/--source: the following token is an inline program chunk.
        if matches!(t, "-e" | "--source") {
            program_from_source_flag = true;
            if toks.get(i + 1).map(|v| v.1).unwrap_or(false) {
                return true; // a dynamic chunk -> opaque
            }
            i += 2; // static chunk: consume flag + value, keep scanning for more
            continue;
        }
        // Attached `-e<prog>` / `--source=<prog>`: this token is a program chunk.
        if t.starts_with("--source=") || (t.starts_with("-e") && t.len() > 2) {
            program_from_source_flag = true;
            if dynamic {
                return true;
            }
            i += 1;
            continue;
        }
        // -F/-v consume a value that is NOT program source -> skip flag + value.
        if matches!(t, "-F" | "--field-separator" | "-v" | "--assign") {
            i += 2;
            continue;
        }
        // Any other flag (attached -F.../-v..., and -f/-i/-l/-E handled as ask
        // elsewhere): skip the single token.
        if t.starts_with('-') {
            i += 1;
            continue;
        }
        // First bare positional is the program, unless `-e`/`--source` already
        // supplied it (then bare positionals are data files, never executed).
        return !program_from_source_flag && dynamic;
    }
    false
}

/// Decide whether an `awk`/`gawk`/`mawk` invocation is safe to auto-allow.
///
/// awk's shell-exec and file-write surface reduces to a small set of syntactic
/// markers that gawk cannot construct at runtime. An inline program containing
/// none of them only reads stdin/file args and prints, so it is allow-safe.
/// Anything else asks (fail-safe: unknown forms prompt, they never bypass).
///
/// Exec/write markers (any one -> ask):
///   `|`        pipe to/from a command, including the `|&` coprocess
///   `>`        file write/append redirect (`print > file`, `>>`)
///   `@`        gawk indirect call (`@f()`), `@load`, `@include`
///   `getline`  read from a command or file
///   `system`   run a shell command
///
/// The `@` marker is load-bearing: gawk invokes a builtin by a runtime-built
/// name via `@f()` (verified: `f="sys""tem"; @f("...")` runs the shell), so a
/// literal `system(` scan alone is unsound. Banning `@` closes that path.
///
/// `||` (logical or) and `>=` (comparison) are exempted: neither is ever a pipe
/// or a redirect, so common conditions like `$2 || $3` and `NR>=10 && NR<=20`
/// auto-allow.
///
/// Program-source flags (`-f`/`--file`, `-i`/`--include`, `-l`/`--load`,
/// `-E`/`--exec`) read the program from a file, load a native extension, or
/// edit files in place; the program is not inline so its surface cannot be
/// inspected -> ask. A program supplied via shell expansion is likewise opaque
/// (see `awk_program_is_opaque`).
///
/// `|` and `>` legitimately appear in a field-separator or assignment value
/// (`awk -F'|'`), so the values of `-F`/`--field-separator`/`-v`/`--assign` are
/// excluded from the marker scan. Everything else (the program itself,
/// `-e`/`--source` inline programs, filenames) is scanned.
///
/// Deliberate over-ask: a lone `>`/`<` comparison (`$3 > 100`) shares the `>`
/// redirect character, so such filters ask. Conservative by design; never a
/// bypass. (`>=`/`<=` are exempt, so range filters still allow.)
fn check_awk(cmd: &CommandInfo) -> GateResult {
    const EXEC_WRITE_REASON: &str = "awk program uses a shell-exec or file-write construct (system, getline, |, @, or a > redirect). These run shell commands or write files; plain field/print/arithmetic awk auto-allows.";
    const EXTERNAL_REASON: &str = "awk -f/-i/-l/-E: runs a program from a file, loads a native extension, or edits files in place. The program is not inline, so its exec/write surface cannot be inspected.";
    const OPAQUE_REASON: &str = "awk program comes from a shell variable, command substitution, or ANSI-C quoting, so its exec/write surface cannot be inspected. Inline single-quoted awk auto-allows.";

    // The program must be statically visible to scan; a shell-produced program
    // could hide any exec/write construct from the marker scan below.
    if awk_program_is_opaque(&cmd.raw) {
        return GateResult::ask(OPAQUE_REASON);
    }

    let mut scan = String::new();
    let mut skip_value = false;
    for arg in &cmd.args {
        if skip_value {
            skip_value = false;
            continue;
        }
        let a = arg.as_str();

        // Program-source / load / exec / inplace flags: unscannable or write.
        if matches!(
            a,
            "-f" | "--file" | "-l" | "--load" | "-i" | "--include" | "-E" | "--exec"
        ) || a.starts_with("--file=")
            || a.starts_with("--load=")
            || a.starts_with("--include=")
            || a.starts_with("--exec=")
        {
            return GateResult::ask(EXTERNAL_REASON);
        }

        // Field-separator / assignment values can hold `|` or `>` legitimately.
        // Drop them from the scan (split form consumes the next arg).
        if matches!(a, "-F" | "--field-separator" | "-v" | "--assign") {
            skip_value = true;
            continue;
        }
        if a.starts_with("-F")
            || a.starts_with("--field-separator=")
            || a.starts_with("-v")
            || a.starts_with("--assign=")
        {
            continue;
        }

        scan.push(' ');
        scan.push_str(a);
    }

    // Exempt `||` (logical or) and `>=` (comparison) before testing for a pipe
    // or a redirect, since neither is one.
    let pipes = scan.replace("||", "");
    let redirects = scan.replace(">=", "");
    if pipes.contains('|')
        || redirects.contains('>')
        || scan.contains('@')
        || scan.contains("getline")
        || scan.contains("system")
    {
        return GateResult::ask(EXEC_WRITE_REASON);
    }

    GateResult::allow()
}

/// Check developer tools that can modify files.
pub fn check_devtools(cmd: &CommandInfo) -> GateResult {
    let result = check_devtools_gate(cmd);
    if result.decision == Decision::Skip {
        match cmd.program.as_str() {
            "sd" => return check_sd(cmd),
            "awk" | "gawk" | "mawk" => return check_awk(cmd),
            _ => {}
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::test_utils::cmd;
    use crate::models::Decision;
    // === sd (pipe mode vs in-place) ===

    #[test]
    fn test_sd_with_file_asks() {
        let result = check_devtools(&cmd("sd", &["old", "new", "file"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_sd_pipe_mode_allows() {
        // No file args = stdin→stdout filter
        let result = check_devtools(&cmd("sd", &["old", "new"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_sd_pipe_mode_with_flags_allows() {
        let result = check_devtools(&cmd("sd", &["-F", "old", "new"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_sd_preview_allows() {
        let result = check_devtools(&cmd("sd", &["-p", "old", "new", "file"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_sd_multiple_files_asks() {
        let result = check_devtools(&cmd("sd", &["old", "new", "a.txt", "b.txt"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_sd_long_value_flag_with_file_asks() {
        // tree-sitter drops bare "5", so args = ["--max-replacements", "old", "new", "file.txt"]
        let result = check_devtools(&cmd(
            "sd",
            &["--max-replacements", "old", "new", "file.txt"],
        ));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_sd_double_dash_with_file_asks() {
        // After --, all args are positional: -old, new, file.txt = 3
        let result = check_devtools(&cmd("sd", &["--", "-old", "new", "file.txt"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_sd_double_dash_pipe_mode_allows() {
        // After --, -old and new = 2 positional (pipe mode)
        let result = check_devtools(&cmd("sd", &["--", "-old", "new"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === awk (custom handler: safe idioms allow, exec/write asks) ===
    //
    // These go through the real parser so `raw` (which the opaque-program guard
    // reads) and `args` match production exactly. The `cmd()` helper space-joins
    // without quotes, which would misrepresent shell quoting.

    /// Parse a command string and return its awk/gawk/mawk command.
    fn awk(raw: &str) -> CommandInfo {
        crate::parser::extract_commands(raw)
            .into_iter()
            .find(|c| matches!(c.program.as_str(), "awk" | "gawk" | "mawk"))
            .expect("expected an awk command")
    }

    #[test]
    fn test_awk_field_print_allows() {
        assert_eq!(
            check_devtools(&awk("awk '{print $1}'")).decision,
            Decision::Allow
        );
    }

    #[test]
    fn test_awk_sum_allows() {
        assert_eq!(
            check_devtools(&awk("awk '{s+=$1} END{print s}' nums")).decision,
            Decision::Allow
        );
    }

    #[test]
    fn test_awk_line_count_allows() {
        assert_eq!(
            check_devtools(&awk("awk 'END{print NR}' file.txt")).decision,
            Decision::Allow
        );
    }

    #[test]
    fn test_awk_range_extraction_allows() {
        assert_eq!(
            check_devtools(&awk("awk '/^---$/{c++; next} c==1' file.md")).decision,
            Decision::Allow
        );
    }

    #[test]
    fn test_awk_row_field_allows() {
        assert_eq!(
            check_devtools(&awk("awk 'NR==2{print $4}'")).decision,
            Decision::Allow
        );
    }

    #[test]
    fn test_awk_printf_byte_math_allows() {
        assert_eq!(
            check_devtools(&awk("awk '{printf \"%.1f GB\", $1/1073741824}'")).decision,
            Decision::Allow
        );
    }

    #[test]
    fn test_awk_ge_le_range_filter_allows() {
        // `>=`/`<=` are comparisons, never redirects -> the range filter allows.
        assert_eq!(
            check_devtools(&awk("awk 'NR>=147 && NR<=360'")).decision,
            Decision::Allow
        );
    }

    #[test]
    fn test_awk_logical_or_allows() {
        // `||` is logical or, never a pipe.
        assert_eq!(
            check_devtools(&awk("awk '$2 != $5 || $3 != $6 {print}'")).decision,
            Decision::Allow
        );
    }

    #[test]
    fn test_awk_dynamic_filename_allows() {
        // The program is a static single-quoted literal; only the FILENAME is a
        // shell variable. awk just reads that file -> safe, allow. (This is the
        // single most common real-world form: frontmatter extraction.)
        assert_eq!(
            check_devtools(&awk("awk '/^---$/{c++; next} c==1' \"$f\"")).decision,
            Decision::Allow
        );
    }

    #[test]
    fn test_awk_dynamic_assign_value_allows() {
        // A `-v` value from the shell is data, not code: awk never executes it.
        assert_eq!(
            check_devtools(&awk("awk -v n=\"$COUNT\" '{print $1+n}'")).decision,
            Decision::Allow
        );
    }

    #[test]
    fn test_awk_field_separator_attached_pipe_allows() {
        // -F'|' parses pipe-delimited data; the separator value is not a shell pipe.
        assert_eq!(
            check_devtools(&awk("awk -F'|' '{print $2}' data")).decision,
            Decision::Allow
        );
    }

    #[test]
    fn test_awk_isolated_from_pipeline_allows() {
        // The shell pipe in `ps | awk ...` belongs to ps, not to awk's program.
        assert_eq!(
            check_devtools(&awk("ps aux | awk '{print $1}'")).decision,
            Decision::Allow
        );
    }

    #[test]
    fn test_awk_version_allows() {
        assert_eq!(
            check_devtools(&awk("awk --version")).decision,
            Decision::Allow
        );
    }

    #[test]
    fn test_gawk_alias_safe_allows() {
        assert_eq!(
            check_devtools(&awk("gawk '{print $1}'")).decision,
            Decision::Allow
        );
    }

    #[test]
    fn test_mawk_alias_safe_allows() {
        assert_eq!(
            check_devtools(&awk("mawk '{print $1}'")).decision,
            Decision::Allow
        );
    }

    #[test]
    fn test_awk_system_asks() {
        assert_eq!(
            check_devtools(&awk("awk 'BEGIN{system(\"id\")}'")).decision,
            Decision::Ask
        );
    }

    #[test]
    fn test_awk_indirect_call_asks() {
        // gawk @f() invokes a runtime-built builtin name; the `@` marker catches it
        // even though no literal `system(` appears.
        assert_eq!(
            check_devtools(&awk("gawk 'BEGIN{f=\"sys\" \"tem\"; @f(\"id\")}'")).decision,
            Decision::Ask
        );
    }

    #[test]
    fn test_awk_command_getline_asks() {
        assert_eq!(
            check_devtools(&awk("awk 'BEGIN{\"date\" | getline d; print d}'")).decision,
            Decision::Ask
        );
    }

    #[test]
    fn test_awk_print_pipe_asks() {
        assert_eq!(
            check_devtools(&awk("awk '{print | \"cat\"}'")).decision,
            Decision::Ask
        );
    }

    #[test]
    fn test_awk_file_write_asks() {
        assert_eq!(
            check_devtools(&awk("awk '{print > \"/tmp/x\"}'")).decision,
            Decision::Ask
        );
    }

    #[test]
    fn test_awk_program_file_asks() {
        // -f reads the program from a file we cannot inspect.
        assert_eq!(
            check_devtools(&awk("awk -f prog.awk data.txt")).decision,
            Decision::Ask
        );
    }

    #[test]
    fn test_awk_inplace_asks() {
        assert_eq!(
            check_devtools(&awk("gawk -i inplace '{print}' file.txt")).decision,
            Decision::Ask
        );
    }

    #[test]
    fn test_awk_load_extension_asks() {
        assert_eq!(
            check_devtools(&awk("gawk -l filefuncs 'BEGIN{print}'")).decision,
            Decision::Ask
        );
    }

    #[test]
    fn test_awk_comparison_over_asks() {
        // Documented conservative over-ask: a lone `>` comparison shares the
        // redirect character, so threshold filters ask. Safe, never a bypass.
        assert_eq!(
            check_devtools(&awk("awk '$3 > 100'")).decision,
            Decision::Ask
        );
    }

    // --- opaque program: produced by shell expansion, cannot be inspected ---

    #[test]
    fn test_awk_variable_program_asks() {
        assert_eq!(
            check_devtools(&awk("awk \"$PROG\"")).decision,
            Decision::Ask
        );
    }

    #[test]
    fn test_awk_command_substitution_program_asks() {
        assert_eq!(
            check_devtools(&awk("awk \"$(cat evil.awk)\"")).decision,
            Decision::Ask
        );
    }

    #[test]
    fn test_awk_backtick_program_asks() {
        assert_eq!(
            check_devtools(&awk("awk `cat evil.awk`")).decision,
            Decision::Ask
        );
    }

    #[test]
    fn test_awk_ansi_c_program_asks() {
        // `$'\x73ystem(...)'` decodes to system(...) at the shell; opaque -> ask.
        assert_eq!(
            check_devtools(&awk("awk $'\\x73ystem(\"id\")'")).decision,
            Decision::Ask
        );
    }

    // --- multi-chunk -e/--source: gawk concatenates every program chunk ---

    #[test]
    fn test_awk_multichunk_source_dynamic_asks() {
        // A static first -e chunk must NOT let a dynamic later chunk through:
        // gawk concatenates them into one program. Regression guard for the
        // opaque-program bypass.
        assert_eq!(
            check_devtools(&awk("awk -e '{print}' -e \"$PROG\"")).decision,
            Decision::Ask
        );
    }

    #[test]
    fn test_awk_multichunk_source_equals_dynamic_asks() {
        assert_eq!(
            check_devtools(&awk("awk -e '{print}' --source=\"$(cat p.awk)\"")).decision,
            Decision::Ask
        );
    }

    #[test]
    fn test_awk_source_flag_static_marker_asks() {
        // The -e value is scanned like any program: a static marker still asks.
        assert_eq!(
            check_devtools(&awk("awk -e 'BEGIN{system(\"id\")}'")).decision,
            Decision::Ask
        );
    }

    #[test]
    fn test_awk_source_flag_dynamic_asks() {
        assert_eq!(
            check_devtools(&awk("awk --source \"$PROG\"")).decision,
            Decision::Ask
        );
    }

    #[test]
    fn test_awk_source_program_then_dynamic_file_allows() {
        // Once -e/--source supplies the (static) program, a trailing bare
        // positional is a data file, not program source -> still allows.
        assert_eq!(
            check_devtools(&awk("awk --source='{print}' \"$f\"")).decision,
            Decision::Allow
        );
    }

    // --- exec/write markers and external flags: regression guards ---

    #[test]
    fn test_awk_coprocess_asks() {
        // gawk two-way coprocess `|&` to a command. Distinct from `||`.
        assert_eq!(
            check_devtools(&awk("gawk 'BEGIN{print \"id\" |& \"/bin/sh\"}'")).decision,
            Decision::Ask
        );
    }

    #[test]
    fn test_awk_append_redirect_asks() {
        assert_eq!(
            check_devtools(&awk("awk '{print >> \"/tmp/out\"}'")).decision,
            Decision::Ask
        );
    }

    #[test]
    fn test_awk_exec_flag_asks() {
        // -E/--exec runs a program from a file, like -f.
        assert_eq!(
            check_devtools(&awk("gawk -E prog.awk")).decision,
            Decision::Ask
        );
    }

    #[test]
    fn test_awk_load_extension_equals_form_asks() {
        // Attached `--load=` loads a native extension -> ask, like split `-l`.
        assert_eq!(
            check_devtools(&awk("gawk --load=filefuncs 'BEGIN{print}'")).decision,
            Decision::Ask
        );
    }

    #[test]
    fn test_awk_regex_alternation_over_asks() {
        // A `|` inside a /regex/ alternation is not a pipe, but the lexical scan
        // cannot tell, so it conservatively asks. Pinned so any future relaxation
        // of `|` detection must consciously keep `|&` / `print | cmd` asking.
        assert_eq!(
            check_devtools(&awk("awk '/a|b/{print}'")).decision,
            Decision::Ask
        );
    }

    // --- split-form value exclusion (the riskier value-consuming branch) ---

    #[test]
    fn test_awk_field_separator_split_pipe_allows() {
        assert_eq!(
            check_devtools(&awk("awk -F '|' '{print $2}' data")).decision,
            Decision::Allow
        );
    }

    #[test]
    fn test_awk_assign_split_marker_value_allows() {
        // A `>` supplied as -v data is excluded from the marker scan.
        assert_eq!(
            check_devtools(&awk("awk -v x='>' '{print x}'")).decision,
            Decision::Allow
        );
    }

    // === Tools with unknown_action = "allow" ===

    #[test]
    fn test_jq_allows() {
        let result = check_devtools(&cmd("jq", &[".key", "file.json"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_shellcheck_allows() {
        let result = check_devtools(&cmd("shellcheck", &["script.sh"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_shellcheck_with_flags_allows() {
        let result = check_devtools(&cmd(
            "shellcheck",
            &["-f", "json", "-s", "bash", "script.sh"],
        ));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === Tools with flag-conditional behavior ===

    #[test]
    fn test_sad_preview_allows() {
        let result = check_devtools(&cmd("sad", &["old", "new", "file"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_sad_commit_asks() {
        let result = check_devtools(&cmd("sad", &["old", "new", "--commit", "file"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_ast_grep_search_allows() {
        let result = check_devtools(&cmd("ast-grep", &["-p", "pattern", "src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_ast_grep_update_asks() {
        let result = check_devtools(&cmd("ast-grep", &["-p", "old", "-r", "new", "-U", "src/"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_yq_read_allows() {
        let result = check_devtools(&cmd("yq", &[".key", "file.yaml"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_yq_inplace_asks() {
        let result = check_devtools(&cmd("yq", &["-i", ".key = \"val\"", "file.yaml"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_prettier_check_allows() {
        let result = check_devtools(&cmd("prettier", &["--check", "src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_prettier_write_asks() {
        let result = check_devtools(&cmd("prettier", &["--write", "src/"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === semgrep ===

    #[test]
    fn test_semgrep_scan_allows() {
        let result = check_devtools(&cmd("semgrep", &["--config", "auto", "."]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_semgrep_fix_asks() {
        let result = check_devtools(&cmd("semgrep", &["--config", "auto", "--autofix", "."]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === eslint ===

    #[test]
    fn test_eslint_check_allows() {
        let result = check_devtools(&cmd("eslint", &["src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_eslint_fix_asks() {
        let result = check_devtools(&cmd("eslint", &["--fix", "src/"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === black ===

    #[test]
    fn test_black_check_allows() {
        let result = check_devtools(&cmd("black", &["--check", "src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_black_format_asks() {
        let result = check_devtools(&cmd("black", &["src/"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === ruff (custom handler) ===

    #[test]
    fn test_ruff_check_allows() {
        let result = check_devtools(&cmd("ruff", &["check", "src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_ruff_check_fix_asks() {
        let result = check_devtools(&cmd("ruff", &["check", "--fix", "src/"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_ruff_format_asks() {
        let result = check_devtools(&cmd("ruff", &["format", "src/"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_ruff_format_check_allows() {
        let result = check_devtools(&cmd("ruff", &["format", "--check", "src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === Mix (Elixir) ===

    #[test]
    fn test_mix_format_asks() {
        let result = check_devtools(&cmd("mix", &["format"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_mix_unknown_asks() {
        let result = check_devtools(&cmd("mix", &["deps.get"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === Dart ===

    #[test]
    fn test_dart_analyze_allows() {
        let result = check_devtools(&cmd("dart", &["analyze"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_dart_format_asks() {
        let result = check_devtools(&cmd("dart", &["format", "."]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_dart_unknown_asks() {
        let result = check_devtools(&cmd("dart", &["pub", "get"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === Buf ===

    #[test]
    fn test_buf_lint_allows() {
        let result = check_devtools(&cmd("buf", &["lint"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_buf_breaking_allows() {
        let result = check_devtools(&cmd("buf", &["breaking"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_buf_format_asks() {
        let result = check_devtools(&cmd("buf", &["format"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_buf_unknown_asks() {
        let result = check_devtools(&cmd("buf", &["generate"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === pytest ===

    #[test]
    fn test_pytest_allows() {
        let result = check_devtools(&cmd("pytest", &["-v", "tests/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_pytest_collect_only_allows() {
        let result = check_devtools(&cmd("pytest", &["--collect-only"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_py_test_alias_allows() {
        let result = check_devtools(&cmd("py.test", &["tests/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === mypy ===

    #[test]
    fn test_mypy_allows() {
        let result = check_devtools(&cmd("mypy", &["src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === pyright ===

    #[test]
    fn test_pyright_allows() {
        let result = check_devtools(&cmd("pyright", &["src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_basedpyright_alias_allows() {
        let result = check_devtools(&cmd("basedpyright", &["src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_pyright_writebaseline_allows() {
        // unknown_action = "allow", so unknown flags still allow
        let result = check_devtools(&cmd("pyright", &["--writebaseline"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === pylint ===

    #[test]
    fn test_pylint_allows() {
        let result = check_devtools(&cmd("pylint", &["src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === flake8 ===

    #[test]
    fn test_flake8_allows() {
        let result = check_devtools(&cmd("flake8", &["src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === bandit ===

    #[test]
    fn test_bandit_allows() {
        let result = check_devtools(&cmd("bandit", &["-r", "src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === coverage ===

    #[test]
    fn test_coverage_report_allows() {
        let result = check_devtools(&cmd("coverage", &["report"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_coverage_run_asks() {
        let result = check_devtools(&cmd("coverage", &["run", "-m", "pytest"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_coverage_html_asks() {
        let result = check_devtools(&cmd("coverage", &["html"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_coverage_json_asks() {
        let result = check_devtools(&cmd("coverage", &["json"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_coverage_xml_asks() {
        let result = check_devtools(&cmd("coverage", &["xml"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_coverage_lcov_asks() {
        let result = check_devtools(&cmd("coverage", &["lcov"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_coverage_erase_asks() {
        let result = check_devtools(&cmd("coverage", &["erase"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === tox ===

    #[test]
    fn test_tox_list_flag_allows() {
        let result = check_devtools(&cmd("tox", &["-l"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_tox_list_long_flag_allows() {
        let result = check_devtools(&cmd("tox", &["--list"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_tox_bare_asks() {
        let result = check_devtools(&cmd("tox", &[]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_tox_run_env_asks() {
        let result = check_devtools(&cmd("tox", &["-e", "py39"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === nox ===

    #[test]
    fn test_nox_list_allows() {
        let result = check_devtools(&cmd("nox", &["--list"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_nox_list_short_allows() {
        let result = check_devtools(&cmd("nox", &["-l"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_nox_bare_asks() {
        let result = check_devtools(&cmd("nox", &[]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_nox_session_asks() {
        let result = check_devtools(&cmd("nox", &["-s", "tests"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === autoflake ===

    #[test]
    fn test_autoflake_check_allows() {
        let result = check_devtools(&cmd("autoflake", &["--check", "src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_autoflake_in_place_asks() {
        let result = check_devtools(&cmd("autoflake", &["--in-place", "src/"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_autoflake_bare_asks() {
        // unknown_action = "ask", bare invocation asks
        let result = check_devtools(&cmd("autoflake", &["src/"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === tsx ===

    #[test]
    fn test_tsx_script_asks() {
        let result = check_devtools(&cmd("tsx", &["script.ts"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_tsx_version_allows() {
        let result = check_devtools(&cmd("tsx", &["--version"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === ts-node ===

    #[test]
    fn test_ts_node_script_asks() {
        let result = check_devtools(&cmd("ts-node", &["script.ts"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_ts_node_version_allows() {
        let result = check_devtools(&cmd("ts-node", &["--version"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_ts_node_help_allows() {
        let result = check_devtools(&cmd("ts-node", &["--help"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === webpack ===

    #[test]
    fn test_webpack_allows() {
        let result = check_devtools(&cmd("webpack", &["--config", "webpack.config.js"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_webpack_cli_alias_allows() {
        let result = check_devtools(&cmd("webpack-cli", &["build"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === rollup ===

    #[test]
    fn test_rollup_allows() {
        let result = check_devtools(&cmd("rollup", &["-c"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === swc ===

    #[test]
    fn test_swc_allows() {
        let result = check_devtools(&cmd("swc", &["src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === parcel ===

    #[test]
    fn test_parcel_build_allows() {
        let result = check_devtools(&cmd("parcel", &["build"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_parcel_serve_asks() {
        let result = check_devtools(&cmd("parcel", &["serve"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_parcel_version_allows() {
        let result = check_devtools(&cmd("parcel", &["--version"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_parcel_watch_asks() {
        let result = check_devtools(&cmd("parcel", &["watch"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === playwright ===

    #[test]
    fn test_playwright_test_allows() {
        let result = check_devtools(&cmd("playwright", &["test"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_playwright_show_report_allows() {
        let result = check_devtools(&cmd("playwright", &["show-report"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_playwright_show_trace_allows() {
        let result = check_devtools(&cmd("playwright", &["show-trace"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_playwright_install_asks() {
        let result = check_devtools(&cmd("playwright", &["install"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_playwright_codegen_asks() {
        let result = check_devtools(&cmd("playwright", &["codegen"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === cypress ===

    #[test]
    fn test_cypress_run_allows() {
        let result = check_devtools(&cmd("cypress", &["run"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_cypress_open_asks() {
        let result = check_devtools(&cmd("cypress", &["open"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_cypress_info_allows() {
        let result = check_devtools(&cmd("cypress", &["info"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_cypress_verify_allows() {
        let result = check_devtools(&cmd("cypress", &["verify"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_cypress_install_asks() {
        let result = check_devtools(&cmd("cypress", &["install"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === wrangler ===

    #[test]
    fn test_wrangler_whoami_allows() {
        let result = check_devtools(&cmd("wrangler", &["whoami"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_wrangler_tail_allows() {
        let result = check_devtools(&cmd("wrangler", &["tail"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_wrangler_dev_asks() {
        let result = check_devtools(&cmd("wrangler", &["dev"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_wrangler_deploy_asks() {
        let result = check_devtools(&cmd("wrangler", &["deploy"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_wrangler_publish_asks() {
        let result = check_devtools(&cmd("wrangler", &["publish"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_wrangler_login_asks() {
        let result = check_devtools(&cmd("wrangler", &["login"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === Ty (Python type checker) ===

    #[test]
    fn test_ty_check_allows() {
        let result = check_devtools(&cmd("ty", &["check"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_ty_bare_allows() {
        let result = check_devtools(&cmd("ty", &[]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_ty_add_ignore_asks() {
        let result = check_devtools(&cmd("ty", &["check", "--add-ignore"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === Markdownlint ===

    #[test]
    fn test_markdownlint_allows() {
        let result = check_devtools(&cmd("markdownlint", &["**/*.md"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_markdownlint_fix_asks() {
        let result = check_devtools(&cmd("markdownlint", &["--fix", "README.md"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_markdownlint_f_short_asks() {
        let result = check_devtools(&cmd("markdownlint", &["-f", "README.md"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === Media / diagrams ===

    #[test]
    fn test_ffprobe_allows() {
        let result = check_devtools(&cmd("ffprobe", &["-show_streams", "clip.mp4"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_d2_render_allows() {
        let result = check_devtools(&cmd("d2", &["diagram.d2", "out.svg"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_ffmpeg_version_allows() {
        let result = check_devtools(&cmd("ffmpeg", &["-version"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_ffmpeg_transcode_asks() {
        let result = check_devtools(&cmd("ffmpeg", &["-i", "in.mp4", "out.webm"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === Non-devtools ===

    #[test]
    fn test_non_devtools_skips() {
        let result = check_devtools(&cmd("git", &["status"]));
        assert_eq!(result.decision, Decision::Skip);
    }
}

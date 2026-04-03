//! Developer tools permission gate.
//!
//! Mostly declarative via rules/devtools.toml.
//!
//! Custom handler for `sd`: without file args it's a stdin→stdout pipe
//! filter (safe), with file args it modifies files in-place (ask).

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

    // sd FIND REPLACE [FILES...] — 2 positional = pipe mode, 3+ = file mode
    if positional <= 2 {
        GateResult::allow()
    } else {
        GateResult::ask("sd: In-place text replacement")
    }
}

/// Check developer tools that can modify files.
pub fn check_devtools(cmd: &CommandInfo) -> GateResult {
    let result = check_devtools_gate(cmd);
    if result.decision == Decision::Skip && cmd.program == "sd" {
        return check_sd(cmd);
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

    // === Non-devtools ===

    #[test]
    fn test_non_devtools_skips() {
        let result = check_devtools(&cmd("git", &["status"]));
        assert_eq!(result.decision, Decision::Skip);
    }
}

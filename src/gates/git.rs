//! Git command permission gate.
//!
//! Mostly declarative via rules/git.toml, with two custom handlers:
//!
//! 1. `extract_subcommand` - Skip global options (-C, --git-dir, -c, etc.)
//!    to find the actual git subcommand. This is necessary because git
//!    allows global options before the subcommand, and TOML can't express
//!    "skip N flags then match subcommand".
//!
//! 2. `check_git_add` - Special handling for git add with -A/--all, ., and
//!    wildcards. These require checking argument values, not just flags,
//!    which TOML can't express. Each case gets a different reason:
//!    - `-A/--all` -> "Staging all files"
//!    - `.` -> "Staging directory"
//!    - `*` in args -> "Staging with wildcard"
//!    - otherwise -> "Staging files"
//!
//! Everything else (checkout -b/-B, checkout --, push --force-with-lease,
//! config subcommands, etc.) is handled declaratively via TOML rules.

use crate::generated::rules::{GIT_ALLOW, GIT_ASK, check_git_declarative};
use crate::git_aliases::{self, Resolved};
use crate::models::{CommandInfo, GateResult};
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

/// Git global options that take a value (must skip arg + value)
pub(crate) static GLOBAL_OPTS_WITH_VALUE: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "-C",
        "-c",
        "--git-dir",
        "--work-tree",
        "--namespace",
        "--super-prefix",
        "--config-env",
        "--exec-path",
        "--list-cmds",
    ]
    .into_iter()
    .collect()
});

/// Git global flags (single flags, no value)
pub(crate) static GLOBAL_FLAGS: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "--bare",
        "--no-replace-objects",
        "--literal-pathspecs",
        "--glob-pathspecs",
        "--noglob-pathspecs",
        "--icase-pathspecs",
        "--no-optional-locks",
        "--paginate",
        "-p",
        "--no-pager",
        "-P",
        "--html-path",
        "--man-path",
        "--info-path",
    ]
    .into_iter()
    .collect()
});

/// Skip git global options to find the actual subcommand.
fn extract_subcommand(args: &[String]) -> Option<(usize, &str)> {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();

        // Options that take a value: -C <path>, -c <key=value>, etc.
        if GLOBAL_OPTS_WITH_VALUE.contains(arg) {
            i += 2;
            continue;
        }

        // Combined form: --git-dir=<path>
        if GLOBAL_OPTS_WITH_VALUE
            .iter()
            .any(|opt| arg.starts_with(&format!("{opt}=")))
        {
            i += 1;
            continue;
        }

        // Short form combined: -C/path (without space)
        if arg.starts_with("-C") && arg.len() > 2 {
            i += 1;
            continue;
        }

        // Single flags without values
        if GLOBAL_FLAGS.contains(arg) {
            i += 1;
            continue;
        }

        // Unknown flags
        if arg.starts_with('-') {
            if matches!(arg, "--version" | "-v" | "--help" | "-h") {
                return Some((i, arg));
            }
            i += 1;
            continue;
        }

        // Found non-flag argument - this is the subcommand
        return Some((i, arg));
    }
    None
}

/// Check git command.
pub fn check_git(cmd: &CommandInfo) -> GateResult {
    let config = crate::config::get();
    if !config.features.git_aliases {
        // Alias resolution disabled. Empty map -> no alias ever resolves;
        // the gate falls through to the existing TOML behavior.
        return check_git_with_alias_map(cmd, &HashMap::new());
    }
    if config.git_aliases.include_local_repo {
        // Merge global + local; local entries shadow global by name.
        let mut merged: HashMap<String, String> = git_aliases::GLOBAL_ALIASES.clone();
        let local = git_aliases::load_local_aliases(".");
        for (k, v) in local {
            merged.insert(k, v);
        }
        return check_git_with_alias_map(cmd, &merged);
    }
    check_git_with_alias_map(cmd, &git_aliases::GLOBAL_ALIASES)
}

/// Test entry point that lets callers inject a synthetic alias map. Production
/// always goes through [`check_git`], which uses the cached `~/.gitconfig`
/// map. Tests use this to exercise resolution without touching the real
/// gitconfig.
pub fn check_git_with_alias_map(
    cmd: &CommandInfo,
    alias_map: &HashMap<String, String>,
) -> GateResult {
    if cmd.program != "git" {
        return GateResult::skip();
    }

    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::allow();
    }

    // Check for --dry-run first (makes any command safe)
    if args.iter().any(|a| a == "--dry-run" || a == "-n") {
        return GateResult::allow();
    }

    // Extract the actual subcommand, skipping global options
    let Some((subcmd_idx, subcommand)) = extract_subcommand(args) else {
        return GateResult::allow();
    };

    // Build normalized args (subcommand + its args, without global opts)
    let normalized_args: Vec<String> = args.iter().skip(subcmd_idx).cloned().collect();

    // Special case: git add with wildcards, --all, or . (complex logic)
    if subcommand == "add" {
        return check_git_add(&normalized_args);
    }

    // git tag with a positional argument (not a flag) is creating a lightweight tag
    // TOML can't express "has positional args beyond subcommand", so handle here
    if subcommand == "tag" && normalized_args.len() > 1 {
        let has_no_flags = !normalized_args[1..].iter().any(|a| a.starts_with('-'));
        if has_no_flags {
            return GateResult::ask("Creating tag");
        }
    }

    // Built-ins win over aliases. If the TOML knows this subcommand at the
    // single-token level (allow or ask, including flag-conditional), apply
    // its rule directly. Compound-only entries like `config get` slip
    // through this check, but conflicts there require an alias named after
    // a real git command (`alias.config = ...`), which is rare enough to
    // accept as a divergence.
    let known_builtin = GIT_ALLOW.contains(subcommand)
        || GIT_ASK.contains_key(subcommand)
        || matches!(subcommand, "branch" | "tag");

    let normalized_cmd = CommandInfo {
        program: cmd.program.clone(),
        args: normalized_args.clone(),
        raw: cmd.raw.clone(),
    };

    if !known_builtin && let Some(resolved) = git_aliases::resolve_with_map(subcommand, alias_map) {
        match resolved {
            Resolved::Tokens(tokens) => {
                let mut new_args = tokens;
                new_args.extend(normalized_args.iter().skip(1).cloned());
                let rewritten = CommandInfo {
                    program: cmd.program.clone(),
                    args: new_args,
                    raw: cmd.raw.clone(),
                };
                return check_git_declarative(&rewritten)
                    .unwrap_or_else(|| GateResult::ask(format!("git: alias {subcommand}")));
            }
            Resolved::Shell => {
                return GateResult::ask(format!("git: shell alias {subcommand}"));
            }
        }
    }

    // Use declarative rules for everything else
    // Note: checkout -b/-B, checkout --, and push --force-with-lease are handled
    // declaratively via TOML rules with if_flags_any
    check_git_declarative(&normalized_cmd)
        .unwrap_or_else(|| GateResult::ask(format!("git: {subcommand}")))
}

/// Check git add for dangerous patterns.
fn check_git_add(args: &[String]) -> GateResult {
    if args
        .iter()
        .any(|a| matches!(a.as_str(), "-A" | "--all" | "-a"))
    {
        return GateResult::ask("git: Staging all files");
    }
    if args.iter().any(|a| a == ".") {
        return GateResult::ask("git: Staging directory");
    }
    if args.iter().skip(1).any(|a| a.contains('*')) {
        return GateResult::ask("git: Staging with wildcard");
    }
    GateResult::ask("git: Staging files")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::test_utils::cmd as make_cmd;
    use crate::models::Decision;

    fn cmd(args: &[&str]) -> CommandInfo {
        make_cmd("git", args)
    }

    // === Read Commands ===

    #[test]
    fn test_read_commands_allow() {
        let read_cmds = [
            &["status"][..],
            &["log"],
            &["log", "--oneline", "-10"],
            &["diff"],
            &["diff", "HEAD~1"],
            &["diff", "--staged"],
            &["show", "HEAD"],
            &["branch"],
            &["branch", "-a"],
            &["branch", "-v"],
            &["branch", "--list"],
            &["tag"],
            &["tag", "-l"],
            &["remote", "-v"],
            &["remote", "show", "origin"],
            &["stash", "list"],
            &["stash", "show"],
            &["describe"],
            &["rev-parse", "HEAD"],
            &["ls-files"],
            &["blame", "file.txt"],
            &["reflog"],
            &["--version"],
            &["help"],
            &["check-ignore", "-v", "CLAUDE.md"],
            &["check-attr", "diff", "README"],
            &["grep", "TODO"],
            &["merge-base", "main", "HEAD"],
            &["show-ref"],
        ];

        for args in read_cmds {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    // === Write Commands ===

    #[test]
    fn test_write_commands_ask() {
        let write_cmds = [
            (&["add", "file.txt"][..], "Staging"),
            (&["add", "."], "Staging directory"),
            (&["add", "-A"], "Staging all"),
            (&["commit", "-m", "message"], "Committing"),
            (&["push", "origin", "main"], "Pushing"),
            (&["pull", "origin", "main"], "Pulling"),
            (&["merge", "feature"], "Merging"),
            (&["rebase", "main"], "Rebasing"),
            (&["checkout", "feature"], "Checking out"),
            (&["checkout", "-b", "new-branch"], "Creating branch"),
            (&["switch", "main"], "Switching"),
            (&["reset", "HEAD~1"], "Resetting"),
            (&["restore", "file.txt"], "Restoring"),
            (&["cherry-pick", "abc123"], "Cherry-picking"),
            (&["revert", "abc123"], "Reverting"),
            (&["fetch", "origin"], "Fetching"),
            (&["clone", "https://github.com/user/repo"], "Cloning"),
            (&["mv", "old.txt", "new.txt"], "Moving"),
            (&["rm", "file.txt"], "Removing"),
            (&["branch", "-d", "old-branch"], "Deleting branch"),
            (&["branch", "-m", "old", "new"], "Renaming branch"),
        ];

        for (args, expected_in_reason) in write_cmds {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
            assert!(
                result
                    .reason
                    .as_ref()
                    .unwrap()
                    .to_lowercase()
                    .contains(&expected_in_reason.to_lowercase()),
                "Expected '{}' in reason for {:?}, got: {:?}",
                expected_in_reason,
                args,
                result.reason
            );
        }
    }

    // === High Risk Commands ===

    #[test]
    fn test_high_risk_asks_with_warning() {
        let high_risk_cmds = [
            (&["push", "--force", "origin", "main"][..], "Force push"),
            (&["push", "-f", "origin", "main"], "Force push"),
            (&["reset", "--hard", "HEAD~1"], "Hard reset"),
            (&["clean", "-fd"], "Clean"),
            (&["clean", "-fdx"], "Clean"),
        ];

        for (args, expected_in_reason) in high_risk_cmds {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
            assert!(
                result.reason.as_ref().unwrap().contains(expected_in_reason),
                "Expected '{}' in reason for {:?}, got: {:?}",
                expected_in_reason,
                args,
                result.reason
            );
        }
    }

    // === Force with Lease (Safe Alternative) ===

    #[test]
    fn test_force_with_lease_not_flagged_as_force() {
        let safe_force_cmds = [
            &["push", "--force-with-lease"][..],
            &["push", "--force-with-lease", "origin", "main"],
            &["push", "origin", "main", "--force-with-lease"],
            &["-C", "/path", "push", "--force-with-lease"],
        ];

        for args in safe_force_cmds {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
            let reason = result.reason.as_ref().unwrap();
            assert!(
                !reason.contains("Force push"),
                "Should not warn about force push for {:?}, got: {}",
                args,
                reason
            );
            assert!(
                reason.contains("Pushing"),
                "Should mention pushing for {:?}",
                args
            );
        }
    }

    // === Dry Run ===

    #[test]
    fn test_dry_run_allows() {
        let dry_run_cmds = [
            &["push", "--dry-run", "origin", "main"][..],
            &["clean", "-fd", "--dry-run"],
            &["add", "--dry-run", "."],
        ];

        for args in dry_run_cmds {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    // === Config Subcommand ===

    #[test]
    fn test_config_read_allows() {
        let config_read = [
            &["config", "--get", "user.name"][..],
            &["config", "--list"],
            &["config", "get", "user.email"],
            &["config", "list"],
        ];

        for args in config_read {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_config_write_asks() {
        let config_write = [
            &["config", "set", "user.name", "Test"][..],
            &["config", "--add", "alias.st", "status"],
            &["config", "--unset", "alias.st"],
        ];

        for args in config_write {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
        }
    }

    // === Global Options ===

    #[test]
    fn test_global_opts_with_read_allows() {
        let global_read = [
            &["-C", "/path/to/repo", "status"][..],
            &["-C", "/home/user/project", "log"],
            &["-C", "/tmp", "log", "--oneline", "-10"],
            &["-C", "/path", "diff"],
            &["-C", "/path", "branch", "-a"],
            &["-C", "/path", "remote", "-v"],
            &["--git-dir=/path/.git", "status"],
            &["--git-dir", "/path/.git", "log"],
            &["--work-tree=/path", "status"],
            &["--work-tree", "/path", "diff"],
            &["-C", "/path", "--git-dir=/path/.git", "status"],
            &["--bare", "log"],
            &["-c", "user.name=Test", "status"],
            &["-C", "/tmp/project", "status"],
            &["-C", "/tmp/project", "log", "--oneline"],
        ];

        for args in global_read {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_global_opts_with_write_asks() {
        let global_write = [
            (&["-C", "/path", "commit", "-m", "msg"][..], "Committing"),
            (&["-C", "/path", "push", "origin", "main"], "Pushing"),
            (&["-C", "/path", "add", "file.txt"], "Staging"),
            (&["-C", "/path", "checkout", "branch"], "Checking out"),
            (
                &["--git-dir=/path/.git", "commit", "-m", "msg"],
                "Committing",
            ),
            (&["--git-dir", "/path/.git", "push"], "Pushing"),
            (&["-C", "/path", "push", "--force"], "Force push"),
            (&["-C", "/path", "reset", "--hard"], "Hard reset"),
            (
                &["-C", "/home/user/project", "add", "."],
                "Staging directory",
            ),
            (
                &["-C", "/home/user/project", "branch", "-d", "old"],
                "Deleting branch",
            ),
        ];

        for (args, expected_in_reason) in global_write {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
            assert!(
                result
                    .reason
                    .as_ref()
                    .unwrap()
                    .to_lowercase()
                    .contains(&expected_in_reason.to_lowercase()),
                "Expected '{}' in reason for {:?}, got: {:?}",
                expected_in_reason,
                args,
                result.reason
            );
        }
    }

    #[test]
    fn test_global_opts_with_dry_run_allows() {
        let dry_run = [
            &["-C", "/path", "push", "--dry-run"][..],
            &["-C", "/path", "add", "--dry-run", "."],
            &["--git-dir=/path/.git", "clean", "-fd", "--dry-run"],
        ];

        for args in dry_run {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_only_global_opts_no_subcommand_allows() {
        let result = check_git(&cmd(&["-C", "/path"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === Tag Commands ===

    #[test]
    fn test_tag_list_allows() {
        let read_cmds = [
            &["tag"][..],
            &["tag", "-l"],
            &["tag", "-l", "v*"],
            &["tag", "--list"],
        ];

        for args in read_cmds {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_tag_create_lightweight_asks() {
        let result = check_git(&cmd(&["tag", "v1.0"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Creating tag"));
    }

    #[test]
    fn test_tag_create_annotated_asks() {
        let create_cmds = [
            &["tag", "-a", "v1.0", "-m", "release"][..],
            &["tag", "--annotate", "v1.0", "-m", "release"],
            &["tag", "-s", "v1.0", "-m", "signed release"],
            &["tag", "--sign", "v1.0"],
            &["tag", "-u", "KEYID", "v1.0"],
            &["tag", "--local-user", "KEYID", "v1.0"],
            &["tag", "-m", "message", "v1.0"],
            &["tag", "--message", "message", "v1.0"],
        ];

        for args in create_cmds {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_tag_delete_asks() {
        let delete_cmds = [&["tag", "-d", "v1.0"][..], &["tag", "--delete", "v1.0"]];

        for args in delete_cmds {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
            assert!(result.reason.as_ref().unwrap().contains("Deleting tag"));
        }
    }

    #[test]
    fn test_tag_force_asks() {
        let force_cmds = [&["tag", "-f", "v1.0"][..], &["tag", "--force", "v1.0"]];

        for args in force_cmds {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
            assert!(
                result
                    .reason
                    .as_ref()
                    .unwrap()
                    .contains("Force-replacing tag")
            );
        }
    }

    #[test]
    fn test_tag_with_global_opts_asks() {
        let result = check_git(&cmd(&["-C", "/path", "tag", "-d", "v1.0"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Deleting tag"));
    }

    // === Non-git Commands ===

    #[test]
    fn test_non_git_skips() {
        let result = check_git(&make_cmd("gh", &["pr", "list"]));
        assert_eq!(result.decision, Decision::Skip);
    }

    // === Aliases ===

    fn alias_map(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn test_alias_to_status_allows() {
        let m = alias_map(&[("st", "status")]);
        let result = check_git_with_alias_map(&cmd(&["st"]), &m);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_alias_to_log_allows() {
        let m = alias_map(&[("lg", "log --oneline -10")]);
        let result = check_git_with_alias_map(&cmd(&["lg"]), &m);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_alias_strips_c_prefix_and_allows() {
        let m = alias_map(&[("astatus", "-c color.ui=false status --short")]);
        let result = check_git_with_alias_map(&cmd(&["astatus"]), &m);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_alias_to_checkout_asks() {
        let m = alias_map(&[("co", "checkout")]);
        let result = check_git_with_alias_map(&cmd(&["co", "main"]), &m);
        assert_eq!(result.decision, Decision::Ask);
        assert!(
            result
                .reason
                .as_ref()
                .unwrap()
                .to_lowercase()
                .contains("checking out"),
            "expected 'Checking out', got: {:?}",
            result.reason
        );
    }

    #[test]
    fn test_alias_to_commit_asks() {
        let m = alias_map(&[("ci", "commit")]);
        let result = check_git_with_alias_map(&cmd(&["ci", "-m", "msg"]), &m);
        assert_eq!(result.decision, Decision::Ask);
        assert!(
            result
                .reason
                .as_ref()
                .unwrap()
                .to_lowercase()
                .contains("committing"),
            "expected 'Committing', got: {:?}",
            result.reason
        );
    }

    #[test]
    fn test_alias_to_reset_asks() {
        let m = alias_map(&[("unstage", "reset HEAD --")]);
        let result = check_git_with_alias_map(&cmd(&["unstage", "file.txt"]), &m);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_shell_alias_asks() {
        let m = alias_map(&[("deploy", "!./deploy.sh")]);
        let result = check_git_with_alias_map(&cmd(&["deploy"]), &m);
        assert_eq!(result.decision, Decision::Ask);
        assert!(
            result
                .reason
                .as_ref()
                .unwrap()
                .to_lowercase()
                .contains("shell alias"),
            "expected 'shell alias', got: {:?}",
            result.reason
        );
    }

    #[test]
    fn test_alias_with_global_opts_composes() {
        let m = alias_map(&[("st", "status")]);
        let result = check_git_with_alias_map(&cmd(&["-C", "/path", "st"]), &m);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_builtin_wins_over_alias_for_status() {
        // alias.status = log -- built-in 'status' wins, returns Allow as status.
        let m = alias_map(&[("status", "log")]);
        let result = check_git_with_alias_map(&cmd(&["status"]), &m);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_builtin_wins_over_alias_for_commit() {
        // alias.commit = log -- built-in 'commit' wins, asks "Committing".
        let m = alias_map(&[("commit", "log")]);
        let result = check_git_with_alias_map(&cmd(&["commit", "-m", "x"]), &m);
        assert_eq!(result.decision, Decision::Ask);
        assert!(
            result
                .reason
                .as_ref()
                .unwrap()
                .to_lowercase()
                .contains("committing"),
            "Built-in commit should win, got: {:?}",
            result.reason
        );
    }

    #[test]
    fn test_unknown_subcommand_no_alias_falls_through_to_ask() {
        // No alias defined for "totally-unknown" -- existing fallback path.
        let m = alias_map(&[]);
        let result = check_git_with_alias_map(&cmd(&["totally-unknown"]), &m);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_dry_run_short_circuits_alias() {
        let m = alias_map(&[("co", "checkout")]);
        let result = check_git_with_alias_map(&cmd(&["co", "main", "--dry-run"]), &m);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_chained_alias_resolves() {
        let m = alias_map(&[("a", "b"), ("b", "status")]);
        let result = check_git_with_alias_map(&cmd(&["a"]), &m);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_user_args_appended_after_alias_body() {
        // alias.lg = log --oneline; "git lg --author=me" should resolve to
        // "log --oneline --author=me".
        let m = alias_map(&[("lg", "log --oneline")]);
        let result = check_git_with_alias_map(&cmd(&["lg", "--author=me"]), &m);
        assert_eq!(result.decision, Decision::Allow);
    }
}

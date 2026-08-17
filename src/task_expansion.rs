//! Mise / package.json task expansion: resolve `mise run <task>` and
//! `npm run <script>` to their underlying commands and re-check them.

use crate::accept_edits::should_auto_allow_in_accept_edits;
use crate::gates::check_single_command;
use crate::mise::{extract_task_commands, find_mise_config, load_mise_config};
use crate::models::{Client, Decision, HookOutput, PermissionDecision, is_auto_mode};
use crate::package_json::{
    find_package_json, get_script_command, load_package_json, parse_script_invocation,
};
use crate::parser::extract_commands;
use crate::raw_floor::check_raw_floor;
use crate::router::gate_ask_output_for_mode;
use crate::settings::Settings;

/// Check a mise task by expanding it to its underlying commands.
///
/// Finds the mise config file, extracts the task's run commands (including dependencies),
/// and checks each command through the gate engine.
/// - `task_name`: The task name (e.g., "lint", "build:prod")
/// - `permission_mode`: The permission mode (e.g., "default", "acceptEdits")
/// - `client`: carries the caller's settings source policy into the expansion,
///   so a nested check cannot reload under a weaker one
pub(crate) fn check_mise_task(
    task_name: &str,
    cwd: &str,
    permission_mode: &str,
    client: Client,
) -> HookOutput {
    // Find mise config file
    let Some(config_path) = find_mise_config(cwd) else {
        return HookOutput::ask(&format!("mise {task_name}: No mise.toml found"));
    };

    // Load and parse the config
    let Some(config) = load_mise_config(&config_path) else {
        return HookOutput::ask(&format!("mise {task_name}: Failed to parse mise.toml"));
    };

    // Extract all commands for this task (including dependencies)
    let commands = extract_task_commands(&config, task_name);

    if commands.is_empty() {
        return HookOutput::ask(&format!(
            "mise {task_name}: Task not found or has no commands"
        ));
    }

    // Check each command through the gate engine
    let mut block_reasons: Vec<String> = Vec::new();
    let mut block_recoveries = Vec::new();
    let mut ask_reasons: Vec<String> = Vec::new();
    // One irreversible command anywhere in the task holds the whole task's ask.
    let mut hold_in_auto = false;

    for cmd_string in &commands {
        // Check each extracted command, with package.json expansion support
        let result = check_command_expanded(cmd_string, cwd, permission_mode, client);

        match result.decision {
            PermissionDecision::Deny => {
                let reason = result.reason.as_deref().unwrap_or("Blocked");
                block_reasons.push(format!("mise {task_name}: {reason}"));
                block_recoveries.extend(result.recovery_actions);
            }
            // Defer means approval is still needed; under auto the inner check
            // returns Defer where it used to return Ask, so folding it into the
            // ignored arm would silently allow the whole task.
            PermissionDecision::Ask | PermissionDecision::Defer => {
                let reason = result.reason.as_deref().unwrap_or("Requires approval");
                ask_reasons.push(format!("mise {task_name}: {reason}"));
                hold_in_auto |= result.hold_in_auto;
            }
            PermissionDecision::Allow | PermissionDecision::Approve => {}
        }
    }

    // Apply priority: block > ask > allow
    if !block_reasons.is_empty() {
        let combined = if block_reasons.len() == 1 {
            block_reasons.remove(0)
        } else {
            block_reasons.join("; ")
        };
        return HookOutput::deny(&combined).with_recoveries(block_recoveries);
    }

    if !ask_reasons.is_empty() {
        let combined = if ask_reasons.len() == 1 {
            ask_reasons.remove(0)
        } else {
            ask_reasons.join("; ")
        };
        // Match the top-level ask/defer behavior for `mise <task>` shapes too.
        // If any expanded command holds its ask under auto, the task does too.
        return gate_ask_output_for_mode(combined, None, permission_mode, false, hold_in_auto);
    }

    // All commands are safe
    HookOutput::allow(Some(&format!("mise {task_name}: All commands safe")))
}

/// Check a package.json script by expanding it to its underlying command.
///
/// Finds package.json, extracts the script's command, and checks it through the gate engine.
/// - `pm`: The package manager name (e.g., "pnpm", "npm")
/// - `script_name`: The script name (e.g., "lint", "build")
/// - `permission_mode`: The permission mode (e.g., "default", "acceptEdits")
pub(crate) fn check_package_script(
    pm: &str,
    script_name: &str,
    cwd: &str,
    permission_mode: &str,
    client: Client,
) -> HookOutput {
    // Find package.json
    let Some(pkg_path) = find_package_json(cwd) else {
        // No package.json found - fall back to normal gate check
        // This handles cases like running in a subdirectory
        return HookOutput::ask(&format!("{pm} run {script_name}: No package.json found"));
    };

    // Load and parse package.json
    let Some(pkg) = load_package_json(&pkg_path) else {
        return HookOutput::ask(&format!(
            "{pm} run {script_name}: Failed to parse package.json"
        ));
    };

    // Get the script command
    let Some(script_cmd) = get_script_command(&pkg, script_name) else {
        return HookOutput::ask(&format!("{pm} run {script_name}: Script not found"));
    };

    // Check the underlying command through the gate engine. Use the mode-aware
    // entry point so raw-string hard-ask patterns (pipe-to-shell, eval) get
    // promoted to deny under auto mode -- matches check_mise_task behavior.
    let result = check_command_expanded(&script_cmd, cwd, permission_mode, client);

    match result.decision {
        PermissionDecision::Deny => {
            let reason = result.reason.as_deref().unwrap_or("Blocked");
            HookOutput::deny(&format!("{pm} run {script_name}: {reason}"))
                .with_recoveries(result.recovery_actions)
        }
        PermissionDecision::Ask => {
            // In acceptEdits mode, check if the underlying command is a file-editing command
            if permission_mode == "acceptEdits" {
                let commands = extract_commands(&script_cmd);
                let settings = Settings::load(client, cwd);
                let allowed_dirs = settings.allowed_directories(cwd);
                if should_auto_allow_in_accept_edits(&commands, &allowed_dirs) {
                    return HookOutput::allow(Some(&format!(
                        "{pm} run {script_name}: Auto-allowed in acceptEdits mode"
                    )));
                }
            }

            let reason = result.reason.as_deref().unwrap_or("Requires approval");
            // Match the top-level ask/defer behavior for `pnpm <script>` /
            // `npm run <script>` shapes too.
            gate_ask_output_for_mode(
                format!("{pm} run {script_name}: {reason}"),
                None,
                permission_mode,
                false,
                result.hold_in_auto,
            )
        }
        PermissionDecision::Allow => HookOutput::allow(Some(&format!(
            "{pm} run {script_name}: {}",
            result.reason.as_deref().unwrap_or("Safe")
        ))),
        PermissionDecision::Approve => {
            // Approve means passthrough. Treat as safe
            HookOutput::allow(Some(&format!("{pm} run {script_name}: Safe")))
        }
        PermissionDecision::Defer => {
            // Preserve defer for wrapper prompt UX. Claude Code checks the
            // wrapper command, not the expanded script body, so these do not
            // hit its Bash acceptEdits auto-allow list.
            let reason = result.reason.as_deref().unwrap_or("Requires approval");
            gate_ask_output_for_mode(
                format!("{pm} run {script_name}: {reason}"),
                None,
                permission_mode,
                false,
                result.hold_in_auto,
            )
        }
    }
}

/// Check a command with package.json script expansion.
/// Used by mise task expansion to handle commands like "pnpm lint" properly.
pub(crate) fn check_command_expanded(
    command_string: &str,
    cwd: &str,
    permission_mode: &str,
    client: Client,
) -> HookOutput {
    if command_string.trim().is_empty() {
        return HookOutput::no_opinion();
    }

    // First do raw string security checks. Hard-deny patterns short-circuit;
    // hard-ask patterns promote to deny under auto mode (see
    // `check_command_with_settings_and_session` for rationale).
    //
    let raw_checks = check_raw_floor(command_string);
    if let Some(output) = raw_checks.hard_deny {
        return output;
    }
    // hard-ask is force-promptable (force_ask on Antigravity); soft asks stay overridable.
    if let Some(output) = raw_checks.hard_ask.map(HookOutput::forced) {
        if is_auto_mode(permission_mode) {
            return HookOutput::deny(
                &output
                    .reason
                    .unwrap_or_else(|| "Dangerous pattern not allowed in auto mode".to_string()),
            );
        }
        return output;
    }
    if let Some(output) = raw_checks.soft_ask {
        return output;
    }

    // Parse the command with tree-sitter to extract individual commands
    let commands = extract_commands(command_string);

    if commands.is_empty() {
        return HookOutput::ask(&format!("Unknown command: {command_string}"));
    }

    // Check each parsed command, tracking cwd changes from "cd" commands
    let mut block_reasons: Vec<String> = Vec::new();
    let mut block_recoveries = Vec::new();
    let mut ask_reasons: Vec<String> = Vec::new();
    let mut hold_in_auto = false;
    let mut effective_cwd = std::path::PathBuf::from(cwd);

    for cmd in &commands {
        // Track "cd" commands to update effective cwd
        if cmd.program == "cd" && !cmd.args.is_empty() {
            let target = &cmd.args[0];
            if !target.starts_with('/') {
                // Relative path
                effective_cwd.push(target);
            } else {
                // Absolute path
                effective_cwd = std::path::PathBuf::from(target);
            }
            continue; // cd itself is always safe
        }

        let cwd_str = effective_cwd.to_string_lossy();
        // Try package.json script expansion for this individual command
        if let Some((pm, script_name)) = parse_script_invocation(&cmd.raw) {
            let result = check_package_script(pm, &script_name, &cwd_str, permission_mode, client);
            match result.decision {
                PermissionDecision::Deny => {
                    block_reasons.push(result.reason.unwrap_or_else(|| "Blocked".to_string()));
                    block_recoveries.extend(result.recovery_actions);
                }
                // Defer is an approval-needed outcome exactly like Ask -- under
                // auto mode the inner check produces Defer rather than Ask, and
                // treating it as "nothing to report" would let a nested script
                // collapse to a blanket allow.
                PermissionDecision::Ask | PermissionDecision::Defer => {
                    hold_in_auto |= result.hold_in_auto;
                    ask_reasons.push(
                        result
                            .reason
                            .unwrap_or_else(|| "Requires approval".to_string()),
                    );
                }
                PermissionDecision::Allow | PermissionDecision::Approve => {}
            }
        } else {
            // Run through gates
            let result = check_single_command(cmd);
            match result.decision {
                Decision::Block => {
                    block_reasons.push(result.reason.unwrap_or_else(|| "Blocked".to_string()));
                }
                Decision::Ask => {
                    // In acceptEdits mode, check if this is a file-editing command
                    if permission_mode == "acceptEdits" {
                        let settings = Settings::load(client, &cwd_str);
                        let allowed_dirs = settings.allowed_directories(&cwd_str);
                        if should_auto_allow_in_accept_edits(
                            std::slice::from_ref(cmd),
                            &allowed_dirs,
                        ) {
                            // Auto-allow file-editing command in acceptEdits mode
                            continue;
                        }
                    }
                    hold_in_auto |= result.hold_in_auto;
                    ask_reasons.push(
                        result
                            .reason
                            .unwrap_or_else(|| "Requires approval".to_string()),
                    );
                }
                Decision::Allow => {}
                Decision::Skip => {
                    ask_reasons.push(format!("Unknown command: {}", cmd.program));
                }
            }
        }
    }

    // Apply priority: block > ask > allow
    if !block_reasons.is_empty() {
        let combined = if block_reasons.len() == 1 {
            block_reasons.remove(0)
        } else {
            block_reasons.join("; ")
        };
        return HookOutput::deny(&combined).with_recoveries(block_recoveries);
    }

    if !ask_reasons.is_empty() {
        let combined = if ask_reasons.len() == 1 {
            ask_reasons.remove(0)
        } else {
            ask_reasons.join("; ")
        };
        let mut output = HookOutput::ask(&combined);
        output.hold_in_auto = hold_in_auto;
        return output;
    }

    HookOutput::allow(None)
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::models::*;
    #[allow(unused_imports)]
    use crate::parser::*;
    use crate::recovery::{FileSelection, RecoveryAction};
    #[allow(unused_imports)]
    use crate::router::tests::{get_claude_wire_decision, get_decision, get_reason};
    #[allow(unused_imports)]
    use crate::router::*;
    #[allow(unused_imports)]
    use crate::{
        accept_edits::*, paths::*, pipe_caps::*, scratch::*, security_floor::*, task_expansion::*,
    };

    mod mise_tasks {
        use super::*;
        use crate::mise::{extract_task_commands, parse_mise_invocation, parse_mise_toml_str};

        #[test]
        fn test_parse_mise_run_task() {
            assert_eq!(
                parse_mise_invocation("mise run test"),
                Some("test".to_string())
            );
            assert_eq!(
                parse_mise_invocation("mise run lint:fix"),
                Some("lint:fix".to_string())
            );
        }

        #[test]
        fn test_parse_mise_shorthand() {
            assert_eq!(
                parse_mise_invocation("mise build"),
                Some("build".to_string())
            );
            assert_eq!(
                parse_mise_invocation("mise dev:frontend"),
                Some("dev:frontend".to_string())
            );
        }

        #[test]
        fn test_parse_mise_subcommands_not_tasks() {
            // These are mise built-in subcommands, not tasks
            assert_eq!(parse_mise_invocation("mise install"), None);
            assert_eq!(parse_mise_invocation("mise use node@20"), None);
            assert_eq!(parse_mise_invocation("mise ls"), None);
            assert_eq!(parse_mise_invocation("mise exec -- node"), None);
        }

        #[test]
        fn test_extract_safe_task_commands() {
            let toml = r#"
[tasks.status]
run = "git status"
"#;
            let config = parse_mise_toml_str(toml).unwrap();
            let commands = extract_task_commands(&config, "status");
            assert_eq!(commands, vec!["git status"]);

            // The underlying command is safe
            let result = check_command(&commands[0]);
            assert_eq!(get_decision(&result), "allow");
        }

        #[test]
        fn test_extract_risky_task_commands() {
            let toml = r#"
[tasks.deploy]
run = "npm publish"
"#;
            let config = parse_mise_toml_str(toml).unwrap();
            let commands = extract_task_commands(&config, "deploy");

            // The underlying command requires approval
            let result = check_command(&commands[0]);
            assert_eq!(get_decision(&result), "ask");
        }

        #[test]
        fn test_extract_blocked_task_commands() {
            let toml = r#"
[tasks.danger]
run = "rm -rf /"
"#;
            let config = parse_mise_toml_str(toml).unwrap();
            let commands = extract_task_commands(&config, "danger");

            // The underlying command is blocked
            let result = check_command(&commands[0]);
            assert_eq!(get_decision(&result), "deny");
        }

        #[test]
        fn test_task_with_depends_checks_all() {
            let toml = r#"
[tasks.build]
run = "npm run build"

[tasks.test]
run = "npm run test"
depends = ["build"]

[tasks.ci]
run = "npm publish"
depends = ["test"]
"#;
            let config = parse_mise_toml_str(toml).unwrap();
            let commands = extract_task_commands(&config, "ci");

            // Should include all commands from dependency chain
            assert_eq!(commands.len(), 3);

            // All npm commands require approval
            for cmd in &commands {
                let result = check_command(cmd);
                assert_eq!(get_decision(&result), "ask", "Failed for: {cmd}");
            }
        }

        #[test]
        fn test_task_with_dir_prepends_cd() {
            let toml = r#"
[tasks."dev:web"]
dir = "frontend"
run = "pnpm dev"
"#;
            let config = parse_mise_toml_str(toml).unwrap();
            let commands = extract_task_commands(&config, "dev:web");

            assert_eq!(commands.len(), 1);
            assert!(commands[0].starts_with("cd frontend &&"));
        }

        #[test]
        fn test_mise_settings_allow_bypasses_expansion() {
            // Create temp dir with mise.toml containing a task that would normally ask
            let tmp = std::env::temp_dir().join("tool-gates-test-mise-settings");
            let _ = std::fs::remove_dir_all(&tmp);
            std::fs::create_dir_all(tmp.join(".claude")).unwrap();

            // mise task that expands to an ask-worthy command
            std::fs::write(
                tmp.join("mise.toml"),
                r#"
[tasks.ci]
run = "npm publish"
"#,
            )
            .unwrap();

            // Settings that allow mise run *
            std::fs::write(
                tmp.join(".claude/settings.local.json"),
                r#"{"permissions": {"allow": ["Bash(mise run *)"]}}"#,
            )
            .unwrap();

            let cwd = tmp.to_string_lossy();
            let result =
                check_command_with_settings("mise run ci", &cwd, "default", Client::Claude);
            assert_eq!(
                get_decision(&result),
                "allow",
                "mise run ci should be allowed when Bash(mise run *) is in settings allow"
            );

            // Also test with redirections (the original bug trigger)
            let result =
                check_command_with_settings("mise run ci 2>&1", &cwd, "default", Client::Claude);
            assert_eq!(
                get_decision(&result),
                "allow",
                "mise run ci 2>&1 should be allowed when Bash(mise run *) is in settings allow"
            );

            let _ = std::fs::remove_dir_all(&tmp);
        }

        #[test]
        fn test_mise_settings_deny_overrides_expansion() {
            let tmp = std::env::temp_dir().join("tool-gates-test-mise-deny");
            let _ = std::fs::remove_dir_all(&tmp);
            std::fs::create_dir_all(tmp.join(".claude")).unwrap();

            // mise task that expands to a safe command
            std::fs::write(
                tmp.join("mise.toml"),
                r#"
[tasks.status]
run = "git status"
"#,
            )
            .unwrap();

            // Settings that deny mise run status
            std::fs::write(
                tmp.join(".claude/settings.local.json"),
                r#"{"permissions": {"deny": ["Bash(mise run status)"]}}"#,
            )
            .unwrap();

            let cwd = tmp.to_string_lossy();
            let result =
                check_command_with_settings("mise run status", &cwd, "default", Client::Claude);
            assert_eq!(
                get_decision(&result),
                "deny",
                "mise run status should be denied when in settings deny"
            );

            let _ = std::fs::remove_dir_all(&tmp);
        }

        #[test]
        fn test_mise_compound_command_not_expanded() {
            // Compound commands with mise should NOT expand the task --
            // each sub-command should be checked individually by gates.
            let tmp = std::env::temp_dir().join("tool-gates-test-mise-compound");
            let _ = std::fs::remove_dir_all(&tmp);
            std::fs::create_dir_all(&tmp).unwrap();

            // Safe mise task
            std::fs::write(
                tmp.join("mise.toml"),
                r#"
[tasks.ci]
run = "echo hello"
"#,
            )
            .unwrap();

            let cwd = tmp.to_string_lossy();

            // Simple mise run should still expand and allow
            let result =
                check_command_with_settings("mise run ci", &cwd, "default", Client::Claude);
            assert_eq!(
                get_decision(&result),
                "allow",
                "simple mise run ci should allow"
            );

            // && with dangerous command -> deny
            let result = check_command_with_settings(
                "mise run ci && rm -rf /",
                &cwd,
                "default",
                Client::Claude,
            );
            assert_eq!(
                get_decision(&result),
                "deny",
                "mise run ci && rm -rf / should deny"
            );

            // ; with dangerous command -> deny
            let result = check_command_with_settings(
                "mise run ci; rm -rf /",
                &cwd,
                "default",
                Client::Claude,
            );
            assert_eq!(
                get_decision(&result),
                "deny",
                "mise run ci; rm -rf / should deny"
            );

            // || with dangerous command -> deny
            let result = check_command_with_settings(
                "mise run ci || rm -rf /",
                &cwd,
                "default",
                Client::Claude,
            );
            assert_eq!(
                get_decision(&result),
                "deny",
                "mise run ci || rm -rf / should deny"
            );

            // | bash (pipe to shell) -> ask (hard ask, not overridable by settings)
            let result =
                check_command_with_settings("mise run ci | bash", &cwd, "default", Client::Claude);
            assert_eq!(
                get_decision(&result),
                "ask",
                "mise run ci | bash should ask"
            );

            // && with ask-worthy command -> ask (not silently allow)
            let result = check_command_with_settings(
                "mise run ci && npm install",
                &cwd,
                "default",
                Client::Claude,
            );
            assert_eq!(
                get_decision(&result),
                "ask",
                "mise run ci && npm install should ask, not silently allow"
            );

            let _ = std::fs::remove_dir_all(&tmp);
        }

        #[test]
        fn test_package_json_compound_command_not_expanded() {
            // Same compound command protection for package.json scripts.
            let tmp = std::env::temp_dir().join("tool-gates-test-pkg-compound");
            let _ = std::fs::remove_dir_all(&tmp);
            std::fs::create_dir_all(&tmp).unwrap();

            std::fs::write(
                tmp.join("package.json"),
                r#"{"scripts": {"lint": "echo lint"}}"#,
            )
            .unwrap();

            let cwd = tmp.to_string_lossy();

            // Simple script run should expand
            let result =
                check_command_with_settings("npm run lint", &cwd, "default", Client::Claude);
            assert_eq!(
                get_decision(&result),
                "allow",
                "simple npm run lint should allow"
            );

            // && with dangerous command -> deny
            let result = check_command_with_settings(
                "npm run lint && rm -rf /",
                &cwd,
                "default",
                Client::Claude,
            );
            assert_eq!(
                get_decision(&result),
                "deny",
                "npm run lint && rm -rf / should deny"
            );

            // ; with dangerous command -> deny
            let result = check_command_with_settings(
                "pnpm run lint; rm -rf /",
                &cwd,
                "default",
                Client::Claude,
            );
            assert_eq!(
                get_decision(&result),
                "deny",
                "pnpm run lint; rm -rf / should deny"
            );

            // | bash -> ask (hard ask, not overridable by settings)
            let result =
                check_command_with_settings("npm run lint | bash", &cwd, "default", Client::Claude);
            assert_eq!(
                get_decision(&result),
                "ask",
                "npm run lint | bash should ask"
            );

            let _ = std::fs::remove_dir_all(&tmp);
        }

        #[test]
        fn package_script_preserves_output_cap_recovery() {
            let temp = tempfile::tempdir().expect("package tempdir");
            std::fs::write(
                temp.path().join("package.json"),
                r#"{"scripts": {"inspect": "cat report.txt | head -n 4"}}"#,
            )
            .expect("write package.json");

            let result = check_package_script(
                "npm",
                "inspect",
                &temp.path().to_string_lossy(),
                "default",
                Client::Claude,
            );

            assert_eq!(result.decision, PermissionDecision::Deny);
            assert!(
                result
                    .recovery_actions
                    .contains(&RecoveryAction::ReadSourceFile {
                        selection: FileSelection::First(4),
                    }),
                "package wrapper dropped recovery: {:?}",
                result.recovery_actions
            );
        }

        #[test]
        fn mise_task_preserves_output_cap_recovery() {
            let temp = tempfile::tempdir().expect("mise tempdir");
            std::fs::write(
                temp.path().join("mise.toml"),
                r#"
[tasks.inspect]
run = "cat report.txt | tail -n 6"
"#,
            )
            .expect("write mise.toml");

            let result = check_mise_task(
                "inspect",
                &temp.path().to_string_lossy(),
                "default",
                Client::Claude,
            );

            assert_eq!(result.decision, PermissionDecision::Deny);
            assert!(
                result
                    .recovery_actions
                    .contains(&RecoveryAction::ReadSourceFile {
                        selection: FileSelection::Last(6),
                    }),
                "mise wrapper dropped recovery: {:?}",
                result.recovery_actions
            );
        }

        #[test]
        fn nested_package_script_preserves_output_cap_recovery() {
            let temp = tempfile::tempdir().expect("nested task tempdir");
            std::fs::write(
                temp.path().join("mise.toml"),
                r#"
[tasks.inspect]
run = "npm run inspect"
"#,
            )
            .expect("write mise.toml");
            std::fs::write(
                temp.path().join("package.json"),
                r#"{"scripts": {"inspect": "cat report.txt | head -n 9"}}"#,
            )
            .expect("write package.json");

            let result = check_mise_task(
                "inspect",
                &temp.path().to_string_lossy(),
                "default",
                Client::Claude,
            );

            assert_eq!(result.decision, PermissionDecision::Deny);
            assert!(
                result
                    .recovery_actions
                    .contains(&RecoveryAction::ReadSourceFile {
                        selection: FileSelection::First(9),
                    }),
                "nested package wrapper dropped recovery: {:?}",
                result.recovery_actions
            );
        }
    }
}

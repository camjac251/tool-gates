//! PermissionRequest hook handler.
//!
//! This module handles the PermissionRequest hook, which runs when Claude Code's
//! internal permission checks decide to ask the user. This is particularly important
//! for subagents, where PreToolUse's `allow` decision is ignored.
//!
//! The PermissionRequest hook can:
//! - Approve commands that our gates already deem safe
//! - Approve Edit/Write operations in agent worktrees (workaround for Claude Code bug)
//! - Deny commands that should be blocked
//! - Pass through to show the normal permission prompt
//!
//! Key insight: PermissionRequest's `allow` IS respected for subagents, unlike PreToolUse.
//! Note: `blocked_path` and `decision_reason` may be missing in real hook payloads,
//! so this handler treats them as optional metadata.

use std::path::Path;

use crate::file_guards::is_guarded;
use crate::models::{
    Client, Decision, HookOutput, PermissionDecision, PermissionRequestInput,
    PermissionRequestOutput,
};
use crate::router::check_command_with_settings;

/// Reasons that indicate a path-based permission check (safe to override if command is safe)
const PATH_BASED_REASONS: &[&str] = &[
    "Path is outside allowed working directories",
    "outside cwd",
    "outside allowed",
    "path outside",
    "working director",
];

/// Check if the decision reason indicates a path-based permission check
fn is_path_based_reason(reason: &Option<String>) -> bool {
    match reason {
        Some(r) => {
            let lower = r.to_lowercase();
            PATH_BASED_REASONS
                .iter()
                .any(|pattern| lower.contains(&pattern.to_lowercase()))
        }
        None => false,
    }
}

/// Handle a PermissionRequest hook.
///
/// Strategy:
/// 1. For Edit/Write tools: check if we're in a worktree context and auto-approve
/// 2. For Bash tools: re-check command policy using the same settings-aware path as PreToolUse
/// 3. If our gates say "allow" AND the reason is path-based, approve it
/// 4. If our gates say "deny", deny it
/// 5. Otherwise, pass through (return None to let normal prompt show)
pub fn handle_permission_request(
    input: &PermissionRequestInput,
) -> Option<PermissionRequestOutput> {
    // Edit/Write tools: auto-approve in worktree contexts
    if Client::is_write_tool(&input.tool_name) {
        return handle_file_permission_request(input);
    }

    // Only handle shell command tools (Bash for Claude, run_shell_command for Gemini)
    if !Client::is_shell_tool(&input.tool_name) {
        return None;
    }

    let command = input.get_command();
    if command.is_empty() {
        return None;
    }

    // Re-check policy using the same evaluator as PreToolUse to keep behavior aligned.
    let mode = if input.permission_mode.is_empty() {
        "default"
    } else {
        input.permission_mode.as_str()
    };
    let policy_output = check_command_with_settings(&command, &input.cwd, mode);
    let (decision, reason) = output_to_decision(policy_output);

    match decision {
        Decision::Allow => {
            // Our gates say it's safe. Check if this is a path-based restriction.
            if is_path_based_reason(&input.decision_reason) {
                // Path-based restriction on a safe command - approve it
                // Optionally add the blocked path to session permissions
                if let Some(ref blocked_path) = input.blocked_path {
                    // Determine the directory to add to session permissions.
                    // - Root path "/": don't expand permissions (too broad)
                    // - Directory-like path (no extension in last component): use directly
                    // - File-like path (has extension): use parent directory
                    if blocked_path == "/" {
                        return Some(PermissionRequestOutput::allow());
                    }
                    let path = std::path::Path::new(blocked_path);
                    let looks_like_file = path
                        .file_name()
                        .and_then(|f| f.to_str())
                        .map(|f| f.contains('.'))
                        .unwrap_or(false);
                    let dir = if looks_like_file {
                        path.parent()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_else(|| blocked_path.clone())
                    } else {
                        blocked_path.clone()
                    };
                    return Some(PermissionRequestOutput::allow_with_directories(vec![dir]));
                }
                return Some(PermissionRequestOutput::allow());
            }

            // Non-path reason but command is safe - still approve
            // This handles cases where internal checks are overly cautious
            Some(PermissionRequestOutput::allow())
        }
        Decision::Block => {
            // Our gates say it's dangerous - deny it
            Some(PermissionRequestOutput::deny(
                &reason.unwrap_or_else(|| "Blocked by tool-gates".to_string()),
            ))
        }
        Decision::Ask => {
            // Our gates want to ask - let the normal prompt show
            // This respects our gate's judgment that user approval is needed
            None
        }
        Decision::Skip => {
            // Unknown command - let the normal prompt show
            None
        }
    }
}

/// Handle PermissionRequest for Edit/Write tools in worktree contexts.
///
/// Claude Code has a bug where agent worktrees are not added to `additionalWorkingDirectories`,
/// so every Edit/Write in a worktree triggers a permission prompt even in `acceptEdits` mode.
/// This works around it by auto-approving edits within the worktree when the cwd is clearly
/// a Claude-created agent worktree.
fn handle_file_permission_request(
    input: &PermissionRequestInput,
) -> Option<PermissionRequestOutput> {
    let file_path = input.get_file_path();
    if file_path.is_empty() {
        return None;
    }

    // Resolve the file path (may be relative to cwd) and clean .. components
    let joined = if Path::new(&file_path).is_absolute() {
        std::path::PathBuf::from(&file_path)
    } else {
        Path::new(&input.cwd).join(&file_path)
    };
    let resolved = clean_path(&joined);

    if !is_worktree_context(&resolved, &input.cwd) {
        return None;
    }

    // Don't auto-approve edits to AI config files even in worktrees
    let config = crate::config::load();
    if is_guarded(&resolved, &config.file_guards) {
        return None;
    }

    // Auto-approve and add the worktree cwd to session permissions
    // so subsequent edits in the same worktree don't prompt again
    Some(PermissionRequestOutput::allow_with_directories(vec![
        input.cwd.clone(),
    ]))
}

/// Check if we're in an agent worktree context and the file is within it.
///
/// Returns true when the cwd is under a `.claude/worktrees/` directory
/// (indicating a Claude-created agent worktree) and the file path is
/// within that cwd.
fn is_worktree_context(resolved_path: &Path, cwd: &str) -> bool {
    let cwd_path = Path::new(cwd);

    // Check if cwd is inside a .claude/worktrees/ directory
    for ancestor in cwd_path.ancestors() {
        let dir_name = match ancestor.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if dir_name == "worktrees" {
            if let Some(parent) = ancestor.parent() {
                if parent.file_name().and_then(|n| n.to_str()) == Some(".claude") {
                    // cwd is under .claude/worktrees/, check file is within cwd
                    return resolved_path.starts_with(cwd_path);
                }
            }
        }
    }
    false
}

/// Resolve `.` and `..` components without filesystem access.
fn clean_path(p: &Path) -> std::path::PathBuf {
    let mut out = std::path::PathBuf::new();
    for component in p.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

fn output_to_decision(output: HookOutput) -> (Decision, Option<String>) {
    let decision = match output.decision {
        PermissionDecision::Allow | PermissionDecision::Approve => Decision::Allow,
        PermissionDecision::Deny => Decision::Block,
        PermissionDecision::Ask => Decision::Ask,
    };
    (decision, output.reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ToolInputVariant;

    fn make_input(command: &str, decision_reason: Option<&str>) -> PermissionRequestInput {
        PermissionRequestInput {
            hook_event_name: "PermissionRequest".to_string(),
            tool_name: "Bash".to_string(),
            cwd: "/tmp".to_string(),
            permission_mode: "default".to_string(),
            tool_input: ToolInputVariant::Map({
                let mut map = serde_json::Map::new();
                map.insert(
                    "command".to_string(),
                    serde_json::Value::String(command.to_string()),
                );
                map
            }),
            decision_reason: decision_reason.map(String::from),
            blocked_path: Some("/outside/path".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn test_safe_command_with_path_reason_approves() {
        let input = make_input(
            "rg pattern /outside/path",
            Some("Path is outside allowed working directories"),
        );
        let result = handle_permission_request(&input);
        assert!(
            result.is_some(),
            "Should approve safe command with path reason"
        );
    }

    #[test]
    fn test_safe_command_with_other_reason_approves() {
        let input = make_input("git status", Some("Some other reason"));
        let result = handle_permission_request(&input);
        assert!(result.is_some(), "Should approve safe command");
    }

    #[test]
    fn test_dangerous_command_denies() {
        let input = make_input(
            "rm -rf /",
            Some("Path is outside allowed working directories"),
        );
        let result = handle_permission_request(&input);
        assert!(result.is_some(), "Should return a result");
        // The result should be a deny
        let json = serde_json::to_string(&result.unwrap()).unwrap();
        assert!(json.contains("deny"), "Should deny dangerous command");
    }

    #[test]
    fn test_ask_command_passes_through() {
        let input = make_input(
            "npm install",
            Some("Path is outside allowed working directories"),
        );
        let result = handle_permission_request(&input);
        // npm install returns Ask from our gates, so we pass through
        assert!(result.is_none(), "Should pass through for ask commands");
    }

    #[test]
    fn test_non_bash_non_file_passes_through() {
        let mut input = make_input("anything", None);
        input.tool_name = "Glob".to_string();
        let result = handle_permission_request(&input);
        assert!(
            result.is_none(),
            "Should pass through for non-Bash/non-file tools"
        );
    }

    #[test]
    fn test_safe_command_without_path_metadata_approves_without_directory_update() {
        let mut input = make_input("rg pattern file.txt", None);
        input.blocked_path = None;
        input.decision_reason = None;

        let result = handle_permission_request(&input);
        assert!(result.is_some(), "safe command should still be approved");

        let json = serde_json::to_string(&result.unwrap()).unwrap();
        assert!(
            !json.contains("addDirectories"),
            "should not add directory permissions when blocked_path is missing"
        );
    }

    #[test]
    fn test_settings_allow_rule_approves() {
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let claude_dir = temp_dir.path().join(".claude");
        fs::create_dir(&claude_dir).unwrap();
        fs::write(
            claude_dir.join("settings.json"),
            r#"{"permissions":{"allow":["Bash(grep:*)"]}}"#,
        )
        .unwrap();

        let mut input = make_input("grep foo file.txt", Some("Some other reason"));
        input.cwd = temp_dir.path().to_string_lossy().to_string();

        let result = handle_permission_request(&input);
        assert!(result.is_some(), "settings allow should approve");
    }

    #[test]
    fn test_settings_ask_rule_passes_through() {
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let claude_dir = temp_dir.path().join(".claude");
        fs::create_dir(&claude_dir).unwrap();
        fs::write(
            claude_dir.join("settings.json"),
            r#"{"permissions":{"ask":["Bash(grep:*)"]}}"#,
        )
        .unwrap();

        let mut input = make_input("grep foo file.txt", Some("Some other reason"));
        input.cwd = temp_dir.path().to_string_lossy().to_string();

        let result = handle_permission_request(&input);
        assert!(result.is_none(), "settings ask should pass through");
    }

    #[test]
    fn test_is_path_based_reason() {
        assert!(is_path_based_reason(&Some(
            "Path is outside allowed working directories".to_string()
        )));
        assert!(is_path_based_reason(&Some("path outside cwd".to_string())));
        assert!(is_path_based_reason(&Some(
            "File is outside allowed working directory".to_string()
        )));
        assert!(!is_path_based_reason(&Some(
            "Permission denied by user".to_string()
        )));
        assert!(!is_path_based_reason(&None));
    }

    /// Helper to build a PermissionRequestInput with a custom blocked_path
    fn make_input_with_blocked_path(
        command: &str,
        decision_reason: Option<&str>,
        blocked_path: Option<&str>,
    ) -> PermissionRequestInput {
        PermissionRequestInput {
            hook_event_name: "PermissionRequest".to_string(),
            tool_name: "Bash".to_string(),
            cwd: "/tmp".to_string(),
            permission_mode: "default".to_string(),
            tool_input: ToolInputVariant::Map({
                let mut map = serde_json::Map::new();
                map.insert(
                    "command".to_string(),
                    serde_json::Value::String(command.to_string()),
                );
                map
            }),
            decision_reason: decision_reason.map(String::from),
            blocked_path: blocked_path.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn test_blocked_path_root_does_not_expand_permissions() {
        // Root path "/" should NOT be added to session permissions (too broad)
        let input = make_input_with_blocked_path(
            "rg pattern /some/file",
            Some("Path is outside allowed working directories"),
            Some("/"),
        );
        let result = handle_permission_request(&input);
        assert!(result.is_some(), "Should approve safe command");
        let json = serde_json::to_string(&result.unwrap()).unwrap();
        assert!(
            !json.contains("addDirectories"),
            "root path should not be added to permissions, got: {json}"
        );
    }

    #[test]
    fn test_blocked_path_directory_uses_path_directly() {
        // Directory-like path (no extension) should be used directly, not parent()
        let input = make_input_with_blocked_path(
            "rg pattern /outside/mydir",
            Some("Path is outside allowed working directories"),
            Some("/outside/mydir"),
        );
        let result = handle_permission_request(&input);
        assert!(result.is_some(), "Should approve safe command");
        let json = serde_json::to_string(&result.unwrap()).unwrap();
        assert!(
            json.contains("/outside/mydir"),
            "should add the directory itself, got: {json}"
        );
        assert!(
            !json.contains("\"/outside\""),
            "should NOT add the grandparent, got: {json}"
        );
    }

    #[test]
    fn test_blocked_path_file_uses_parent_directory() {
        // File-like path (has extension) should use parent() for the directory
        let input = make_input_with_blocked_path(
            "rg pattern /outside/dir/file.txt",
            Some("Path is outside allowed working directories"),
            Some("/outside/dir/file.txt"),
        );
        let result = handle_permission_request(&input);
        assert!(result.is_some(), "Should approve safe command");
        let json = serde_json::to_string(&result.unwrap()).unwrap();
        assert!(
            json.contains("/outside/dir"),
            "should add the parent directory of the file, got: {json}"
        );
        assert!(
            !json.contains("file.txt"),
            "should NOT contain the file name in directory permissions, got: {json}"
        );
    }

    // === Worktree Edit/Write tests ===

    fn make_file_input(tool_name: &str, file_path: &str, cwd: &str) -> PermissionRequestInput {
        PermissionRequestInput {
            hook_event_name: "PermissionRequest".to_string(),
            tool_name: tool_name.to_string(),
            cwd: cwd.to_string(),
            permission_mode: "acceptEdits".to_string(),
            tool_input: ToolInputVariant::Map({
                let mut map = serde_json::Map::new();
                map.insert(
                    "file_path".to_string(),
                    serde_json::Value::String(file_path.to_string()),
                );
                map
            }),
            ..Default::default()
        }
    }

    #[test]
    fn test_write_in_worktree_approves() {
        let input = make_file_input(
            "Write",
            "/project/.claude/worktrees/agent-abc123/src/main.rs",
            "/project/.claude/worktrees/agent-abc123",
        );
        let result = handle_permission_request(&input);
        assert!(result.is_some(), "Should approve Write in agent worktree");
        let json = serde_json::to_string(&result.unwrap()).unwrap();
        assert!(json.contains("allow"), "Should be an allow decision");
        assert!(
            json.contains("agent-abc123"),
            "Should add worktree cwd to session permissions"
        );
    }

    #[test]
    fn test_edit_in_worktree_approves() {
        let input = make_file_input(
            "Edit",
            "/project/.claude/worktrees/agent-abc123/frontend/src/Component.tsx",
            "/project/.claude/worktrees/agent-abc123",
        );
        let result = handle_permission_request(&input);
        assert!(result.is_some(), "Should approve Edit in agent worktree");
    }

    #[test]
    fn test_write_outside_worktree_passes_through() {
        // Normal cwd (not a worktree) should pass through
        let input = make_file_input("Write", "/project/src/main.rs", "/project");
        let result = handle_permission_request(&input);
        assert!(
            result.is_none(),
            "Should pass through for Write outside worktree context"
        );
    }

    #[test]
    fn test_write_to_guarded_file_in_worktree_passes_through() {
        // AI config files should NOT be auto-approved even in worktrees
        let input = make_file_input(
            "Write",
            "/project/.claude/worktrees/agent-abc123/CLAUDE.md",
            "/project/.claude/worktrees/agent-abc123",
        );
        let result = handle_permission_request(&input);
        assert!(
            result.is_none(),
            "Should pass through for guarded file in worktree"
        );
    }

    #[test]
    fn test_write_outside_worktree_cwd_passes_through() {
        // File outside the worktree's cwd should not be auto-approved
        let input = make_file_input(
            "Write",
            "/other/project/src/main.rs",
            "/project/.claude/worktrees/agent-abc123",
        );
        let result = handle_permission_request(&input);
        assert!(
            result.is_none(),
            "Should pass through for file outside worktree cwd"
        );
    }

    #[test]
    fn test_edit_with_relative_path_in_worktree_approves() {
        // Relative paths should be resolved against cwd
        let input = make_file_input(
            "Edit",
            "src/lib.rs",
            "/project/.claude/worktrees/agent-abc123",
        );
        let result = handle_permission_request(&input);
        assert!(
            result.is_some(),
            "Should approve Edit with relative path in worktree"
        );
    }

    #[test]
    fn test_worktree_context_detection() {
        // Positive cases
        assert!(is_worktree_context(
            Path::new("/project/.claude/worktrees/agent-abc/src/main.rs"),
            "/project/.claude/worktrees/agent-abc",
        ));
        assert!(is_worktree_context(
            Path::new("/home/user/repo/.claude/worktrees/task-123/deep/nested/file.ts"),
            "/home/user/repo/.claude/worktrees/task-123",
        ));

        // Negative cases
        assert!(!is_worktree_context(
            Path::new("/project/src/main.rs"),
            "/project",
        ));
        assert!(!is_worktree_context(
            Path::new("/other/path/file.rs"),
            "/project/.claude/worktrees/agent-abc",
        ));
        // Just having "worktrees" in the path isn't enough without ".claude" parent
        assert!(!is_worktree_context(
            Path::new("/project/worktrees/main/src/lib.rs"),
            "/project/worktrees/main",
        ));
    }

    #[test]
    fn test_write_to_settings_json_in_worktree_passes_through() {
        // .claude/settings.json is a guarded config file
        let input = make_file_input(
            "Write",
            "/project/.claude/worktrees/agent-abc123/.claude/settings.json",
            "/project/.claude/worktrees/agent-abc123",
        );
        let result = handle_permission_request(&input);
        assert!(
            result.is_none(),
            "Should pass through for .claude/settings.json in worktree"
        );
    }

    #[test]
    fn test_path_traversal_blocked() {
        // ../../etc/passwd should not be auto-approved even from a worktree cwd
        let input = make_file_input(
            "Write",
            "../../etc/passwd",
            "/project/.claude/worktrees/agent-abc123",
        );
        let result = handle_permission_request(&input);
        assert!(
            result.is_none(),
            "Path traversal outside worktree should pass through"
        );
    }

    #[test]
    fn test_empty_file_path_passes_through() {
        let input = make_file_input("Write", "", "/project/.claude/worktrees/agent-abc123");
        let result = handle_permission_request(&input);
        assert!(result.is_none(), "Empty file_path should pass through");
    }

    #[test]
    fn test_edit_in_worktree_default_mode_approves() {
        // Should approve regardless of permission_mode
        let mut input = make_file_input(
            "Edit",
            "/project/.claude/worktrees/agent-abc123/src/lib.rs",
            "/project/.claude/worktrees/agent-abc123",
        );
        input.permission_mode = "default".to_string();
        let result = handle_permission_request(&input);
        assert!(
            result.is_some(),
            "Should approve Edit in worktree regardless of permission mode"
        );
    }
}

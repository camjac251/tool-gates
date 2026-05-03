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

pub fn handle_permission_request(
    input: &PermissionRequestInput,
    tool_input_map: &serde_json::Map<String, serde_json::Value>,
) -> Option<PermissionRequestOutput> {
    handle_permission_request_for_client(input, tool_input_map, Client::Claude)
}

pub fn handle_permission_request_for_client(
    input: &PermissionRequestInput,
    tool_input_map: &serde_json::Map<String, serde_json::Value>,
    client: Client,
) -> Option<PermissionRequestOutput> {
    // Block rules run first for ALL tool types, including write tools.
    // The earlier code returned early for is_write_tool, which let block_tools
    // rules be silently bypassed on the PermissionRequest path. Docs claim
    // block rules always win and the subagent path must honor that too.
    let config = crate::config::load();
    if let Some(hook_output) =
        crate::tool_blocks::check_tool_block(&input.tool_name, tool_input_map, config.block_rules())
    {
        let reason = hook_output
            .reason
            .unwrap_or_else(|| "Blocked by tool-gates".to_string());
        return Some(PermissionRequestOutput::deny(&reason));
    }

    // Edit/Write/apply_patch tools: auto-approve in worktree contexts.
    // Runs after block_tools so a configured block on a write tool wins.
    // Claude/Gemini include agent_id, so only subagent calls auto-approve.
    // Codex does not currently send agent_id on PermissionRequest, so its
    // apply_patch path falls back to the stricter worktree-path check inside
    // handle_file_permission_request.
    let can_consider_worktree_write =
        input.agent_id.is_some() || (client == Client::Codex && input.tool_name == "apply_patch");
    if Client::is_write_tool(&input.tool_name) && can_consider_worktree_write {
        return handle_file_permission_request(input);
    }

    // MCP tools in acceptEdits mode: consult `[[accept_edits_mcp]]` rules.
    // Subagents need this because PreToolUse's `allow` decision is ignored
    // for subagent tool calls -- PermissionRequest is the only hook where
    // an approval actually lands.
    if let Some(output) = handle_mcp_accept_edits(input) {
        return Some(output);
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

/// Handle PermissionRequest for Edit/Write/apply_patch tools in worktree contexts.
///
/// Subagent-only path. The caller in `handle_permission_request` gates on
/// `agent_id.is_some()` so main-thread invocations never reach this handler;
/// auto-approving them would silently bypass the user's permission_mode when
/// the user has opened Claude Code directly inside a `.claude/worktrees/*`
/// directory.
///
/// Claude Code has a bug where agent worktrees are not added to `additionalWorkingDirectories`,
/// so every Edit/Write in a subagent worktree triggers a permission prompt even in `acceptEdits` mode.
/// This works around it by auto-approving edits within the worktree when the cwd is clearly
/// a Claude-created agent worktree.
///
/// `apply_patch` (Codex) carries paths inside the patch body in
/// `tool_input.command` rather than `file_path`. We parse the patch and apply
/// the same worktree containment + guarded-file checks against every affected
/// path; if any path falls outside the worktree or is a guarded AI config
/// file, return `None` so the normal permission prompt fires.
fn handle_file_permission_request(
    input: &PermissionRequestInput,
) -> Option<PermissionRequestOutput> {
    let paths = collect_paths_for_permission(input);
    if paths.is_empty() {
        return None;
    }

    let config = crate::config::load();
    for raw in &paths {
        let joined = if Path::new(raw).is_absolute() {
            std::path::PathBuf::from(raw)
        } else {
            Path::new(&input.cwd).join(raw)
        };
        let resolved = clean_path(&joined);

        if !is_worktree_context(&resolved, &input.cwd) {
            return None;
        }

        // Don't auto-approve edits to AI config files even in worktrees
        if is_guarded(&resolved, &config.file_guards) {
            return None;
        }
    }

    // Auto-approve and add the worktree cwd to session permissions
    // so subsequent edits in the same worktree don't prompt again
    Some(PermissionRequestOutput::allow_with_directories(vec![
        input.cwd.clone(),
    ]))
}

/// Collect every file path this PermissionRequest would write to. Read from
/// `file_path` for Claude/Gemini tools, from the parsed unified-diff body for
/// Codex `apply_patch`.
fn collect_paths_for_permission(input: &PermissionRequestInput) -> Vec<String> {
    if input.tool_name == "apply_patch" {
        let command = input.get_command();
        if command.is_empty() {
            return Vec::new();
        }
        return crate::apply_patch_parser::parse_patch(&command)
            .into_iter()
            .flat_map(|f| {
                f.affected_paths()
                    .into_iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
            })
            .filter(|p| !p.is_empty())
            .collect();
    }

    let path = input.get_file_path();
    if path.is_empty() {
        Vec::new()
    } else {
        vec![path]
    }
}

/// Handle PermissionRequest for MCP tools under `acceptEdits` mode.
///
/// Claude Code never extends acceptEdits to MCP tools natively -- every MCP
/// tool's internal `checkPermissions` returns passthrough regardless of mode.
/// This handler is the subagent-side counterpart to the MCP branch in
/// `handle_pre_tool_use_hook`: both check the same `[[accept_edits_mcp]]`
/// rule list, but this one fires for subagents where PreToolUse's `allow`
/// is ignored.
///
/// Returns Some(allow) when a rule matches and all directory conditions are
/// met. Returns None otherwise (pass through to whatever the next handler
/// decides -- typically the shell-tool branch or normal permission prompt).
///
/// All three None branches (wrong mode / non-MCP tool / no matching rule)
/// are indistinguishable from outside -- callers should not rely on which
/// branch was taken.
fn handle_mcp_accept_edits(input: &PermissionRequestInput) -> Option<PermissionRequestOutput> {
    let config = crate::config::load();

    let project_dir = std::env::var("CLAUDE_PROJECT_DIR")
        .or_else(|_| std::env::var("GEMINI_PROJECT_DIR"))
        .unwrap_or_default();

    match_mcp_rule(
        &config.accept_edits_mcp,
        &input.tool_name,
        &input.permission_mode,
        &project_dir,
    )
    .map(|_rule| {
        // The subagent PermissionRequest `allow` wire format has no reason
        // slot, so `rule.reason` is intentionally dropped here. See the
        // doc comment on McpApprovalRule.reason in config.rs.
        PermissionRequestOutput::allow()
    })
}

/// Pure rule-matching for MCP accept-edits approval.
///
/// Returns the first matching rule, or None. All inputs are data; no I/O.
/// Split out from `handle_mcp_accept_edits` so the matching logic can be
/// unit-tested without touching the filesystem or env vars.
///
/// Exact-match on `permission_mode` is intentional here. Unlike
/// `is_auto_mode` in router.rs which normalizes whitespace/case because
/// failing-closed on a safety-floor deny is unsafe, this allow-path
/// fails-closed to "prompt" when the mode string drifts — which is the
/// correct default for an approval rule.
pub(crate) fn match_mcp_rule<'a>(
    rules: &'a [crate::config::McpApprovalRule],
    tool_name: &str,
    permission_mode: &str,
    project_dir: &str,
) -> Option<&'a crate::config::McpApprovalRule> {
    if permission_mode != "acceptEdits" {
        return None;
    }
    if !Client::is_mcp_tool(tool_name) {
        return None;
    }
    rules
        .iter()
        .find(|r| r.matches_tool(tool_name) && r.conditions_met(project_dir))
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
        // Defer is a wire-level "let CC handle it" -- semantically Ask
        // for any caller deciding what to do next.
        PermissionDecision::Ask | PermissionDecision::Defer => Decision::Ask,
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
        let result = handle_permission_request(&input, &serde_json::Map::new());
        assert!(
            result.is_some(),
            "Should approve safe command with path reason"
        );
    }

    #[test]
    fn test_safe_command_with_other_reason_approves() {
        let input = make_input("git status", Some("Some other reason"));
        let result = handle_permission_request(&input, &serde_json::Map::new());
        assert!(result.is_some(), "Should approve safe command");
    }

    #[test]
    fn test_dangerous_command_denies() {
        let input = make_input(
            "rm -rf /",
            Some("Path is outside allowed working directories"),
        );
        let result = handle_permission_request(&input, &serde_json::Map::new());
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
        let result = handle_permission_request(&input, &serde_json::Map::new());
        // npm install returns Ask from our gates, so we pass through
        assert!(result.is_none(), "Should pass through for ask commands");
    }

    #[test]
    fn test_non_bash_non_file_passes_through() {
        // Use a tool name that isn't blocked by default rules (Glob/Grep are
        // in the defaults). "TodoWrite" is a plausible Claude tool that
        // tool-gates has no opinion on.
        let mut input = make_input("anything", None);
        input.tool_name = "TodoWrite".to_string();
        let result = handle_permission_request(&input, &serde_json::Map::new());
        assert!(
            result.is_none(),
            "Should pass through for non-Bash/non-file tools without block rules"
        );
    }

    #[test]
    fn test_safe_command_without_path_metadata_approves_without_directory_update() {
        let mut input = make_input("rg pattern file.txt", None);
        input.blocked_path = None;
        input.decision_reason = None;

        let result = handle_permission_request(&input, &serde_json::Map::new());
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

        let result = handle_permission_request(&input, &serde_json::Map::new());
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

        let result = handle_permission_request(&input, &serde_json::Map::new());
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
        let result = handle_permission_request(&input, &serde_json::Map::new());
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
        let result = handle_permission_request(&input, &serde_json::Map::new());
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
        let result = handle_permission_request(&input, &serde_json::Map::new());
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
            // Default to a subagent invocation so worktree auto-approve fires.
            // Tests targeting main-thread behavior set this back to None.
            agent_id: Some("test-subagent".to_string()),
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
        let result = handle_permission_request(&input, &serde_json::Map::new());
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
        let result = handle_permission_request(&input, &serde_json::Map::new());
        assert!(result.is_some(), "Should approve Edit in agent worktree");
    }

    #[test]
    fn test_write_outside_worktree_passes_through() {
        // Normal cwd (not a worktree) should pass through
        let input = make_file_input("Write", "/project/src/main.rs", "/project");
        let result = handle_permission_request(&input, &serde_json::Map::new());
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
        let result = handle_permission_request(&input, &serde_json::Map::new());
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
        let result = handle_permission_request(&input, &serde_json::Map::new());
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
        let result = handle_permission_request(&input, &serde_json::Map::new());
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
        let result = handle_permission_request(&input, &serde_json::Map::new());
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
        let result = handle_permission_request(&input, &serde_json::Map::new());
        assert!(
            result.is_none(),
            "Path traversal outside worktree should pass through"
        );
    }

    #[test]
    fn test_empty_file_path_passes_through() {
        let input = make_file_input("Write", "", "/project/.claude/worktrees/agent-abc123");
        let result = handle_permission_request(&input, &serde_json::Map::new());
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
        let result = handle_permission_request(&input, &serde_json::Map::new());
        assert!(
            result.is_some(),
            "Should approve Edit in worktree regardless of permission mode"
        );
    }

    #[test]
    fn test_write_in_worktree_main_thread_passes_through() {
        // Main-thread Write/Edit must NOT be auto-approved even when cwd is
        // under .claude/worktrees/. This case happens when the user opens
        // Claude Code directly inside a worktree to debug it. They expect
        // their permission_mode to be honored, not silently bypassed.
        let mut input = make_file_input(
            "Write",
            "/project/.claude/worktrees/agent-abc123/src/main.rs",
            "/project/.claude/worktrees/agent-abc123",
        );
        input.agent_id = None;
        input.permission_mode = "default".to_string();
        let result = handle_permission_request(&input, &serde_json::Map::new());
        assert!(
            result.is_none(),
            "Main thread must fall through to permission prompt"
        );
    }

    #[test]
    fn test_edit_in_worktree_main_thread_passes_through() {
        // Same as above but for Edit and acceptEdits mode. The gate is on
        // agent_id, not on permission_mode.
        let mut input = make_file_input(
            "Edit",
            "/project/.claude/worktrees/agent-abc123/src/lib.rs",
            "/project/.claude/worktrees/agent-abc123",
        );
        input.agent_id = None;
        let result = handle_permission_request(&input, &serde_json::Map::new());
        assert!(
            result.is_none(),
            "Main thread Edit must not be auto-approved by worktree handler"
        );
    }

    #[test]
    fn test_codex_apply_patch_in_worktree_without_agent_id_approves() {
        // Codex PermissionRequest input currently has no agent_id field. Keep
        // apply_patch support alive by using the worktree path boundary as
        // the approval signal for Codex only.
        let mut map = serde_json::Map::new();
        map.insert(
            "command".to_string(),
            serde_json::Value::String(
                "*** Begin Patch\n*** Update File: src/lib.rs\n@@\n-old\n+new\n*** End Patch\n"
                    .to_string(),
            ),
        );
        let input = PermissionRequestInput {
            hook_event_name: "PermissionRequest".to_string(),
            tool_name: "apply_patch".to_string(),
            cwd: "/project/.claude/worktrees/agent-abc123".to_string(),
            permission_mode: "default".to_string(),
            agent_id: None,
            tool_input: ToolInputVariant::Map(map),
            ..Default::default()
        };

        let result =
            handle_permission_request_for_client(&input, &serde_json::Map::new(), Client::Codex);

        assert!(
            result.is_some(),
            "Codex apply_patch in a worktree must not be blocked on missing agent_id"
        );
    }

    #[test]
    fn test_claude_apply_patch_without_agent_id_still_passes_through() {
        let mut map = serde_json::Map::new();
        map.insert(
            "command".to_string(),
            serde_json::Value::String(
                "*** Begin Patch\n*** Update File: src/lib.rs\n@@\n-old\n+new\n*** End Patch\n"
                    .to_string(),
            ),
        );
        let input = PermissionRequestInput {
            hook_event_name: "PermissionRequest".to_string(),
            tool_name: "apply_patch".to_string(),
            cwd: "/project/.claude/worktrees/agent-abc123".to_string(),
            permission_mode: "default".to_string(),
            agent_id: None,
            tool_input: ToolInputVariant::Map(map),
            ..Default::default()
        };

        let result = handle_permission_request(&input, &serde_json::Map::new());

        assert!(
            result.is_none(),
            "Claude apply_patch without agent_id must still honor main-thread prompt behavior"
        );
    }

    // === accept_edits_mcp tests ===

    fn make_mcp_input(tool_name: &str, mode: &str) -> PermissionRequestInput {
        PermissionRequestInput {
            hook_event_name: "PermissionRequest".to_string(),
            tool_name: tool_name.to_string(),
            cwd: "/tmp".to_string(),
            permission_mode: mode.to_string(),
            tool_input: ToolInputVariant::Map(serde_json::Map::new()),
            ..Default::default()
        }
    }

    /// Config is loaded from disk via OnceLock, so these tests run against the
    /// actual user config. They only assert fall-through behavior that must
    /// hold regardless of what the user has configured.
    #[test]
    fn test_mcp_accept_edits_default_mode_passes_through() {
        // Default mode: MCP rules must never fire
        let input = make_mcp_input("mcp__serena__replace_symbol_body", "default");
        let result = handle_permission_request(&input, &serde_json::Map::new());
        assert!(
            result.is_none(),
            "MCP tool in default mode should pass through"
        );
    }

    #[test]
    fn test_bash_in_accept_edits_routes_through_shell_branch() {
        // Bash under acceptEdits must NOT trigger the MCP branch:
        // git status routes through shell-tool policy, not MCP.
        let mut input = make_input("git status", None);
        input.permission_mode = "acceptEdits".to_string();
        let result = handle_permission_request(&input, &serde_json::Map::new());
        // git status is allowed by our gates; whatever the outcome, it must
        // not be handled by the MCP branch. Assert it's approved (Allow path).
        assert!(
            result.is_some(),
            "Bash in acceptEdits should route normally"
        );
    }

    #[test]
    fn test_mcp_accept_edits_gemini_namespace_detected() {
        // With no user rules configured, a Gemini MCP tool in acceptEdits mode
        // must reach the MCP branch and fall through to None (no match).
        // Skip if the user has rules — we can't assert the outcome deterministically then.
        if crate::config::load().accept_edits_mcp.is_empty() {
            let input = make_mcp_input("mcp_serena_find_symbol", "acceptEdits");
            assert!(
                handle_permission_request(&input, &serde_json::Map::new()).is_none(),
                "With no MCP rules configured, acceptEdits Gemini MCP must pass through"
            );
        }
    }

    #[test]
    fn test_mcp_accept_edits_respects_block_rules() {
        // Block rules MUST fire before the MCP accept-edits allow rules
        // so default blocks (firecrawl on GitHub URLs) can't be bypassed
        // by a rule the user added to accept_edits_mcp.
        //
        // Only run when the user's config still uses the default block rules
        // (i.e. they haven't customized `block_tools`). Otherwise we can't
        // assume firecrawl is still blocked.
        if crate::config::load().block_tools.is_some() {
            return;
        }

        // The production handler receives tool_input_map as a separate parameter
        // (re-parsed from the raw JSON in main.rs), so we pass the same map here.
        let mut map = serde_json::Map::new();
        map.insert(
            "url".to_string(),
            serde_json::Value::String(
                "https://raw.githubusercontent.com/example/repo/main/file.txt".to_string(),
            ),
        );

        let input = PermissionRequestInput {
            hook_event_name: "PermissionRequest".to_string(),
            tool_name: "mcp__firecrawl__firecrawl_scrape".to_string(),
            cwd: "/tmp".to_string(),
            permission_mode: "acceptEdits".to_string(),
            tool_input: ToolInputVariant::Map(map.clone()),
            ..Default::default()
        };

        let result = handle_permission_request(&input, &map);
        let output = result.expect("firecrawl on raw.githubusercontent.com must be denied");
        let json =
            serde_json::to_string(&output).expect("serialize PermissionRequestOutput for assert");
        assert!(
            json.contains("\"behavior\":\"deny\""),
            "expected deny-shaped output, got: {json}"
        );
    }

    // ----- Pure match_mcp_rule unit tests (no config I/O, no env) -----

    fn approval_rule(tool: &str) -> crate::config::McpApprovalRule {
        crate::config::McpApprovalRule {
            tool: tool.to_string(),
            reason: None,
            if_project_under: vec![],
            if_project_has: vec![],
        }
    }

    fn approval_rule_with_reason(tool: &str, reason: &str) -> crate::config::McpApprovalRule {
        crate::config::McpApprovalRule {
            tool: tool.to_string(),
            reason: Some(reason.to_string()),
            if_project_under: vec![],
            if_project_has: vec![],
        }
    }

    #[test]
    fn match_mcp_rule_wrong_mode_returns_none() {
        let rules = vec![approval_rule("mcp__serena__*")];
        assert!(match_mcp_rule(&rules, "mcp__serena__find_symbol", "default", "").is_none());
        assert!(match_mcp_rule(&rules, "mcp__serena__find_symbol", "", "").is_none());
        assert!(match_mcp_rule(&rules, "mcp__serena__find_symbol", "auto", "").is_none());
    }

    #[test]
    fn match_mcp_rule_non_mcp_tool_returns_none() {
        let rules = vec![approval_rule("*")];
        // Bash is not an MCP tool even though the glob matches.
        assert!(match_mcp_rule(&rules, "Bash", "acceptEdits", "").is_none());
        assert!(match_mcp_rule(&rules, "Read", "acceptEdits", "").is_none());
    }

    #[test]
    fn match_mcp_rule_empty_rules_returns_none() {
        assert!(match_mcp_rule(&[], "mcp__serena__find_symbol", "acceptEdits", "").is_none());
    }

    #[test]
    fn match_mcp_rule_prefix_glob_matches() {
        let rules = vec![approval_rule("mcp__serena__*")];
        let m = match_mcp_rule(&rules, "mcp__serena__find_symbol", "acceptEdits", "");
        assert!(m.is_some());
        assert_eq!(m.unwrap().tool, "mcp__serena__*");
    }

    #[test]
    fn match_mcp_rule_contains_glob_matches_both_namespaces() {
        // `*serena*` should catch both Claude double-underscore and Gemini
        // single-underscore MCP namespaces.
        let rules = vec![approval_rule("*serena*")];
        assert!(match_mcp_rule(&rules, "mcp__serena__find_symbol", "acceptEdits", "").is_some());
        assert!(match_mcp_rule(&rules, "mcp_serena_find_symbol", "acceptEdits", "").is_some());
    }

    #[test]
    fn match_mcp_rule_directory_conditions_filter() {
        let mut rule = approval_rule("mcp__pw__*");
        rule.if_project_under = vec!["/allowed".to_string()];
        let rules = vec![rule];

        // Matches when project is under the allowed path.
        assert!(match_mcp_rule(&rules, "mcp__pw__click", "acceptEdits", "/allowed/sub").is_some());
        // Rejected when project is elsewhere.
        assert!(match_mcp_rule(&rules, "mcp__pw__click", "acceptEdits", "/other").is_none());
        // Rejected when project_dir is empty (fail-closed).
        assert!(match_mcp_rule(&rules, "mcp__pw__click", "acceptEdits", "").is_none());
    }

    #[test]
    fn match_mcp_rule_returns_rule_with_reason() {
        // Callers can read the reason off the returned rule reference
        // (used by the main-thread PreToolUse path to populate allow reason).
        let rules = vec![approval_rule_with_reason(
            "mcp__x__*",
            "batched under acceptEdits",
        )];
        let m = match_mcp_rule(&rules, "mcp__x__y", "acceptEdits", "");
        let got = m.expect("should match");
        assert_eq!(got.reason.as_deref(), Some("batched under acceptEdits"));
    }

    #[test]
    fn match_mcp_rule_first_match_wins() {
        let rules = vec![
            approval_rule_with_reason("mcp__serena__find_symbol", "specific"),
            approval_rule_with_reason("mcp__serena__*", "glob"),
        ];
        let m = match_mcp_rule(&rules, "mcp__serena__find_symbol", "acceptEdits", "");
        assert_eq!(m.unwrap().reason.as_deref(), Some("specific"));
    }
}

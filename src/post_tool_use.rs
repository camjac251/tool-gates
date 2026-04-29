//! PostToolUse hook handler.
//!
//! Detects when commands that returned "ask" complete successfully,
//! and adds them to the pending approval queue.

use crate::models::{PostToolUseInput, PostToolUseOutput};
use crate::pending::{PendingApproval, append_pending};
use crate::tracking::take_tracked_command;

pub fn handle_post_tool_use(input: &PostToolUseInput) -> Option<PostToolUseOutput> {
    // Atomically remove-and-return the tracked command in a single lock scope.
    // This avoids the TOCTOU race of peek-then-take (two separate lock acquisitions).
    let tracked = take_tracked_command(&input.tool_use_id)?;

    // Only add to pending if the command succeeded
    if !input.is_success() {
        // Already removed from tracking above — nothing more to do
        return None;
    }

    // Skip the pending append if a settings.json rule now allows this command.
    // This catches the race where a user added the rule manually (or via
    // `tool-gates approve`) between PreToolUse tracking and PostToolUse
    // confirmation -- otherwise a stale entry sits in the queue suggesting
    // the same approval the user already made.
    if command_already_allowed_by_settings(&tracked.command, &tracked.cwd) {
        return None;
    }

    // Create a pending approval entry
    let approval = PendingApproval::new(
        tracked.command,
        tracked.suggested_patterns,
        tracked.breakdown,
        tracked.project_id,
        tracked.cwd,
        tracked.session_id,
    );

    // Append to global pending queue.
    // If this fails, the entry is already removed from tracking — acceptable
    // since it would have expired via TTL anyway.
    if let Err(e) = append_pending(approval) {
        eprintln!("Warning: Failed to save pending approval: {e}");
    }

    // Silent — Claude already saw the permission prompt and user's approval
    // in the conversation flow. The pending queue accumulates data for the
    // /tool-gates:review skill to use when the user asks for it.
    None
}

/// Returns true if `command` would be allowed by the user's settings.json,
/// considering both deny precedence and the most-specific ask/allow resolver.
/// Used to filter pending entries that are already redundant with existing
/// rules.
fn command_already_allowed_by_settings(command: &str, cwd: &str) -> bool {
    let settings = crate::settings::Settings::load(cwd);
    matches!(
        settings.check_command(command),
        crate::settings::SettingsDecision::Allow
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_is_success_with_exit_code_0() {
        let input = PostToolUseInput {
            tool_response: Some(json!({"exit_code": 0})),
            ..Default::default()
        };
        assert!(input.is_success());
    }

    #[test]
    fn test_is_success_with_exit_code_1() {
        let input = PostToolUseInput {
            tool_response: Some(json!({"exit_code": 1})),
            ..Default::default()
        };
        assert!(!input.is_success());
    }

    #[test]
    fn test_is_success_with_no_response() {
        // PostToolUse only fires for successful calls, so missing
        // tool_response should default to success
        let input = PostToolUseInput {
            tool_response: None,
            ..Default::default()
        };
        assert!(input.is_success());
    }

    #[test]
    fn test_is_success_with_string_response() {
        // Bash tool_response may be a plain string (stdout), not a JSON object
        let input = PostToolUseInput {
            tool_response: Some(json!("some command output")),
            ..Default::default()
        };
        assert!(input.is_success());
    }

    #[test]
    fn test_handle_untracked_command_returns_none() {
        let input = PostToolUseInput {
            tool_use_id: "untracked_id".to_string(),
            tool_response: Some(json!({"exit_code": 0})),
            ..Default::default()
        };

        // Should return None since this ID wasn't tracked
        assert!(handle_post_tool_use(&input).is_none());
    }

    #[test]
    fn test_command_already_allowed_by_settings_no_settings() {
        // No settings file present anywhere -> never allowed.
        // Use /tmp as cwd; command shape doesn't matter.
        assert!(!command_already_allowed_by_settings(
            "npm install foo",
            "/tmp"
        ));
    }

    #[serial_test::serial]
    #[test]
    fn test_command_already_allowed_by_settings_matches_user_allow() {
        use std::env;
        use std::fs;
        let temp = tempfile::TempDir::new().unwrap();
        let saved = env::var("HOME").ok();
        // SAFETY: serialized via #[serial], no concurrent env access.
        unsafe { env::set_var("HOME", temp.path()) };

        let claude_dir = temp.path().join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        fs::write(
            claude_dir.join("settings.json"),
            r#"{"permissions": {"allow": ["Bash(npm install:*)"]}}"#,
        )
        .unwrap();

        // Cwd doesn't matter for user-scope settings.
        assert!(command_already_allowed_by_settings(
            "npm install foo",
            temp.path().to_str().unwrap()
        ));
        // Unrelated command must not match.
        assert!(!command_already_allowed_by_settings(
            "rm -rf /tmp/x",
            temp.path().to_str().unwrap()
        ));

        // Restore HOME so peer tests aren't disturbed.
        unsafe {
            match saved {
                Some(v) => env::set_var("HOME", v),
                None => env::remove_var("HOME"),
            }
        }
    }
}

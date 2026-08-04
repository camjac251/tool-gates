//! Claude TaskOutput sequencing contract tests.
//!
//! These spawn the real binary across consecutive hook events so the
//! assertions cover the persistent session state and emitted wire format.

use std::io::Write;
use std::process::{Command, Output, Stdio};

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_tool-gates")
}

fn run_claude(stdin_json: &str, xdg_cache: &std::path::Path) -> Output {
    let mut child = Command::new(bin_path())
        .env("XDG_CACHE_HOME", xdg_cache)
        .env_remove("CLAUDE_PROJECT_DIR")
        .env_remove("GEMINI_PROJECT_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tool-gates");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stdin_json.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait for tool-gates")
}

fn record_background_bash(xdg_cache: &std::path::Path, session_id: &str, task_id: &str) {
    let payload = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": session_id,
        "cwd": "/tmp/project",
        "tool_name": "Bash",
        "tool_use_id": "toolu_background_start",
        "tool_input": {
            "command": "my-service watch",
            "run_in_background": true
        },
        "tool_response": {
            "backgroundTaskId": task_id
        }
    });
    let output = run_claude(&payload.to_string(), xdg_cache);
    assert!(
        output.status.success(),
        "background PostToolUse failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn task_output(
    xdg_cache: &std::path::Path,
    session_id: &str,
    task_id: &str,
    block: Option<bool>,
) -> Output {
    let mut tool_input = serde_json::json!({"task_id": task_id});
    if let Some(block) = block {
        tool_input["block"] = serde_json::json!(block);
    }
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": session_id,
        "cwd": "/tmp/project",
        "tool_name": "TaskOutput",
        "tool_use_id": "toolu_task_output",
        "tool_input": tool_input
    });
    run_claude(&payload.to_string(), xdg_cache)
}

fn submit_user_prompt(xdg_cache: &std::path::Path, session_id: &str) -> Output {
    let payload = serde_json::json!({
        "hook_event_name": "UserPromptSubmit",
        "session_id": session_id,
        "cwd": "/tmp/project",
        "prompt": "Continue with the next step."
    });
    run_claude(&payload.to_string(), xdg_cache)
}

fn read_file_pre_tool_use(xdg_cache: &std::path::Path, session_id: &str) -> Output {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": session_id,
        "cwd": "/tmp/project",
        "tool_name": "Read",
        "tool_use_id": "toolu_useful_read",
        "tool_input": {"file_path": "/tmp/project/README.md"}
    });
    run_claude(&payload.to_string(), xdg_cache)
}

fn successful_post_tool_use(
    xdg_cache: &std::path::Path,
    session_id: &str,
    tool_name: &str,
) -> Output {
    let payload = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": session_id,
        "cwd": "/tmp/project",
        "tool_name": tool_name,
        "tool_use_id": "toolu_completed_work",
        "tool_input": {"file_path": "/tmp/project/README.md"},
        "tool_response": {"result": "completed"}
    });
    run_claude(&payload.to_string(), xdg_cache)
}

fn failed_post_tool_use(xdg_cache: &std::path::Path, session_id: &str) -> Output {
    let payload = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": session_id,
        "cwd": "/tmp/project",
        "tool_name": "Read",
        "tool_use_id": "toolu_failed_work",
        "tool_input": {"file_path": "/tmp/project/missing.txt"},
        "tool_response": {"exit_code": 1}
    });
    run_claude(&payload.to_string(), xdg_cache)
}

#[test]
fn immediate_blocking_wait_for_just_started_background_bash_is_denied() {
    let xdg_cache = tempfile::tempdir().expect("cache tempdir");
    record_background_bash(xdg_cache.path(), "session-a", "task-a");

    let output = task_output(xdg_cache.path(), "session-a", "task-a", Some(true));
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");

    assert!(
        output.status.success(),
        "TaskOutput PreToolUse failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("\"permissionDecision\":\"deny\"") && stdout.contains("background command"),
        "expected structured redundant-wait denial, got: {stdout}"
    );
}

#[test]
fn omitted_block_uses_task_output_blocking_default_and_is_denied() {
    let xdg_cache = tempfile::tempdir().expect("cache tempdir");
    record_background_bash(xdg_cache.path(), "session-default", "task-default");

    let output = task_output(xdg_cache.path(), "session-default", "task-default", None);
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");

    assert!(
        stdout.contains("\"permissionDecision\":\"deny\""),
        "expected omitted block to retain TaskOutput's blocking default, got: {stdout}"
    );
}

#[test]
fn a_new_user_turn_clears_the_immediate_wait_candidate() {
    let xdg_cache = tempfile::tempdir().expect("cache tempdir");
    record_background_bash(xdg_cache.path(), "session-turn", "task-turn");
    let prompt = submit_user_prompt(xdg_cache.path(), "session-turn");
    assert!(
        prompt.status.success(),
        "UserPromptSubmit failed: {}",
        String::from_utf8_lossy(&prompt.stderr)
    );

    let output = task_output(xdg_cache.path(), "session-turn", "task-turn", Some(true));
    assert!(
        output.stdout.is_empty(),
        "later user turn must pass through, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn attempted_intervening_tool_work_does_not_license_a_blocking_wait() {
    let xdg_cache = tempfile::tempdir().expect("cache tempdir");
    record_background_bash(xdg_cache.path(), "session-work", "task-work");
    let read = read_file_pre_tool_use(xdg_cache.path(), "session-work");
    assert!(
        read.status.success(),
        "Read PreToolUse failed: {}",
        String::from_utf8_lossy(&read.stderr)
    );

    let output = task_output(xdg_cache.path(), "session-work", "task-work", Some(true));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("\"permissionDecision\":\"deny\""),
        "a tool attempt is not completed useful work: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn successful_intervening_tool_work_allows_a_later_blocking_wait() {
    let xdg_cache = tempfile::tempdir().expect("cache tempdir");
    record_background_bash(xdg_cache.path(), "session-success", "task-success");
    let read = successful_post_tool_use(xdg_cache.path(), "session-success", "Read");
    assert!(
        read.status.success(),
        "Read PostToolUse failed: {}",
        String::from_utf8_lossy(&read.stderr)
    );

    let output = task_output(
        xdg_cache.path(),
        "session-success",
        "task-success",
        Some(true),
    );
    assert!(
        output.stdout.is_empty(),
        "later wait after successful work must pass through, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn successful_unmatched_tool_work_clears_the_candidate() {
    let xdg_cache = tempfile::tempdir().expect("cache tempdir");
    record_background_bash(xdg_cache.path(), "session-agent-work", "task-agent-work");
    let agent = successful_post_tool_use(xdg_cache.path(), "session-agent-work", "Agent");
    assert!(agent.status.success(), "Agent PostToolUse failed");

    let output = task_output(
        xdg_cache.path(),
        "session-agent-work",
        "task-agent-work",
        Some(true),
    );
    assert!(
        output.stdout.is_empty(),
        "successful Agent work must clear the immediate sequence, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn failed_intervening_work_does_not_clear_the_candidate() {
    let xdg_cache = tempfile::tempdir().expect("cache tempdir");
    record_background_bash(xdg_cache.path(), "session-failed-work", "task-failed-work");
    let failed = failed_post_tool_use(xdg_cache.path(), "session-failed-work");
    assert!(
        failed.status.success(),
        "failed-work hook invocation failed"
    );

    let output = task_output(
        xdg_cache.path(),
        "session-failed-work",
        "task-failed-work",
        Some(true),
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("\"permissionDecision\":\"deny\""),
        "failed work must not license a blocking wait: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn unrelated_task_output_does_not_consume_an_old_bash_sequence() {
    let xdg_cache = tempfile::tempdir().expect("cache tempdir");
    record_background_bash(xdg_cache.path(), "session-unrelated", "task-local");

    let unrelated = task_output(
        xdg_cache.path(),
        "session-unrelated",
        "task-agent",
        Some(true),
    );
    assert!(
        unrelated.stdout.is_empty(),
        "unrelated task must pass through, got: {}",
        String::from_utf8_lossy(&unrelated.stdout)
    );

    let later = task_output(
        xdg_cache.path(),
        "session-unrelated",
        "task-local",
        Some(true),
    );
    assert!(
        later.stdout.is_empty(),
        "the unrelated task is intervening work, got: {}",
        String::from_utf8_lossy(&later.stdout)
    );
}

#[test]
fn malformed_task_output_input_fails_open_and_clears_the_candidate() {
    let xdg_cache = tempfile::tempdir().expect("cache tempdir");
    record_background_bash(xdg_cache.path(), "session-malformed", "task-malformed");

    let malformed = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "session-malformed",
        "cwd": "/tmp/project",
        "tool_name": "TaskOutput",
        "tool_use_id": "toolu_malformed",
        "tool_input": {"task_id": "task-malformed", "block": "yes"}
    });
    let first = run_claude(&malformed.to_string(), xdg_cache.path());
    assert!(
        first.stdout.is_empty(),
        "uncertain input must fail open, got: {}",
        String::from_utf8_lossy(&first.stdout)
    );

    let later = task_output(
        xdg_cache.path(),
        "session-malformed",
        "task-malformed",
        Some(true),
    );
    assert!(
        later.stdout.is_empty(),
        "uncertain intervening input must clear stale state, got: {}",
        String::from_utf8_lossy(&later.stdout)
    );
}

#[test]
fn nonblocking_status_check_is_allowed_without_licensing_a_blocking_poll() {
    let xdg_cache = tempfile::tempdir().expect("cache tempdir");
    record_background_bash(xdg_cache.path(), "session-status", "task-status");

    let status = task_output(
        xdg_cache.path(),
        "session-status",
        "task-status",
        Some(false),
    );
    assert!(
        status.stdout.is_empty(),
        "block=false must pass through, got: {}",
        String::from_utf8_lossy(&status.stdout)
    );

    let blocking = task_output(
        xdg_cache.path(),
        "session-status",
        "task-status",
        Some(true),
    );
    assert!(
        String::from_utf8_lossy(&blocking.stdout).contains("\"permissionDecision\":\"deny\""),
        "a status check is not useful intervening work: {}",
        String::from_utf8_lossy(&blocking.stdout)
    );
}

#[test]
fn task_ids_never_correlate_across_sessions() {
    let xdg_cache = tempfile::tempdir().expect("cache tempdir");
    record_background_bash(xdg_cache.path(), "session-source", "task-shared");

    let output = task_output(xdg_cache.path(), "session-other", "task-shared", Some(true));
    assert!(
        output.stdout.is_empty(),
        "cross-session task IDs must pass through, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn only_positive_background_bash_results_create_candidates() {
    let xdg_cache = tempfile::tempdir().expect("cache tempdir");
    let cases = [
        (
            "session-foreground",
            serde_json::json!({"run_in_background": false}),
            serde_json::json!({"backgroundTaskId": "task-foreground"}),
            "task-foreground",
        ),
        (
            "session-no-id",
            serde_json::json!({"run_in_background": true}),
            serde_json::json!({"success": true}),
            "task-no-id",
        ),
        (
            "session-failed",
            serde_json::json!({"run_in_background": true}),
            serde_json::json!({"backgroundTaskId": "task-failed", "exit_code": 1}),
            "task-failed",
        ),
    ];

    for (session_id, extra_input, tool_response, task_id) in cases {
        let mut tool_input = serde_json::json!({"command": "my-service watch"});
        tool_input
            .as_object_mut()
            .expect("tool input object")
            .extend(extra_input.as_object().expect("extra input object").clone());
        let payload = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": session_id,
            "cwd": "/tmp/project",
            "tool_name": "Bash",
            "tool_use_id": "toolu_candidate_check",
            "tool_input": tool_input,
            "tool_response": tool_response
        });
        let post = run_claude(&payload.to_string(), xdg_cache.path());
        assert!(post.status.success(), "PostToolUse failed for {session_id}");

        let output = task_output(xdg_cache.path(), session_id, task_id, Some(true));
        assert!(
            output.stdout.is_empty(),
            "non-positive background result must pass through for {session_id}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[test]
fn agent_task_results_are_not_treated_as_background_bash() {
    let xdg_cache = tempfile::tempdir().expect("cache tempdir");
    let payload = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": "session-agent",
        "cwd": "/tmp/project",
        "tool_name": "Agent",
        "tool_use_id": "toolu_agent_start",
        "tool_input": {"description": "Review one file"},
        "tool_response": {"backgroundTaskId": "task-agent"}
    });
    let post = run_claude(&payload.to_string(), xdg_cache.path());
    assert!(post.status.success(), "Agent PostToolUse failed");

    let output = task_output(xdg_cache.path(), "session-agent", "task-agent", Some(true));
    assert!(
        output.stdout.is_empty(),
        "agent task must pass through, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn corrupt_persisted_state_fails_open() {
    let xdg_cache = tempfile::tempdir().expect("cache tempdir");
    let state_dir = xdg_cache.path().join("tool-gates");
    std::fs::create_dir_all(&state_dir).expect("create state dir");
    std::fs::write(state_dir.join("task-output-guard.json"), "not-json")
        .expect("write corrupt state");

    let output = task_output(
        xdg_cache.path(),
        "session-corrupt",
        "task-corrupt",
        Some(true),
    );
    assert!(
        output.stdout.is_empty(),
        "corrupt state must fail open, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("Warning: Failed to inspect background task state"),
        "corrupt state must emit a diagnostic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(state_dir.join("task-output-guard.json"))
            .expect("reread corrupt state"),
        "not-json",
        "corrupt state evidence must not be overwritten"
    );
}

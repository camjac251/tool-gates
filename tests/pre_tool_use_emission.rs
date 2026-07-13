//! Real-binary coverage for client-specific PreToolUse output contracts.

use std::io::Write;
use std::process::{Command, Output, Stdio};

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_tool-gates")
}

fn run_hook(client: Option<&str>, payload: &str) -> Output {
    let temp = tempfile::tempdir().expect("hook tempdir");
    let mut command = Command::new(bin_path());
    if let Some(client) = client {
        command.args(["--client", client]);
    }
    let mut child = command
        .current_dir(temp.path())
        .env("HOME", temp.path().join("home"))
        .env("XDG_CONFIG_HOME", temp.path().join("config"))
        .env("XDG_CACHE_HOME", temp.path().join("cache"))
        .env_remove("CLAUDE_PROJECT_DIR")
        .env_remove("GEMINI_PROJECT_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hook");
    child
        .stdin
        .as_mut()
        .expect("hook stdin")
        .write_all(payload.as_bytes())
        .expect("write hook payload");
    child.wait_with_output().expect("wait for hook")
}

fn stdout_json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "parse hook stdout: {error}; stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn claude_deny_uses_structured_output_with_success_status() {
    let output = run_hook(
        None,
        r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#,
    );
    let value = stdout_json(&output);

    assert!(
        output.status.success(),
        "Claude structured deny failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn gemini_deny_uses_flat_block_output_and_exit_two() {
    let output = run_hook(
        None,
        r#"{"hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"rm -rf /"}}"#,
    );
    let value = stdout_json(&output);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(value["decision"], "block");
}

#[test]
fn codex_deny_uses_structured_output_with_success_status() {
    let output = run_hook(
        Some("codex"),
        r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#,
    );
    let value = stdout_json(&output);

    assert!(
        output.status.success(),
        "Codex structured deny failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn antigravity_deny_uses_flat_output_with_success_status() {
    let output = run_hook(
        Some("antigravity"),
        r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf /"}},"workspacePaths":["/workspace"]}"#,
    );
    let value = stdout_json(&output);

    assert!(
        output.status.success(),
        "Antigravity structured deny failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(value["decision"], "deny");
}

#[test]
fn codex_non_deny_emits_nothing() {
    let output = run_hook(
        Some("codex"),
        r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status"}}"#,
    );

    assert!(output.status.success());
    assert!(
        output.stdout.is_empty(),
        "Codex pass-through emitted: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn antigravity_non_deny_emits_nothing() {
    let output = run_hook(
        Some("antigravity"),
        r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"git status"}},"workspacePaths":["/workspace"]}"#,
    );

    assert!(output.status.success());
    assert!(
        output.stdout.is_empty(),
        "Antigravity pass-through emitted: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn antigravity_malformed_json_fails_closed() {
    let output = run_hook(
        Some("antigravity"),
        r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf /""#,
    );
    let value = stdout_json(&output);

    assert!(output.status.success());
    assert_eq!(value["decision"], "deny");
}

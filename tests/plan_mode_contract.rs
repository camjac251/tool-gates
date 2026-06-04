//! Plan-mode contract tests.
//!
//! These spawn the real binary for hook surfaces that write to stdout so the
//! assertions cover the actual serialized hook output.

use std::io::Write;
use std::process::{Command, Output, Stdio};

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_tool-gates")
}

fn run_tool_gates(
    stdin_json: &str,
    xdg_config: &std::path::Path,
    xdg_cache: &std::path::Path,
) -> Output {
    let mut child = Command::new(bin_path())
        .env("XDG_CONFIG_HOME", xdg_config)
        .env("XDG_CACHE_HOME", xdg_cache)
        .env_remove("CLAUDE_PROJECT_DIR")
        .env_remove("GEMINI_PROJECT_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn tool-gates: {e}"));
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stdin_json.as_bytes())
        .expect("write stdin");
    child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("wait for tool-gates: {e}"))
}

#[test]
fn claude_bash_pre_tool_use_denies_mutating_command_in_plan_mode() {
    let xdg_config = tempfile::tempdir().expect("config tempdir");
    let xdg_cache = tempfile::tempdir().expect("cache tempdir");

    let output = run_tool_gates(
        r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"touch /tmp/testfile"},"cwd":"/tmp/project","session_id":"plan-mode-bash","tool_use_id":"toolu_plan_bash","permission_mode":"plan"}"#,
        xdg_config.path(),
        xdg_cache.path(),
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");

    assert!(
        output.status.success(),
        "PreToolUse should succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("\"permissionDecision\":\"deny\"") && stdout.contains("Plan mode"),
        "expected plan-mode deny on mutating bash, got: {stdout}"
    );
}

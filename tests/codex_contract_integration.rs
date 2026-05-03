//! Codex hook contract integration tests.
//!
//! These spawn the real binary with `--client codex` so the assertions cover
//! Codex-specific stdout/exit-code behavior and PreToolUse/PostToolUse
//! tracking side effects.

use std::io::Write;
use std::process::{Command, Output, Stdio};

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_tool-gates")
}

fn run_codex(
    hook_name: &str,
    stdin_json: &str,
    xdg_config: &std::path::Path,
    xdg_cache: &std::path::Path,
) -> Output {
    let mut child = Command::new(bin_path())
        .args(["--client", "codex"])
        .env("XDG_CONFIG_HOME", xdg_config)
        .env("XDG_CACHE_HOME", xdg_cache)
        .env_remove("CLAUDE_PROJECT_DIR")
        .env_remove("GEMINI_PROJECT_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn tool-gates for {hook_name}: {e}"));
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stdin_json.as_bytes())
        .expect("write stdin");
    child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("wait for {hook_name}: {e}"))
}

#[test]
fn codex_malformed_pre_tool_use_returns_structured_deny_on_success_status() {
    let xdg_config = tempfile::tempdir().expect("config tempdir");
    let xdg_cache = tempfile::tempdir().expect("cache tempdir");

    let output = run_codex(
        "PreToolUse",
        "{not-json",
        xdg_config.path(),
        xdg_cache.path(),
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");

    assert!(
        output.status.success(),
        "Codex structured denies must exit 0 so Codex parses stdout; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("\"hookEventName\":\"PreToolUse\"")
            && stdout.contains("\"permissionDecision\":\"deny\"")
            && stdout.contains("tool-gates: malformed PreToolUse hook input"),
        "expected Codex deny JSON on stdout, got: {stdout}"
    );
}

#[test]
fn codex_shell_ask_flows_to_pending_after_successful_post_tool_use() {
    let xdg_config = tempfile::tempdir().expect("config tempdir");
    let xdg_cache = tempfile::tempdir().expect("cache tempdir");

    let pre = run_codex(
        "PreToolUse",
        r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"mytool deploy"},"cwd":"/tmp/project","session_id":"session-codex","tool_use_id":"toolu_codex_track","permission_mode":"default","transcript_path":null}"#,
        xdg_config.path(),
        xdg_cache.path(),
    );
    assert!(
        pre.status.success(),
        "PreToolUse should pass through for Codex ask output; stderr: {}",
        String::from_utf8_lossy(&pre.stderr)
    );

    let post = run_codex(
        "PostToolUse",
        r#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"mytool deploy"},"tool_response":{"exit_code":0},"cwd":"/tmp/project","session_id":"session-codex","tool_use_id":"toolu_codex_track"}"#,
        xdg_config.path(),
        xdg_cache.path(),
    );
    assert!(
        post.status.success(),
        "PostToolUse should succeed; stderr: {}",
        String::from_utf8_lossy(&post.stderr)
    );

    let pending_path = xdg_cache.path().join("tool-gates").join("pending.jsonl");
    let pending = std::fs::read_to_string(&pending_path)
        .unwrap_or_else(|e| panic!("read pending queue at {}: {e}", pending_path.display()));
    assert!(
        pending.contains("\"command\":\"mytool deploy\"")
            && pending.contains("\"session_id\":\"session-codex\""),
        "Codex successful PostToolUse should promote tracked ask to pending queue: {pending}"
    );
}

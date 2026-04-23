//! Integration tests for the `[[accept_edits_mcp]]` feature.
//!
//! These tests spawn the release binary with a fixture config, feed it
//! a hook JSON on stdin, and assert on the JSON emitted on stdout. This
//! exercises the real PreToolUse / PermissionRequest dispatch code paths
//! end-to-end, not just the pure match logic.

use std::io::Write;
use std::process::{Command, Stdio};

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_tool-gates")
}

/// Spawn the tool-gates binary with `XDG_CONFIG_HOME` pointed at a temp dir,
/// feed `stdin_json` to stdin, and return stdout as a String.
fn run(stdin_json: &str, xdg: &std::path::Path) -> String {
    let mut child = Command::new(bin_path())
        .env("XDG_CONFIG_HOME", xdg)
        .env_remove("CLAUDE_PROJECT_DIR")
        .env_remove("GEMINI_PROJECT_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tool-gates binary");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stdin_json.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait_with_output");
    String::from_utf8(out.stdout).expect("utf8 stdout")
}

/// Write a config.toml under `<xdg>/tool-gates/config.toml`.
fn write_config(xdg: &std::path::Path, body: &str) {
    let cfg_dir = xdg.join("tool-gates");
    std::fs::create_dir_all(&cfg_dir).expect("mkdir cfg dir");
    std::fs::write(cfg_dir.join("config.toml"), body).expect("write config.toml");
}

#[test]
fn accept_edits_mcp_main_thread_allow() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_config(
        tmp.path(),
        r#"[[accept_edits_mcp]]
tool = "mcp__serena__*"
reason = "Batched under acceptEdits"
"#,
    );
    let out = run(
        r#"{"hook_event_name":"PreToolUse","tool_name":"mcp__serena__find_symbol","cwd":"/tmp","permission_mode":"acceptEdits","tool_input":{},"session_id":"t","tool_use_id":"toolu_t"}"#,
        tmp.path(),
    );
    assert!(
        out.contains("\"permissionDecision\":\"allow\""),
        "expected allow, got: {out}"
    );
    assert!(
        out.contains("Batched under acceptEdits"),
        "expected reason, got: {out}"
    );
}

#[test]
fn accept_edits_mcp_default_mode_passes_through() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_config(
        tmp.path(),
        r#"[[accept_edits_mcp]]
tool = "mcp__serena__*"
"#,
    );
    let out = run(
        r#"{"hook_event_name":"PreToolUse","tool_name":"mcp__serena__find_symbol","cwd":"/tmp","permission_mode":"default","tool_input":{},"session_id":"t","tool_use_id":"toolu_t"}"#,
        tmp.path(),
    );
    // Not allow — either empty/no-opinion output or "ask". The rule must not
    // fire outside acceptEdits mode.
    assert!(
        !out.contains("\"permissionDecision\":\"allow\""),
        "rule should not fire in default mode, got: {out}"
    );
}

#[test]
fn accept_edits_mcp_block_rule_wins() {
    // A user adds an allow rule for firecrawl in acceptEdits, but the
    // default block rule on `*firecrawl*` + GitHub URL must still deny.
    // This asserts the main-thread ordering (block before allow).
    let tmp = tempfile::tempdir().expect("tempdir");
    write_config(
        tmp.path(),
        r#"[[accept_edits_mcp]]
tool = "*firecrawl*"
"#,
    );
    let out = run(
        r#"{"hook_event_name":"PreToolUse","tool_name":"mcp__firecrawl__firecrawl_scrape","cwd":"/tmp","permission_mode":"acceptEdits","tool_input":{"url":"https://raw.githubusercontent.com/example/repo/main/file.txt"},"session_id":"t","tool_use_id":"toolu_t"}"#,
        tmp.path(),
    );
    assert!(
        out.contains("\"permissionDecision\":\"deny\""),
        "block must override accept_edits_mcp allow, got: {out}"
    );
}

#[test]
fn permission_request_mcp_not_short_circuited() {
    // The PermissionRequest dispatcher must not short-circuit MCP tools
    // before reaching handle_permission_request. With no user rules, the
    // handler returns None and we expect pass-through (empty output) —
    // specifically, NOT a deny caused by some upstream guard.
    let tmp = tempfile::tempdir().expect("tempdir");
    // No config file — fully default behavior.
    let out = run(
        r#"{"hook_event_name":"PermissionRequest","tool_name":"mcp__serena__find_symbol","cwd":"/tmp","permission_mode":"acceptEdits","tool_input":{},"session_id":"t"}"#,
        tmp.path(),
    );
    assert!(
        out.is_empty() || !out.contains("\"behavior\":\"deny\""),
        "dispatcher must not short-circuit MCP tools: {out}"
    );
}

#[test]
fn permission_request_block_rule_denies_firecrawl_github() {
    // Subagent path: default block rule for *firecrawl* + raw GitHub URL
    // must deny. This asserts Fix 1 (block check runs before MCP allow)
    // in an integration-level test, not just a unit test.
    let tmp = tempfile::tempdir().expect("tempdir");
    // No config — uses default block rules.
    let out = run(
        r#"{"hook_event_name":"PermissionRequest","tool_name":"mcp__firecrawl__firecrawl_scrape","cwd":"/tmp","permission_mode":"acceptEdits","tool_input":{"url":"https://raw.githubusercontent.com/example/repo/main/file.txt"},"session_id":"t"}"#,
        tmp.path(),
    );
    assert!(
        out.contains("\"behavior\":\"deny\""),
        "firecrawl on GitHub must deny on subagent path: {out}"
    );
}

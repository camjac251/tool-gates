//! Integration tests for the scratch-directory auto-allow.
//!
//! Spawns the release binary with `TOOL_GATES_SCRATCH` pointed at a temp dir and a
//! `Write` hook payload on stdin, then asserts on the JSON emitted on stdout.
//! This exercises the real file-tool branch in `main.rs` end-to-end.

use std::io::Write;
use std::process::{Command, Stdio};

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_tool-gates")
}

/// Spawn the binary with `XDG_CONFIG_HOME` (no config) and `TOOL_GATES_SCRATCH`
/// pointed at `scratch`, feed `stdin_json`, return stdout. `session` pins
/// `CLAUDE_CODE_SESSION_ID` in the child env; `None` removes it, so results
/// stay deterministic even when the test itself runs inside a Claude session.
fn run(stdin_json: &str, xdg: &std::path::Path, scratch: &std::path::Path) -> String {
    run_with_session(stdin_json, xdg, scratch, None)
}

fn run_with_session(
    stdin_json: &str,
    xdg: &std::path::Path,
    scratch: &std::path::Path,
    session: Option<&str>,
) -> String {
    let mut command = Command::new(bin_path());
    command
        .env("XDG_CONFIG_HOME", xdg)
        .env("TOOL_GATES_SCRATCH", scratch)
        .env_remove("CLAUDE_PROJECT_DIR")
        .env_remove("GEMINI_PROJECT_DIR");
    match session {
        Some(sid) => command.env("CLAUDE_CODE_SESSION_ID", sid),
        None => command.env_remove("CLAUDE_CODE_SESSION_ID"),
    };
    let mut child = command
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
    assert!(
        out.status.success(),
        "tool-gates exited with {}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf8 stdout")
}

fn write_payload(file_path: &str, mode: &str) -> String {
    format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"Write","cwd":"/home/user/project","permission_mode":"{mode}","tool_input":{{"file_path":"{file_path}","content":"x"}},"session_id":"t","tool_use_id":"toolu_t"}}"#
    )
}

#[test]
fn write_under_scratch_auto_allows() {
    let xdg = tempfile::tempdir().expect("xdg");
    let scratch = tempfile::tempdir().expect("scratch");
    let target = format!("{}/p/s/note.txt", scratch.path().display());
    let out = run(
        &write_payload(&target, "default"),
        xdg.path(),
        scratch.path(),
    );
    assert!(
        out.contains("\"permissionDecision\":\"allow\""),
        "write under scratch should allow, got: {out}"
    );
}

#[test]
fn write_outside_scratch_does_not_allow() {
    let xdg = tempfile::tempdir().expect("xdg");
    let scratch = tempfile::tempdir().expect("scratch");
    let out = run(
        &write_payload("/tmp/not-scratch/note.txt", "default"),
        xdg.path(),
        scratch.path(),
    );
    assert_eq!(out, "", "write outside scratch must pass through");
}

#[test]
fn write_under_scratch_in_plan_mode_does_not_allow() {
    let xdg = tempfile::tempdir().expect("xdg");
    let scratch = tempfile::tempdir().expect("scratch");
    let target = format!("{}/p/note.txt", scratch.path().display());
    let out = run(&write_payload(&target, "plan"), xdg.path(), scratch.path());
    assert_eq!(out, "", "plan mode must pass scratch writes through");
}

// === Claude Code native session scratchpad ===

const SID: &str = "01234567-89ab-cdef-0123-456789abcdef";

fn claude_pad() -> String {
    format!(
        "{}/-home-u-proj/{SID}/scratchpad",
        tool_gates::router::claude_scratchpad_root().display()
    )
}

#[test]
fn write_under_claude_scratchpad_auto_allows() {
    let xdg = tempfile::tempdir().expect("xdg");
    let scratch = tempfile::tempdir().expect("scratch");
    let target = format!("{}/note.txt", claude_pad());
    let out = run_with_session(
        &write_payload(&target, "default"),
        xdg.path(),
        scratch.path(),
        Some(SID),
    );
    assert!(
        out.contains("\"permissionDecision\":\"allow\""),
        "write under the session scratchpad should allow, got: {out}"
    );
}

#[test]
fn write_under_claude_scratchpad_wrong_session_does_not_allow() {
    let xdg = tempfile::tempdir().expect("xdg");
    let scratch = tempfile::tempdir().expect("scratch");
    let target = format!("{}/note.txt", claude_pad());
    let out = run_with_session(
        &write_payload(&target, "default"),
        xdg.path(),
        scratch.path(),
        Some("99999999-89ab-cdef-0123-456789abcdef"),
    );
    assert_eq!(out, "", "another session's scratchpad must pass through");
}

#[test]
fn write_under_claude_scratchpad_without_session_does_not_allow() {
    let xdg = tempfile::tempdir().expect("xdg");
    let scratch = tempfile::tempdir().expect("scratch");
    let target = format!("{}/note.txt", claude_pad());
    let out = run(
        &write_payload(&target, "default"),
        xdg.path(),
        scratch.path(),
    );
    assert_eq!(out, "", "a missing session id must pass through");
}

#[test]
fn write_under_claude_scratchpad_in_plan_mode_does_not_allow() {
    let xdg = tempfile::tempdir().expect("xdg");
    let scratch = tempfile::tempdir().expect("scratch");
    let target = format!("{}/note.txt", claude_pad());
    let out = run_with_session(
        &write_payload(&target, "plan"),
        xdg.path(),
        scratch.path(),
        Some(SID),
    );
    assert_eq!(out, "", "plan mode must pass scratchpad writes through");
}

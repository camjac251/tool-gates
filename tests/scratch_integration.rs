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
/// pointed at `scratch`, feed `stdin_json`, return stdout.
fn run(stdin_json: &str, xdg: &std::path::Path, scratch: &std::path::Path) -> String {
    let mut child = Command::new(bin_path())
        .env("XDG_CONFIG_HOME", xdg)
        .env("TOOL_GATES_SCRATCH", scratch)
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
    assert!(
        !out.contains("\"permissionDecision\":\"allow\""),
        "write outside scratch must not auto-allow, got: {out}"
    );
}

#[test]
fn write_under_scratch_in_plan_mode_does_not_allow() {
    let xdg = tempfile::tempdir().expect("xdg");
    let scratch = tempfile::tempdir().expect("scratch");
    let target = format!("{}/p/note.txt", scratch.path().display());
    let out = run(&write_payload(&target, "plan"), xdg.path(), scratch.path());
    assert!(
        !out.contains("\"permissionDecision\":\"allow\""),
        "plan mode must not auto-allow scratch writes, got: {out}"
    );
}

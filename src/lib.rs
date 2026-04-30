//! Tool Gates - Intelligent tool permission gate for AI coding assistants.
//!
//! Formerly `bash-gates`. This library provides command parsing and permission
//! checking for bash commands, designed for use as hooks in Claude Code and Gemini CLI.
//!
//! **Claude Code hooks:**
//! - `PreToolUse`: Block dangerous commands, allow safe ones, provide hints
//! - `PermissionRequest`: Approve safe commands for subagents (where PreToolUse allow is ignored)
//! - `PostToolUse`: Track successful execution of approved commands
//!
//! **Gemini CLI hooks:**
//! - `BeforeTool`: Same gate engine, auto-detected from `hook_event_name`
//! - `AfterTool`: Post-execution security scanning
//!
//! The client is auto-detected from the `hook_event_name` field in the JSON input.
//!
//! # Example
//!
//! ```
//! use tool_gates::{check_command, PermissionDecision};
//!
//! // Safe command - allowed
//! let output = check_command("git status");
//! assert_eq!(output.decision, PermissionDecision::Allow);
//!
//! // Dangerous command - blocked
//! let output = check_command("rm -rf /");
//! assert_eq!(output.decision, PermissionDecision::Deny);
//! ```

pub mod cache;
pub mod config;
pub mod file_guards;
pub mod gates;
pub mod generated;
pub mod git_aliases;
pub mod hint_tracker;
pub mod hints;
pub mod mise;
pub mod models;
pub mod package_json;
pub mod parser;
pub mod patterns;
pub mod pending;
pub mod permission_request;
pub mod post_tool_use;
pub mod router;
pub mod security_reminders;
pub mod settings;
pub mod settings_writer;
pub mod tool_blocks;
pub mod tool_cache;
pub mod tracking;
pub mod tui;

pub use models::{Client, CommandInfo, Decision, GateResult, PermissionDecision};
pub use permission_request::handle_permission_request;
pub use router::{
    check_command, check_command_with_settings, check_command_with_settings_and_session,
};

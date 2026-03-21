//! Tool Gates - Intelligent tool permission gate for AI coding assistants.
//!
//! Formerly `bash-gates`. This library provides command parsing and permission
//! checking for bash commands, designed for use as Claude Code hooks:
//! - `PreToolUse`: Block dangerous commands, allow safe ones, provide hints
//! - `PermissionRequest`: Approve safe commands for subagents (where PreToolUse allow is ignored)
//! - `PostToolUse`: Track successful execution of approved commands
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

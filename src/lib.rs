//! Tool Gates - Intelligent tool permission gate for AI coding assistants.
//!
//! Formerly `bash-gates`. This library provides command parsing and permission
//! checking for assistant tool calls, designed for use as hooks in Claude Code,
//! Gemini CLI, and Codex CLI.
//!
//! **Claude Code hooks:**
//! - `PreToolUse`: Block dangerous commands, allow safe ones, provide hints
//! - `PermissionRequest`: Approve safe commands for subagents (where PreToolUse allow is ignored)
//! - `PostToolUse`: Track successful execution of approved commands
//!
//! **Gemini CLI hooks:**
//! - `BeforeTool`: Same gate engine, auto-detected from `hook_event_name`
//! - `AfterTool`: Post-execution context hook; tracking/security scanning are not plumbed yet
//!
//! Claude Code and Gemini CLI are auto-detected from `hook_event_name`; Codex
//! uses the explicit `--client codex` flag because it shares Claude's event names.
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

pub mod apply_patch_parser;
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
pub mod permission_request;
pub mod router;
pub mod rules_export;
pub mod rules_schema;
pub mod security_reminders;
pub mod settings;
pub mod tool_blocks;
pub mod tool_cache;

// These modules depend on crates that do not compile for
// `wasm32-unknown-unknown` (`fs2` file locking has no wasm target arm; `uuid`
// v4 and `ratatui`/`crossterm` are host-only). They drive the CLI binary and
// the hook tracking/approval queue, none of which is on the WASM simulator's
// decision path. Excluded from the `wasm` feature build; always present
// natively, so the binary, tests, and msrv check are unaffected.
#[cfg(not(feature = "wasm"))]
pub mod pending;
#[cfg(not(feature = "wasm"))]
pub mod post_tool_use;
#[cfg(not(feature = "wasm"))]
pub mod settings_writer;
#[cfg(not(feature = "wasm"))]
pub mod tracking;
#[cfg(not(feature = "wasm"))]
pub mod tui;

pub use models::{Client, CommandInfo, Decision, GateResult, PermissionDecision};
pub use permission_request::handle_permission_request;
pub use router::{
    check_command, check_command_with_settings, check_command_with_settings_and_session,
};

// === WASM bridge ===
//
// Compiled only for the `wasm` feature (off by default). Exposes a single
// `decide(command, mode, settings_json)` entry point to JavaScript via
// wasm-bindgen for the docs-site command simulator. The native binary, tests,
// and the msrv `cargo check` (run without --features) never compile this module.
#[cfg(feature = "wasm")]
mod wasm_bridge {
    use serde::Serialize;
    use std::collections::HashMap;
    use wasm_bindgen::prelude::*;

    /// Result of one simulated command, matching the `SIMS` entry shape the
    /// docs-site frontend consumes.
    ///
    /// `stages` maps a stage name (`"raw" | "parse" | "gate" | "settings"`) to
    /// its `StageStatus` string (`"passed" | "allow" | "ask" | "block" |
    /// "skipped"`). `notes` maps the same stage names to a human-readable note.
    /// `decision` is the collapsed 3-value verdict; `reason` is the gate reason
    /// text (may contain inline HTML such as `<code>` / `<b>`).
    #[derive(Serialize)]
    struct SimResponse {
        cmd: String,
        stages: HashMap<String, String>,
        notes: HashMap<String, String>,
        decision: String,
        reason: String,
    }

    /// Decide a command for the docs-site simulator and return a `SimResponse`
    /// serialized to a JS object.
    ///
    /// `command` is the raw shell command. `mode` is one of
    /// `default | acceptEdits | auto | bypassPermissions | dontAsk | plan`. Runs
    /// the real raw-string and hard-deny scan, the tree-sitter parse, and the
    /// gate dispatch via the instrumented pipeline. Supports optional custom
    /// settings JSON rules.
    #[wasm_bindgen]
    pub fn decide(command: &str, mode: &str, settings_json: Option<String>) -> JsValue {
        let sim = crate::router::decide_instrumented(command, mode, settings_json.as_deref());

        let mut stages = HashMap::new();
        stages.insert("raw".to_string(), sim.raw_status.to_string());
        stages.insert("parse".to_string(), sim.parse_status.to_string());
        stages.insert("gate".to_string(), sim.gate_status.to_string());
        stages.insert("settings".to_string(), sim.settings_status.to_string());

        let mut notes = HashMap::new();
        notes.insert("raw".to_string(), sim.raw_note);
        notes.insert("parse".to_string(), sim.parse_note);
        notes.insert("gate".to_string(), sim.gate_note);
        notes.insert("settings".to_string(), sim.settings_note);

        let response = SimResponse {
            cmd: command.to_string(),
            stages,
            notes,
            decision: sim.decision.to_string(),
            reason: sim.reason,
        };

        // serde-wasm-bindgen serializes to a plain JS object. The closure shape
        // is fixed and always serializable, so the unwrap cannot fail in
        // practice; an error here would be a programmer error, not user input.
        serde_wasm_bindgen::to_value(&response)
            .expect("SimResponse is always serializable to a JsValue")
    }

    // Minimal C-locale `<wctype.h>` / `<string.h>` shims for the tree-sitter-bash
    // scanner. wasm32-unknown-unknown links no libc, so these symbols would be
    // unresolved imports without them. ASCII-only by design: the scanner only
    // classifies shell-syntax bytes, where ASCII ranges match the C locale. `wc`
    // is compared directly (never narrowed to u8) so a wide code point cannot
    // alias into an ASCII range and misclassify.
    #[unsafe(no_mangle)]
    pub extern "C" fn iswspace(wc: i32) -> i32 {
        i32::from(wc == 0x20 || (0x09..=0x0d).contains(&wc))
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn iswalpha(wc: i32) -> i32 {
        i32::from((0x41..=0x5a).contains(&wc) || (0x61..=0x7a).contains(&wc))
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn iswalnum(wc: i32) -> i32 {
        i32::from(
            (0x30..=0x39).contains(&wc)
                || (0x41..=0x5a).contains(&wc)
                || (0x61..=0x7a).contains(&wc),
        )
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn iswdigit(wc: i32) -> i32 {
        i32::from((0x30..=0x39).contains(&wc))
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn strcmp(s1: *const i8, s2: *const i8) -> i32 {
        let mut i = 0;
        loop {
            unsafe {
                let c1 = *s1.offset(i);
                let c2 = *s2.offset(i);
                if c1 != c2 || c1 == 0 {
                    return (c1 as i32) - (c2 as i32);
                }
            }
            i += 1;
        }
    }
}

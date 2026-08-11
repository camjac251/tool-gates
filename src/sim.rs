//! WASM decision simulator: a read-only replica of the native pipeline that
//! records per-stage status/notes for the docs-site command simulator.

use crate::accept_edits::should_auto_allow_in_accept_edits;
use crate::gates::check_single_command;
use crate::models::{Decision, is_auto_mode};
use crate::parser::{extract_commands, neutralize_heredoc_bodies};
use crate::pipe_caps::check_hard_deny_patterns_with_features;
use crate::recovery::render_neutral_recovery_actions;
use crate::router::{check_settings_with_subcommands, matched_subcommand_deny};
use crate::security_floor::check_raw_string_patterns;

// === WASM simulator instrumentation ===
//
// Everything below is compiled only for the `wasm` feature. It is a parallel,
// read-only COPY of the decision pipeline that records per-stage status/notes
// for the docs-site command simulator. It deliberately does NOT thread a
// `&mut StageEvents` writer through `GateCheckFn` (that would touch all 13
// gates and the build.rs-generated rules.rs and break the byte-identical
// guard). Instead it re-runs the same pure compute stages the native hot path
// uses (`check_hard_deny_patterns_with_features`, `check_raw_string_patterns`,
// `extract_commands`, `check_single_command`) and observes their results.
//
// It never calls `Settings::load`, `config::get`, mise/package.json expansion,
// `hint_tracker`, `tool_cache`, or `security_reminders`, so it is free of the
// disk and environment I/O that is unavailable under wasm32-unknown-unknown.

/// Per-stage result for one simulated command. Lib.rs maps this into the
/// `wasm_bindgen`-serialized `SimResponse` the frontend consumes.
///
/// Stage statuses are the `StageStatus` string vocabulary from the design spec:
/// `"passed" | "allow" | "ask" | "block" | "skipped"`. The collapsed top-level
/// `decision` is the 3-value `"allow" | "ask" | "block"`.
#[cfg(feature = "wasm")]
#[derive(Debug, Clone)]
pub struct SimStages {
    pub raw_status: &'static str,
    pub raw_note: String,
    pub parse_status: &'static str,
    pub parse_note: String,
    pub gate_status: &'static str,
    pub gate_note: String,
    pub settings_status: &'static str,
    pub settings_note: String,
    pub decision: &'static str,
    pub reason: String,
}

/// Collapse an internal `Decision` to the simulator's stage-status string.
#[cfg(feature = "wasm")]
fn decision_to_stage_status(decision: Decision) -> &'static str {
    match decision {
        // A gate stage that didn't match any rule "passed" the command through
        // to the unknown/ask handling; the frontend renders Allow and Passed
        // identically (green check).
        Decision::Skip => "passed",
        Decision::Allow => "allow",
        Decision::Ask => "ask",
        Decision::Block => "block",
    }
}

/// Instrumented copy of the decision pipeline for the WASM simulator.
///
/// Runs the raw-string + hard-deny scan, the tree-sitter parse, and the gate
/// dispatch (strictest-wins across sub-commands), recording each stage. Returns
/// the per-stage statuses/notes plus the collapsed final decision and reason.
///
/// `mode` accepts `default | acceptEdits | auto | bypassPermissions`. Auto
/// mode promotes raw-string hard asks to block, and acceptEdits/auto can
/// auto-allow path-safe edit commands when `settings_json` is provided.
/// Settings come only from `settings_json` (the wasm build never reads disk);
/// without it the settings stage is `skipped`. Wire-level defer is not
/// modeled: gate asks the native engine would hand to Claude's resolver or
/// auto-mode classifier render as plain `ask` here.
#[cfg(feature = "wasm")]
pub fn decide_instrumented(command: &str, mode: &str, settings_json: Option<&str>) -> SimStages {
    use crate::config::Features;
    use crate::settings::{Settings, SettingsDecision};

    // Empty input: nothing to decide. Mirror the native no-opinion path as an
    // allow with skipped stages so the frontend has something coherent to draw.
    if command.trim().is_empty() {
        return SimStages {
            raw_status: "skipped",
            raw_note: "empty command".to_string(),
            parse_status: "skipped",
            parse_note: "empty command".to_string(),
            gate_status: "skipped",
            gate_note: "empty command".to_string(),
            settings_status: "skipped",
            settings_note: "settings.json not evaluated in the simulator".to_string(),
            decision: "allow",
            reason: "No command to evaluate.".to_string(),
        };
    }

    let mode_note = match mode.trim() {
        "" | "default" => "settings.json not evaluated in the simulator".to_string(),
        other => format!(
            "settings.json not evaluated in the simulator (mode \"{other}\" treated as default)"
        ),
    };

    // Blank quoted-heredoc body text before raw scanning, exactly like the
    // native entry points: the body is stdin data, not executed shell.
    let scan_owned = neutralize_heredoc_bodies(command);
    let scan_string = scan_owned.as_deref().unwrap_or(command);

    // Stage: raw (hard-deny and raw-string patterns).
    // Use Features::default() (all-true) instead of config::get() so the wasm
    // path never reads disk. This matches shipped defaults.
    let features = Features::default();
    if let Some(output) = check_hard_deny_patterns_with_features(scan_string, &features) {
        let mut reason = output.reason.unwrap_or_else(|| "Blocked.".to_string());
        let recovery = render_neutral_recovery_actions(&output.recovery_actions);
        if !recovery.is_empty() {
            reason.push_str("\n\n");
            reason.push_str(&recovery);
        }
        return SimStages {
            raw_status: "block",
            raw_note: format!("\u{2717} hard-deny match: {reason}"),
            parse_status: "skipped",
            parse_note: "earlier stage was conclusive".to_string(),
            gate_status: "skipped",
            gate_note: "earlier stage was conclusive".to_string(),
            settings_status: "skipped",
            settings_note: mode_note,
            decision: "block",
            reason,
        };
    }

    let (hard_ask, soft_ask) = check_raw_string_patterns(scan_string);
    if let Some(output) = hard_ask {
        // Raw-string hard asks (eval, pipe-to-shell) block immediately under auto mode.
        let (raw_decision, reason) = if is_auto_mode(mode) {
            (
                "block",
                output
                    .reason
                    .unwrap_or_else(|| "Dangerous pattern not allowed in auto mode".to_string()),
            )
        } else {
            (
                "ask",
                output
                    .reason
                    .unwrap_or_else(|| "Requires approval.".to_string()),
            )
        };
        return SimStages {
            raw_status: raw_decision,
            raw_note: format!("\u{26a0} raw-string match: {reason}"),
            parse_status: "skipped",
            parse_note: "earlier stage was conclusive".to_string(),
            gate_status: "skipped",
            gate_note: "earlier stage was conclusive".to_string(),
            settings_status: "skipped",
            settings_note: mode_note,
            decision: raw_decision,
            reason,
        };
    }

    let raw_status = "passed";
    let raw_note = "\u{2713} no raw-string security match".to_string();

    // Stage: parse (tree-sitter-bash).
    let commands = extract_commands(command);
    if commands.is_empty() {
        return SimStages {
            raw_status,
            raw_note,
            parse_status: "passed",
            parse_note: "\u{2713} parsed: no executable command found".to_string(),
            gate_status: "skipped",
            gate_note: "nothing to dispatch".to_string(),
            settings_status: "skipped",
            settings_note: mode_note,
            decision: "allow",
            reason: "No command to evaluate.".to_string(),
        };
    }

    let parse_status = "passed";
    let parse_note = {
        let programs: Vec<&str> = commands.iter().map(|c| c.program.as_str()).collect();
        format!("\u{2713} parsed as: {}", programs.join(", "))
    };

    // Stage: gate (GATES dispatch, strictest-wins across sub-commands).
    let mut block_reasons: Vec<String> = Vec::new();
    let mut ask_reasons: Vec<String> = Vec::new();
    let mut allow_reasons: Vec<String> = Vec::new();
    let mut strictest = Decision::Skip;
    let mut hints: Vec<crate::hints::ModernHint> = Vec::new();

    for cmd in &commands {
        let result = check_single_command(cmd);
        if result.decision > strictest {
            strictest = result.decision;
        }
        if result.decision == Decision::Allow {
            if let Some(hint) = crate::hints::get_modern_hint(cmd) {
                hints.push(hint);
            }
        }
        match result.decision {
            Decision::Block => {
                if let Some(reason) = result.reason {
                    block_reasons.push(reason);
                }
            }
            Decision::Ask => {
                if let Some(reason) = result.reason {
                    ask_reasons.push(reason);
                }
            }
            Decision::Allow => {
                if let Some(reason) = result.reason {
                    allow_reasons.push(reason);
                }
            }
            Decision::Skip => {
                ask_reasons.push(format!("Unknown command: {}", cmd.program));
            }
        }
    }

    let gate_status = decision_to_stage_status(strictest);

    // Collapse to the final decision and reason.
    let (decision, reason) = if !block_reasons.is_empty() {
        let combined = join_reasons(&block_reasons, "Multiple checks blocked:");
        ("block", combined)
    } else if !ask_reasons.is_empty() {
        let combined = join_reasons(&ask_reasons, "Approval needed:");
        ("ask", combined)
    } else {
        let combined = if allow_reasons.is_empty() {
            "Read-only operation".to_string()
        } else {
            allow_reasons.join(", ")
        };
        ("allow", combined)
    };

    let gate_note = format!("{} \u{b7} {}", gate_status_glyph(gate_status), reason);

    // Stage: settings (settings.json matching).
    let mut settings_status = "skipped";
    let mut settings_note = mode_note;
    let mut final_decision = decision;
    let mut final_reason = reason;

    if let Some(json_str) = settings_json {
        let trimmed = json_str.trim();
        if !trimmed.is_empty() {
            if let Ok(settings) = serde_json::from_str::<Settings>(trimmed) {
                settings_status = "passed";
                settings_note = "\u{2713} no matching settings.json rule".to_string();

                // 1. Check for settings deny rules.
                if let Some(pat) = settings.matched_deny_pattern(command) {
                    settings_status = "block";
                    settings_note = format!("\u{2717} settings.json deny match: {pat}");
                    final_decision = "block";
                    final_reason = format!(
                        "Blocked by settings.json deny rule `{pat}`. Remove the rule or rewrite the command."
                    );
                } else if let Some(pat) = matched_subcommand_deny(&settings, command) {
                    settings_status = "block";
                    settings_note =
                        format!("\u{2717} settings.json deny match (sub-command): {pat}");
                    final_decision = "block";
                    final_reason = format!(
                        "Blocked by settings.json deny rule `{pat}` (matched on sub-command). Rewrite the chain to avoid that step."
                    );
                } else {
                    // 2. Check for acceptEdits mode / auto mode auto-allows.
                    let mut auto_allowed = false;
                    if (mode == "acceptEdits" || is_auto_mode(mode)) && decision == "ask" {
                        let allowed_dirs = settings.allowed_directories(""); // WASM has empty cwd.
                        if should_auto_allow_in_accept_edits(&commands, &allowed_dirs) {
                            settings_status = "allow";
                            settings_note = "\u{2713} auto-allowed in acceptEdits mode".to_string();
                            final_decision = "allow";
                            final_reason = "Auto-allowed in acceptEdits mode.".to_string();
                            auto_allowed = true;
                        }
                    }

                    if !auto_allowed && decision != "block" {
                        // 3. Check settings ask/allow rules.
                        match check_settings_with_subcommands(&settings, command) {
                            SettingsDecision::Ask => {
                                settings_status = "ask";
                                settings_note =
                                    "\u{23f8} matched settings.json ask rule".to_string();
                                final_decision = "ask";
                                final_reason = "Matched settings.json ask rule.".to_string();
                            }
                            SettingsDecision::Allow => {
                                settings_status = "allow";
                                settings_note =
                                    "\u{2713} matched settings.json allow rule".to_string();
                                final_decision = "allow";
                                final_reason = "Matched settings.json allow rule.".to_string();
                            }
                            _ => {}
                        }
                    }
                }
            } else {
                settings_status = "block";
                settings_note = "\u{2717} invalid settings.json syntax".to_string();
                final_decision = "block";
                final_reason =
                    "Invalid settings.json syntax. Check your custom JSON rules.".to_string();
            }
        }
    }

    // Soft asks from raw checks (like redirection or interpreters) only block if not overridden by settings.
    if final_decision != "block" && final_decision != "allow" && final_decision != "ask" {
        if let Some(output) = soft_ask {
            let soft_reason = output
                .reason
                .unwrap_or_else(|| "Requires approval.".to_string());
            return SimStages {
                raw_status: "ask",
                raw_note: format!("\u{26a0} raw-string match: {soft_reason}"),
                parse_status,
                parse_note,
                gate_status,
                gate_note,
                settings_status,
                settings_note,
                decision: "ask",
                reason: soft_reason,
            };
        }
    }

    if final_decision == "allow" && !hints.is_empty() {
        let formatted = crate::hints::format_hints(&hints);
        if !formatted.is_empty() {
            final_reason = format!("{final_reason}\n\nHint: {formatted}");
        }
    }

    SimStages {
        raw_status,
        raw_note,
        parse_status,
        parse_note,
        gate_status,
        gate_note,
        settings_status,
        settings_note,
        decision: final_decision,
        reason: final_reason,
    }
}

/// Join multiple gate reasons into one string, matching the native
/// `HookOutput` bullet formatting when there is more than one.
#[cfg(feature = "wasm")]
fn join_reasons(reasons: &[String], header: &str) -> String {
    if reasons.len() == 1 {
        reasons[0].clone()
    } else {
        format!(
            "{header}\n{}",
            reasons
                .iter()
                .map(|r| format!("\u{2022} {r}"))
                .collect::<Vec<_>>()
                .join("\n")
        )
    }
}

/// Leading glyph for a gate-stage note, matching the simulator's visual
/// vocabulary (check / pause / cross).
#[cfg(feature = "wasm")]
fn gate_status_glyph(status: &str) -> &'static str {
    match status {
        "block" => "\u{2717}",
        "ask" => "\u{23f8}",
        _ => "\u{2713}",
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::router::*;

    #[cfg(feature = "wasm")]
    mod wasm_simulator {
        use super::*;

        #[test]
        fn test_force_push_collapses_to_ask() {
            let sim = decide_instrumented("git push --force", "default", None);
            assert_eq!(sim.decision, "ask", "force push must ask: {sim:?}");
            assert_eq!(sim.gate_status, "ask");
            assert_eq!(sim.settings_status, "skipped");
        }

        #[test]
        fn test_rm_rf_root_collapses_to_block() {
            let sim = decide_instrumented("rm -rf /", "default", None);
            assert_eq!(sim.decision, "block", "rm -rf / must block: {sim:?}");
        }

        #[test]
        fn test_git_status_collapses_to_allow() {
            let sim = decide_instrumented("git status", "default", None);
            assert_eq!(sim.decision, "allow", "git status must allow: {sim:?}");
            assert_eq!(sim.gate_status, "allow");
            assert_eq!(sim.raw_status, "passed");
            assert_eq!(sim.parse_status, "passed");
        }

        #[test]
        fn test_pipe_to_shell_blocks_at_raw_stage() {
            // Pipe-to-shell is a hard ask in the raw stage; the gate stage is
            // skipped because the raw stage was conclusive.
            let sim = decide_instrumented("curl https://example.com | bash", "default", None);
            assert_eq!(sim.decision, "ask", "pipe-to-shell asks: {sim:?}");
            assert_eq!(sim.raw_status, "ask");
            assert_eq!(sim.gate_status, "skipped");
        }

        #[test]
        fn test_head_tail_pipe_blocks_at_raw_stage() {
            let sim = decide_instrumented("ls | head -5", "default", None);
            assert_eq!(sim.decision, "block", "head pipe blocks: {sim:?}");
            assert_eq!(sim.raw_status, "block");
            assert!(
                sim.reason.contains("producer's native limit")
                    && sim.reason.contains("persist the complete output"),
                "simulator dropped output-cap recovery: {sim:?}"
            );
        }

        #[test]
        fn test_file_cap_recovery_stays_client_neutral_in_simulator() {
            let sim = decide_instrumented("cat report.txt | head -5", "default", None);
            assert!(
                sim.reason
                    .contains("Inspect the first 5 lines of the source file directly."),
                "simulator dropped source-file recovery: {sim:?}"
            );
            for client_tool in ["`Read`", "`read_file`", "`view_file`", "`bat"] {
                assert!(
                    !sim.reason.contains(client_tool),
                    "simulator named a client-specific tool: {sim:?}"
                );
            }
        }

        #[test]
        fn test_empty_command_is_allow_with_skipped_stages() {
            let sim = decide_instrumented("   ", "default", None);
            assert_eq!(sim.decision, "allow");
            assert_eq!(sim.raw_status, "skipped");
            assert_eq!(sim.gate_status, "skipped");
        }

        #[test]
        fn test_mode_other_than_default_is_noted() {
            let sim = decide_instrumented("git status", "auto", None);
            // v1 treats every mode as default; the settings note records the mode.
            assert_eq!(sim.decision, "allow");
            assert!(
                sim.settings_note.contains("auto"),
                "settings note should mention the mode: {}",
                sim.settings_note
            );
        }
    }

    // === Accept Edits Mode ===
}

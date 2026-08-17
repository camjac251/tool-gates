//! Main router that combines all gates.
//!
//! The orchestrator: entry points, settings resolution, mode shaping, and the
//! settings-aware engine. Concern-specific logic lives in sibling modules
//! (`security_floor`, `pipe_caps`, `scratch`, `paths`, `accept_edits`,
//! `task_expansion`, `sim`), re-exported below where external call sites expect
//! `crate::router::*` paths.

use crate::hint_tracker;
use crate::hints::{format_hints, get_modern_hint};
use crate::mise::parse_mise_invocation;
use crate::models::{
    Client, CommandInfo, Decision, HookOutput, PermissionDecision, is_auto_mode, is_plan_mode,
};
use crate::package_json::parse_script_invocation;
use crate::parser::extract_commands;
use crate::settings::{Settings, SettingsDecision};

use crate::accept_edits::should_auto_allow_in_accept_edits;
use crate::raw_floor::check_raw_floor;
use crate::task_expansion::{check_mise_task, check_package_script};

// Re-export shims so external call sites (main.rs, permission_request.rs,
// gates/helpers.rs, lib.rs) keep resolving `crate::router::*` paths.
pub use crate::gates::check_single_command;
pub(crate) use crate::paths::is_under_any_dir;
pub use crate::scratch::{claude_scratchpad_root, is_under_scratch, is_under_scratch_with_vars};
#[cfg(feature = "wasm")]
pub use crate::sim::decide_instrumented;

/// Check a bash command string and return the appropriate hook output.
///
/// Handles compound commands (&&, ||, |, ;) by checking each command
/// and applying the strictest decision.
///
/// Priority: BLOCK > ASK > ALLOW
///
/// For allowed commands that use legacy tools, includes hints about
/// modern alternatives in the additionalContext field.
pub fn check_command(command_string: &str) -> HookOutput {
    check_command_for_session(command_string, "")
}

/// Run the raw-string safety floor shared by top-level commands and quoted
/// scripts passed to local shell wrappers such as `bash -c`.
///
/// Returns `Some` only when a hard deny or raw-string ask applies. Callers can
/// continue into parsed gate evaluation when this returns `None`.
pub(crate) fn check_raw_security_floor(command_string: &str) -> Option<HookOutput> {
    let checks = check_raw_floor(command_string);
    if let Some(output) = checks.hard_deny {
        return Some(output);
    }

    // Check for patterns at the raw string level. The hard-ask floor must be
    // force-promptable on Antigravity (force_ask), never suppressible by an
    // "Always Allow" grant; soft asks stay overridable.
    checks.hard_ask.map(HookOutput::forced).or(checks.soft_ask)
}

/// Check a bash command with session-scoped hint dedup.
///
/// When `session_id` is non-empty, each hint fires at most once per session.
pub fn check_command_for_session(command_string: &str, session_id: &str) -> HookOutput {
    if command_string.trim().is_empty() {
        return HookOutput::no_opinion();
    }

    if let Some(result) = check_raw_security_floor(command_string) {
        return result;
    }

    // Parse the command into individual commands
    let commands = extract_commands(command_string);

    check_command_for_session_with_commands(command_string, session_id, &commands)
}

/// Core gate analysis on pre-parsed commands with session-scoped hint dedup.
///
/// Separated from `check_command_for_session` so callers that already have
/// parsed commands (and already ran raw string checks) can skip the duplicate work.
fn check_command_for_session_with_commands(
    _command_string: &str,
    session_id: &str,
    commands: &[CommandInfo],
) -> HookOutput {
    if commands.is_empty() {
        return HookOutput::no_opinion();
    }

    let mut block_reasons: Vec<String> = Vec::new();
    let mut ask_reasons: Vec<String> = Vec::new();
    let mut hints: Vec<crate::hints::ModernHint> = Vec::new();
    // One irreversible sub-command holds the whole compound command's ask.
    let mut hold_in_auto = false;

    for cmd in commands {
        let result = check_single_command(cmd);

        if result.decision != Decision::Block
            && let Some(hint) = get_modern_hint(cmd)
        {
            hints.push(hint);
        }

        match result.decision {
            Decision::Block => {
                if let Some(reason) = result.reason {
                    block_reasons.push(reason);
                }
            }
            Decision::Ask => {
                hold_in_auto |= result.hold_in_auto;
                if let Some(reason) = result.reason {
                    ask_reasons.push(reason);
                }
            }
            // Allow is auto-approved, so the per-rule reason is not surfaced to
            // the agent. That reason documents the rule on the generated docs
            // site; the runtime wire output stays lean. Modern-CLI hints still
            // attach via additionalContext below.
            Decision::Allow => {}
            Decision::Skip => {
                ask_reasons.push(format!("Unknown command: {}", cmd.program));
            }
        }
    }

    hint_tracker::filter_hints(session_id, &mut hints);

    if !block_reasons.is_empty() {
        let combined = if block_reasons.len() == 1 {
            block_reasons.remove(0)
        } else {
            format!(
                "Multiple checks blocked:\n{}",
                block_reasons
                    .iter()
                    .map(|r| format!("• {r}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        };
        return HookOutput::deny(&combined);
    }

    if !ask_reasons.is_empty() {
        let combined = if ask_reasons.len() == 1 {
            ask_reasons.remove(0)
        } else {
            format!(
                "Approval needed:\n{}",
                ask_reasons
                    .iter()
                    .map(|r| format!("• {r}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        };
        let hints_str = format_hints(&hints);
        let mut output = if hints_str.is_empty() {
            HookOutput::ask(&combined)
        } else {
            HookOutput::ask_with_context(&combined, &hints_str)
        };
        output.hold_in_auto = hold_in_auto;
        return output;
    }

    let allow_reason = "Read-only operation";

    let hints_str = format_hints(&hints);
    if !hints_str.is_empty() {
        return HookOutput::allow_with_context(Some(allow_reason), &hints_str);
    }

    HookOutput::allow(Some(allow_reason))
}

/// Return the first deny pattern matched by any sub-command in a compound
/// command, or `None` if nothing matches.
///
/// For compound commands like "cd /tmp && rm -rf .", this ensures that deny
/// rules like Bash(rm:*) still catch the dangerous sub-command even though
/// the full string doesn't start with "rm". Returns the matched pattern so
/// the deny reason can name it instead of being generic.
pub(crate) fn matched_subcommand_deny<'a>(
    settings: &'a Settings,
    command_string: &str,
) -> Option<&'a str> {
    let commands = extract_commands(command_string);
    if commands.len() <= 1 {
        return None; // Single command already checked against full string
    }
    commands
        .iter()
        .find_map(|cmd| settings.matched_deny_pattern(&cmd.raw))
}

/// Check compound command sub-commands against settings ask/allow rules.
///
/// Tries the full raw string first (backward compat). If no match, checks
/// each AST-parsed sub-command. Takes the strictest result across all
/// sub-commands so that patterns like Bash(npm install:*) match
/// "cd /tmp && npm install".
///
/// Strictness: Deny > Ask > Allow > NoMatch
///
/// When a sub-command has no settings rule but the gate engine allows it
/// (e.g. `echo`, `head`, `true`), it counts as covered rather than NoMatch.
/// This lets gate-safe commands participate in compound settings approval
/// without needing explicit settings rules for every safe utility.
pub(crate) fn check_settings_with_subcommands(
    settings: &Settings,
    command_string: &str,
) -> SettingsDecision {
    // Try full string first (handles exact patterns and simple commands)
    let full_result = settings.check_command_excluding_deny(command_string);
    if full_result != SettingsDecision::NoMatch {
        return full_result;
    }

    // For compound commands, check each sub-command individually
    let commands = extract_commands(command_string);
    if commands.len() <= 1 {
        return SettingsDecision::NoMatch;
    }

    let mut has_ask = false;
    let mut has_settings_allow = false;
    let mut has_no_match = false;

    for cmd in &commands {
        match settings.check_command_excluding_deny(&cmd.raw) {
            SettingsDecision::Deny => {
                unreachable!("check_command_excluding_deny never returns Deny")
            }
            SettingsDecision::Ask => has_ask = true,
            SettingsDecision::Allow => has_settings_allow = true,
            SettingsDecision::NoMatch => {
                // If the gate engine allows this command, treat it as covered.
                // This bridges gate-safe commands (echo, head, cat, true, cd)
                // into compound settings approval without needing individual
                // settings rules for every safe utility.
                let gate_result = check_single_command(cmd);
                if gate_result.decision != Decision::Allow {
                    has_no_match = true;
                }
            }
        }
    }

    // Strictest wins: Ask > Allow > NoMatch.
    // Only return Allow when ALL sub-commands are covered (by settings or gates)
    // AND at least one segment matched a settings rule. If all segments are only
    // gate-allowed, fall through to the gate result which has a more accurate reason.
    if has_ask {
        SettingsDecision::Ask
    } else if has_settings_allow && !has_no_match {
        SettingsDecision::Allow
    } else {
        SettingsDecision::NoMatch
    }
}

// Claude Code acceptEdits has its own Bash base-command allowlist, matched on
// the bare base name with no path validation at all. When tool-gates hands the
// decision back, Claude can allow the command through that fast path. Keep
// those fallback asks explicit unless tool-gates' own path-aware acceptEdits
// policy approved them first.
const CLAUDE_ACCEPT_EDITS_BASH_BASE_ALLOWLIST: &[&str] =
    &["mkdir", "touch", "rm", "rmdir", "mv", "cp", "sed"];

/// True when Claude's acceptEdits fast path could approve this whole command.
///
/// Claude walks every sub-command and bails to the normal permission flow the
/// moment one is not on the base list, so the fast path only fires when *all*
/// of them match. Requiring the same here keeps `mkdir -p dist && cargo build`
/// out of the guard, and mirrors the `.all()` in `should_auto_allow_in_accept_edits`.
/// Reduce a program token to the base name Claude's fast path would look up.
///
/// Claude strips a prefix set (`timeout`, `nice`, `stdbuf`, `nohup`, `command`,
/// `builtin`, `noglob`, `VAR=x`) and resolves the basename before matching, so
/// comparing the raw token here would let `stdbuf -o0 rm …` or `\rm …` slip past
/// a guard whose whole job is to stay in lockstep with that lookup.
fn claude_base_name(program: &str) -> &str {
    let stripped = program
        .trim_matches(|c| c == '"' || c == '\'')
        .trim_start_matches('\\');
    stripped.rsplit('/').next().unwrap_or(stripped)
}

/// Prefixes Claude sees through when resolving a Bash base command. The parser
/// already collapses `env`/`nohup`/`timeout`-style wrappers, so this covers the
/// ones it leaves as the program token.
const CLAUDE_TRANSPARENT_PREFIXES: &[&str] = &[
    "stdbuf", "noglob", "command", "builtin", "time", "nice", "timeout", "nohup",
];

fn needs_explicit_ask_to_avoid_claude_accept_edits_passthrough(commands: &[CommandInfo]) -> bool {
    if commands.is_empty() {
        return false;
    }
    commands.iter().all(|cmd| {
        let mut base = claude_base_name(&cmd.program);
        // Walk past a transparent prefix to the command it actually runs.
        if CLAUDE_TRANSPARENT_PREFIXES.contains(&base) {
            match cmd
                .args
                .iter()
                .map(String::as_str)
                .find(|a| !a.starts_with('-') && !a.contains('='))
            {
                Some(inner) => base = claude_base_name(inner),
                // A bare prefix with nothing to run: Claude finds no base
                // command either, so its fast path cannot fire.
                None => return false,
            }
        }
        CLAUDE_ACCEPT_EDITS_BASH_BASE_ALLOWLIST.contains(&base)
    })
}

pub(crate) fn gate_ask_output_for_mode(
    reason: String,
    context: Option<String>,
    permission_mode: &str,
    hard_ask_in_accept_edits: bool,
    hold_in_auto: bool,
) -> HookOutput {
    if is_plan_mode(permission_mode) {
        return plan_mode_deny_output();
    }

    if is_auto_mode(permission_mode) {
        // A hook "ask" is handed straight back to the user: Claude Code passes
        // it into the permission resolver's short-circuit slot, so it never
        // reaches the auto-mode classifier and never reaches the acceptEdits
        // fast path either. That makes "ask" a sufficient gate here -- a deny
        // would only cost the user a decision they are entitled to make.
        //
        // `hold_in_auto` rules opt out of classifier adjudication for the same
        // reason, by choice rather than necessity: their blast radius is
        // external and irreversible.
        if hard_ask_in_accept_edits || hold_in_auto {
            let mut output = match context {
                Some(context) => HookOutput::ask_with_context(&reason, &context),
                None => HookOutput::ask(&reason),
            };
            // Keep the disposition on the output so an enclosing wrapper
            // (a mise task, a package script) re-deriving its own decision
            // from this one still sees that the ask must not be deferred.
            output.hold_in_auto = hold_in_auto;
            return output;
        }
        // Everything else defers. Defer is the only decision that reaches the
        // auto-mode classifier, so emitting "ask" here would exclude the whole
        // gate catalog from the very mechanism auto mode exists to provide.
        HookOutput::defer(reason, context)
    } else if permission_mode == "acceptEdits" && hard_ask_in_accept_edits {
        if let Some(context) = context {
            HookOutput::ask_with_context(&reason, &context)
        } else {
            HookOutput::ask(&reason)
        }
    } else {
        HookOutput::defer(reason, context)
    }
}

fn plan_mode_deny_output() -> HookOutput {
    HookOutput::deny(
        "Plan mode: command requires approval. Exit plan mode to run mutating commands.",
    )
}

/// Check a bash command with settings.json awareness and permission mode detection.
///
/// Loads settings from user (~/.claude/settings.json) and project (.claude/settings.json),
/// and combines with gate analysis. `client` selects which of those scopes the
/// invocation may consult; see [`Settings::resolve`].
///
/// Priority order:
/// 1. Gate blocks → deny directly (dangerous commands always blocked)
/// 2. Settings.json deny → deny (user's explicit deny rules always respected)
/// 3. Settings.json ask → ask (defer to Claude Code)
/// 4. Plan mode allows only gate-proven read-only commands
/// 5. acceptEdits mode + file-editing command → allow automatically
/// 6. Settings.json allow → allow
/// 7. Gate result (allow/ask)
pub fn check_command_with_settings(
    command_string: &str,
    cwd: &str,
    permission_mode: &str,
    client: Client,
) -> HookOutput {
    check_command_with_settings_and_session(command_string, cwd, permission_mode, "", client)
}

/// Check a bash command with settings.json awareness, permission mode detection,
/// and session-scoped hint dedup.
pub fn check_command_with_settings_and_session(
    command_string: &str,
    cwd: &str,
    permission_mode: &str,
    session_id: &str,
    client: Client,
) -> HookOutput {
    let result = check_command_with_settings_and_session_inner(
        command_string,
        cwd,
        permission_mode,
        session_id,
        client,
    );

    // Plan mode: anything the gate would have asked about is a mutation by
    // definition (read-only commands return Allow). Promote Ask -> Deny so
    // the model gets a clear signal instead of a permission prompt that
    // doesn't match plan mode's intent. Defer is in the same bucket --
    // it's an ask that's been redirected to CC; in plan mode neither
    // should run.
    if is_plan_mode(permission_mode)
        && (result.decision == PermissionDecision::Ask
            || result.decision == PermissionDecision::Defer)
    {
        return HookOutput::deny(
            "Plan mode: command requires approval. Exit plan mode to run mutating commands.",
        );
    }

    result
}

/// Inner implementation; see public wrapper for plan-mode post-processing.
fn check_command_with_settings_and_session_inner(
    command_string: &str,
    cwd: &str,
    permission_mode: &str,
    session_id: &str,
    client: Client,
) -> HookOutput {
    if command_string.trim().is_empty() {
        return HookOutput::no_opinion();
    }

    // Check for raw string security patterns BEFORE any expansion.
    // Hard asks (pipe-to-shell, eval) return immediately. Not overridable by settings.
    // Soft asks (pipe-to-interpreter, output redirection) are saved so
    // settings.json allow rules can override them via pattern approval.
    //
    // Under auto mode a tool-gates "ask" goes to the Claude Code classifier,
    // which is reasoning-blind to tool-gates' rationale. Hard-ask patterns
    // (pipe-to-shell, eval) have no legitimate use case and belong in the
    // deterministic safety floor, so promote them to deny instead of ask.
    //
    let raw_checks = check_raw_floor(command_string);
    if let Some(output) = raw_checks.hard_deny {
        return output;
    }
    // hard-ask is force-promptable (force_ask on Antigravity); soft asks stay overridable.
    let soft_ask = raw_checks.soft_ask;
    if let Some(result) = raw_checks.hard_ask.map(HookOutput::forced) {
        if is_auto_mode(permission_mode) {
            return HookOutput::deny(
                &result
                    .reason
                    .unwrap_or_else(|| "Dangerous pattern not allowed in auto mode".to_string()),
            );
        }
        return result;
    }

    // Load settings.json early - needed for task expansion, deny check, acceptEdits, and rule matching
    let settings = Settings::load(client, cwd);

    // Parse command to detect compound commands (&&, ||, |, ;).
    // Task expansion (mise/package.json) only applies to simple commands --
    // compound commands fall through to normal gate analysis where each
    // sub-command is checked individually.
    let commands = extract_commands(command_string);
    let is_simple_command = commands.len() <= 1;

    // Check for mise task invocation and expand to underlying commands.
    // Settings are checked FIRST against the original command so that explicit
    // allow/deny rules (e.g. Bash(mise run *)) take priority over expansion.
    if is_simple_command {
        if let Some(task_name) = parse_mise_invocation(command_string) {
            if let Some(pat) = settings.matched_deny_pattern(command_string) {
                return HookOutput::deny(&format!(
                    "Blocked by settings.json deny rule `{pat}`. Remove the rule or rewrite the command."
                ));
            }
            match check_settings_with_subcommands(&settings, command_string) {
                SettingsDecision::Allow if !is_plan_mode(permission_mode) => {
                    return HookOutput::allow(Some("Matched settings.json allow rule"));
                }
                SettingsDecision::Ask => {
                    return HookOutput::ask("Matched settings.json ask rule");
                }
                _ => {}
            }
            return check_mise_task(&task_name, cwd, permission_mode, client);
        }

        // Check for package.json script invocation (npm run, pnpm run, etc.)
        // Same settings-first logic as mise.
        if let Some((pm, script_name)) = parse_script_invocation(command_string) {
            if let Some(pat) = settings.matched_deny_pattern(command_string) {
                return HookOutput::deny(&format!(
                    "Blocked by settings.json deny rule `{pat}`. Remove the rule or rewrite the command."
                ));
            }
            match check_settings_with_subcommands(&settings, command_string) {
                SettingsDecision::Allow if !is_plan_mode(permission_mode) => {
                    return HookOutput::allow(Some("Matched settings.json allow rule"));
                }
                SettingsDecision::Ask => {
                    return HookOutput::ask("Matched settings.json ask rule");
                }
                _ => {}
            }
            return check_package_script(pm, &script_name, cwd, permission_mode, client);
        }
    }

    // Run gate analysis - blocks take priority.
    // Reuse already-parsed commands to avoid double tree-sitter parsing.
    let gate_result =
        check_command_for_session_with_commands(command_string, session_id, &commands);
    let gate_context = gate_result.context.clone();

    if gate_result.decision == PermissionDecision::Deny {
        return gate_result;
    }

    // Check settings.json deny rules FIRST - user's explicit deny rules always respected
    // This must happen before acceptEdits to prevent acceptEdits from bypassing deny rules
    // For compound commands (&&, ||, |, ;), also check each sub-command individually
    // so that deny rules like Bash(rm:*) catch "cd /tmp && rm -rf ."
    if let Some(pat) = settings.matched_deny_pattern(command_string) {
        return HookOutput::deny(&format!(
            "Blocked by settings.json deny rule `{pat}`. Remove the rule or rewrite the command."
        ));
    }
    if let Some(pat) = matched_subcommand_deny(&settings, command_string) {
        return HookOutput::deny(&format!(
            "Blocked by settings.json deny rule `{pat}` (matched on sub-command). Rewrite the chain to avoid that step."
        ));
    }

    // Settings ask rules still require approval, so in plan mode they become
    // a deny through the public post-processing wrapper. Settings allow rules
    // and acceptEdits shortcuts do not prove a command is read-only; only the
    // deterministic gate Allow result can pass in plan mode.
    match check_settings_with_subcommands(&settings, command_string) {
        SettingsDecision::Ask => {
            if let Some(context) = gate_context.as_deref() {
                return HookOutput::ask_with_context("Matched settings.json ask rule", context);
            }
            return HookOutput::ask("Matched settings.json ask rule");
        }
        SettingsDecision::Allow | SettingsDecision::NoMatch => {}
        SettingsDecision::Deny => {
            unreachable!("settings deny rules are handled before plan-mode enforcement");
        }
    }

    if is_plan_mode(permission_mode) {
        if gate_result.decision == PermissionDecision::Allow && soft_ask.is_none() {
            return gate_result;
        }
        return plan_mode_deny_output();
    }

    // In acceptEdits mode, auto-allow file-editing commands that:
    // - Are file-editing commands
    // - Don't target sensitive paths (system files, credentials)
    // - Don't target paths outside allowed directories (cwd + additionalDirectories)
    //
    // Claude Code auto mode has its own "would this be allowed in acceptEdits?"
    // fast path before the classifier. Run the same tool-gates-owned policy
    // under auto so approved edits are allowed by us, not by Claude's broader
    // hardcoded Bash base-command list.
    if (permission_mode == "acceptEdits" || is_auto_mode(permission_mode))
        && gate_result.decision == PermissionDecision::Ask
    {
        let commands = extract_commands(command_string);
        let allowed_dirs = settings.allowed_directories(cwd);
        if should_auto_allow_in_accept_edits(&commands, &allowed_dirs) {
            return HookOutput::allow(Some("Auto-allowed in acceptEdits mode"));
        }
    }

    // Check remaining settings.json allow rules - deny and ask already checked above.
    // For compound commands, also check each sub-command so that patterns like
    // Bash(npm install:*) match "cd /tmp && npm install".
    match check_settings_with_subcommands(&settings, command_string) {
        SettingsDecision::Ask => unreachable!("settings ask rules are handled before plan mode"),
        SettingsDecision::Allow => {
            // User explicitly allows - return allow immediately
            if let Some(context) = gate_context.as_deref() {
                return HookOutput::allow_with_context(
                    Some("Matched settings.json allow rule"),
                    context,
                );
            }
            return HookOutput::allow(Some("Matched settings.json allow rule"));
        }
        SettingsDecision::Deny => {
            // Should not happen since we use check_command_excluding_deny
            unreachable!("check_command_excluding_deny should not return Deny");
        }
        SettingsDecision::NoMatch => {
            // No match - fall through to raw string / gate result
        }
    }

    // If raw string check flagged the command and no settings rule overrode it,
    // return the raw string result. This means pipe-to-python, output redirection,
    // etc. still ask by default, but can be permanently allowed via settings rules.
    //
    // Soft asks are a conservative default rather than a floor -- settings rules
    // already override them -- so under auto mode most of them are better judged
    // by the classifier, which sees the whole command. Two exceptions hold their
    // ask: rows marked `auto = "prompt"` (the ones that cascade destructively
    // across every match), and commands Claude's acceptEdits fast path could
    // approve, where the explicit ask is what keeps them out of it.
    // The gate's own disposition has to be consulted here too. This branch
    // returns before the gate-ask path below, so without it an irreversible
    // command could shed its hold just by gaining a redirect: the soft ask on
    // `>` would win the race and defer `npm publish > log.txt`.
    if let Some(raw_result) = soft_ask {
        if is_auto_mode(permission_mode)
            && !raw_result.hold_in_auto
            && !gate_result.hold_in_auto
            && !needs_explicit_ask_to_avoid_claude_accept_edits_passthrough(&commands)
        {
            let reason = raw_result
                .reason
                .clone()
                .unwrap_or_else(|| "Requires approval".to_string());
            return HookOutput::defer(reason, raw_result.context.clone());
        }
        return raw_result;
    }

    // Final return path. If the gate would ask but there's no raw-string
    // flag and no explicit settings rule, default interactive mode defers
    // so CC's resolver can produce the prefix-suggestion prompt button.
    //
    // In acceptEdits, CC auto-allows a hardcoded list of Bash base commands
    // when hooks defer. Keep ownership of the decision for those programs and
    // return an explicit ask. Other gate asks can still defer for the
    // prefix-suggestion prompt.
    //
    // In auto mode, CC also probes whether the tool would be allowed in
    // acceptEdits before invoking the classifier. If the command is on that
    // hardcoded Bash list and tool-gates did not already allow it above, hold
    // an explicit ask: a hook ask short-circuits CC's resolver before the
    // probe runs, so the acceptEdits fast path cannot silently approve it.
    if gate_result.decision == PermissionDecision::Ask {
        let hard_ask_in_accept_edits =
            needs_explicit_ask_to_avoid_claude_accept_edits_passthrough(&commands);
        return gate_ask_output_for_mode(
            gate_result
                .reason
                .clone()
                .unwrap_or_else(|| "Requires approval".to_string()),
            gate_result.context.clone(),
            permission_mode,
            hard_ask_in_accept_edits,
            gate_result.hold_in_auto,
        );
    }

    // Return gate result (allow, ask under auto mode, or skip)
    gate_result
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // Helper to get permission decision
    /// Return the semantic decision for tests. Defer is a wire-level
    /// "let CC handle the prompt" -- equivalent to "ask" from the
    /// caller's perspective (the command will need approval). Tests that
    /// want to distinguish defer from ask should call
    /// `result.decision.as_str()` directly.
    pub(crate) fn get_decision(result: &HookOutput) -> &str {
        match result.decision {
            PermissionDecision::Defer => "ask",
            _ => result.decision.as_str(),
        }
    }

    pub(crate) fn get_reason(result: &HookOutput) -> &str {
        result.reason.as_deref().unwrap_or("")
    }

    pub(crate) fn get_claude_wire_decision(result: &HookOutput) -> Option<String> {
        let value = result.serialize(crate::models::Client::Claude);
        value
            .get("hookSpecificOutput")
            .and_then(|hso| hso.get("permissionDecision"))
            .and_then(|decision| decision.as_str())
            .map(str::to_owned)
    }

    mod settings_context_preservation {
        use super::*;
        use std::fs;
        use tempfile::TempDir;

        fn find_hintable_command() -> Option<(&'static str, &'static str)> {
            use crate::tool_cache::get_cache;
            let cache = get_cache();
            if cache.is_available("rg") {
                return Some(("grep -r pattern logs/", "rg"));
            }
            if cache.is_available("bat") {
                return Some(("cat README.md", "bat"));
            }
            if cache.is_available("fd") {
                return Some(("find . -name '*.rs'", "fd"));
            }
            None
        }

        #[test]
        fn test_settings_allow_preserves_gate_hint_context() {
            let Some((command, hint_keyword)) = find_hintable_command() else {
                eprintln!("SKIP: no modern CLI tools available for hint test");
                return;
            };

            let temp_dir = TempDir::new().unwrap();
            let claude_dir = temp_dir.path().join(".claude");
            fs::create_dir(&claude_dir).unwrap();

            let program = command.split_whitespace().next().unwrap();
            let settings_content =
                format!(r#"{{"permissions":{{"allow":["Bash({program}:*)"]}}}}"#);
            fs::write(claude_dir.join("settings.json"), &settings_content).unwrap();

            let cwd = temp_dir.path().to_str().unwrap();
            let result = check_command_with_settings(command, cwd, "default", Client::Claude);

            assert_eq!(get_decision(&result), "allow");
            // Hints may or may not be present depending on dedup state,
            // but if present they should contain the expected keyword
            if let Some(ref ctx) = result.context {
                assert!(
                    ctx.contains(hint_keyword),
                    "Expected hint containing '{hint_keyword}', got: {ctx}"
                );
            }
        }

        #[test]
        fn test_settings_ask_preserves_gate_hint_context() {
            let Some((command, hint_keyword)) = find_hintable_command() else {
                eprintln!("SKIP: no modern CLI tools available for hint test");
                return;
            };

            let temp_dir = TempDir::new().unwrap();
            let claude_dir = temp_dir.path().join(".claude");
            fs::create_dir(&claude_dir).unwrap();

            let program = command.split_whitespace().next().unwrap();
            let settings_content = format!(r#"{{"permissions":{{"ask":["Bash({program}:*)"]}}}}"#);
            fs::write(claude_dir.join("settings.json"), &settings_content).unwrap();

            let cwd = temp_dir.path().to_str().unwrap();
            let result = check_command_with_settings(command, cwd, "default", Client::Claude);

            assert_eq!(get_decision(&result), "ask");
            if let Some(ref ctx) = result.context {
                assert!(
                    ctx.contains(hint_keyword),
                    "Expected hint containing '{hint_keyword}', got: {ctx}"
                );
            }
        }
    }

    /// Tests for targets_sensitive_path function.
    /// Verifies that system paths and security-critical files are blocked,
    /// while regular user dotfiles are allowed.
    mod compound_commands {
        use super::*;

        #[test]
        fn test_all_read_allows() {
            let result = check_command("git status && git log && git branch");
            assert_eq!(get_decision(&result), "allow");
        }

        #[test]
        fn test_any_write_asks() {
            let result = check_command("git status && git add . && git log");
            assert_eq!(get_decision(&result), "ask");
        }

        #[test]
        fn test_any_blocked_denies() {
            let result = check_command("echo test && rm -rf /");
            assert_eq!(get_decision(&result), "deny");
        }

        #[test]
        fn test_pipeline_read_only() {
            // Pipe between two read-only commands. Avoids `| head` / `| tail`
            // because the head/tail deny rule (see `check_head_tail_pipe`) would
            // override at the raw-string stage before compound analysis runs.
            let result = check_command("ls -la | sort");
            assert_eq!(get_decision(&result), "allow");
        }

        #[test]
        fn test_semicolon_chain_read() {
            let result = check_command("ls -la; pwd; whoami");
            assert_eq!(get_decision(&result), "allow");
        }

        // Complex multi-command chains (user's real-world cases)
        #[test]
        fn test_git_add_commit_push_chain() {
            let result = check_command(
                "git add -A && git commit --amend --no-edit && git push --force-with-lease",
            );
            assert_eq!(
                get_decision(&result),
                "ask",
                "Should ask for git add/commit/push chain"
            );
            let reason = get_reason(&result);
            assert!(reason.contains("git"), "Reason should mention git");
        }

        #[test]
        fn test_git_reset_commit_chain() {
            let result = check_command("git reset --soft HEAD~2 && git commit -m \"squash\"");
            assert_eq!(get_decision(&result), "ask", "Should ask for reset+commit");
        }

        #[test]
        fn test_git_log_then_push() {
            let result = check_command("git log --oneline -2 && git push --force-with-lease");
            assert_eq!(get_decision(&result), "ask", "Should ask due to force push");
        }

        // || operator tests
        #[test]
        fn test_or_chain_all_read() {
            let result = check_command("git status || git log || pwd");
            assert_eq!(get_decision(&result), "allow");
        }

        #[test]
        fn test_or_chain_with_write() {
            let result = check_command("git pull || git fetch && git merge");
            assert_eq!(get_decision(&result), "ask");
        }

        // Mixed operators
        #[test]
        fn test_mixed_and_or() {
            let result = check_command("git fetch && git status || git pull");
            assert_eq!(get_decision(&result), "ask", "pull should trigger ask");
        }

        // Semicolon with writes
        #[test]
        fn test_semicolon_with_writes() {
            let result = check_command("npm install; npm run build; npm test");
            assert_eq!(get_decision(&result), "ask", "install should trigger ask");
        }

        // Multiple risky operations
        #[test]
        fn test_multiple_risky_ops() {
            let result = check_command("rm -rf node_modules && npm install && npm run build");
            assert_eq!(get_decision(&result), "ask");
            let reason = get_reason(&result);
            // Should mention multiple operations
            assert!(
                reason.contains("rm") || reason.contains("npm"),
                "Should mention operations"
            );
        }

        // Pipeline with write at end
        #[test]
        fn test_pipeline_with_write() {
            let result = check_command("cat file.txt | grep pattern | tee output.txt");
            // tee writes to file, so it should ask for permission
            assert_eq!(get_decision(&result), "ask");
        }

        // Block wins over ask
        #[test]
        fn test_block_wins_in_chain() {
            let result = check_command("npm install && rm -rf / && git push");
            assert_eq!(get_decision(&result), "deny", "Block should win");
        }

        // cd before command (common pattern)
        #[test]
        fn test_cd_then_command() {
            let result = check_command("cd /tmp && git clone https://github.com/test/repo");
            assert_eq!(get_decision(&result), "ask", "clone should trigger ask");
        }

        // echo with dangerous-looking content (should allow - it's just echo)
        #[test]
        fn test_echo_safe() {
            let result = check_command("echo 'rm -rf /' && pwd");
            assert_eq!(
                get_decision(&result),
                "allow",
                "echo of dangerous text is safe"
            );
        }
    }

    mod quoted_substitution_composition {
        use super::*;

        #[test]
        fn mutating_inner_command_requires_approval() {
            let result = check_command(r#"echo "$(git add file.txt)""#);
            assert_eq!(get_decision(&result), "ask");
        }

        #[test]
        fn unknown_inner_command_requires_approval() {
            let result = check_command(r#"echo "$(mytool deploy)""#);
            assert_eq!(get_decision(&result), "ask");
        }

        #[test]
        fn read_only_inner_command_remains_allowed() {
            let result = check_command(r#"echo "$(git status)""#);
            assert_eq!(get_decision(&result), "allow");
        }
    }

    mod env_split_string_composition {
        use super::*;

        #[test]
        fn unknown_split_string_utility_requires_approval() {
            let result = check_command("env --split-string='mytool --check'");
            assert_eq!(get_decision(&result), "ask");
        }

        #[test]
        fn safe_split_string_utility_remains_allowed() {
            let result = check_command("env -S 'git status'");
            assert_eq!(get_decision(&result), "allow");
        }

        #[test]
        fn blocked_split_string_utility_remains_denied() {
            let result = check_command("env --split-string='rm -rf /'");
            assert_eq!(get_decision(&result), "deny");
        }

        #[test]
        fn ambiguous_split_string_requires_approval() {
            let result = check_command("env --split-string='$COMMAND --check'");
            assert_eq!(get_decision(&result), "ask");
        }
    }

    mod privilege_wrapper_composition {
        use super::*;

        #[test]
        fn safe_inner_commands_keep_the_privilege_approval_floor() {
            for command in [
                "sudo git status",
                "sudo -u root git status",
                "sudo -k git status",
                "doas git status",
            ] {
                let result = check_command(command);
                assert_eq!(get_decision(&result), "ask", "wrong decision for {command}");
                assert!(
                    get_reason(&result).contains(command.split_whitespace().next().unwrap()),
                    "reason must name the privilege wrapper for {command}"
                );
            }
        }

        #[test]
        fn non_executing_timestamp_reset_remains_allowed() {
            let result = check_command("sudo -k");
            assert_eq!(get_decision(&result), "allow");
        }

        #[test]
        fn blocked_inner_command_outranks_the_privilege_floor() {
            let result = check_command("sudo rm -rf /");
            assert_eq!(get_decision(&result), "deny");
        }
    }

    // === Compound Command Settings Matching ===

    mod compound_settings {
        use super::*;
        use crate::settings::{Permissions, Settings, SettingsDecision};

        fn make_settings(allow: &[&str], ask: &[&str], deny: &[&str]) -> Settings {
            Settings {
                permissions: Permissions {
                    allow: allow.iter().map(|s| s.to_string()).collect(),
                    ask: ask.iter().map(|s| s.to_string()).collect(),
                    deny: deny.iter().map(|s| s.to_string()).collect(),
                    additional_directories: vec![],
                },
            }
        }

        // --- Deny checks ---

        #[test]
        fn test_deny_catches_subcommand_in_compound() {
            let settings = make_settings(&[], &[], &["Bash(rm:*)"]);
            // "rm -rf ." is a sub-command, full string starts with "cd"
            let matched = matched_subcommand_deny(&settings, "cd /tmp && rm -rf .");
            assert_eq!(matched, Some("Bash(rm:*)"));
        }

        #[test]
        fn test_deny_single_command_defers_to_full_string() {
            let settings = make_settings(&[], &[], &["Bash(rm:*)"]);
            // Single command. Helper returns None (full string check handles it)
            assert!(matched_subcommand_deny(&settings, "rm -rf .").is_none());
        }

        #[test]
        fn test_deny_no_match_in_compound() {
            let settings = make_settings(&[], &[], &["Bash(rm:*)"]);
            assert!(matched_subcommand_deny(&settings, "cd /tmp && npm install").is_none());
        }

        // --- Allow checks ---

        #[test]
        fn test_gate_allowed_segment_counts_as_covered() {
            // cd has no settings rule but is gate-allowed (safe command).
            // Gate-allowed segments count as covered, so both segments are
            // resolved and the settings Allow for npm install wins.
            let settings = make_settings(&["Bash(npm install:*)"], &[], &[]);
            let result = check_settings_with_subcommands(&settings, "cd /tmp && npm install");
            assert_eq!(result, SettingsDecision::Allow);
        }

        #[test]
        fn test_all_subcommands_match_returns_allow() {
            // When ALL sub-commands match settings rules, compound is allowed
            let settings = make_settings(&["Bash(cd:*)", "Bash(npm install:*)"], &[], &[]);
            let result = check_settings_with_subcommands(&settings, "cd /tmp && npm install");
            assert_eq!(result, SettingsDecision::Allow);
        }

        #[test]
        fn test_gate_allowed_cd_with_settings_allow_cargo() {
            // cd is gate-allowed, cargo build matches settings allow rule.
            // Both segments covered -> Allow.
            let settings = make_settings(&["Bash(cargo build:*)"], &[], &[]);
            let result = check_settings_with_subcommands(
                &settings,
                "cd /home/user/project && cargo build --release",
            );
            assert_eq!(result, SettingsDecision::Allow);
        }

        #[test]
        fn test_incidental_match_does_not_allow_dangerous_commands() {
            // Regression: awk matching a settings rule must NOT auto-approve
            // curl POST commands in the same compound expression
            let settings = make_settings(&["Bash(awk:*)"], &[], &[]);
            let result = check_settings_with_subcommands(
                &settings,
                "curl -sk -X POST https://example.com && awk '{print $1}' file.txt",
            );
            assert_eq!(result, SettingsDecision::NoMatch);
        }

        #[test]
        fn test_all_gate_allowed_falls_through() {
            // Both cd and cargo build are gate-allowed, but no settings rule
            // matches either. Falls through to NoMatch so the gate result
            // (also Allow) provides a more accurate reason.
            let settings = make_settings(&["Bash(npm:*)"], &[], &[]);
            let result =
                check_settings_with_subcommands(&settings, "cd /tmp && cargo build --release");
            assert_eq!(result, SettingsDecision::NoMatch);
        }

        #[test]
        fn test_full_string_match_still_works() {
            // Simple non-compound command still works via full string check
            let settings = make_settings(&["Bash(npm install:*)"], &[], &[]);
            let result = check_settings_with_subcommands(&settings, "npm install lodash");
            assert_eq!(result, SettingsDecision::Allow);
        }

        // --- Ask wins over allow ---

        #[test]
        fn test_ask_subcommand_wins_over_allow_subcommand() {
            // Use cd prefix so full string doesn't match git/npm patterns
            let settings = make_settings(&["Bash(git status:*)"], &["Bash(npm install:*)"], &[]);
            let result =
                check_settings_with_subcommands(&settings, "cd /tmp && git status && npm install");
            assert_eq!(result, SettingsDecision::Ask);
        }

        // --- Pipeline sub-commands ---

        #[test]
        fn test_allow_in_pipeline() {
            let settings = make_settings(&["Bash(git log:*)"], &[], &[]);
            let result = check_settings_with_subcommands(&settings, "git log | head -10");
            assert_eq!(result, SettingsDecision::Allow);
        }

        #[test]
        fn test_echo_pipe_to_settings_allowed_script() {
            // echo is gate-allowed, the script matches a settings allow rule.
            // Both segments covered -> Allow.
            let settings = make_settings(
                &["Bash(/home/user/.claude/skills/my-skill/scripts/tool *)"],
                &[],
                &[],
            );
            let result = check_settings_with_subcommands(
                &settings,
                "echo 'query text' | /home/user/.claude/skills/my-skill/scripts/tool search -n 3",
            );
            assert_eq!(result, SettingsDecision::Allow);
        }

        #[test]
        fn test_gate_ask_segment_still_blocks_compound_allow() {
            // curl POST is gate-ask (not gate-allowed), so it counts as
            // has_no_match and prevents the compound from being auto-approved.
            let settings = make_settings(&["Bash(awk:*)"], &[], &[]);
            let result = check_settings_with_subcommands(
                &settings,
                "curl -sk -X POST https://example.com | awk '{print $1}'",
            );
            assert_eq!(result, SettingsDecision::NoMatch);
        }

        // --- Single command skips sub-command check ---

        #[test]
        fn test_single_command_nomatch_stays_nomatch() {
            let settings = make_settings(&["Bash(npm:*)"], &[], &[]);
            let result = check_settings_with_subcommands(&settings, "cargo build");
            assert_eq!(result, SettingsDecision::NoMatch);
        }
    }

    // === Priority Order ===

    mod priority_order {
        use super::*;

        #[test]
        fn test_block_wins_over_ask() {
            let result = check_command("npm install && rm -rf /");
            assert_eq!(get_decision(&result), "deny");
        }

        #[test]
        fn test_ask_wins_over_allow() {
            let result = check_command("git status && rm file.txt");
            assert_eq!(get_decision(&result), "ask");
        }
    }

    // === Empty and Invalid ===

    mod empty_and_invalid {
        use super::*;

        #[test]
        fn test_empty_string_no_opinion() {
            let result = check_command("");
            assert_eq!(result.decision, PermissionDecision::Approve);
        }

        #[test]
        fn test_whitespace_only_no_opinion() {
            let result = check_command("   ");
            assert_eq!(result.decision, PermissionDecision::Approve);
        }

        #[test]
        fn test_unknown_command_asks() {
            let result = check_command("someunknowncommand --flag");
            assert_eq!(
                get_decision(&result),
                "ask",
                "Unknown commands should ask for approval"
            );
        }

        #[test]
        fn test_awk_safe_idiom_allows_and_surfaces_modern_hint() {
            // A line-count idiom has no exec/write marker, so check_awk allows it.
            // The modern-CLI hint still rides the allow via additionalContext so
            // the agent learns the autoapproved alternative. The hint is gated on
            // rg being available (we never nudge toward an uninstalled tool), so
            // assert conditionally to stay hermetic on CI runners that lack rg.
            // The routing itself is covered unconditionally by the hint_awk tests.
            let result = check_command("awk 'END{print NR}' file.txt");
            assert_eq!(get_decision(&result), "allow");
            let ctx = result.context.unwrap_or_default();
            if crate::tool_cache::get_cache().is_available("rg") {
                assert!(
                    ctx.contains("rg -c"),
                    "expected rg line-count hint, got: {ctx}"
                );
            } else {
                assert!(ctx.is_empty(), "no hint expected without rg, got: {ctx}");
            }
        }

        #[test]
        fn test_awk_range_extraction_allows_with_no_hint() {
            // Pattern-delimited range extraction has no exec/write marker (allow)
            // and no autoapproved peer, so it must not be nudged toward a worse
            // tool either.
            let result = check_command("awk '/^---$/{c++; next} c==1' file.md");
            assert_eq!(get_decision(&result), "allow");
            assert!(
                result.context.is_none(),
                "range extraction should get no hint, got: {:?}",
                result.context
            );
        }
    }

    // === Integration ===

    #[test]
    fn test_git_status_allows() {
        let result = check_command("git status");
        assert_eq!(get_decision(&result), "allow");
    }

    #[test]
    fn test_rm_rf_root_blocks() {
        let result = check_command("rm -rf /");
        assert_eq!(get_decision(&result), "deny");
    }

    /// Integration coverage through the full check_command pipeline
    /// (parser, router, gates, settings) for every home-equivalent form
    /// of `rm`. Unit tests bypass the tree-sitter parser, so a quoting or
    /// expansion surprise there could mask these forms.
    #[serial_test::serial]
    #[test]
    fn test_rm_rf_home_variants_all_deny() {
        // The rm-rf home-detection reads HOME via `dirs::home_dir()`. If
        // a peer test temporarily mutates HOME to a tempdir (e.g., the
        // serial settings/tracking tests), this read sees the wrong path
        // and the deny mismatches. #[serial] keeps both sides on one
        // mutex so the read happens against real HOME.
        for cmd_str in [
            "rm -rf $HOME",
            "rm -rf ${HOME}",
            "rm -rf /home/$USER",
            "rm -rf /home/${USER}",
            "rm -rf $HOME/.ssh",
            "rm -rf ${HOME}/.aws/credentials",
            "rm -rf $HOME/.gnupg",
        ] {
            let result = check_command(cmd_str);
            assert_eq!(
                get_decision(&result),
                "deny",
                "expected deny for: {cmd_str}"
            );
        }
    }

    /// Negative integration test: benign subdirectories under home must
    /// still pass through to ask, not block. Same HOME-read concern as
    /// the deny test above.
    #[serial_test::serial]
    #[test]
    fn test_rm_rf_benign_home_subdir_asks() {
        let result = check_command("rm -rf $HOME/projects/foo");
        assert_eq!(get_decision(&result), "ask");
    }

    #[test]
    fn test_echo_quoted_command_allows() {
        let result = check_command(r#"echo "gh pr create""#);
        assert_eq!(get_decision(&result), "allow");
    }

    // === Mise Task Expansion ===

    mod hint_dedup {
        use super::*;

        #[test]
        fn test_hint_deduped_within_session() {
            let r1 = check_command_for_session("head -n 10 file.txt", "dedup-1");
            let r2 = check_command_for_session("head -n 10 file.txt", "dedup-1");
            if r1.context.is_some() {
                assert!(r2.context.is_none(), "second call should suppress hint");
            }
        }

        #[test]
        fn test_no_approval_context() {
            let result = check_command_with_settings_and_session(
                "npm install lodash",
                "/tmp",
                "default",
                "dedup-2",
                Client::Claude,
            );
            if let Some(ref c) = result.context {
                assert!(
                    !c.contains("pending list"),
                    "approval instructions should not appear in additionalContext"
                );
            }
        }
    }

    // === Transparent Wrapper Stripping (end-to-end) ===
}

/// Runtime paths under an enterprise managed document that sets
/// `allowManagedPermissionRulesOnly`. These go through the public routing entry
/// point rather than the resolver, so nested expansion is covered too.
#[cfg(test)]
mod managed_only_runtime_tests {
    use super::tests::get_decision;
    use super::*;
    use crate::settings::fixtures::SettingsFixture;

    /// Managed document asserting the flag, with `rules` spliced into
    /// `permissions`.
    fn managed_only(rules: &str) -> String {
        format!(r#"{{"allowManagedPermissionRulesOnly": true, "permissions": {{{rules}}}}}"#)
    }

    #[test]
    fn bash_routing_uses_the_managed_allow_and_drops_the_lower_allow() {
        let fixture = SettingsFixture::new()
            .with_managed(&managed_only(r#""allow": ["Bash(mytool42:*)"]"#))
            .with_user(r#"{"permissions": {"allow": ["Bash(othertool42:*)"]}}"#)
            .with_project(r#"{"permissions": {"allow": ["Bash(thirdtool42:*)"]}}"#);
        let cwd = fixture.cwd();

        fixture.run(|| {
            let managed =
                check_command_with_settings("mytool42 verify", &cwd, "default", Client::Claude);
            assert_eq!(get_decision(&managed), "allow");

            for excluded in ["othertool42 verify", "thirdtool42 verify"] {
                let result = check_command_with_settings(excluded, &cwd, "default", Client::Claude);
                assert_ne!(
                    get_decision(&result),
                    "allow",
                    "{excluded} must not inherit a lower-scope allow"
                );
            }
        });
    }

    #[test]
    fn bash_routing_drops_a_lower_deny() {
        let lower_deny = r#"{"permissions": {"deny": ["Bash(git status:*)"]}}"#;

        let excluded = SettingsFixture::new()
            .with_managed(&managed_only(""))
            .with_user(lower_deny);
        let cwd = excluded.cwd();
        let under_managed_only = excluded
            .run(|| check_command_with_settings("git status", &cwd, "default", Client::Claude));
        assert_eq!(get_decision(&under_managed_only), "allow");

        // Same lower rule, managed flag off: the deny participates again.
        let merged = SettingsFixture::new()
            .with_managed(r#"{"allowManagedPermissionRulesOnly": false, "permissions": {}}"#)
            .with_user(lower_deny);
        let cwd = merged.cwd();
        let under_merge = merged
            .run(|| check_command_with_settings("git status", &cwd, "default", Client::Claude));
        assert_eq!(get_decision(&under_merge), "deny");
    }

    #[test]
    fn compound_commands_match_only_managed_rules() {
        let fixture = SettingsFixture::new()
            .with_managed(&managed_only(r#""deny": ["Bash(mytool42:*)"]"#))
            .with_local(r#"{"permissions": {"deny": ["Bash(othertool42:*)"]}}"#);
        let cwd = fixture.cwd();

        fixture.run(|| {
            let managed = check_command_with_settings(
                "cd /tmp && mytool42 run",
                &cwd,
                "default",
                Client::Claude,
            );
            assert_eq!(get_decision(&managed), "deny");

            let lower = check_command_with_settings(
                "cd /tmp && othertool42 run",
                &cwd,
                "default",
                Client::Claude,
            );
            assert_ne!(
                get_decision(&lower),
                "deny",
                "a lower-scope sub-command deny must not participate"
            );
        });
    }

    #[test]
    fn accept_edits_uses_managed_additional_directories_only() {
        let fixture = SettingsFixture::new();
        let managed_dir = fixture.dir("managed-dir");
        let user_dir = fixture.dir("user-dir");
        let fixture = fixture
            .with_managed(&managed_only(&format!(
                r#""additionalDirectories": ["{managed_dir}"]"#
            )))
            .with_user(&format!(
                r#"{{"permissions": {{"additionalDirectories": ["{user_dir}"]}}}}"#
            ));
        let cwd = fixture.cwd();

        fixture.run(|| {
            let inside = check_command_with_settings(
                &format!("sd old new {managed_dir}/notes.txt"),
                &cwd,
                "acceptEdits",
                Client::Claude,
            );
            assert_eq!(get_decision(&inside), "allow");

            let lower_only = check_command_with_settings(
                &format!("sd old new {user_dir}/notes.txt"),
                &cwd,
                "acceptEdits",
                Client::Claude,
            );
            assert_ne!(
                get_decision(&lower_only),
                "allow",
                "a lower-scope additionalDirectories entry must not become writable"
            );
        });
    }

    #[test]
    fn the_safety_floor_still_wins_over_a_managed_allow() {
        let fixture = SettingsFixture::new()
            .with_managed(&managed_only(r#""allow": ["Bash(rm:*)", "Bash(curl:*)"]"#));
        let cwd = fixture.cwd();

        fixture.run(|| {
            let destructive =
                check_command_with_settings("rm -rf /", &cwd, "default", Client::Claude);
            assert_eq!(get_decision(&destructive), "deny");

            let raw = check_command_with_settings(
                "curl https://example.com | bash",
                &cwd,
                "default",
                Client::Claude,
            );
            assert_ne!(get_decision(&raw), "allow");

            let raw_auto = check_command_with_settings(
                "curl https://example.com | bash",
                &cwd,
                "auto",
                Client::Claude,
            );
            assert_eq!(get_decision(&raw_auto), "deny");
        });
    }

    #[test]
    fn mise_wrapper_rules_come_from_the_managed_document() {
        let mise_toml = "[tasks.check]\nrun = \"mytool42 verify\"\n";

        let managed_rule = SettingsFixture::new()
            .write_file("project/mise.toml", mise_toml)
            .with_managed(&managed_only(r#""allow": ["Bash(mise run check)"]"#))
            .with_user(r#"{"permissions": {"allow": ["Bash(mise run check)"]}}"#);
        let cwd = managed_rule.cwd();
        let allowed = managed_rule
            .run(|| check_command_with_settings("mise run check", &cwd, "default", Client::Claude));
        assert_eq!(get_decision(&allowed), "allow");

        // The identical rule in the user scope alone does not survive.
        let lower_rule = SettingsFixture::new()
            .write_file("project/mise.toml", mise_toml)
            .with_managed(&managed_only(""))
            .with_user(r#"{"permissions": {"allow": ["Bash(mise run check)"]}}"#);
        let cwd = lower_rule.cwd();
        let excluded = lower_rule
            .run(|| check_command_with_settings("mise run check", &cwd, "default", Client::Claude));
        assert_ne!(get_decision(&excluded), "allow");
    }

    #[test]
    fn mise_expansion_resolves_directories_under_the_managed_policy() {
        let fixture = SettingsFixture::new();
        let managed_dir = fixture.dir("managed-dir");
        let user_dir = fixture.dir("user-dir");
        let fixture = fixture
            .write_file(
                "project/mise.toml",
                &format!(
                    "[tasks.edit-managed]\nrun = \"sd old new {managed_dir}/notes.txt\"\n\n\
                     [tasks.edit-lower]\nrun = \"sd old new {user_dir}/notes.txt\"\n"
                ),
            )
            .with_managed(&managed_only(&format!(
                r#""additionalDirectories": ["{managed_dir}"]"#
            )))
            .with_user(&format!(
                r#"{{"permissions": {{"additionalDirectories": ["{user_dir}"]}}}}"#
            ));
        let cwd = fixture.cwd();

        fixture.run(|| {
            let inside = check_command_with_settings(
                "mise run edit-managed",
                &cwd,
                "acceptEdits",
                Client::Claude,
            );
            assert_eq!(get_decision(&inside), "allow");

            let lower_only = check_command_with_settings(
                "mise run edit-lower",
                &cwd,
                "acceptEdits",
                Client::Claude,
            );
            assert_ne!(
                get_decision(&lower_only),
                "allow",
                "expansion must not reload lower-scope directories"
            );
        });
    }

    #[test]
    fn package_script_expansion_resolves_directories_under_the_managed_policy() {
        let fixture = SettingsFixture::new();
        let managed_dir = fixture.dir("managed-dir");
        let user_dir = fixture.dir("user-dir");
        let fixture = fixture
            .write_file(
                "project/package.json",
                &format!(
                    r#"{{"name": "demo", "scripts": {{
                        "edit-managed": "sd old new {managed_dir}/notes.txt",
                        "edit-lower": "sd old new {user_dir}/notes.txt"
                    }}}}"#
                ),
            )
            .with_managed(&managed_only(&format!(
                r#""additionalDirectories": ["{managed_dir}"]"#
            )))
            .with_user(&format!(
                r#"{{"permissions": {{"additionalDirectories": ["{user_dir}"]}}}}"#
            ));
        let cwd = fixture.cwd();

        fixture.run(|| {
            let inside = check_command_with_settings(
                "npm run edit-managed",
                &cwd,
                "acceptEdits",
                Client::Claude,
            );
            assert_eq!(get_decision(&inside), "allow");

            let lower_only = check_command_with_settings(
                "npm run edit-lower",
                &cwd,
                "acceptEdits",
                Client::Claude,
            );
            assert_ne!(
                get_decision(&lower_only),
                "allow",
                "expansion must not reload lower-scope directories"
            );
        });
    }

    #[test]
    fn other_clients_keep_their_lower_scope_rules() {
        for client in [Client::Codex, Client::Antigravity, Client::Gemini] {
            let fixture = SettingsFixture::new()
                .with_managed(&managed_only(r#""allow": ["Bash(mytool42:*)"]"#))
                .with_user(r#"{"permissions": {"allow": ["Bash(othertool42:*)"]}}"#);
            let cwd = fixture.cwd();

            fixture.run(|| {
                let lower =
                    check_command_with_settings("othertool42 verify", &cwd, "default", client);
                assert_eq!(
                    get_decision(&lower),
                    "allow",
                    "{client:?} must keep the four-source merge"
                );
                let managed =
                    check_command_with_settings("mytool42 verify", &cwd, "default", client);
                assert_eq!(get_decision(&managed), "allow");
            });
        }
    }
}

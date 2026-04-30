//! Tool Gates - Intelligent tool permission gate for AI coding assistants.
//!
//! Formerly `bash-gates`. Single binary that handles all tool types:
//! - **Bash/Monitor**: AST-parsed command gating (13 ordered gates, settings.json integration)
//! - **Read/Write/Edit**: Symlink guard for AI config files
//! - **Glob/Grep/MCP tools**: Configurable tool blocking
//!
//! Supports Claude Code and Gemini CLI hook systems:
//! - Claude Code: `PreToolUse`, `PermissionRequest`, `PostToolUse` (Bash, Monitor, Write, Edit)
//! - Gemini CLI: `BeforeTool`, `AfterTool` (tool_name: "run_shell_command")
//!
//! Configuration: `~/.config/tool-gates/config.toml`
//!
//! Usage:
//!   `echo '{"tool_name": "Bash", "tool_input": {"command": "gh pr list"}}' | tool-gates`
//!   `echo '{"tool_name": "Read", "tool_input": {"file_path": "/project/CLAUDE.md"}}' | tool-gates`
//!   `echo '{"tool_name": "Glob", "tool_input": {"pattern": "*.rs"}}' | tool-gates`
//!
//! Install:
//!   `tool-gates hooks add -s user`      # Claude Code
//!   `tool-gates hooks add --gemini`     # Gemini CLI

use std::env;
use std::io::{self, Read};
use tool_gates::config;
use tool_gates::file_guards::check_file_guard;
use tool_gates::models::{
    Client, HookInput, HookOutput, PermissionDecision, PermissionDeniedInput,
    PermissionDeniedOutput, PermissionRequestInput, PostToolUseInput, is_auto_mode, is_plan_mode,
};
use tool_gates::patterns::suggest_patterns;
use tool_gates::pending::{clear_pending, pending_count, read_pending};
use tool_gates::permission_request::handle_permission_request;
use tool_gates::post_tool_use::handle_post_tool_use;
use tool_gates::router::{check_command_with_settings_and_session, check_single_command};
use tool_gates::security_reminders::check_security_reminders;
use tool_gates::settings_writer::{
    RuleType, Scope, add_rule, list_all_rules, list_rules, remove_rule,
};
use tool_gates::tool_blocks::check_tool_block;
use tool_gates::tool_cache;
use tool_gates::tracking::{CommandPart, track_ask_command};
use tool_gates::tui::run_review;

fn main() {
    // One-time migration from ~/.cache/bash-gates/ to ~/.cache/tool-gates/
    tool_gates::cache::ensure_cache_migrated();

    let args: Vec<String> = env::args().collect();

    // Handle subcommands first
    if args.len() > 1 && args[1] == "hooks" {
        handle_hooks_subcommand(&args[2..]);
        return;
    }

    if args.len() > 1 && args[1] == "approve" {
        handle_approve_subcommand(&args[2..]);
        return;
    }

    if args.len() > 1 && args[1] == "rules" {
        handle_rules_subcommand(&args[2..]);
        return;
    }

    if args.len() > 1 && args[1] == "pending" {
        handle_pending_subcommand(&args[2..]);
        return;
    }

    if args.len() > 1 && args[1] == "doctor" {
        handle_doctor_subcommand();
        return;
    }

    if args.len() > 1 && args[1] == "review" {
        let show_all = args.iter().any(|a| a == "--all" || a == "-a");
        handle_review_subcommand(show_all);
        return;
    }

    // Handle global flags
    if args.iter().any(|a| a == "--refresh-tools") {
        eprintln!("Refreshing tool cache...");
        let cache = tool_cache::refresh_cache();
        let available: Vec<_> = cache
            .tools
            .iter()
            .filter(|(_, v)| **v)
            .map(|(k, _)| k.as_str())
            .collect();
        eprintln!(
            "Available modern tools: {}",
            if available.is_empty() {
                "none".to_string()
            } else {
                available.join(", ")
            }
        );
        return;
    }

    if args.iter().any(|a| a == "--tools-status") {
        println!("{}", tool_cache::cache_status());
        return;
    }

    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("tool-gates {}", env!("GIT_VERSION"));
        return;
    }

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_main_help();
        return;
    }

    // Read input from stdin
    let mut input = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input) {
        eprintln!("Error reading stdin: {e}");
        print_no_opinion_for(Client::Claude);
        return;
    }

    if input.trim().is_empty() {
        print_no_opinion_for(Client::Claude);
        return;
    }

    // First, try to detect hook type from raw JSON
    let hook_event: Option<String> = serde_json::from_str::<serde_json::Value>(&input)
        .ok()
        .and_then(|v| {
            v.get("hook_event_name")
                .and_then(|h| h.as_str().map(String::from))
        });

    // Detect which client is calling us
    let client = Client::from_hook_event(hook_event.as_deref().unwrap_or("PreToolUse"));

    // Route based on hook event type
    match hook_event.as_deref() {
        Some("PermissionRequest") => {
            handle_permission_request_hook(&input);
        }
        Some("PostToolUse") | Some("AfterTool") => {
            handle_post_tool_use_hook(&input, client);
        }
        Some("PermissionDenied") => {
            handle_permission_denied_hook(&input);
        }
        _ => {
            // Default: PreToolUse (Claude) or BeforeTool (Gemini) or unspecified
            handle_pre_tool_use_hook(&input, client);
        }
    }
}

/// Handle PermissionDenied hook (Claude auto mode only).
///
/// Fires when the auto-mode classifier denies a tool call. If tool-gates would
/// have allowed the same command, emit `retry: true` so the model gets a second
/// shot -- this closes the loop on classifier false positives where tool-gates
/// has stronger domain knowledge (e.g. "cargo check" is clearly safe, but the
/// classifier denied it because it lacked user intent context).
fn handle_permission_denied_hook(input: &str) {
    let pd_input: PermissionDeniedInput = match serde_json::from_str(input) {
        Ok(pi) => pi,
        Err(e) => {
            eprintln!("Error: Invalid PermissionDenied JSON: {e}");
            return;
        }
    };

    // Only act on shell tools for now -- that's where tool-gates has the
    // deepest gate knowledge. File tools and MCP calls don't benefit.
    if !Client::is_shell_tool(&pd_input.tool_name) {
        return;
    }

    // Defensive: this hook is documented to fire only on auto-mode classifier
    // denials. If Claude Code ever broadens firing criteria (user deny, plan
    // mode, future mode variants), retry:true would push the model to retry
    // commands the user or system explicitly rejected. Fail closed.
    if !is_auto_mode(&pd_input.permission_mode) {
        return;
    }

    // Respect the bash_gates opt-out so users who disabled the gate engine
    // don't get retry hints driven by the engine they turned off.
    if !config::load().features.bash_gates {
        return;
    }

    let command = pd_input.get_command();
    if command.is_empty() {
        return;
    }

    // Re-check under "default" mode (not "auto") so hard-ask promotion to deny
    // doesn't fire -- we want to know what tool-gates' own floor says, and
    // "default" gives us the Allow / Ask / Deny signal we need.
    let gate_result = check_command_with_settings_and_session(
        &command,
        &pd_input.cwd,
        "default",
        &pd_input.session_id,
    );

    // Only suggest retry if tool-gates clearly allows. If our own floor would
    // ask or deny, defer to the classifier's decision.
    if gate_result.decision != PermissionDecision::Allow {
        return;
    }

    let output = PermissionDeniedOutput::retry();
    match serde_json::to_string(&output) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("Error serializing PermissionDenied output: {e}"),
    }
}

/// Handle PreToolUse (Claude) / BeforeTool (Gemini) hook. Routes all tool types
fn handle_pre_tool_use_hook(input: &str, client: Client) {
    let hook_input: HookInput = match serde_json::from_str(input) {
        Ok(hi) => hi,
        Err(e) => {
            eprintln!("Error: Invalid JSON input: {e}");
            print_no_opinion_for(client);
            return;
        }
    };

    let config = config::load();

    // Check configurable block rules first (applies to ALL tool types)
    // Re-extract tool_input as raw map since Structured variant
    // drops unknown fields (url, pattern, etc.)
    let tool_input_map = serde_json::from_str::<serde_json::Value>(input)
        .ok()
        .and_then(|v| v.get("tool_input").cloned())
        .and_then(|v| match v {
            serde_json::Value::Object(m) => Some(m),
            _ => None,
        })
        .unwrap_or_default();
    if let Some(output) =
        check_tool_block(&hook_input.tool_name, &tool_input_map, config.block_rules())
    {
        if let Ok(json) = serde_json::to_string(&output.serialize(client)) {
            println!("{json}");
            if client == Client::Gemini {
                std::process::exit(2);
            }
        } else {
            print_deny_and_exit(client, "Internal error serializing block deny");
        }
        return;
    }

    // MCP tools in acceptEdits mode: consult `[[accept_edits_mcp]]` rules
    // before falling through to the normal tool-type dispatch.
    //
    // Claude Code itself never extends acceptEdits to MCP tools (every MCP
    // tool's internal checkPermissions returns passthrough regardless of
    // permission_mode). This branch is the user-space extension: users
    // declare which MCP tools should auto-allow under acceptEdits without
    // granting permanent approval via settings.json.
    //
    // Ordering guarantees:
    // - block_tools already ran above, so default blocks (firecrawl GitHub
    //   URLs, etc.) still win and these rules cannot override them.
    // - This runs before tool-type dispatch so MCP tools don't fall through
    //   to the pass-through branch first.
    if hook_input.permission_mode == "acceptEdits"
        && Client::is_mcp_tool(&hook_input.tool_name)
        && !config.accept_edits_mcp.is_empty()
    {
        let project_dir = std::env::var("CLAUDE_PROJECT_DIR")
            .or_else(|_| std::env::var("GEMINI_PROJECT_DIR"))
            .unwrap_or_default();
        for rule in &config.accept_edits_mcp {
            if rule.matches_tool(&hook_input.tool_name) && rule.conditions_met(&project_dir) {
                let reason = rule
                    .reason
                    .as_deref()
                    .and_then(|m| if m.trim().is_empty() { None } else { Some(m) });
                let output = HookOutput::allow(reason);
                match serde_json::to_string(&output.serialize(client)) {
                    Ok(json) => println!("{json}"),
                    Err(e) => {
                        eprintln!("tool-gates: error serializing accept_edits_mcp allow: {e}");
                        print_no_opinion_for(client);
                    }
                }
                return;
            }
        }
    }

    // Plan mode: model is in "read and explore" only. Hard-deny mutating file
    // tools (Write/Edit) before they reach file_guards/security_reminders so
    // the deny reason is unambiguous. Bash mutations are handled in
    // handle_bash_pre_tool_use after gate analysis (read-only Bash like
    // `git status` should still allow).
    if is_plan_mode(&hook_input.permission_mode) && Client::is_write_tool(&hook_input.tool_name) {
        let output = HookOutput::deny(
            "Plan mode: file edits are not allowed. Exit plan mode before writing.",
        );
        if let Ok(json) = serde_json::to_string(&output.serialize(client)) {
            println!("{json}");
            if client == Client::Gemini {
                std::process::exit(2);
            }
        } else {
            print_deny_and_exit(client, "Internal error serializing plan-mode deny");
        }
        return;
    }

    // Route by tool type (handles both Claude and Gemini tool names)
    let tool_name = hook_input.tool_name.as_str();
    if Client::is_shell_tool(tool_name) {
        // Bash / Monitor / run_shell_command: full gate engine
        if !config.features.bash_gates {
            print_no_opinion_for(client);
            return;
        }
        handle_bash_pre_tool_use(&hook_input, client);
    } else if Client::is_file_tool(tool_name) {
        // File tools: symlink guard + security reminders
        // 1. File guards: symlink check for AI config files
        if config.features.file_guards {
            let file_paths = extract_file_paths_from_map(&tool_input_map);
            for file_path in &file_paths {
                if let Some(output) =
                    check_file_guard(file_path, &hook_input.tool_name, &config.file_guards)
                {
                    if let Ok(json) = serde_json::to_string(&output.serialize(client)) {
                        println!("{json}");
                        if client == Client::Gemini {
                            std::process::exit(2);
                        }
                    } else {
                        print_deny_and_exit(client, "Internal error serializing file guard deny");
                    }
                    return;
                }
            }
        }

        // 2. Security reminders: content scanning for write/edit tools
        if config.features.security_reminders && Client::is_write_tool(tool_name) {
            if let Some(output) = check_security_reminders(
                &hook_input.tool_name,
                &tool_input_map,
                &config.security_reminders,
                &hook_input.session_id,
            ) {
                let json_value = output.serialize(client);
                let is_gemini_block = client == Client::Gemini
                    && json_value.get("decision").and_then(|d| d.as_str()) == Some("block");
                if let Ok(json) = serde_json::to_string(&json_value) {
                    println!("{json}");
                    if is_gemini_block {
                        std::process::exit(2);
                    }
                } else {
                    print_deny_and_exit(client, "Internal error serializing security reminder");
                }
            }
        }
        // No output = allow (pass through)
    } else if Client::is_skill_tool(tool_name) {
        // Skill / activate_skill: auto-approve based on config rules.
        //
        // Auto mode note: rules here fire regardless of permission_mode.
        // `[[auto_approve_skills]]` entries are explicit trust declarations
        // by the user, and auto mode opts into classifier review for unknown
        // commands -- it shouldn't revoke rules the user deliberately added.
        // If stricter auto-mode behavior is desired later, add a feature flag
        // rather than changing the default.
        if !config.auto_approve_skills.is_empty() {
            let skill_name = tool_input_map
                .get("skill")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            // Both Gemini and Claude set CLAUDE_PROJECT_DIR for compatibility
            let project_dir = std::env::var("CLAUDE_PROJECT_DIR")
                .or_else(|_| std::env::var("GEMINI_PROJECT_DIR"))
                .unwrap_or_default();

            for rule in &config.auto_approve_skills {
                if rule.matches_skill(skill_name) && rule.conditions_met(&project_dir) {
                    let reason = rule
                        .message
                        .as_deref()
                        .and_then(|m| if m.is_empty() { None } else { Some(m) });
                    let output = HookOutput::allow(reason);
                    if let Ok(json) = serde_json::to_string(&output.serialize(client)) {
                        println!("{json}");
                    }
                    return;
                }
            }
        }
        // No match = pass through (no opinion)
    }
    // All other tools: pass through (blocks already checked above)
}

/// Extract all file paths from a raw tool_input map.
/// Handles single-file tools (file_path).
fn extract_file_paths_from_map(map: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    let mut paths = Vec::new();

    // Single file_path (Read/Write/Edit)
    if let Some(fp) = map.get("file_path").and_then(|v| v.as_str()) {
        if !fp.is_empty() {
            paths.push(fp.to_string());
        }
    }

    paths
}

/// Handle Bash-specific PreToolUse logic (gate engine + tracking)
fn handle_bash_pre_tool_use(hook_input: &HookInput, client: Client) {
    let command = hook_input.get_command();
    if command.is_empty() {
        print_no_opinion_for(client);
        return;
    }

    // Check command with settings.json awareness, mode detection, and session hint dedup
    let output = check_command_with_settings_and_session(
        &command,
        &hook_input.cwd,
        &hook_input.permission_mode,
        &hook_input.session_id,
    );

    // If the result is "ask", track it for PostToolUse correlation (Claude only,
    // Gemini doesn't provide tool_use_id).
    //
    // Under auto mode, tool-gates "ask" does NOT surface a user prompt -- the
    // Claude Code classifier decides silently. Pending-queue entries there
    // represent classifier decisions, not human approvals, so skip tracking.
    // Tracking fires for both Ask and Defer: in either case the user
    // (or CC's resolver) is going to consider whether to approve, and a
    // success means we should record the pattern for the pending queue.
    if client == Client::Claude
        && (output.decision == PermissionDecision::Ask
            || output.decision == PermissionDecision::Defer)
        && !hook_input.tool_use_id.is_empty()
        && !is_auto_mode(&hook_input.permission_mode)
    {
        let commands = tool_gates::parser::extract_commands(&command);

        // Evaluate each subcommand individually to find which ones
        // actually triggered "ask" vs which are already allowed.
        let mut suggested_patterns: Vec<String> = Vec::new();
        let mut breakdown: Vec<CommandPart> = Vec::new();

        for cmd in &commands {
            let result = check_single_command(cmd);
            let (decision, reason) = match result.decision {
                tool_gates::Decision::Allow => (
                    tool_gates::Decision::Allow,
                    result.reason.unwrap_or_else(|| "Allowed".to_string()),
                ),
                tool_gates::Decision::Block => (
                    tool_gates::Decision::Block,
                    result.reason.unwrap_or_else(|| "Blocked".to_string()),
                ),
                // Ask or Skip (unknown) both mean this subcommand needs approval
                _ => {
                    let reason = result.reason.unwrap_or_else(|| {
                        output
                            .reason
                            .clone()
                            .unwrap_or_else(|| "Requires approval".to_string())
                    });
                    // Only suggest patterns for subcommands that actually need approval
                    suggested_patterns.extend(suggest_patterns(cmd));
                    (tool_gates::Decision::Ask, reason)
                }
            };
            breakdown.push(CommandPart::new(&cmd.program, &cmd.args, decision, &reason));
        }

        // For compound commands, prepend patterns from the first program.
        // Settings patterns match the full command string as a prefix,
        // so only the first program's pattern (e.g. sg:*) actually works
        // to allow the entire pipeline. Per-subcommand patterns (e.g.
        // python3:*) are informational and cover standalone usage.
        if commands.len() > 1 {
            if let Some(first) = commands.first() {
                let mut full_cmd_patterns = suggest_patterns(first);
                full_cmd_patterns.extend(suggested_patterns);
                suggested_patterns = full_cmd_patterns;
            }
        }

        // Deduplicate patterns while preserving order
        let mut seen = std::collections::HashSet::new();
        suggested_patterns.retain(|p| seen.insert(p.clone()));

        // Skip tracking if no subcommand actually needs approval
        // (e.g. raw string check fired but all individual programs are allowed)
        if suggested_patterns.is_empty() {
            // Nothing actionable to suggest, don't pollute pending queue
        } else {
            track_ask_command(
                &hook_input.tool_use_id,
                &command,
                suggested_patterns,
                breakdown,
                &hook_input.project_id(),
                &hook_input.cwd,
                &hook_input.session_id,
            );
        }
    }

    // Serialize in the appropriate format for the client
    let json_value = output.serialize(client);
    let is_gemini_block = client == Client::Gemini
        && json_value.get("decision").and_then(|d| d.as_str()) == Some("block");
    match serde_json::to_string(&json_value) {
        Ok(json) => {
            println!("{json}");
            if is_gemini_block {
                std::process::exit(2);
            }
        }
        Err(e) => {
            eprintln!("Error serializing output: {e}");
            print_no_opinion_for(client);
        }
    }
}

fn handle_permission_request_hook(input: &str) {
    let perm_input: PermissionRequestInput = match serde_json::from_str(input) {
        Ok(pi) => pi,
        Err(e) => {
            eprintln!("Error: Invalid PermissionRequest JSON: {e}");
            // Don't output anything - let normal prompt show
            return;
        }
    };

    // Only process shell tools, file tools (Edit/Write worktree approval),
    // and MCP tools (for the accept_edits_mcp path). Other tool types let
    // the normal permission prompt show.
    if !Client::is_shell_tool(&perm_input.tool_name)
        && !Client::is_write_tool(&perm_input.tool_name)
        && !Client::is_mcp_tool(&perm_input.tool_name)
    {
        return;
    }

    // Extract the raw tool_input as a Map from the source JSON. Needed
    // because ToolInputVariant is untagged and `Structured(ToolInput)`
    // silently wins for MCP payloads (every ToolInput field is optional),
    // erasing fields like `url` that block rules rely on. Re-parsing from
    // the raw input sidesteps that.
    let tool_input_map = serde_json::from_str::<serde_json::Value>(input)
        .ok()
        .and_then(|v| v.get("tool_input").cloned())
        .and_then(|v| match v {
            serde_json::Value::Object(m) => Some(m),
            _ => None,
        })
        .unwrap_or_default();

    // Check if we should approve this (PermissionRequest is Claude-only)
    if let Some(output) = handle_permission_request(&perm_input, &tool_input_map) {
        match serde_json::to_string(&output) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("Error serializing PermissionRequest output: {e}");
                // Don't output anything - let normal prompt show
            }
        }
    }
    // If None, we don't output anything - lets the normal permission prompt show
}

/// Handle PostToolUse (Claude) / AfterTool (Gemini) hook
fn handle_post_tool_use_hook(input: &str, client: Client) {
    let post_input: PostToolUseInput = match serde_json::from_str(input) {
        Ok(pi) => pi,
        Err(e) => {
            eprintln!("Error: Invalid PostToolUse JSON: {e}");
            return;
        }
    };

    let tool_name = post_input.tool_name.as_str();
    if Client::is_shell_tool(tool_name) {
        // Shell commands: track successful executions for approval learning
        // Gemini doesn't provide tool_use_id, so tracking won't work
        if client == Client::Gemini {
            return;
        }
        if let Some(output) = handle_post_tool_use(&post_input) {
            if let Ok(json) = serde_json::to_string(&output) {
                println!("{json}");
            } else {
                eprintln!("Error: failed to serialize PostToolUse output");
            }
        }
    } else if Client::is_write_tool(tool_name) {
        // File tools: post-write security scanning (Tier 2 anti-patterns)
        // PostToolUseOutput uses Claude-specific wire format (hookEventName: "PostToolUse"),
        // so skip for Gemini until AfterTool output is properly serialized
        if client == Client::Gemini {
            return;
        }
        let config = config::load();
        if !config.features.security_reminders {
            return;
        }
        // Re-extract tool_input as raw map
        let tool_input_map = serde_json::from_str::<serde_json::Value>(input)
            .ok()
            .and_then(|v| v.get("tool_input").cloned())
            .and_then(|v| match v {
                serde_json::Value::Object(m) => Some(m),
                _ => None,
            })
            .unwrap_or_default();
        if let Some(output) = tool_gates::security_reminders::check_security_reminders_post(
            &post_input.tool_name,
            &tool_input_map,
            &config.security_reminders,
            &post_input.session_id,
        ) {
            if let Ok(json) = serde_json::to_string(&output) {
                println!("{json}");
            } else {
                eprintln!("Error: failed to serialize PostToolUse security output");
            }
        }
    }
}

fn get_binary_path() -> String {
    // On Linux, current_exe() reads /proc/self/exe which the kernel resolves
    // through symlinks to the real binary (e.g., Homebrew Cellar path). That
    // path breaks on brew upgrade. Instead, use argv[0] and resolve via PATH
    // to get the stable symlink path.
    let argv0 = std::env::args().next().unwrap_or_default();

    if argv0.contains('/') {
        // Invoked with an explicit path. Use it directly (preserves symlinks)
        return argv0;
    }

    // Bare name (e.g., "tool-gates"). Find the symlink in PATH
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            let candidate = std::path::PathBuf::from(dir).join(&argv0);
            if candidate.exists() {
                return candidate.display().to_string();
            }
        }
    }

    // Last resort: current_exe (may be Cellar path, but better than nothing)
    std::env::current_exe()
        .ok()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "tool-gates".to_string())
}

/// PreToolUse matcher for built-in tools (exact match mode).
/// Bash (gate engine), Read/Write/Edit (file guards), Glob/Grep (block rules).
const PRE_TOOL_USE_MATCHER: &str = "Bash|Monitor|Read|Write|Edit|Glob|Grep|Skill";

/// PreToolUse matcher for MCP tools (regex mode).
/// Matches all MCP tool calls; block rules in config decide what to deny.
const MCP_TOOL_USE_MATCHER: &str = "mcp__.*";

/// PermissionRequest matcher for Bash (command approval) + file tools (worktree approval).
const PERMISSION_REQUEST_MATCHER: &str = "Bash|Monitor|Write|Edit";

/// PermissionDenied matcher for classifier denials in auto mode.
/// Scoped to shell tools -- that's where tool-gates has gate knowledge deep
/// enough to judge whether to suggest a retry. File tools and MCP calls are
/// handled by the classifier alone.
const PERMISSION_DENIED_MATCHER: &str = "Bash|Monitor";

/// PostToolUse matcher for Bash (approval tracking) + file tools (security reminders).
const POST_TOOL_USE_MATCHER: &str = "Bash|Monitor|Write|Edit";

fn generate_hook_entry(binary_path: &str, matcher: &str) -> serde_json::Value {
    serde_json::json!({
        "matcher": matcher,
        "hooks": [{"type": "command", "command": binary_path, "timeout": 10}]
    })
}

fn generate_hooks_json(binary_path: &str) -> serde_json::Value {
    serde_json::json!({
        "PreToolUse": [
            generate_hook_entry(binary_path, PRE_TOOL_USE_MATCHER),
            generate_hook_entry(binary_path, MCP_TOOL_USE_MATCHER),
        ],
        "PermissionRequest": [generate_hook_entry(binary_path, PERMISSION_REQUEST_MATCHER)],
        "PermissionDenied": [generate_hook_entry(binary_path, PERMISSION_DENIED_MATCHER)],
        "PostToolUse": [
            generate_hook_entry(binary_path, POST_TOOL_USE_MATCHER),
        ]
    })
}

fn generate_gemini_hook_entry(binary_path: &str, matcher: &str) -> serde_json::Value {
    serde_json::json!({
        "matcher": matcher,
        "hooks": [{"type": "command", "command": binary_path, "timeout": 5000}]
    })
}

/// Gemini BeforeTool matcher for shell + file + search + skill tools.
const GEMINI_BEFORE_TOOL_MATCHER: &str = "run_shell_command|read_file|read_many_files|write_file|replace|glob|grep_search|activate_skill";

/// Gemini BeforeTool matcher for MCP tools (single underscore prefix).
const GEMINI_MCP_TOOL_MATCHER: &str = "mcp_.*";

/// Gemini AfterTool matcher for shell (tracking) + write tools (security reminders).
const GEMINI_AFTER_TOOL_MATCHER: &str = "run_shell_command|write_file|replace";

fn generate_gemini_hooks_json(binary_path: &str) -> serde_json::Value {
    serde_json::json!({
        "BeforeTool": [
            generate_gemini_hook_entry(binary_path, GEMINI_BEFORE_TOOL_MATCHER),
            generate_gemini_hook_entry(binary_path, GEMINI_MCP_TOOL_MATCHER),
        ],
        "AfterTool": [
            generate_gemini_hook_entry(binary_path, GEMINI_AFTER_TOOL_MATCHER),
        ]
    })
}

/// Get the settings file path based on scope
/// - "user" → ~/.claude/settings.json (or CLAUDE_CONFIG_DIR/settings.json)
/// - "project" → .claude/settings.json (committed, shared with team)
/// - "local" → .claude/settings.local.json (not committed, user+project specific)
fn get_settings_path(scope: &str) -> std::path::PathBuf {
    match scope {
        "user" => {
            // Check CLAUDE_CONFIG_DIR env var first, fall back to ~/.claude
            std::env::var("CLAUDE_CONFIG_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| {
                    dirs::home_dir()
                        .unwrap_or_else(|| std::path::PathBuf::from("."))
                        .join(".claude")
                })
                .join("settings.json")
        }
        "project" => std::path::PathBuf::from(".claude").join("settings.json"),
        "local" => std::path::PathBuf::from(".claude").join("settings.local.json"),
        _ => {
            eprintln!(
                "Error: Invalid scope '{}'. Use: user, project, or local",
                scope
            );
            std::process::exit(1);
        }
    }
}

/// Check if a single hook entry contains a tool-gates (or bash-gates) command.
fn is_tool_gates_entry(entry: &serde_json::Value) -> bool {
    entry
        .get("hooks")
        .and_then(|h| h.as_array())
        .is_some_and(|hooks| {
            hooks.iter().any(|hook| {
                hook.get("command")
                    .and_then(|c| c.as_str())
                    .is_some_and(|cmd| cmd.contains("tool-gates") || cmd.contains("bash-gates"))
            })
        })
}

/// Check if any entry in a hook array contains a tool-gates command.
fn has_tool_gates_hook(hooks_array: &serde_json::Value) -> bool {
    hooks_array
        .as_array()
        .is_some_and(|arr| arr.iter().any(is_tool_gates_entry))
}

/// Sync tool-gates hook entries for a hook event.
/// Replaces existing tool-gates entries with expected ones if matchers differ.
/// Returns None if unchanged, or a description of what changed.
fn sync_hook_entries(
    hooks_array: &mut serde_json::Value,
    expected: &[serde_json::Value],
) -> Option<String> {
    let arr = hooks_array.as_array_mut().unwrap();
    let old_matchers: Vec<String> = arr
        .iter()
        .filter(|e| is_tool_gates_entry(e))
        .filter_map(|e| e.get("matcher").and_then(|m| m.as_str()).map(String::from))
        .collect();

    let new_matchers: Vec<&str> = expected
        .iter()
        .filter_map(|e| e.get("matcher").and_then(|m| m.as_str()))
        .collect();

    if old_matchers.len() == new_matchers.len()
        && old_matchers
            .iter()
            .zip(new_matchers.iter())
            .all(|(a, b)| a.as_str() == *b)
    {
        return None;
    }

    arr.retain(|entry| !is_tool_gates_entry(entry));
    for entry in expected {
        arr.push(entry.clone());
    }

    if old_matchers.is_empty() {
        Some("added".to_string())
    } else {
        Some(format!(
            "{} -> {}",
            old_matchers.join(", "),
            new_matchers.join(", ")
        ))
    }
}

/// Install hooks into settings.json
fn install_hooks(scope: &str, dry_run: bool) {
    let binary_path = get_binary_path();
    let settings_path = get_settings_path(scope);

    eprintln!("tool-gates installer");
    eprintln!("Binary: {}", binary_path);
    eprintln!("Target: {} ({})", settings_path.display(), scope);
    eprintln!();

    // Read existing settings or create new
    let mut settings: serde_json::Value = if settings_path.exists() {
        match std::fs::read_to_string(&settings_path) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error: Failed to parse {}: {}", settings_path.display(), e);
                    std::process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("Error: Failed to read {}: {}", settings_path.display(), e);
                std::process::exit(1);
            }
        }
    } else {
        serde_json::json!({})
    };

    // Ensure hooks object exists
    if settings.get("hooks").is_none() {
        settings["hooks"] = serde_json::json!({});
    }

    let hooks = settings.get_mut("hooks").unwrap();
    let pre_tool_use_entry = generate_hook_entry(&binary_path, PRE_TOOL_USE_MATCHER);
    let mcp_tool_use_entry = generate_hook_entry(&binary_path, MCP_TOOL_USE_MATCHER);
    let perm_request_entry = generate_hook_entry(&binary_path, PERMISSION_REQUEST_MATCHER);
    let perm_denied_entry = generate_hook_entry(&binary_path, PERMISSION_DENIED_MATCHER);
    let post_tool_use_entry = generate_hook_entry(&binary_path, POST_TOOL_USE_MATCHER);
    let mut changes = Vec::new();

    // Sync PreToolUse hooks (built-in tools + MCP tools as separate entries)
    if hooks.get("PreToolUse").is_none() {
        hooks["PreToolUse"] = serde_json::json!([]);
    }
    match sync_hook_entries(
        &mut hooks["PreToolUse"],
        &[pre_tool_use_entry, mcp_tool_use_entry],
    ) {
        None => eprintln!("✓ PreToolUse hooks up to date"),
        Some(ref change) if change == "added" => {
            changes.push("PreToolUse");
            eprintln!("+ Adding PreToolUse hooks (built-in tools + MCP)");
        }
        Some(change) => {
            changes.push("PreToolUse");
            eprintln!("~ Updating PreToolUse matchers ({})", change);
        }
    }

    // Sync PermissionRequest hook (Bash + Write/Edit for worktree approval)
    if hooks.get("PermissionRequest").is_none() {
        hooks["PermissionRequest"] = serde_json::json!([]);
    }
    match sync_hook_entries(&mut hooks["PermissionRequest"], &[perm_request_entry]) {
        None => eprintln!("✓ PermissionRequest hook up to date"),
        Some(ref change) if change == "added" => {
            changes.push("PermissionRequest");
            eprintln!("+ Adding PermissionRequest hook");
        }
        Some(change) => {
            changes.push("PermissionRequest");
            eprintln!("~ Updating PermissionRequest matcher ({})", change);
        }
    }

    // Sync PermissionDenied hook (auto-mode classifier retry guidance)
    if hooks.get("PermissionDenied").is_none() {
        hooks["PermissionDenied"] = serde_json::json!([]);
    }
    match sync_hook_entries(&mut hooks["PermissionDenied"], &[perm_denied_entry]) {
        None => eprintln!("✓ PermissionDenied hook up to date"),
        Some(ref change) if change == "added" => {
            changes.push("PermissionDenied");
            eprintln!("+ Adding PermissionDenied hook (auto-mode retry)");
        }
        Some(change) => {
            changes.push("PermissionDenied");
            eprintln!("~ Updating PermissionDenied matcher ({change})");
        }
    }

    // Sync PostToolUse hook (Bash tracking + file security reminders)
    if hooks.get("PostToolUse").is_none() {
        hooks["PostToolUse"] = serde_json::json!([]);
    }
    match sync_hook_entries(&mut hooks["PostToolUse"], &[post_tool_use_entry]) {
        None => eprintln!("✓ PostToolUse hook up to date"),
        Some(ref change) if change == "added" => {
            changes.push("PostToolUse");
            eprintln!("+ Adding PostToolUse hook (Bash tracking + file security)");
        }
        Some(change) => {
            changes.push("PostToolUse");
            eprintln!("~ Updating PostToolUse matcher ({})", change);
        }
    }

    if changes.is_empty() {
        eprintln!("\nAll hooks up to date.");
        return;
    }

    if dry_run {
        eprintln!("\n--dry-run: Would write to {}", settings_path.display());
        eprintln!("\nResulting hooks configuration:");
        println!(
            "{}",
            serde_json::to_string_pretty(&settings["hooks"]).unwrap()
        );
        return;
    }

    // Create parent directory if needed
    if let Some(parent) = settings_path.parent() {
        if !parent.exists() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("Error: Failed to create {}: {}", parent.display(), e);
                std::process::exit(1);
            }
        }
    }

    // Write settings
    match std::fs::write(
        &settings_path,
        serde_json::to_string_pretty(&settings).unwrap() + "\n",
    ) {
        Ok(_) => {
            eprintln!("\n✓ Installed to {}", settings_path.display());
            eprintln!("\nHooks updated: {}", changes.join(", "));
        }
        Err(e) => {
            eprintln!("Error: Failed to write {}: {}", settings_path.display(), e);
            std::process::exit(1);
        }
    }
}

/// Get Gemini CLI settings path
fn get_gemini_settings_path(scope: &str) -> std::path::PathBuf {
    match scope {
        "user" => dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".gemini")
            .join("settings.json"),
        "project" => std::path::PathBuf::from(".gemini").join("settings.json"),
        _ => {
            eprintln!(
                "Error: Invalid Gemini scope '{}'. Use: user or project",
                scope
            );
            std::process::exit(1);
        }
    }
}

/// Install hooks into Gemini CLI settings.json
fn install_gemini_hooks(scope: &str, dry_run: bool) {
    let binary_path = get_binary_path();
    let settings_path = get_gemini_settings_path(scope);

    eprintln!("tool-gates installer (Gemini CLI)");
    eprintln!("Binary: {}", binary_path);
    eprintln!("Target: {} ({})", settings_path.display(), scope);
    eprintln!();

    let mut settings: serde_json::Value = if settings_path.exists() {
        match std::fs::read_to_string(&settings_path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_else(|e| {
                eprintln!("Error: Failed to parse {}: {}", settings_path.display(), e);
                std::process::exit(1);
            }),
            Err(e) => {
                eprintln!("Error: Failed to read {}: {}", settings_path.display(), e);
                std::process::exit(1);
            }
        }
    } else {
        serde_json::json!({})
    };

    if settings.get("hooks").is_none() {
        settings["hooks"] = serde_json::json!({});
    }

    let hooks = settings.get_mut("hooks").unwrap();
    let gemini_hooks = generate_gemini_hooks_json(&binary_path);
    let mut changes = Vec::new();

    for event in ["BeforeTool", "AfterTool"] {
        if hooks.get(event).is_none() {
            hooks[event] = serde_json::json!([]);
        }
        let expected: Vec<serde_json::Value> = gemini_hooks[event]
            .as_array()
            .map(|a| a.to_vec())
            .unwrap_or_default();
        match sync_hook_entries(&mut hooks[event], &expected) {
            None => eprintln!("✓ {} hook up to date", event),
            Some(ref change) if change == "added" => {
                changes.push(event);
                eprintln!("+ Adding {} hook(s)", event);
            }
            Some(change) => {
                changes.push(event);
                eprintln!("~ Updating {} matchers ({})", event, change);
            }
        }
    }

    if changes.is_empty() {
        eprintln!("\nAll hooks up to date.");
        return;
    }

    if dry_run {
        eprintln!("\n--dry-run: Would write to {}", settings_path.display());
        eprintln!("\nResulting hooks configuration:");
        println!(
            "{}",
            serde_json::to_string_pretty(&settings["hooks"]).unwrap()
        );
        return;
    }

    if let Some(parent) = settings_path.parent() {
        if !parent.exists() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("Error: Failed to create {}: {}", parent.display(), e);
                std::process::exit(1);
            }
        }
    }

    match std::fs::write(
        &settings_path,
        serde_json::to_string_pretty(&settings).unwrap() + "\n",
    ) {
        Ok(_) => {
            eprintln!("\n✓ Installed to {}", settings_path.display());
            eprintln!("\nHooks added: {}", changes.join(", "));
            eprintln!("\nGemini CLI hooks:");
            eprintln!("  - BeforeTool: Command safety (allow/block/ask)");
            eprintln!("  - AfterTool: Post-execution context");
        }
        Err(e) => {
            eprintln!("Error: Failed to write {}: {}", settings_path.display(), e);
            std::process::exit(1);
        }
    }
}

/// Handle `tool-gates hooks` subcommand
fn handle_hooks_subcommand(args: &[String]) {
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print_hooks_help();
        return;
    }

    let subcommand = &args[0];
    let sub_args = &args[1..];

    match subcommand.as_str() {
        "add" => handle_hooks_add(sub_args),
        "status" => handle_hooks_status(),
        "json" => print_hooks_json(sub_args),
        _ => {
            eprintln!("Unknown hooks subcommand: {}", subcommand);
            eprintln!("Run 'tool-gates hooks --help' for usage.");
            std::process::exit(1);
        }
    }
}

/// Handle `tool-gates hooks add`
fn handle_hooks_add(args: &[String]) {
    let dry_run = args.iter().any(|a| a == "--dry-run" || a == "-n");
    let gemini = args.iter().any(|a| a == "--gemini");

    // Parse --scope option
    let scope = args
        .iter()
        .position(|a| a == "--scope" || a == "-s")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    if gemini {
        // Gemini: scope defaults to "user" (~/.gemini/settings.json)
        let scope = scope.unwrap_or("user");
        install_gemini_hooks(scope, dry_run);
        return;
    }

    // No scope specified: show help (always required, even for dry-run)
    if scope.is_none() {
        eprintln!("Error: --scope (-s) is required\n");
        print_hooks_add_help();
        std::process::exit(1);
    }

    let scope = scope.unwrap();
    install_hooks(scope, dry_run);
}

/// Check a settings file for hook installation and print status
fn check_settings_hooks(scope: &str, path: &std::path::Path, hook_names: &[&str]) {
    eprint!("{:8} {} ", scope, path.display());

    if !path.exists() {
        eprintln!("(not found)");
        return;
    }

    match std::fs::read_to_string(path) {
        Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(settings) => {
                let hooks = settings.get("hooks");
                let statuses: Vec<bool> = hook_names
                    .iter()
                    .map(|name| {
                        hooks
                            .and_then(|h| h.get(*name))
                            .map(has_tool_gates_hook)
                            .unwrap_or(false)
                    })
                    .collect();

                let installed_count = statuses.iter().filter(|&&x| x).count();

                if installed_count == hook_names.len() {
                    eprintln!("✓ installed (all hooks)");
                } else if installed_count > 0 {
                    let missing: Vec<&str> = hook_names
                        .iter()
                        .zip(statuses.iter())
                        .filter(|(_, installed)| !*installed)
                        .map(|(&name, _)| name)
                        .collect();
                    eprintln!("⚠ partial (missing {})", missing.join(", "));
                } else {
                    eprintln!("- not installed");
                }
            }
            Err(_) => eprintln!("(parse error)"),
        },
        Err(_) => eprintln!("(read error)"),
    }
}

/// Handle `tool-gates hooks status`
fn handle_hooks_status() {
    eprintln!("tool-gates hook status\n");

    eprintln!("Claude Code:");
    let claude_scopes = [
        ("user", get_settings_path("user")),
        ("project", get_settings_path("project")),
        ("local", get_settings_path("local")),
    ];
    let claude_hooks = [
        "PreToolUse",
        "PermissionRequest",
        "PermissionDenied",
        "PostToolUse",
    ];
    for (scope, path) in &claude_scopes {
        check_settings_hooks(scope, path, &claude_hooks);
    }

    eprintln!("\nGemini CLI:");
    let gemini_scopes = [
        ("user", get_gemini_settings_path("user")),
        ("project", get_gemini_settings_path("project")),
    ];
    let gemini_hooks = ["BeforeTool", "AfterTool"];
    for (scope, path) in &gemini_scopes {
        check_settings_hooks(scope, path, &gemini_hooks);
    }
}

/// Print hooks JSON only
fn print_hooks_json(args: &[String]) {
    let binary_path = get_binary_path();
    let gemini = args.iter().any(|a| a == "--gemini");
    let hooks = if gemini {
        generate_gemini_hooks_json(&binary_path)
    } else {
        generate_hooks_json(&binary_path)
    };
    println!("{}", serde_json::to_string_pretty(&hooks).unwrap());
}

fn print_main_help() {
    eprintln!("tool-gates - Intelligent tool permission gate for AI coding assistants");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  tool-gates                   Read hook input from stdin (default)");
    eprintln!("  tool-gates hooks <command>   Manage Claude Code / Gemini CLI hooks");
    eprintln!("  tool-gates approve <pattern> Add permission rule to settings");
    eprintln!("  tool-gates rules <command>   List/remove permission rules");
    eprintln!("  tool-gates pending <command> Manage pending approval queue");
    eprintln!("  tool-gates review            Interactive TUI for pending approvals");
    eprintln!("  tool-gates doctor            Check config, hooks, and cache health");
    eprintln!("  tool-gates --refresh-tools   Refresh modern CLI tool detection");
    eprintln!("  tool-gates --tools-status    Show detected modern tools");
    eprintln!("  tool-gates --help            Show this help");
    eprintln!("  tool-gates --version         Show version");
    eprintln!();
    eprintln!("COMMANDS:");
    eprintln!("  hooks add -s <scope>         Add hooks to Claude Code settings");
    eprintln!("  hooks add --gemini           Add hooks to Gemini CLI settings");
    eprintln!("  hooks status                 Show hook installation status");
    eprintln!("  approve <pattern> -s <scope> Add allow rule for command pattern");
    eprintln!("  rules list                   List all permission rules");
    eprintln!("  rules remove <pattern>       Remove a permission rule");
    eprintln!(
        "  rules ask-audit              List ask-rules that suppress the third prompt button"
    );
    eprintln!("  pending list                 List pending approvals");
    eprintln!("  pending clear                Clear pending approval queue");
    eprintln!("  review                       Interactive TUI for pending approvals");
    eprintln!();
    eprintln!("SCOPES:");
    eprintln!("  user     ~/.claude/settings.json (global, recommended)");
    eprintln!("  project  .claude/settings.json (shared with team)");
    eprintln!("  local    .claude/settings.local.json (personal, not committed)");
    eprintln!();
    eprintln!("EXAMPLES:");
    eprintln!("  tool-gates hooks add -s user          # Install Claude Code hooks");
    eprintln!("  tool-gates hooks add --gemini         # Install Gemini CLI hooks");
    eprintln!("  tool-gates approve 'npm:*' -s local   # Allow npm commands");
    eprintln!("  tool-gates rules list                 # Show all rules");
    eprintln!("  tool-gates pending list               # Show pending approvals");
}

fn print_hooks_help() {
    eprintln!("tool-gates hooks - Manage Claude Code / Gemini CLI hooks");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  tool-gates hooks add -s <scope>   Add hooks to Claude Code settings");
    eprintln!("  tool-gates hooks add --gemini      Add hooks to Gemini CLI settings");
    eprintln!("  tool-gates hooks status            Show hook installation status");
    eprintln!("  tool-gates hooks json [--gemini]   Output hooks JSON only");
    eprintln!();
    eprintln!("CLAUDE CODE SCOPES:");
    eprintln!("  user     ~/.claude/settings.json (global user settings)");
    eprintln!("  project  .claude/settings.json (committed, shared with team)");
    eprintln!("  local    .claude/settings.local.json (not committed)");
    eprintln!();
    eprintln!("GEMINI CLI SCOPES:");
    eprintln!("  user     ~/.gemini/settings.json (default)");
    eprintln!("  project  .gemini/settings.json");
    eprintln!();
    eprintln!("EXAMPLES:");
    eprintln!("  tool-gates hooks add -s user         # Claude Code (recommended)");
    eprintln!("  tool-gates hooks add --gemini        # Gemini CLI");
    eprintln!("  tool-gates hooks add -s user --dry-run  # Preview changes");
}

fn print_hooks_add_help() {
    eprintln!("USAGE:");
    eprintln!("  tool-gates hooks add -s <scope> [--dry-run]");
    eprintln!("  tool-gates hooks add --gemini [-s <scope>] [--dry-run]");
    eprintln!();
    eprintln!("SCOPES:");
    eprintln!("  user     ~/.claude/settings.json");
    eprintln!("  project  .claude/settings.json");
    eprintln!("  local    .claude/settings.local.json");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("  -s, --scope <scope>   Target settings file (required for Claude Code)");
    eprintln!("  --gemini              Install for Gemini CLI instead of Claude Code");
    eprintln!("  -n, --dry-run         Preview changes without writing");
}

// === Approve subcommand ===

fn handle_approve_subcommand(args: &[String]) {
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print_approve_help();
        return;
    }

    // Find the pattern (first non-flag argument)
    let pattern = args.iter().find(|a| !a.starts_with('-'));

    let Some(pattern) = pattern else {
        eprintln!("Error: Pattern is required");
        eprintln!();
        print_approve_help();
        std::process::exit(1);
    };

    // Validate pattern is not empty or whitespace-only
    let pattern = pattern.trim();
    if pattern.is_empty() {
        eprintln!("Error: Pattern cannot be empty");
        std::process::exit(1);
    }

    // Parse --scope option
    let scope_str = args
        .iter()
        .position(|a| a == "--scope" || a == "-s")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    let Some(scope_str) = scope_str else {
        eprintln!("Error: --scope (-s) is required");
        eprintln!();
        print_approve_help();
        std::process::exit(1);
    };

    let Some(scope) = Scope::parse(scope_str) else {
        eprintln!(
            "Error: Invalid scope '{}'. Use: user, project, or local",
            scope_str
        );
        std::process::exit(1);
    };

    // Parse --type option (default: allow)
    let rule_type_str = args
        .iter()
        .position(|a| a == "--type" || a == "-t")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("allow");

    let rule_type = match rule_type_str {
        "allow" => RuleType::Allow,
        "ask" => RuleType::Ask,
        "deny" => RuleType::Deny,
        _ => {
            eprintln!(
                "Error: Invalid rule type '{}'. Use: allow, ask, or deny",
                rule_type_str
            );
            std::process::exit(1);
        }
    };

    // Check for --dry-run
    let dry_run = args.iter().any(|a| a == "--dry-run" || a == "-n");

    let formatted = tool_gates::settings_writer::format_pattern(pattern);

    if dry_run {
        eprintln!(
            "--dry-run: Would add {} rule: {}",
            rule_type.as_str(),
            formatted
        );
        eprintln!("  Scope: {} ({})", scope.as_str(), scope.path().display());
        return;
    }

    // Add the rule
    match add_rule(scope, pattern, rule_type) {
        Ok(_) => {
            eprintln!("✓ Added {} rule: {}", rule_type.as_str(), formatted);
            eprintln!("  Scope: {} ({})", scope.as_str(), scope.path().display());
        }
        Err(e) => {
            eprintln!("Error: Failed to add rule: {}", e);
            std::process::exit(1);
        }
    }
}

fn print_approve_help() {
    eprintln!("tool-gates approve - Add a command pattern to settings.json");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  tool-gates approve <pattern> -s <scope> [--type <type>] [--dry-run]");
    eprintln!();
    eprintln!("ARGUMENTS:");
    eprintln!("  <pattern>   Command pattern to approve (e.g., 'npm install:*', 'git:*')");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("  -s, --scope <scope>   Target scope: user, project, or local (required)");
    eprintln!("  -t, --type <type>     Rule type: allow (default), ask, or deny");
    eprintln!("  -n, --dry-run         Preview changes without writing");
    eprintln!();
    eprintln!("EXAMPLES:");
    eprintln!("  tool-gates approve 'npm install:*' -s local");
    eprintln!("  tool-gates approve 'biome:*' -s user");
    eprintln!("  tool-gates approve 'rm -rf*' -s user -t deny");
    eprintln!("  tool-gates approve 'cargo:*' -s local --dry-run");
}

// === Rules subcommand ===

fn handle_rules_subcommand(args: &[String]) {
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print_rules_help();
        return;
    }

    let subcommand = &args[0];
    let sub_args = &args[1..];

    match subcommand.as_str() {
        "list" => handle_rules_list(sub_args),
        "remove" => handle_rules_remove(sub_args),
        "ask-audit" => handle_rules_ask_audit(sub_args),
        _ => {
            eprintln!("Unknown rules subcommand: {}", subcommand);
            eprintln!("Run 'tool-gates rules --help' for usage.");
            std::process::exit(1);
        }
    }
}

fn handle_rules_list(args: &[String]) {
    // Parse --scope option
    let scope_str = args
        .iter()
        .position(|a| a == "--scope" || a == "-s")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    let rules = if let Some(scope_str) = scope_str {
        let Some(scope) = Scope::parse(scope_str) else {
            eprintln!(
                "Error: Invalid scope '{}'. Use: user, project, or local",
                scope_str
            );
            std::process::exit(1);
        };
        list_rules(scope)
    } else {
        list_all_rules()
    };

    if rules.is_empty() {
        eprintln!("No permission rules found.");
        return;
    }

    eprintln!("Permission rules:\n");

    // Group by scope
    for scope in [Scope::User, Scope::Project, Scope::Local] {
        let scope_rules: Vec<_> = rules.iter().filter(|r| r.scope == scope).collect();
        if scope_rules.is_empty() {
            continue;
        }

        eprintln!("  {} ({}):", scope.as_str(), scope.path().display());
        for rule in scope_rules {
            let type_indicator = match rule.rule_type {
                RuleType::Allow => "✓",
                RuleType::Ask => "?",
                RuleType::Deny => "✗",
            };
            eprintln!(
                "    {} {} ({})",
                type_indicator,
                rule.pattern,
                rule.rule_type.as_str()
            );
        }
        eprintln!();
    }
}

fn handle_rules_remove(args: &[String]) {
    // Find the pattern (first non-flag argument)
    let pattern = args.iter().find(|a| !a.starts_with('-'));

    let Some(pattern) = pattern else {
        eprintln!("Error: Pattern is required");
        eprintln!("Usage: tool-gates rules remove <pattern> -s <scope>");
        std::process::exit(1);
    };

    // Parse --scope option
    let scope_str = args
        .iter()
        .position(|a| a == "--scope" || a == "-s")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    let Some(scope_str) = scope_str else {
        eprintln!("Error: --scope (-s) is required");
        eprintln!("Usage: tool-gates rules remove <pattern> -s <scope>");
        std::process::exit(1);
    };

    let Some(scope) = Scope::parse(scope_str) else {
        eprintln!(
            "Error: Invalid scope '{}'. Use: user, project, or local",
            scope_str
        );
        std::process::exit(1);
    };

    match remove_rule(scope, pattern) {
        Ok(true) => {
            let formatted = tool_gates::settings_writer::format_pattern(pattern);
            eprintln!("✓ Removed rule: {}", formatted);
        }
        Ok(false) => {
            eprintln!("Rule not found: {}", pattern);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: Failed to remove rule: {}", e);
            std::process::exit(1);
        }
    }
}

fn print_rules_help() {
    eprintln!("tool-gates rules - Manage permission rules in settings.json");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  tool-gates rules list [--scope <scope>]");
    eprintln!("  tool-gates rules remove <pattern> -s <scope>");
    eprintln!("  tool-gates rules ask-audit [--apply]");
    eprintln!();
    eprintln!("COMMANDS:");
    eprintln!("  list        List all permission rules");
    eprintln!("  remove      Remove a permission rule");
    eprintln!("  ask-audit   List `permissions.ask` Bash rules that suppress the");
    eprintln!("              \"Yes, and don't ask again for X\" prompt button");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("  -s, --scope <scope>   Filter by scope: user, project, or local");
    eprintln!(
        "  --apply               (ask-audit only) Walk gate-covered rules with [y/N] per rule"
    );
}

fn handle_rules_ask_audit(args: &[String]) {
    let apply = args.iter().any(|a| a == "--apply");

    let ask_rules: Vec<_> = list_all_rules()
        .into_iter()
        .filter(|r| r.rule_type == RuleType::Ask && r.pattern.starts_with("Bash("))
        .collect();

    if ask_rules.is_empty() {
        eprintln!("No `permissions.ask` Bash rules found.");
        eprintln!();
        eprintln!("tool-gates' gate engine asks for unfamiliar commands without needing rules in");
        eprintln!(
            "settings.json. The three-button prompt (Yes / Yes-and-don't-ask-again / No) appears"
        );
        eprintln!("for those commands automatically.");
        return;
    }

    let mut gate_covered: Vec<&_> = Vec::new();
    let mut safety_floor: Vec<&_> = Vec::new();
    let mut indeterminate: Vec<&_> = Vec::new();
    for rule in &ask_rules {
        match classify_ask_rule(&rule.pattern) {
            AskRuleCategory::GateCovered => gate_covered.push(rule),
            AskRuleCategory::SafetyFloor => safety_floor.push(rule),
            AskRuleCategory::Indeterminate => indeterminate.push(rule),
        }
    }

    if apply {
        run_ask_audit_apply(&gate_covered);
        return;
    }

    eprintln!(
        "Found {} `permissions.ask` Bash rule(s). Each one trades the third prompt button for a forced 2-button confirmation.",
        ask_rules.len()
    );
    eprintln!();
    eprintln!(
        "Categories below classify each rule by what tool-gates would do without it. Use them as a"
    );
    eprintln!(
        "starting point for review, not a removal recommendation -- many gate-covered rules are"
    );
    eprintln!(
        "kept deliberately as a slip-click safety floor (no chance of an accidental \"Yes, and don't"
    );
    eprintln!("ask again\" creating a persistent allow rule).");

    if !gate_covered.is_empty() {
        eprintln!();
        eprintln!(
            "Gate-covered ({}): tool-gates would still ask (or deny) for these commands without",
            gate_covered.len()
        );
        eprintln!(
            "the rule. Remove if you want the three-button prompt; keep if you'd rather force the"
        );
        eprintln!("2-button confirmation as a slip-click guard.");
        for rule in &gate_covered {
            eprintln!("  {} ({} scope)", rule.pattern, rule.scope.as_str());
            eprintln!(
                "    remove: tool-gates rules remove '{}' -s {}",
                rule.pattern,
                rule.scope.as_str()
            );
        }
    }

    if !safety_floor.is_empty() {
        eprintln!();
        eprintln!(
            "Safety floor ({}): tool-gates' gate engine would auto-allow these commands.",
            safety_floor.len()
        );
        eprintln!("Keep these rules if you want to be prompted for the command anyway.");
        eprintln!("Removing them gives auto-allow with no prompt -- not the three-button prompt.");
        for rule in &safety_floor {
            eprintln!("  {} ({} scope)", rule.pattern, rule.scope.as_str());
            eprintln!(
                "    remove: tool-gates rules remove '{}' -s {}",
                rule.pattern,
                rule.scope.as_str()
            );
        }
    }

    if !indeterminate.is_empty() {
        eprintln!();
        eprintln!(
            "Indeterminate ({}): pattern shape is too generic to classify automatically.",
            indeterminate.len()
        );
        eprintln!("Inspect each one manually to decide whether to keep it.");
        for rule in &indeterminate {
            eprintln!("  {} ({} scope)", rule.pattern, rule.scope.as_str());
            eprintln!(
                "    remove: tool-gates rules remove '{}' -s {}",
                rule.pattern,
                rule.scope.as_str()
            );
        }
    }

    if !gate_covered.is_empty() {
        eprintln!();
        eprintln!(
            "Tip: `tool-gates rules ask-audit --apply` walks the gate-covered rules one at a time"
        );
        eprintln!(
            "with [y/N] per rule, defaulting to keep. Editing settings.json directly is also fine."
        );
    }
}

fn run_ask_audit_apply(gate_covered: &[&tool_gates::settings_writer::PermissionRule]) {
    if gate_covered.is_empty() {
        eprintln!("No gate-covered rules to review.");
        return;
    }

    eprintln!(
        "Walking {} gate-covered rule(s). For each one, type 'y' to remove, anything else to keep.",
        gate_covered.len()
    );
    eprintln!(
        "Default is keep. Removed rules trade the 2-button confirmation for a three-button prompt"
    );
    eprintln!("(adds a one-click \"Yes, and don't ask again for X\" option per project).");
    eprintln!();

    let mut removed = 0usize;
    let mut kept = 0usize;
    let mut errors: Vec<String> = Vec::new();

    for rule in gate_covered {
        eprint!(
            "  {} ({} scope) -- remove? [y/N] ",
            rule.pattern,
            rule.scope.as_str()
        );
        use std::io::Write;
        let _ = std::io::stderr().flush();
        let mut answer = String::new();
        if std::io::stdin().read_line(&mut answer).is_err() {
            eprintln!("\nFailed to read input. Aborting.");
            std::process::exit(1);
        }
        let trimmed = answer.trim().to_lowercase();
        if trimmed != "y" && trimmed != "yes" {
            kept += 1;
            continue;
        }

        match remove_rule(rule.scope, &rule.pattern) {
            Ok(true) => {
                eprintln!("    removed.");
                removed += 1;
            }
            Ok(false) => {
                eprintln!("    not present (maybe already removed).");
            }
            Err(e) => {
                let msg = format!(
                    "    error removing {} ({} scope): {}",
                    rule.pattern,
                    rule.scope.as_str(),
                    e
                );
                eprintln!("{}", msg);
                errors.push(msg);
            }
        }
    }
    eprintln!();
    eprintln!(
        "Removed {}/{} rule(s); kept {}.",
        removed,
        gate_covered.len(),
        kept
    );
    if !errors.is_empty() {
        std::process::exit(1);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AskRuleCategory {
    /// Gate engine would ask (or deny) for this command without the rule.
    /// The rule is technically redundant from a "would I be prompted?"
    /// perspective, but may still be intentional: it forces a 2-button
    /// prompt, which prevents an accidental "Yes, and don't ask again"
    /// click from creating a persistent allow rule.
    GateCovered,
    /// Gate engine would auto-allow without the rule. Removing the rule
    /// drops the prompt entirely; keeping it is a deliberate "always
    /// prompt me" floor.
    SafetyFloor,
    /// Pattern shape can't be round-tripped into a representative command
    /// (internal globs, etc.). Inspect manually.
    Indeterminate,
}

fn classify_ask_rule(pattern: &str) -> AskRuleCategory {
    let Some(inner) = pattern
        .strip_prefix("Bash(")
        .and_then(|s| s.strip_suffix(')'))
    else {
        return AskRuleCategory::Indeterminate;
    };

    // Word-boundary prefix: `<command>:*` matches `<command>` and
    // `<command> <anything>`. The literal prefix is the representative.
    let candidate = if let Some(prefix) = inner.strip_suffix(":*") {
        prefix.trim().to_string()
    } else if let Some(prefix) = inner.strip_suffix(" *") {
        // Glob prefix with explicit space-star: `<prefix> *` matches
        // `<prefix> ...`. Strip the trailing star and let the prefix
        // stand in.
        prefix.trim().to_string()
    } else if inner.contains('*') {
        // Internal glob (e.g., `echo > /etc/ *`). Round-tripping these
        // accurately is brittle -- bail out.
        return AskRuleCategory::Indeterminate;
    } else {
        // Exact pattern: use it verbatim.
        inner.trim().to_string()
    };

    if candidate.is_empty() {
        return AskRuleCategory::Indeterminate;
    }

    // Use the full security pipeline (raw-string deny/ask + gate engine)
    // so destructive shapes like `find . -delete` are recognized via the
    // raw-string layer. Empty session_id keeps hint dedup state out of
    // the audit. Settings are NOT consulted: we want to know what
    // tool-gates would do *without* the rule we're classifying.
    let result = tool_gates::router::check_command_for_session(&candidate, "");

    match result.decision {
        // Deny: removing the ask rule still blocks the command. The
        // ask rule is strictly weaker than tool-gates' floor; safe to
        // delete (post-removal posture is *stricter*, not weaker).
        PermissionDecision::Deny => AskRuleCategory::GateCovered,
        PermissionDecision::Ask => AskRuleCategory::GateCovered,
        PermissionDecision::Allow => AskRuleCategory::SafetyFloor,
        // Defer / Approve / other shapes shouldn't show up from
        // check_command_for_session (no settings, no defer wrapping).
        // Treat as indeterminate to be safe.
        _ => AskRuleCategory::Indeterminate,
    }
}

// === Pending subcommand ===

fn handle_pending_subcommand(args: &[String]) {
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print_pending_help();
        return;
    }

    let subcommand = &args[0];
    let sub_args = &args[1..];

    match subcommand.as_str() {
        "list" => handle_pending_list(sub_args),
        "clear" => handle_pending_clear(sub_args),
        _ => {
            eprintln!("Unknown pending subcommand: {}", subcommand);
            eprintln!("Run 'tool-gates pending --help' for usage.");
            std::process::exit(1);
        }
    }
}

fn handle_pending_list(args: &[String]) {
    let is_project = args.iter().any(|a| a == "--project" || a == "-p");
    let is_json = args.iter().any(|a| a == "--json");

    let cwd = std::env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(String::from));

    // Filter by project if --project flag is set
    let filter = if is_project { cwd.as_deref() } else { None };
    let all_entries = read_pending(filter);

    if is_json {
        // Machine-readable JSON output to stdout
        let json_entries: Vec<serde_json::Value> = all_entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "command": e.command,
                    "patterns": e.patterns,
                    "breakdown": e.breakdown.iter().map(|b| {
                        let mut obj = serde_json::json!({
                            "program": b.program,
                            "decision": b.decision,
                        });
                        if b.decision != "allow" {
                            obj["reason"] = serde_json::json!(b.reason);
                        }
                        if !b.args.is_empty() {
                            obj["args"] = serde_json::json!(b.args);
                        }
                        obj
                    }).collect::<Vec<_>>(),
                    "count": e.count,
                    "project": e.project_id,
                    "cwd": e.cwd,
                    "last_seen": e.last_seen.to_rfc3339(),
                })
            })
            .collect();
        match serde_json::to_string_pretty(&json_entries) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("Error serializing pending entries: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    if all_entries.is_empty() {
        eprintln!("No pending approvals.");
        return;
    }

    eprintln!("Pending approvals ({}):\n", all_entries.len());

    for entry in &all_entries {
        // Show abbreviated project_id (extract last segment)
        let project = entry
            .project_id
            .rsplit('-')
            .find(|s| !s.is_empty())
            .unwrap_or(&entry.project_id);

        eprintln!(
            "  [{}] {} (seen {} time{})",
            project,
            entry.command,
            entry.count,
            if entry.count == 1 { "" } else { "s" }
        );

        // Show per-subcommand breakdown for compound commands
        if entry.breakdown.len() > 1 {
            let parts: Vec<String> = entry
                .breakdown
                .iter()
                .map(|b| {
                    if b.decision == "allow" {
                        format!("{} (allow)", b.program)
                    } else {
                        format!("{} ({})", b.program, b.decision)
                    }
                })
                .collect();
            eprintln!("    Breakdown: {}", parts.join(" | "));
        }

        if !entry.patterns.is_empty() {
            eprintln!("    Suggested patterns:");
            for pattern in &entry.patterns {
                eprintln!("      - {}", pattern);
            }
        }

        // Format time
        let duration = chrono::Utc::now() - entry.last_seen;
        let time_str = if duration.num_days() > 0 {
            format!("{} days ago", duration.num_days())
        } else if duration.num_hours() > 0 {
            format!("{} hours ago", duration.num_hours())
        } else if duration.num_minutes() > 0 {
            format!("{} min ago", duration.num_minutes())
        } else {
            "just now".to_string()
        };
        eprintln!("    Last seen: {}", time_str);
        eprintln!();
    }

    eprintln!("To approve a pattern: tool-gates approve '<pattern>' -s <scope>");
    eprintln!("To review interactively: tool-gates review");
}

fn handle_pending_clear(args: &[String]) {
    let is_project = args.iter().any(|a| a == "--project" || a == "-p");
    let is_all = args.iter().any(|a| a == "--all" || a == "-a");
    let is_force = args.iter().any(|a| a == "--force" || a == "-f");

    let cwd = std::env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(String::from));

    if !is_project && !is_all {
        eprintln!("Error: Specify --project or --all");
        eprintln!("Usage: tool-gates pending clear [--project | --all] --force");
        std::process::exit(1);
    }

    // Count entries to be cleared
    let filter = if is_project { cwd.as_deref() } else { None };
    let total_count = pending_count(filter);

    if total_count == 0 {
        eprintln!("No pending approvals to clear.");
        return;
    }

    // Require --force for destructive action
    if !is_force {
        eprintln!(
            "This will permanently delete {} pending approval(s).",
            total_count
        );
        eprintln!("Add --force (-f) to confirm.");
        std::process::exit(1);
    }

    match clear_pending(filter) {
        Ok(count) => {
            let scope = if is_project { "project" } else { "all" };
            eprintln!("✓ Cleared: {} {}", count, scope);
        }
        Err(e) => {
            eprintln!("Error clearing pending: {}", e);
        }
    }
}

fn print_pending_help() {
    eprintln!("tool-gates pending - Manage pending approval queue");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  tool-gates pending list [--project]");
    eprintln!("  tool-gates pending clear [--project | --all] --force");
    eprintln!();
    eprintln!("COMMANDS:");
    eprintln!("  list    List pending approvals");
    eprintln!("  clear   Clear pending approval queue (requires --force)");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("  -p, --project   Filter to current project only");
    eprintln!("  -a, --all       Clear all pending approvals");
    eprintln!("  -f, --force     Confirm destructive clear operation");
}

// === Review subcommand ===

fn handle_review_subcommand(show_all: bool) {
    if let Err(e) = run_review(show_all) {
        eprintln!("Error running review TUI: {}", e);
        std::process::exit(1);
    }
}

// === Doctor subcommand ===

fn handle_doctor_subcommand() {
    let mut issues: Vec<String> = Vec::new();
    let mut ok_count = 0;

    eprintln!("tool-gates doctor\n");

    // 1. Version
    eprintln!("  Version: {}", env!("GIT_VERSION"));

    // 2. Config file
    let config_path = dirs::home_dir()
        .map(|h| h.join(".config/tool-gates/config.toml"))
        .unwrap_or_default();
    if config_path.exists() {
        match std::fs::read_to_string(&config_path) {
            Ok(content) => match toml::from_str::<config::Config>(&content) {
                Ok(cfg) => {
                    eprintln!("  ✓ Config: {} (valid)", config_path.display());
                    // Show feature status
                    let features = &cfg.features;
                    let enabled: Vec<&str> = [
                        ("bash_gates", features.bash_gates),
                        ("file_guards", features.file_guards),
                        ("hints", features.hints),
                        ("security_reminders", features.security_reminders),
                        ("head_tail_pipe_block", features.head_tail_pipe_block),
                    ]
                    .iter()
                    .filter(|(_, v)| *v)
                    .map(|(k, _)| *k)
                    .collect();
                    let disabled: Vec<&str> = [
                        ("bash_gates", features.bash_gates),
                        ("file_guards", features.file_guards),
                        ("hints", features.hints),
                        ("security_reminders", features.security_reminders),
                        ("head_tail_pipe_block", features.head_tail_pipe_block),
                    ]
                    .iter()
                    .filter(|(_, v)| !*v)
                    .map(|(k, _)| *k)
                    .collect();
                    if !disabled.is_empty() {
                        eprintln!("    Features disabled: {}", disabled.join(", "));
                    } else {
                        eprintln!("    All features enabled");
                    }
                    let _ = enabled; // suppress unused warning
                    if !cfg.auto_approve_skills.is_empty() {
                        eprintln!(
                            "    Skill auto-approve rules: {}",
                            cfg.auto_approve_skills.len()
                        );
                    }
                    if !cfg.security_reminders.disable_rules.is_empty() {
                        eprintln!(
                            "    Disabled security rules: {}",
                            cfg.security_reminders.disable_rules.join(", ")
                        );
                    }
                    ok_count += 1;
                }
                Err(e) => {
                    let msg = format!("Config parse error: {e}");
                    eprintln!("  ✗ Config: {} ({})", config_path.display(), msg);
                    issues.push(msg);
                }
            },
            Err(e) => {
                let msg = format!("Config read error: {e}");
                eprintln!("  ✗ Config: {}", msg);
                issues.push(msg);
            }
        }
    } else {
        eprintln!(
            "  - Config: {} (not found, using defaults)",
            config_path.display()
        );
        ok_count += 1;
    }

    // 3. Hook installation status across all scopes
    eprintln!();
    let scopes = [
        ("user", get_settings_path("user")),
        ("project", get_settings_path("project")),
        ("local", get_settings_path("local")),
    ];

    let mut any_installed = false;
    for (scope, path) in &scopes {
        if !path.exists() {
            continue;
        }
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let settings: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => {
                let msg = format!("Settings parse error: {}", path.display());
                eprintln!("  ✗ Hooks ({}): parse error", scope);
                issues.push(msg);
                continue;
            }
        };
        let hooks = match settings.get("hooks") {
            Some(h) => h,
            None => continue,
        };

        let has_pre = hooks
            .get("PreToolUse")
            .map(has_tool_gates_hook)
            .unwrap_or(false);
        let has_perm = hooks
            .get("PermissionRequest")
            .map(has_tool_gates_hook)
            .unwrap_or(false);
        let has_perm_denied = hooks
            .get("PermissionDenied")
            .map(has_tool_gates_hook)
            .unwrap_or(false);
        let has_post = hooks
            .get("PostToolUse")
            .map(has_tool_gates_hook)
            .unwrap_or(false);

        let count = [has_pre, has_perm, has_perm_denied, has_post]
            .iter()
            .filter(|&&x| x)
            .count();
        if count == 0 {
            continue;
        }

        any_installed = true;
        if count == 4 {
            eprintln!("  ✓ Hooks ({}): all 4 installed", scope);
            ok_count += 1;
        } else {
            let mut missing = Vec::new();
            if !has_pre {
                missing.push("PreToolUse");
            }
            if !has_perm {
                missing.push("PermissionRequest");
            }
            if !has_perm_denied {
                missing.push("PermissionDenied");
            }
            if !has_post {
                missing.push("PostToolUse");
            }
            let msg = format!("Missing hooks in {}: {}", scope, missing.join(", "));
            eprintln!(
                "  ⚠ Hooks ({}): {}/4 (missing {})",
                scope,
                count,
                missing.join(", ")
            );
            issues.push(msg);
        }

        // Check for stale external hooks (old Python scripts)
        if let Some(hook_entries) = hooks.as_object() {
            for (_event, matchers) in hook_entries {
                if let Some(arr) = matchers.as_array() {
                    for entry in arr {
                        if let Some(inner_hooks) = entry.get("hooks").and_then(|h| h.as_array()) {
                            for hook in inner_hooks {
                                if let Some(cmd) = hook.get("command").and_then(|c| c.as_str()) {
                                    if cmd.contains(".py") || cmd.contains("uvx") {
                                        let msg = format!(
                                            "Legacy Python hook in {}: {}",
                                            scope,
                                            cmd.chars().take(80).collect::<String>()
                                        );
                                        eprintln!("  ⚠ {}", msg);
                                        issues.push(msg);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if !any_installed {
        let msg = "No tool-gates hooks installed in any settings file".to_string();
        eprintln!("  ✗ Hooks: not installed");
        eprintln!("    Run: tool-gates hooks add -s user");
        issues.push(msg);
    }

    // 4. Cache files
    eprintln!();
    let cache_dir = tool_gates::cache::cache_dir();
    let cache_files = [
        ("available-tools.json", "Tool detection cache"),
        ("hint-tracker.json", "Hint dedup tracker"),
        ("pending.jsonl", "Pending approvals"),
        ("tracking.json", "Ask tracking (PreToolUse->PostToolUse)"),
    ];

    for (file, desc) in &cache_files {
        let path = cache_dir.join(file);
        if path.exists() {
            if let Ok(meta) = std::fs::metadata(&path) {
                let size = meta.len();
                let age = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .map(|d| {
                        if d.as_secs() > 86400 {
                            format!("{}d old", d.as_secs() / 86400)
                        } else if d.as_secs() > 3600 {
                            format!("{}h old", d.as_secs() / 3600)
                        } else {
                            "recent".to_string()
                        }
                    })
                    .unwrap_or_else(|| "unknown age".to_string());
                eprintln!("  ✓ {}: {} ({}, {})", desc, file, humanize_bytes(size), age);
                ok_count += 1;
            }
        } else {
            eprintln!("  - {}: not yet created", desc);
        }
    }

    // 5. Usage stats: pending queue, tracking, top-asked commands
    eprintln!();
    let pending = tool_gates::pending::read_pending(None);
    let tracking = tool_gates::tracking::TrackingStore::with_shared_lock(|s| {
        s.entries
            .values()
            .map(|e| (e.command.clone(), e.session_id.clone()))
            .collect::<Vec<_>>()
    })
    .unwrap_or_default();

    eprintln!(
        "  Stats: {} pending entry(ies), {} tracked command(s) in flight",
        pending.len(),
        tracking.len()
    );

    if !pending.is_empty() {
        let mut by_project: std::collections::HashMap<String, (usize, u32)> =
            std::collections::HashMap::new();
        for entry in &pending {
            let key = if entry.cwd.is_empty() {
                entry.project_id.clone()
            } else {
                entry.cwd.clone()
            };
            let slot = by_project.entry(key).or_insert((0, 0));
            slot.0 += 1;
            slot.1 += entry.count;
        }
        let mut rows: Vec<_> = by_project.into_iter().collect();
        rows.sort_by(|a, b| b.1.0.cmp(&a.1.0).then_with(|| a.0.cmp(&b.0)));
        for (project, (n_entries, total_count)) in rows.iter().take(5) {
            eprintln!(
                "    {}: {} entry(ies), {} total approvals",
                project, n_entries, total_count
            );
        }

        // Top-N most-asked commands across all projects.
        let mut top: Vec<_> = pending
            .iter()
            .map(|e| (e.count, e.command.as_str()))
            .collect();
        top.sort_by_key(|(count, _)| std::cmp::Reverse(*count));
        let preview = top.iter().take(5).collect::<Vec<_>>();
        if !preview.is_empty() {
            eprintln!("    Top-asked:");
            for (count, cmd) in preview {
                let shown: String = cmd.chars().take(60).collect();
                let suffix = if cmd.chars().count() > 60 { "..." } else { "" };
                eprintln!("      {}x {}{}", count, shown, suffix);
            }
        }
    }

    if !tracking.is_empty() {
        let session_count: std::collections::HashSet<&str> =
            tracking.iter().map(|(_, s)| s.as_str()).collect();
        if session_count.len() > 1 {
            eprintln!(
                "    {} session(s) with tracked entries (concurrent sessions share tracking.json; the 24h TTL clears orphans)",
                session_count.len()
            );
        }
    }

    // 6. `permissions.ask` Bash rules suppress the third "Yes, and don't
    // ask again for X" prompt button (CC's resolver returns ask without
    // populating the suggestion list whenever a settings ask rule matches,
    // and the prompt UI shows the third button only when suggestions are
    // non-empty). Surface a quick summary; deep details are in
    // `tool-gates rules ask-audit`.
    let ask_rules: Vec<_> = list_all_rules()
        .into_iter()
        .filter(|r| r.rule_type == RuleType::Ask && r.pattern.starts_with("Bash("))
        .collect();
    if !ask_rules.is_empty() {
        let mut gate_covered = 0usize;
        let mut safety_floor = 0usize;
        let mut indeterminate = 0usize;
        for rule in &ask_rules {
            match classify_ask_rule(&rule.pattern) {
                AskRuleCategory::GateCovered => gate_covered += 1,
                AskRuleCategory::SafetyFloor => safety_floor += 1,
                AskRuleCategory::Indeterminate => indeterminate += 1,
            }
        }
        eprintln!();
        eprintln!(
            "  Note: {} `permissions.ask` Bash rule(s) suppress the third \"Yes, and don't ask again for X\" prompt button.",
            ask_rules.len()
        );
        eprintln!(
            "    {} gate-covered (gate would also ask), {} safety floor (gate would auto-allow), {} indeterminate.",
            gate_covered, safety_floor, indeterminate
        );
        eprintln!(
            "    Run `tool-gates rules ask-audit` for the per-rule breakdown and remove commands."
        );
    }

    // 7. Old bash-gates remnants
    let old_cache = dirs::home_dir()
        .map(|h| h.join(".cache/bash-gates"))
        .unwrap_or_default();
    if old_cache.exists() {
        let msg =
            "Old ~/.cache/bash-gates/ directory still exists. Run: rm -rf ~/.cache/bash-gates/"
                .to_string();
        eprintln!("\n  ⚠ {}", msg);
        issues.push(msg);
    }

    // Summary
    eprintln!();
    if issues.is_empty() {
        eprintln!("All {} checks passed.", ok_count);
    } else {
        eprintln!("{} checks passed, {} issue(s):", ok_count, issues.len());
        for issue in &issues {
            eprintln!("  - {}", issue);
        }
    }

    if !issues.is_empty() {
        std::process::exit(1);
    }
}

fn humanize_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

/// Print empty JSON to signal no opinion (pass through to normal flow).
fn print_no_opinion_for(client: Client) {
    let output = HookOutput::no_opinion();
    if let Ok(json) = serde_json::to_string(&output.serialize(client)) {
        println!("{json}");
    } else {
        println!("{{}}");
    }
}

/// Print a deny/block result in the correct client format and exit with code 2 for Gemini.
fn print_deny_and_exit(client: Client, reason: &str) {
    let output = HookOutput::deny(reason);
    let json_value = output.serialize(client);
    if let Ok(json) = serde_json::to_string(&json_value) {
        println!("{json}");
    } else {
        eprintln!("Error: failed to serialize deny output");
    }
    if client == Client::Gemini {
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tool_gates::check_command;

    #[test]
    fn test_hook_input_parsing() {
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "git status"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.get_command(), "git status");
    }

    #[test]
    fn test_hook_input_with_map() {
        let json =
            r#"{"tool_name": "Bash", "tool_input": {"command": "npm install", "timeout": 120}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.get_command(), "npm install");
    }

    #[test]
    fn test_check_command_git_status() {
        let output = check_command("git status");
        assert_eq!(output.decision, PermissionDecision::Allow);
    }

    #[test]
    fn test_check_command_npm_install() {
        let output = check_command("npm install");
        assert_eq!(output.decision, PermissionDecision::Ask);
    }

    #[test]
    fn test_check_command_rm_rf_root() {
        let output = check_command("rm -rf /");
        assert_eq!(output.decision, PermissionDecision::Deny);
    }

    #[test]
    fn test_output_claude_wire_format() {
        let output = check_command("git status");
        let json = serde_json::to_string(&output.serialize(Client::Claude)).unwrap();
        assert!(
            json.contains("PreToolUse"),
            "Expected PreToolUse in: {json}"
        );
        assert!(
            json.contains("hookSpecificOutput"),
            "Expected hookSpecificOutput in: {json}"
        );
    }

    // === Integration tests: JSON input -> decision flow ===

    /// Simulate the full hook flow: JSON input -> parse -> check -> Claude JSON output
    fn simulate_hook(json_input: &str) -> String {
        let input: HookInput = serde_json::from_str(json_input).unwrap();
        let command = input.get_command();
        let output = check_command(&command);
        serde_json::to_string(&output.serialize(Client::Claude)).unwrap()
    }

    #[test]
    fn test_integration_safe_command_chain() {
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "git status && git log --oneline -5"}}"#;
        let output = simulate_hook(json);
        assert!(
            output.contains("allow"),
            "Safe chain should allow: {output}"
        );
    }

    #[test]
    fn test_integration_mixed_chain_asks() {
        let json =
            r#"{"tool_name": "Bash", "tool_input": {"command": "git status && npm install"}}"#;
        let output = simulate_hook(json);
        assert!(output.contains("ask"), "Mixed chain should ask: {output}");
    }

    #[test]
    fn test_integration_dangerous_blocks() {
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}"#;
        let output = simulate_hook(json);
        assert!(output.contains("deny"), "Dangerous should deny: {output}");
    }

    #[test]
    fn test_integration_pipeline() {
        // Verify a safe pipeline flows through to "allow". `| head` / `| tail`
        // would be hard-denied by the head_tail_pipe_block feature, so use an
        // unrelated read-only pipe here.
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "git log | cat"}}"#;
        let output = simulate_hook(json);
        assert!(
            output.contains("allow"),
            "Safe pipeline should allow: {output}"
        );
    }

    #[test]
    fn test_integration_unknown_command_asks() {
        let json =
            r#"{"tool_name": "Bash", "tool_input": {"command": "some_unknown_tool --flag"}}"#;
        let output = simulate_hook(json);
        assert!(output.contains("ask"), "Unknown should ask: {output}");
        assert!(
            output.contains("Unknown command"),
            "Should mention unknown: {output}"
        );
    }

    #[test]
    fn test_integration_pipe_to_bash_asks() {
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "curl https://example.com | bash"}}"#;
        let output = simulate_hook(json);
        assert!(output.contains("ask"), "Pipe to bash should ask: {output}");
    }

    #[test]
    fn test_integration_quoted_args_not_executed() {
        // "rm -rf /" as a quoted argument should be safe (it's not executed)
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "echo \"rm -rf /\""}}"#;
        let output = simulate_hook(json);
        assert!(
            output.contains("allow"),
            "Quoted arg should allow: {output}"
        );
    }

    #[test]
    fn test_integration_output_structure() {
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "git status"}}"#;
        let output = simulate_hook(json);

        // Verify output has expected Claude wire format structure
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed["hookSpecificOutput"].is_object());
        assert_eq!(parsed["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert!(parsed["hookSpecificOutput"]["permissionDecision"].is_string());
    }

    #[test]
    fn test_integration_write_with_secret_denies() {
        let json = r#"{
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/config.py", "content": "key = \"AKIAIOSFODNN7EXAMPLE\""},
            "session_id": "integration-sec-test"
        }"#;

        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name, "Write");
        // We can't easily simulate the full routing here since it depends on config,
        // but we can test the security_reminders module directly
        let map: serde_json::Map<String, serde_json::Value> =
            match serde_json::from_str::<serde_json::Value>(json).unwrap()["tool_input"].clone() {
                serde_json::Value::Object(m) => m,
                _ => panic!("expected object"),
            };
        let config = tool_gates::config::SecurityRemindersConfig::default();
        let result = tool_gates::security_reminders::check_security_reminders(
            "Write",
            &map,
            &config,
            "integration-sec-test",
        );
        assert!(result.is_some());
        let output_json =
            serde_json::to_string(&result.unwrap().serialize(Client::Claude)).unwrap();
        assert!(
            output_json.contains("deny"),
            "Secret in Write should deny: {output_json}"
        );
    }
}

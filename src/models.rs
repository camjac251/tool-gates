//! Core types for the tool gates permission system.
//!
//! Supports two hook types:
//! - `PreToolUse`: Runs before tool execution, can allow/deny/ask
//! - `PermissionRequest`: Runs when internal checks want to ask, can approve for subagents

use serde::{Deserialize, Serialize};

/// Sanitize a path to match Claude Code's project ID format.
/// Replaces non-alphanumeric characters with `-`.
fn sanitize_path(path: &str) -> String {
    path.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect()
}

/// True if Claude Code's `permission_mode` signals auto mode. Normalizes
/// whitespace and ASCII case so minor contract drift (` auto `, `Auto`,
/// `AUTO`) still takes the safety-floor path rather than silently
/// falling back to ask. Exact-match failure on a safety-floor gate is
/// worst-case behavior for a defensive layer.
pub fn is_auto_mode(mode: &str) -> bool {
    mode.trim().eq_ignore_ascii_case("auto")
}

/// True if Claude Code's `permission_mode` signals plan mode. Plan mode is
/// "read-and-explore only" -- the model can investigate but should not edit
/// or execute mutating commands. Same case-insensitive normalization as
/// `is_auto_mode` since mode strings are CC-supplied and we want to fail
/// safe on minor drift.
pub fn is_plan_mode(mode: &str) -> bool {
    mode.trim().eq_ignore_ascii_case("plan")
}

/// Permission decision types with priority: Block > Ask > Allow > Skip
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Decision {
    Skip = 0,  // Gate doesn't handle this command
    Allow = 1, // Explicitly allowed
    Ask = 2,   // Requires user approval
    Block = 3, // Blocked
}

impl Decision {
    /// Returns the stricter of two decisions (used in tests)
    #[cfg(test)]
    pub fn stricter(self, other: Decision) -> Decision {
        if self > other { self } else { other }
    }
}

/// Information about a parsed command
#[derive(Debug, Clone, Default)]
pub struct CommandInfo {
    /// Original command string
    pub raw: String,
    /// The executable (gh, aws, kubectl, etc.)
    pub program: String,
    /// Arguments after the program
    pub args: Vec<String>,
}

/// Result from a permission gate check
#[derive(Debug, Clone)]
pub struct GateResult {
    pub decision: Decision,
    pub reason: Option<String>,
}

impl GateResult {
    /// Gate doesn't handle this command - pass through
    pub fn skip() -> Self {
        Self {
            decision: Decision::Skip,
            reason: None,
        }
    }

    pub fn allow() -> Self {
        Self {
            decision: Decision::Allow,
            reason: None,
        }
    }

    pub fn allow_with_reason(reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Allow,
            reason: Some(reason.into()),
        }
    }

    pub fn ask(reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Ask,
            reason: Some(reason.into()),
        }
    }

    pub fn block(reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Block,
            reason: Some(reason.into()),
        }
    }
}

// === Client Detection ===

/// Which AI coding tool is calling us
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Client {
    Claude,
    Gemini,
}

impl Client {
    /// Detect client from hook_event_name
    pub fn from_hook_event(event: &str) -> Self {
        match event {
            "BeforeTool" | "AfterTool" => Client::Gemini,
            _ => Client::Claude,
        }
    }

    /// The tool name used for shell commands
    pub fn shell_tool_name(self) -> &'static str {
        match self {
            Client::Claude => "Bash",
            Client::Gemini => "run_shell_command",
        }
    }

    /// Check if a tool_name represents a shell command tool
    pub fn is_shell_tool(tool_name: &str) -> bool {
        tool_name == "Bash" || tool_name == "Monitor" || tool_name == "run_shell_command"
    }

    /// Check if a tool_name represents a file operation tool (read, write, edit)
    pub fn is_file_tool(tool_name: &str) -> bool {
        matches!(
            tool_name,
            "Read" | "Write" | "Edit" | "read_file" | "read_many_files" | "write_file" | "replace"
        )
    }

    /// Check if a tool_name is a read-only file tool
    pub fn is_read_tool(tool_name: &str) -> bool {
        matches!(tool_name, "Read" | "read_file" | "read_many_files")
    }

    /// Check if a tool_name is a write/edit file tool
    pub fn is_write_tool(tool_name: &str) -> bool {
        matches!(tool_name, "Write" | "Edit" | "write_file" | "replace")
    }

    /// Check if a tool_name represents a skill/extension tool
    pub fn is_skill_tool(tool_name: &str) -> bool {
        tool_name == "Skill" || tool_name == "activate_skill"
    }

    /// Check if a tool_name is a glob/search tool
    pub fn is_glob_tool(tool_name: &str) -> bool {
        tool_name == "Glob" || tool_name == "glob"
    }

    /// Check if a tool_name is a grep/search tool
    pub fn is_grep_tool(tool_name: &str) -> bool {
        tool_name == "Grep" || tool_name == "grep_search"
    }

    /// Check if a tool_name is an MCP tool (either prefix format)
    pub fn is_mcp_tool(tool_name: &str) -> bool {
        tool_name.starts_with("mcp__") || tool_name.starts_with("mcp_")
    }
}

// === Hook Input/Output Types ===

/// Tool input from Claude Code / Gemini CLI
#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)]
pub struct ToolInput {
    #[serde(default)]
    pub command: String,
    pub description: Option<String>,
    pub timeout: Option<u32>,
    /// File path for Read/Write/Edit tools
    #[serde(default)]
    pub file_path: Option<String>,
}

/// Input received by `PreToolUse` hook
#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)]
pub struct HookInput {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub transcript_path: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: String,
    #[serde(default)]
    pub hook_event_name: String,
    #[serde(default)]
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: ToolInputVariant,
    #[serde(default)]
    pub tool_use_id: String,
}

/// Tool input can be either structured or a raw map
#[derive(Debug, Deserialize, Default)]
#[serde(untagged)]
pub enum ToolInputVariant {
    Structured(ToolInput),
    Map(serde_json::Map<String, serde_json::Value>),
    #[default]
    Empty,
}

impl HookInput {
    /// Extract command string from `tool_input`
    pub fn get_command(&self) -> String {
        match &self.tool_input {
            ToolInputVariant::Structured(ti) => ti.command.clone(),
            ToolInputVariant::Map(m) => m
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            ToolInputVariant::Empty => String::new(),
        }
    }

    /// Extract file_path from `tool_input` (for Read/Write/Edit tools)
    pub fn get_file_path(&self) -> String {
        match &self.tool_input {
            ToolInputVariant::Structured(ti) => ti.file_path.clone().unwrap_or_default(),
            ToolInputVariant::Map(m) => m
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            ToolInputVariant::Empty => String::new(),
        }
    }

    /// Extract all file paths from `tool_input`.
    ///
    /// Handles single-file tools (Read/Write/Edit with `file_path`).
    pub fn get_file_paths(&self) -> Vec<String> {
        let mut paths = Vec::new();

        // Single file_path (Read/Write/Edit)
        let fp = self.get_file_path();
        if !fp.is_empty() {
            paths.push(fp);
        }

        paths
    }

    /// Extract stable project identifier from `transcript_path`.
    ///
    /// The transcript_path format is:
    /// `~/.claude/projects/<sanitized-project-path>/<session>.jsonl`
    ///
    /// Returns the sanitized project path (e.g., "-home-user-projects-myapp")
    /// which is stable across the session even if `cwd` changes.
    pub fn project_id(&self) -> String {
        // Parse: ~/.claude/projects/<project-id>/<session>.jsonl
        if let Some(projects_idx) = self.transcript_path.find("/projects/") {
            let after_projects = &self.transcript_path[projects_idx + 10..];
            if let Some(slash_idx) = after_projects.find('/') {
                return after_projects[..slash_idx].to_string();
            }
        }
        // Fallback to sanitized cwd if transcript_path not available
        sanitize_path(&self.cwd)
    }
}

/// Permission decision for a hook response.
/// This is the provider-agnostic decision type used by HookOutput.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionDecision {
    /// No opinion. Pass through to default behavior.
    Approve,
    /// Explicitly allowed by tool-gates.
    Allow,
    /// Explicit ask. Tool-gates wants the prompt to fire and is overriding
    /// CC's normal flow with an "ask" decision.
    Ask,
    /// Tool-gates would have asked but is letting CC's resolver decide.
    /// Serialized as `hookSpecificOutput` with no `permissionDecision` so
    /// CC continues into its normal pipeline (settings rules, then tool's
    /// own checkPermissions). Lets the Bash tool's prefix-suggestion path
    /// fire so the prompt shows the third "Yes, and don't ask again for X"
    /// button. Used only when the gate has no security concern beyond
    /// "this is unfamiliar".
    Defer,
    /// Blocked.
    Deny,
}

impl PermissionDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Allow => "allow",
            Self::Ask => "ask",
            // Defer carries no wire-level permissionDecision; the string
            // form is internal-only and used for log lines.
            Self::Defer => "defer",
            Self::Deny => "deny",
        }
    }
}

/// Provider-agnostic hook output.
/// Serialized differently for Claude Code vs Gemini CLI at output time.
#[derive(Debug, Clone)]
pub struct HookOutput {
    pub decision: PermissionDecision,
    pub reason: Option<String>,
    pub context: Option<String>,
    pub updated_command: Option<String>,
}

impl HookOutput {
    /// No opinion. tool-gates doesn't handle this tool/command.
    /// Returns empty JSON so Claude Code proceeds with its normal flow.
    pub fn no_opinion() -> Self {
        Self {
            decision: PermissionDecision::Approve,
            reason: None,
            context: None,
            updated_command: None,
        }
    }

    /// Return explicit allow (overrides settings.json)
    pub fn allow(reason: Option<&str>) -> Self {
        Self {
            decision: PermissionDecision::Allow,
            reason: reason.map(String::from),
            context: None,
            updated_command: None,
        }
    }

    /// Return explicit allow with additional context for Claude
    pub fn allow_with_context(reason: Option<&str>, context: &str) -> Self {
        Self {
            decision: PermissionDecision::Allow,
            reason: reason.map(String::from),
            context: Some(context.to_string()),
            updated_command: None,
        }
    }

    /// Return ask for user permission
    pub fn ask(reason: &str) -> Self {
        Self {
            decision: PermissionDecision::Ask,
            reason: Some(reason.to_string()),
            context: None,
            updated_command: None,
        }
    }

    /// Return ask with additional context for Claude
    pub fn ask_with_context(reason: &str, context: &str) -> Self {
        Self {
            decision: PermissionDecision::Ask,
            reason: Some(reason.to_string()),
            context: Some(context.to_string()),
            updated_command: None,
        }
    }

    /// Defer to Claude Code's normal resolver. Same context-passing as
    /// `ask_with_context`, but the wire output omits `permissionDecision`
    /// so CC's pipeline runs the tool's own checkPermissions and produces
    /// prefix suggestions for the prompt UI.
    pub fn defer(reason: impl Into<String>, context: Option<String>) -> Self {
        Self {
            decision: PermissionDecision::Defer,
            reason: Some(reason.into()),
            context,
            updated_command: None,
        }
    }

    /// Return ask with a modified command (safer alternative)
    pub fn ask_with_updated_command(
        reason: &str,
        new_command: &str,
        context: Option<&str>,
    ) -> Self {
        Self {
            decision: PermissionDecision::Ask,
            reason: Some(reason.to_string()),
            context: context.map(String::from),
            updated_command: Some(new_command.to_string()),
        }
    }

    /// Return deny (block the command)
    pub fn deny(reason: &str) -> Self {
        Self {
            decision: PermissionDecision::Deny,
            reason: Some(reason.to_string()),
            context: None,
            updated_command: None,
        }
    }

    /// Return deny with additional context explaining the danger
    pub fn deny_with_context(reason: &str, context: &str) -> Self {
        Self {
            decision: PermissionDecision::Deny,
            reason: Some(reason.to_string()),
            context: Some(context.to_string()),
            updated_command: None,
        }
    }

    /// Serialize for the given client.
    pub fn serialize(&self, client: Client) -> serde_json::Value {
        match client {
            Client::Claude => self.to_claude_json(),
            Client::Gemini => self.to_gemini_json(),
        }
    }

    /// Serialize to Claude Code wire format.
    ///
    /// Approve: `{"decision":"approve"}`
    /// Defer:   `{"hookSpecificOutput":{"hookEventName":"PreToolUse",...}}` (no permissionDecision)
    /// Others:  `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow",...}}`
    fn to_claude_json(&self) -> serde_json::Value {
        if self.decision == PermissionDecision::Approve {
            return serde_json::json!({ "decision": "approve" });
        }

        let mut hso = serde_json::Map::new();
        hso.insert("hookEventName".to_string(), serde_json::json!("PreToolUse"));

        // Defer omits permissionDecision so CC's resolver continues into
        // its normal flow. The Bash tool's checkPermissions still runs and
        // produces the prefix-suggestion that lights up the third
        // "Yes, and don't ask again for X" prompt button.
        if self.decision != PermissionDecision::Defer {
            hso.insert(
                "permissionDecision".to_string(),
                serde_json::json!(self.decision.as_str()),
            );
        }

        if let Some(ref reason) = self.reason {
            hso.insert(
                "permissionDecisionReason".to_string(),
                serde_json::json!(reason),
            );
        }

        if let Some(ref cmd) = self.updated_command {
            let updated_input = serde_json::json!({ "command": cmd });
            hso.insert("updatedInput".to_string(), updated_input);
        }

        if let Some(ref ctx) = self.context {
            hso.insert("additionalContext".to_string(), serde_json::json!(ctx));
        }

        serde_json::json!({ "hookSpecificOutput": serde_json::Value::Object(hso) })
    }

    /// Serialize to Gemini CLI wire format.
    ///
    /// Approve: `{"decision":"allow"}`
    /// Others: `{"decision":"allow|ask|block","reason":"..."}` with optional hookSpecificOutput for extras
    fn to_gemini_json(&self) -> serde_json::Value {
        if self.decision == PermissionDecision::Approve {
            return serde_json::json!({ "decision": "allow" });
        }

        let mut out = serde_json::Map::new();

        // Map permission decision (Gemini uses "block" instead of "deny").
        // Defer is a Claude-only concept (Claude's resolver runs the
        // tool's checkPermissions when the hook omits permissionDecision);
        // Gemini's flow has no equivalent prefix-suggestion path, so a
        // Defer collapses to "ask" on the Gemini side -- same end-user
        // experience Gemini already has today for ask-tier commands.
        let decision = match self.decision {
            PermissionDecision::Deny => "block",
            PermissionDecision::Defer => "ask",
            other => other.as_str(),
        };
        out.insert("decision".to_string(), serde_json::json!(decision));

        // Reason at top level
        if let Some(ref reason) = self.reason {
            out.insert("reason".to_string(), serde_json::json!(reason));
        }

        // Additional context and updated command go in hookSpecificOutput
        if self.context.is_some() || self.updated_command.is_some() {
            let mut hook_out = serde_json::Map::new();
            if let Some(ref ctx) = self.context {
                hook_out.insert("additionalContext".to_string(), serde_json::json!(ctx));
            }
            if let Some(ref cmd) = self.updated_command {
                hook_out.insert(
                    "tool_input".to_string(),
                    serde_json::json!({ "command": cmd }),
                );
            }
            out.insert(
                "hookSpecificOutput".to_string(),
                serde_json::Value::Object(hook_out),
            );
        }

        serde_json::Value::Object(out)
    }
}

// === PermissionRequest Hook Types ===

/// Permission suggestion from Claude Code (what it wants to add)
#[derive(Debug, Deserialize, Clone)]
pub struct PermissionSuggestion {
    #[serde(rename = "type")]
    pub suggestion_type: String,
    #[serde(default)]
    pub directories: Vec<String>,
    #[serde(default)]
    pub rules: Vec<serde_json::Value>,
    #[serde(default)]
    pub behavior: Option<String>,
    #[serde(default)]
    pub destination: Option<String>,
}

/// Input received by `PermissionRequest` hook
#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)]
pub struct PermissionRequestInput {
    #[serde(default)]
    pub hook_event_name: String,
    #[serde(default)]
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: ToolInputVariant,
    #[serde(default)]
    pub permission_suggestions: Vec<PermissionSuggestion>,
    #[serde(default)]
    /// Optional path that triggered the permission prompt.
    /// May be absent depending on Claude Code version/runtime path.
    pub blocked_path: Option<String>,
    #[serde(default)]
    /// Optional reason from Claude Code for why it prompted.
    /// May be absent depending on Claude Code version/runtime path.
    pub decision_reason: Option<String>,
    #[serde(default)]
    pub tool_use_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: String,
}

impl PermissionRequestInput {
    /// Extract file_path from `tool_input` (for Write/Edit tools)
    pub fn get_file_path(&self) -> String {
        match &self.tool_input {
            ToolInputVariant::Structured(ti) => ti.file_path.clone().unwrap_or_default(),
            ToolInputVariant::Map(m) => m
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            ToolInputVariant::Empty => String::new(),
        }
    }

    /// Extract command string from `tool_input`
    pub fn get_command(&self) -> String {
        match &self.tool_input {
            ToolInputVariant::Structured(ti) => ti.command.clone(),
            ToolInputVariant::Map(m) => m
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            ToolInputVariant::Empty => String::new(),
        }
    }
}

/// Decision for PermissionRequest - allow or deny
#[derive(Debug, Serialize)]
#[serde(tag = "behavior")]
pub enum PermissionRequestDecision {
    #[serde(rename = "allow", rename_all = "camelCase")]
    Allow {
        #[serde(skip_serializing_if = "Option::is_none")]
        updated_input: Option<serde_json::Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        updated_permissions: Option<Vec<UpdatedPermission>>,
    },
    #[serde(rename = "deny")]
    Deny {
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        interrupt: Option<bool>,
    },
}

/// Permission update to add (e.g., addDirectories)
#[derive(Debug, Serialize, Clone)]
pub struct UpdatedPermission {
    #[serde(rename = "type")]
    pub permission_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directories: Option<Vec<String>>,
    pub destination: String,
}

/// Hook-specific output for `PermissionRequest`
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequestSpecificOutput {
    pub hook_event_name: String,
    pub decision: PermissionRequestDecision,
}

/// Output format for PermissionRequest hooks
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequestOutput {
    pub hook_specific_output: PermissionRequestSpecificOutput,
}

impl PermissionRequestOutput {
    /// Approve the permission request (command will execute)
    pub fn allow() -> Self {
        Self {
            hook_specific_output: PermissionRequestSpecificOutput {
                hook_event_name: "PermissionRequest".to_string(),
                decision: PermissionRequestDecision::Allow {
                    updated_input: None,
                    updated_permissions: None,
                },
            },
        }
    }

    /// Approve and also add directories to session permissions
    pub fn allow_with_directories(directories: Vec<String>) -> Self {
        Self {
            hook_specific_output: PermissionRequestSpecificOutput {
                hook_event_name: "PermissionRequest".to_string(),
                decision: PermissionRequestDecision::Allow {
                    updated_input: None,
                    updated_permissions: Some(vec![UpdatedPermission {
                        permission_type: "addDirectories".to_string(),
                        directories: Some(directories),
                        destination: "session".to_string(),
                    }]),
                },
            },
        }
    }

    /// Deny the permission request
    pub fn deny(message: &str) -> Self {
        Self {
            hook_specific_output: PermissionRequestSpecificOutput {
                hook_event_name: "PermissionRequest".to_string(),
                decision: PermissionRequestDecision::Deny {
                    message: Some(message.to_string()),
                    interrupt: None,
                },
            },
        }
    }

    /// Deny and interrupt the agent
    pub fn deny_and_interrupt(message: &str) -> Self {
        Self {
            hook_specific_output: PermissionRequestSpecificOutput {
                hook_event_name: "PermissionRequest".to_string(),
                decision: PermissionRequestDecision::Deny {
                    message: Some(message.to_string()),
                    interrupt: Some(true),
                },
            },
        }
    }
}

// === PostToolUse Hook Types ===

/// Input received by `PostToolUse` hook
#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)]
pub struct PostToolUseInput {
    #[serde(default)]
    pub hook_event_name: String,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: ToolInputVariant,
    #[serde(default)]
    pub tool_use_id: String,
    /// Response from the tool execution
    #[serde(default)]
    pub tool_response: Option<serde_json::Value>,
}

impl PostToolUseInput {
    /// Extract command string from `tool_input`
    pub fn get_command(&self) -> String {
        match &self.tool_input {
            ToolInputVariant::Structured(ti) => ti.command.clone(),
            ToolInputVariant::Map(m) => m
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            ToolInputVariant::Empty => String::new(),
        }
    }

    /// Check if the tool response indicates success.
    ///
    /// PostToolUse only fires for successful tool calls — failures trigger
    /// the separate PostToolUseFailure event. So we default to `true` unless
    /// an explicit non-zero exit code is present.
    pub fn is_success(&self) -> bool {
        self.tool_response
            .as_ref()
            .and_then(|r| {
                r.get("exit_code")
                    .or_else(|| r.get("exitCode"))
                    .and_then(|c| c.as_i64())
                    .map(|c| c == 0)
            })
            .unwrap_or(true)
    }
}

// === PermissionDenied Hook Types ===

/// Input received by `PermissionDenied` hook.
///
/// Fires only when the auto-mode classifier denies a tool call. Schema
/// matches Claude Code's hook input contract: common base fields plus
/// `tool_name`, `tool_input`, `tool_use_id`, and the classifier `reason`.
#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)]
pub struct PermissionDeniedInput {
    #[serde(default)]
    pub hook_event_name: String,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: String,
    #[serde(default)]
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: ToolInputVariant,
    #[serde(default)]
    pub tool_use_id: String,
    /// Classifier denial reason string
    #[serde(default)]
    pub reason: String,
}

impl PermissionDeniedInput {
    /// Extract command string from `tool_input` (for Bash-style tools)
    pub fn get_command(&self) -> String {
        match &self.tool_input {
            ToolInputVariant::Structured(ti) => ti.command.clone(),
            ToolInputVariant::Map(m) => m
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            ToolInputVariant::Empty => String::new(),
        }
    }
}

/// Hook-specific output for `PermissionDenied`.
///
/// Only `retry` is honored by Claude Code. When `retry: true`, Claude
/// appends a meta message telling the model it may retry the blocked
/// tool call.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionDeniedSpecificOutput {
    pub hook_event_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry: Option<bool>,
}

/// Output format for PermissionDenied hooks
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionDeniedOutput {
    pub hook_specific_output: PermissionDeniedSpecificOutput,
}

impl PermissionDeniedOutput {
    /// Tell Claude Code the model may retry this tool call.
    pub fn retry() -> Self {
        Self {
            hook_specific_output: PermissionDeniedSpecificOutput {
                hook_event_name: "PermissionDenied".to_string(),
                retry: Some(true),
            },
        }
    }
}

/// Hook-specific output for `PostToolUse`
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostToolUseSpecificOutput {
    pub hook_event_name: String,
    /// Additional context to inject into Claude's conversation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// Output format for PostToolUse hooks
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostToolUseOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook_specific_output: Option<PostToolUseSpecificOutput>,
}

impl PostToolUseOutput {
    /// Return empty output (no action needed)
    pub fn none() -> Self {
        Self {
            hook_specific_output: None,
        }
    }

    /// Return output with additional context
    pub fn with_context(context: &str) -> Self {
        Self {
            hook_specific_output: Some(PostToolUseSpecificOutput {
                hook_event_name: "PostToolUse".to_string(),
                additional_context: Some(context.to_string()),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_ordering() {
        assert!(Decision::Block > Decision::Ask);
        assert!(Decision::Ask > Decision::Allow);
    }

    #[test]
    fn test_decision_stricter() {
        assert_eq!(Decision::Allow.stricter(Decision::Ask), Decision::Ask);
        assert_eq!(Decision::Ask.stricter(Decision::Allow), Decision::Ask);
        assert_eq!(Decision::Block.stricter(Decision::Ask), Decision::Block);
    }

    #[test]
    fn test_hook_output_fields() {
        let output = HookOutput::allow(Some("Read-only operation"));
        assert_eq!(output.decision, PermissionDecision::Allow);
        assert_eq!(output.reason.as_deref(), Some("Read-only operation"));
    }

    #[test]
    fn test_claude_serialization_allow() {
        let output = HookOutput::allow(Some("Read-only operation"));
        let json = serde_json::to_string(&output.to_claude_json()).unwrap();
        assert!(json.contains("allow"), "should contain allow: {json}");
        assert!(
            json.contains("Read-only operation"),
            "should contain reason: {json}"
        );
        assert!(
            json.contains("hookSpecificOutput"),
            "should contain hookSpecificOutput: {json}"
        );
        assert!(
            json.contains("PreToolUse"),
            "should contain PreToolUse: {json}"
        );
    }

    #[test]
    fn test_claude_serialization_approve() {
        let output = HookOutput::no_opinion();
        let json = serde_json::to_string(&output.to_claude_json()).unwrap();
        assert!(
            json.contains("\"decision\":\"approve\""),
            "approve should produce decision:approve: {json}"
        );
        assert!(
            !json.contains("hookSpecificOutput"),
            "approve should not have hookSpecificOutput: {json}"
        );
    }

    #[test]
    fn test_claude_serialization_deny() {
        let output = HookOutput::deny("Dangerous command");
        let json = serde_json::to_string(&output.to_claude_json()).unwrap();
        assert!(
            json.contains("\"permissionDecision\":\"deny\""),
            "should contain deny: {json}"
        );
        assert!(
            json.contains("Dangerous command"),
            "should contain reason: {json}"
        );
    }

    #[test]
    fn test_claude_serialization_ask_with_updated_command() {
        let output = HookOutput::ask_with_updated_command("safer", "ls -la", Some("hint"));
        let json = serde_json::to_string(&output.to_claude_json()).unwrap();
        assert!(
            json.contains("updatedInput"),
            "should contain updatedInput: {json}"
        );
        assert!(
            json.contains("ls -la"),
            "should contain new command: {json}"
        );
        assert!(
            json.contains("additionalContext"),
            "should contain additionalContext: {json}"
        );
    }

    #[test]
    fn test_permission_request_allow_uses_camel_case() {
        let output = PermissionRequestOutput::allow_with_directories(vec!["/tmp".to_string()]);
        let json = serde_json::to_string(&output).unwrap();
        assert!(
            json.contains("updatedPermissions"),
            "expected camelCase 'updatedPermissions', got: {json}"
        );
        assert!(
            !json.contains("updated_permissions"),
            "should not contain snake_case 'updated_permissions', got: {json}"
        );
    }

    #[test]
    fn test_permission_request_deny_uses_camel_case() {
        let output = PermissionRequestOutput::deny_and_interrupt("dangerous");
        let json = serde_json::to_string(&output).unwrap();
        // 'message' and 'interrupt' are single words so casing doesn't matter,
        // but 'hookEventName' from the wrapper must be camelCase
        assert!(
            json.contains("hookEventName"),
            "expected camelCase 'hookEventName', got: {json}"
        );
    }

    // === Gemini CLI output tests ===

    #[test]
    fn test_client_detection_from_hook_event() {
        assert_eq!(Client::from_hook_event("BeforeTool"), Client::Gemini);
        assert_eq!(Client::from_hook_event("AfterTool"), Client::Gemini);
        assert_eq!(Client::from_hook_event("PreToolUse"), Client::Claude);
        assert_eq!(Client::from_hook_event("PostToolUse"), Client::Claude);
        assert_eq!(Client::from_hook_event("PermissionRequest"), Client::Claude);
        assert_eq!(Client::from_hook_event(""), Client::Claude);
    }

    #[test]
    fn test_is_shell_tool() {
        assert!(Client::is_shell_tool("Bash"));
        assert!(Client::is_shell_tool("Monitor"));
        assert!(Client::is_shell_tool("run_shell_command"));
        assert!(!Client::is_shell_tool("read_file"));
        assert!(!Client::is_shell_tool("write_file"));
    }

    #[test]
    fn test_gemini_allow_output() {
        let output = HookOutput::allow(Some("Read-only"));
        let gemini = output.serialize(Client::Gemini);
        assert_eq!(gemini["decision"], "allow");
        assert_eq!(gemini["reason"], "Read-only");
        assert!(gemini.get("hookSpecificOutput").is_none());
    }

    #[test]
    fn test_gemini_allow_with_context_output() {
        let output = HookOutput::allow_with_context(Some("Safe"), "Use bat instead");
        let gemini = output.serialize(Client::Gemini);
        assert_eq!(gemini["decision"], "allow");
        assert_eq!(gemini["reason"], "Safe");
        assert_eq!(
            gemini["hookSpecificOutput"]["additionalContext"],
            "Use bat instead"
        );
    }

    #[test]
    fn test_gemini_deny_uses_block() {
        let output = HookOutput::deny("Dangerous command");
        let gemini = output.serialize(Client::Gemini);
        assert_eq!(
            gemini["decision"], "block",
            "Gemini uses 'block' not 'deny': {gemini}"
        );
        assert_eq!(gemini["reason"], "Dangerous command");
    }

    #[test]
    fn test_gemini_ask_output() {
        let output = HookOutput::ask("Needs approval");
        let gemini = output.serialize(Client::Gemini);
        assert_eq!(gemini["decision"], "ask");
        assert_eq!(gemini["reason"], "Needs approval");
    }

    #[test]
    fn test_gemini_approve_passthrough() {
        let output = HookOutput::no_opinion();
        let gemini = output.serialize(Client::Gemini);
        assert_eq!(gemini["decision"], "allow");
    }

    #[test]
    fn test_gemini_no_nested_permission_decision() {
        // Gemini output must NOT contain Claude-specific nested fields
        let output = HookOutput::allow(Some("test"));
        let gemini_str = serde_json::to_string(&output.serialize(Client::Gemini)).unwrap();
        assert!(
            !gemini_str.contains("permissionDecision"),
            "Gemini output should not contain permissionDecision: {gemini_str}"
        );
        assert!(
            !gemini_str.contains("hookEventName"),
            "Gemini output should not contain hookEventName: {gemini_str}"
        );
    }

    #[test]
    fn test_serialize_dispatches_correctly() {
        let output = HookOutput::allow(Some("test"));
        let claude = output.serialize(Client::Claude);
        let gemini = output.serialize(Client::Gemini);
        // Claude has hookSpecificOutput nesting, Gemini has flat decision
        assert!(claude.get("hookSpecificOutput").is_some());
        assert!(gemini.get("hookSpecificOutput").is_none());
    }

    #[test]
    fn test_permission_decision_as_str() {
        assert_eq!(PermissionDecision::Approve.as_str(), "approve");
        assert_eq!(PermissionDecision::Allow.as_str(), "allow");
        assert_eq!(PermissionDecision::Ask.as_str(), "ask");
        assert_eq!(PermissionDecision::Deny.as_str(), "deny");
    }

    // === Tool name classification tests ===

    #[test]
    fn test_is_file_tool() {
        // Claude tool names
        assert!(Client::is_file_tool("Read"));
        assert!(Client::is_file_tool("Write"));
        assert!(Client::is_file_tool("Edit"));
        // Gemini tool names
        assert!(Client::is_file_tool("read_file"));
        assert!(Client::is_file_tool("read_many_files"));
        assert!(Client::is_file_tool("write_file"));
        assert!(Client::is_file_tool("replace"));
        // Not file tools
        assert!(!Client::is_file_tool("Bash"));
        assert!(!Client::is_file_tool("run_shell_command"));
        assert!(!Client::is_file_tool("Glob"));
    }

    #[test]
    fn test_is_read_tool() {
        assert!(Client::is_read_tool("Read"));
        assert!(Client::is_read_tool("read_file"));
        assert!(Client::is_read_tool("read_many_files"));
        assert!(!Client::is_read_tool("Write"));
        assert!(!Client::is_read_tool("write_file"));
        assert!(!Client::is_read_tool("replace"));
    }

    #[test]
    fn test_is_write_tool() {
        assert!(Client::is_write_tool("Write"));
        assert!(Client::is_write_tool("Edit"));
        assert!(Client::is_write_tool("write_file"));
        assert!(Client::is_write_tool("replace"));
        assert!(!Client::is_write_tool("Read"));
        assert!(!Client::is_write_tool("read_file"));
    }

    #[test]
    fn test_is_skill_tool() {
        assert!(Client::is_skill_tool("Skill"));
        assert!(Client::is_skill_tool("activate_skill"));
        assert!(!Client::is_skill_tool("Bash"));
    }

    #[test]
    fn test_is_glob_grep_tool() {
        assert!(Client::is_glob_tool("Glob"));
        assert!(Client::is_glob_tool("glob"));
        assert!(!Client::is_glob_tool("Grep"));
        assert!(Client::is_grep_tool("Grep"));
        assert!(Client::is_grep_tool("grep_search"));
        assert!(!Client::is_grep_tool("Glob"));
    }

    #[test]
    fn test_permission_denied_output_serializes_camel_case() {
        // Claude Code expects exact camelCase: hookSpecificOutput.hookEventName, retry.
        let output = PermissionDeniedOutput::retry();
        let json = serde_json::to_string(&output).expect("should serialize");
        assert!(
            json.contains("\"hookSpecificOutput\""),
            "missing hookSpecificOutput: {json}"
        );
        assert!(
            json.contains("\"hookEventName\":\"PermissionDenied\""),
            "missing hookEventName: {json}"
        );
        assert!(
            json.contains("\"retry\":true"),
            "missing retry:true: {json}"
        );
    }

    #[test]
    fn test_permission_denied_input_parses() {
        let input = serde_json::json!({
            "hook_event_name": "PermissionDenied",
            "session_id": "abc",
            "cwd": "/repo",
            "permission_mode": "auto",
            "tool_name": "Bash",
            "tool_input": {"command": "cargo check"},
            "tool_use_id": "tc_123",
            "reason": "classifier denied",
        });
        let parsed: PermissionDeniedInput = serde_json::from_value(input).unwrap();
        assert_eq!(parsed.tool_name, "Bash");
        assert_eq!(parsed.get_command(), "cargo check");
        assert_eq!(parsed.reason, "classifier denied");
        assert_eq!(parsed.permission_mode, "auto");
    }

    #[test]
    fn test_is_auto_mode_normalizes_case_and_whitespace() {
        // Exact match
        assert!(is_auto_mode("auto"));
        // Whitespace trim -- hook payload variations
        assert!(is_auto_mode(" auto "));
        assert!(is_auto_mode("auto\n"));
        assert!(is_auto_mode("\tauto"));
        // Case insensitive
        assert!(is_auto_mode("AUTO"));
        assert!(is_auto_mode("Auto"));
        assert!(is_auto_mode("aUtO"));
        // Non-matches
        assert!(!is_auto_mode(""));
        assert!(!is_auto_mode("default"));
        assert!(!is_auto_mode("auto-safe"));
        assert!(!is_auto_mode("auto_v2"));
        assert!(!is_auto_mode("plan"));
        assert!(!is_auto_mode("acceptEdits"));
    }

    #[test]
    fn test_is_plan_mode_normalizes_case_and_whitespace() {
        assert!(is_plan_mode("plan"));
        assert!(is_plan_mode(" plan "));
        assert!(is_plan_mode("PLAN"));
        assert!(is_plan_mode("Plan"));
        assert!(!is_plan_mode(""));
        assert!(!is_plan_mode("default"));
        assert!(!is_plan_mode("auto"));
        assert!(!is_plan_mode("acceptEdits"));
        assert!(!is_plan_mode("planning"));
    }

    #[test]
    fn test_is_mcp_tool() {
        // Claude MCP format (double underscore)
        assert!(Client::is_mcp_tool("mcp__ast-grep__find_code"));
        assert!(Client::is_mcp_tool("mcp__firecrawl__scrape"));
        // Gemini MCP format (single underscore)
        assert!(Client::is_mcp_tool("mcp_ast-grep_find_code"));
        assert!(Client::is_mcp_tool("mcp_firecrawl_scrape"));
        // Not MCP
        assert!(!Client::is_mcp_tool("Bash"));
        assert!(!Client::is_mcp_tool("Read"));
    }
}

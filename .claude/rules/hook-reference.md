---
paths:
  - "src/models.rs"
  - "src/gates/*.rs"
  - "src/lib.rs"
  - "src/main.rs"
---

# Hook Input/Output Reference

tool-gates supports three clients:
- **Claude Code**: `PreToolUse` / `PermissionRequest` / `PermissionDenied` / `PostToolUse` events. Detected from `hook_event_name`.
- **Gemini CLI**: `BeforeTool` / `AfterTool` events. Detected from `hook_event_name`.
- **Codex CLI**: `PreToolUse` / `PermissionRequest` / `PostToolUse` events. **Cannot** be detected from `hook_event_name` (Codex shares Claude's event names verbatim). Selected via the explicit `--client codex` argv flag, which the installer bakes into the hook command.

The `Client` enum in `models.rs` maps the chosen client to the appropriate serialization format, tool name mapping, and exit code behavior.

All Claude JSON output uses **camelCase** field names (`hookEventName`, `permissionDecision`, `updatedPermissions`). Enforced by `#[serde(rename_all = "camelCase")]` on output structs in `models.rs`. New fields must follow this convention with test coverage asserting exact casing.

## Common Base Fields (all hook inputs)

Every hook input includes these fields from the base schema:

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | `string` | Current session UUID |
| `transcript_path` | `string \| null` | Path to the session's JSONL transcript file. Codex emits `null` when no transcript is available; `HookInput`'s deserializer coerces null to empty string |
| `cwd` | `string` | Current working directory |
| `permission_mode` | `string` (optional) | Current permission mode (e.g., `"acceptEdits"`) |
| `agent_id` | `string` (optional) | Present only when hook fires from a subagent. Absent for main thread, even in `--agent` sessions. |
| `agent_type` | `string` (optional) | Agent type name (e.g., `"code-reviewer"`). Present for subagents (with `agent_id`) or main thread of `--agent` sessions (without `agent_id`). |
| `turn_id` | `string` (Codex only) | Per-turn identifier from Codex; tool-gates doesn't currently key off this field but accepts it without rejecting the payload. |

## PreToolUse

**Input fields** (in addition to common base):

| Field | Type | Description |
|-------|------|-------------|
| `hook_event_name` | `"PreToolUse"` | Identifies the hook type |
| `tool_name` | `string` | Tool being invoked (e.g., `"Bash"`) |
| `tool_input` | `object` | Tool-specific input (e.g., `{"command": "..."}`) |
| `tool_use_id` | `string` | Unique ID for this tool invocation |

**Output format:**
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow|ask|deny",
    "permissionDecisionReason": "Human-readable reason",
    "additionalContext": "Optional hints shown to Claude",
    "updatedInput": {"command": "modified command"}
  }
}
```

`updatedInput` (optional) replaces the original tool input. Use to rewrite commands before execution.

## PermissionRequest

Fires when Claude Code would normally show a permission prompt to the user.

**Input fields** (in addition to common base):

| Field | Type | Description |
|-------|------|-------------|
| `hook_event_name` | `"PermissionRequest"` | Identifies the hook type |
| `tool_name` | `string` | Tool being requested |
| `tool_input` | `object` | Tool-specific input |
| `permission_suggestions` | `array` (optional) | Suggested permission updates (addRules, addDirectories, etc.) |

Note: `decision_reason` and `blocked_path` are NOT in PermissionRequest hook input. Those only appear in the remote control protocol.

**Output (approve):**
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PermissionRequest",
    "decision": {
      "behavior": "allow",
      "updatedInput": {"command": "modified command"},
      "updatedPermissions": [{
        "type": "addDirectories",
        "directories": ["/path/to/allow"],
        "destination": "session"
      }]
    }
  }
}
```

`updatedInput` and `updatedPermissions` are both optional. Permission update types: `addRules`, `replaceRules`, `removeRules`, `setMode`, `addDirectories`, `removeDirectories`.

**Output (deny):**
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PermissionRequest",
    "decision": {
      "behavior": "deny",
      "message": "Reason for denial",
      "interrupt": false
    }
  }
}
```

`interrupt` (optional, default false): when true, stops the current agentic loop.

**Output (pass through):** Return empty/no output to let the normal permission prompt show.

## PostToolUse

Fires after a tool completes.

**Input fields** (in addition to common base):

| Field | Type | Description |
|-------|------|-------------|
| `hook_event_name` | `"PostToolUse"` | Identifies the hook type |
| `tool_name` | `string` | Tool that was invoked |
| `tool_input` | `object` | Original tool input |
| `tool_response` | `object` | Command result (includes `exit_code`, `stdout`, `stderr` for Bash) |
| `tool_use_id` | `string` | Unique ID to correlate with PreToolUse |

**Output format:**
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PostToolUse",
    "additionalContext": "Optional context added to Claude's view",
    "updatedMCPToolOutput": {}
  }
}
```

`updatedMCPToolOutput` (optional) replaces the output for MCP tools only.

PostToolUse output from tool-gates is currently empty (silent) to avoid cluttering Claude's context.

## PostToolUseFailure

Fires when a tool invocation fails.

**Input fields** (in addition to common base):

| Field | Type | Description |
|-------|------|-------------|
| `hook_event_name` | `"PostToolUseFailure"` | Identifies the hook type |
| `tool_name` | `string` | Tool that failed |
| `tool_input` | `object` | Original tool input |
| `tool_use_id` | `string` | Unique ID for the failed invocation |
| `error` | `string` | Error message |
| `is_interrupt` | `boolean` (optional) | Whether the failure was due to user interrupt |

## General Output Fields

These fields are available on all hook outputs (not just hookSpecificOutput):

| Field | Type | Description |
|-------|------|-------------|
| `continue` | `boolean` (optional) | Whether Claude should continue after hook (default: true) |
| `suppressOutput` | `boolean` (optional) | Hide stdout from transcript (default: false) |
| `stopReason` | `string` (optional) | Message shown when `continue` is false |
| `decision` | `"approve" \| "block"` (optional) | General decision (used by some hook types) |
| `reason` | `string` (optional) | Explanation for the decision |
| `systemMessage` | `string` (optional) | Warning message shown to the user |

## Gemini CLI Hooks

Gemini uses `BeforeTool` (pre) and `AfterTool` (post) events. Detected by `Client::from_hook_event()`.

**Tool name mapping** (Gemini -> Claude equivalents):
| Gemini | Claude |
|--------|--------|
| `run_shell_command` | `Bash` |
| `read_file` / `read_many_files` | `Read` |
| `write_file` | `Write` |
| `replace` | `Edit` |
| `glob` | `Glob` |
| `grep_search` | `Grep` |
| `activate_skill` | `Skill` |
| `mcp_*` (single `_`) | `mcp__*` (double `__`) |

**Output format** (flat, no nesting):
```json
{
  "decision": "allow|ask|block",
  "reason": "Human-readable reason"
}
```

Key differences from Claude:
- Gemini accepts both `"block"` and `"deny"` for blocking decisions, and both `"allow"` and `"approve"` for allowing. We output `"block"` for clarity.
- `decision` and `reason` are flat top-level fields (not nested in `hookSpecificOutput`)
- `additionalContext` goes inside `hookSpecificOutput` only when present (for hints)
- Exit code 2 used as process-level block signal. Gemini treats any non-zero/non-1 exit as deny for non-JSON output, but JSON `decision` field takes precedence when present.
- No `tool_use_id` from Gemini, so PostToolUse tracking is skipped
- MCP tools use single underscore prefix (`mcp_server_tool`) vs Claude's double (`mcp__server__tool`)

## Codex CLI Hooks

Codex emits `PreToolUse` / `PermissionRequest` / `PostToolUse` events with snake_case input fields and camelCase output -- the same surface shape as Claude. The wire format is similar enough that the same `HookInput` / `PostToolUseInput` deserializers parse it. Detection is via the explicit `--client codex` argv flag (`Client::from_cli_name`); `from_hook_event()` cannot distinguish Codex from Claude because the event names are identical.

**Hook config file**: `~/.codex/hooks.json` (user) or `<repo>/.codex/hooks.json` (project). Top-level `{ "hooks": { ... } }` object, same shape as Claude/Gemini settings.json.

**Tool name mapping** (Codex -> Claude equivalents):
| Codex | Claude |
|-------|--------|
| `Bash` | `Bash` |
| `apply_patch` | `Write` / `Edit` (single payload, unified-diff in `tool_input.command`) |
| `mcp__server__tool` | `mcp__server__tool` (same convention) |

**`apply_patch` payload**: tool_input is `{ "command": "<entire-patch-body>" }`. Paths are inside the body as `*** Add File: <path>` / `*** Update File: <path>` / `*** Delete File: <path>` headers, optionally with `*** Move to: <target>` for renames. tool-gates parses this in `apply_patch_parser.rs` and routes each affected path through file_guards + security_reminders.

**Output format**:
```json
// Allow / Ask / no opinion: empty stdout, exit 0 (Codex's UI prompts the user)
// Deny: nested hookSpecificOutput
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Human-readable reason"
  }
}
```

Key differences from Claude (rejected by Codex's parser, dropped silently by tool-gates):
- PreToolUse `permissionDecision: "allow"` and `"ask"` are marked invalid -> tool-gates emits empty stdout (`Value::Null` from `to_codex_json`) so Codex's prompt fires instead.
- PreToolUse `additionalContext` is rejected -> hints + Tier-3 warnings move to PostToolUse for Codex (Codex accepts `additionalContext` on Post).
- PreToolUse `updatedInput` is rejected -> command rewriting won't take effect on Codex.
- PreToolUse `continue: false` / `stopReason` / `suppressOutput` are rejected -> tool-gates doesn't emit them for Codex.
- PermissionRequest `addDirectories` / `updatedInput` / `updatedPermissions` / `interrupt` are rejected -> worktree approval reduces to a flat `behavior: "allow"` with no path expansion.
- No PermissionDenied event in Codex (no auto-mode classifier).
- `transcript_path` is nullable in Codex's schema -> `HookInput` uses a `deserialize_null_string` helper to coerce null to empty string.

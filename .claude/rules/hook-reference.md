---
paths:
  - "src/models.rs"
  - "src/gates/*.rs"
  - "src/lib.rs"
  - "src/main.rs"
---

# Hook Input/Output Reference

All JSON output uses **camelCase** field names (`hookEventName`, `permissionDecision`, `updatedPermissions`). Enforced by `#[serde(rename_all = "camelCase")]` on output structs in `models.rs`. New fields must follow this convention with test coverage asserting exact casing.

## Common Base Fields (all hook inputs)

Every hook input includes these fields from the base schema:

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | `string` | Current session UUID |
| `transcript_path` | `string` | Path to the session's JSONL transcript file |
| `cwd` | `string` | Current working directory |
| `permission_mode` | `string` (optional) | Current permission mode (e.g., `"acceptEdits"`) |
| `agent_id` | `string` (optional) | Present only when hook fires from a subagent. Absent for main thread, even in `--agent` sessions. |
| `agent_type` | `string` (optional) | Agent type name (e.g., `"code-reviewer"`). Present for subagents (with `agent_id`) or main thread of `--agent` sessions (without `agent_id`). |

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

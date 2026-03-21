---
name: hook-reference
description: Detailed hook input/output JSON formats for Claude Code and Gemini CLI hooks. Use when working on hook handlers, debugging hook behavior, or modifying models.rs.
user-invocable: false
---

# Hook Input/Output Reference

bash-gates supports two clients, auto-detected from `hook_event_name`:

| Client | Shell tool_name | Hook events | Wire format |
|--------|----------------|-------------|-------------|
| Claude Code | `Bash` | `PreToolUse`, `PermissionRequest`, `PostToolUse` | Nested `hookSpecificOutput` |
| Gemini CLI | `run_shell_command` | `BeforeTool`, `AfterTool` | Flat `decision` + `reason` |

## Internal Model (provider-agnostic)

`HookOutput` stores a flat `PermissionDecision` enum (`Approve`, `Allow`, `Ask`, `Deny`) with optional `reason`, `context`, and `updated_command`. Serialization to wire format happens via `output.serialize(client)` at the output boundary in `main.rs`.

## PreToolUse / BeforeTool Output

**Claude Code:**
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow|ask|deny",
    "permissionDecisionReason": "Human-readable reason",
    "additionalContext": "Optional hints for Claude"
  }
}
```

**Gemini CLI:**
```json
{
  "decision": "allow|ask|block",
  "reason": "Human-readable reason",
  "hookSpecificOutput": {
    "additionalContext": "Optional hints"
  }
}
```

Key differences:
- Gemini uses `"block"` where Claude uses `"deny"`
- Gemini exit code 2 = hard block (emergency brake)
- Gemini puts `decision`/`reason` at top level, `additionalContext` in nested `hookSpecificOutput`
- Claude wraps everything in `hookSpecificOutput`

## PermissionRequest (Claude Code only)

Gemini CLI has no equivalent hook.

### Input Fields

| Field | Type | Description |
|-------|------|-------------|
| `hook_event_name` | `"PermissionRequest"` | Identifies the hook type |
| `tool_name` | `"Bash"` | Shell tool name |
| `tool_input` | `{"command": "..."}` | The command being requested |
| `decision_reason` | `string` (optional) | Why Claude Code is asking |
| `blocked_path` | `string` (optional) | The specific path that triggered the prompt |
| `agent_id` | `string` (optional) | Present for subagents, absent for main session |

### Output (approve with directory access)

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PermissionRequest",
    "decision": {
      "behavior": "allow",
      "updatedPermissions": [{
        "type": "addDirectories",
        "directories": ["/path/to/allow"],
        "destination": "session"
      }]
    }
  }
}
```

### Output (deny)

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PermissionRequest",
    "decision": {
      "behavior": "deny",
      "reason": "Dangerous command blocked"
    }
  }
}
```

### Output (pass through)

Return empty/no output to let the normal permission prompt show.

## PostToolUse / AfterTool

| Field | Type | Description |
|-------|------|-------------|
| `hook_event_name` | `"PostToolUse"` or `"AfterTool"` | Identifies the hook type |
| `tool_name` | `"Bash"` or `"run_shell_command"` | Shell tool name |
| `tool_use_id` | `string` | Correlation ID (Claude only -- absent in Gemini) |
| `tool_response` | `object` | Command result including `exit_code`, `stdout`, `stderr` |

PostToolUse tracking (pending approval queue) is Claude-only since Gemini doesn't provide `tool_use_id`. AfterTool for Gemini returns early with no output.

## Serde Casing

Claude-specific output structs (`PermissionRequestOutput`, `PostToolUseOutput`) use `#[serde(rename_all = "camelCase")]` for camelCase field names. The main `HookOutput` uses manual `serialize(client)` -- not serde derive -- so field names are controlled explicitly per client.

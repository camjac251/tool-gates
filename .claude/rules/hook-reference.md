---
paths:
  - "src/models.rs"
  - "src/gates/*.rs"
  - "src/lib.rs"
  - "src/main.rs"
---

# Hook Input/Output Reference

tool-gates supports four clients:
- **Claude Code**: `PreToolUse` / `PermissionRequest` / `PermissionDenied` / `PostToolUse` events. Detected from `hook_event_name`.
- **Codex CLI**: `PreToolUse` / `PermissionRequest` / `PostToolUse` events. **Cannot** be detected from `hook_event_name` (Codex shares Claude's event names verbatim). Selected via the explicit `--client codex` argv flag, which the installer bakes into the hook command.
- **Antigravity CLI** (`agy`): a single `PreToolUse` hook. Sends **no** `hook_event_name` and uses a distinct payload shape (`toolCall.name` + PascalCase args). Selected via the explicit `--client antigravity` argv flag, which the installer bakes into the hook command.
- **Gemini CLI** (deprecated): `BeforeTool` / `AfterTool` events. Detected from `hook_event_name`. Google sunsets the consumer Gemini CLI on 2026-06-18; use Antigravity for new setups.

The `Client` enum in `models.rs` maps the chosen client to the appropriate serialization format, tool name mapping, and exit code behavior.

All Claude JSON output uses **camelCase** field names (`hookEventName`, `permissionDecision`, `updatedPermissions`). Enforced by `#[serde(rename_all = "camelCase")]` on output structs in `models.rs`. New fields must follow this convention with test coverage asserting exact casing.

## Common Base Fields (all hook inputs)

Every hook input includes these fields from the base schema:

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | `string` | Current session UUID |
| `transcript_path` | `string \| null` | Path to the session's JSONL transcript file. Codex emits `null` when no transcript is available; `HookInput`'s deserializer coerces null to empty string |
| `cwd` | `string` | Current working directory |
| `permission_mode` | `string` (optional) | Current permission mode (e.g., `"acceptEdits"`). Codex currently emits `"default"` or `"bypassPermissions"` |
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
| `decision_reason` | `string` (optional) | Best-effort reason from the client's permission resolver; may be absent depending on runtime path |
| `blocked_path` | `string` (optional) | Best-effort path that triggered a permission boundary; may be absent depending on runtime path |

`decision_reason` and `blocked_path` are optional and runtime-dependent. Treat them as hints, not required schema fields.

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
    "updatedToolOutput": {},
    "updatedMCPToolOutput": {}
  }
}
```

`updatedToolOutput` (optional) replaces the tool output before it is sent to the model. Works for all tools and is preferred over `updatedMCPToolOutput`.

`updatedMCPToolOutput` (optional, legacy) replaces the output for MCP tools only.

PostToolUse is silent for tracking-only successes. It can emit `additionalContext` for post-write security reminders, Codex modern-CLI hints, and warning tiers.

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

Codex emits `PreToolUse` / `PermissionRequest` / `PostToolUse` events with snake_case input fields and camelCase output: the same surface shape as Claude. The wire format is similar enough that the same `HookInput` / `PostToolUseInput` deserializers parse it. Detection is via the explicit `--client codex` argv flag (`Client::from_cli_name`); `from_hook_event()` cannot distinguish Codex from Claude because the event names are identical.

**Hook config file**: `~/.codex/hooks.json` (user) or `<repo>/.codex/hooks.json` (project). Top-level `{ "hooks": { ... } }` object, same shape as Claude/Gemini settings.json.

Codex hooks installed by tool-gates cover PreToolUse for Bash/apply_patch and MCP tools, PermissionRequest for Bash/apply_patch, and PostToolUse for Bash/apply_patch. MCP PermissionRequest is not installed for Codex today because Codex does not emit `acceptEdits`, so `[[accept_edits_mcp]]` rules cannot safely fire for Codex MCP calls.

**Tool name mapping** (Codex -> Claude equivalents):
| Codex | Claude |
|-------|--------|
| `Bash` | `Bash` |
| `apply_patch` | `Write` / `Edit` (single payload, unified-diff in `tool_input.command`) |
| `mcp__server__tool` | `mcp__server__tool` (same convention) |

**`apply_patch` payload**: tool_input is `{ "command": "<entire-patch-body>" }`. Paths are inside the body as `*** Add File: <path>` / `*** Update File: <path>` / `*** Delete File: <path>` headers, optionally with `*** Move to: <target>` for renames. tool-gates parses this in `apply_patch_parser.rs` and routes each affected path through file_guards + security_reminders.

**Output format**:
```json
// Allow / Ask / no opinion: empty stdout, exit 0 (pass-through to Codex;
// prompting depends on approval_policy and execpolicy)
// Deny: nested hookSpecificOutput on stdout, exit 0
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
- Modern-CLI hints + Tier-3 warnings ride PostToolUse for Codex, not PreToolUse. Not a parser limitation: Codex accepts `additionalContext` on both PreToolUse and PostToolUse (upstream #20692). tool-gates' Pre handler returns empty stdout on a non-deny decision (`allow`/`ask` are rejected), so today a hint riding an allow has no Pre output to attach to.
- PreToolUse `updatedInput` is rejected -> command rewriting won't take effect on Codex.
- PreToolUse `continue: false` / `stopReason` / `suppressOutput` are rejected -> tool-gates doesn't emit them for Codex.
- PermissionRequest uses `hookSpecificOutput.decision.behavior` (`"allow"` / `"deny"`) plus optional deny `message`.
- PermissionRequest `addDirectories` / `updatedInput` / `updatedPermissions` / `interrupt` are rejected -> worktree approval reduces to an allow decision with no path expansion.
- Codex PermissionRequest input does not include `agent_id`; `apply_patch` worktree approval uses the worktree path boundary instead.
- No PermissionDenied event in Codex (no auto-mode classifier).
- `transcript_path` is nullable in Codex's schema -> `HookInput` uses a `deserialize_null_string` helper to coerce null to empty string.

## Antigravity CLI Hooks

Antigravity (`agy`) is Google's successor to the Gemini CLI. tool-gates supports it through a single `PreToolUse` hook selected via the explicit `--client antigravity` argv flag. Antigravity sends **no** `hook_event_name`, so it cannot be detected by event name (and `from_hook_event()` is never consulted for it); the flag is mandatory.

**Hook config file**: `~/.gemini/config/hooks.json` (shared user scope, the installer default and the path the CLI backend shares) or `.agents/hooks.json` (project scope, via `-s project`). The native `permissions.allow` list lives in a separate file, `~/.gemini/antigravity-cli/settings.json`. Unlike the other clients, the hooks file is a top-level object **keyed by hook name**, not a flat `{event: [...]}` map or a `{"hooks": {...}}` wrapper:

```json
{ "tool-gates": { "PreToolUse": [ { "matcher": "run_command|view_file|...", "hooks": [ { "type": "command", "command": "/path/to/tool-gates --client antigravity", "timeout": 30 } ] } ] } }
```

The installer (`install_antigravity_hooks`) owns only the `tool-gates` named entry and leaves any other named hooks untouched. Only `PreToolUse` is installed: Antigravity also exposes `PostToolUse`, `PreInvocation`, `PostInvocation`, and `Stop`, but its post payload carries no tool name or input and it has no `PermissionRequest` event, so PreToolUse is the entire gate.

**Payload normalization**: Antigravity's PreToolUse stdin nests the tool under `toolCall` (camelCase envelope) with PascalCase argument keys. `normalize_antigravity_pre_tool_use` in `main.rs` rewrites it into the canonical `HookInput` shape before the engine runs, layering the lowercase `command` / `file_path` / `content` keys the pipeline reads on top of the preserved original args. A payload without `toolCall` (a Post/Stop event) returns `None` and tool-gates emits nothing.

**Input fields (stdin)**:

| Field | Type | Description |
|-------|------|-------------|
| `toolCall.name` | `string` | The tool being executed (e.g. `run_command`). |
| `toolCall.args` | `object` | Tool arguments, PascalCase. Command at `args.CommandLine`; write target at `args.TargetFile`; read path at `args.AbsolutePath`. |
| `stepIdx` | `integer` | 0-based trajectory step index. |
| `conversationId` | `string` | Conversation UUID (mapped to `session_id`). |
| `workspacePaths` | `array<string>` | Mounted workspace roots (first element mapped to `cwd`). |
| `transcriptPath` | `string` | Path to `transcript.jsonl`. |
| `artifactDirectoryPath` | `string` | Conversation artifact directory. |

**Tool name mapping** (Antigravity -> Claude equivalents):
| Antigravity | Claude | Source key |
|-------------|--------|------------|
| `run_command` | `Bash` | `args.CommandLine` |
| `view_file` | `Read` | `args.AbsolutePath` |
| `write_to_file` | `Write` | `args.TargetFile` + `args.CodeContent` |
| `replace_file_content` | `Edit` | `args.TargetFile` + `args.ReplacementContent` |
| `multi_replace_file_content` | `Edit` | `args.TargetFile` + concatenated `args.ReplacementChunks[].ReplacementContent` |
| `grep_search` | `Grep` | `args.Query` |
| `find_by_name` | `Glob` | `args.Pattern` |

**Output format** (flat object on stdout, exit 0):
```json
{ "decision": "allow|ask|deny|force_ask", "reason": "Human-readable reason" }
```

Mapping from tool-gates' internal decision:
- `Approve` (no opinion) -> empty stdout. Antigravity's own fine-grained permission engine (the `action(target)` allow/deny/ask lists) decides; tool-gates never speaks for an unrecognized command. (`decision` is required by the schema; emitting none relies on the currently-undocumented behavior that Antigravity defers to its own engine.)
- `Allow` -> empty stdout. A hook allow is the lowest rank and inert on agy (agy keeps the strictest of the hook and native decisions), so tool-gates emits nothing and lets the native engine decide; prompt-free allowlisting is via native `permissions.allow` (`tool-gates agy allowlist`).
- `Ask` (soft) -> `{"decision":"ask"}` (prompts, respecting the user's "Always Allow" grants).
- `Ask` (hard floor: pipe-to-shell, `eval`) -> `{"decision":"force_ask"}` (always prompts, ignoring "Always Allow", set via `HookOutput::forced()`).
- `Defer` -> `{"decision":"ask"}` (no Antigravity equivalent of Claude's resolver-suggestion path).
- `Deny` -> `{"decision":"deny"}` (hard block; remediation context is folded into `reason`).

The hard-ask floor maps to `force_ask`, not `ask`, because pipe-to-shell and `eval` are ask-tier (never deny) and Antigravity's plain `ask` honors a prior "Always Allow" grant, which would let a granted command silently bypass the floor. tool-gates does not emit `permissionOverrides`: a hook's `permissionOverrides` does not suppress the current call's prompt, so it buys nothing. The Pre output has no `additionalContext` field, so modern-CLI hints and Tier-3 warnings are dropped on allow/ask. Prompt-free safe commands come from agy's native `permissions.allow` in `~/.gemini/antigravity-cli/settings.json`, generated by `tool-gates agy allowlist`. MCP is not wired for Antigravity yet (its MCP tool-name format for hook matchers is undocumented).

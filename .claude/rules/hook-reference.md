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
- **Gemini CLI** (deprecated compatibility): `BeforeTool` / `AfterTool` events. Detected from `hook_event_name`. Google's consumer Gemini CLI sunset date was 2026-06-18; use Antigravity for new setups.

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

The installer (`install_antigravity_hooks`) owns only the `tool-gates` named entry and leaves any other named hooks untouched.

**Project scope is not reliable.** A probe with a `matcher: "*"` hook in `<repo>/.agents/hooks.json` never fired under `agy --print`: the log reported `loaded 1 named hooks from 1 hooks.json file(s)` (the user-scope file only). agy's own changelog says workspace-local `.agents/hooks.json` loading was fixed "after trusting a folder by reloading hooks whenever workspaces change", so it appears to depend on a workspace-change event that a one-shot print run does not produce. The workspace was already in `trustedWorkspaces`. Prefer `-s user` for Antigravity; treat `-s project` as unverified. The binary also references a third path, `~/.gemini/antigravity-cli/hooks.json`, which its changelog calls a bug that was fixed in favor of the shared `~/.gemini/config/hooks.json`. Only `PreToolUse` is installed: Antigravity also exposes `PostToolUse`, `PreInvocation`, `PostInvocation`, and `Stop`, but its post payload carries no tool name or input and it has no `PermissionRequest` event, so PreToolUse is the entire gate.

**Payload normalization**: Antigravity's PreToolUse stdin nests the tool under `toolCall` (camelCase envelope) with PascalCase argument keys. `normalize_antigravity_pre_tool_use` in `main.rs` rewrites it into the canonical `HookInput` shape before the engine runs, layering the lowercase `command` / `file_path` / `content` keys the pipeline reads on top of the preserved original args. A payload without `toolCall` (a Post/Stop event) returns `None` and tool-gates emits nothing.

**Input fields (stdin)**:

| Field | Type | Description |
|-------|------|-------------|
| `toolCall.name` | `string` | The tool being executed (e.g. `run_command`). |
| `toolCall.args` | `object` | Tool arguments, PascalCase. Command at `args.CommandLine`; write target at `args.TargetFile`; read path at `args.AbsolutePath`. |
| `stepIdx` | `integer` | 0-based trajectory step index. Combined with `conversationId` into a synthetic `tool_use_id` (`<conversationId>:<stepIdx>`), because Antigravity has no per-call tool id and an empty one would collide across pending items. Falls back to whichever part is present. |
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

**Confirmed against a live payload.** `hooks.md` says matcher tool names are "derived by lowercasing the step type and removing the `CORTEX_STEP_TYPE_` prefix", and the binary's step-type enum has no `WRITE_TO_FILE` (the nearest is `PROPOSE_CODE`), which would have meant the write matcher never fires. A hook capture from a real `agy` run settles it in favor of the model-facing name:

```json
{
  "toolCall": {
    "name": "write_to_file",
    "args": {
      "TargetFile": "/abs/path/probe-scratch.txt",
      "CodeContent": "hello",
      "Overwrite": true,
      "Description": "Create probe-scratch.txt containing the word hello",
      "toolAction": "Creating probe file",
      "toolSummary": "Probe file creation"
    }
  },
  "stepIdx": 3,
  "conversationId": "62166620-...",
  "modelName": "gemini-3.7-flash-high",
  "workspacePaths": [],
  "transcriptPath": ".../brain/<conversationId>/.system_generated/logs/transcript_full.jsonl",
  "artifactDirectoryPath": ".../brain/<conversationId>"
}
```

So `steps.DeriveToolName` prefers `typedPayloadToolName` over `enumToolName`, and the tool names in the table above are the right ones. Also confirmed: no permission-mode field of any kind, `modelName` is present (undocumented), and `transcriptPath` / `artifactDirectoryPath` point under `brain/<conversationId>/`, not the `.gemini/antigravity/` example in `hooks.md`.

`workspacePaths` **can be empty** (it was, under `agy --print`). `write_to_file` carries no `Cwd`, so `normalize_antigravity_pre_tool_use` resolves `cwd` to `""` and `Settings::load` then skips the project and local documents; only user and managed rules apply. The safety floor, file guards, and Tier-1 secret scanning are unaffected (all verified by replaying the captured payload), so this degrades rule scope, not the gate.

**MCP, also confirmed from a live capture.** agy routes *every* MCP call through the single tool name `call_mcp_tool` and puts the server and tool in the args:

```json
{"toolCall": {"name": "call_mcp_tool",
              "args": {"ServerName": "probe", "ToolName": "probe_ping", "Arguments": {},
                       "toolAction": "...", "toolSummary": "..."}}}
```

Two consequences. The matcher must list `call_mcp_tool` literally, because `mcp_.*` does not match it. And because the name alone is identical for every MCP call, `normalize_antigravity_pre_tool_use` rebuilds Claude's canonical `mcp__<ServerName>__<ToolName>` from the args, so `[[block_tools]]` rules select per server and per tool with no agy-specific syntax. Verified against the captured payload: `mcp__probe__probe_ping` denies, `mcp__probe__*` denies, `mcp__other__probe_ping` correctly does not match. A payload missing either part keeps `call_mcp_tool`, which `Client::is_mcp_tool` still recognizes, so a catch-all rule holds.

**Output format** (flat object on stdout, exit 0). Confirmed against the `agy` binary's embedded jsonschema, which is stricter than `hooks.md`:

```json
{ "decision": "allow|ask|deny|force_ask|deny_unless_prior_grant", "reason": "Human-readable reason" }
```

- `decision` is **required**, `enum=allow,deny,ask,force_ask,deny_unless_prior_grant`. `deny_unless_prior_grant` is undocumented in `hooks.md`; tool-gates does not emit it.
- `reason` is **required whenever `decision` is not `allow`** (schema: "The reason why the tool call is blocked or why permission is asked. Required if decision is not 'allow'."). `to_antigravity_json` therefore falls back to a generic reason on every non-allow tier rather than omitting the field.
- `permissionOverrides` applies only to `ask`: "requests these standard permission resource strings instead of default." It does not suppress the current prompt, so tool-gates does not emit it.
- `overwrite` is a shallow top-level merge into the tool call's args, applied before the call runs.
- agy runs `dropUnsupportedFields` over hook output, so unknown keys are discarded rather than rejected.

agy also exposes a `SessionStart` hook (`hookcaller.CallSessionStartHook`) and prompt-mode handlers (`type: "prompt"` with a model), neither of which `hooks.md` documents. tool-gates uses neither.

Mapping from tool-gates' internal decision:
- `Approve` (no opinion) -> empty stdout. Antigravity's own fine-grained permission engine (the `action(target)` allow/deny/ask lists) decides; tool-gates never speaks for an unrecognized command. (`decision` is required by the schema; emitting none relies on the currently-undocumented behavior that Antigravity defers to its own engine.)
- `Allow` -> empty stdout. A hook allow is the lowest rank and inert on agy (agy keeps the strictest of the hook and native decisions), so tool-gates emits nothing and lets the native engine decide; prompt-free allowlisting is via native `permissions.allow` (`tool-gates agy allowlist`).
- `Ask` (soft) -> `{"decision":"ask"}` (prompts, respecting the user's "Always Allow" grants).
- `Ask` (hard floor: pipe-to-shell, `eval`) -> `{"decision":"force_ask"}` (always prompts, ignoring "Always Allow", set via `HookOutput::forced()`).
- `Defer` -> `{"decision":"ask"}` (no Antigravity equivalent of Claude's resolver-suggestion path).
- `Deny` -> `{"decision":"deny"}` (hard block; remediation context is folded into `reason`).

The hard-ask floor maps to `force_ask`, not `ask`, because pipe-to-shell and `eval` are ask-tier (never deny) and Antigravity's plain `ask` honors a prior "Always Allow" grant, which would let a granted command silently bypass the floor. tool-gates does not emit `permissionOverrides`: a hook's `permissionOverrides` does not suppress the current call's prompt, so it buys nothing. The Pre output has no `additionalContext` field, so modern-CLI hints and Tier-3 warnings are dropped on allow/ask. Prompt-free safe commands come from agy's native `permissions.allow` in `~/.gemini/antigravity-cli/settings.json`, generated by `tool-gates agy allowlist` (and, per pattern, by `tool-gates approve <pattern> --antigravity` / `rules list|remove --antigravity`).

The MCP matcher lists `call_mcp_tool`, `mcp_tool`, and `mcp_.*` because the agy spelling is unconfirmed; `[[accept_edits_mcp]]` rules cannot fire, because they key off acceptEdits.

### The shared-config overlay does not clobber the allowlist

The grants an "Always Allow" click writes live in `~/.gemini/config/config.json` under `userSettings.globalPermissionGrants`, a `PermissionGrantsConfig` with `allow` / `deny` / `ask` string lists (not `userSettings.permissions`, which agy ignores). Populating it and restarting gives, in this order:

```
applyUserSettings: stored shared config permissions: allow=1 deny=0 ask=0 from .../config/config.json
CLI settings initialized: permissions=&{Allow:[command(actionlint) ... 206 rules] Deny:[] Ask:[]}
```

The shared config is processed **first** and the CLI settings still resolve to all 206 rules from `antigravity-cli/settings.json`. So a user grant does not replace the `agy allowlist` set. The two are tracked separately; how they combine at check time would need `EnsurePermissions decision:` lines from a real prompt, but the destructive case is ruled out.

### The payload probe recipe

Useful for any future payload question. Project scope does not work (see above), so it has to go in the user hooks file:

```bash
cp ~/.gemini/config/hooks.json /tmp/hooks.json.bak
# add a second named hook beside "tool-gates":
#   "payload-probe": {"PreToolUse": [{"matcher": "*", "hooks": [{
#     "type": "command", "timeout": 15,
#     "command": "{ cat; echo; } >> /tmp/probe.jsonl; printf '%s' '{\"decision\":\"deny\",\"reason\":\"probe\"}'"}]}]}
agy -p "<prompt whose FIRST tool call is the one you want to capture>"
cp /tmp/hooks.json.bak ~/.gemini/config/hooks.json   # ALWAYS restore
```

The deny stops the run from executing anything, and also ends the turn, so it is one tool call per run: phrase the prompt so the tool you want is called first. Restoring the backup matters. A leftover deny-all hook breaks every later agy session. `write_to_file` and `call_mcp_tool` were captured this way; `view_file`, `grep_search`, `find_by_name`, `replace_file_content`, and `run_command` are inferred from them. For an MCP capture, register a throwaway stdio server in `~/.gemini/config/mcp_config.json` first (`{"mcpServers": {"probe": {"command": "python3", "args": ["/path/to/server.py"]}}}`); a minimal server only needs `initialize`, `tools/list`, and `tools/call` over line-delimited JSON-RPC on stdio.

**Two notes for future work.** `deny_unless_prior_grant` stays unused: `force_ask` is the conservative choice for the hard-ask floor and its semantics are documented, while the fifth value appears nowhere but the schema enum. And agy's own permission engine already does shell analysis tool-gates duplicates (`permissionManager.checkCompound`, `redirectionRequiresExactMatch`, `isSafeDeviceSink`, `isOverridableAskSource`), worth reading before adding agy-specific gate logic.

Two things the normalizer deliberately does **not** do, both because every mode-driven and allow-widening path downstream *relaxes* a gate, and PreToolUse is Antigravity's only gate:

- `permission_mode` is pinned to `"default"`. The machine-wide `agentMode` in `~/.gemini/antigravity-cli/settings.json` is not consulted: a live conversation can have moved off it, and nothing in the payload would reveal that, so a stale `"accept-edits"` would silently turn tool-gates' asks into allows.
- `Settings::load` does not read `~/.gemini/antigravity-cli/settings.json`. That file is agy's engine input, and `tool-gates agy allowlist` writes a broad `command(<prog>)` list into it on the explicit understanding that the hook still tightens over dangerous forms. Reading it back as a tool-gates allow list would let `command(find)` approve `find . -delete`. `command(...)` is still accepted as a synonym for `Bash(...)` inside `.claude/settings.json`, so a rule copied out of agy keeps working where tool-gates does read rules.

`~/.gemini/antigravity-cli/settings.json` is the **only** settings path in the binary; there is no `.agents/settings.json`. `.agents/` holds `hooks.json`, `skills.json`, `plugins`, `rules`, `skills`, and `agents` only. agy's native permission resource grammar is `action(target)`: `command(<cmd>)`, `mcp(<server>/<tool>)`, `read(<path>)`. Its permissions object has `allow`, `deny`, and `ask` (all three confirmed as struct tags), so `approve --antigravity --type ask|deny` writes keys agy understands.

`agy allowlist` writes to the right file, verified end to end: after `tool-gates agy allowlist --apply`, agy's startup log reports

```
applyUserSettings: no shared config permissions from ~/.gemini/config/config.json
CLI settings initialized: permissions=&{Allow:[command(actionlint) command(air) ... ] Deny:[] Ask:[]}, toolPermission=request-review
```

All 206 generated rules load, and the `Deny`/`Ask` slots exist alongside `Allow`. The struct field is `GlobalPermissions json:"permissions,omitempty"`, beside `ToolPermission`, `VimInsertFirst`, and `PickerGrouping`.

agy overlays a **second** source on top at startup: `userSettings.permissions` in `~/.gemini/config/config.json`, applied by `store.(*Manager).applyUserSettings` (`applyUserSettings: stored shared config permissions: allow=%d deny=%d ask=%d from %s`) and written by `persistSharedConfigPermissions` when the user grants "Always Allow". Per-project grants land in `~/.gemini/config/projects/<id>.json` under `settings` via `persistProjectPermissions`. With the shared config empty, the settings.json rules survive intact (log above). Whether a populated shared config merges with or replaces them is still unverified: it needs an interactive "Always Allow" grant. If it replaces, one grant drops the whole generated allowlist.

The `agentMode` key in that settings file is a machine-wide default (`agy --mode` accepts `accept-edits` and `plan`, and the binary logs "Applying agentMode from settings"). It is applied at startup and is not part of any hook payload.

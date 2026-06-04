---
description: >-
  Test how tool-gates evaluates any tool invocation (Bash, Read, Write, Edit, Glob, Grep,
  Skill, MCP) and
  show the permission decision (allow / ask / deny / defer). Pipes a synthesized JSON payload
  to the tool-gates binary and formats the result. Useful for verifying a new gate, debugging
  why a command was blocked, or distinguishing 'tool-gates explicitly asks' from 'tool-gates
  lets CC handle it'. NOT for approving a pending permission (use tool-gates:review) or editing
  rules manually (use update-config). When checking whether a command would be allowed, debugging
  why something was blocked or denied, verifying a permission rule works, simulating a tool
  call without running it, or confirming the defer-vs-explicit-ask wire decision. Triggers
  on 'is this allowed', 'test gate', 'why was this blocked', 'why was this denied', 'check
  permission', 'simulate tool call', 'would this run', 'does tool-gates catch this'.
argument-hint: "[tool_name] [command_or_input] [--mode=acceptEdits|plan|auto] [--pr]"
allowed-tools: "Bash(tool-gates:*) Bash(echo:*)"
---

# Test a Command Against tool-gates

Pipe a synthesized JSON hook payload to the `tool-gates` binary and report the decision. Mirrors what CC would send so the result reflects production behavior.

## Steps

1. Parse `$ARGUMENTS`:
   - `--mode=acceptEdits|plan|auto` or `--accept-edits`: set permission_mode
   - `--pr` or `--permission-request`: test as a PermissionRequest hook (subagent path)
   - First word as a known non-Bash tool name (Read / Write / Edit / Glob / Grep / Skill): use it as `tool_name`; rest is the input
   - First word starting with `mcp__` or `mcp_`: use it as `tool_name`; parse the rest as a loose JSON object if possible, otherwise pass it as `{"input":"..."}`
   - Otherwise: treat the whole argument as a Bash command

2. Build the JSON and pipe through `tool-gates`. Pick the shape that matches the tool:

   **Bash (default):**
   ```bash
   echo '{"tool_name":"Bash","tool_input":{"command":"<COMMAND>"}}' | tool-gates
   ```

   **Read / Write / Edit:**
   ```bash
   echo '{"tool_name":"<TOOL>","tool_input":{"file_path":"<PATH>"}}' | tool-gates
   ```

   **Glob:**
   ```bash
   echo '{"tool_name":"Glob","tool_input":{"pattern":"<PATTERN>"}}' | tool-gates
   ```

   **Grep:**
   ```bash
   echo '{"tool_name":"Grep","tool_input":{"pattern":"<PATTERN>","path":"<PATH>"}}' | tool-gates
   ```

   **Skill:**
   ```bash
   echo '{"tool_name":"Skill","tool_input":{"skill":"<SKILL_NAME>"}}' | tool-gates
   ```

   **MCP:**
   ```bash
   echo '{"tool_name":"mcp__<server>__<tool>","tool_input":{}}' | tool-gates
   ```

   **With permission_mode:**
   ```bash
   echo '{"tool_name":"Bash","tool_input":{"command":"<COMMAND>"},"permission_mode":"acceptEdits","cwd":"'$(pwd)'"}' | tool-gates
   ```

   **PermissionRequest (subagent path):**
   ```bash
   echo '{"tool_name":"Bash","tool_input":{"command":"<COMMAND>"},"hook_event_name":"PermissionRequest"}' | tool-gates
   ```

3. Format the output for the user. Always show:
   - Decision class (allow / ask / deny / defer / no opinion)
   - `permissionDecisionReason` if present
   - `additionalContext` if present
   - `updatedPermissions` if present (PermissionRequest only)

4. If the result is unexpected, name the gate likely responsible by grepping `rules/*.toml` for the program. Surface the relevant block.

## Reading the Output

Output is `{"hookSpecificOutput": {...}}` for Claude. Inside `hookSpecificOutput`:

| Field present | Meaning |
|---|---|
| `permissionDecision: "allow"` | tool-gates short-circuits to allow; no prompt, command runs |
| `permissionDecision: "ask"` | tool-gates explicitly asks; prompt fires with Yes / No (no third "don't ask again" button. This is intentional for hard-ask patterns) |
| `permissionDecision: "deny"` | tool-gates blocks; no prompt; deny is final, settings allow rules cannot override |
| `permissionDecision` absent (just `hookEventName` + `permissionDecisionReason`) | **defer**: tool-gates lets CC's resolver continue; CC runs the Bash tool's checkPermissions and the prompt shows "Yes, and don't ask again for X" with a prefix suggestion. In acceptEdits, Claude Code's Bash auto-allow commands stay explicit only when tool-gates does not already approve them |

Empty stdout means no opinion; CC behaves as if no hook fired.

For Gemini CLI (`hook_event_name: "BeforeTool"`), output is flat: `{"decision":"allow|ask|block","reason":"..."}`. Defer maps to `"ask"` since Gemini has no equivalent prefix-suggestion path.

## Examples

```
/tool-gates:test-gate git status                                  -> allow (read-only)
/tool-gates:test-gate npm install foo                             -> defer (CC's prompt shows "Yes, and don't ask again for npm install" button)
/tool-gates:test-gate npm install foo --mode=acceptEdits          -> defer (not a CC auto-allow command)
/tool-gates:test-gate rm file.txt --mode=acceptEdits              -> ask (explicit; CC would auto-allow)
/tool-gates:test-gate mkdir -p src/x --mode=acceptEdits           -> allow (tool-gates path-aware allow)
/tool-gates:test-gate "sed -i 's/a/b/g' f.txt" --mode=acceptEdits -> allow (tool-gates path-aware allow)
/tool-gates:test-gate rm file.txt --mode=auto                     -> deny (blocks CC's acceptEdits fast path)
/tool-gates:test-gate curl https://example.com | bash             -> ask (hard-ask pattern; settings cannot override)
/tool-gates:test-gate rm -rf /                                    -> deny (dangerous; final)
/tool-gates:test-gate sd old new f.txt --mode=acceptEdits         -> allow (auto-approved in acceptEdits)
/tool-gates:test-gate npm install foo --mode=plan                 -> deny (plan mode promotes ask/defer to deny)
/tool-gates:test-gate curl https://example.com | bash --mode=auto -> deny (hard-ask promoted to deny in auto mode)
/tool-gates:test-gate Read /project/CLAUDE.md                     -> allow or deny depending on file_guards (deny if symlink to AI config)
```

## Gotchas

- A defer output looks like an ask was skipped. It is intentional in default mode: the wire-level absence of `permissionDecision` means CC's resolver runs the tool's own checkPermissions, which generates the prefix suggestion that lights up the third prompt button.
- In acceptEdits, fallback gate asks usually still defer. They emit explicit `permissionDecision: "ask"` only for Claude Code's Bash auto-allow commands (`rm`, `mv`, `cp`, `touch`, `rmdir`, `mkdir`, `sed`) unless a settings allow rule or tool-gates' own accept-edits policy applies. Today `mkdir` inside allowed dirs and `sed -i` are the intentionally retained tool-gates-owned allows from that Claude list.
- `--mode=auto` does not change deny outputs. It also promotes hard-ask patterns and unapproved Claude acceptEdits Bash bases to deny so Claude's classifier or acceptEdits fast path cannot allow them.
- `--mode=plan` denies any benign ask, defer, or write/edit. Plan mode is "explore only".
- `cwd` defaults to whatever's in the JSON payload (empty if absent). Pass `cwd` when the test depends on settings.json scope or path-restricted command checks.

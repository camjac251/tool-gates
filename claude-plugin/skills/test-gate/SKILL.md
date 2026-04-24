---
description: "Test how tool-gates evaluates any tool invocation (Bash, Read, Write, Edit, Glob) and show the permission decision (allow/ask/deny). Pipes a synthesized JSON payload to the tool-gates binary and formats the result. NOT for approving a pending permission (use tool-gates:review) or editing rule files manually (use update-config)."
when_to_use: >-
  When checking if a command would be allowed, debugging why something was
  blocked or denied, verifying a permission rule works, or simulating how a
  tool call would be handled. Triggers on 'is this allowed', 'test gate',
  'why was this blocked', 'why was this denied', 'check permission',
  'simulate tool call', 'would this run'.
argument-hint: "[tool_name] [command_or_input] [--mode=acceptEdits]"
---

# Test a command against tool-gates

Test how tool-gates handles the given command. Pipe JSON to the `tool-gates` binary and show the formatted result.

## Instructions

1. Parse `$ARGUMENTS` for the tool name, input, and optional flags:
   - `--mode=acceptEdits` or `--accept-edits`: test in acceptEdits permission mode
   - `--pr` or `--permission-request`: test as a PermissionRequest hook
   - If the first word is a known non-Bash tool name (Read, Write, Edit, Glob), use it as `tool_name` and the rest as `tool_input`
   - Otherwise, assume `tool_name` is "Bash" and everything is the command

2. Build the JSON input and pipe to `tool-gates`:

**Bash command (default):**
```bash
echo '{"tool_name": "Bash", "tool_input": {"command": "<COMMAND>"}}' | tool-gates
```

**Non-Bash tool (Read, Write, Edit):**
```bash
echo '{"tool_name": "<TOOL>", "tool_input": {"file_path": "<PATH>"}}' | tool-gates
```

For Glob, use `{"pattern": "<PATTERN>"}` instead of `file_path`.

**With acceptEdits mode:**
```bash
echo '{"tool_name": "Bash", "tool_input": {"command": "<COMMAND>"}, "permission_mode": "acceptEdits", "cwd": "'$(pwd)'"}' | tool-gates
```

**PermissionRequest hook:**
```bash
echo '{"tool_name": "Bash", "tool_input": {"command": "<COMMAND>"}, "hook_event_name": "PermissionRequest"}' | tool-gates
```

3. Format the output. Show:
   - The **decision** (allow/ask/deny)
   - The **reason** if present
   - Any **additionalContext** (hints, approval commands)
   - Any **updatedPermissions** (for PermissionRequest)

4. If the result is unexpected, suggest which gate or rule is responsible by checking `rules/*.toml` for the program name.

## Output format

Output JSON has `.hookSpecificOutput` with:
- `permissionDecision`: `allow`, `ask`, or `deny`
- `permissionDecisionReason`: human-readable reason
- `additionalContext`: optional hints for Claude
- For PermissionRequest: `decision.updatedPermissions[]`

Empty output means `allow` (no hook output = passthrough).

For Gemini CLI (`hook_event_name: "BeforeTool"`), output is flat: `{"decision": "allow|ask|block", "reason": "..."}`.

## Examples

```
/test-gate git status              -> allow (read-only)
/test-gate npm install             -> ask (installing packages)
/test-gate rm -rf /                -> deny (dangerous)
/test-gate sd old new f.txt --mode=acceptEdits  -> allow (auto-approved)
/test-gate Read /project/CLAUDE.md -> deny (if symlink guard)
```

---
name: test-gate
description: Test tool-gates against any tool invocation (Bash, Read, Glob, etc.) to see the permission decision (allow/ask/deny). Use when debugging gate behavior, verifying a new rule, or checking how a command or tool is handled.
argument-hint: [tool_name] [command_or_input] [--mode=acceptEdits]
allowed-tools: Bash
---

# Test a command against tool-gates

Test how tool-gates handles the given command. Pipe JSON to the binary and show the formatted result.

## Instructions

1. Parse `$ARGUMENTS` for the tool name, input, and optional flags:
   - `--mode=acceptEdits` or `--accept-edits` -- test in acceptEdits permission mode
   - `--pr` or `--permission-request` -- test as a PermissionRequest hook
   - If the first word is a known non-Bash tool name (Read, Write, Edit, Glob, etc.), use it as `tool_name` and the rest as `tool_input`
   - Otherwise, assume `tool_name` is "Bash" and everything is the command to test

2. Build the JSON input and pipe it to `tool-gates`:

**Bash command (default):**
```bash
echo '{"tool_name": "Bash", "tool_input": {"command": "<COMMAND>"}}' | tool-gates
```

**Non-Bash tool (Read, Write, Edit, Glob, etc.):**
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
   - Any **additionalContext** (hints)
   - Any **updatedPermissions** (for PermissionRequest)

4. If the result is unexpected, suggest which gate or TOML rule is responsible by checking `rules/*.toml` for the program name.

## Examples

```
/test-gate git status              -> allow (read-only)
/test-gate npm install             -> ask (installing packages)
/test-gate rm -rf /                -> deny (dangerous)
/test-gate sd old new file.txt --mode=acceptEdits  -> allow (auto-approved)
/test-gate npm install --mode=acceptEdits          -> ask (not file-editing)
/test-gate Read /project/CLAUDE.md -> deny (if symlink)
/test-gate Glob *.rs               -> deny (blocked tool)
```

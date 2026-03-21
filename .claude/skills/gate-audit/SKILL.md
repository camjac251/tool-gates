---
name: gate-audit
description: Mine Claude Code session logs for bash commands getting incorrect permission decisions. Find read-only commands that return "ask" when they should be "allow", unknown commands that need gates, and false categorizations. Triggers include "audit gates", "find missing gates", "edge cases", "false ask", "mine sessions".
argument-hint: "[project-path-or-encoded-name]"
---

# Gate Audit

Analyze Claude Code session logs to find bash commands getting incorrect permission decisions from tool-gates.

## Session File Locations

Session transcripts live at:
```
~/.claude/projects/<encoded-path>/<session-uuid>.jsonl
~/.claude/projects/<encoded-path>/<session-uuid>/subagents/agent-<id>.jsonl
```

The path is encoded by replacing all non-alphanumeric chars with `-` (lossy: hyphens in the original path also become `-`).

### JSONL Bash extraction

Assistant entries contain tool calls in `.message.content[]` as `{"type": "tool_use", "name": "Bash", "input": {"command": "..."}}`. The jq filter used throughout this skill:

```
select(.type == "assistant") | .message.content[]? |
  select(.type == "tool_use" and .name == "Bash") | .input.command
```

## Workflow

### 1. Resolve target project

If `$ARGUMENTS` is provided, use it. Accept either:
- A full path (e.g., `/home/user/projects/myapp`)
- An already-encoded name (e.g., `-home-user-projects-myapp`)

Convert paths to encoded form by replacing non-alphanumeric chars with `-`.

If no argument, ask which project to audit.

Verify the session directory exists:
```bash
eza ~/.claude/projects/<encoded-path>/
```

### 2. Extract all unique bash commands

Extract from ALL session files including subagents:
```bash
fd -e jsonl . ~/.claude/projects/<encoded-path>/ -x \
  jq -r 'select(.type == "assistant") | .message.content[]? |
    select(.type == "tool_use" and .name == "Bash") |
    .input.command' {} 2>/dev/null | sort -u > /tmp/gate-audit-commands.txt
```

**Warning**: jq extraction sometimes captures non-command text (code fragments, commit messages). These get "ask" as "Unknown command" which is correct behavior. Filter them out before analysis.

Report counts:
```bash
# Total JSONL files (sessions + subagents)
fd -e jsonl . ~/.claude/projects/<encoded-path>/ | rg -c "."

# Subagent sessions
fd -e jsonl . ~/.claude/projects/<encoded-path>/ | rg -c subagents

# Total unique commands
rg -c "." /tmp/gate-audit-commands.txt
```

### 3. Classify every command through tool-gates

The `tool-gates` binary should be on PATH. If not, build with `cargo build --release` and use `./target/release/tool-gates`.

Run all commands through the hook interface:
```bash
while IFS= read -r cmd; do
  result=$(printf '{"tool_name":"Bash","tool_input":{"command":%s}}' \
    "$(printf '%s' "$cmd" | jq -Rs .)" | \
    tool-gates 2>/dev/null | \
    jq -r '.hookSpecificOutput | "\(.permissionDecision // "allow")\t\(.permissionDecisionReason // "-")"')
  printf "%s\t%s\n" "$result" "$cmd"
done < /tmp/gate-audit-commands.txt > /tmp/gate-audit-decisions.txt
```

**Important**: This can take several minutes for large command sets. Use `run_in_background` for 500+ commands.

### 4. Analyze results

Summarize decision counts:
```bash
choose 0 -i /tmp/gate-audit-decisions.txt | sort | uniq -c | sort -rn
```

Extract "ask" commands with reasons:
```bash
rg '^ask\t' /tmp/gate-audit-decisions.txt | choose 1:
```

### 5. Identify read-only edge cases

For each "ask" command, evaluate whether it's genuinely read-only:

**Likely should be `allow` (read-only):**
- Version/help flags: `--version`, `-V`, `--help`, `-h`
- List/query subcommands: `list`, `show`, `status`, `info`, `search`, `registry`
- Git read-only plumbing: `check-ignore`, `check-attr`, `grep`, `merge-base`, `show-ref`
- Shell builtins in pipes: `read` in `while read` loops
- Tool discovery: `which`, `command -v`, `type`

**Should remain `ask` (mutations):**
- File writes: `mkdir`, `mv`, `cp`, `rm`, `rmdir`, `touch`
- Git mutations: `add`, `commit`, `push`, `pull`, `clone`, `stash`
- Package installs: `cargo install`, `npm install`, `pip install`
- In-place edits: `sd`, `sed -i`, `rustfmt` (without `--check`)
- Network mutations: `curl -X POST`, `git push`

**Should be `ask` but with better categorization (not "Unknown command"):**
- Commands handled by no gate. Add to the appropriate gate file.

### 6. Propose fixes

For each edge case, identify which file to modify:

| Fix type | Where |
|----------|-------|
| New allow subcommand | `rules/<gate>.toml` -- add `[[programs.allow]]` entry |
| New program to existing gate | `rules/<gate>.toml` -- add `[[programs]]` section + wire in `src/gates/<gate>.rs` match arm |
| New safe command | `rules/basics.toml` -- add to `safe_commands` list |
| Move ask to allow | `rules/<gate>.toml` -- change `[[programs.ask]]` to `[[programs.allow]]` |

**Critical**: When adding programs to TOML, also check the gate's Rust match statement in `src/gates/<gate>.rs`. Declarative rules only fire if the custom handler routes the program to the declarative function. This is the most common gotcha.

### 7. Verify and test

After making changes:
```bash
cargo build --release && cargo test
```

Re-run the full audit (step 3) and present before/after comparison of decision counts.

## Reference: Hook Input/Output

Input (pipe to stdin):
```json
{"tool_name": "Bash", "tool_input": {"command": "the command to test"}}
```

Output fields:
- `.hookSpecificOutput.permissionDecision`: `allow`, `ask`, or `deny`
- `.hookSpecificOutput.permissionDecisionReason`: human-readable reason
- Empty output means `allow` (hook returns nothing for allowed commands in some paths)

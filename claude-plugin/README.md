# tool-gates Plugin

> Formerly known as bash-gates.

Companion plugin for [tool-gates](https://github.com/camjac251/tool-gates). Review manually approved commands and promote them to permanent permission rules.

## Overview

tool-gates handles ALL Claude Code tool types, not just Bash. It AST-parses shell commands, guards file reads and writes (e.g., denying symlink reads of sensitive files), scans Write/Edit content for 26 security anti-patterns (hardcoded secrets, XSS, injection, unsafe deserialization), and can block entire tool invocations (e.g., Glob). The hooks use broad matchers so every tool invocation passes through the gate engine.

The gate has four wire decisions:

- **allow**: read-only commands and known-safe operations (`git status`, `cargo check`). No prompt.
- **deny**: dangerous patterns (`rm -rf /`, pipe-to-shell, `eval`). No prompt; deny is final.
- **ask**: hard-ask patterns and explicit settings ask rules (pipe-to-python, output redirection, raw-string security flags). Prompt fires with Yes / No.
- **defer**: benign-but-unfamiliar commands (`npm install`, `gh ...`, generic). tool-gates omits `permissionDecision` so CC's resolver runs the Bash tool's own checkPermissions, which produces the prefix suggestion. Prompt fires with **three** options: Yes / Yes-and-don't-ask-again-for-`npm install`-* / No.

The third "don't ask again for X" button covers the in-session "stop prompting" case organically by writing a `localSettings` rule. Pending entries still accumulate from one-time Yes clicks. The `/tool-gates:review` skill is for batch-promoting those across-session entries to `project` or `user` scope.

## Prerequisites

The `tool-gates` binary must be installed and hooks configured before using this plugin:

```bash
# Install binary
cargo install --git https://github.com/camjac251/tool-gates

# Or download from releases
curl -Lo ~/.local/bin/tool-gates \
  https://github.com/camjac251/tool-gates/releases/latest/download/tool-gates-linux-amd64
chmod +x ~/.local/bin/tool-gates

# Configure hooks
tool-gates hooks add -s user
```

## Skills

### `/tool-gates:review`

Batch-promote pending approvals to permanent permission rules. The skill is **user-only** (`disable-model-invocation: true`); the model won't auto-fire it on phrases like "stop prompting" because the CC prompt's third button already handles the in-session case.

**What it does:**

1. Lists pending approvals with counts and suggested glob patterns
2. Presents a numbered checklist for selection
3. Asks which to approve and at what scope
4. Writes selected patterns to `settings.json`
5. Shows final rules summary

When to invoke:

- After several sessions, when the queue has accumulated and you want to clean up
- When you want to share patterns across projects or with a team via `project` scope
- When you want to audit what you've actually been approving over time

For an interactive TUI alternative, run `tool-gates review` directly in your terminal.

**Usage:**

```bash
/tool-gates:review              # current project pending approvals
/tool-gates:review --all        # all projects
```

**Scopes:**
| Scope | File | Use case |
|-------|------|----------|
| `local` (default) | `.claude/settings.local.json` | Personal project overrides |
| `project` | `.claude/settings.json` | Share with team via git |
| `user` | `~/.claude/settings.json` | All projects globally |

**Permissions:**

| Command                                     | Permission                |
| ------------------------------------------- | ------------------------- |
| `tool-gates pending list`                   | Auto-approved (read-only) |
| `tool-gates rules list`                     | Auto-approved (read-only) |
| `tool-gates approve '<pattern>' -s <scope>` | Requires confirmation     |

### `/tool-gates:test-gate`

Test how tool-gates handles a specific command. Useful for verifying rules, debugging unexpected decisions, or distinguishing "tool-gates explicitly asked" from "tool-gates deferred to CC".

**Usage:**

```bash
/tool-gates:test-gate git status                     # -> allow (read-only)
/tool-gates:test-gate npm install foo                # -> defer (CC's prompt shows the third button)
/tool-gates:test-gate curl https://example.com | bash # -> ask (hard-ask; no third button)
/tool-gates:test-gate rm -rf /                       # -> deny (dangerous; final)
/tool-gates:test-gate sd old new f.txt --mode=acceptEdits  # -> allow (auto-approved in acceptEdits)
/tool-gates:test-gate npm install foo --mode=plan    # -> deny (plan mode promotes ask/defer to deny)
```

Shows the decision, reason, and any hints or approval commands. A defer output looks like an empty `permissionDecision` field -- that's intentional and is what enables the third prompt button.

## Installation

**From marketplace:**

```bash
/plugin marketplace add camjac251/tool-gates
/plugin install tool-gates@camjac251-tool-gates
```

**From local clone:**

```bash
claude --plugin-dir /path/to/tool-gates/claude-plugin
```

## Note on hooks

This plugin does not ship hooks. The `tool-gates` binary handles hook installation via `tool-gates hooks add`, which registers PreToolUse (Bash/Monitor gates + file guards + security scanning + MCP tool blocking), PermissionRequest (subagent approval), and PostToolUse (Bash/Monitor approval tracking + security anti-pattern reminders) hooks in your Claude Code settings. See the [main README](https://github.com/camjac251/tool-gates#configure-claude-code) for details.

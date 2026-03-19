# tool-gates Plugin

> Formerly known as bash-gates.

Companion plugin for [tool-gates](https://github.com/camjac251/tool-gates) -- review manually approved commands and promote them to permanent permission rules.

## Overview

tool-gates handles ALL Claude Code tool types, not just Bash. It AST-parses shell commands, guards file reads and writes (e.g., denying symlink reads of sensitive files), scans Write/Edit content for 26 security anti-patterns (hardcoded secrets, XSS, injection, unsafe deserialization), and can block entire tool invocations (e.g., Glob). The hooks use broad matchers so every tool invocation passes through the gate engine.

When you use tool-gates, operations that aren't recognized as safe require manual approval. Over time, these approvals accumulate. This plugin provides the `/tool-gates:review` skill to batch-review those pending approvals and save patterns to your `settings.json` so you don't get prompted again.

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

Review commands you've been manually approving and optionally promote them to permanent rules.

**What it does:**

1. Lists pending approvals with counts and suggested glob patterns
2. Presents a numbered checklist for selection
3. Asks which to approve and at what scope
4. Writes selected patterns to `settings.json`
5. Shows final rules summary

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

Test how tool-gates handles a specific command. Useful for verifying rules or debugging unexpected decisions.

**Usage:**

```bash
/tool-gates:test-gate git status                     # -> allow (read-only)
/tool-gates:test-gate npm install                    # -> ask (installing packages)
/tool-gates:test-gate rm -rf /                       # -> deny (dangerous)
/tool-gates:test-gate sd old new f.txt --mode=acceptEdits  # -> allow (auto-approved)
```

Shows the decision, reason, and any hints or approval commands.

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

This plugin does not ship hooks. The `tool-gates` binary handles hook installation via `tool-gates hooks add`, which registers PreToolUse (Bash gates + file guards + security scanning + MCP tool blocking), PermissionRequest (subagent approval), and PostToolUse (Bash approval tracking + security anti-pattern reminders) hooks in your Claude Code settings. See the [main README](https://github.com/camjac251/tool-gates#configure-claude-code) for details.

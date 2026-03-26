---
description: Review and approve pending tool-gates permissions. Lists commands you've been manually approving with counts and suggested glob patterns, lets you multi-select which to permanently allow, and writes rules to settings.json.
when_to_use: >
  Use when the user wants to allow a command, approve a permission, stop getting prompted for a tool,
  make an approval permanent, always allow something, auto-approve, or batch-approve pending approvals.
  Triggers include "allow", "approve", "permission", "stop prompting", "always allow", "auto approve",
  "pending approvals". NOT for manual settings.json edits, hooks, env vars, or MCP config (use
  update-config).
argument-hint: "[--all]"
---

# Review Pending Approvals

1. Run `tool-gates pending list $ARGUMENTS` to get pending approvals.
   - Default: shows current project's pending approvals only
   - `--all`: shows all projects

2. If no pending approvals, tell the user and stop.

3. Present as a numbered list using the first suggested pattern for each:
   ```
   1. [ ] cargo build --release (12x) -> cargo build:*
   2. [ ] npm install (8x) -> npm install:*
   3. [ ] git push origin main (3x) -> git push:*
   ```
   If multiple patterns are suggested, show the most specific one. Mention alternatives briefly (e.g., "or broader: `cargo:*`").

4. Ask the user which to approve (e.g., "1, 3" or "all") and at what scope:
   - **local** (default): just you, this project (`.claude/settings.local.json`)
   - **project**: shared with team via git (`.claude/settings.json`)
   - **user**: all projects globally (`~/.claude/settings.json`)

5. For each selection, run `tool-gates approve '<pattern>' -s <scope>`.

6. Show final rules with `tool-gates rules list`.

## Safety notes

- Warn about overly broad patterns (e.g., `git:*` allows force-push, `rm:*` allows recursive delete)
- Low-count commands (1-2x) may be one-offs worth skipping
- Prefer specific patterns (`git push:*`) over broad ones (`git:*`) unless the user explicitly wants broad

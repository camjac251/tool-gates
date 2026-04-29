---
description: "Batch-promote frequently-asked tool-gates patterns to permanent permission rules in settings.json. Lists pending approvals (commands the user approved one-time through the prompt, accumulated across sessions), shows counts and suggested glob patterns, multi-selects to write at user/project/local scope. Use after several sessions to triage what's piled up, or to share patterns across projects. For single-prompt approvals the user should usually click 'Yes, and don't ask again for X' in the CC prompt instead -- it covers the in-session case organically since tool-gates defers benign asks. NOT for manual settings.json edits, hooks, env vars, or MCP config (use update-config). NOT for scanning a transcript to build an allowlist from scratch (use fewer-permission-prompts)."
when_to_use: >-
  When the user wants to triage their pending approval queue, batch-promote
  frequently-asked patterns to permanent rules, share approvals across
  projects, or audit what's accumulated. Triggers on 'review pending',
  'pending approvals', 'tool-gates review', 'promote to permanent',
  'clean up the queue', 'share these rules', 'batch approve',
  'audit my approvals'. NOT for in-session "stop asking me about X" --
  that's the CC prompt's third button.
argument-hint: "[--all]"
disable-model-invocation: true
allowed-tools: "Bash(tool-gates pending list:*) Bash(tool-gates rules list:*) Bash(tool-gates approve:*)"
---

# Review Pending Approvals

Promote pending one-time approvals into permanent settings.json rules. Single-shot in-session approvals already work via the CC prompt's "Yes, and don't ask again for X" button (tool-gates defers benign asks so CC's resolver populates the prefix suggestion). This skill is for the cross-session cleanup pass.

## Steps

1. Run `tool-gates pending list $ARGUMENTS` to fetch the queue.
   - Default: current project only
   - `--all`: every project

2. If the queue is empty, tell the user and stop.

3. Present a numbered checklist using the most-specific suggested pattern per row:

   ```
   1. [ ] cargo build --release (12x) -> cargo build:*
   2. [ ] npm install (8x)            -> npm install:*
   3. [ ] git push origin main (3x)   -> git push:*
   ```

   When a row has multiple patterns, mention broader alternatives briefly. Example: "row 3 could use the broader `git:*` if you also want force-push allowed."

4. Ask which to approve and at what scope:
   - **local** (default): just this project, just this user. Writes to `.claude/settings.local.json` (gitignored).
   - **project**: shared with the team via git. Writes to `.claude/settings.json`.
   - **user**: every project on this machine. Writes to `~/.claude/settings.json`.

5. For each selection, run `tool-gates approve '<pattern>' -s <scope>`.

6. Show the final state with `tool-gates rules list`.

## Safety Notes

- Warn on overly broad patterns. `git:*` allows force-push; `rm:*` allows recursive delete; `curl:*` plus a separate output-redirect rule can defeat the soft-ask check.
- Skip rows with count 1-2x unless the user is sure -- those are usually one-offs that won't recur.
- Prefer the most-specific pattern that covers the user's real workflow over the broadest one the queue suggests.
- The compaction logic in `pending.rs` already collapses near-duplicates by broadest-non-program-only pattern (e.g. `npm install foo/bar/baz` -> one row keyed on `npm install:*`). Trust the suggestion; broaden manually only when you've inspected the breakdown.

## Sibling cleanup: ask-rule audit

If the user is here because they *aren't getting* the third "Yes, and don't ask again" prompt button as often as they expect, the cause is usually an old `permissions.ask` rule in their settings.json that's matching ahead of CC's prefix-suggestion path. Different problem from the pending queue, fixed by `tool-gates rules ask-audit`. That command lists ask rules grouped by what removing them would do (redundant / safety floor / indeterminate), with a copy-pasteable remove for each. Mention it once if the user complains about the prompt UI; otherwise stay focused on the queue.

## Gotchas

- The CC prompt's "Yes, and don't ask again for X" writes the rule to `localSettings`. tool-gates' approve-via-skill writes wherever the user picks. If a pattern already exists in localSettings from the prompt button, the user might want `project` or `user` scope here for sharing -- duplicates across scopes are harmless, the more-specific scope wins.
- Pending entries that match a settings allow rule already get filtered at PostToolUse time (handled in `post_tool_use.rs`). If the user sees a row that they think should already be allowed, check `tool-gates rules list` -- the rule may exist but not match the row's exact subcommand shape.
- Plan mode and auto mode never produce pending entries via this skill's flow. Plan mode denies; auto mode lets the classifier decide silently. Both bypass the human-approval tracking path that feeds the queue.

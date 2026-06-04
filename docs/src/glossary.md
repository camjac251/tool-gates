  <p class="breadcrumb"><a href="index.html">Reference</a> / Glossary</p>
  <h1 id="glossary-h1">Glossary</h1>
  <p class="page-lede">Vocabulary that recurs across the docs. Grouped by where the term first appears in the pipeline.</p>
  <div class="sec-head" style="margin-top: var(--s-6)">
    <p class="lbl">Tool names</p>
    <h2>What each client calls each tool type.</h2>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>Term</th><th>Meaning</th></tr>
    </thead>
    <tbody>
      <tr><td><code>Bash</code></td><td>Claude Code's shell-command tool. The dominant input to tool-gates.</td></tr>
      <tr><td><code>Monitor</code></td><td>Claude Code's long-running command tool (background tail, watch loops). Gated by the same rules as Bash.</td></tr>
      <tr><td><code>Read</code> / <code>Write</code> / <code>Edit</code></td><td>Claude Code's file-operation tools. Write and Edit pass through the security-reminders scanner; Read is checked against file guards.</td></tr>
      <tr><td><code>Glob</code> / <code>Grep</code></td><td>Claude Code's file-search tools. Default tool-blocks redirect to <code>fd</code> / <code>rg</code>.</td></tr>
      <tr><td><code>Skill</code> / <code>activate_skill</code></td><td>Slash-command activation. Auto-approved via <code>[[auto_approve_skills]]</code> with project-directory conditions.</td></tr>
      <tr><td><code>apply_patch</code></td><td>Codex CLI's canonical edit tool. Payload is a unified diff in <code>tool_input.command</code>; tool-gates parses out each <code>*** Add/Update/Delete File:</code> header.</td></tr>
      <tr><td><code>run_shell_command</code></td><td>Gemini CLI's shell tool. Same engine as <code>Bash</code> on Claude.</td></tr>
      <tr><td><code>mcp__&lt;server&gt;__&lt;tool&gt;</code></td><td>MCP tool name. Double underscore separator on Claude / Codex; single on Gemini (<code>mcp_*</code>).</td></tr>
    </tbody>
  </table>
  <div class="sec-head">
    <p class="lbl">Hook events</p>
    <h2>When tool-gates fires.</h2>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>Term</th><th>Meaning</th></tr>
    </thead>
    <tbody>
      <tr><td><code>PreToolUse</code></td><td>Claude Code's primary gate. Decides allow / ask / deny before the call executes.</td></tr>
      <tr><td><code>PermissionRequest</code></td><td>Claude Code's subagent gate. Subagents ignore PreToolUse's <code>allow</code>; this hook re-applies the same policy.</td></tr>
      <tr><td><code>PermissionDenied</code></td><td>Auto-mode classifier denied a command; tool-gates checks if its own engine would have allowed it, returns <code>retry: true</code> if so.</td></tr>
      <tr><td><code>PostToolUse</code></td><td>Fires after execution. Tracks successful asks into the pending queue; scans Write/Edit bodies for Tier 2 anti-patterns.</td></tr>
      <tr><td><code>BeforeTool</code> / <code>AfterTool</code></td><td>Gemini CLI's two hooks. BeforeTool covers the main gate path; AfterTool is installed for post-execution context, but current code returns early for tracking and Tier 2 security scanning on Gemini.</td></tr>
    </tbody>
  </table>
  <div class="sec-head">
    <p class="lbl">Permission modes</p>
    <h2>What the assistant is allowed to do without prompting.</h2>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>Term</th><th>Meaning</th></tr>
    </thead>
    <tbody>
      <tr><td><code>default</code></td><td>Normal gate flow. Known-safe commands can allow, dangerous commands deny, and unknown or mutating commands ask or defer; Codex prompt visibility also depends on <code>approval_policy</code>.</td></tr>
      <tr><td><code>plan</code></td><td>Read-only planning mode. tool-gates allows read-only exploration but denies Write/Edit/apply_patch and mutating shell asks, defers, unknowns, and unapproved Claude acceptEdits bases.</td></tr>
      <tr><td><code>acceptEdits</code></td><td>Path-safe file-editing commands can auto-allow inside allowed directories. tool-gates extends this to scoped MCP tools via <code>[[accept_edits_mcp]]</code>; Codex does not currently emit this mode and uses <code>[codex] accept_project_edits</code> separately.</td></tr>
      <tr><td><code>auto</code></td><td>Claude Code's classifier-driven mode. Asks are decided silently by a server-side classifier instead of prompting. tool-gates promotes hard-asks to deny and emits retry hints when classifier denials disagree with the gate engine.</td></tr>
      <tr><td><code>bypassPermissions</code></td><td>Client-specific bypass mode. If the client still invokes hooks, tool-gates hard denies and configured block rules remain the floor.</td></tr>
      <tr><td><code>approval_policy</code> (Codex)</td><td>Codex's own axis for whether a tool-gates <code>ask</code> surfaces a prompt: <code>untrusted</code> prompts for every non-safe command, <code>on-request</code> and <code>on-failure</code> lean on the sandbox and mostly don't, <code>never</code> never asks. See the <a href="codex.html">Codex approval model</a>.</td></tr>
    </tbody>
  </table>
  <div class="sec-head">
    <p class="lbl">Decisions</p>
    <h2>What tool-gates returns.</h2>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>Term</th><th>Meaning</th></tr>
    </thead>
    <tbody>
      <tr><td><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></td><td>Run without prompting. Read-only and known-safe operations.</td></tr>
      <tr><td><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></td><td>Pause for approval (Yes / No, two buttons). Mutations and unknown commands.</td></tr>
      <tr><td><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></td><td>Deny outright regardless of settings.</td></tr>
      <tr><td><span class="pill defer">Defer</span></td><td>Omits <code>permissionDecision</code> entirely. Lets the client's own resolver run, which lights up the third "don't ask again for X" button on Claude Code.</td></tr>
      <tr><td><code>warn</code></td><td>Marker on an <code>ask</code> rule (<code>warn = true</code>) flagging a dangerous-but-recoverable operation (git push --force, git reset --hard). Surfaces in the Security floor cross-cut.</td></tr>
    </tbody>
  </table>
  <div class="sec-head">
    <p class="lbl">Pipeline</p>
    <h2>How the engine works.</h2>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>Term</th><th>Meaning</th></tr>
    </thead>
    <tbody>
      <tr><td>Raw-string pass</td><td>Pre-AST security checks for pipe-to-shell, eval, head/tail pipe, etc. Runs before tree-sitter; catches patterns the parser would treat as syntactically valid.</td></tr>
      <tr><td>Hard-ask</td><td>An <code>ask</code> the raw-string pass promotes to <code>deny</code> when <code>permission_mode == auto</code>. No legitimate use case in autonomous operation.</td></tr>
      <tr><td>Hard-deny</td><td>Patterns gated by <code>features.head_tail_pipe_block</code> (and similar). Block before the gate engine runs.</td></tr>
      <tr><td>tree-sitter</td><td>The Bash AST parser. <code>tree-sitter-bash</code> extracts <code>CommandInfo</code> with program + args + raw form; handles compound commands.</td></tr>
      <tr><td><code>CommandInfo</code></td><td>The internal struct each gate handler receives: <code>program</code>, <code>args</code>, <code>raw</code>.</td></tr>
      <tr><td>Gate</td><td>One of 13 specialised handlers. Most logic is declarative TOML; complex cases use a Rust <code>check_*</code> function.</td></tr>
      <tr><td>Custom handler</td><td>A Rust function in <code>gates/&lt;gate&gt;.rs</code> registered via TOML's <code>[[custom_handlers]]</code>. Handles logic TOML can't express (path normalisation, method-aware HTTP, SQL parsing).</td></tr>
      <tr><td>Strictest wins</td><td>For compound commands (<code>&amp;&amp;</code>, <code>||</code>, <code>|</code>, <code>;</code>) the harshest per-segment decision becomes the whole-command decision. block &gt; ask &gt; allow &gt; skip.</td></tr>
    </tbody>
  </table>
  <div class="sec-head">
    <p class="lbl">Storage and state</p>
    <h2>Where state lives.</h2>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>Term</th><th>Meaning</th></tr>
    </thead>
    <tbody>
      <tr><td><code>~/.claude/settings.json</code></td><td>Claude Code permission rules. tool-gates respects every explicit allow / deny / ask before applying its own gate decision.</td></tr>
      <tr><td><code>~/.gemini/settings.json</code></td><td>Gemini CLI hook configuration.</td></tr>
      <tr><td><code>~/.codex/hooks.json</code></td><td>Codex CLI hook configuration.</td></tr>
      <tr><td><code>~/.config/tool-gates/config.toml</code></td><td>User configuration for feature toggles, tool blocking, MCP / Skill auto-approval, file guards, hints, cache, git aliases.</td></tr>
      <tr><td><code>~/.cache/tool-gates/pending.jsonl</code></td><td>The pending-approval queue. Successful asks land here for promotion via <code>tool-gates review</code>.</td></tr>
      <tr><td><code>~/.cache/tool-gates/tracking.json</code></td><td>PreToolUse → PostToolUse correlation (24h TTL).</td></tr>
      <tr><td><code>~/.cache/tool-gates/available-tools.json</code></td><td>Modern-CLI tool detection cache (7-day TTL).</td></tr>
      <tr><td><code>tool_use_id</code></td><td>Claude Code's per-call identifier used to correlate PreToolUse with PostToolUse. Gemini doesn't provide one (so tracking is Claude-only).</td></tr>
    </tbody>
  </table>
  <div class="sec-head">
    <p class="lbl">Other</p>
    <h2>Less common but worth knowing.</h2>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>Term</th><th>Meaning</th></tr>
    </thead>
    <tbody>
      <tr><td>Subagent</td><td>A delegated Claude Code agent. Ignores PreToolUse's <code>allow</code>; the PermissionRequest hook re-applies policy.</td></tr>
      <tr><td>Worktree</td><td>A <code>.claude/worktrees/&lt;id&gt;</code> directory used for subagent isolation. tool-gates auto-approves Edit/Write inside the worktree's cwd.</td></tr>
      <tr><td>Pattern specificity</td><td>Length of the non-wildcard prefix in a settings.json pattern. When ask and allow both match, the longer wins; ties go to ask.</td></tr>
      <tr><td><code>$HOME</code> expansion</td><td>Settings patterns containing <code>$HOME</code> are expanded to the actual home directory before matching.</td></tr>
      <tr><td>Drift gate</td><td>A CI step that runs <code>git diff --exit-code</code> on generated files. Fails the build if a TOML edit didn't trigger a re-run of the generator.</td></tr>
      <tr><td>Tier 1 / 2 / 3</td><td>The three security-reminder severities. T1 denies source writes before they land and warns on doc-file secrets after write; T2 nudges after via system-reminder; T3 informs via additionalContext. See the Security reminders page.</td></tr>
    </tbody>
  </table>

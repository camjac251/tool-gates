  <p class="breadcrumb"><a href="index.html">Core Concepts</a> / Hook Model</p>
  <h1 id="hook-h1">Hook Model</h1>
  <p class="page-lede">Claude Code exposes many hook points; tool-gates registers on the four that gate tool calls. Each one closes a gap the others can't. Gemini CLI and Codex CLI expose fewer of them; the engine routes around what's missing.</p>
  <p class="note">This page shows when each hook runs. Mode-specific policy lives one layer up in <a href="modes.html">Permission Modes</a>.</p>
  <div class="lifecycle" aria-label="Tool-call lifecycle through tool-gates on Claude Code">
    <div class="lc-bar">
      <span class="lights"><i></i><i></i><i></i></span>
      <span class="lc-label">tool-call lifecycle · Claude Code</span>
    </div>
    <div class="lc-track">
      <div class="lc-node start">
        <span class="lc-icon">●</span>
        <div class="lc-title">Tool call</div>
        <div class="lc-sub">Bash · Monitor · Write · Edit · MCP · Skill. The assistant emits a tool-use event.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node hook">
        <span class="lc-icon">▸</span>
        <span class="lc-tag">PreToolUse</span>
        <div class="lc-title">Decide</div>
        <div class="lc-sub">Shell parsed with tree-sitter and routed to the right gate. Returns <code>allow</code>, <code>ask</code>, or <code>deny</code>. Modern-CLI hints, file guards, and Tier 1 source-file secret denies ride here.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node hook conditional">
        <span class="lc-icon">▸</span>
        <span class="lc-tag">PermissionRequest</span>
        <div class="lc-when">fires for subagents</div>
        <div class="lc-title">Re-decide</div>
        <div class="lc-sub">Subagents ignore PreToolUse's <code>allow</code>. This hook re-runs the gate so the same policy applies to delegated work.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node hook conditional">
        <span class="lc-icon">▸</span>
        <span class="lc-tag">PermissionDenied</span>
        <div class="lc-when">fires when the auto-mode classifier denies</div>
        <div class="lc-title">Retry hint</div>
        <div class="lc-sub">If the classifier denied a call tool-gates would have allowed (e.g. <code>cargo check</code>), returns <code>retry: true</code> so the model gets a second shot.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node exec">
        <span class="lc-icon">▷</span>
        <div class="lc-title">Execute</div>
        <div class="lc-sub">The tool call runs.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node hook">
        <span class="lc-icon">▸</span>
        <span class="lc-tag">PostToolUse</span>
        <div class="lc-title">Track + scan</div>
        <div class="lc-sub">Successful asks queue for promotion to <code>settings.json</code>. Write/Edit bodies pass the Tier 2 anti-pattern scanner; nudges ride on <code>additionalContext</code>.</div>
      </div>
    </div>
  </div>
  <div class="sec-head" style="margin-top:var(--s-7)">
    <p class="lbl">Gemini CLI</p>
    <h2>Two hooks. No subagent, no classifier.</h2>
  </div>
  <div class="lifecycle" aria-label="Tool-call lifecycle on Gemini CLI">
    <div class="lc-bar">
      <span class="lights"><i></i><i></i><i></i></span>
      <span class="lc-label">tool-call lifecycle · Gemini CLI · v0.36.0+</span>
    </div>
    <div class="lc-track">
      <div class="lc-node start">
        <span class="lc-icon">●</span>
        <div class="lc-title">Tool call</div>
        <div class="lc-sub"><code>run_shell_command</code>, <code>write_file</code>, <code>replace</code>, <code>read_file</code>, <code>glob</code>, <code>grep_search</code>, <code>activate_skill</code>, <code>mcp_*</code>. Auto-detected from <code>hook_event_name</code>.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node hook">
        <span class="lc-icon">▸</span>
        <span class="lc-tag">BeforeTool</span>
        <div class="lc-title">Decide</div>
        <div class="lc-sub">Same engine as Claude's PreToolUse: tree-sitter parse, gate dispatch, settings merge. Modern-CLI hints, file guards, and Tier 1 source-file secret denies ride here. Wire format: flat <code>decision</code> + <code>reason</code>; tool-gates emits <code>"block"</code> for hard blocks, Gemini also accepts <code>"deny"</code>, and exit code 2 blocks. <code>ask</code> requires Gemini CLI v0.36.0+.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node exec">
        <span class="lc-icon">▷</span>
        <div class="lc-title">Execute</div>
        <div class="lc-sub">The tool call runs.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node hook">
        <span class="lc-icon">▸</span>
        <span class="lc-tag">AfterTool</span>
        <div class="lc-title">Post context</div>
        <div class="lc-sub">Installed for post-execution context. Current Gemini handling returns early for shell tracking because Gemini does not provide <code>tool_use_id</code>, and Tier 2 write scanning is not yet plumbed for Gemini output.</div>
      </div>
    </div>
  </div>
  <div class="sec-head" style="margin-top:var(--s-7)">
    <p class="lbl">Codex CLI</p>
    <h2>Three hooks. Strict wire format; hints move to PostToolUse.</h2>
  </div>
  <div class="lifecycle" aria-label="Tool-call lifecycle on Codex CLI">
    <div class="lc-bar">
      <span class="lights"><i></i><i></i><i></i></span>
      <span class="lc-label">tool-call lifecycle · Codex CLI</span>
    </div>
    <div class="lc-track">
      <div class="lc-node start">
        <span class="lc-icon">●</span>
        <div class="lc-title">Tool call</div>
        <div class="lc-sub"><code>Bash</code>, <code>apply_patch</code> (carries the unified diff in <code>tool_input.command</code>), <code>mcp__*</code>. Selected via <code>--client codex</code> baked into the hook command; Codex shares Claude's event names.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node hook">
        <span class="lc-icon">▸</span>
        <span class="lc-tag">PreToolUse</span>
        <div class="lc-title">Decide (deny only)</div>
        <div class="lc-sub">Codex's parser rejects <code>permissionDecision: "allow"</code> and <code>"ask"</code>, so tool-gates emits empty stdout for those and hands the decision back to Codex. Only hard blocks emit <code>permissionDecision: "deny"</code>. Whether the user is then prompted is governed by Codex's <code>approval_policy</code>, not tool-gates; see the <a href="codex.html">Codex approval model</a>.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node hook conditional">
        <span class="lc-icon">▸</span>
        <span class="lc-tag">PermissionRequest</span>
        <div class="lc-when">on confirmation prompt</div>
        <div class="lc-title">Allow / deny only</div>
        <div class="lc-sub">Codex accepts only <code>hookSpecificOutput.decision.behavior</code> (<code>allow</code> or <code>deny</code>) plus an optional deny <code>message</code>. Other fields (like <code>addDirectories</code>, <code>updatedInput</code>, <code>updatedPermissions</code>, and <code>interrupt</code>) are not just dropped: they are treated as unsupported, causing Codex's parser to reject the hook output as invalid. tool-gates actively strips them to maintain compatibility.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node exec">
        <span class="lc-icon">▷</span>
        <div class="lc-title">Execute</div>
        <div class="lc-sub">The tool call runs.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node hook">
        <span class="lc-icon">▸</span>
        <span class="lc-tag">PostToolUse</span>
        <div class="lc-title">Track, scan, hint</div>
        <div class="lc-sub">Tier 2 anti-pattern nudges land here. Modern-CLI hints and Tier 3 warnings also ride this hook on Codex (a tool-gates routing choice; Codex itself accepts <code>additionalContext</code> on PreToolUse too). Codex's <code>PostToolUse</code> rejects fields like <code>updatedMCPToolOutput</code> as unsupported, which causes validation failures. tool-gates strips them dynamically. No PermissionDenied event because Codex has no auto-mode classifier yet.</div>
      </div>
    </div>
  </div>
  <p class="note">
    <svg class="alert" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
    <span><b>On Codex, a tool-gates <code>ask</code> only becomes a prompt under <code>approval_policy = "untrusted"</code>.</b> Codex's built-in safe-read list, the execpolicy lever that routes those reads through tool-gates, and the two settings that silently disable prompting are covered in the <a href="codex.html">Codex approval model</a>.</span>
  </p>
  <div class="sec-head" style="margin-top:var(--s-7)">
    <p class="lbl">Reference</p>
    <h2>Why four hooks?</h2>
    <p>Each one closes a specific gap the others leave open. None is redundant.</p>
  </div>
  <div class="hook-cards">
    <article class="hook-card">
      <h4>PreToolUse</h4>
      <p>The main gate. Bash / Monitor, Read / Write / Edit, Glob / Grep, MCP, and Skill calls pass through and get a decision back.</p>
      <p class="hook-detail">Also injects modern-CLI hints via <code>additionalContext</code>, blocks Tier 1 secrets in source Write/Edit bodies, and enforces file guards on symlinked AI-config files like <code>CLAUDE.md</code> and <code>.cursorrules</code>.</p>
    </article>
    <article class="hook-card">
      <h4>PermissionRequest</h4>
      <p>Claude's subagents ignore PreToolUse's <code>allow</code>. This hook re-runs the gate for them so the same policy applies to delegated work.</p>
      <p class="hook-detail">Also fires when Claude's resolver wants to ask about a path outside cwd; tool-gates can promote that to <code>deny</code> if the engine knows the call is dangerous.</p>
    </article>
    <article class="hook-card">
      <h4>PermissionDenied</h4>
      <p>Auto mode runs a server-side classifier instead of prompting the human. The classifier sometimes denies calls tool-gates would allow.</p>
      <p class="hook-detail">tool-gates re-checks. If the engine agrees the call is safe, this hook returns <code>retry: true</code> and the model tries again. Requires Claude Code 2.1.88+.</p>
    </article>
    <article class="hook-card">
      <h4>PostToolUse</h4>
      <p>Fires after the call runs. Used for approval learning (queue successful asks) and Tier 2 anti-pattern nudges on Write/Edit content.</p>
      <p class="hook-detail">On Codex, tool-gates currently carries Tier 3 informational warnings and modern-CLI hints here rather than on PreToolUse.</p>
    </article>
  </div>
  <p class="note">
    <svg class="alert" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
    <span><b>Reasoning Effort level.</b> In newer versions of the CLI, an <code>effort</code> field (Zod object <code>{ level: "adaptive" | "low" | "medium" | "high" }</code>) is injected into all hook event payloads, conveying the active turn's reasoning intensity.</span>
  </p>
  <p class="note">
    <svg class="alert" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
    <span><b>Gemini CLI has only BeforeTool and AfterTool.</b> Codex CLI has no PermissionDenied event (no auto-mode classifier yet). The engine routes around what's missing. Gemini carries modern-CLI hints and Tier 3 warnings on BeforeTool; Codex moves them to PostToolUse because tool-gates emits empty stdout for non-deny PreToolUse decisions.</span>
  </p>

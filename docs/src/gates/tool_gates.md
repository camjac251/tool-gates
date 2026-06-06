<div class="gate-head">
  <p class="breadcrumb"><a href="../index.html">Gates</a> / Tool Gates CLI</p>
  <h1>Tool Gates CLI gate</h1>
  <div class="gate-meta">
    <span class="tag">priority <b>23</b></span>
    <span class="tag">unknown <b>ask</b></span>
    <span class="tag">aliases <b>bash-gates</b> → <b>tool-gates</b></span>
  </div>

  <div class="summary" aria-label="Rule counts at a glance">
    <div class="seg-bar" role="img" aria-label="9 allow, 6 ask, 0 block">
      <div class="seg allow" style="flex: 9"></div>
      <div class="seg ask"   style="flex: 6"></div>
      <div class="seg block" style="flex: 0"></div>
    </div>
    <div class="counts">
      <span class="ca"><i></i><b>9</b> allow</span>
      <span class="cas"><i></i><b>6</b> ask</span>
      <span class="cb"><i></i><b>0</b> block</span>
    </div>
  </div>

  <p class="gate-lede">tool-gates protects itself. Read-only queries (inspecting the pending queue, listing rules, hook status, doctor) skip prompting. Writes to settings files or the cache ask. See the <a href="../cli.html">CLI reference</a> for the full subcommand set.</p>
</div>

<div class="chips" role="group" aria-label="Filter rules by decision">
  <button class="chip all"   data-filter="all"   aria-pressed="true"><i></i>All <span class="n">15</span></button>
  <button class="chip allow" data-filter="allow" aria-pressed="false"><i></i>Allow <span class="n">9</span></button>
  <button class="chip ask"   data-filter="ask"   aria-pressed="false"><i></i>Ask <span class="n">6</span></button>
  <button class="chip block" data-filter="block" aria-pressed="false"><i></i>Block <span class="n">0</span></button>
</div>

<div class="rule-card">
  <header>
    <h2>Allowed · inspection</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/tool_gates.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/tool_gates.toml#allow
    </a>
    <span class="count">9 patterns</span>
  </header>

<div class="rule-row" data-decision="allow" id="tool_gates-tool-gates-pending-list">
  <div class="rule-cmd"><span class="prog">tool-gates</span> pending list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspect the pending-approvals queue.</div>
</div>
<div class="rule-row" data-decision="allow" id="tool_gates-tool-gates-rules-list">
  <div class="rule-cmd"><span class="prog">tool-gates</span> rules list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">List active permission rules.</div>
</div>
<div class="rule-row" data-decision="allow" id="tool_gates-tool-gates-hooks-status">
  <div class="rule-cmd"><span class="prog">tool-gates</span> hooks status</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Report hook wiring per client / scope.</div>
</div>
<div class="rule-row" data-decision="allow" id="tool_gates-tool-gates-hooks-json">
  <div class="rule-cmd"><span class="prog">tool-gates</span> hooks json</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Report hook wiring per client / scope.</div>
</div>
<div class="rule-row" data-decision="allow" id="tool_gates-tool-gates-doctor">
  <div class="rule-cmd"><span class="prog">tool-gates</span> doctor</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Health check. Read-only; safe to run anytime.</div>
</div>
<div class="rule-row" data-decision="allow" id="tool_gates-tool-gates-rules-ask-audit">
  <div class="rule-cmd"><span class="prog">tool-gates</span> rules ask-audit</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Categorise <code>permissions.ask</code> rules. Read-only listing without <code>--apply</code>.</div>
</div>
<div class="rule-row" data-decision="allow" id="tool_gates-tool-gates-help-h">
  <div class="rule-cmd"><span class="prog">tool-gates</span> <span class="flag">--help</span> <span class="flag">-h</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags.</div>
</div>
<div class="rule-row" data-decision="allow" id="tool_gates-tool-gates-version-v">
  <div class="rule-cmd"><span class="prog">tool-gates</span> <span class="flag">--version</span> <span class="flag">-V</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags.</div>
</div>
<div class="rule-row" data-decision="allow" id="tool_gates-tool-gates-tools-status">
  <div class="rule-cmd"><span class="prog">tool-gates</span> <span class="flag">--tools-status</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags.</div>
</div>
</div>

<div class="rule-card">
  <header>
    <h2>Asks first · mutations</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/tool_gates.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/tool_gates.toml#ask
    </a>
    <span class="count">6 patterns</span>
  </header>

<div class="rule-row" data-decision="ask" id="tool_gates-tool-gates-approve">
  <div class="rule-cmd"><span class="prog">tool-gates</span> approve</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adds a permanent permission rule to a Claude/Gemini/Codex settings file. Future matching tool calls auto-allow without prompting.</div>
</div>
<div class="rule-row" data-decision="ask" id="tool_gates-tool-gates-rules-remove">
  <div class="rule-cmd"><span class="prog">tool-gates</span> rules remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes a permission rule from a settings file. Future matching tool calls revert to the default gate decision.</div>
</div>
<div class="rule-row" data-decision="ask" id="tool_gates-tool-gates-pending-clear">
  <div class="rule-cmd"><span class="prog">tool-gates</span> pending clear</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Empties <code>~/.cache/tool-gates/pending.jsonl</code>. Drops every queued approval; cannot be undone.</div>
</div>
<div class="rule-row" data-decision="ask" id="tool_gates-tool-gates-hooks-add">
  <div class="rule-cmd"><span class="prog">tool-gates</span> hooks add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Writes tool-gates hook entries into a Claude/Gemini/Codex settings file. Changes how every future tool call in that scope is gated.</div>
</div>
<div class="rule-row" data-decision="ask" id="tool_gates-tool-gates-review">
  <div class="rule-cmd"><span class="prog">tool-gates</span> review</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Opens the interactive approval TUI. Selecting Approve writes a permanent permission rule to a settings file.</div>
</div>
<div class="rule-row" data-decision="ask" id="tool_gates-tool-gates-refresh-tools">
  <div class="rule-cmd"><span class="prog">tool-gates</span> <span class="flag">--refresh-tools</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Re-scans the system for modern CLI tools (bat, rg, fd, etc.) and rewrites <code>~/.cache/tool-gates/available-tools.json</code>. Used to surface hints.</div>
</div>
</div>

  <p class="breadcrumb"><a href="index.html">Core Concepts</a> / Permission Modes</p>
  <h1 id="modes-h1">Permission Modes</h1>
  <p class="page-lede">Clients send <code>permission_mode</code> with hook events, but each client gives that value a different shape. tool-gates treats mode as a policy layer above the normal gate decision so the same shell rule can behave differently in planning, batch-edit, and classifier-driven sessions.</p>

  <section aria-labelledby="mode-matrix">
    <div class="sec-head">
      <p class="lbl">Mode matrix</p>
      <h2 id="mode-matrix">What changes by mode.</h2>
    </div>
    <table class="data-table">
      <thead>
        <tr><th>Mode</th><th>Clients</th><th>tool-gates behavior</th></tr>
      </thead>
      <tbody>
        <tr>
          <td><code>default</code></td>
          <td>Claude Code, Codex CLI, Antigravity CLI, Gemini CLI</td>
          <td>Normal gate flow. Known-safe commands can allow, dangerous commands deny, and unknown or mutating commands ask or defer. On Codex, whether an ask becomes a visible prompt also depends on <code>approval_policy</code>. On Antigravity, a hook allow does not suppress a prompt (agy keeps the strictest decision); its native <code>permissions.allow</code> does.</td>
        </tr>
        <tr>
          <td><code>acceptEdits</code></td>
          <td>Claude Code; any client that sends the exact string</td>
          <td>Path-safe file-editing commands can auto-allow inside the project and configured additional directories. Deny rules, ask rules, guarded AI config paths, sensitive paths, and tool block rules still win. <code>[[accept_edits_mcp]]</code> can extend this to scoped MCP tools. Codex does not currently emit this mode; its project-edit shortcut is configured separately under <code>[codex]</code>.</td>
        </tr>
        <tr>
          <td><code>auto</code></td>
          <td>Claude Code</td>
          <td>Allowed commands skip the classifier and run. Denied commands stay denied. Asks go to Claude Code's classifier instead of a human prompt. tool-gates promotes high-risk asks such as pipe-to-shell and <code>eval</code> to deny, avoids adding classifier approvals to the human pending queue, and emits PermissionDenied retry hints when the classifier rejects a command the gate engine would allow.</td>
        </tr>
        <tr>
          <td><code>plan</code></td>
          <td>Claude Code</td>
          <td>Read-only planning stays allowed, but mutations are blocked. Mutating shell asks, defers, unknowns, and unapproved Claude acceptEdits bases deny instead of reaching a prompt. Settings allow rules and acceptEdits shortcuts do not turn mutations into allows while the client is in plan mode.</td>
        </tr>
        <tr>
          <td><code>bypassPermissions</code></td>
          <td>Client-specific; Codex emits this value today</td>
          <td>No special auto-allow path inside tool-gates. If the client still invokes hooks, hard denies and configured block rules remain the floor. Client-native bypass behavior controls which prompts or sandbox checks run outside tool-gates.</td>
        </tr>
        <tr>
          <td><code>dontAsk</code></td>
          <td>Simulator and compatibility inputs</td>
          <td>No dedicated branch in the current gate pipeline. tool-gates treats it like the normal gate path; the client decides what reaches hooks and how prompts are displayed.</td>
        </tr>
      </tbody>
    </table>
  </section>

  <section aria-labelledby="codex-axis">
    <div class="sec-head">
      <p class="lbl">Codex axis</p>
      <h2 id="codex-axis">Codex approval policy is separate from mode.</h2>
    </div>
    <div class="hook-cards">
      <article class="hook-card">
        <h3><code>untrusted</code></h3>
        <p>Codex prompts for every non-safe command. This is the closest fit to Claude Code's default permission UI when tool-gates returns ask or defer.</p>
      </article>
      <article class="hook-card">
        <h3><code>on-request</code> / <code>on-failure</code></h3>
        <p>Codex leans on the sandbox and asks only when a command requests elevation or when a sandboxed attempt fails. tool-gates still evaluates the hook event it receives, but an ask may not surface as an immediate prompt.</p>
      </article>
      <article class="hook-card">
        <h3><code>never</code></h3>
        <p>Codex never asks the operator for approval. tool-gates deny decisions still matter for hook events, but ask/defer behavior is constrained by Codex's no-prompt policy.</p>
      </article>
    </div>
    <p class="note">Use the <a href="codex.html">Codex approval model</a> for the full wire-format details, including why Codex hooks use the explicit <code>--client codex</code> flag and why non-deny PreToolUse output is silent.</p>
  </section>

  <section aria-labelledby="mode-shortcuts">
    <div class="sec-head">
      <p class="lbl">Rule of thumb</p>
      <h2 id="mode-shortcuts">Pick the smallest mode that matches the work.</h2>
    </div>
    <div class="alert">
      <p><strong>Plan</strong> is for exploration only. <strong>acceptEdits</strong> is for path-safe batch edits where deny and ask rules still matter. <strong>auto</strong> is for deterministic gate decisions first, then classifier review of remaining asks.</p>
    </div>
    <p class="note">Related pages: <a href="hook-model.html">Hook model</a>, <a href="auto-mode.html">Auto mode</a>, <a href="codex.html">Codex approval model</a>, and <a href="configuration.html">Configuration</a>.</p>
  </section>

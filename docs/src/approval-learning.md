  <p class="breadcrumb"><a href="index.html">Core Concepts</a> / Approval Learning</p>
  <h1 id="approval-h1">Approval Learning</h1>
  <p class="page-lede">When you click Yes on a tool-gates ask, the command joins a pending queue. The <code>tool-gates review</code> TUI lets you promote any of those patterns to a permanent rule in <code>settings.json</code>, so future matching calls auto-allow without prompting.</p>
  <div class="sec-head" style="margin-top: var(--s-6)">
    <p class="lbl">Lifecycle</p>
    <h2>Ask once, promote once, never see it again.</h2>
  </div>
  <div class="lifecycle" aria-label="Approval-learning lifecycle">
    <div class="lc-bar">
      <span class="lights"><i></i><i></i><i></i></span>
      <span class="lc-label">approval learning</span>
    </div>
    <div class="lc-track">
      <div class="lc-node start">
        <span class="lc-icon">●</span>
        <div class="lc-title">Ask</div>
        <div class="lc-sub">tool-gates returns <code>ask</code>; you click Yes. The command executes.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node hook">
        <span class="lc-icon">▸</span>
        <span class="lc-tag">PostToolUse</span>
        <div class="lc-title">Track</div>
        <div class="lc-sub">On successful execution, the (project, command) pair lands in <code>~/.cache/tool-gates/pending.jsonl</code>.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node hook">
        <span class="lc-icon">▸</span>
        <span class="lc-tag">tool-gates review</span>
        <div class="lc-title">Promote</div>
        <div class="lc-sub">You open the TUI (or run <code>tool-gates approve</code> directly). Pick the pattern and scope; tool-gates writes a permission rule into <code>settings.json</code>.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node exec">
        <span class="lc-icon">▷</span>
        <div class="lc-title">Auto-allow</div>
        <div class="lc-sub">Future matching calls return <code>allow</code> with no prompt.</div>
      </div>
    </div>
  </div>
  <div class="sec-head">
    <p class="lbl">CLI</p>
    <h2>Inspect and promote without the TUI.</h2>
  </div>
  <p class="step-prose">Inspect the pending queue:</p>
  <pre class="code-block"><span class="prompt">$</span> tool-gates pending list</pre>
  <pre class="code-block"><span class="prompt">$</span> tool-gates pending list --project</pre>
  <pre class="code-block"><span class="prompt">$</span> tool-gates pending list --json</pre>

  <p class="step-prose">Promote a pattern directly:</p>
  <pre class="code-block"><span class="prompt">$</span> tool-gates approve 'npm install*' -s local</pre>
  <pre class="code-block"><span class="prompt">$</span> tool-gates approve 'cargo*' -s user</pre>

  <p class="step-prose">Manage existing rules:</p>
  <pre class="code-block"><span class="prompt">$</span> tool-gates rules list</pre>
  <pre class="code-block"><span class="prompt">$</span> tool-gates rules remove 'pattern' -s local</pre>

  <p class="step-prose">Inspect ask rules that suppress the third "don't ask again" button:</p>
  <pre class="code-block"><span class="prompt">$</span> tool-gates rules ask-audit</pre>
  <p class="step-prose">Interactively audit and clean up ask rules via a TUI checklist:</p>
  <pre class="code-block"><span class="prompt">$</span> tool-gates rules ask-audit --apply</pre>
  <div class="sec-head">
    <p class="lbl">Scopes</p>
    <h2>Where the rule lives.</h2>
    <p>Pick the scope that matches who should see this rule.</p>
  </div>
  <div class="install-clients">
    <article class="install-client">
      <header>
        <h3>local</h3>
        <span class="hooks-count">per-machine</span>
      </header>
      <p>Personal overrides on this checkout only. Not committed.</p>
      <p class="settings-path">.claude/settings.local.json</p>
    </article>
    <article class="install-client">
      <header>
        <h3>project</h3>
        <span class="hooks-count">team baseline</span>
      </header>
      <p>Shared rules for everyone working on this repo. Committed.</p>
      <p class="settings-path">.claude/settings.json</p>
    </article>
    <article class="install-client">
      <header>
        <h3>user</h3>
        <span class="hooks-count">global</span>
      </header>
      <p>Personal defaults across every project on this machine.</p>
      <p class="settings-path">~/.claude/settings.json</p>
    </article>
  </div>
  <div class="sec-head">
    <p class="lbl">Review TUI</p>
    <h2>Or promote interactively.</h2>
    <p>Run <code>tool-gates review</code> for a keyboard-first dashboard: pending commands with colour-and-symbol-coded segments, a blast-radius meter that escalates friction as a rule widens, and tabs for managing the <code>allow</code> / <code>deny</code> rules you already have. Full walkthrough and keymap live on the <a href="review-tui.html">Review TUI</a> page.</p>
  </div>
  <p class="note">
    <svg class="alert" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
    <span><b>Only human approvals queue.</b> Under auto mode the classifier decides silently; nothing it approves goes into <code>pending.jsonl</code>. The review queue stays focused on patterns you explicitly clicked through.</span>
  </p>

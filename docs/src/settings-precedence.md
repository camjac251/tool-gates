  <nav class="breadcrumb" aria-label="Breadcrumb">
    <ol>
      <li><a href="index.html">tool-gates</a></li>
      <li>How It Decides</li>
      <li aria-current="page">Settings Precedence</li>
    </ol>
  </nav>
  <h1 id="settings-h1">Settings Precedence</h1>
  <p class="page-lede">Four settings files contribute to the final permission set. Higher-priority files win when keys conflict. tool-gates respects every explicit rule before applying its own gate decisions. One enterprise flag narrows that set to a single file.</p>
  <div class="sec-head" style="margin-top: var(--s-6)">
    <p class="lbl">File priority</p>
    <h2>Where rules live.</h2>
    <p>Top of the list wins. The same precedence applies on macOS and Linux.</p>
  </div>
  <div class="data-table-frame">
    <div class="data-table-scroll" data-table-scroll>
      <table class="data-table">
    <thead>
      <tr><th>Priority</th><th>Location</th><th>Use case</th></tr>
    </thead>
    <tbody>
      <tr>
        <td><span class="level-badge top"><span class="n">1</span> highest</span></td>
        <td>
          <code>/etc/claude-code/managed-settings.json</code> (Linux)<br/>
          <code>/Library/Application Support/ClaudeCode/managed-settings.json</code> (macOS)<br/>
          <code>C:\Program Files\ClaudeCode\managed-settings.json</code> (Windows)
        </td>
        <td>Enterprise managed. Locked by IT; overrides everything below, and can exclude it entirely.</td>
      </tr>
      <tr>
        <td><span class="level-badge"><span class="n">2</span></span></td>
        <td><code>.claude/settings.local.json</code></td>
        <td>Local project overrides. Per-developer, not committed.</td>
      </tr>
      <tr>
        <td><span class="level-badge"><span class="n">3</span></span></td>
        <td><code>.claude/settings.json</code></td>
        <td>Shared project rules. Committed; team baseline.</td>
      </tr>
      <tr>
        <td><span class="level-badge"><span class="n">4</span> lowest</span></td>
        <td><code>~/.claude/settings.json</code></td>
        <td>Personal defaults across every project on this machine.</td>
      </tr>
    </tbody>
  </table>
    </div>
  </div>
  <div class="sec-head">
    <p class="lbl">Managed-only resolution</p>
    <h2>When the enterprise file is the whole ruleset.</h2>
    <p>When the managed settings document sets <code>allowManagedPermissionRulesOnly</code> to boolean <code>true</code>, tool-gates evaluates Claude against that document alone. The user, project, and local files are not loaded into the effective permission set at all.</p>
  </div>
  <div class="data-table-frame">
    <div class="data-table-scroll" data-table-scroll>
      <table class="data-table">
    <thead>
      <tr><th>Aspect</th><th>Behavior</th></tr>
    </thead>
    <tbody>
      <tr>
        <td>What is excluded</td>
        <td>Every lower-scope entry: <code>allow</code>, <code>ask</code>, <code>deny</code>, and <code>additionalDirectories</code>. The flag draws a source boundary, not a grants-only filter, so a personal <code>deny</code> rule stops participating alongside a personal <code>allow</code>.</td>
      </tr>
      <tr>
        <td>Allowed directories</td>
        <td>The invocation <code>cwd</code> plus the managed document's <code>additionalDirectories</code>. A directory listed only in a lower scope does not become writable or auto-approvable.</td>
      </tr>
      <tr>
        <td>Empty managed permissions</td>
        <td>Resolve to no rules. tool-gates does not fall back to a lower scope because the managed file has nothing to say.</td>
      </tr>
      <tr>
        <td>Malformed managed permissions</td>
        <td>Resolve to no rules. A document that is valid JSON and asserts the flag keeps the boundary even when its <code>permissions</code> block cannot be parsed.</td>
      </tr>
      <tr>
        <td>Who can set it</td>
        <td>Only the managed document at the platform path above. The same key in a user, project, or local file has no authority to turn managed-only resolution on or off, and a non-boolean value leaves the four-source merge in place.</td>
      </tr>
      <tr>
        <td>Other clients</td>
        <td>Codex, Antigravity, and deprecated Gemini keep the four-source merge whatever the flag says. The flag is a Claude Code setting, and tool-gates only applies it to Claude.</td>
      </tr>
      <tr>
        <td>Safety floor</td>
        <td>Unchanged. A managed <code>allow</code> does not unlock a destructive command or a raw-string pattern such as pipe-to-shell.</td>
      </tr>
    </tbody>
  </table>
    </div>
  </div>
  <p class="step-prose">Nested evaluation inherits the same boundary. Mise task expansion, package-script expansion, compound sub-command checks, and the <code>acceptEdits</code> directory check all resolve settings under the client that started the invocation, so none of them can reload a lower scope mid-decision.</p>
  <p class="step-prose">With the flag absent or <code>false</code>, everything below applies exactly as it always has.</p>
  <div class="sec-head">
    <p class="lbl">Interaction</p>
    <h2>How tool-gates respects your rules.</h2>
    <p>Your explicit settings.json rules override tool-gates' built-in decision in every case but one: a dangerous call stays blocked even if a rule allows it.</p>
  </div>
  <div class="data-table-frame">
    <div class="data-table-scroll" data-table-scroll>
      <table class="data-table">
    <thead>
      <tr><th>settings.json</th><th>tool-gates</th><th>Result</th></tr>
    </thead>
    <tbody>
      <tr>
        <td><code>deny</code> rule</td>
        <td>any</td>
        <td><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Deny</span> &nbsp; explicit deny respected.</td>
      </tr>
      <tr>
        <td><code>ask</code> rule</td>
        <td>any</td>
        <td><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span> &nbsp; two-button prompt (Yes / No).</td>
      </tr>
      <tr>
        <td><code>allow</code> rule</td>
        <td>dangerous</td>
        <td><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Deny</span> &nbsp; tool-gates still blocks the dangerous floor.</td>
      </tr>
      <tr>
        <td><code>allow</code> or none</td>
        <td>safe</td>
        <td><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></td>
      </tr>
      <tr>
        <td>none</td>
        <td>unknown</td>
        <td><span class="pill defer">Defer</span> in default / acceptEdits; <span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span> in auto; <span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span> in plan unless the gate proves the command is read-only.</td>
      </tr>
    </tbody>
  </table>
    </div>
  </div>
  <p class="step-prose">When a <code>permissions.deny</code> rule matches, the decision reason names the exact <code>Bash(...)</code> pattern. This lets the agent identify the configured boundary that rejected the command instead of receiving a generic settings denial.</p>
  <div class="sec-head">
    <p class="lbl">Pattern formats</p>
    <h2>How rules match commands.</h2>
  </div>
  <div class="data-table-frame">
    <div class="data-table-scroll" data-table-scroll>
      <table class="data-table">
    <thead>
      <tr><th>Pattern</th><th>Type</th><th>Matches</th></tr>
    </thead>
    <tbody>
      <tr><td><code>Bash(git:*)</code></td><td>Word-boundary prefix</td><td>The <code>:</code> splits on spaces. Matches <code>git</code>, <code>git status</code>, <code>git push</code>; NOT <code>github</code>.</td></tr>
      <tr><td><code>Bash(cat /dev/zero*)</code></td><td>Glob prefix</td><td>Matches anything that starts with the literal prefix.</td></tr>
      <tr><td><code>Bash(pwd)</code></td><td>Exact</td><td>Only the exact command, no trailing args.</td></tr>
      <tr><td><code>Bash(uv run $HOME/scripts/*)</code></td><td>$HOME expansion</td><td>tool-gates expands <code>$HOME</code> in a pattern to the home directory before matching. (Claude Code itself natively expands the <code>~/</code> form.)</td></tr>
    </tbody>
  </table>
    </div>
  </div>
  <div class="sec-head">
    <p class="lbl">Specificity resolution</p>
    <h2>When ask and allow both match.</h2>
    <p>Specificity is the length of the non-wildcard prefix. The more specific pattern wins; exact matches are highest. Ties go to ask, the safer default. <code>Bash(mytool --verbose:*)</code> (length 16) beats <code>Bash(mytool:*)</code> (length 6), so a narrow allow can override a broad ask. Deny rules are checked first and use simple matching with no specificity comparison.</p>
  </div>
  <p class="note">
    <svg class="alert" aria-hidden="true" focusable="false" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
    <span>When a <code>permissions.ask</code> rule in settings.json matches, Claude Code's resolver shows a two-button prompt instead of three (the "don't ask again for X" button is suppressed). <code>tool-gates rules ask-audit</code> categorises each rule by what tool-gates would do without it (gate-covered, safety floor, indeterminate) and offers per-rule removal.</span>
  </p>

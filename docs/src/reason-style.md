  <p class="breadcrumb"><a href="index.html">Development</a> / Reason Style</p>
  <h1 id="reason-h1">Reason Style Guide</h1>
  <p class="page-lede">Every <code>reason</code> string in <code>rules/*.toml</code> is sent to the AI agent as <code>permissionDecisionReason</code>. Treat each one as a help-menu entry, not a security disclaimer. The reasons are the docs.</p>
  <div class="sec-head" style="margin-top: var(--s-6)">
    <p class="lbl">Format</p>
    <h2>Two sentences, max.</h2>
  </div>
<pre class="code-block"><span class="comment">&lt;verb-phrase of what the command does&gt;.</span>
<span class="comment">&lt;risk / scope / reversibility note if non-obvious&gt;.</span></pre>
  <p class="step-prose">First sentence: what the command does, in plain language. Second sentence: only if there's a non-obvious risk, scope, or reversibility point worth teaching. Procedural mutations like <code>"Installing packages"</code> stay one terse sentence.</p>
  <div class="sec-head">
    <p class="lbl">Examples</p>
    <h2>Good vs bad.</h2>
  </div>
  <div class="hook-cards">
    <article class="hook-card" style="border-color: color-mix(in oklab, var(--allow) 25%, var(--border))">
      <h4 style="color: var(--allow)">Good</h4>
      <p>"Hard reset discards uncommitted changes in the working tree and index. Safer: <code>git stash</code> first, or <code>git reset --soft</code> to keep changes staged."</p>
      <p class="hook-detail">Says what happens, then offers a safer alternative the agent can suggest.</p>
    </article>
    <article class="hook-card" style="border-color: color-mix(in oklab, var(--allow) 25%, var(--border))">
      <h4 style="color: var(--allow)">Good</h4>
      <p>"Drops a stash permanently. Run <code>git stash list</code> first to confirm the index; cannot be undone."</p>
      <p class="hook-detail">Reversibility note plus a concrete pre-check command.</p>
    </article>
    <article class="hook-card" style="border-color: color-mix(in oklab, var(--block) 25%, var(--border))">
      <h4 style="color: var(--block)">Bad: label only</h4>
      <p>"git stash drop"</p>
      <p class="hook-detail">Tells the agent nothing it didn't already know from the command name.</p>
    </article>
    <article class="hook-card" style="border-color: color-mix(in oklab, var(--block) 25%, var(--border))">
      <h4 style="color: var(--block)">Bad: authorization hedge</h4>
      <p>"Port scanning. Only scan networks you own or have written authorization to test."</p>
      <p class="hook-detail">The reason teaches the agent about the operation; it doesn't gate access. Leave authorization to the operator.</p>
    </article>
  </div>
  <div class="sec-head">
    <p class="lbl">Rules</p>
    <h2>Hard requirements.</h2>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>Rule</th><th>Why</th></tr>
    </thead>
    <tbody>
      <tr><td>Max 250 chars</td><td>Enforced by <code>build.rs</code> (<code>MAX_REASON_CHARS</code>). Build fails on overflow. Trim before adding.</td></tr>
      <tr><td>No em-dashes</td><td>Periods separate clauses; ASCII-only quotes. Em-dashes are a style smell in agent-facing prose.</td></tr>
      <tr><td>No authorization hedges</td><td>Don't write "verify you have permission" or "only do this on resources you own". The reason teaches; it doesn't gate.</td></tr>
      <tr><td>Generic placeholders only</td><td>Use <code>&lt;file&gt;</code>, <code>&lt;path&gt;</code>, <code>&lt;host&gt;</code>, <code>&lt;user&gt;</code>, <code>&lt;region&gt;</code>, <code>&lt;resource&gt;</code>, <code>&lt;key&gt;</code>, <code>&lt;pid&gt;</code>. Never embed real hostnames, IPs, usernames, paths, or service names. Tests and reasons are public.</td></tr>
      <tr><td>Terse for procedural mutations</td><td>One sentence for routine ones like <code>"Installing packages"</code> or <code>"Formatting files"</code>. Add a second sentence only when there's a non-obvious risk worth teaching.</td></tr>
    </tbody>
  </table>
  <p class="note">
    <svg class="alert" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
    <span><b>The style applies to source-level prompts too.</b> Strings in <code>src/router.rs</code>, <code>src/security_reminders.rs</code>, and <code>src/hints.rs</code> follow the same rules. If you add a hard-deny pattern or a new modern-CLI hint, write its prompt in this voice.</span>
  </p>

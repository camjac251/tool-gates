  <p class="breadcrumb"><a href="index.html">Development</a> / Architecture</p>
  <h1 id="arch-h1">Architecture</h1>
  <p class="page-lede">What happens between a tool call landing on stdin and a decision returning on stdout. The pipeline runs in the same Rust binary for every client; only the wire-format serialiser at the end varies.</p>
  <div class="lifecycle" aria-label="Internal pipeline" style="margin-top: var(--s-5)">
    <div class="lc-bar">
      <span class="lights"><i></i><i></i><i></i></span>
      <span class="lc-label">tool-gates internal pipeline</span>
    </div>
    <div class="lc-track">
      <div class="lc-node start">
        <span class="lc-icon">●</span>
        <div class="lc-title">Tool-call JSON on stdin</div>
        <div class="lc-sub">Client auto-detected from <code>hook_event_name</code> (or <code>--client codex</code> CLI flag). Routes by <code>tool_name</code>: Bash/Monitor to the gate engine, Write/Edit to file guards + security reminders, MCP to block rules + accept-edits, Skill to auto-approval rules.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node hook">
        <span class="lc-icon">▸</span>
        <span class="lc-tag">router.rs</span>
        <div class="lc-title">Raw-string scan</div>
        <div class="lc-sub">Pre-AST string checks before parsing. Catches <code>| bash</code>, <code>eval</code>, <code>source</code>, <code>xargs rm</code>, destructive <code>find</code>/<code>fd</code>, dangerous command substitution, semicolon injection, output redirection. Hard-deny patterns (head/tail pipe) run first.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node hook">
        <span class="lc-icon">▸</span>
        <span class="lc-tag">parser.rs</span>
        <div class="lc-title">tree-sitter parse</div>
        <div class="lc-sub">Bash AST via <code>tree-sitter-bash</code>. Extracts <code>Vec&lt;CommandInfo&gt;</code> with program, args, raw form. Compound commands (<code>&amp;&amp;</code>, <code>||</code>, <code>|</code>, <code>;</code>) split into per-segment evaluations. Mise / package.json task expansion runs after parse.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node hook">
        <span class="lc-icon">▸</span>
        <span class="lc-tag">gates/*.rs</span>
        <div class="lc-title">Gate dispatch</div>
        <div class="lc-sub">13 gates, ordered by priority. Lower runs first; <code>basics</code> at 100 is always last. Each gate either returns a decision or <code>Skip</code>. Custom handlers in Rust cover what TOML can't express. Strictest decision wins for compound commands.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node hook">
        <span class="lc-icon">▸</span>
        <span class="lc-tag">settings.rs</span>
        <div class="lc-title">Settings.json merge</div>
        <div class="lc-sub">Reads four files in priority order (managed → local → project → user). Deny rules win unconditionally. Otherwise: ask vs allow resolved by pattern specificity (longest non-wildcard prefix; ties go to ask). <code>$HOME</code> expansion applied before match.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node exec">
        <span class="lc-icon">▷</span>
        <div class="lc-title">Decision on stdout</div>
        <div class="lc-sub">Serialised per client. Claude: nested <code>hookSpecificOutput.permissionDecision</code>. Gemini: flat <code>decision</code> + <code>reason</code> (tool-gates emits <code>"block"</code> for hard blocks; Gemini also accepts <code>"deny"</code>, and exit code 2 blocks). Codex: empty stdout for allow/ask, nested <code>permissionDecision: "deny"</code> for blocks. Modern-CLI hints ride on <code>additionalContext</code>.</div>
      </div>
    </div>
  </div>
  <div class="sec-head" style="margin-top: var(--s-7)">
    <p class="lbl">Why the order matters</p>
    <h2>Each stage closes a gap the next can't.</h2>
  </div>
  <div class="hook-cards">
    <article class="hook-card">
      <h4>Raw-string before AST</h4>
      <p>Pipe-to-shell and eval are caught before parsing because tree-sitter sees them as syntactically valid bash. The AST doesn't know that <code>curl | bash</code> is the security threat; the raw-string pass does.</p>
    </article>
    <article class="hook-card">
      <h4>Custom handlers before declarative</h4>
      <p>Path-aware <code>rm</code> normalisation, gh-api method routing, sudo command extraction. These need imperative Rust because they parse the inner structure of the command, not just match on subcommand strings.</p>
    </article>
    <article class="hook-card">
      <h4>Gates priority-ordered</h4>
      <p>Specific gates (git, gh, cloud) decide before <code>basics</code> catches anything as safe. Otherwise <code>git status</code> would be allowed by basics before the git gate could surface its real reason text.</p>
    </article>
    <article class="hook-card">
      <h4>Settings merge last</h4>
      <p>Gate blocks always win over settings.json (the safety floor is not configurable). Otherwise: explicit deny &gt; explicit ask &gt; explicit allow &gt; gate decision &gt; unknown (defer or ask).</p>
    </article>
  </div>
  <div class="sec-head">
    <p class="lbl">Side data</p>
    <h2>Hints, tracking, security scan.</h2>
    <p>Three subsystems run alongside the main pipeline without changing the decision.</p>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>Subsystem</th><th>Source</th><th>What it does</th></tr>
    </thead>
    <tbody>
      <tr><td>Modern CLI hints</td><td><code>hints.rs</code></td><td>For allowed commands using legacy tools, append a suggestion on <code>additionalContext</code>. Gated on the modern tool being installed (7-day cache in <code>tool_cache.rs</code>). Session-deduped via <code>hint_tracker.rs</code>.</td></tr>
      <tr><td>Approval tracking</td><td><code>tracking.rs</code></td><td>PreToolUse → PostToolUse correlation with 24h TTL. Successful asks land in <code>~/.cache/tool-gates/pending.jsonl</code> for the review TUI.</td></tr>
      <tr><td>Security reminders</td><td><code>security_reminders.rs</code></td><td>Three-tier scan of Write/Edit bodies. Tier 1 denies source writes before they land, with doc-file secrets nudged after write; Tier 2 nudges via PostToolUse; Tier 3 warns on <code>additionalContext</code>. See the <a href="security-reminders.html">Security reminders</a> page.</td></tr>
    </tbody>
  </table>
  <p class="note">
    <svg class="alert" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
    <span><b>Generated gate code lives under <code>src/generated/rules.rs</code>.</b> Built by <code>build.rs</code> from every <code>rules/*.toml</code> on every cargo build. Do not edit by hand; changes are overwritten. The generator also emits per-gate <code>check_*_gate()</code> functions that the Rust gate files wrap and extend with custom handlers.</span>
  </p>

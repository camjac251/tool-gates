  <nav class="breadcrumb" aria-label="Breadcrumb">
    <ol>
      <li><a href="index.html">tool-gates</a></li>
      <li>Contribute</li>
      <li aria-current="page">Architecture</li>
    </ol>
  </nav>
  <h1 id="arch-h1">Architecture</h1>
  <p class="page-lede">What happens between a tool call landing on stdin and a decision returning on stdout. The pipeline runs in the same Rust binary for every client; only the wire-format serialiser at the end varies.</p>
  <figure class="lifecycle" aria-labelledby="internal-pipeline-label" style="margin-top: var(--s-5)">
    <div class="lc-bar">
      <span class="lights"><i></i><i></i><i></i></span>
      <span class="lc-label" id="internal-pipeline-label">tool-gates internal pipeline</span>
    </div>
    <div class="lc-track">
      <div class="lc-node start">
        <span class="lc-icon">●</span>
        <div class="lc-title">Tool-call JSON on stdin</div>
        <div class="lc-sub">Client auto-detected from <code>hook_event_name</code> (or the <code>--client codex</code> / <code>--client antigravity</code> flag; Antigravity payloads are normalized into the canonical shape first). Routes by <code>tool_name</code>: Bash/Monitor to the gate engine, TaskOutput to the immediate-wait guard, Write/Edit to file guards + security reminders, MCP to block rules + accept-edits, Skill to auto-approval rules. Claude's UserPromptSubmit event clears prior-turn wait correlation.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node hook">
        <span class="lc-icon">▸</span>
        <span class="lc-tag">raw_floor.rs</span>
        <div class="lc-title">Raw-string scan</div>
        <div class="lc-sub">Shared pre-AST checks cover the top-level command plus executable strings inside local shell wrappers and <code>xargs ... shell -c</code>. The hard/soft-ask catalog lives in <code>security_floor.rs</code>; output-cap hard denials live in <code>pipe_caps.rs</code> and run first. A cap denial records a stable cause plus semantic recovery actions, including a source-file selection only when the parser confirms one unambiguous file reader.</div>
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
        <div class="lc-title">Settings.json resolution</div>
        <div class="lc-sub">Reads up to four files in priority order (managed → local → project → user), merging them unless the managed document sets <code>allowManagedPermissionRulesOnly</code>, which reduces Claude's set to that one file (see <a href="settings-precedence.html">Settings Precedence</a>). The calling client is an explicit input, so Codex and Antigravity always keep the merge. Deny rules win unconditionally. Otherwise: ask vs allow resolved by pattern specificity (longest non-wildcard prefix; ties go to ask). <code>$HOME</code> expansion applied before match.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node exec">
        <span class="lc-icon">▷</span>
        <div class="lc-title">Decision on stdout</div>
        <div class="lc-sub">Serialised per client. Claude: nested <code>hookSpecificOutput.permissionDecision</code> with recovery in <code>additionalContext</code>. Codex: empty stdout for non-denies; blocks use nested <code>permissionDecision: "deny"</code> with recovery in <code>additionalContext</code>. Antigravity: flat tightening decisions with deny recovery folded into <code>reason</code>, empty stdout for allow and no-opinion. Gemini (deprecated): flat <code>decision</code> + <code>reason</code>; block recovery is folded into the agent-facing reason, while nonblocking context uses the user-facing <code>systemMessage</code>. At this boundary, <code>recovery.rs</code> maps semantic file recovery to <code>Read</code>, <code>read_file</code>, <code>view_file</code>, or a conditional shell fallback according to <code>FILE_TOOL_SPECS</code>.</div>
      </div>
    </div>
  </figure>
  <div class="sec-head">
    <p class="lbl">Task expansion</p>
    <h2>Wrapper tasks are evaluated by their contents.</h2>
    <p>A task runner's name is not enough to classify its effects. Tool Gates resolves supported task definitions, checks the commands they invoke, and uses the strictest resulting decision. Recovery actions survive package-script and mise composition, so a wrapper cannot discard the corrective path attached by an inner denial.</p>
  </div>
  <div class="hook-cards">
    <article class="hook-card">
      <h3>mise tasks</h3>
      <p><code>mise run &lt;task&gt;</code>, <code>mise r &lt;task&gt;</code>, and direct <code>mise &lt;task&gt;</code> forms expand from <code>mise.toml</code> or <code>.mise.toml</code>. Dependencies run first, circular dependencies are ignored after the first visit, and a task's <code>dir</code> applies to its command. Built-in mise subcommands are never mistaken for task names.</p>
      <p class="hook-detail">The mise-generated <code>eval "set -- ${usage_args-}"</code> argument-forwarding prefix, including supported splat and array forms, is stripped before the security floor checks the actual task body.</p>
    </article>
    <article class="hook-card">
      <h3>package scripts</h3>
      <p><code>npm run</code>, <code>pnpm run</code>, <code>yarn run</code>, and <code>bun run</code> resolve the named script from the nearest <code>package.json</code>. Non-built-in pnpm, yarn, and bun shorthand forms resolve the same way.</p>
      <p class="hook-detail"><code>bun &lt;file&gt;</code> and <code>bun run &lt;file&gt;</code> stay file execution when the argument contains a path separator or a recognized code-file extension; they are not looked up as script names.</p>
    </article>
  </div>
  <div class="sec-head" style="margin-top: var(--s-7)">
    <p class="lbl">Why the order matters</p>
    <h2>Each stage closes a gap the next can't.</h2>
  </div>
  <div class="hook-cards">
    <article class="hook-card">
      <h3>Raw-string before AST</h3>
      <p>Pipe-to-shell and eval are caught before parsing because tree-sitter sees them as syntactically valid bash. The AST doesn't know that <code>curl | bash</code> is the security threat; the raw-string pass does.</p>
    </article>
    <article class="hook-card">
      <h3>Custom handlers before declarative</h3>
      <p>Path-aware <code>rm</code> normalisation, gh-api method routing, sudo command extraction. These need imperative Rust because they parse the inner structure of the command, not just match on subcommand strings.</p>
    </article>
    <article class="hook-card">
      <h3>Gates priority-ordered</h3>
      <p>Specific gates (git, gh, cloud) decide before <code>basics</code> catches anything as safe. Otherwise <code>git status</code> would be allowed by basics before the git gate could surface its real reason text.</p>
    </article>
    <article class="hook-card">
      <h3>Settings resolved last</h3>
      <p>Gate blocks always win over settings.json (the safety floor is not configurable), whichever sources contributed the rule. Otherwise: explicit deny &gt; explicit ask &gt; explicit allow &gt; gate decision &gt; unknown (defer or ask).</p>
    </article>
  </div>
  <div class="sec-head">
    <p class="lbl">Side data</p>
    <h2>Recovery, hints, tracking, security scan.</h2>
    <p>Five subsystems run alongside the main pipeline; the TaskOutput guard can deny one narrowly correlated sequence.</p>
  </div>
  <div class="data-table-frame">
    <div class="data-table-scroll" data-table-scroll>
      <table class="data-table">
    <thead>
      <tr><th>Subsystem</th><th>Source</th><th>What it does</th></tr>
    </thead>
    <tbody>
      <tr><td>Recovery guidance</td><td><code>recovery.rs</code></td><td>Stores corrective steps as semantic actions, then renders them with the active client's registered capabilities. Causes remain stable across clients; native tool names appear only at serialization. Surfaces without an active hook client, such as the WASM simulator, render neutral recovery without naming a tool.</td></tr>
      <tr><td>Modern CLI hints</td><td><code>hints.rs</code></td><td>For allowed commands using legacy tools, attach a client-neutral suggestion through the context channel that client supports: Claude agent context, Gemini's user-facing <code>systemMessage</code>, Codex PostToolUse context, and no output for Antigravity no-opinion decisions. Gated on the modern tool being installed (7-day cache in <code>tool_cache.rs</code>). Session-deduped via <code>hint_tracker.rs</code>.</td></tr>
      <tr><td>Approval tracking</td><td><code>tracking.rs</code></td><td>PreToolUse → PostToolUse correlation with 24h TTL. Successful asks land in <code>~/.cache/tool-gates/pending.jsonl</code> for the review TUI.</td></tr>
      <tr><td>TaskOutput guard</td><td><code>task_output_guard.rs</code></td><td>Records only successful background Bash results with a structured task id. A blocking TaskOutput call is denied only for the same session and task with no intervening successful tool work or user turn. Successful non-TaskOutput results close the immediate sequence. State expires after 10 minutes and is capped at 128 sessions.</td></tr>
      <tr><td>Security reminders</td><td><code>security_reminders.rs</code></td><td>Three-tier scan of Write/Edit bodies. Tier 1 denies source writes before they land, with doc-file secrets nudged after write; Tier 2 nudges via PostToolUse; Tier 3 warns on <code>additionalContext</code>. See the <a href="security-reminders.html">Security reminders</a> page.</td></tr>
    </tbody>
  </table>
    </div>
  </div>
  <p class="note">
    <svg class="alert" aria-hidden="true" focusable="false" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
    <span><b>Generated gate code lives under <code>src/generated/rules.rs</code>.</b> Built by <code>build.rs</code> from every <code>rules/*.toml</code> on every cargo build. Do not edit by hand; changes are overwritten. The generator also emits per-gate <code>check_*_gate()</code> functions that the Rust gate files wrap and extend with custom handlers.</span>
  </p>

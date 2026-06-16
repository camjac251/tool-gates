  <p class="breadcrumb"><a href="index.html">Core Concepts</a> / Antigravity CLI</p>
  <h1 id="antigravity-h1">Antigravity CLI</h1>
  <p class="page-lede">Antigravity (<code>agy</code>) is Google's successor to the Gemini CLI. tool-gates supports it through a single PreToolUse hook with its own wire format: a payload that nests the tool under <code>toolCall</code>, a flat <code>{decision, reason}</code> output, and a <code>hooks.json</code> keyed by hook name. This page covers what tool-gates gates on Antigravity and how the pieces map.</p>
  <div class="sec-head" style="margin-top: var(--s-6)">
    <p class="lbl">Selection</p>
    <h2>Antigravity is chosen by a flag, not auto-detected.</h2>
    <p>Antigravity's hook payload carries no <code>hook_event_name</code>, so tool-gates cannot tell it apart from Claude by inspection. The installer bakes <code>--client antigravity</code> into the hook command; that flag selects the wire format. Without it, an Antigravity payload would be misread as Claude.</p>
  </div>
  <div class="sec-head" style="margin-top: var(--s-7)">
    <p class="lbl">Payload</p>
    <h2>tool-gates normalizes the Antigravity shape.</h2>
    <p>Antigravity sends a camelCase envelope where the tool lives under <code>toolCall.name</code> and its arguments use PascalCase keys (the command is at <code>toolCall.args.CommandLine</code>, a write target at <code>toolCall.args.TargetFile</code>). tool-gates rewrites this into its canonical internal shape so the same engine that serves Claude, Codex, and Gemini runs unchanged. The original args are preserved alongside the canonical <code>command</code> / <code>file_path</code> / <code>content</code> keys.</p>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>Antigravity tool</th><th>Maps to</th><th>Command / path source</th></tr>
    </thead>
    <tbody>
      <tr><td><code>run_command</code></td><td>Bash</td><td><code>args.CommandLine</code></td></tr>
      <tr><td><code>view_file</code></td><td>Read</td><td><code>args.AbsolutePath</code></td></tr>
      <tr><td><code>write_to_file</code></td><td>Write</td><td><code>args.TargetFile</code> + <code>args.CodeContent</code></td></tr>
      <tr><td><code>replace_file_content</code></td><td>Edit</td><td><code>args.TargetFile</code> + <code>args.ReplacementContent</code></td></tr>
      <tr><td><code>multi_replace_file_content</code></td><td>Edit</td><td><code>args.TargetFile</code> + concatenated <code>args.ReplacementChunks[].ReplacementContent</code></td></tr>
      <tr><td><code>grep_search</code></td><td>Grep</td><td><code>args.Query</code></td></tr>
      <tr><td><code>find_by_name</code></td><td>Glob</td><td><code>args.Pattern</code></td></tr>
    </tbody>
  </table>
  <div class="sec-head" style="margin-top: var(--s-7)">
    <p class="lbl">Decision</p>
    <h2>A flat decision, and "no opinion" defers to Antigravity.</h2>
    <p>The PreToolUse hook returns a flat JSON object on stdout. <code>decision</code> is required and is one of <code>allow</code>, <code>ask</code>, <code>deny</code>, or <code>force_ask</code>.</p>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>tool-gates result</th><th>Antigravity output</th><th>Effect</th></tr>
    </thead>
    <tbody>
      <tr><td>No opinion</td><td>empty stdout</td><td>Antigravity's own fine-grained permission engine decides. tool-gates never auto-allows a command it does not recognize. (<code>decision</code> is required by the schema; this relies on the currently-undocumented behavior that emitting none defers to Antigravity's engine.)</td></tr>
      <tr><td>Allow (known-safe)</td><td><code>{"decision":"allow"}</code></td><td>Uses Antigravity's documented allow shape. Prompt suppression depends on Antigravity's native permission engine.</td></tr>
      <tr><td>Ask (soft)</td><td><code>{"decision":"ask"}</code></td><td>Prompts, respecting the user's "Always Allow" grants. Used for routine mutations and unknown commands.</td></tr>
      <tr><td>Ask (hard floor)</td><td><code>{"decision":"force_ask"}</code></td><td>Pipe-to-shell, <code>eval</code>, and dangerous substitution. Always prompts, ignoring any "Always Allow" grant, so the floor can never be permanently granted away.</td></tr>
      <tr><td>Deny</td><td><code>{"decision":"deny"}</code></td><td>Hard block. Remediation text is folded into <code>reason</code> since the Pre output has no <code>additionalContext</code> field.</td></tr>
    </tbody>
  </table>
  <p class="sub-note">The hard-ask safety floor maps to <code>force_ask</code>, not <code>ask</code>: pipe-to-shell and <code>eval</code> are ask-tier (never deny), and Antigravity's plain <code>ask</code> honors a prior "Always Allow" grant, which would let a granted command silently bypass the floor. <code>force_ask</code> always prompts. tool-gates does not emit <code>permissionOverrides</code> (scope-widening grants): a single gate decision needs no scope widening.</p>
  <div class="sec-head" style="margin-top: var(--s-7)">
    <p class="lbl">Scope</p>
    <h2>One hook does the whole gate.</h2>
  </div>
  <div class="hook-cards">
    <article class="hook-card">
      <h4>PreToolUse only</h4>
      <p>Antigravity also exposes <code>PostToolUse</code>, <code>PreInvocation</code>, <code>PostInvocation</code>, and <code>Stop</code>, but its post payload carries no tool name or input and it has no PermissionRequest event. The single PreToolUse hook is the entire gate.</p>
    </article>
    <article class="hook-card">
      <h4>Named-hook <code>hooks.json</code></h4>
      <p>Antigravity's <code>hooks.json</code> is a top-level object keyed by hook name, so tool-gates owns one entry, <code>tool-gates</code>, and leaves any other named hooks untouched: <code>{"tool-gates": {"PreToolUse": [...]}}</code>.</p>
    </article>
    <article class="hook-card">
      <h4>Secrets and file guards</h4>
      <p>Write content arrives in the PreToolUse args, so Tier 1 secret scanning runs on the write before it lands. File guards apply on both reads (<code>view_file</code>) and writes for symlinked AI-config files.</p>
    </article>
    <article class="hook-card">
      <h4>MCP not wired yet</h4>
      <p>Antigravity's MCP tool-name format for hook matchers is not documented, so MCP block rules are not yet applied for Antigravity. Shell, file, grep, and glob tools are all gated.</p>
    </article>
  </div>
  <div class="config-block">
    <header>
      <h3>Install</h3>
      <span class="src-tag">~/.gemini/config/hooks.json</span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="c"># shared user/global path (recommended, default)</span>
$ tool-gates hooks add --antigravity
<span class="c"># preview without writing</span>
$ tool-gates hooks add --antigravity --dry-run
<span class="c"># project scope</span>
$ tool-gates hooks add --antigravity -s project</pre>
      </div>
      <div class="config-prose">
        <p>Antigravity user hooks live at <code>~/.gemini/config/hooks.json</code>, which is the installer default and the path shared by the CLI backend. Project hooks live at <code>.agents/hooks.json</code> and are available with <code>-s project</code>. The matcher covers <code>run_command</code>, <code>view_file</code>, <code>write_to_file</code>, <code>replace_file_content</code>, <code>multi_replace_file_content</code>, <code>grep_search</code>, and <code>find_by_name</code>.</p>
        <p>Plugin-packaged hooks are useful for distribution, but they are not required for hook installs. Treat plugin support as a separate global-install path that should be verified with <code>agy plugin validate</code> and a deny probe before relying on it.</p>
        <p>Confirm with <code>tool-gates hooks status</code>, which lists the Antigravity shared user and project hook paths alongside the other clients.</p>
      </div>
    </div>
  </div>

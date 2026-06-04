  <p class="breadcrumb"><a href="index.html">Start</a> / Codex approval model</p>
  <h1 id="codex-h1">Codex approval model</h1>
  <p class="page-lede">On Codex, whether a tool-gates <code>ask</code> becomes a visible prompt is decided by Codex's own <code>approval_policy</code>, not by tool-gates. This page covers what tool-gates can and cannot control on Codex, and the one supported lever, execpolicy rules, that makes it authoritative over Codex's built-in safe-read list.</p>
  <div class="sec-head" style="margin-top: var(--s-6)">
    <p class="lbl">Where the prompt comes from</p>
    <h2>Codex's <code>approval_policy</code> owns the prompt, not tool-gates.</h2>
    <p>On Codex a tool-gates <code>ask</code> is pass-through. PreToolUse only honours <code>deny</code>, so allow, ask, and unknown all emit empty stdout and hand the decision back to Codex. Whether the user is then prompted depends entirely on Codex's <code>approval_policy</code>.</p>
  </div>
  <table class="data-table">
    <thead>
      <tr><th><code>approval_policy</code></th><th>Does a tool-gates <code>ask</code> reach a prompt?</th></tr>
    </thead>
    <tbody>
      <tr><td><code>untrusted</code></td><td>Yes. Every command Codex doesn't recognise as a known-safe read is sent to the approval path, where the PermissionRequest hook (tool-gates) and then the user decide. This is the only policy where tool-gates acts as a prompt layer.</td></tr>
      <tr><td><code>on-request</code></td><td>Mostly no. Non-dangerous commands run inside the sandbox without a prompt; the user is asked only when the model explicitly requests escalation. A tool-gates <code>ask</code> is moot.</td></tr>
      <tr><td><code>on-failure</code></td><td>No. Commands run sandboxed and prompt only if they fail. A tool-gates <code>ask</code> never surfaces.</td></tr>
      <tr><td><code>never</code></td><td>No prompts at all.</td></tr>
    </tbody>
  </table>
  <p class="sub-note">These four are the common presets. Codex also has a fifth <code>granular</code> policy for fine-grained per-category approvals.</p>
  <div class="sec-head" style="margin-top: var(--s-7)">
    <p class="lbl">Under untrusted</p>
    <h2>How a command reaches tool-gates.</h2>
  </div>
  <div class="lifecycle" aria-label="Approval flow on Codex under untrusted">
    <div class="lc-bar">
      <span class="lights"><i></i><i></i><i></i></span>
      <span class="lc-label">approval flow · Codex · approval_policy = untrusted</span>
    </div>
    <div class="lc-track">
      <div class="lc-node start">
        <span class="lc-icon">●</span>
        <div class="lc-title">Tool call</div>
        <div class="lc-sub"><code>Bash</code> or <code>apply_patch</code>.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node hook">
        <span class="lc-icon">▸</span>
        <span class="lc-tag">PreToolUse</span>
        <div class="lc-title">Deny floor</div>
        <div class="lc-sub">tool-gates can hard-<code>deny</code> here, and only deny. Everything else passes through.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node hook conditional">
        <span class="lc-icon">▸</span>
        <span class="lc-tag">safe-list / execpolicy</span>
        <div class="lc-when">Codex-internal</div>
        <div class="lc-title">Auto-approve?</div>
        <div class="lc-sub">A command on Codex's built-in <code>is_safe_command</code> read list auto-approves here and never reaches tool-gates, unless an execpolicy rule (matched first) forces it onward.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node hook conditional">
        <span class="lc-icon">▸</span>
        <span class="lc-tag">PermissionRequest</span>
        <div class="lc-when">when approval is needed</div>
        <div class="lc-title">tool-gates decides</div>
        <div class="lc-sub"><code>allow</code> auto-approves and suppresses the prompt; <code>deny</code> blocks; pass-through hands off to the user prompt.</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node exec">
        <span class="lc-icon">▷</span>
        <div class="lc-title">User prompt, then run</div>
        <div class="lc-sub">Codex shows the prompt only when tool-gates passed through.</div>
      </div>
    </div>
  </div>
  <div class="sec-head" style="margin-top: var(--s-7)">
    <p class="lbl">Capability</p>
    <h2>What tool-gates can and cannot do on Codex.</h2>
  </div>
  <div class="hook-cards">
    <article class="hook-card">
      <h4>Deny always works</h4>
      <p>A hard <code>deny</code> lands on both PreToolUse and PermissionRequest. The security floor (destructive <code>rm</code>, pipe-to-shell, your own deny rules) is fully enforced on Codex.</p>
    </article>
    <article class="hook-card">
      <h4>Allow only via PermissionRequest</h4>
      <p>A positive <code>allow</code> that auto-approves and suppresses the prompt is honoured only on the PermissionRequest hook, and only under <code>untrusted</code>. PreToolUse can never allow, ask, or rewrite input; tool-gates only emits Codex-shaped JSON there for hard denies. (Codex can accept <code>additionalContext</code> on PreToolUse, though tool-gates currently carries hints and Tier-3 warnings on PostToolUse.)</p>
    </article>
    <article class="hook-card">
      <h4>Safe-reads are invisible</h4>
      <p>Codex auto-approves <code>cat</code>, <code>ls</code>, <code>grep</code>, <code>rg</code>, <code>sed -n</code>, <code>git status/log/diff</code>, and similar reads before any hook runs. tool-gates never sees them on PermissionRequest; it can only <code>deny</code> them via PreToolUse, never turn them into a prompt. The lever to change that is execpolicy, below.</p>
    </article>
    <article class="hook-card">
      <h4>Project edits can auto-allow</h4>
      <p>With <code>[codex] accept_project_edits</code>, an <code>apply_patch</code> whose paths are all inside the project auto-approves on PermissionRequest, honouring your settings.json deny and ask patterns and the file guards. Opt-in, off by default; covered below.</p>
    </article>
    <article class="hook-card">
      <h4>Strict output validation</h4>
      <p>Codex validates hook stdout JSON stringently. Returning extra fields like <code>updatedInput</code>, <code>updatedPermissions</code>, <code>addDirectories</code>, or <code>interrupt</code> in <code>PermissionRequest</code> responses, or <code>updatedMCPToolOutput</code> in <code>PostToolUse</code> responses, results in a validation error rather than being silently ignored. tool-gates actively strips these fields to maintain hook compatibility.</p>
    </article>
  </div>
  <div class="sec-head" style="margin-top: var(--s-7)">
    <p class="lbl">Why deny-only</p>
    <h2>There is no <code>ask</code> on Codex PreToolUse.</h2>
    <p>On Codex, PreToolUse accepts only <code>deny</code>; no hook decision can force a prompt for an otherwise-permitted command. That is why tool-gates can only <code>deny</code> on PreToolUse, and why routing a safe-read to a prompt happens through execpolicy rather than a hook decision.</p>
  </div>
  <div class="config-block">
    <header>
      <h3>Making tool-gates authoritative: execpolicy</h3>
      <span class="src-tag">~/.codex/rules/</span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="c"># ~/.codex/rules/default.rules</span>
<span class="k">prefix_rule</span>(pattern=[<span class="s">"cat"</span>], decision=<span class="s">"prompt"</span>)
<span class="k">prefix_rule</span>(pattern=[<span class="s">"ls"</span>], decision=<span class="s">"prompt"</span>)
<span class="k">prefix_rule</span>(pattern=[<span class="s">"grep"</span>], decision=<span class="s">"prompt"</span>)
<span class="k">prefix_rule</span>(pattern=[<span class="s">"rg"</span>], decision=<span class="s">"prompt"</span>)
<span class="k">prefix_rule</span>(pattern=[<span class="s">"sed"</span>], decision=<span class="s">"prompt"</span>)
<span class="k">prefix_rule</span>(pattern=[<span class="s">"git"</span>], decision=<span class="s">"prompt"</span>)</pre>
      </div>
      <div class="config-prose">
        <p>Codex evaluates execpolicy rules before its built-in <code>is_safe_command</code> fallback. A <code>prefix_rule</code> with <code>decision="prompt"</code> on an otherwise-safe program overrides the auto-approval and routes the command to the approval path, where the PermissionRequest hook (tool-gates) and the user decide. This is the supported way to make tool-gates authoritative over Codex's allowlist.</p>
        <p>There is no wildcard: the first pattern token is a literal program name, so you enumerate each command you want gated. Validate a rule with <code>codex execpolicy check --rules ~/.codex/rules/default.rules -- cat foo</code>. Pair this with <code>approval_policy = "untrusted"</code>; under <code>never</code> a <code>prompt</code> rule is forbidden instead of surfaced.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>Auto-allowing project edits: <code>[codex] accept_project_edits</code></h3>
      <span class="src-tag">~/.config/tool-gates/config.toml</span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec">[codex]</span>
<span class="k">accept_project_edits</span> = <span class="b">true</span>   <span class="c"># default false</span>
<span class="k">allow_edits_anywhere</span> = <span class="b">false</span>  <span class="c"># default false</span></pre>
      </div>
      <div class="config-prose">
        <p>With <code>accept_project_edits</code> enabled, a Codex <code>apply_patch</code> edit auto-approves on the PermissionRequest hook (<code>behavior: allow</code>, no prompt) when every touched path is inside the project (the session cwd plus the <code>additionalDirectories</code> from <code>settings.json</code>) and no path is guarded, asked, or denied. Codex shell commands are also evaluated as <code>acceptEdits</code>, so in-project file-editing commands (<code>sd</code>, <code>prettier --write</code>, <code>mkdir -p</code>, <code>sed -i</code>, ...) auto-allow while dangerous bases (<code>rm</code>, <code>mv</code>, <code>cp</code>) and out-of-project targets still prompt. This mirrors Claude Code's <code>acceptEdits</code> for Codex.</p>
        <p>The auto-allow honours your <code>~/.claude/settings.json</code> <code>Write(...)</code> / <code>Edit(...)</code> / <code>MultiEdit(...)</code> rules: a <code>deny</code> pattern denies the patch, an <code>ask</code> pattern (for example <code>Write(**/.env*)</code>, <code>Write(**/secrets/**)</code>, <code>Edit(**/package-lock.json)</code>) still prompts, and the AI-config file guards still prompt. Patterns match gitignore-style, so <code>**/package-lock.json</code> matches at any depth. For a multi-file patch the strictest path decision wins: one denied or asked path blocks or prompts the whole patch.</p>
        <p><code>allow_edits_anywhere = true</code> widens the auto-allow to edits anywhere on disk, still subject to every deny pattern, ask pattern, and file guard. Leave it off to keep auto-approval scoped to the project.</p>
      </div>
    </div>
  </div>
  <div class="sec-head" style="margin-top: var(--s-7)">
    <p class="lbl">Footguns</p>
    <h2>Two settings silently disable the prompt layer.</h2>
  </div>
  <p class="note">
    <svg class="alert" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
    <span><b>Both flip <code>approval_policy</code> to <code>on-request</code>, where mutations stop prompting.</b> Selecting <b>Default</b> in the Codex <code>/permissions</code> popup changes it for the running session only (a runtime override, not written to disk), so a restart restores your config. Enabling <b>"Approve for me"</b> (Guardian) persists <code>approval_policy = "on-request"</code> to <code>config.toml</code>. Keep <code>untrusted</code> if you want tool-gates and prompts to govern mutations.</span>
  </p>
  <div class="sec-head" style="margin-top: var(--s-7)">
    <p class="lbl">Sandbox vs approval</p>
    <h2>The sandbox and the prompt are different axes.</h2>
    <p>Codex's sandbox decides where a command may write; <code>approval_policy</code> decides when you are asked. They are independent. Turning the sandbox off (<code>sandbox_mode = "danger-full-access"</code>) does not reduce prompts, because prompts come from <code>approval_policy</code>, not the sandbox. It only removes containment, leaving tool-gates plus your prompts plus the execpolicy deny floor as the safety net. A stricter sandbox, likewise, does not add prompts.</p>
  </div>

  <nav class="breadcrumb" aria-label="Breadcrumb">
    <ol>
      <li><a href="index.html">tool-gates</a></li>
      <li>How It Decides</li>
      <li aria-current="page">Scratch Directory</li>
    </ol>
  </nav>
  <h1 id="scratch-h1">Scratch Directory</h1>
  <p class="page-lede">A friction-free, session-scoped working directory for an agent's throwaway files: patch diffs, fetch dumps, screenshots, draft PR bodies, captured build output. Writes whose target resolves under a recognized scratch root (<code>$TOOL_GATES_SCRATCH</code>, or Claude Code's native session scratchpad) auto-allow in every permission mode, so agents stop prompting for intermediate work.</p>

  <div class="sec-head" style="margin-top: var(--s-6)">
    <p class="lbl">The base</p>
    <h2>One environment variable, a per-session subtree.</h2>
  </div>
  <p class="step-prose">The base is <code>$TOOL_GATES_SCRATCH</code> (default <code>~/.cache/tool-gates-scratch</code>). The convention is to write under a per-project, per-session subtree so parallel work never collides and scratch lines up with the session transcript:</p>
  <pre class="code-block">$TOOL_GATES_SCRATCH/&lt;project-slug&gt;/$CLAUDE_CODE_SESSION_ID/</pre>
  <p class="step-prose">The project slug mirrors the <code>~/.claude/projects/&lt;slug&gt;/&lt;session&gt;/</code> transcript scheme (the working dir with <code>/</code> turned into <code>-</code>), and the session id lets a session's subagents and workflow agents resolve the <em>same</em> dir. Those segments are organizational only: the permission decision is a pure prefix match against the base, so the leading <code>$TOOL_GATES_SCRATCH</code> is the only part that matters for auto-allow.</p>

  <div class="sec-head">
    <p class="lbl">Second root</p>
    <h2>Claude Code's native session scratchpad.</h2>
  </div>
  <p class="step-prose">Claude Code creates its own per-session scratchpad at session start and hands the agent the literal path in the system prompt, no variables required:</p>
  <pre class="code-block">&lt;tmpdir&gt;/claude-&lt;uid&gt;/&lt;project-segment&gt;/&lt;session-id&gt;/scratchpad/</pre>
  <p class="step-prose">Claude Code auto-allows its file tools there, but not Bash, so a redirect, <code>mkdir</code>, <code>tee</code>, or <code>cp</code> into it would still prompt. tool-gates recognizes this directory as a second scratch root with the same upgrade set as below. The match is bound to the <em>current</em> session: the session-id path component must equal the gate's own <code>CLAUDE_CODE_SESSION_ID</code> (UUID-shaped), the <code>claude-&lt;uid&gt;</code> component is exact, and scope ends at <code>scratchpad/</code>, so another session's scratchpad, the <code>tasks/</code> sibling, and anything else under the temp dir still prompt. Other clients never set that variable, so the root is inert for them.</p>

  <div class="sec-head">
    <p class="lbl">What auto-allows</p>
    <h2>Writes whose target lands under the base.</h2>
    <p>Each of these upgrades a would-be <code>ask</code> to <code>allow</code> when (and only when) the thing being written resolves under the scratch base.</p>
  </div>
  <div class="install-clients">
    <article class="install-client">
      <header>
        <h3>File tools</h3>
        <span class="hooks-count">target path</span>
      </header>
      <p><code>Write</code>, <code>Edit</code>, <code>MultiEdit</code>, <code>NotebookEdit</code> (and the Codex <code>apply_patch</code> / Gemini / Antigravity write aliases). Every touched path must be under scratch.</p>
    </article>
    <article class="install-client">
      <header>
        <h3>Bash writes</h3>
        <span class="hooks-count">destination</span>
      </header>
      <p><code>mkdir</code>, <code>touch</code>, <code>tee</code> (all targets); <code>cp</code>, <code>mv</code> (destination); <code>chmod</code>/<code>chown</code>/<code>chgrp</code> (the files); <code>sd</code> in-place edits.</p>
    </article>
    <article class="install-client">
      <header>
        <h3>Redirects &amp; downloads</h3>
        <span class="hooks-count">output target</span>
      </header>
      <p><code>&gt;</code> / <code>&gt;&gt;</code> / <code>&amp;&gt;</code> redirects (including quoted targets), <code>curl -o</code>, and <code>wget -O</code> / <code>-P</code>.</p>
    </article>
  </div>

  <div class="sec-head">
    <p class="lbl">What still asks</p>
    <h2>Two reasons a write near scratch still prompts.</h2>
  </div>
  <p class="step-prose"><b>Excluded by design.</b> Tools whose command sublanguage can run shell or write outside the named target are deliberately left asking, because a scratch target does not bound what they do: <code>sed -i</code> (the <code>e</code> command runs shell, <code>w</code> writes any file), <code>sqlite3</code> (<code>.shell</code> / <code>.system</code> / <code>.output</code>), <code>zip</code> (<code>-O</code> redirects output elsewhere), and <code>ouch</code> / <code>tar</code> decompression (zip-slip).</p>
  <p class="step-prose"><b>Deferred.</b> Tools that need careful per-command parsing before they can be scratch-scoped still prompt for now: <code>tar</code>, <code>ln -s</code>, and <code>git init</code> / <code>clone</code> / <code>worktree</code>.</p>

  <div class="sec-head">
    <p class="lbl">The boundary</p>
    <h2>Widen where the agent writes, not what it can touch.</h2>
  </div>
  <p class="step-prose">The auto-allow is destination-gated and one-directional. You can write, move, or copy <em>into</em> scratch without a prompt, but moving or copying <em>out</em> of scratch to anywhere else (the project, <code>/etc</code>, <code>~/.ssh</code>) prompts like any normal write. Reading a file from elsewhere <em>into</em> scratch (<code>cp /etc/x scratch/</code>) is allowed by design: the write lands in scratch, the read is harmless, and nothing leaves the machine.</p>
  <p class="note">
    <svg class="alert" aria-hidden="true" focusable="false" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
    <span><b>It only upgrades <code>ask</code> to <code>allow</code>, never relaxes a block.</b> Targets are canonicalized first (symlinks and <code>..</code> resolved), so a path that escapes the base still gates. A dangerous-path block, a <code>settings.json</code> deny, and the AI-config <a href="settings-precedence.html">file guards</a> all still win. On <a href="modes.html">plan mode</a> the file-tool path skips the upgrade entirely. The upgrade is a wire <code>allow</code>, so whether it removes the prompt depends on the client: a true allow on Claude, a fall-through to the approval policy on Codex, and inert on Gemini and Antigravity, where the native engine keeps the stricter decision so scratch writes still prompt.</span>
  </p>

  <div class="sec-head">
    <p class="lbl">Setup</p>
    <h2>Set the base; point the agent at it.</h2>
  </div>
  <p class="step-prose">Set <code>TOOL_GATES_SCRATCH</code> in your environment. Putting it in the <code>env</code> block of <code>~/.claude/settings.json</code> makes it ambient: it reaches every Bash call, every subagent, and every workflow agent, and survives context compaction.</p>
  <pre class="code-block">{ "env": { "TOOL_GATES_SCRATCH": "/home/you/.cache/tool-gates-scratch" } }</pre>
  <p class="step-prose">There is no <code>config.toml</code> toggle; relocate the base only via the env var. The literal <code>$TOOL_GATES_SCRATCH</code> token in a command is substituted only while the env var is set: unset, the shell would expand it to nothing, so the gate leaves the token alone and prompts (fully-spelled paths under the default base still match). An override that contains an unresolvable variable makes this root inert (fail closed: nothing resolves under it); the session-scratchpad root above is independent and keeps matching. The gate only removes the prompt, so the other half is instructing your agent to write its throwaway and intermediate files under the canonical path (and to <code>mkdir -p</code> it first) instead of <code>/tmp</code>.</p>

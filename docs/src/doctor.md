  <p class="breadcrumb"><a href="index.html">Reference</a> / Tool Gates Doctor</p>
  <h1 id="doctor-h1">Tool Gates Doctor</h1>
  <p class="page-lede">A read-only health check. Verifies the binary is on PATH, hooks are wired into every supported client at every relevant scope, cache files are readable, and no legacy <code>bash-gates</code> configuration remains in your settings.</p>
  <div class="sec-head" style="margin-top: var(--s-6)">
    <p class="lbl">Run it</p>
    <h2>One command, four checks.</h2>
  </div>
<pre class="code-block"><span class="prompt">$</span> tool-gates doctor
<span class="comment">✓ binary: ~/.local/bin/tool-gates (vX.Y.Z)</span>
<span class="comment">✓ config: ~/.config/tool-gates/config.toml (6 features, defaults)</span>
<span class="comment">✓ hooks · claude:    user + project (4 hooks each)</span>
<span class="comment">✓ hooks · codex:       user (3 hooks)</span>
<span class="comment">✓ hooks · antigravity: user (1 hook)</span>
<span class="comment">✓ hooks · gemini:      user (2 hooks, deprecated)</span>
<span class="comment">✓ cache: ~/.cache/tool-gates (4 files, 18 KB)</span>
<span class="comment">✓ legacy: no bash-gates remnants in settings files</span>
<span class="comment">All checks passed.</span></pre>
  <div class="sec-head">
    <p class="lbl">What it checks</p>
    <h2>Coverage.</h2>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>Check</th><th>Looks for</th></tr>
    </thead>
    <tbody>
      <tr><td>binary</td><td>Resolves <code>tool-gates</code> on PATH and prints the version. Flags a mismatch if the version embedded in the hook command differs from what's installed.</td></tr>
      <tr><td>config</td><td>Reads <code>~/.config/tool-gates/config.toml</code> if present and reports which features are toggled off.</td></tr>
      <tr><td>hooks</td><td>Walks every settings file (Claude, Codex, Antigravity, Gemini; user and project scopes) and confirms each expected hook is present with the correct matcher and timeout. Reports missing or stale hook commands.</td></tr>
      <tr><td>cache</td><td>Lists <code>~/.cache/tool-gates/</code> contents (pending queue, available-tools cache, hint-tracker, and ask-tracking caches). Warns if any file is unreadable.</td></tr>
      <tr><td>legacy</td><td>Scans settings.json for hook commands referencing the old <code>bash-gates</code> binary. Suggests <code>tool-gates hooks add</code> to fix.</td></tr>
    </tbody>
  </table>
  <p class="note">
    <svg class="alert" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
    <span><b>Read-only.</b> doctor never modifies settings or cache. Safe to run anytime. If a check fails it prints the suggested fix without applying it.</span>
  </p>

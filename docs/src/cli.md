  <p class="breadcrumb"><a href="index.html">Reference</a> / CLI Reference</p>
  <h1 id="cli-h1">CLI Reference</h1>
  <p class="page-lede">Every subcommand of <code>tool-gates</code>. The binary doubles as the hook entry point (reads tool-call JSON from stdin and emits a decision) and as a management CLI for inspecting and editing your settings.</p>
  <div class="sec-head" style="margin-top: var(--s-6)">
    <p class="lbl">Hook lifecycle</p>
    <h2>Install, inspect, audit.</h2>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>Command</th><th>What it does</th></tr>
    </thead>
    <tbody>
      <tr>
        <td><code>tool-gates hooks add -s user</code></td>
        <td>Wire all four tool-gates hooks into <code>~/.claude/settings.json</code>. Use <code>-s project</code> or <code>-s local</code> for project-scoped installs.</td>
      </tr>
      <tr>
        <td><code>tool-gates hooks add --gemini</code></td>
        <td>Wire BeforeTool and AfterTool into <code>~/.gemini/settings.json</code>.</td>
      </tr>
      <tr>
        <td><code>tool-gates hooks add --codex</code></td>
        <td>Wire PreToolUse, PermissionRequest, PostToolUse into <code>~/.codex/hooks.json</code>. The installer bakes <code>--client codex</code> into each command so the wire format routes correctly.</td>
      </tr>
      <tr>
        <td><code>tool-gates hooks add --antigravity</code></td>
        <td>Wire a single PreToolUse hook into <code>~/.gemini/antigravity-cli/hooks.json</code> (global-only; the sole path agy reads hooks from). The installer bakes <code>--client antigravity</code> into the command. Antigravity (<code>agy</code>) is Google's successor to the Gemini CLI.</td>
      </tr>
      <tr>
        <td><code>tool-gates hooks add … --dry-run</code></td>
        <td>Print what would change without writing. Works on every <code>hooks add</code> variant.</td>
      </tr>
      <tr>
        <td><code>tool-gates hooks status</code></td>
        <td>Report which clients have hooks installed and at which scope. Green / red status per hook.</td>
      </tr>
      <tr>
        <td><code>tool-gates hooks json [--codex|--antigravity|--gemini]</code></td>
        <td>Emit the canonical hook configuration as JSON (Claude shape by default; pass a client flag for that client's shape). Useful for diffing against an existing settings file.</td>
      </tr>
    </tbody>
  </table>
  <div class="sec-head">
    <p class="lbl">Approval learning</p>
    <h2>Pending queue and rules management.</h2>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>Command</th><th>What it does</th></tr>
    </thead>
    <tbody>
      <tr><td><code>tool-gates pending list [--project] [--json]</code></td><td>List queued asks across every project by default. <code>--project</code> filters to the current project; <code>--json</code> emits machine-readable output.</td></tr>
      <tr><td><code>tool-gates pending clear [--project | --all] --force</code></td><td>Empty the selected queue. Requires an explicit scope and <code>--force</code>; cannot be undone.</td></tr>
      <tr><td><code>tool-gates approve '&lt;pattern&gt;' -s &lt;scope&gt; [--type &lt;type&gt;] [--dry-run]</code></td><td>Write a permission rule into the named settings file. Scope is <code>local</code>, <code>project</code>, or <code>user</code>; type is <code>allow</code> by default and can be <code>ask</code> or <code>deny</code>.</td></tr>
      <tr><td><code>tool-gates rules list</code></td><td>List every rule currently in any settings file you control.</td></tr>
      <tr><td><code>tool-gates rules remove '&lt;pattern&gt;' -s &lt;scope&gt;</code></td><td>Remove a specific rule from the named settings file.</td></tr>
      <tr><td><code>tool-gates rules ask-audit</code></td><td>List <code>permissions.ask</code> rules in settings.json categorised by what tool-gates would do without them (gate-covered, safety floor, indeterminate).</td></tr>
      <tr><td><code>tool-gates rules ask-audit --apply</code></td><td>Multi-select TUI for removing redundant ask rules. The third "don't ask again" button reappears for everything removed.</td></tr>
      <tr><td><code>tool-gates rules export --format md [--out PATH] [--rules-dir PATH]</code></td><td>Regenerate <code>gates/*.md</code>, <code>security-floor.md</code>, and <code>hints.md</code> from <code>rules/*.toml</code> and the hint catalog. <code>--out</code> defaults to <code>docs/src</code>.</td></tr>
      <tr><td><code>tool-gates review</code></td><td>Open the interactive three-panel dashboard. <code>--all</code> shows every project; the default is the current project.</td></tr>
    </tbody>
  </table>
  <div class="sec-head">
    <p class="lbl">Diagnostics</p>
    <h2>Health check, cache, version.</h2>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>Command</th><th>What it does</th></tr>
    </thead>
    <tbody>
      <tr><td><code>tool-gates doctor</code></td><td>Verify config, hook installation, cache files, and flag legacy <code>bash-gates</code> remnants. <a href="doctor.html">More on the doctor page</a>.</td></tr>
      <tr><td><code>tool-gates --tools-status</code></td><td>Print which modern CLI tools (bat, rg, fd, sg, etc.) are detected on PATH. The hint engine uses this cache.</td></tr>
      <tr><td><code>tool-gates --refresh-tools</code></td><td>Re-scan the system for modern CLI tools and rewrite <code>~/.cache/tool-gates/available-tools.json</code>. Run after installing new tools.</td></tr>
      <tr><td><code>tool-gates --version</code></td><td>Print the version.</td></tr>
      <tr><td><code>tool-gates --help</code></td><td>Print the top-level help. Each subcommand also accepts <code>--help</code>.</td></tr>
    </tbody>
  </table>
  <p class="note">
    <svg class="alert" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
    <span><b>The CLI surfaces only the safe operations.</b> Mutating subcommands (<code>approve</code>, <code>rules remove</code>, <code>pending clear</code>, <code>hooks add</code>) ask for confirmation through the same gate engine that protects every other tool call. See the <a href="gates/tool_gates.html">tool_gates gate</a>.</span>
  </p>

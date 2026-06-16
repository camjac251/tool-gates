  <p class="breadcrumb"><a href="index.html">Getting Started</a> / Installation</p>
  <h1 id="install-h1">Installation</h1>
  <p class="page-lede">tool-gates is a single Rust binary. Install it, then point your assistant's settings at it. The same binary serves Claude Code, Codex CLI, Antigravity CLI, and the deprecated Gemini CLI. Claude Code and Gemini CLI are auto-detected from the hook payload; Codex and Antigravity are selected by the <code>--client codex</code> / <code>--client antigravity</code> flag the installer bakes into the hook command.</p>
  <div class="step">
    <p class="step-label">Step 1 · Install the binary</p>
    <div class="tabs">
      <div class="tablist" role="tablist">
        <button class="tab" data-tab="brew" role="tab" aria-selected="true">Homebrew</button>
        <button class="tab" data-tab="bin" role="tab" aria-selected="false">Pre-built binary</button>
        <button class="tab" data-tab="cargo" role="tab" aria-selected="false">Cargo</button>
      </div>
      <div class="tab-panels">
        <div class="tab-panel is-active" data-panel="brew" role="tabpanel">
          <p class="step-prose">Recommended on macOS and Linux. Bottles are built for arm64 and x86_64; the formula updates automatically on every release. Homebrew installation is supported for v1.5.6 and newer.</p>
<pre class="code-block"><span class="prompt">$</span> brew install camjac251/tap/tool-gates</pre>
          <p class="step-prose">Upgrade later with <code>brew upgrade tool-gates</code>.</p>
        </div>
        <div class="tab-panel" data-panel="bin" role="tabpanel">
          <p class="step-prose">Pick the right artifact for your platform; drop it on <code>PATH</code> and mark it executable. Pre-built binaries are available for versions v1.5.4 and newer.</p>
<pre class="code-block"><span class="prompt">$</span> curl -Lo ~/.local/bin/tool-gates https://github.com/camjac251/tool-gates/releases/latest/download/tool-gates-macos-arm64 &amp;&amp; chmod +x ~/.local/bin/tool-gates</pre>
          <p class="step-prose">Replace <code>macos-arm64</code> with <code>macos-x86_64</code>, <code>linux-arm64</code>, or <code>linux-x86_64</code> for your platform. Windows binaries are available for Bash-like environments such as Git Bash or MSYS2. PowerShell/cmd.exe command classification is not first-class yet; WSL users should use the Linux binary.</p>
        </div>
        <div class="tab-panel" data-panel="cargo" role="tabpanel">
          <p class="step-prose">Requires Rust 1.86 or newer. Builds from source into Cargo's bin directory.</p>
<pre class="code-block"><span class="prompt">$</span> cargo install --git https://github.com/camjac251/tool-gates</pre>
        </div>
      </div>
    </div>
  </div>
  <div class="step">
    <p class="step-label">Step 2 · Wire it into your assistant</p>
    <p class="step-prose">Each client uses a different hook protocol. The <code>hooks add</code> subcommand writes the right settings file in the right format. Multiple clients can run side by side. Settings files don't overlap.</p>
    <div class="install-clients">
      <article class="install-client">
        <header>
          <h3>Claude Code</h3>
          <span class="hooks-count">4 hooks</span>
        </header>
        <p>Compatible with the latest versions of Claude Code, with built-in fallbacks for legacy hook contracts.</p>
        <p>Personal use (recommended):</p>
<pre class="code-block"><span class="prompt">$</span> tool-gates hooks add -s user</pre>
        <p>Shared with team:</p>
<pre class="code-block"><span class="prompt">$</span> tool-gates hooks add -s project</pre>
        <ul class="hook-list">
          <li><code>PreToolUse</code>: main gate</li>
          <li><code>PermissionRequest</code>: subagent gate</li>
          <li><code>PermissionDenied</code>: auto-mode retry hint</li>
          <li><code>PostToolUse</code>: approval learning + Tier 2 nudges</li>
        </ul>
        <p class="settings-path">~/.claude/settings.json</p>
      </article>
      <article class="install-client">
        <header>
          <h3>Gemini CLI</h3>
          <span class="hooks-count">2 hooks</span>
        </header>
        <p><b>Deprecated:</b> Google sunsets the consumer Gemini CLI on 2026-06-18; use Antigravity for new setups. Requires Gemini CLI v0.36.0+ for <code>ask</code>-decision support on BeforeTool hooks.</p>
<pre class="code-block"><span class="prompt">$</span> tool-gates hooks add --gemini</pre>
        <ul class="hook-list">
          <li><code>BeforeTool</code>: gates every tool call</li>
          <li><code>AfterTool</code>: post-execution hook (no tracking/scanning yet)</li>
        </ul>
        <p class="settings-path">~/.gemini/settings.json</p>
      </article>
      <article class="install-client">
        <header>
          <h3>Codex CLI</h3>
          <span class="hooks-count">3 hooks</span>
        </header>
        <p>The installer bakes <code>--client codex</code> into every hook command so the wire format routes correctly.</p>
<pre class="code-block"><span class="prompt">$</span> tool-gates hooks add --codex</pre>
        <ul class="hook-list">
          <li><code>PreToolUse</code>: Bash + apply_patch + MCP</li>
          <li><code>PermissionRequest</code>: flat allow/deny</li>
          <li><code>PostToolUse</code>: Tier 3 warnings ride here</li>
        </ul>
        <p class="settings-path">~/.codex/hooks.json</p>
      </article>
      <article class="install-client">
        <header>
          <h3>Antigravity CLI</h3>
          <span class="hooks-count">1 hook</span>
        </header>
        <p>Google's successor to the Gemini CLI (<code>agy</code>). The installer bakes <code>--client antigravity</code> into the hook command so the wire format routes correctly.</p>
<pre class="code-block"><span class="prompt">$</span> tool-gates hooks add --antigravity</pre>
        <ul class="hook-list">
          <li><code>PreToolUse</code>: command safety, file guards, secret scanning</li>
        </ul>
        <p class="settings-path">~/.gemini/config/hooks.json</p>
      </article>
    </div>
    <p class="step-prose">Preview what would change with <code>--dry-run</code>:</p>
    <p class="step-prose">Claude Code:</p>
    <pre class="code-block"><span class="prompt">$</span> tool-gates hooks add -s user --dry-run</pre>
    <p class="step-prose">Gemini CLI:</p>
    <pre class="code-block"><span class="prompt">$</span> tool-gates hooks add --gemini --dry-run</pre>
    <p class="step-prose">Codex CLI:</p>
    <pre class="code-block"><span class="prompt">$</span> tool-gates hooks add --codex --dry-run</pre>
    <p class="step-prose">Antigravity CLI:</p>
    <pre class="code-block"><span class="prompt">$</span> tool-gates hooks add --antigravity --dry-run</pre>
  </div>
  <div class="step">
    <p class="step-label">Step 3 · Verify</p>
    <p class="step-prose">Confirm every hook is wired across every client:</p>
    <pre class="code-block"><span class="prompt">$</span> tool-gates hooks status</pre>
    <p class="step-prose">Or pipe a tool-call payload directly into the binary and watch the decision come back:</p>
    <p class="step-prose">Test a safe command (allowed):</p>
    <pre class="code-block"><span class="prompt">$</span> echo '{"tool_name":"Bash","tool_input":{"command":"git status"}}' | tool-gates
<span class="comment">→ {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"Read-only operation"}}</span></pre>
    <p class="step-prose">Test a dangerous command (blocked):</p>
    <pre class="code-block"><span class="prompt">$</span> echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | tool-gates
<span class="comment">→ {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"rm: `rm -rf /` blocked: would recursively delete the entire root filesystem."}}</span></pre>
    <p class="step-prose">For a full health check on config, hooks, cache files, and legacy <code>bash-gates</code> remnants: <code>tool-gates doctor</code>.</p>
  </div>
  <div class="step">
    <p class="step-label">Step 4 · Optional Claude Code plugin</p>
    <p class="step-prose">tool-gates also ships as a Claude Code plugin with two slash commands: <code>/tool-gates:review</code> opens the approval TUI, <code>/tool-gates:test-gate</code> runs a command against the gate engine without executing it. The plugin provides skills only; the hook installation above is the prerequisite.</p>
    <p class="step-prose">Add the marketplace:</p>
    <pre class="code-block"><span class="prompt">/plugin</span> marketplace add camjac251/tool-gates</pre>
    <p class="step-prose">Install the plugin:</p>
    <pre class="code-block"><span class="prompt">/plugin</span> install tool-gates@camjac251-tool-gates</pre>
    <p class="step-prose">Or from a local clone:</p>
    <pre class="code-block"><span class="prompt">$</span> claude --plugin-dir /path/to/tool-gates/claude-plugin</pre>
    <p class="step-prose">After install, the two slash commands are available inside any Claude Code session:</p>
    <p class="step-prose">Open the approval TUI:</p>
    <pre class="code-block"><span class="prompt">/tool-gates:review</span></pre>
    <p class="step-prose">Preview how the engine would decide a command:</p>
    <pre class="code-block"><span class="prompt">/tool-gates:test-gate</span></pre>
  </div>

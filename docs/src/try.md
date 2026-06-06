  <p class="breadcrumb"><a href="index.html">Getting Started</a> / Try the Simulator</p>
  <div class="try-title-bar">
    <h1 id="sim-h1" style="margin: 0;">Try the Simulator</h1>
    <span class="sim-engine-status" id="simEngineStatus" data-state="loading" aria-live="polite">
      <span class="sim-engine-dot" aria-hidden="true"></span>
      <span class="sim-engine-label">Loading engine…</span>
      <span class="sim-engine-meta">curated examples ready</span>
    </span>
  </div>
  <p class="page-lede">Watch a command walk through the gate pipeline. Pick a curated example below or enter your own command to see how the rules are evaluated. All commands (including curated examples) run locally in your browser using the real <code>tool-gates</code> engine compiled to WebAssembly. You can also drag and drop your own <code>settings.json</code> or <code>settings.local.json</code> files to simulate custom permission rules.</p>

  <div class="sec-head" style="margin-top: var(--s-5)">
    <p class="lbl">Examples</p>
    <h2>Pick a command.</h2>
  </div>
  <div class="sim-picker" role="group" aria-label="Example commands">
    <button class="sim-chip" data-sim="git-status" aria-pressed="true">git status</button>
    <button class="sim-chip" data-sim="git-push-force" aria-pressed="false">git push --force</button>
    <button class="sim-chip" data-sim="curl-bash" aria-pressed="false">curl … | bash</button>
    <button class="sim-chip" data-sim="rm-root" aria-pressed="false">rm -rf /</button>
    <button class="sim-chip" data-sim="compound" aria-pressed="false">git status &amp;&amp; rm -rf /</button>
    <button class="sim-chip" data-sim="npm-install" aria-pressed="false">npm install lodash</button>
    <button class="sim-chip" data-sim="cargo-check" aria-pressed="false">cargo check</button>
    <button class="sim-chip" data-sim="head-pipe" aria-pressed="false">cargo test | head -20</button>
    <button class="sim-chip" data-sim="gh-repo-list" aria-pressed="false">gh repo list</button>
    <button class="sim-chip" data-sim="gh-repo-delete" aria-pressed="false">gh repo delete</button>
    <button class="sim-chip" data-sim="cat-file" aria-pressed="false">cat file.txt</button>
    <button class="sim-chip" data-sim="grep-r" aria-pressed="false">grep -r "TODO" src/</button>
  </div>

  <div class="sim-engine">
    <form class="sim-custom" id="simCustomForm" autocomplete="off">
      <span class="prompt" aria-hidden="true">$</span>
      <input class="sim-custom-input" id="simCustomInput" name="command" type="text" disabled aria-disabled="true" aria-label="Custom command" placeholder="Loading engine: try a curated example above" />
      <button class="btn btn-ghost sim-custom-run" id="simCustomRun" type="submit" disabled>Run</button>
    </form>
  </div>

  <div class="sim-settings-upload" id="settingsDropZone">
    <div class="drop-zone-content">
      <svg class="icon-upload" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
        <polyline points="17 8 12 3 7 8"></polyline>
        <line x1="12" y1="3" x2="12" y2="15"></line>
      </svg>
      <div class="drop-zone-text">
        <span class="highlight">Drag &amp; drop settings.json</span> or settings.local.json files here
      </div>
      <div class="drop-zone-sub">Files are parsed locally and never uploaded. Click to browse.</div>
    </div>
    <input type="file" id="settingsFileInput" multiple accept=".json" style="display: none;" />
  </div>

  <div class="active-settings-panel" id="activeSettingsPanel" style="display: none;">
    <div class="panel-header">
      <span class="panel-title">Active Settings Rules</span>
      <button class="btn btn-ghost btn-xs" id="clearSettingsBtn">Clear</button>
    </div>
    <div class="panel-body" id="activeSettingsRulesList"></div>
  </div>

  <div class="sim-input" aria-live="polite">
    <span class="prompt">$</span><span class="sim-cmd" id="simCmdDisplay">git status</span>
  </div>
  <div class="lifecycle" aria-label="Gate pipeline">
    <div class="lc-bar">
      <span class="lights"><i></i><i></i><i></i></span>
      <span class="lc-label">gate pipeline · stepping through</span>
    </div>
    <div class="lc-track" id="simStages">
      <div class="lc-node sim-stage" data-stage="raw">
        <span class="lc-icon">▸</span>
        <span class="lc-tag">router.rs</span>
        <div class="lc-title">Raw-string scan</div>
        <div class="sim-stage-note">awaiting input…</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node sim-stage" data-stage="parse">
        <span class="lc-icon">▸</span>
        <span class="lc-tag">parser.rs</span>
        <div class="lc-title">tree-sitter parse</div>
        <div class="sim-stage-note">awaiting input…</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node sim-stage" data-stage="gate">
        <span class="lc-icon">▸</span>
        <span class="lc-tag">gates/*.rs</span>
        <div class="lc-title">Gate dispatch</div>
        <div class="sim-stage-note">awaiting input…</div>
      </div>
      <div class="lc-edge"></div>
      <div class="lc-node sim-stage" data-stage="settings">
        <span class="lc-icon">▸</span>
        <span class="lc-tag">settings.rs</span>
        <div class="lc-title">Settings.json merge</div>
        <div class="sim-stage-note">awaiting input…</div>
      </div>
    </div>
  </div>
  <div class="sim-result" id="simResult" aria-live="polite">
    <span class="sim-pill-host"></span>
    <div class="sim-reason"></div>
  </div>
  <p class="note" style="margin-top: var(--s-6)">
    <svg class="alert" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
    <span><b>Execution is completely local.</b> Loading the engine fetches a WebAssembly-compiled <code>tool-gates</code> build (~600KB) that runs the actual raw-string, parse, and gate-dispatch pipeline in your browser. Dragged-and-dropped settings files are parsed in memory and never sent to any server.</span>
  </p>

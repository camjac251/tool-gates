  <div class="hero">
    <span class="eyebrow reveal" style="--i:0"><span class="dot"></span> Rust · tree-sitter · Claude Code · Codex CLI · Antigravity CLI</span>
    <h1 id="home-h1" class="reveal" style="--i:1">Decide what your agent is allowed to <span class="hl">run</span>.</h1>
    <p class="lede reveal" style="--i:2">tool-gates is a permission hook for AI coding assistants. On the hook surfaces each client exposes, it gates shell commands, file edits, MCP calls, and Skill activations, parses commands with a real <code>tree-sitter</code> AST, and resolves them against thirteen declarative gates covering 400+ command patterns. One result per call: <b>allow</b>, <b>ask</b>, <b>defer</b>, or <b>block</b>.</p>
    <div class="cta-row reveal" style="--i:3">
      <a href="gates/git.html" class="btn btn-primary">Browse the gates</a>
      <a href="install.html" class="btn btn-ghost">Install <span class="sh">brew install camjac251/tap/tool-gates</span></a>
    </div>
    <!-- Interceptor panel: real surfaces -->
    <div class="interceptor reveal" style="--i:4" aria-label="Example tool calls and how tool-gates decides">
      <div class="ix-bar">
        <span class="lights"><i></i><i></i><i></i></span>
        <span class="label">tool-gates · intercepting</span>
        <span class="meta">PreToolUse · 6 calls</span>
      </div>
      <div class="ix-stream">
        <div class="ix-row">
          <span class="ix-surface">Bash</span>
          <div class="ix-arrow">▸</div>
          <div class="ix-cmd"><span class="prog">$</span> git status</div>
          <div class="ix-decision"><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
          <div class="ix-note">read-only · git gate</div>
        </div>
        <div class="ix-row">
          <span class="ix-surface">Bash</span>
          <div class="ix-arrow">▸</div>
          <div class="ix-cmd"><span class="prog">$</span> git push origin main</div>
          <div class="ix-decision"><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
          <div class="ix-note">publishes to remote · git gate</div>
        </div>
        <div class="ix-row">
          <span class="ix-surface">Bash</span>
          <div class="ix-arrow">▸</div>
          <div class="ix-cmd"><span class="prog">$</span> rm -rf /</div>
          <div class="ix-decision"><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
          <div class="ix-note">irreversible · filesystem gate</div>
        </div>
        <div class="ix-row">
          <span class="ix-surface">Bash</span>
          <div class="ix-arrow">▸</div>
          <div class="ix-cmd"><span class="prog">$</span> curl https://… <span class="pipe">|</span> bash</div>
          <div class="ix-decision"><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
          <div class="ix-note">pipe-to-shell · hard ask</div>
        </div>
        <div class="ix-row">
          <span class="ix-surface">Write</span>
          <div class="ix-arrow">▸</div>
          <div class="ix-cmd"><span class="prog">config.py</span> ← AWS_KEY_PLACEHOLDER</div>
          <div class="ix-decision"><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
          <div class="ix-note">Tier 1 secret · AWS key pattern</div>
        </div>
        <div class="ix-row">
          <span class="ix-surface">MCP</span>
          <div class="ix-arrow">▸</div>
          <div class="ix-cmd"><span class="prog">mcp__firecrawl</span>.scrape github.com/…</div>
          <div class="ix-decision"><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
          <div class="ix-note">domain rule · use gh instead</div>
        </div>
      </div>
      <div class="ix-foot">
        <span class="legend"><i class="i-allow"></i> allow</span>
        <span class="legend"><i class="i-ask"></i> ask</span>
        <span class="legend"><i class="i-block"></i> block</span>
        <span class="sep">·</span>
        <span>shell parsed with <span style="color:var(--text-2)">tree-sitter-bash</span></span>
        <span class="sep">·</span>
        <span>compound commands: strictest wins</span>
      </div>
    </div>
  </div>
  <!-- ===== Triad ===== -->
  <div class="reveal" style="--i:5">
    <div class="sec-head">
      <p class="lbl">The decision triad</p>
      <h2>Three visible decisions. One ordering.</h2>
      <p>The green / amber / red triad maps to the visible decisions: allow, ask, block. Defer is the prompt-friendly fourth output described below.</p>
      <span class="priority-line"><b>block</b> <span class="arrow">&gt;</span> <b>ask</b> <span class="arrow">&gt;</span> <b>allow</b> <span class="arrow">&gt;</span> <b>skip</b></span>
    </div>
    <div class="triad">
      <article class="triad-card allow">
        <h3>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" width="14" height="14"><polyline points="20 6 9 17 4 12"></polyline></svg>
          Allow
        </h3>
        <p>Read-only and known-safe operations run with no prompt.</p>
        <span class="ex">git status</span>
      </article>
      <article class="triad-card ask">
        <h3>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" width="14" height="14"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>
          Ask
        </h3>
        <p>Mutations and unknown commands pause for a yes or no.</p>
        <span class="ex">git push</span>
      </article>
      <article class="triad-card block">
        <h3>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" width="14" height="14"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>
          Block
        </h3>
        <p>Irreversible or hostile patterns are denied regardless of settings.</p>
        <span class="ex">rm -rf /</span>
      </article>
    </div>
    <p class="triad-foot">A fourth output, <b>defer</b>, omits the decision and lets the assistant's own resolver populate the "don't ask again for X" button. Used for benign asks not covered by an explicit rule.</p>
  </div>
  <!-- ===== Compound priority strip ===== -->
  <div class="compound reveal" style="--i:6" aria-label="Compound command resolution">
    <p class="lbl">Compound resolution</p>
    <div class="cm-h">
      <h3>Strictest wins.</h3>
      <span class="hint">tree-sitter sees both halves of <code style="font-family:var(--font-mono);font-size:12px;color:var(--text-2);background:var(--surface-2);padding:1px 5px;border-radius:var(--r-1)">&amp;&amp;</code> · <code style="font-family:var(--font-mono);font-size:12px;color:var(--text-2);background:var(--surface-2);padding:1px 5px;border-radius:var(--r-1)">||</code> · <code style="font-family:var(--font-mono);font-size:12px;color:var(--text-2);background:var(--surface-2);padding:1px 5px;border-radius:var(--r-1)">|</code> · <code style="font-family:var(--font-mono);font-size:12px;color:var(--text-2);background:var(--surface-2);padding:1px 5px;border-radius:var(--r-1)">;</code> chains. One verdict for the whole call.</span>
    </div>
    <div class="expr">
      <div class="tok allow">
        <div class="tag">allow</div>
        <div class="cmd"><span class="prog">$</span> git status</div>
      </div>
      <div class="op">&amp;&amp;</div>
      <div class="tok block">
        <div class="tag">block</div>
        <div class="cmd"><span class="prog">$</span> rm -rf /</div>
      </div>
    </div>
    <div class="verdict">
      <span>verdict</span>
      <span class="arrow">→</span>
      <span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span>
      <span style="color:var(--text-3)">the whole expression is denied; the safe half is not a redeeming feature.</span>
    </div>
  </div>
  <!-- ===== Four surfaces (more than shell) ===== -->
  <div class="reveal" style="--i:7">
    <div class="sec-head">
      <p class="lbl">Surfaces</p>
      <h2>More than shell.</h2>
      <p>The same engine fires across every tool surface the assistant exposes. Shell is the loudest case; the other three are where the agent slips past most policy systems.</p>
    </div>
    <div class="surfaces">
      <div class="surf">
        <div class="ic"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg></div>
        <h4>Bash · Monitor</h4>
        <p>Shell commands are parsed with tree-sitter and resolved per-program. Compound chains decompose; raw-string passes catch pipe-to-shell and eval first.</p>
        <span class="ex">git push --force</span>
      </div>
      <div class="surf">
        <div class="ic"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg></div>
        <h4>Write · Edit · apply_patch</h4>
        <p>File-edit bodies are scanned for 28 anti-patterns. Tier-1 secrets deny before write; symlinked AI config files (CLAUDE.md, .cursorrules) are guarded so the agent can't read through them.</p>
        <span class="ex">config.py ← AWS_KEY</span>
      </div>
      <div class="surf">
        <div class="ic"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg></div>
        <h4>MCP tools</h4>
        <p>Configurable block rules cover Glob, Grep, and firecrawl/ref/exa calls to GitHub. In <code style="font-family:var(--font-mono);font-size:12px">acceptEdits</code> mode, named MCP tools auto-approve, filling the gap Claude Code leaves open.</p>
        <span class="ex">mcp__exa.search</span>
      </div>
      <div class="surf">
        <div class="ic"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg></div>
        <h4>Skill activations</h4>
        <p><code style="font-family:var(--font-mono);font-size:12px">[[auto_approve_skills]]</code> auto-approves Skill calls based on project-directory conditions. No external hook scripts; the rule is declarative.</p>
        <span class="ex">activate_skill review</span>
      </div>
    </div>
  </div>
  <!-- ===== Four clients ===== -->
  <div class="reveal" style="--i:8">
    <div class="sec-head">
      <p class="lbl">Multi-client</p>
      <h2>Four clients, one engine.</h2>
      <p>The same Rust binary serves Claude Code, Codex CLI, Antigravity CLI, and the deprecated Gemini CLI. The client is auto-detected from the hook payload, or selected with <code style="font-family:var(--font-mono);font-size:0.92em">--client codex</code> / <code style="font-family:var(--font-mono);font-size:0.92em">--client antigravity</code> where event names collide or are absent. Each gets exactly the wire format it expects.</p>
    </div>
    <div class="clients">
      <article class="client">
        <h4>Claude Code <span class="count">· 4 hooks</span></h4>
        <ul>
          <li><i></i>PreToolUse</li>
          <li><i></i>PermissionRequest</li>
          <li><i></i>PermissionDenied</li>
          <li><i></i>PostToolUse</li>
        </ul>
        <p class="client-note">PermissionDenied emits <code>retry: true</code> when the auto-mode classifier denies a command tool-gates would allow.</p>
        <p class="pathline"><code>~/.claude/settings.json</code></p>
      </article>
      <article class="client">
        <h4>Gemini CLI <span class="count">· 2 hooks · deprecated</span></h4>
        <ul>
          <li><i></i>BeforeTool</li>
          <li><i></i>AfterTool</li>
        </ul>
        <p class="client-note"><b>Deprecated:</b> Google sunsets the consumer Gemini CLI on 2026-06-18; use Antigravity for new setups. Requires v0.36.0+ for <code>ask</code> support. No PermissionRequest, no approval tracking; tool-gates emits <code>"block"</code> for hard blocks, and Gemini also accepts <code>"deny"</code>.</p>
        <p class="pathline"><code>~/.gemini/settings.json</code></p>
      </article>
      <article class="client">
        <h4>Codex CLI <span class="count">· 3 hooks</span></h4>
        <ul>
          <li><i></i>PreToolUse</li>
          <li><i></i>PermissionRequest</li>
          <li><i></i>PostToolUse</li>
        </ul>
        <p class="client-note"><code>apply_patch</code> is the canonical edit tool; tool-gates parses the unified diff so file-guards and secret scans run per affected path.</p>
        <p class="pathline"><code>~/.codex/hooks.json</code></p>
      </article>
      <article class="client">
        <h4>Antigravity CLI <span class="count">· 1 hook</span></h4>
        <ul>
          <li><i></i>PreToolUse</li>
        </ul>
        <p class="client-note">Google's Gemini CLI successor (<code>agy</code>). Selected via <code>--client antigravity</code>; a flat <code>decision</code> output and a <code>hooks.json</code> keyed by hook name. PreToolUse drives the whole gate.</p>
        <p class="pathline"><code>~/.gemini/antigravity-cli/hooks.json</code></p>
      </article>
    </div>
    <p class="clients-foot"><b>One binary.</b> Routing is via <code style="font-family:var(--font-mono);font-size:0.92em">hook_event_name</code>, or the <code style="font-family:var(--font-mono);font-size:0.92em">--client</code> flag where event names collide or are absent; the same gate engine returns the right shape for the right client.</p>
  </div>
  <!-- ===== TOML proof ===== -->
  <div class="reveal" style="--i:9">
    <div class="sec-head">
      <p class="lbl">Single source of truth</p>
      <h2>The TOML is the doc.</h2>
      <p>Every rule below is generated from the same files <code style="font-family:var(--font-mono);font-size:0.92em">build.rs</code> already reads to build the binary. Editing a reason changes the published page; CI fails when the committed docs drift.</p>
    </div>
    <div class="proof">
      <div class="pf-cols">
        <div class="pf-col">
          <div class="pf-tab">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
            <span class="file">rules/git.toml</span>
          </div>
<pre><span class="sec">[meta]</span>
<span class="k">name</span>     = <span class="s">"git"</span>
<span class="k">priority</span> = <span class="s">10</span>
<span class="c"># Read-only. Pass through</span>
<span class="sec">[[programs.allow]]</span>
<span class="k">subcommand</span> = <span class="s">"status"</span>
<span class="c"># Mutation. Pause for approval</span>
<span class="sec">[[programs.ask]]</span>
<span class="k">subcommand</span> = <span class="s">"push"</span>
<span class="k">reason</span>     = <span class="s">"Publishes local commits</span>
<span class="s">             to a remote. Inspect</span>
<span class="s">             `git log @{u}..` first."</span>
<span class="c"># Force push. Same name, narrower flag</span>
<span class="sec">[[programs.ask]]</span>
<span class="k">subcommand</span>    = <span class="s">"push"</span>
<span class="k">if_flags_any</span>  = [<span class="s">"--force"</span>, <span class="s">"-f"</span>]
<span class="k">warn</span>          = <span class="s">true</span>
<span class="k">reason</span>        = <span class="s">"Force push overwrites</span>
<span class="s">                upstream history. Safer:</span>
<span class="s">                `--force-with-lease`."</span></pre>
        </div>
        <div class="pf-col">
          <div class="pf-tab">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>
            <span class="file">docs / git gate</span>
          </div>
          <div class="out-row">
            <span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span>
            <div>
              <div class="ocmd"><span class="prog">git</span> status</div>
              <div class="oreason">Read-only. No reason text required.</div>
            </div>
          </div>
          <div class="out-row">
            <span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span>
            <div>
              <div class="ocmd"><span class="prog">git</span> push</div>
              <div class="oreason">Publishes local commits to a remote. Inspect <code style="font-family:var(--font-mono);font-size:0.86em">git log @{u}..</code> first.</div>
            </div>
          </div>
          <div class="out-row">
            <span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span>
            <div>
              <div class="ocmd"><span class="prog">git</span> push <span style="color:var(--accent-2)">--force</span></div>
              <div class="oreason">Force push overwrites upstream history. Safer: <code style="font-family:var(--font-mono);font-size:0.86em">--force-with-lease</code> fails if the remote moved.</div>
            </div>
          </div>
        </div>
      </div>
      <footer>
        <span class="pf-flow">
          <code>rules/*.toml</code>
          <span>→</span>
          <code>tool-gates rules export --format md</code>
          <span>→</span>
          <code>mdBook</code>
          <span>→</span>
          <span style="color:var(--accent)">this page</span>
        </span>
        <span class="sep">·</span>
        <span>CI runs <code>git diff --exit-code</code>; stale docs fail the build.</span>
      </footer>
    </div>
  </div>
  <!-- ===== Modern CLI hints ===== -->
  <div class="reveal" style="--i:10">
    <div class="sec-head">
      <p class="lbl">Modern CLI hints</p>
      <h2>Allow, then teach.</h2>
      <p>When the agent reaches for a legacy tool that has a sharper modern alternative, tool-gates allows the call <em>and</em> attaches a one-line suggestion via <code style="font-family:var(--font-mono);font-size:0.92em">additionalContext</code>. Hints only fire when the modern tool is actually installed on this machine.</p>
    </div>
    <div class="hints">
      <header>
        <h3>Examples</h3>
        <span class="note">7-day cache · <code style="font-family:var(--font-mono);font-size:0.9em">tool-gates --tools-status</code> to inspect</span>
      </header>
      <div class="hint-row">
        <div class="old"><span class="prog">$</span> <s>cat</s> README.md</div>
        <div class="arrow">→</div>
        <div class="new"><span class="prog">$</span> bat README.md</div>
        <div class="why"><b>Tip from tool-gates:</b> syntax highlighting + line numbers + markdown rendering.</div>
      </div>
      <div class="hint-row">
        <div class="old"><span class="prog">$</span> <s>grep -r</s> "TODO" src/</div>
        <div class="arrow">→</div>
        <div class="new"><span class="prog">$</span> rg "TODO" src/</div>
        <div class="why"><b>Tip from tool-gates:</b> respects <code style="font-family:var(--font-mono);font-size:0.86em">.gitignore</code>, multithreaded, faster on large trees.</div>
      </div>
      <div class="hint-row">
        <div class="old"><span class="prog">$</span> <s>find</s> . -name "*.rs"</div>
        <div class="arrow">→</div>
        <div class="new"><span class="prog">$</span> fd -e rs</div>
        <div class="why"><b>Tip from tool-gates:</b> shorter syntax; <code style="font-family:var(--font-mono);font-size:0.86em">--max-results</code> caps output at the source.</div>
      </div>
      <div class="hint-row">
        <div class="old"><span class="prog">$</span> rg "TODO" <s>| head -20</s></div>
        <div class="arrow">→</div>
        <div class="new"><span class="prog">$</span> rg -m 20 "TODO"</div>
        <div class="why"><b>Pipe to head is blocked.</b> Caps applied at the source produce smaller, deterministic output. Also <code style="font-family:var(--font-mono);font-size:0.86em">fd --max-results N</code>, <code style="font-family:var(--font-mono);font-size:0.86em">bat -r START:END</code>.</div>
      </div>
    </div>
  </div>
  <!-- ===== Security reminders ===== -->
  <div class="reveal" style="--i:11">
    <div class="sec-head">
      <p class="lbl">Security reminders</p>
      <h2>Three tiers of write-time review.</h2>
      <p>28 anti-patterns watch every Write/Edit body. The hard floor denies before the file ever lands; the middle tier nudges Claude and Codex after the write so the next action can self-correct; the top tier just informs.</p>
    </div>
    <div class="tiers">
      <article class="tier t1">
        <div class="row1"><span class="tname">Tier 1</span><span class="when">· PreToolUse · deny</span></div>
        <h4>Hard-coded secrets.</h4>
        <p>Denied before the write. The operator sees a top-level <code style="font-family:var(--font-mono);font-size:0.92em">systemMessage</code> so the block isn't silent.</p>
        <div class="examples">
          <span>AKIA…</span><span>ghp_…</span><span>BEGIN PRIVATE KEY</span><span>xoxb-…</span><span>sk_live_…</span>
        </div>
      </article>
      <article class="tier t2">
        <div class="row1"><span class="tname">Tier 2</span><span class="when">· PostToolUse · context</span></div>
        <h4>Anti-pattern in the body.</h4>
        <p>Write lands; the assistant sees a <code style="font-family:var(--font-mono);font-size:0.92em">&lt;system-reminder&gt;</code> in its next turn. No re-prompting, no wasted edit. Deduped per (file, rule) per session.</p>
        <div class="examples">
          <span>eval()</span><span>shell=True</span><span>dangerouslySetInnerHTML</span><span>yaml.load</span><span>SQL f-string</span>
        </div>
      </article>
      <article class="tier t3">
        <div class="row1"><span class="tname">Tier 3</span><span class="when">· Pre/Post hook · allow + warn</span></div>
        <h4>Informational only.</h4>
        <p>Pattern is allowed; a one-line warning rides on <code style="font-family:var(--font-mono);font-size:0.92em">additionalContext</code>. Fires once per session.</p>
        <div class="examples">
          <span>verify=False</span><span>chmod 777</span><span>MD5/SHA1</span><span>CORS *</span><span>autoescape=False</span><span>Math.random()</span><span>createHash md5/sha1</span>
        </div>
      </article>
    </div>
  </div>

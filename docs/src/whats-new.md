  <nav class="breadcrumb" aria-label="Breadcrumb">
    <ol>
      <li><a href="index.html">tool-gates</a></li>
      <li>Start</li>
      <li aria-current="page">What's New</li>
    </ol>
  </nav>
  <h1 id="whatsnew-h1">What's new</h1>
  <p class="page-lede">Release cadence is fast. Start with the latest eight versions, then open the historical archive when you need an earlier change. The complete release history remains in <a href="https://github.com/camjac251/tool-gates/blob/main/CHANGELOG.md" target="_blank" rel="noopener">CHANGELOG.md</a>.</p>
  <section class="release-current" aria-labelledby="release-current-title">
    <header class="sec-head release-section-head">
      <span class="lbl">Current window</span>
      <h2 id="release-current-title">Latest eight versions</h2>
      <p>From v1.34.1 through v1.33.0, newest first.</p>
    </header>
  <div class="config-block">
    <header>
      <h3>v1.34.1 · August 11, 2026</h3>
      <span class="src-tag">classifier retry hints · <a href="https://github.com/camjac251/tool-gates/commit/e5135ca" target="_blank" rel="noopener">e5135ca</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  skip retry hints on safety-filter refusal denials
  skip retry hints when the classifier request was aborted</pre>
      </div>
      <div class="config-prose">
        <p>PermissionDenied retry hints close the loop on classifier false positives: when auto mode's classifier denies a command the gate engine would allow, tool-gates tells the model it may retry. Two denial classes wear the classifier's label without being a judgment of the command, and both were getting a contradictory hint. A safety filter can refuse to evaluate the check because of earlier conversation content; that block is about the transcript, not the action, and Claude Code already tells the model to move past it, so a retry only re-triggers the refusal. A classifier request aborted by an interrupt or timeout is a stop signal, and a retry hint talks over it. Both now match the non-judgment guard and suppress the hint.</p>
        <p>The boundary is deliberate: plain could-not-evaluate errors and transcript-too-long denials stay retryable, because the guidance there is to retry or compact and the hint still helps. With auto mode becoming the default permission mode for new sessions on August 14, 2026, the PermissionDenied path moves from opt-in traffic to the common case; the <a href="auto-mode.html">Auto mode</a> page now documents the rollout, the repo-level opt-out, and how <code>classifyAllShell</code> interacts with the gate catalog.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.34.0 · August 6, 2026</h3>
      <span class="src-tag">opt-in comment-volume lint · <a href="https://github.com/camjac251/tool-gates/commit/d7f833c" target="_blank" rel="noopener">d7f833c</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  flag an edit that adds far more commentary than code
  flag a single comment block running past a short paragraph
  tune thresholds and disable individual rules under [comment_lint]</pre>
      </div>
      <div class="config-prose">
        <p>Existing guidance covers whether a comment is worth writing; nothing bounded how many or how long. Two volume rules now do. The first fires when an edit's narrative comment lines outweigh the code it adds, and the second when one run of own-line comments stretches past a short paragraph. Doc comments and tooling directives are exempt, because both are addressed to a reader who asked for them, and only code extensions are scanned.</p>
        <p>The check runs on the PostToolUse path beside security reminders and design lint, so it sees Claude <code>Write</code>/<code>Edit</code> and Codex <code>apply_patch</code> added lines through one shared surface. Thresholds target the tail rather than the median: 40 comment lines per 100 code lines, applied only once an edit adds 15 code lines, and a maximum run of 5 consecutive comment lines. Small edits are legitimately comment-dense and would otherwise dominate, and every injection costs tokens and disturbs the prompt cache, so the floor is deliberately high.</p>
        <p>Off by default. This is a house style rather than a safety floor, so it stays behind <code>features.comment_lint</code>; thresholds and individual rule ids are configurable under <code>[comment_lint]</code>.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.33.5 · August 6, 2026</h3>
      <span class="src-tag">redirect targets + background waits · <a href="https://github.com/camjac251/tool-gates/commit/f305d71" target="_blank" rel="noopener">f305d71</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  stop redirect targets at shell separators
  keep process substitution in the redirect target
  reject a blocking wait on a just-started background task</pre>
      </div>
      <div class="config-prose">
        <p>The redirect floor resolved an unquoted target by reading to the next whitespace, so a separator glued to the path became part of it. <code>2&gt;/dev/null; echo done</code> resolved to <code>/dev/null;</code>, which missed the <code>/dev/null</code> exemption and then matched the <code>/dev/</code> prefix, reporting a discarded stream as a clobber of a system path. Subshell and unspaced pipe forms failed the same way, and a redirect into the session scratch dir lost its exemption for the same reason. Every target class now stops at the metacharacters that close a bash word.</p>
        <p><code>(</code> is deliberately not in that set. It only ever opens a target, so excluding it drops the match for <code>&gt;(cmd)</code> process substitution entirely and <code>echo x &gt;(cat)</code> reads as a plain read-only command rather than a subprocess write. A differential sweep across 1,930 redirect forms confirms the <code>/dev/null</code> exemption is the only resulting behavior change, in either direction.</p>
        <p>A command started with <code>run_in_background</code> for concurrency could be followed immediately by a blocking <code>TaskOutput</code>, which discards the concurrency and spends a turn waiting. Successful background starts are now correlated by session and task, and only that immediate pairing is denied. A later intentional wait on the same task still runs, and non-blocking status checks are never affected. The correlation is session-scoped with a ten-minute expiry and fails open on any ambiguity, so a missing or malformed argument allows rather than blocks.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.33.4 · July 31, 2026</h3>
      <span class="src-tag">client-aware recovery · <a href="https://github.com/camjac251/tool-gates/commit/dfaec8f" target="_blank" rel="noopener">dfaec8f</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  keep output-cap recovery semantic until serialization
  distinguish source files from streams in recovery advice
  preserve recovery actions through task expansion</pre>
      </div>
      <div class="config-prose">
        <p>Output-cap denials mixed the shared safety cause with reader advice that could name a tool the client does not have or use a wire field it does not consume. Recovery is now carried as a semantic action until serialization, so each client renders it through its own supported channel and its own tool names, sourced from the per-client file-tool registry instead of being fixed in shared copy. Advice distinguishes a source file from a stream, and actions survive mise and package-script expansion, so a wrapped command keeps the guidance its inner command earned.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.33.3 · July 30, 2026</h3>
      <span class="src-tag">client-neutral feedback · <a href="https://github.com/camjac251/tool-gates/commit/d003f6b" target="_blank" rel="noopener">d003f6b</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  keep shared deny copy portable across clients
  drop client-only tool names from the less hint</pre>
      </div>
      <div class="config-prose">
        <p>Shared feedback is written once and rendered for every client, so naming one client's tools inside it leaves the others with advice they cannot follow. Routine denies stay operator-visible even when the optional top-level warning is omitted, and the per-client visibility contract is now documented rather than implied. The <code>less</code> hint drops its reference to specific tool names and states the portable reason instead: line-numbered output supports precise follow-up edits and range reads.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.33.2 · July 30, 2026</h3>
      <span class="src-tag">sensitive redirect holds · <a href="https://github.com/camjac251/tool-gates/commit/7b03484" target="_blank" rel="noopener">7b03484</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  hold redirects to system and credential paths under auto mode</pre>
      </div>
      <div class="config-prose">
        <p>v1.33.0 routed soft asks to auto mode's classifier, which treated every output redirect alike, so clobbering <code>/etc/passwd</code> or rewriting <code>~/.ssh/authorized_keys</code> became a classifier decision where it had been a prompt. Writing one named file is the most common shell shape there is and belongs on the classifier; a sensitive destination does not. The redirect handler already resolves its target to exempt <code>/dev/null</code> and the session scratch dir, so it keeps the ask when that path is a system directory, a credential store, or a key file, and names the target in the reason. The per-path test was split out of the acceptEdits policy so the floor asks the same question rather than growing a second list that can drift. Ordinary destinations, and <code>/dev/null</code>, are unchanged.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.33.1 · July 30, 2026</h3>
      <span class="src-tag">build drift detection · <a href="https://github.com/camjac251/tool-gates/commit/1d4fb4e" target="_blank" rel="noopener">1d4fb4e</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  flag clients whose hooks resolve to different builds
  report a hook command that resolves to no binary</pre>
      </div>
      <div class="config-prose">
        <p>Installed is not the same as current. Every hook check reported a client as installed while the command it invokes resolved to an older binary, so a stale absolute path, or a bare name shadowed earlier on <code>PATH</code>, kept answering permission checks with previous logic and <code>doctor</code> still passed. Doctor now resolves the binary behind every installed hook across all four clients and groups them by target, and clients disagreeing with each other is the reported failure. Comparing them to each other rather than to the running process avoids flagging a build run out of the source tree, whose path legitimately differs from the installed one.</p>
        <p>Resolution mirrors what the shell would do: first word, quotes stripped because the Antigravity installer writes them, bare names looked up on <code>PATH</code>, and the result canonicalized so a symlinked install compares equal to its target. A command that resolves to no binary is reported separately, since that hook cannot run at all. The remediation names the reason the installer must be invoked by absolute path: it records argv[0] when that contains a separator and otherwise resolves through <code>PATH</code>, which is how a shadowed binary reinstalls itself.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.33.0 · July 30, 2026</h3>
      <span class="src-tag">auto-mode classifier routing · <a href="https://github.com/camjac251/tool-gates/commit/a9a93f2" target="_blank" rel="noopener">a9a93f2</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  defer gate asks under auto mode so the classifier adjudicates
  auto = "prompt" holds a prompt the classifier cannot bypass
  record whether a human or the classifier approved a queue entry
<span class="sec fixed">Fixed</span>
  scope the acceptEdits base guard to the whole command chain
  reach 27 cloud rules that subcommand lookups could never match
  apply git rules to path-qualified invocations
  consult the gcloud catalog at every argument count
  allow ten rules whose own reason text refutes the ask</pre>
      </div>
      <div class="config-prose">
        <p>Routes the gate catalog through auto mode's classifier instead of around it. Claude Code returns a hook <code>ask</code> to the user without consulting that classifier, so emitting one under auto excluded every declarative rule from the mechanism the mode exists to provide; <code>defer</code> is the decision that reaches it. Replaying a local approval history puts roughly four in five previously-prompted commands on the classifier path.</p>
        <p>Irreversible, externally visible work opts out. <code>auto = "prompt"</code> on an ask rule keeps a prompt the classifier cannot bypass, and now covers registry publishes, credential and key mutation, infrastructure teardown, remote state overwrites, and the commands that rewrite tool-gates' own permission config. The disposition survives wrapper expansion, so a mise task or package script that reaches <code>npm publish</code> inherits the hold. The same marker applies to raw-floor rows, holding the patterns that run a destructive command once per match (<code>find -delete</code>, <code>find -exec</code>, <code>fd -x</code>, <code>xargs</code>) while redirects, <code>source</code>, and pipe-to-interpreter defer.</p>
        <p>The acceptEdits base-command guard now requires every sub-command in a chain, matching when Claude's own fast path can fire, so <code>mkdir -p dist &amp;&amp; cargo build</code> no longer denies under auto. Its outcome drops from deny to ask, and base names resolve through quoting, a leading backslash, and transparent prefixes so <code>\rm</code> and <code>stdbuf -o0 rm</code> cannot slip past. The approval queue records entries under auto tagged with whether a person answered a prompt or the classifier resolved a defer unseen, and the review list shows the difference so a rule is never granted on a silent approval.</p>
        <p>Three long-standing catalog bugs surfaced while tracing that work. Declarative subcommand lookups only ever built a two-word key, leaving all 27 three-word cloud rules unreachable. The Git gate rejected path-qualified invocations, so <code>/usr/bin/git push --force</code> lost every Git rule. The gcloud handler consulted its catalog only below three arguments, so a rule matched its bare form and nothing else. Ten rules whose reason text already described read-only or locally regenerable behavior became allows, among them <code>helm repo update</code>, <code>gh run watch</code>, <code>mise activate</code>, <code>ninja clean</code>, <code>meson compile</code>, and <code>git fetch</code> without its ref-rewriting flags.</p>
      </div>
    </div>
  </div>
  </section>
  <details class="release-archive" id="release-archive" aria-labelledby="release-archive-title">
    <summary>
      <h2 class="release-summary" id="release-archive-title">
        <span class="release-summary-kicker">Historical archive</span>
        <span class="release-summary-title">Browse 59 earlier releases</span>
        <span class="release-summary-range">v1.32.4 to v1.1.0</span>
        <span class="release-summary-icon" aria-hidden="true"></span>
      </h2>
    </summary>
    <div class="release-archive-list">
  <div class="config-block">
    <header>
      <h3>v1.32.4 · July 28, 2026</h3>
      <span class="src-tag">bounded hint feedback · <a href="https://github.com/camjac251/tool-gates/commit/372c3c6" target="_blank" rel="noopener">372c3c6</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  keep output-cap recovery guidance concise
  skip file-viewing hints for tail -F and --follow forms
  deduplicate and cap feedback at three hints per response
  avoid unavailable project-scoped tool names in search guidance</pre>
      </div>
      <div class="config-prose">
        <p>Keeps corrective feedback useful without letting it flood the agent's context. Consumer-side <code>head</code>/<code>tail</code> caps still explain that unseen output is lost, but recovery advice now states the invariant: use the producer's native limit when the task needs a bounded result; otherwise run uncapped and inspect persisted output. File-viewing hints now skip retrying and named <code>tail</code> follow forms. Compound calls deduplicate repeated suggestions and attach at most three unique hints per response. Code-search guidance describes available symbol-aware and semantic capabilities instead of naming project-scoped MCP tools that may not be loaded.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.32.3 · July 26, 2026</h3>
      <span class="src-tag">nested-shell guardrails + search routing · <a href="https://github.com/camjac251/tool-gates/commit/f10e982" target="_blank" rel="noopener">f10e982</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  apply guardrails inside bash/sh/zsh -c and -lc scripts
  inspect xargs-invoked shell scripts with the same raw floor
  distinguish ast-grep from the unrelated system sg command
  classify rg context searches after consuming their flag values</pre>
      </div>
      <div class="config-prose">
        <p>Extends the raw security floor into executable strings passed to local shell wrappers and <code>xargs ... shell -c</code>, including combined flags such as <code>-lc</code>. Nested truncation, pipe-to-shell, and other raw-pattern checks now receive the same decision as their top-level forms. Direct <code>sg</code> use asks with migration guidance because that name can resolve to either the deprecated ast-grep alias or the unrelated system group command. Search hints also consume split <code>rg -A</code>/<code>-B</code>/<code>-C</code> values before classifying the pattern, so exact identifier searches remain lexical while declarations, body captures, inventories, and conceptual queries get the appropriate structural or semantic guidance.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.32.2 · July 26, 2026</h3>
      <span class="src-tag">complete counts + canonical ast-grep · <a href="https://github.com/camjac251/tool-gates/commit/1d4a4d7" target="_blank" rel="noopener">1d4a4d7</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  allow full-stream rg count modes without treating them as caps
  keep count modes combined with max-count blocked
  replace deprecated sg recommendations with ast-grep</pre>
      </div>
      <div class="config-prose">
        <p>Allows <code>rg -c .</code>, <code>--count</code>, and <code>--count-matches</code> through the output-cap floor because they consume the complete stream and emit a scalar rather than discard unseen rows. Combining count mode with <code>-m</code> or <code>--max-count</code> remains blocked. Actionable search guidance now uses the canonical <code>ast-grep</code> executable instead of the deprecated <code>sg</code> name.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.32.1 · July 13, 2026</h3>
      <span class="src-tag">hardening + reliability · <a href="https://github.com/camjac251/tool-gates/commit/b1d6112" target="_blank" rel="noopener">b1d6112</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  make hook, settings, and agy config updates transactional
  resolve symlinks before approving project edits
  inspect quoted substitutions and env-split embedded commands
  normalize blocked URL hosts and preserve privilege-wrapper decisions
  repair Gemini hook reporting and notebook edit coverage
<span class="sec other">Other</span>
  reduce repeated config, parser, scanner, alias, and WASM work
  stabilize generated rules, docs checks, CI, and MSRV coverage</pre>
      </div>
      <div class="config-prose">
        <p>Hardens the boundaries where command parsing, path approval, and configuration persistence meet. Hook installation, settings permission changes, and the Antigravity allowlist now use transactional updates so a failed write cannot partially replace a working configuration. Project-edit approval resolves symlinks before testing scope; block rules normalize URL hosts; command inspection reaches substitutions inside quoted arguments and commands embedded in <code>env -S</code> strings; privilege wrappers keep the underlying gate decision. Gemini reports the hook set that was actually installed, notebook edits are covered end to end, and tracker state survives across sessions. The same release trims repeated parsing and filesystem work across configuration loading, security scans, Git alias discovery, and WASM builds, while tightening generated-rule, documentation, CI, and MSRV checks.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.32.0 · July 8, 2026</h3>
      <span class="src-tag">native scratchpad + gate fixes · <a href="https://github.com/camjac251/tool-gates/commit/56ccac4" target="_blank" rel="noopener">56ccac4</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  recognize Claude Code's native per-session scratchpad
  auto-allow supported file and shell writes within that root
<span class="sec fixed">Fixed</span>
  honor package-manager allow rules and gate mutating subcommands
  route unmatched system tools through the generated dispatcher
  fail closed on malformed settings.json
  inspect newline-separated eval/source and multibyte truncation forms
<span class="sec other">Other</span>
  generate reminder and design-lint docs from their scanner catalogs
  make the raw-string security floor declarative</pre>
      </div>
      <div class="config-prose">
        <p>Extends scratch handling to Claude Code's native per-session scratchpad under the system temporary directory. File tools already trusted this directory, but Bash redirects and write commands still prompted; tool-gates now recognizes the same bounded root at every scratch-aware call site. The matcher requires the current user and UUID-shaped session identifier and ends at <code>scratchpad/</code>, so sibling task and session directories remain gated. This release also honors package-manager allow rules while gating their mutating subcommands, routes unmatched system tools through the generated dispatcher, preserves malformed <code>settings.json</code> files instead of replacing them, and closes newline and multibyte parsing gaps in the raw-string safety floor. Security-reminder and design-lint reference pages are generated from their scanner catalogs, while the raw-string security floor is declarative, reducing drift between behavior and documentation.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.31.1 · June 25, 2026</h3>
      <span class="src-tag">flag gating · <a href="https://github.com/camjac251/tool-gates/commit/5ad22a7" target="_blank" rel="noopener">5ad22a7</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  gate exec/write flags on otherwise-safe tools:
  rg --pre / --hostname-bin (code execution), sort -o,
  find -fprintf, pg_dump -f, gitleaks -r, unrar x,
  ip / route / ifconfig / arp network mutations
  drop fx and fselect from the always-safe list</pre>
      </div>
      <div class="config-prose">
        <p>Closes a gap where several read-only tools were auto-allowed regardless of flags that run a program or write a file. <code>rg --pre</code> and <code>--hostname-bin</code> run an external program per file (arbitrary code execution); <code>sort -o</code>, <code>find -fprintf</code>, <code>pg_dump -f</code>, <code>gitleaks -r</code>, and <code>unrar x</code> write or overwrite files; <code>ip</code>/<code>route</code>/<code>ifconfig</code>/<code>arp</code> can change network config. These are the program's own arguments, not pipes or redirects, so the existing shell-construct checks never saw them and the gate returned <code>allow</code> on every client. They now ask, with <code>rg --pre</code> a hard ask in the same tier as pipe-to-shell. <code>fx</code> and <code>fselect</code> leave the always-safe list because their danger lives inside a quoted expression or query the parser can't inspect. Normal usage stays allowed: <code>rg pattern</code>, <code>sort -u</code>, <code>find -print</code>, <code>ip addr show</code>.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.31.0 · June 25, 2026</h3>
      <span class="src-tag">Antigravity allowlist · <a href="https://github.com/camjac251/tool-gates/commit/30055e3" target="_blank" rel="noopener">30055e3</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  tool-gates agy allowlist [--apply]: generate agy's native
  permissions.allow block for read-only commands</pre>
      </div>
      <div class="config-prose">
        <p>Antigravity resolves a tool call as the strictest of its candidate decisions, so a hook <code>allow</code> is the lowest rank and cannot suppress a prompt agy's own rules would show. The way to stop agy prompting for a read-only command is its native <code>permissions.allow</code> list. <code>tool-gates agy allowlist</code> generates that list from tool-gates' own unconditionally-safe command set, one <code>command(&lt;prog&gt;)</code> rule per program; <code>--apply</code> merges it into <code>~/.gemini/antigravity-cli/settings.json</code>, preserving existing entries and writing a backup first. The hook still gates dangerous forms, so a native <code>command(find)</code> does not let <code>find . -delete</code> through. See the <a href="antigravity.html#allowlist">Antigravity</a> page.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.30.0 · June 23, 2026</h3>
      <span class="src-tag">design lint cleanset · <a href="https://github.com/camjac251/tool-gates/commit/2de112f" target="_blank" rel="noopener">2de112f</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  design-lint: extend the catalog from 17 to 22 rules
  typography/script-font, color/maxed-saturation
  motion/transition-all, motion/scale-hover
  content/emoji-decoration</pre>
      </div>
      <div class="config-prose">
        <p>Extends the opt-in design-lint catalog from 17 rules to 22. The new rules flag decorative script display fonts (Pacifico, Caveat, Comic Sans, Lobster, Dancing Script), pure-channel hex colors like <code>#f00</code> or <code>#00ff00</code> used outside <code>:root</code> token definitions, <code>transition: all</code> and the <code>transition-all</code> utility, default <code>scale(1.05)</code> and <code>scale(1.1)</code> hover effects, and emoji placed inside headings or buttons. Each rule ships with positive and false-positive tests, and the <a href="design-lint.html">Design Lint</a> reference page documents the full set.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.29.0 · June 23, 2026</h3>
      <span class="src-tag">design lint · <a href="https://github.com/camjac251/tool-gates/commit/805bcf3" target="_blank" rel="noopener">805bcf3</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  design-lint: opt-in PostToolUse content gate for UI writes
  17 rules: generic gradients/palettes, default fonts, filler copy
  OKLCH hue-based violet/purple gradient detection
  off by default (features.design_lint), exempts :root tokens</pre>
      </div>
      <div class="config-prose">
        <p>Adds an opt-in PostToolUse content gate that scans UI file writes and edits for generic, templated design and missing UI-quality basics. It catches the overused <code>#667eea</code>/<code>#764ba2</code> gradient, beige and brass "premium" palettes, default Tailwind indigo, Inter as the display font, placeholder names and fabricated stats, marketing filler copy, em and en dashes in rendered text, hardcoded Tailwind palette classes, raw hex in inline styles, hotlinked images, and interactive elements with no visible focus style. Violet and purple gradients are matched by OKLCH hue rather than a fixed hex list, so arbitrary violets are caught too. Findings attach as <code>additionalContext</code> next to the security reminders so the assistant can self-correct on the next turn. The gate is off by default (<code>features.design_lint</code>), raw color values inside <code>:root</code> token definitions are exempt, and individual rules disable by id. See the <a href="design-lint.html">Design Lint</a> reference page.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.28.0 · June 20, 2026</h3>
      <span class="src-tag">scratch coverage + awk gate · <a href="https://github.com/camjac251/tool-gates/commit/368a1da" target="_blank" rel="noopener">368a1da</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  scratch auto-allow extended to mv / tee / chmod / sd
  quoted redirect targets, curl -o / wget -O
  MultiEdit / NotebookEdit writes under the scratch dir
  awk gate: auto-allow read-only awk, ask on exec / write / opaque programs</pre>
      </div>
      <div class="config-prose">
        <p>Broadens the v1.27.0 session scratch auto-allow from <code>Write</code>/<code>Edit</code> plus <code>mkdir</code>/<code>touch</code>/<code>cp</code>/redirect to the rest of the common write surface, so agents stop being prompted for routine throwaway work. New scratch-aware upgrades: <code>mv</code> (destination), <code>tee</code> output, <code>chmod</code>/<code>chown</code>/<code>chgrp</code>, <code>curl -o</code>/<code>wget -O</code> downloads, <code>sd</code> in-place edits, and <code>MultiEdit</code>/<code>NotebookEdit</code> file writes.</p>
        <p>Also fixes a quoted-redirect gap: a quoted scratch target like <code>&gt; "$TOOL_GATES_SCRATCH/..."</code> previously prompted because the quoted path was blanked before the scratch check, so the real target is now recovered from the original command. The safety model: each gate flips Ask to Allow only when the write target resolves under the scratch base (symlink or <code>..</code> escapes still gate), and every non-scratch write still prompts. Tools whose sublanguage can run shell or write outside the named target (<code>sed -i</code>, <code>sqlite3</code>, <code>zip</code>, <code>tar</code>) are deliberately left asking, since a scratch target does not bound what they do.</p>
        <p>Also adds a guarded <code>awk</code>/<code>gawk</code>/<code>mawk</code> gate so common read-only idioms (field selection, column sums, line counts, range extraction) auto-allow instead of prompting, while any awk that runs a command or writes a file still asks. A program auto-allows only as a static, inline, single-quoted literal with none of the exec/write markers (<code>system</code>, <code>getline</code>, a real <code>|</code> pipe, an <code>@</code> indirect call, or a <code>&gt;</code> redirect); <code>||</code> and <code>&gt;=</code> are exempt so logical-or and range comparisons still allow. A program built from a shell variable, command substitution, ANSI-C quoting, or a later <code>-e</code>/<code>--source</code> chunk is opaque and asks since its text cannot be inspected, and <code>-f</code>/<code>-i</code>/<code>-l</code>/<code>-E</code> external-program flags ask. Dynamic filenames and <code>-v</code> values still allow because awk never executes them. Measured against the real session corpus, a clear majority of routine awk now auto-allows, with no file-writing or command-running awk allowed.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.27.0 · June 19, 2026</h3>
      <span class="src-tag">scratch + awk hints · <a href="https://github.com/camjac251/tool-gates/commit/2a5b993" target="_blank" rel="noopener">2a5b993</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  auto-allow writes under a session scratch dir ($TOOL_GATES_SCRATCH)
  awk idiom hints route to numbat / jq / rg / jc / choose</pre>
      </div>
      <div class="config-prose">
        <p>Adds a friction-free session scratch directory so agents stop reaching for <code>/tmp</code>. When <code>$TOOL_GATES_SCRATCH</code> is set (default <code>~/.cache/tool-gates-scratch</code>), <code>Write</code>/<code>Edit</code> targets and shell <code>mkdir</code>/<code>touch</code>/<code>cp</code>/redirect destinations that resolve under it are auto-allowed in every permission mode. Targets are canonicalized first, so a symlink or <code>..</code> that escapes the base is not matched, and sensitive or guarded paths still gate. On Claude this is a true allow; on Codex (deny-only PreToolUse) it falls through.</p>
        <p>Also replaces the single generic <code>awk</code> suggestion with idiom-aware routing: byte/size math points at <code>numbat</code>, column sums at <code>jq -Rn</code>, line counts at <code>rg -c</code>, positional row/field extraction at <code>jc | jq</code>, and plain field selection at <code>choose</code>. Stateful range extraction and bare filters get no nudge.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.26.0 · June 19, 2026</h3>
      <span class="src-tag">risk gating · <a href="https://github.com/camjac251/tool-gates/commit/4ec9a59" target="_blank" rel="noopener">4ec9a59</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  require an explicit confirm for shared high-stakes family globs in the review TUI</pre>
      </div>
      <div class="config-prose">
        <p>Tightens the review TUI blast-radius model. A scoped family glob over a high-stakes program (<code>docker run:*</code>, <code>aws s3:*</code>, <code>ssh</code>, <code>rm</code>, ...) written to project or global settings is a team- or machine-wide standing grant to run arbitrary subcommands of a high-blast-radius tool, so approving one now requires an explicit <code>y</code> confirm. Local-only grants and non-high-stakes programs are unchanged.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.25.0 · June 19, 2026</h3>
      <span class="src-tag">review TUI · <a href="https://github.com/camjac251/tool-gates/commit/c62f858" target="_blank" rel="noopener">c62f858</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  redesign review TUI with a flat keyboard model and rules manager
  Pending / Approved / Denied views with allow/deny rule removal
  blast-radius risk model that confirms before a dangerous write
  project switcher grouped by parent, plus undo for the last action
<span class="sec other">Other</span>
  Review TUI reference page</pre>
      </div>
      <div class="config-prose">
        <p>Replaces the focus-mode three-panel layout with a flat keyboard model: arrows always navigate, letter keys act (<code>a</code> approve, <code>d</code> deny, <code>x</code> remove, <code>y</code> confirm). Adds Pending, Approved, and Denied views; the two rule views read <code>settings.json</code> and remove existing allow/deny rules behind a confirmation. A new blast-radius risk model (pattern breadth, scope reach, and whether the program is high-stakes) colors the panel and forces an explicit confirm before a dangerous write, and a compound segment with no safe suggested pattern is refused instead of fabricating a broad glob for the wrong program. Walkthrough and keymap live on the new <a href="review-tui.html">Review TUI</a> page.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.24.1 · June 16, 2026</h3>
      <span class="src-tag">Antigravity scopes · <a href="https://github.com/camjac251/tool-gates/commit/2237a64" target="_blank" rel="noopener">2237a64</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  Antigravity hooks: default to ~/.gemini/config/hooks.json, add -s project
<span class="sec other">Other</span>
  fix four-client grid layout and footer wrapping on the index page</pre>
      </div>
      <div class="config-prose">
        <p>Corrects the Antigravity hook install model. v1.24.0 shipped Antigravity as global-only at <code>~/.gemini/antigravity-cli/hooks.json</code>; this release moves the default to the shared user path <code>~/.gemini/config/hooks.json</code> and adds a <code>-s project</code> scope that writes <code>.agents/hooks.json</code>. <code>tool-gates hooks status</code> and <code>tool-gates doctor</code> now report both scopes. Also fixes the four-client install grid layout and footer wrapping on the documentation index.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.24.0 · June 9, 2026</h3>
      <span class="src-tag">Antigravity CLI · <a href="https://github.com/camjac251/tool-gates/commit/f12e0a0" target="_blank" rel="noopener">f12e0a0</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  Antigravity CLI (agy) support: --client antigravity, single PreToolUse hook
  hooks add / status / json --antigravity (named-hook hooks.json)
  Antigravity tool-name mapping + payload normalization
<span class="sec other">Changed</span>
  Gemini CLI marked deprecated (Google sunsets it 2026-06-18)</pre>
      </div>
      <div class="config-prose">
        <p>Adds Antigravity CLI (Google's <code>agy</code>, the Gemini CLI successor) as a first-class client. Antigravity uses a distinct wire format: a payload nesting the tool under <code>toolCall</code> with PascalCase args, a flat <code>{decision, reason}</code> output, and a <code>hooks.json</code> keyed by hook name. tool-gates normalizes the payload, installs a single PreToolUse hook via <code>tool-gates hooks add --antigravity</code>, and gates shell, file, grep, and glob tools. The Gemini CLI client is marked deprecated across the docs because Google sunsets the consumer Gemini CLI on 2026-06-18; it keeps working through the transition.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.23.0 · June 6, 2026</h3>
      <span class="src-tag">docs &amp; approvals · <a href="https://github.com/camjac251/tool-gates/commit/a43ee4a" target="_blank" rel="noopener">a43ee4a</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  mdBook documentation site with interactive WASM simulator
  rules export generator for markdown references
  Codex project-edit auto-approval config
  pre-commit rules-export hook in Lefthook
<span class="sec fixed">Fixed</span>
  head/tail pipe block scoped to build/test/gh producers
  documentation accuracy corrections for Codex and MSRV</pre>
      </div>
      <div class="config-prose">
        <p>Introduces an interactive documentation site with a WebAssembly command simulator. It adds a declarative rules exporter (tool-gates rules export) and auto approval configurations for Codex in project edits ([codex] accept_project_edits). The output truncation pipe blocker was refined to focus only on build, test, and GitHub producers (such as cargo, npm, go, make, and gh), allowing soft producers (like cat and ls) to pass through with modern CLI hints. This release also adds a Lefthook pre-commit hook to automatically regenerate the Markdown documentation on rule changes.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.22.0 · May 26, 2026</h3>
      <span class="src-tag">media &amp; CLI · <a href="https://github.com/camjac251/tool-gates/commit/6657772" target="_blank" rel="noopener">6657772</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  ffprobe / d2 allow
  ffmpeg info flags gated
  read-only tool-gates CLI subcommands
<span class="sec fixed">Fixed</span>
  skip quoted-heredoc bodies in raw-string scans
  stop false asks from mise usage-args + bun file-exec</pre>
      </div>
      <div class="config-prose">
        <p>Adds gating for media tools (allowing ffprobe and d2, while gating ffmpeg info flags). It introduces read-only subcommands (including pending list, rules list, hooks status, and doctor) to the tool-gates command line interface. It also updates the raw string scanner to skip quoted heredocs. It resolves false positive asks caused by mise usage argument (stripping the usage_args eval prefix) and bun file execution expansion (by checking for code extensions or path separators).</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.21.2 · May 21, 2026</h3>
      <span class="src-tag">maintenance · <a href="https://github.com/camjac251/tool-gates/commit/57cac7e" target="_blank" rel="noopener">57cac7e</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec other">Other</span>
  drop vendor-specific output_tail reference from head/tail deny</pre>
      </div>
      <div class="config-prose">
        <p>Cleans up the output truncation blocker by dropping a vendor specific output tail reference from the head and tail deny rule.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.21.1 · May 21, 2026</h3>
      <span class="src-tag">polish · <a href="https://github.com/camjac251/tool-gates/commit/0e0a0d4" target="_blank" rel="noopener">0e0a0d4</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  improve head/tail and github block deny messages
<span class="sec other">Other</span>
  replace generic "syntax highlighting" hint suffix with agent-actionable benefits
  polish modern hint messages for consistency
  rewrite hook deny messages with risk and remediation</pre>
      </div>
      <div class="config-prose">
        <p>Improves the clarity and usefulness of hook feedback. The denial messages for the output truncation and GitHub blockers now state the security risk and clear remediation steps. The modern hint suffix was replaced with agent actionable benefits. All other hints were polished for consistency.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.21.0 · May 13, 2026</h3>
      <span class="src-tag">polish · <a href="https://github.com/camjac251/tool-gates/commit/9b2a6de" target="_blank" rel="noopener">9b2a6de</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  enforce no-rg-on-code rule, route to probe/chunkhound/serena/ast-grep
<span class="sec other">Other</span>
  hints catalog, systemMessage tiering, length guard</pre>
      </div>
      <div class="config-prose">
        <p>Enforces a rule against running rg on code files. It routes searches to specialized tools such as probe, chunkhound, serena, and ast-grep. It introduces a hints catalog, system message tiering, and a length guard.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.20.0 · May 13, 2026</h3>
      <span class="src-tag">reasons · <a href="https://github.com/camjac251/tool-gates/commit/de952ff" target="_blank" rel="noopener">de952ff</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  help-menu reason prompts, new hints, tiered systemMessage
<span class="sec fixed">Fixed</span>
  pass --edition 2024 to rustfmt in build.rs</pre>
      </div>
      <div class="config-prose">
        <p>Introduces detailed reason prompts to the help menu for rejected hooks. It also adds tiered system messages and updates the build script to pass the 2024 edition to rustfmt.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.19.2 · May 8, 2026</h3>
      <span class="src-tag">maintenance · <a href="https://github.com/camjac251/tool-gates/commit/0480925" target="_blank" rel="noopener">0480925</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  harden accept-edits fallback</pre>
      </div>
      <div class="config-prose">
        <p>Hardens the fallback behavior in accept edits mode. It ensures that the permission policy is correctly applied when resolving command wrappers.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.19.1 · May 3, 2026</h3>
      <span class="src-tag">maintenance · <a href="https://github.com/camjac251/tool-gates/commit/ebb6e6d" target="_blank" rel="noopener">ebb6e6d</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  align client hook contracts</pre>
      </div>
      <div class="config-prose">
        <p>Aligns the hook interface contracts across the Claude, Gemini, and Codex clients. This ensures consistent decision behavior across all tools.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.19.0 · May 3, 2026</h3>
      <span class="src-tag">Codex · <a href="https://github.com/camjac251/tool-gates/commit/024465c" target="_blank" rel="noopener">024465c</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  add Codex CLI client support
<span class="sec fixed">Fixed</span>
  gate worktree auto-approve on subagent agent_id
  fire Claude PermissionRequest for MCP tools</pre>
      </div>
      <div class="config-prose">
        <p>Adds support for the Codex command line interface client. It gates worktree auto approvals on the subagent agent ID. It also fires Claude PermissionRequest events for Model Context Protocol tools to streamline subagent flows.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.18.0 · April 30, 2026</h3>
      <span class="src-tag">git aliases · <a href="https://github.com/camjac251/tool-gates/commit/69175dc" target="_blank" rel="noopener">69175dc</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  resolve user-defined aliases against ~/.gitconfig
<span class="sec fixed">Fixed</span>
  split nested if-let to satisfy MSRV 1.86
  drop redundant plan-mode hard-deny on Write/Edit
<span class="sec other">Other</span>
  restore HOME after with_temp_cache to stop sequential leak</pre>
      </div>
      <div class="config-prose">
        <p>Resolves user defined git aliases against the user git configuration file so that custom git shortcuts are evaluated correctly. It also splits nested if let blocks to support Rust 1.86. It drops redundant plan mode checks and prevents home directory leaks during tracking tests.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.17.0 · April 30, 2026</h3>
      <span class="src-tag">audit TUI · <a href="https://github.com/camjac251/tool-gates/commit/8b48d7a" target="_blank" rel="noopener">8b48d7a</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  polish round, install patterns, doctor nudge, audit TUI
  close ask-audit gaps with broader find guard and --apply
  categorize ask-audit rules by gate-engine outcome
  add ask-audit to surface third-button-suppressing rules
  defer benign gate-ask to CC for prefix-suggestion prompt
  surface usage stats in the doctor report
  self-heal cache with single-tool re-probe
  collapse near-duplicate entries by pattern key
  hard-deny mutating tools in plan mode
<span class="sec fixed">Fixed</span>
  post-review fixes on the 1.6.0 series
  skip pending append when settings already allow
<span class="sec other">Other</span>
  cover defer wire format, ask-audit, and 24h tracking TTL
  reframe ask-audit around slip-click safety, drop bulk apply
  cover wire-format defer path for mise/pnpm wrappers
  bump to 1.6.0
  reframe skills around defer behavior
  replace 15min TTL with session-bounded GC
  tighten review/test-gate skill descriptions, bump to 1.5.9</pre>
      </div>
      <div class="config-prose">
        <p>Introduces the ask audit command to identify rules that shadow accept edits or suppress the third button in Claude Code. It adds an interactive review terminal user interface. It collapses duplicate pending entries and integrates plan mode checks to block mutations. It also defers benign asks to Claude Code to preserve the prefix suggestion prompt. It adds self healing capabilities to the tool detection cache.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.16.1 · April 24, 2026</h3>
      <span class="src-tag">maintenance · <a href="https://github.com/camjac251/tool-gates/commit/7ace761" target="_blank" rel="noopener">7ace761</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  drop vendor-specific refs from head/tail deny message</pre>
      </div>
      <div class="config-prose">
        <p>Polishes the deny message for the head and tail truncation blocker. It removes vendor-specific references that did not apply to the general toolchain.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.16.0 · April 23, 2026</h3>
      <span class="src-tag">head/tail block · <a href="https://github.com/camjac251/tool-gates/commit/6dad625" target="_blank" rel="noopener">6dad625</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  deny | head / | tail pipes with config toggle
<span class="sec other">Other</span>
  warn about permissions.ask shadowing accept_edits_mcp</pre>
      </div>
      <div class="config-prose">
        <p>Adds a configuration toggle to block piping command outputs to head or tail. It also adds a configuration warning when user settings shadow the Model Context Protocol accept edits rule.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.15.0 · April 23, 2026</h3>
      <span class="src-tag">MCP approvals · <a href="https://github.com/camjac251/tool-gates/commit/4c5aa93" target="_blank" rel="noopener">4c5aa93</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  auto-approve MCP tools in acceptEdits mode</pre>
      </div>
      <div class="config-prose">
        <p>Enables auto approvals for Model Context Protocol tools in acceptEdits mode. This streamlines editing workflows for subagents.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.14.0 · April 22, 2026</h3>
      <span class="src-tag">API hints · <a href="https://github.com/camjac251/tool-gates/commit/a53313b" target="_blank" rel="noopener">a53313b</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  nudge network tools to gh api for GitHub URLs</pre>
      </div>
      <div class="config-prose">
        <p>Nudges network tools to use gh api when requesting GitHub URLs. This reduces unnecessary web scraping or API token usage.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.13.0 · April 21, 2026</h3>
      <span class="src-tag">auto mode · <a href="https://github.com/camjac251/tool-gates/commit/1078f0f" target="_blank" rel="noopener">1078f0f</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  integrate with Claude Code classifier</pre>
      </div>
      <div class="config-prose">
        <p>Integrates with the Claude Code auto mode classifier. This enables hard ask promotion to deny, pending queue filtering, and PermissionDenied retry signals.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.12.1 · April 15, 2026</h3>
      <span class="src-tag">maintenance · <a href="https://github.com/camjac251/tool-gates/commit/04889ff" target="_blank" rel="noopener">04889ff</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  unify home-directory path handling across gates
  enforce cargo fmt --check and restage crate-wide fmt
<span class="sec other">Other</span>
  use generic user in fixtures</pre>
      </div>
      <div class="config-prose">
        <p>Unifies home directory path handling across all gates. It enforces strict cargo formatting checks in the continuous integration pipeline. It also uses generic users in test fixtures.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.12.0 · April 10, 2026</h3>
      <span class="src-tag">Monitor tool · <a href="https://github.com/camjac251/tool-gates/commit/e65011b" target="_blank" rel="noopener">e65011b</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  add Monitor tool support</pre>
      </div>
      <div class="config-prose">
        <p>Adds support for the Claude Code Monitor tool. This enables permission gating for background monitoring commands.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.11.0 · April 3, 2026</h3>
      <span class="src-tag">wrapper resolution · <a href="https://github.com/camjac251/tool-gates/commit/35b587e" target="_blank" rel="noopener">35b587e</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  acceptEdits wrapper resolution for package manager invocations</pre>
      </div>
      <div class="config-prose">
        <p>Resolves package manager wrappers during acceptEdits mode. This ensures that linters and formatters can run without triggering prompts.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.10.0 · April 3, 2026</h3>
      <span class="src-tag">runtimes · <a href="https://github.com/camjac251/tool-gates/commit/fbdccdf" target="_blank" rel="noopener">fbdccdf</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  add runtimes gate, expand coverage across all gates</pre>
      </div>
      <div class="config-prose">
        <p>Consolidates Python, Node, Ruby, Deno, PHP, and other language runtimes into a single runtime gate. This provides unified security analysis across language execution commands.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.9.2 · March 31, 2026</h3>
      <span class="src-tag">maintenance · <a href="https://github.com/camjac251/tool-gates/commit/6c6e252" target="_blank" rel="noopener">6c6e252</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  remove redundant workflow_dispatch that races with push</pre>
      </div>
      <div class="config-prose">
        <p>Fixes a continuous integration race condition. It removes a redundant workflow dispatch trigger that raced with pushes.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.9.1 · March 31, 2026</h3>
      <span class="src-tag">maintenance · <a href="https://github.com/camjac251/tool-gates/commit/4b7676e" target="_blank" rel="noopener">4b7676e</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  remove approval context from additionalContext</pre>
      </div>
      <div class="config-prose">
        <p>Removes redundant approval context from the hook additionalContext response. This minimizes context token usage.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.9.0 · March 31, 2026</h3>
      <span class="src-tag">matchers · <a href="https://github.com/camjac251/tool-gates/commit/8df9031" target="_blank" rel="noopener">8df9031</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  detect and update stale matchers on hooks add</pre>
      </div>
      <div class="config-prose">
        <p>Automatically detects and updates out of date matchers in the Claude configuration when registering hooks.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.8.0 · March 30, 2026</h3>
      <span class="src-tag">worktrees · <a href="https://github.com/camjac251/tool-gates/commit/29fa637" target="_blank" rel="noopener">29fa637</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  auto-approve Edit/Write in agent worktrees
<span class="sec fixed">Fixed</span>
  let gate-allowed commands participate in compound settings approval
<span class="sec other">Other</span>
  clarify branch allow rule covers create too</pre>
      </div>
      <div class="config-prose">
        <p>Enables auto approvals for file edits inside agent worktrees during PermissionRequest events. It also allows gate allowed commands to participate in compound settings approvals. It clarifies that the branch allow rule covers creation too.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.7.3 · March 28, 2026</h3>
      <span class="src-tag">maintenance · <a href="https://github.com/camjac251/tool-gates/commit/07d939c" target="_blank" rel="noopener">07d939c</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec other">Other</span>
  remove MultiEdit tool and mcp-cli gate
  replace em-dash patterns with periods and commas
  bump to 1.5.8, add when_to_use to skills</pre>
      </div>
      <div class="config-prose">
        <p>Bumps the plugin to version 1.5.8. It removes the MultiEdit tool and the mcp cli gate. It replaces all em dash patterns in the source code and configuration with periods and commas.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.7.2 · March 25, 2026</h3>
      <span class="src-tag">maintenance · <a href="https://github.com/camjac251/tool-gates/commit/763b556" target="_blank" rel="noopener">763b556</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  resolve binary path via argv[0] and PATH lookup</pre>
      </div>
      <div class="config-prose">
        <p>Improves binary path resolution in hook scripts. It searches the environment PATH variable when argv[0] is not an absolute path.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.7.1 · March 25, 2026</h3>
      <span class="src-tag">maintenance · <a href="https://github.com/camjac251/tool-gates/commit/cf24984" target="_blank" rel="noopener">cf24984</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  use symlink path instead of canonicalized Cellar path</pre>
      </div>
      <div class="config-prose">
        <p>Resolves Homebrew installation path issues. It references the symlinked binary path rather than the canonicalized Cellar path.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.7.0 · March 25, 2026</h3>
      <span class="src-tag">Gemini · <a href="https://github.com/camjac251/tool-gates/commit/b31c96d" target="_blank" rel="noopener">b31c96d</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  native BeforeTool/AfterTool hook support</pre>
      </div>
      <div class="config-prose">
        <p>Introduces native support for Gemini CLI BeforeTool and AfterTool hooks. It automatically translates payloads and responses to match the Gemini format.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.6.0 · March 22, 2026</h3>
      <span class="src-tag">coverage · <a href="https://github.com/camjac251/tool-gates/commit/e7f5c40" target="_blank" rel="noopener">e7f5c40</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  add gates for missing programs</pre>
      </div>
      <div class="config-prose">
        <p>Adds dedicated rules and gates for missing system programs. This expands command coverage and improves security check safety.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.5.10 · March 22, 2026</h3>
      <span class="src-tag">maintenance · <a href="https://github.com/camjac251/tool-gates/commit/6422d4a" target="_blank" rel="noopener">6422d4a</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  format generated code with rustfmt, prettyplease fallback
  run rustfmt on generated files to prevent dirty worktree
  use recursive globs so hooks trigger for all source files
  include expansion nodes in command argument extraction
  detect github_pat_ fine-grained personal access tokens
  detect Stripe sk_live_ and sk_test_ secret keys
  use atomic write-then-rename for hint tracker and tool cache
  split compound commands in fallback parser
  recover from poisoned mutex instead of panicking
  log serialization errors instead of silently swallowing
  strip transparent command wrappers before gate evaluation
  block entire .git/ directory in acceptEdits mode
<span class="sec other">Other</span>
  remove unused tools from detection cache
  remove unused lsd from tool detection
  compile security regexes once via LazyLock</pre>
      </div>
      <div class="config-prose">
        <p>Provides a large reliability release. It adds fine-grained token detection for GitHub and Stripe. It uses atomic cache updates, strips transparent command wrappers, and blocks direct modifications to the git directory in accept edits mode. It also ensures generated code is formatted to prevent dirty worktrees.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.5.9 · March 21, 2026</h3>
      <span class="src-tag">maintenance · <a href="https://github.com/camjac251/tool-gates/commit/b401b57" target="_blank" rel="noopener">b401b57</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  remove ALWAYS, fix pipe false positives, add new detections
<span class="sec other">Other</span>
  bump plugin versions to 1.5.7
  update skills and convert hook-reference to path-scoped rule</pre>
      </div>
      <div class="config-prose">
        <p>Polishes modern command hints and removes the redundant ALWAYS indicator. It updates plugin skills to match path-scoped rules.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.5.8 · March 21, 2026</h3>
      <span class="src-tag">maintenance · <a href="https://github.com/camjac251/tool-gates/commit/bd6973d" target="_blank" rel="noopener">bd6973d</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  sync simulate_append test helper with new dedup logic
  per-subcommand gate evaluation for compound commands
<span class="sec other">Other</span>
  add Windows x64 and arm64 build targets</pre>
      </div>
      <div class="config-prose">
        <p>Enables per subcommand gate evaluation for compound commands. It adds Windows target platform support to the automated build pipeline.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.5.7 · March 21, 2026</h3>
      <span class="src-tag">maintenance · <a href="https://github.com/camjac251/tool-gates/commit/a714abb" target="_blank" rel="noopener">a714abb</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  specify musl target for binary size check
  specificity-based ask/allow resolution and $HOME expansion
<span class="sec other">Other</span>
  use dedicated app token for release automation
  auto-merge release-plz PRs and trigger release</pre>
      </div>
      <div class="config-prose">
        <p>Improves settings resolution by adding specificity based allow/ask matching. It expands the HOME variable in pattern matching. It also integrates release plz with custom bot authentication.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.5.6 · March 21, 2026</h3>
      <span class="src-tag">maintenance · <a href="https://github.com/camjac251/tool-gates/commit/1b29246" target="_blank" rel="noopener">1b29246</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  stage build-generated files in pre-commit
<span class="sec other">Other</span>
  add Homebrew as recommended install method</pre>
      </div>
      <div class="config-prose">
        <p>Stages build generated rules during pre-commit hooks. It documents Homebrew as the recommended installation method.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.5.5 · March 20, 2026</h3>
      <span class="src-tag">maintenance · <a href="https://github.com/camjac251/tool-gates/commit/6b759cf" target="_blank" rel="noopener">6b759cf</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  use actions/checkout for homebrew-tap push auth
<span class="sec other">Other</span>
  bump build provenance attestation action</pre>
      </div>
      <div class="config-prose">
        <p>Corrects Homebrew tap repository push authentication in GitHub Actions. It integrates build provenance attestation to secure release binary publishing.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.5.4 · March 20, 2026</h3>
      <span class="src-tag">maintenance · <a href="https://github.com/camjac251/tool-gates/commit/f3c372a" target="_blank" rel="noopener">f3c372a</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  Use CARGO_MANIFEST_DIR to detect package verify context
  Remove publish=false from Cargo.toml
  Remove name field from skills so prefix shows in autocomplete
<span class="sec other">Other</span>
  Move plugin to subdirectory to prevent skill leakage</pre>
      </div>
      <div class="config-prose">
        <p>Fixes Cargo package verification issues in the release pipeline. It moves the plugin into a subdirectory to prevent skill leakage. It also removes the name field from skills to improve editor autocompletion.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.5.3 · March 20, 2026</h3>
      <span class="src-tag">maintenance · <a href="https://github.com/camjac251/tool-gates/commit/d3af03d" target="_blank" rel="noopener">d3af03d</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  Switch to release-plz with homebrew tap automation
<span class="sec fixed">Fixed</span>
  Skip codegen during cargo package verify
  Match import order to cargo fmt for idempotent codegen
  Sort custom handler lists for deterministic codegen
  Commit generated files so cargo package verify succeeds
  Remove musl default target so cargo package works in CI
  Ignore cross-session hint dedup test in shared process
  Remove name field from skills so prefix shows in autocomplete
<span class="sec other">Other</span>
  Move plugin to subdirectory to prevent skill leakage</pre>
      </div>
      <div class="config-prose">
        <p>Switches the release workflow to release-plz with automated homebrew tap publishing. It moves the plugin to a subdirectory to prevent skill leakage. It fixes cargo package verification and cargo build issues under continuous integration by committing generated files, matching import order to cargo fmt, sorting custom handler lists, and skipping codegen during verification. It also ignores cross-session hint deduplication tests in shared processes.</p>
      </div>
    </div>
  </div>
<div class="config-block">
    <header>
      <h3>v1.5.2 · March 18, 2026</h3>
      <span class="src-tag">maintenance · <a href="https://github.com/camjac251/tool-gates/commit/55af0b2" target="_blank" rel="noopener">55af0b2</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  Require all sub-commands to match settings for compound allow</pre>
      </div>
      <div class="config-prose">
        <p>Hardens security for compound commands. It requires all subcommands to match allowed patterns in user settings before granting auto approval.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.5.1 · March 14, 2026</h3>
      <span class="src-tag">maintenance · <a href="https://github.com/camjac251/tool-gates/commit/044e763" target="_blank" rel="noopener">044e763</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec fixed">Fixed</span>
  Remove patch from acceptEdits auto-allow, add 20 security tests</pre>
      </div>
      <div class="config-prose">
        <p>Removes the patch command from the acceptEdits auto allow list to prevent arbitrary write bypasses. It backs this check with 20 new security tests.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.5.0 · March 13, 2026</h3>
      <span class="src-tag">safeties · <a href="https://github.com/camjac251/tool-gates/commit/f1cd14f" target="_blank" rel="noopener">f1cd14f</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  Smarter secret handling for .env and doc files</pre>
      </div>
      <div class="config-prose">
        <p>Improves secret checking heuristics. This prevents false positive leakage reports in documentation and environment files.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.4.0 · March 11, 2026</h3>
      <span class="src-tag">skills &amp; doctor · <a href="https://github.com/camjac251/tool-gates/commit/e13491d" target="_blank" rel="noopener">e13491d</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  Add skill auto-approval and doctor command</pre>
      </div>
      <div class="config-prose">
        <p>Introduces the doctor command to diagnose hook health. It adds auto approval configurations for trusted project skills.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.3.0 · March 10, 2026</h3>
      <span class="src-tag">config · <a href="https://github.com/camjac251/tool-gates/commit/662cb64" target="_blank" rel="noopener">662cb64</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  Add per-tier config toggles and Configuration docs</pre>
      </div>
      <div class="config-prose">
        <p>Adds granular configuration toggles in the config file. This enables or disables specific gate tiers.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.2.0 · March 10, 2026</h3>
      <span class="src-tag">MCP &amp; reminders · <a href="https://github.com/camjac251/tool-gates/commit/225407a" target="_blank" rel="noopener">225407a</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  Add MCP tool matcher for PreToolUse hooks
  Add security reminders for Write/Edit/MultiEdit content scanning
<span class="sec fixed">Fixed</span>
  Replace deprecated approve decision with proper allow/no-opinion</pre>
      </div>
      <div class="config-prose">
        <p>Implements PreToolUse hook support for Model Context Protocol tools. It adds content scanning security reminders for file write operations. It also replaces deprecated approval responses.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>v1.1.0 · March 10, 2026</h3>
      <span class="src-tag">initial release · <a href="https://github.com/camjac251/tool-gates/commit/0cf5508" target="_blank" rel="noopener">0cf5508</a></span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec added">Added</span>
  Initial commit: Rust bash permission gate for Claude Code
  Integrate settings.json to respect user permissions
  Add declarative rules system with build-time codegen
  Add PermissionRequest hook support for subagent approval
  Add hooks subcommand for managing Claude Code hooks
  Add modern CLI hints via additionalContext
  Redesign review TUI with project-first dashboard layout</pre>
      </div>
      <div class="config-prose">
        <p>The initial public release of tool-gates. It features an AST based bash parser for precise command identification. It integrates with settings files. It checks against shell execution patterns. It provides a terminal user interface for review and hooks subcommand management.</p>
      </div>
    </div>
  </div>
    </div>
  </details>
  <p class="note">
    <svg class="alert" aria-hidden="true" focusable="false" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
    <span><b>Release automation via release-plz.</b> Push to main triggers a version-bump PR; merging it cuts the GitHub release with cross-compiled binaries (linux x86_64/arm64, macos x86_64/arm64, windows x86_64/arm64) and updates the Homebrew tap. MSRV is Rust 1.97.1. Note: Releases prior to v1.5.4 have been purged on GitHub and do not have downloadable pre-built assets; Homebrew tap installation requires v1.5.6 or newer.</span>
  </p>

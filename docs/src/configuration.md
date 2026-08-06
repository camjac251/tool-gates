  <nav class="breadcrumb" aria-label="Breadcrumb">
    <ol>
      <li><a href="index.html">Reference</a></li>
      <li aria-current="page">Configuration</li>
    </ol>
  </nav>
  <h1 id="config-h1">Configuration</h1>
  <p class="page-lede">tool-gates works without a config file, and most users never write one. When you do, it lives at <code>~/.config/tool-gates/config.toml</code> and covers feature toggles, tool blocking, MCP and Skill auto-approval, file guards, hints, cache, and git aliases.</p>
  <div class="config-block">
    <header>
      <h2>Feature toggles</h2>
      <span class="src-tag">defaults shown</span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec">[features]</span>
<span class="k">bash_gates</span>           = <span class="b">true</span>
<span class="k">file_guards</span>          = <span class="b">true</span>
<span class="k">hints</span>                = <span class="b">true</span>
<span class="k">security_reminders</span>   = <span class="b">true</span>
<span class="k">head_tail_pipe_block</span> = <span class="b">true</span>
<span class="k">git_aliases</span>          = <span class="b">true</span>
<span class="k">design_lint</span>          = <span class="b">false</span>
<span class="k">comment_lint</span>         = <span class="b">false</span></pre>
      </div>
      <div class="config-prose">
        <p>Each subsystem can be turned off independently. Toggles merge with defaults; missing keys keep their default value.</p>
        <p><code>head_tail_pipe_block</code> denies consumer-side <code>| head -N</code> and <code>| tail -N</code> caps for every producer so the agent uses a source-native bound such as <code>rg -m N</code>, <code>fd --max-results N</code>, or <code>bat -r START:END</code>. The producer changes the recovery message, not the decision. First-N slices through <code>sed</code> or <code>awk</code>, plus catch-all <code>| rg .</code> filters, use the same floor.</p>
        <p>Streaming <code>tail -f</code>/<code>-F</code>, top-N selection after <code>sort</code>, and picks inside command substitutions or backticks are exempt. Quoted literals and standalone <code>head</code>/<code>tail</code> calls with no upstream pipe are not caps. Complete-stream aggregation with <code>rg -c .</code>, <code>--count</code>, or <code>--count-matches</code> is also exempt, but combining count mode with <code>-m</code>/<code>--max-count</code> remains blocked.</p>
        <p><code>git_aliases</code> resolves user-defined aliases against <code>~/.gitconfig</code> so <code>git st</code> runs through the same allow/ask rules as <code>git status</code>.</p>
        <p><code>design_lint</code> and <code>comment_lint</code> are the opt-in subsystems (default <code>false</code>). Security reminders cover the safety floor; these two cover house style. <code>design_lint</code> is a frontend design-quality linter for UI writes; <code>comment_lint</code> flags code writes that add far more narrative commentary than code. Set either <code>true</code> to enable.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h2>Tool blocking</h2>
      <span class="src-tag">documented</span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec">[[block_tools]]</span>
<span class="k">tool</span>          = <span class="s">"Glob"</span>
<span class="k">message</span>       = <span class="s">"Use rg instead of Glob"</span>
<span class="sec">[[block_tools]]</span>
<span class="k">tool</span>          = <span class="s">"mcp__firecrawl__*"</span>
<span class="k">message</span>       = <span class="s">"Use gh CLI for GitHub content."</span>
<span class="k">block_domains</span> = [<span class="s">"github.com"</span>]
<span class="k">requires_tool</span> = <span class="s">"rg"</span></pre>
      </div>
      <div class="config-prose">
        <p>Blocks tools by name. Works for any tool type: Bash, Read/Write/Edit, Glob, Grep, Skill, MCP.</p>
        <p><code>tool</code> is exact, prefix glob (<code>mcp__exa*</code>), or contains pattern. <code>block_domains</code> narrows the block to URLs containing the listed domains. <code>requires_tool</code> only blocks when the named modern CLI is detected on PATH.</p>
        <p>Omitting <code>[[block_tools]]</code> uses the built-in defaults (Glob, Grep, firecrawl / ref / exa GitHub URLs). Set <code>block_tools = []</code> to disable all blocking.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h2>MCP accept-edits approval</h2>
      <span class="src-tag">documented</span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec">[[accept_edits_mcp]]</span>
<span class="k">tool</span> = <span class="s">"mcp__serena__replace_symbol_body"</span>
<span class="sec">[[accept_edits_mcp]]</span>
<span class="k">tool</span>   = <span class="s">"mcp__serena__*"</span>
<span class="k">reason</span> = <span class="s">"Symbol edits batched through acceptEdits"</span>
<span class="sec">[[accept_edits_mcp]]</span>
<span class="k">tool</span>             = <span class="s">"mcp__playwright__browser_click"</span>
<span class="k">if_project_under</span> = [<span class="s">"~/projects/trusted"</span>]</pre>
      </div>
      <div class="config-prose">
        <p>Auto-approve MCP tool calls only when the session is in <code>acceptEdits</code> mode. In any other mode the rules are inert. Block rules run first; this cannot unlock a blocked tool.</p>
        <p><code>tool</code> supports exact, prefix (<code>mcp__serena*</code>), suffix (<code>*_scrape</code>), and substring (<code>*serena*</code>) patterns. Substring matches catch sibling servers whose names also contain the literal, so prefer prefix patterns for cross-namespace coverage.</p>
        <p><code>if_project_has</code> and <code>if_project_under</code> scope rules to specific directories. <code>~</code> expansion is supported.</p>
        <p><code>reason</code> surfaces only on the main-thread PreToolUse path. Subagent PermissionRequest allow has no reason slot; the field is silently dropped there. The rule is active only for clients that emit <code>acceptEdits</code>; Codex currently does not, so Codex MCP calls do not use this feature. Codex <code>apply_patch</code> file edits have a separate toggle, <code>[codex] accept_project_edits</code>.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h2>Skill auto-approval</h2>
      <span class="src-tag">documented</span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec">[[auto_approve_skills]]</span>
<span class="k">skill</span>          = <span class="s">"my-plugin*"</span>
<span class="k">if_project_has</span> = [<span class="s">".my-plugin"</span>]
<span class="sec">[[auto_approve_skills]]</span>
<span class="k">skill</span>            = <span class="s">"deploy-tool"</span>
<span class="k">if_project_under</span> = [<span class="s">"~/projects/staging"</span>]</pre>
      </div>
      <div class="config-prose">
        <p>Auto-approve Skill calls based on directory conditions. Explicit trust declaration; no external hook scripts needed.</p>
        <p><code>if_project_has</code> requires the project directory to contain one of the listed files or directories. <code>if_project_under</code> requires the project to be at or under one of the listed paths.</p>
        <p>The project directory comes from <code>CLAUDE_PROJECT_DIR</code> or, for Gemini compatibility, <code>GEMINI_PROJECT_DIR</code>. If neither is set, directory-conditioned rules fail closed.</p>
        <p>Honoured under auto mode too. <code>[[auto_approve_skills]]</code> rules aren't revoked by opting into the classifier.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h2>File guards</h2>
      <span class="src-tag">documented</span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec">[file_guards]</span>
<span class="k">extra_names</span>      = [<span class="s">".custom-config"</span>]
<span class="k">extra_dirs</span>       = [<span class="s">".mytools"</span>]
<span class="k">extra_prefixes</span>   = [<span class="s">"CUSTOM_"</span>]
<span class="k">extra_extensions</span> = [<span class="s">".secret"</span>]</pre>
      </div>
      <div class="config-prose">
        <p>Symlink guards protect AI configuration files from being read or edited through a symlink that points somewhere else. Default list covers <code>CLAUDE.md</code>, <code>.cursorrules</code>, <code>GEMINI.md</code>, the <code>.codex/</code> directory, <code>.agentignore</code>, <code>.claude/settings.json</code>, and others.</p>
        <p><code>extra_*</code> fields extend the built-in list by exact filename, directory name, filename prefix, or file extension.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h2>Hints</h2>
      <span class="src-tag">documented</span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec">[hints]</span>
<span class="k">disable</span> = [<span class="s">"man"</span>, <span class="s">"du"</span>]</pre>
      </div>
      <div class="config-prose">
        <p>When <code>features.hints = true</code> (default), allowed commands using legacy tools get one-line suggestions for modern alternatives via <code>additionalContext</code>.</p>
        <p><code>disable</code> suppresses hints for specific commands you prefer to keep. Hints never change the decision; they only inform.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h2>Cache</h2>
      <span class="src-tag">documented</span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec">[cache]</span>
<span class="k">ttl_days</span> = <span class="n">14</span>  <span class="c"># default 7</span></pre>
      </div>
      <div class="config-prose">
        <p>Controls how often tool-gates re-checks which modern CLI tools are installed. Lower values detect newly installed tools faster; higher values reduce disk I/O.</p>
        <p>Force a refresh anytime with <code>tool-gates --refresh-tools</code>.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h2>Git aliases</h2>
      <span class="src-tag">documented</span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec">[git_aliases]</span>
<span class="k">include_local_repo</span> = <span class="b">true</span>  <span class="c"># default false</span></pre>
      </div>
      <div class="config-prose">
        <p>Repo-local aliases (in <code>$REPO/.git/config</code>) are off by default. A malicious alias in a third-party repo should not silently inherit alias trust on first checkout.</p>
        <p>Built-in commands always win over aliases (<code>alias.status = log</code> does not shadow real <code>status</code>). Shell-prefixed aliases (<code>!cmd</code>) never resolve; they ask. Chained aliases resolve up to five levels with cycle detection; a cycle or depth overflow also asks.</p>
        <p>The global alias map is read once per process. When local aliases are enabled, the repository map is read for the current project and shadows the global map.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h2>Security reminders</h2>
      <span class="src-tag">documented</span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec">[security_reminders]</span>
<span class="k">secrets</span> = <span class="b">true</span>
<span class="k">anti_patterns</span> = <span class="b">true</span>
<span class="k">warnings</span> = <span class="b">true</span>
<span class="k">disable_rules</span> = [<span class="s">"eval_injection"</span>]</pre>
      </div>
      <div class="config-prose">
        <p>Disable individual rules by id, including Tier 1 rules, when you have a deliberate local exception. For a broad secret-scan opt-out, set <code>secrets = false</code>.</p>
        <p>Use Tier 1 disables sparingly: they remove the hard-deny floor for that specific secret rule.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h2>Design lint</h2>
      <span class="src-tag">documented</span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec">[features]</span>
<span class="k">design_lint</span> = <span class="b">true</span>
<span class="sec">[design_lint]</span>
<span class="k">disable_rules</span> = [<span class="s">"color/default-indigo"</span>]</pre>
      </div>
      <div class="config-prose">
        <p>Opt-in (default off). Set <code>design_lint = true</code> under <code>[features]</code> to scan UI file writes and edits for generic, templated design patterns and missing UI-quality basics.</p>
        <p>Disable individual rules by id (for example <code>color/default-indigo</code> or <code>content/dash</code>) when a project deliberately uses that pattern. CSS custom-property <em>definitions</em> in a <code>:root</code> block are exempt from the raw-color rules, so defining a brand token is never flagged.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h2>Comment lint</h2>
      <span class="src-tag">documented</span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec">[features]</span>
<span class="k">comment_lint</span> = <span class="b">true</span>
<span class="sec">[comment_lint]</span>
<span class="k">max_per_100</span> = <span class="b">40</span>
<span class="k">min_code_lines</span> = <span class="b">15</span>
<span class="k">max_block_lines</span> = <span class="b">5</span>
<span class="k">disable_rules</span> = [<span class="s">"volume/long-block"</span>]</pre>
      </div>
      <div class="config-prose">
        <p>Opt-in (default off). Set <code>comment_lint = true</code> under <code>[features]</code> to measure how much narrative commentary a code write or edit adds relative to the code it adds.</p>
        <p><code>max_per_100</code> is narrative comment lines per 100 code lines before <code>volume/comment-heavy</code> fires, and <code>min_code_lines</code> is how much code an edit must add before that rule applies at all. <code>max_block_lines</code> caps the longest run of consecutive own-line comments before <code>volume/long-block</code> fires.</p>
        <p>Doc comments (<code>///</code>, <code>//!</code>, <code>/** */</code>, Python docstrings) and tooling directives (<code>#&nbsp;noqa</code>, <code>//nolint</code>, <code>eslint-disable</code>) are exempt, and only code extensions are scanned.</p>
      </div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h2>Codex settings</h2>
      <span class="src-tag">defaults shown</span>
    </header>
    <div class="config-body">
      <div class="config-toml">
<pre><span class="sec">[codex]</span>
<span class="k">accept_project_edits</span> = <span class="b">false</span>
<span class="k">allow_edits_anywhere</span> = <span class="b">false</span></pre>
      </div>
      <div class="config-prose">
        <p>Configures Codex-specific auto-approval rules.</p>
        <p>When <code>accept_project_edits = true</code>, in-project <code>apply_patch</code> edits auto-approve on the Codex <code>PermissionRequest</code> hook. It also evaluates Codex shell commands in in-project directories as <code>acceptEdits</code>, allowing safe formatting and linting while keeping dangerous operations gated.</p>
        <p>When <code>allow_edits_anywhere = true</code>, the auto-approval is widened to edits anywhere on disk, subject to standard deny rules and file guards.</p>
      </div>
    </div>
  </div>
  <p class="note">
    <svg class="alert" aria-hidden="true" focusable="false" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
    <span><b>Codex command gating lives outside this file.</b> Codex's built-in safe-read auto-approval is governed by execpolicy rules in <code>~/.codex/rules/</code>, not tool-gates config. To route those reads through tool-gates, see the <a href="codex.html">Codex approval model</a>. The one Codex setting that does live here, <code>[codex] accept_project_edits</code>, auto-approves in-project edits on Codex (<code>apply_patch</code> plus file-editing shell commands); that same page covers it.</span>
  </p>
  <p class="config-path">
    <span class="lbl">Config path</span>
    <code>~/.config/tool-gates/config.toml</code>
    <span class="right">Optional. Sane defaults if absent.</span>
  </p>

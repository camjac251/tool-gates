  <nav class="breadcrumb" aria-label="Breadcrumb">
    <ol>
      <li><a href="index.html">Reference</a></li>
      <li aria-current="page">Comment lint</li>
    </ol>
  </nav>
  <h1 id="comment-lint-h1">Comment lint</h1>
  <p class="page-lede">tool-gates measures how much narrative commentary a write or edit adds relative to the code it adds, and how long any single comment runs. It covers Claude <code>Write</code>/<code>Edit</code> and Codex <code>apply_patch</code> added lines on the PostToolUse path, the same path as the security-reminder and design-lint nudges. Antigravity has no PostToolUse hook, so comment lint does not run there. Findings are a single tier: a match attaches a post-write nudge so the next action can trim. Nothing is blocked. The gate is opt-in (default off) and only scans code extensions; Markdown, JSON, and other prose or data files are skipped.</p>
  <div class="sec-head" style="margin-top: var(--s-6)">
    <p class="lbl">Why it is opt-in</p>
    <h2>Volume, not judgement.</h2>
    <p>Assistant prompts already say <em>whether</em> to write a comment. Nothing bounds how many or how long, which is where commentary accumulates: an edit that adds more narration than code, or one comment that runs a full paragraph. These rules measure only that. They make no claim about whether an individual comment is worth keeping.</p>
    <p>Doc comments are exempt. <code>///</code>, <code>//!</code>, <code>/** */</code>, and Python docstrings are API documentation, and flagging them would push toward undocumented public surfaces. Tooling directives (<code># noqa</code>, <code>//nolint</code>, <code>eslint-disable</code>, <code>@ts-expect-error</code>) are exempt too: they are machine instructions, not prose.</p>
    <p>Defaults are tuned to the tail rather than the median. Every <code>additionalContext</code> injection costs tokens and disturbs the prompt cache, so a gate that fires on a typical edit costs more than it saves.</p>
  </div>
  <div class="rule-card">
    <header>
      <h2>Comment volume</h2>
      <span class="count">post-write nudge · PostToolUse</span>
    </header>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>volume/comment-heavy</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">Keep the ones a reader could not infer from the code and delete the rest.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>volume/long-block</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">State the constraint in one or two lines, or move the explanation to a doc comment on the item it describes.</div>
    </div>
  </div>
  <div class="config-block">
    <header>
      <h3>Configure</h3>
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
        <p>Opt-in. Set <code>comment_lint = true</code> under <code>[features]</code> to turn the gate on; it is off by default.</p>
        <p><code>max_per_100</code> is narrative comment lines per 100 code lines before <code>volume/comment-heavy</code> fires. <code>min_code_lines</code> is how much code an edit must add before that rule applies at all, so a small edit that is legitimately comment-dense stays quiet.</p>
        <p><code>max_block_lines</code> is the longest run of consecutive own-line comments allowed before <code>volume/long-block</code> fires. Raise it for codebases that favor long explanatory headers.</p>
        <p>Lower the thresholds to tighten the house style; raise them to make the gate rarer. Disable a single rule by id via <code>disable_rules</code>.</p>
      </div>
    </div>
  </div>

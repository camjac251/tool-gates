  <p class="breadcrumb"><a href="index.html">Reference</a> / Design lint</p>
  <h1 id="design-lint-h1">Design lint</h1>
  <p class="page-lede">tool-gates scans UI file write/edit bodies for generic, templated design patterns and missing UI-quality basics. It covers Claude <code>Write</code>/<code>Edit</code>, Codex <code>apply_patch</code> added lines, and Antigravity <code>write_to_file</code>/<code>replace_file_content</code>/<code>multi_replace_file_content</code>, on the same PostToolUse path as security reminders. Findings are a single tier: every match attaches a post-write nudge so the next action can self-correct. Nothing is blocked. The gate is opt-in (default off) and only scans UI extensions (<code>.tsx</code>, <code>.jsx</code>, <code>.vue</code>, <code>.svelte</code>, <code>.astro</code>, <code>.html</code>, <code>.css</code>, <code>.scss</code>, and similar).</p>
  <div class="sec-head" style="margin-top: var(--s-6)">
    <p class="lbl">Why it is opt-in</p>
    <h2>Design conventions are a quality opinion, not a safety floor.</h2>
    <p>Unlike security reminders, these rules encode a house style for frontend output: avoid the patterns that read as generic or templated, and keep the accessibility basics. That is a deliberate choice a project opts into, so the gate defaults off. When enabled, each match attaches a <code>&lt;system-reminder&gt;</code> via <code>additionalContext</code> after the write lands. Raw color values inside a <code>:root</code> token <em>definition</em> are exempt: defining a brand token is legitimate; reaching for the same value in markup is what gets flagged.</p>
  </div>
  <div class="rule-card">
    <header>
      <h2>Color</h2>
      <span class="count">post-write nudge · PostToolUse</span>
    </header>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>color/default-indigo</code></div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason">Default Tailwind indigo accent (<code>#6366f1</code>, <code>#4f46e5</code>, ...). Use a theme token; define indigo in the theme if the brand genuinely calls for it.</div>
    </div>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>color/purple-gradient</code></div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason">Purple, violet, or indigo gradient, detected by OKLCH hue so arbitrary violets are caught, not just literals. Favor a flat surface; define brand violet as a token if it is real.</div>
    </div>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>color/cliche-gradient</code></div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason">The overused <code>#667eea</code> / <code>#764ba2</code> "tech" gradient. Use a solid color or a narrow-band gradient.</div>
    </div>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>color/overused-palette</code></div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason">The overused beige / brass / espresso "premium" palette. Choose colors that reflect the actual brand.</div>
    </div>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>color/hardcoded-palette</code></div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason">Hardcoded Tailwind palette color (<code>bg-blue-500</code>, ...). Use semantic theme tokens such as <code>bg-background</code>, <code>text-foreground</code>.</div>
    </div>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>color/raw-hex</code></div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason">Raw hex in an inline style. Use a theme token.</div>
    </div>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>color/theme-accessor</code></div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason"><code>theme(colors.*)</code> in raw CSS. Reference the CSS variable directly, e.g. <code>var(--color-muted)</code>.</div>
    </div>
  </div>
  <div class="rule-card">
    <header>
      <h2>Typography</h2>
      <span class="count">post-write nudge · PostToolUse</span>
    </header>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>typography/default-font</code></div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason">Inter as the display font. Choose a typeface suited to the product's character.</div>
    </div>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>typography/small-body-text</code></div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason"><code>text-xs</code> / <code>text-sm</code> on a <code>&lt;p&gt;</code>. Body text should be 16px or larger; reserve smaller sizes for metadata.</div>
    </div>
  </div>
  <div class="rule-card">
    <header>
      <h2>Content</h2>
      <span class="count">post-write nudge · PostToolUse</span>
    </header>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>content/placeholder-name</code></div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason">Placeholder or stock person / company name. Use real content or an explicit <code>[placeholder]</code>.</div>
    </div>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>content/fabricated-stat</code></div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason">Round, unsourced statistic (<code>99.9%</code>, <code>10,000+</code>). Use a real measured number or remove it.</div>
    </div>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>content/filler-copy</code></div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason">Generic marketing filler ("Elevate", "Seamless", "Unleash", ...). State a concrete outcome instead.</div>
    </div>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>content/dash</code></div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason">Em or en dash in rendered text. Use a period, comma, colon, or parentheses.</div>
    </div>
  </div>
  <div class="rule-card">
    <header>
      <h2>Structure &amp; accessibility</h2>
      <span class="count">post-write nudge · PostToolUse</span>
    </header>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>a11y/focus-visible</code></div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason">Focus outline removed with no <code>focus-visible</code> replacement in the file. Add a visible focus style.</div>
    </div>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>behavior/scroll-into-view</code></div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason"><code>scrollIntoView</code> mutates ancestor scroll position in embedded contexts. Use <code>scrollTo</code> with a computed offset.</div>
    </div>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>layout/accent-stripe</code></div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason">Card with a 4px left accent stripe. Use a tonal background or a thin bottom border instead.</div>
    </div>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>assets/hotlinked-image</code></div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason">Hotlinked external image (<code>unsplash.com</code>). Download and self-host the asset.</div>
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
<span class="k">design_lint</span> = <span class="b">true</span>
<span class="sec">[design_lint]</span>
<span class="k">disable_rules</span> = [<span class="s">"color/default-indigo"</span>]</pre>
      </div>
      <div class="config-prose">
        <p>Opt-in. Set <code>design_lint = true</code> under <code>[features]</code> to turn the gate on; it is off by default.</p>
        <p>Disable individual rules by id (for example <code>color/default-indigo</code> or <code>content/dash</code>) when a project deliberately uses that pattern.</p>
        <p>Only UI file extensions are scanned. CSS custom-property <em>definitions</em> in a <code>:root</code> block are exempt from the raw-color rules, so defining a brand token is never flagged, while the same value used in markup or inline styles still is.</p>
      </div>
    </div>
  </div>

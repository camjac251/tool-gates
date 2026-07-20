  <nav class="breadcrumb" aria-label="Breadcrumb">
    <ol>
      <li><a href="index.html">Reference</a></li>
      <li aria-current="page">Design lint</li>
    </ol>
  </nav>
  <h1 id="design-lint-h1">Design lint</h1>
  <p class="page-lede">tool-gates scans UI file write/edit bodies for generic, templated design patterns and missing UI-quality basics. It covers Claude <code>Write</code>/<code>Edit</code> and Codex <code>apply_patch</code> added lines on the PostToolUse path, the same path as the security-reminder nudges. Antigravity has no PostToolUse hook, so design-lint does not run there. Findings are a single tier: every match attaches a post-write nudge so the next action can self-correct. Nothing is blocked. The gate is opt-in (default off) and only scans UI extensions (<code>.tsx</code>, <code>.jsx</code>, <code>.vue</code>, <code>.svelte</code>, <code>.astro</code>, <code>.html</code>, <code>.css</code>, <code>.scss</code>, and similar).</p>
  <div class="sec-head" style="margin-top: var(--s-6)">
    <p class="lbl">Why it is opt-in</p>
    <h2>A design opinion you switch on per project.</h2>
    <p>Security reminders enforce a safety floor everywhere. These rules encode a house style for frontend output: avoid the patterns that read as generic or templated, and keep the accessibility basics. That is a deliberate choice a project opts into, so the gate defaults off. When enabled, each match attaches a <code>&lt;system-reminder&gt;</code> via <code>additionalContext</code> after the write lands. Raw color values inside a <code>:root</code> token <em>definition</em> are exempt: defining a brand token is legitimate; reaching for the same value in markup is what gets flagged.</p>
  </div>
  <div class="rule-card">
    <header>
      <h2>Color</h2>
      <span class="count">post-write nudge · PostToolUse</span>
    </header>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>color/cliche-gradient</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">Overused #667eea / #764ba2 'tech' gradient. Use a solid color or a narrow-band gradient.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>color/purple-gradient</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">Purple, violet, or indigo gradient. Favor a flat surface with intentional typography; if the brand truly uses violet, define it as a token and reference it via var().</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>color/overused-palette</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">Overused beige / brass / espresso 'premium' palette. Choose colors that reflect the actual brand.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>color/default-indigo</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">Default Tailwind indigo accent. Use a theme token; define indigo in the theme if the brand genuinely calls for it.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>color/hardcoded-palette</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">Hardcoded Tailwind palette color. Use semantic theme tokens (bg-background, text-foreground, ...).</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>color/raw-hex</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">Raw hex in an inline style. Use a theme token.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>color/theme-accessor</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">theme(colors.*) in raw CSS. Reference the CSS variable directly, e.g. var(--color-muted).</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>color/maxed-saturation</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">Pure screen-primary color (#f00, #00ff00, ...). Use an OKLCH value with moderate chroma in a safe lightness range.</div>
    </div>
  </div>
  <div class="rule-card">
    <header>
      <h2>Typography</h2>
      <span class="count">post-write nudge · PostToolUse</span>
    </header>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>typography/default-font</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">Inter as the display font. Choose a typeface suited to the product's character.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>typography/small-body-text</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">text-xs / text-sm on a &lt;p&gt;. Body text should be 16px or larger; reserve smaller sizes for metadata.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>typography/script-font</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">Script or handwriting font used as display type (Pacifico, Caveat, Comic Sans, ...). Reserve script faces for genuine handwriting context.</div>
    </div>
  </div>
  <div class="rule-card">
    <header>
      <h2>Content</h2>
      <span class="count">post-write nudge · PostToolUse</span>
    </header>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>content/placeholder-name</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">Placeholder or stock person/company name. Use real content or an explicit [placeholder].</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>content/fabricated-stat</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">Round, unsourced statistic. Use a real measured number or remove it.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>content/filler-copy</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">Generic marketing filler ('Elevate', 'Seamless', 'Unleash', ...). State a concrete outcome instead.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>content/dash</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">Em or en dash in rendered text. Use a period, comma, colon, or parentheses.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>content/emoji-decoration</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">Emoji decorating a heading or button. Reads casual in most product and editorial UI; remove unless the brand uses emoji deliberately.</div>
    </div>
  </div>
  <div class="rule-card">
    <header>
      <h2>Motion</h2>
      <span class="count">post-write nudge · PostToolUse</span>
    </header>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>motion/transition-all</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">transition: all (or the transition-all utility) animates every property, including layout. List the specific properties to transition.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>motion/scale-hover</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">Default scale(1.05) / scale(1.1) hover. Differentiate hover by element: a color shift for links, a ring for buttons.</div>
    </div>
  </div>
  <div class="rule-card">
    <header>
      <h2>Structure &amp; accessibility</h2>
      <span class="count">post-write nudge · PostToolUse</span>
    </header>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>layout/accent-stripe</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">Card with a 4px left accent stripe. Use a tonal background or a thin bottom border instead.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>behavior/scroll-into-view</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">scrollIntoView mutates ancestor scroll position in embedded contexts. Use scrollTo with a computed offset.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>assets/hotlinked-image</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">Hotlinked external image. Download and self-host the asset.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>a11y/focus-visible</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">Focus outline removed with no focus-visible replacement. Add a visible focus style.</div>
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

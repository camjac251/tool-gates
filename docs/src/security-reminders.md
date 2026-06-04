  <p class="breadcrumb"><a href="index.html">Reference</a> / Security reminders</p>
  <h1 id="secrems-h1">Security reminders</h1>
  <p class="page-lede">tool-gates scans write/edit bodies for 28 anti-patterns organised into three tiers, including Claude <code>Write</code>/<code>Edit</code>, Gemini <code>write_file</code>/<code>replace</code> before-tool checks, and Codex <code>apply_patch</code> added lines. The hard floor denies source writes before the file ever lands, while documentation files get a post-write warning. The middle tier nudges the assistant after a write so the next action can self-correct. The top tier informs without blocking.</p>
  <div class="sec-head" style="margin-top: var(--s-6)">
    <p class="lbl">Why Tier 2 nudges after the write</p>
    <h2>Self-correction beats re-prompting.</h2>
    <p>Tier 2 patterns let the write succeed, then attach a <code>&lt;system-reminder&gt;</code> on <code>additionalContext</code>. Claude and Codex see the warning in the next turn and can edit the file before doing anything else; Gemini AfterTool output is not plumbed for Tier 2 yet. No wasted Write call from blocking-then-retrying. Each (file, rule) pair fires at most once per session.</p>
  </div>
  <div class="rule-card">
    <header>
      <h2>Tier 1 · Hard-coded secrets</h2>
      <span class="count">source deny · docs warn</span>
    </header>
    <div class="rule-row" data-decision="block">
      <div class="rule-cmd"><code>AKIA…</code></div>
      <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Deny</span></div>
      <div class="rule-reason">AWS access key ID. 20-character base32 starting with <code>AKIA</code>.</div>
    </div>
    <div class="rule-row" data-decision="block">
      <div class="rule-cmd"><code>ghp_… · ghs_… · ghu_… · gho_… · ghr_…</code></div>
      <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Deny</span></div>
      <div class="rule-reason">GitHub personal, server, user, OAuth, and refresh tokens.</div>
    </div>
    <div class="rule-row" data-decision="block">
      <div class="rule-cmd"><code>-----BEGIN * PRIVATE KEY-----</code></div>
      <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Deny</span></div>
      <div class="rule-reason">Private key PEM headers. RSA, EC, OpenSSH, encrypted variants all match.</div>
    </div>
    <div class="rule-row" data-decision="block">
      <div class="rule-cmd"><code>sk_live_… · xoxb-… · AIza…</code></div>
      <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Deny</span></div>
      <div class="rule-reason">Stripe live secret keys, Slack bot tokens, Google API keys. Format-matched.</div>
    </div>
    <div class="rule-row" data-decision="block">
      <div class="rule-cmd">GitHub Actions injection</div>
      <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Deny</span></div>
      <div class="rule-reason">Untrusted <code>${{ github.event.* }}</code> values flowing into <code>run:</code> blocks. Blocked when written to <code>.github/workflows/*.yml</code>.</div>
    </div>
  </div>
  <div class="rule-card">
    <header>
      <h2>Tier 2 · Anti-patterns in code</h2>
      <span class="count">post-write nudge · PostToolUse</span>
    </header>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>eval(…)</code> · <code>new Function(…)</code></div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason">Arbitrary JavaScript execution from a string. Use proper parsing instead.</div>
    </div>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>child_process.exec</code> · <code>os.system</code> · <code>subprocess(shell=True)</code></div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason">Shell injection vectors. Use array-form spawn or escape inputs.</div>
    </div>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>dangerouslySetInnerHTML</code> · <code>.innerHTML =</code> · <code>document.write</code></div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason">XSS sinks. Sanitise with DOMPurify or use <code>textContent</code>.</div>
    </div>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>pickle.load</code> · <code>marshal.load</code> · <code>shelve.open</code> · <code>__import__</code></div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason">Python deserialization sinks. Untrusted input becomes code execution.</div>
    </div>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>yaml.load</code> (no SafeLoader)</div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason">PyYAML default loader executes Python tags. Use <code>yaml.safe_load</code>.</div>
    </div>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd">SQL f-string interpolation</div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason">Classic SQL injection. Use parameterised queries.</div>
    </div>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>render_template_string</code> (Flask)</div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason">Server-side template injection. Use a fixed template file with safe vars.</div>
    </div>
    <div class="rule-row" data-decision="ask">
      <div class="rule-cmd"><code>unserialize</code> (PHP)</div>
      <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Nudge</span></div>
      <div class="rule-reason">PHP object injection. Use <code>json_decode</code>.</div>
    </div>
  </div>
  <div class="rule-card">
    <header>
      <h2>Tier 3 · Informational warnings</h2>
      <span class="count">allow + warn · PreToolUse/BeforeTool; Codex PostToolUse</span>
    </header>
    <div class="rule-row" data-decision="allow">
      <div class="rule-cmd"><code>verify=False</code></div>
      <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Warn</span></div>
      <div class="rule-reason">SSL verification disabled. Acceptable for local dev; never in production.</div>
    </div>
    <div class="rule-row" data-decision="allow">
      <div class="rule-cmd"><code>chmod 777</code></div>
      <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Warn</span></div>
      <div class="rule-reason">World-writable. Pick the minimum needed: 755 for dirs, 644 for files.</div>
    </div>
    <div class="rule-row" data-decision="allow">
      <div class="rule-cmd">MD5 / SHA1 for security</div>
      <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Warn</span></div>
      <div class="rule-reason">Broken hash functions for signatures or password storage. Use SHA-256 / Argon2.</div>
    </div>
    <div class="rule-row" data-decision="allow">
      <div class="rule-cmd">CORS wildcard <code>*</code></div>
      <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Warn</span></div>
      <div class="rule-reason"><code>Access-Control-Allow-Origin: *</code> with credentials is a security hole.</div>
    </div>
    <div class="rule-row" data-decision="allow">
      <div class="rule-cmd"><code>v-html=</code> (Vue) · <code>autoescape=False</code></div>
      <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Warn</span></div>
      <div class="rule-reason">Template engines with autoescape disabled. XSS-prone if any value comes from user input.</div>
    </div>
    <div class="rule-row" data-decision="allow">
      <div class="rule-cmd"><code>Math.random()</code></div>
      <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Warn</span></div>
      <div class="rule-reason">Not cryptographically secure. Use <code>crypto.getRandomValues()</code> for tokens, IDs, and nonces.</div>
    </div>
    <div class="rule-row" data-decision="allow">
      <div class="rule-cmd"><code>createHash('md5')</code> / <code>('sha1')</code> (JS)</div>
      <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Warn</span></div>
      <div class="rule-reason">Broken hashes in Node. Use SHA-256+ for integrity, bcrypt/scrypt/argon2 for passwords.</div>
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
<span class="k">security_reminders</span> = <span class="b">true</span>
<span class="sec">[security_reminders]</span>
<span class="k">secrets</span> = <span class="b">true</span>
<span class="k">anti_patterns</span> = <span class="b">true</span>
<span class="k">warnings</span> = <span class="b">true</span>
<span class="k">disable_rules</span> = [<span class="s">"eval_injection"</span>]</pre>
      </div>
      <div class="config-prose">
        <p>Disable individual rules by id when a Tier 2 nudge fires on a legitimate use of (for example) <code>eval()</code> in your codebase.</p>
        <p>Tier 1 secret rules are on by default. Disable them by id via <code>disable_rules</code>, or all at once with <code>secrets = false</code>.</p>
        <p>Documentation files (<code>.md</code>, <code>.txt</code>, <code>.rst</code>, etc.) are exempt for Tier 2/3 content checks. Tier 1 secrets in source files deny before write; Tier 1 secrets in docs get a PostToolUse warning; dedicated secret files (<code>.env</code>, <code>.envrc</code>, <code>.env.*</code>) skip secret detection because they exist to hold secrets.</p>
      </div>
    </div>
  </div>

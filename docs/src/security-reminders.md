  <nav class="breadcrumb" aria-label="Breadcrumb">
    <ol>
      <li><a href="index.html">Reference</a></li>
      <li aria-current="page">Security reminders</li>
    </ol>
  </nav>
  <h1 id="secrems-h1">Security reminders</h1>
  <p class="page-lede">tool-gates scans write/edit bodies for 28 anti-patterns organised into three tiers, including Claude <code>Write</code>/<code>Edit</code>, Codex <code>apply_patch</code> added lines, Antigravity <code>write_to_file</code>/<code>replace_file_content</code>/<code>multi_replace_file_content</code>, and Gemini <code>write_file</code>/<code>replace</code> before-tool checks. The hard floor denies source writes before the file ever lands, while documentation files get a post-write warning. The middle tier nudges the assistant after a write so the next action can self-correct. The top tier informs without blocking.</p>
  <div class="sec-head" style="margin-top: var(--s-6)">
    <p class="lbl">Why Tier 2 nudges after the write</p>
    <h2>Self-correction beats re-prompting.</h2>
    <p>Tier 2 patterns let the write succeed, then attach a <code>&lt;system-reminder&gt;</code> on <code>additionalContext</code>. Claude and Codex see the warning in the next turn and can edit the file before doing anything else. Gemini and Antigravity install no post hook, so Tier 2 nudges are unavailable there. Gemini still receives Tier 1 denies and Tier 3 warnings on BeforeTool; Antigravity applies Tier 1 denies on PreToolUse but cannot carry Tier 3 additionalContext. No wasted Write call from blocking-then-retrying. Each (file, rule) pair fires at most once per session.</p>
  </div>
  <div class="rule-card">
    <header>
      <h2>Tier 1 · Hard-coded secrets</h2>
      <span class="count">source deny · docs warn</span>
    </header>
    <div class="rule-row" data-decision="block">
      <div class="rule-cmd"><code>hardcoded_aws_key</code></div>
      <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
      <div class="rule-reason">Hardcoded AWS access key detected. Use environment variables or a secrets manager instead. Never commit AWS keys to source code.</div>
    </div>
    <div class="rule-row" data-decision="block">
      <div class="rule-cmd"><code>hardcoded_private_key</code></div>
      <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
      <div class="rule-reason">Private key detected in file content. Private keys must never be committed to source code. Use environment variables, a secrets manager, or file references outside the repo.</div>
    </div>
    <div class="rule-row" data-decision="block">
      <div class="rule-cmd"><code>hardcoded_github_token</code></div>
      <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
      <div class="rule-reason">GitHub token detected in file content. Use GITHUB_TOKEN environment variable or gh auth instead. Revoke this token if it was ever committed.</div>
    </div>
    <div class="rule-row" data-decision="block">
      <div class="rule-cmd"><code>hardcoded_generic_secret</code></div>
      <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
      <div class="rule-reason">API key or token detected in file content. Use environment variables or a secrets manager. Never hardcode secrets in source code.</div>
    </div>
    <div class="rule-row" data-decision="block">
      <div class="rule-cmd"><code>github_actions_injection</code></div>
      <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
      <div class="rule-reason">GitHub Actions workflow injection risk. Untrusted input (issue title, PR body, commit message, head_ref) used directly in a run: block can lead to command injection. UNSAFE: run: echo "${{ github.event.issue.title }}" SAFE: env: TITLE: ${{ github.event.issue.title }} run: echo "$TITLE" See: https://github.blog/security/vulnerability-research/how-to-catch-github-actions-workflow-injections-before-attackers-do/</div>
    </div>
  </div>
  <div class="rule-card">
    <header>
      <h2>Tier 2 · Anti-patterns in code</h2>
      <span class="count">post-write nudge · PostToolUse</span>
    </header>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>child_process_exec</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">child_process.exec() can lead to command injection. Use child_process.execFile() or child_process.spawn() instead. They don't invoke a shell and prevent argument injection.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>new_function_injection</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">new Function() with dynamic strings can lead to code injection. Consider alternative approaches that don't evaluate arbitrary code.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>eval_injection</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">eval() executes arbitrary code and is a major security risk. Use JSON.parse() for data parsing, or alternative design patterns that don't require code evaluation.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>os_system_injection</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">os.system() passes commands through the shell and is vulnerable to injection. Use subprocess.run() with a list of arguments (no shell=True) instead.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>pickle_deserialization</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">pickle can execute arbitrary code during deserialization. Use JSON, msgpack, or other safe serialization formats for untrusted data. Only use pickle with data you fully trust.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>dangerous_inner_html</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">dangerouslySetInnerHTML can lead to XSS if used with untrusted content. Sanitize all content with DOMPurify or use safe alternatives like textContent.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>document_write_xss</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">document.write() can be exploited for XSS attacks. Use DOM manipulation methods like createElement() and appendChild() instead.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>inner_html_assignment</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">Setting innerHTML with untrusted content can lead to XSS. Use textContent for plain text, or sanitize HTML content with DOMPurify.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>unsafe_yaml_load</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">yaml.load() without SafeLoader can execute arbitrary Python code. Use yaml.safe_load() or yaml.load(f, Loader=yaml.SafeLoader) instead.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>sql_string_interpolation</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">SQL query built with string interpolation is vulnerable to SQL injection. Use parameterized queries (?, %s, :param) instead of f-strings or .format().</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>subprocess_shell_true</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">subprocess with shell=True is vulnerable to command injection. Pass a list of arguments instead: subprocess.run(["cmd", "arg1", "arg2"]).</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>flask_ssti</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">render_template_string() with user input can lead to server-side template injection (SSTI). Use render_template() with a file instead, or sanitize all dynamic content.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>marshal_deserialization</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">marshal can execute arbitrary code during deserialization. Use JSON or other safe serialization formats for untrusted data.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>python_dynamic_import</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">__import__() with dynamic strings can load arbitrary modules. Use static imports or importlib with validated module names.</div>
    </div>
    <div class="rule-row" data-decision="nudge">
      <div class="rule-cmd"><code>php_unserialize</code></div>
      <div><span class="pill nudge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"></polyline></svg>Nudge</span></div>
      <div class="rule-reason">unserialize() with untrusted data can lead to arbitrary code execution via PHP object injection. Use json_decode() instead.</div>
    </div>
  </div>
  <div class="rule-card">
    <header>
      <h2>Tier 3 · Informational warnings</h2>
      <span class="count">allow + warn · PreToolUse/BeforeTool; Codex PostToolUse</span>
    </header>
    <div class="rule-row" data-decision="allow">
      <div class="rule-cmd"><code>ssl_verification_disabled</code></div>
      <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span> <span class="warn-tag" title="allow + warn">warn</span></div>
      <div class="rule-reason">SSL/TLS verification is disabled. This makes the connection vulnerable to man-in-the-middle attacks. Only disable for local development with self-signed certs.</div>
    </div>
    <div class="rule-row" data-decision="allow">
      <div class="rule-cmd"><code>chmod_777</code></div>
      <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span> <span class="warn-tag" title="allow + warn">warn</span></div>
      <div class="rule-reason">chmod 777 / 0o777 grants read+write+execute to all users. Use more restrictive permissions (e.g., 0o755 for dirs, 0o644 for files).</div>
    </div>
    <div class="rule-row" data-decision="allow">
      <div class="rule-cmd"><code>weak_crypto_hash</code></div>
      <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span> <span class="warn-tag" title="allow + warn">warn</span></div>
      <div class="rule-reason">MD5/SHA1 are cryptographically broken for security purposes. Use SHA-256+ for integrity checks, bcrypt/argon2 for passwords.</div>
    </div>
    <div class="rule-row" data-decision="allow">
      <div class="rule-cmd"><code>vue_v_html</code></div>
      <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span> <span class="warn-tag" title="allow + warn">warn</span></div>
      <div class="rule-reason">v-html renders raw HTML and is vulnerable to XSS with untrusted content. Sanitize content with DOMPurify or use text interpolation {{ }} instead.</div>
    </div>
    <div class="rule-row" data-decision="allow">
      <div class="rule-cmd"><code>template_autoescape_disabled</code></div>
      <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span> <span class="warn-tag" title="allow + warn">warn</span></div>
      <div class="rule-reason">Disabling autoescape removes XSS protection from template output. Only disable for content you have already sanitized.</div>
    </div>
    <div class="rule-row" data-decision="allow">
      <div class="rule-cmd"><code>cors_wildcard</code></div>
      <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span> <span class="warn-tag" title="allow + warn">warn</span></div>
      <div class="rule-reason">CORS wildcard origin (*) allows any website to make requests. Restrict to specific trusted origins in production.</div>
    </div>
    <div class="rule-row" data-decision="allow">
      <div class="rule-cmd"><code>math_random_security</code></div>
      <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span> <span class="warn-tag" title="allow + warn">warn</span></div>
      <div class="rule-reason">Math.random() is not cryptographically secure. Use crypto.getRandomValues() or crypto.randomUUID() for security-sensitive values (tokens, session IDs, nonces).</div>
    </div>
    <div class="rule-row" data-decision="allow">
      <div class="rule-cmd"><code>js_weak_crypto_hash</code></div>
      <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span> <span class="warn-tag" title="allow + warn">warn</span></div>
      <div class="rule-reason">MD5/SHA1 are cryptographically broken for security purposes. Use SHA-256+ for integrity checks, bcrypt/scrypt/argon2 for passwords.</div>
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

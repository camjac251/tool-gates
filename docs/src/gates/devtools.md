<div class="gate-head">
  <p class="breadcrumb"><a href="../index.html">Gates</a> / Development Tools</p>
  <h1>Development Tools gate</h1>
  <div class="gate-meta">
    <span class="tag">priority <b>25</b></span>
    <span class="tag">unknown <b>ask</b></span>
    <span class="tag">covers <b>77+ tools</b></span>
    <span class="tag">write-flag detection</span>
  </div>

  <div class="summary" aria-label="Rule counts at a glance">
    <div class="seg-bar" role="img" aria-label="80 allow, 70 ask, 0 block">
      <div class="seg allow" style="flex: 80"></div>
      <div class="seg ask"   style="flex: 70"></div>
      <div class="seg block" style="flex: 0"></div>
    </div>
    <div class="counts">
      <span class="ca"><i></i><b>80</b> allow</span>
      <span class="cas"><i></i><b>70</b> ask</span>
      <span class="cb"><i></i><b>0</b> block</span>
    </div>
  </div>

  <p class="gate-lede">Developer tools that can modify files. Linters and type checkers run in inspection mode by default and ask when a write flag (<code>--write</code>, <code>--fix</code>, <code>-i</code>, <code>-w</code>) appears. Default <code>unknown_action</code> is <code>allow</code> because most tools in this category are read-only analysis.</p>
</div>

<div class="chips" role="group" aria-label="Filter rules by decision">
  <button class="chip all"   data-filter="all"   aria-pressed="true"><i></i>All <span class="n">150</span></button>
  <button class="chip allow" data-filter="allow" aria-pressed="false"><i></i>Allow <span class="n">80</span></button>
  <button class="chip ask"   data-filter="ask"   aria-pressed="false"><i></i>Ask <span class="n">70</span></button>
  <button class="chip block" data-filter="block" aria-pressed="false"><i></i>Block <span class="n">0</span></button>
</div>

<div class="rule-card">
  <header>
    <h2>Allowed · read-only modes</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/devtools.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/devtools.toml#allow
    </a>
    <span class="count">80 patterns</span>
  </header>

<div class="rule-row" data-decision="allow" id="devtools-actionlint">
  <div class="rule-cmd"><span class="prog">actionlint</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lints GitHub Actions workflow files. Read-only static analysis.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-air">
  <div class="rule-cmd"><span class="prog">air</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Live-reloads a Go app, rebuilding and restarting it on file changes. Runs the project's own build and binary.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-autoflake-check-check-diff">
  <div class="rule-cmd"><span class="prog">autoflake</span> <span class="flag">--check</span> <span class="flag">--check-diff</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports unused imports/variables and prints the diff. Read-only with <code>--check</code>/<code>--check-diff</code>; no files are written.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-bandit">
  <div class="rule-cmd"><span class="prog">bandit</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Scans Python for common security issues. Read-only static analysis.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-biome-lint">
  <div class="rule-cmd"><span class="prog">biome</span> lint</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports Biome lint diagnostics for the matched files. Read-only; writing fixes needs <code>--write</code>/<code>--fix</code>.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-black-check-diff">
  <div class="rule-cmd"><span class="prog">black</span> <span class="flag">--check</span> <span class="flag">--diff</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports whether files are <code>black</code>-formatted and prints the diff. Read-only with <code>--check</code>/<code>--diff</code>; no files are written.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-buf-lint">
  <div class="rule-cmd"><span class="prog">buf</span> lint</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports Protobuf lint diagnostics for the schema. Read-only; no files are written.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-buf-breaking">
  <div class="rule-cmd"><span class="prog">buf</span> breaking</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports breaking-change diagnostics against a baseline schema. Read-only; no files are written.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-buf-ls-files">
  <div class="rule-cmd"><span class="prog">buf</span> ls-files</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the Protobuf files in the module. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-buf-version">
  <div class="rule-cmd"><span class="prog">buf</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the <code>buf</code> version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-coverage-report">
  <div class="rule-cmd"><span class="prog">coverage</span> report</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints a coverage summary to stdout from the existing <code>.coverage</code> data file. Read-only; no report files are written.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-coverage-version">
  <div class="rule-cmd"><span class="prog">coverage</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the coverage.py version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-coverage-help">
  <div class="rule-cmd"><span class="prog">coverage</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints coverage.py usage help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-cypress-run">
  <div class="rule-cmd"><span class="prog">cypress</span> run</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the Cypress test suite headless and reports results. Writes test artifacts (videos, screenshots) to the configured output dir.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-cypress-verify">
  <div class="rule-cmd"><span class="prog">cypress</span> verify</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Verifies that the installed Cypress binary is runnable. Read-only check; no tests are run.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-cypress-version">
  <div class="rule-cmd"><span class="prog">cypress</span> version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints Cypress binary and package versions. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-cypress-info">
  <div class="rule-cmd"><span class="prog">cypress</span> info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints Cypress environment and detected-browser info. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-cypress-version-2">
  <div class="rule-cmd"><span class="prog">cypress</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Cypress version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-cypress-help">
  <div class="rule-cmd"><span class="prog">cypress</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints Cypress usage help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-d2">
  <div class="rule-cmd"><span class="prog">d2</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Renders D2 diagram source to an image. Writes the output file when one is specified.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-dart-analyze">
  <div class="rule-cmd"><span class="prog">dart</span> analyze</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs Dart static analysis and reports diagnostics. Read-only; no files are written.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-dart-info">
  <div class="rule-cmd"><span class="prog">dart</span> info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints Dart/Flutter environment and tooling info. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-dart-version">
  <div class="rule-cmd"><span class="prog">dart</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Dart SDK version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-esbuild">
  <div class="rule-cmd"><span class="prog">esbuild</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Bundles JS/TS. Writes output when an outfile or outdir is set, otherwise prints to stdout.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-ffmpeg-version-buildconf-l-h-help">
  <div class="rule-cmd"><span class="prog">ffmpeg</span> <span class="flag">-version</span> <span class="flag">-buildconf</span> <span class="flag">-L</span> <span class="flag">-h</span> <span class="flag">--help</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints ffmpeg version, build config, license, or usage help. Read-only info flags; no transcode runs.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-ffprobe">
  <div class="rule-cmd"><span class="prog">ffprobe</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspects media files and prints stream and format metadata. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-flake8">
  <div class="rule-cmd"><span class="prog">flake8</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lints Python and reports style and error findings. Read-only static analysis.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-gitleaks">
  <div class="rule-cmd"><span class="prog">gitleaks</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Scans for committed secrets and reports findings. Read-only; does not modify files.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-hadolint">
  <div class="rule-cmd"><span class="prog">hadolint</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lints Dockerfiles and reports issues. Read-only static analysis.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-isort-check-check-only-diff">
  <div class="rule-cmd"><span class="prog">isort</span> <span class="flag">--check</span> <span class="flag">--check-only</span> <span class="flag">--diff</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports whether imports are sorted and prints the diff. Read-only with <code>--check</code>/<code>--check-only</code>/<code>--diff</code>; no files are written.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-jest">
  <div class="rule-cmd"><span class="prog">jest</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the Jest test suite and prints results. Read-only unless tests write files or <code>-u</code> updates snapshots.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-jq">
  <div class="rule-cmd"><span class="prog">jq</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Processes JSON from files or stdin and prints the result. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-knip">
  <div class="rule-cmd"><span class="prog">knip</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Finds unused files, dependencies, and exports. Read-only analysis.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-lefthook-run">
  <div class="rule-cmd"><span class="prog">lefthook</span> run</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the configured git hooks on demand (the commands defined in <code>lefthook.yml</code>). Side effects depend on those configured commands.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-lefthook-version">
  <div class="rule-cmd"><span class="prog">lefthook</span> version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the lefthook version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-lefthook-dump">
  <div class="rule-cmd"><span class="prog">lefthook</span> dump</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the merged lefthook configuration to stdout. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-mocha">
  <div class="rule-cmd"><span class="prog">mocha</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the Mocha test suite and prints results. Read-only unless the tests write files.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-mypy">
  <div class="rule-cmd"><span class="prog">mypy</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Type-checks Python and reports errors. Read-only static analysis.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-nox-version">
  <div class="rule-cmd"><span class="prog">nox</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the nox version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-nox-help">
  <div class="rule-cmd"><span class="prog">nox</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints nox usage help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-nox-l-list">
  <div class="rule-cmd"><span class="prog">nox</span> <span class="flag">-l</span> <span class="flag">--list</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the sessions declared in <code>noxfile.py</code>. Read-only; no session is run.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-nx">
  <div class="rule-cmd"><span class="prog">nx</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs Nx workspace tasks. Executes the configured target scripts.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-oxlint">
  <div class="rule-cmd"><span class="prog">oxlint</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lints JS/TS and reports findings. Read-only unless <code>--fix</code> is set.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-parcel-build">
  <div class="rule-cmd"><span class="prog">parcel</span> build</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Builds the production bundle into the configured dist dir. Writes build artifacts only; no dev server is started.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-parcel-version">
  <div class="rule-cmd"><span class="prog">parcel</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Parcel version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-parcel-help">
  <div class="rule-cmd"><span class="prog">parcel</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints Parcel usage help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-patch-dry-run">
  <div class="rule-cmd"><span class="prog">patch</span> <span class="flag">--dry-run</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Simulates applying a patch and reports whether it would succeed. Read-only with <code>--dry-run</code>; no files are modified.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-playwright-test">
  <div class="rule-cmd"><span class="prog">playwright</span> test</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the Playwright test suite headless and reports results. Writes test artifacts (report, traces) to the configured output dir.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-playwright-show-report">
  <div class="rule-cmd"><span class="prog">playwright</span> show-report</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Serves the existing HTML test report locally for viewing. Read-only; no tests are run.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-playwright-show-trace">
  <div class="rule-cmd"><span class="prog">playwright</span> show-trace</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Opens the trace viewer on an existing trace file. Read-only; no tests are run.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-playwright-version">
  <div class="rule-cmd"><span class="prog">playwright</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Playwright version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-playwright-help">
  <div class="rule-cmd"><span class="prog">playwright</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints Playwright usage help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-pylint">
  <div class="rule-cmd"><span class="prog">pylint</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lints Python and reports findings. Read-only static analysis.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-pyright">
  <div class="rule-cmd"><span class="prog">pyright</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Type-checks Python and reports errors. Read-only static analysis.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-pytest">
  <div class="rule-cmd"><span class="prog">pytest</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the Python test suite and prints results. Read-only unless the tests write files or hit external services.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-rollup">
  <div class="rule-cmd"><span class="prog">rollup</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Bundles JS modules. Outputs to the configured file or directory.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-ruff-format-check-diff">
  <div class="rule-cmd"><span class="prog">ruff</span> format <span class="flag">--check</span> <span class="flag">--diff</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Checks Python formatting and prints the diff. Read-only with <code>--check</code>/<code>--diff</code>; no files are written.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-rustfmt-check">
  <div class="rule-cmd"><span class="prog">rustfmt</span> <span class="flag">--check</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports whether files are <code>rustfmt</code>-formatted via the exit code. Read-only with <code>--check</code>; no files are written.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-scalafmt-check">
  <div class="rule-cmd"><span class="prog">scalafmt</span> <span class="flag">--check</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports whether Scala files are <code>scalafmt</code>-formatted via the exit code. Read-only with <code>--check</code>; no files are written.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-shellcheck">
  <div class="rule-cmd"><span class="prog">shellcheck</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lints shell scripts and reports issues. Read-only static analysis.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-stylua-check">
  <div class="rule-cmd"><span class="prog">stylua</span> <span class="flag">--check</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports whether Lua files are <code>stylua</code>-formatted via the exit code. Read-only with <code>--check</code>; no files are written.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-swc">
  <div class="rule-cmd"><span class="prog">swc</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Compiles and transforms JS/TS. Writes output to the configured location.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-swiftformat-lint">
  <div class="rule-cmd"><span class="prog">swiftformat</span> <span class="flag">--lint</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports Swift formatting violations without rewriting. Read-only with <code>--lint</code>; no files are written.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-tox-version">
  <div class="rule-cmd"><span class="prog">tox</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the tox version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-tox-help">
  <div class="rule-cmd"><span class="prog">tox</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints tox usage help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-tox-l-list-listenvs">
  <div class="rule-cmd"><span class="prog">tox</span> <span class="flag">-l</span> <span class="flag">--list</span> <span class="flag">--listenvs</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the environments declared in <code>tox.ini</code> / <code>pyproject.toml</code>. Read-only; no env is run.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-ts-node-version">
  <div class="rule-cmd"><span class="prog">ts-node</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the ts-node version. Read-only; no script is run.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-ts-node-help">
  <div class="rule-cmd"><span class="prog">ts-node</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints ts-node usage help. Read-only; no script is run.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-tsc">
  <div class="rule-cmd"><span class="prog">tsc</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Type-checks TypeScript and reports errors. Emits compiled output only when configured to (<code>--noEmit</code> disables writes).</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-tsup">
  <div class="rule-cmd"><span class="prog">tsup</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Bundles TypeScript/JavaScript. Outputs to the configured dist directory.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-tsx-version">
  <div class="rule-cmd"><span class="prog">tsx</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the tsx version. Read-only; no script is run.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-tsx-help">
  <div class="rule-cmd"><span class="prog">tsx</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints tsx usage help. Read-only; no script is run.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-turbo">
  <div class="rule-cmd"><span class="prog">turbo</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs Turborepo tasks across the workspace. Executes the configured pipeline scripts.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-vite">
  <div class="rule-cmd"><span class="prog">vite</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the Vite dev server or build. A build writes to the configured dist directory.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-vitest">
  <div class="rule-cmd"><span class="prog">vitest</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the Vitest test suite and prints results. Read-only unless tests write files or <code>-u</code> updates snapshots.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-webpack">
  <div class="rule-cmd"><span class="prog">webpack</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Bundles assets to the output directory. Runs plugins and loaders that can execute build code.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-wrangler-whoami">
  <div class="rule-cmd"><span class="prog">wrangler</span> whoami</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the authenticated Cloudflare account for the current credentials. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-wrangler-version">
  <div class="rule-cmd"><span class="prog">wrangler</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the wrangler version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-wrangler-help">
  <div class="rule-cmd"><span class="prog">wrangler</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints wrangler usage help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="devtools-wrangler-tail">
  <div class="rule-cmd"><span class="prog">wrangler</span> tail</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Streams live logs from a deployed Worker. Read-only observation; does not change the deployment.</div>
</div>
</div>

<div class="rule-card">
  <header>
    <h2>Asks first · write flags</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/devtools.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/devtools.toml#ask
    </a>
    <span class="count">70 patterns</span>
  </header>

<div class="rule-row" data-decision="ask" id="devtools-ast-grep-u-update-all">
  <div class="rule-cmd"><span class="prog">ast-grep</span> <span class="flag">-U</span> <span class="flag">--update-all</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">ast-grep -U: applies the rewrite pattern across matched files. Default ast-grep is search-only; <code>-U</code>/<code>--update-all</code> writes the changes.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-autoflake-in-place-i">
  <div class="rule-cmd"><span class="prog">autoflake</span> <span class="flag">--in-place</span> <span class="flag">-i</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">autoflake --in-place: rewrites Python files to remove unused imports/variables. Default autoflake prints suggested diffs only.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-autopep8-i-in-place">
  <div class="rule-cmd"><span class="prog">autopep8</span> <span class="flag">-i</span> <span class="flag">--in-place</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formatting files in-place</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-awk">
  <div class="rule-cmd"><span class="prog">awk</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">awk program uses a shell-exec or file-write construct (system, getline, |, @, or a &gt; redirect), or reads its program from a file. Plain field/print/arithmetic awk auto-allows.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-biome-check-write-fix-fix-unsafe">
  <div class="rule-cmd"><span class="prog">biome</span> check <span class="flag">--write</span> <span class="flag">--fix</span> <span class="flag">--fix-unsafe</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Writing fixes</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-biome-format-write">
  <div class="rule-cmd"><span class="prog">biome</span> format <span class="flag">--write</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formatting files</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-black">
  <div class="rule-cmd"><span class="prog">black</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formatting files</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-buf-format">
  <div class="rule-cmd"><span class="prog">buf</span> format</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formatting files</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-clang-format-i">
  <div class="rule-cmd"><span class="prog">clang-format</span> <span class="flag">-i</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formatting files in-place</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-comby-in-place-i">
  <div class="rule-cmd"><span class="prog">comby</span> <span class="flag">-in-place</span> <span class="flag">-i</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">comby -in-place: applies the structural match-and-rewrite to the matched files. Default comby prints diffs to stdout.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-coverage-run">
  <div class="rule-cmd"><span class="prog">coverage</span> run</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">coverage run: executes the given Python script/module under coverage. Writes a <code>.coverage</code> data file in cwd.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-coverage-html">
  <div class="rule-cmd"><span class="prog">coverage</span> html</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">coverage html: writes an HTML report tree (default <code>htmlcov/</code>) from the current <code>.coverage</code> data file.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-coverage-json">
  <div class="rule-cmd"><span class="prog">coverage</span> json</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">coverage json: writes a <code>coverage.json</code> report file from the current <code>.coverage</code> data file.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-coverage-xml">
  <div class="rule-cmd"><span class="prog">coverage</span> xml</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">coverage xml: writes a <code>coverage.xml</code> (Cobertura) report file from the current <code>.coverage</code> data file.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-coverage-lcov">
  <div class="rule-cmd"><span class="prog">coverage</span> lcov</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">coverage lcov: writes a <code>coverage.lcov</code> report file from the current <code>.coverage</code> data file.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-coverage-erase">
  <div class="rule-cmd"><span class="prog">coverage</span> erase</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">coverage erase: deletes the <code>.coverage</code> data file in cwd. Pending reports cannot be regenerated without rerunning.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-coverage-combine">
  <div class="rule-cmd"><span class="prog">coverage</span> combine</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">coverage combine: merges multiple <code>.coverage.*</code> data files into a single <code>.coverage</code> file. Inputs are consumed.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-cypress-open">
  <div class="rule-cmd"><span class="prog">cypress</span> open</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">cypress open: launches the Cypress test runner GUI. Long-running until the window is closed.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-cypress-install">
  <div class="rule-cmd"><span class="prog">cypress</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">cypress install: downloads the Cypress binary to the local cache (~200MB).</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-dart-format">
  <div class="rule-cmd"><span class="prog">dart</span> format</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formatting files</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-dartfmt">
  <div class="rule-cmd"><span class="prog">dartfmt</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formatting files</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-dos2unix">
  <div class="rule-cmd"><span class="prog">dos2unix</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Converting line endings</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-elm-format">
  <div class="rule-cmd"><span class="prog">elm-format</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formatting files</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-eslint-fix">
  <div class="rule-cmd"><span class="prog">eslint</span> <span class="flag">--fix</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Auto-fixing</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-gci-write">
  <div class="rule-cmd"><span class="prog">gci</span> <span class="flag">write</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formatting imports</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-gofmt-w">
  <div class="rule-cmd"><span class="prog">gofmt</span> <span class="flag">-w</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formatting files</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-gofumpt-w">
  <div class="rule-cmd"><span class="prog">gofumpt</span> <span class="flag">-w</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formatting files</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-goimports-w">
  <div class="rule-cmd"><span class="prog">goimports</span> <span class="flag">-w</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formatting imports</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-golangci-lint-fix">
  <div class="rule-cmd"><span class="prog">golangci-lint</span> <span class="flag">--fix</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Applying lint fixes</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-grit-apply">
  <div class="rule-cmd"><span class="prog">grit</span> apply</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">grit apply: applies a Grit migration pattern to matched files. Other grit subcommands are read-only/listing operations.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-isort">
  <div class="rule-cmd"><span class="prog">isort</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Sorting imports</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-ktlint-f-format">
  <div class="rule-cmd"><span class="prog">ktlint</span> <span class="flag">-F</span> <span class="flag">--format</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formatting files</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-lefthook-install">
  <div class="rule-cmd"><span class="prog">lefthook</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">lefthook install: writes hook scripts to <code>.git/hooks/</code> per <code>lefthook.yml</code>. Subsequent git operations invoke them.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-lefthook-uninstall">
  <div class="rule-cmd"><span class="prog">lefthook</span> uninstall</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">lefthook uninstall: removes lefthook-managed hook scripts from <code>.git/hooks/</code>. Git stops invoking the configured hooks.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-lefthook-add">
  <div class="rule-cmd"><span class="prog">lefthook</span> add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">lefthook add: creates hook script files under <code>.git/hooks/</code> for the named hook. Edits the git hooks directory.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-markdownlint-fix-f">
  <div class="rule-cmd"><span class="prog">markdownlint</span> <span class="flag">--fix</span> <span class="flag">-f</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Auto-fixing markdown</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-mix-format">
  <div class="rule-cmd"><span class="prog">mix</span> format</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formatting files</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-nox">
  <div class="rule-cmd"><span class="prog">nox</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">nox: runs the configured sessions from <code>noxfile.py</code>. Each session creates/uses a virtualenv and runs arbitrary Python code per the noxfile.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-parcel-serve">
  <div class="rule-cmd"><span class="prog">parcel</span> serve</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">parcel serve: starts the Parcel dev server on a local port. Binds to localhost until interrupted.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-parcel-watch">
  <div class="rule-cmd"><span class="prog">parcel</span> watch</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">parcel watch: rebuilds the bundle on file changes. Long-running; writes output to the configured dist dir.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-patch">
  <div class="rule-cmd"><span class="prog">patch</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Applying patch (targets come from patch file content, not CLI args)</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-perltidy-b">
  <div class="rule-cmd"><span class="prog">perltidy</span> <span class="flag">-b</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formatting in-place</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-playwright-install">
  <div class="rule-cmd"><span class="prog">playwright</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">playwright install: downloads Chromium/Firefox/WebKit binaries to the Playwright cache (~300MB-1GB total).</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-playwright-codegen">
  <div class="rule-cmd"><span class="prog">playwright</span> codegen</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">playwright codegen: opens a browser and records user actions as test code. Writes the generated spec to stdout or <code>-o &lt;file&gt;</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-prettier-write-w">
  <div class="rule-cmd"><span class="prog">prettier</span> <span class="flag">--write</span> <span class="flag">-w</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Writing formatted files</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-rubocop-a-a-auto-correct-autocorrect">
  <div class="rule-cmd"><span class="prog">rubocop</span> <span class="flag">-a</span> <span class="flag">-A</span> <span class="flag">--auto-correct</span> <span class="flag">--autocorrect</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Auto-correcting</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-ruff-check-fix">
  <div class="rule-cmd"><span class="prog">ruff</span> check <span class="flag">--fix</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Auto-fixing</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-ruff-format">
  <div class="rule-cmd"><span class="prog">ruff</span> format</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formatting files</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-rustfmt">
  <div class="rule-cmd"><span class="prog">rustfmt</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formatting files</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-sad-commit">
  <div class="rule-cmd"><span class="prog">sad</span> <span class="flag">--commit</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">sad --commit: applies the proposed search-and-replace to the matched files. Default sad without <code>--commit</code> is preview-only.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-scalafmt">
  <div class="rule-cmd"><span class="prog">scalafmt</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formatting files</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-sd">
  <div class="rule-cmd"><span class="prog">sd</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">sd in-place: rewrites the given files (regex find/replace). Without file args sd is a stdin-&gt;stdout pipe; with file args it modifies in place.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-semgrep-autofix-fix">
  <div class="rule-cmd"><span class="prog">semgrep</span> <span class="flag">--autofix</span> <span class="flag">--fix</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">semgrep --autofix: applies rule-driven code rewrites to matched files. Default semgrep only reports findings.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-shfmt-w">
  <div class="rule-cmd"><span class="prog">shfmt</span> <span class="flag">-w</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formatting files</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-standardrb-a-a-auto-correct-autocorrect">
  <div class="rule-cmd"><span class="prog">standardrb</span> <span class="flag">-a</span> <span class="flag">-A</span> <span class="flag">--auto-correct</span> <span class="flag">--autocorrect</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Auto-correcting</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-stylelint-fix">
  <div class="rule-cmd"><span class="prog">stylelint</span> <span class="flag">--fix</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Auto-fixing styles</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-stylua">
  <div class="rule-cmd"><span class="prog">stylua</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formatting files</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-swiftformat">
  <div class="rule-cmd"><span class="prog">swiftformat</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formatting files</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-tox">
  <div class="rule-cmd"><span class="prog">tox</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">tox: runs the configured environments from <code>tox.ini</code> / <code>pyproject.toml</code>. Each env creates/uses a virtualenv and runs arbitrary commands per config.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-ts-node">
  <div class="rule-cmd"><span class="prog">ts-node</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">ts-node: runs the given TypeScript file under Node. The script's side effects (network, FS, child processes) execute.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-tsx">
  <div class="rule-cmd"><span class="prog">tsx</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">tsx: runs the given TypeScript file directly (Node + esbuild). The script's side effects (network, FS, child processes) execute.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-ty-add-ignore">
  <div class="rule-cmd"><span class="prog">ty</span> <span class="flag">--add-ignore</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">ty --add-ignore: inserts <code>ty: ignore</code> comments into source files at flagged diagnostics. Default ty only reports.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-unix2dos">
  <div class="rule-cmd"><span class="prog">unix2dos</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Converting line endings</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-watchexec">
  <div class="rule-cmd"><span class="prog">watchexec</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">watchexec: runs the given command whenever matching files change. The wrapped command's side effects fire on every change.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-wrangler-dev">
  <div class="rule-cmd"><span class="prog">wrangler</span> dev</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">wrangler dev: runs the Worker locally on a dev port. Long-running; binds to localhost until interrupted.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-wrangler-deploy">
  <div class="rule-cmd"><span class="prog">wrangler</span> deploy</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Cloudflare wrangler deploy: publishes the Worker live to Cloudflare. Verify env vs preview vs production; the Worker starts handling traffic immediately.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-wrangler-publish">
  <div class="rule-cmd"><span class="prog">wrangler</span> publish</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Cloudflare wrangler publish: pushes the Worker live (older form of deploy). Verify env; the Worker starts handling traffic immediately.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-wrangler-login">
  <div class="rule-cmd"><span class="prog">wrangler</span> login</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">wrangler login: starts the OAuth flow and writes Cloudflare credentials to <code>~/.wrangler</code> (or <code>~/.config/.wrangler</code>). Anyone with read access to the file gets those credentials.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-wrangler-pages">
  <div class="rule-cmd"><span class="prog">wrangler</span> pages</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">wrangler pages: Cloudflare Pages operation (deploy/dev/project). <code>pages deploy</code> publishes a site live to Cloudflare's edge.</div>
</div>
<div class="rule-row" data-decision="ask" id="devtools-yq-i-inplace">
  <div class="rule-cmd"><span class="prog">yq</span> <span class="flag">-i</span> <span class="flag">--inplace</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">yq -i: rewrites the YAML file in place per the given expression. Default yq prints to stdout; <code>-i</code>/<code>--inplace</code> writes the file.</div>
</div>
</div>

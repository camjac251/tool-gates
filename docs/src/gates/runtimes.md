<div class="gate-head">
  <p class="breadcrumb"><a href="../index.html">Gates</a> / runtimes</p>
  <h1>runtimes gate</h1>
  <div class="gate-meta">
    <span class="tag">priority <b>27</b></span>
    <span class="tag">unknown <b>ask</b></span>
    <span class="tag">covers <b>python · node · ruby · deno · php · lua · java · dotnet · swift · elixir</b></span>
  </div>

  <div class="summary" aria-label="Rule counts at a glance">
    <div class="seg-bar" role="img" aria-label="48 allow, 37 ask, 0 block">
      <div class="seg allow" style="flex: 48"></div>
      <div class="seg ask"   style="flex: 37"></div>
      <div class="seg block" style="flex: 0"></div>
    </div>
    <div class="counts">
      <span class="ca"><i></i><b>48</b> allow</span>
      <span class="cas"><i></i><b>37</b> ask</span>
      <span class="cb"><i></i><b>0</b> block</span>
    </div>
  </div>

  <p class="gate-lede">Language runtime invocations. Version and syntax-check flags are safe. Anything that executes code (inline via <code>-c</code>/<code>-e</code> or a script file) asks. No blocks at this layer; the filesystem-level floor catches the destructive cases.</p>
</div>

<div class="chips" role="group" aria-label="Filter rules by decision">
  <button class="chip all"   data-filter="all"   aria-pressed="true"><i></i>All <span class="n">85</span></button>
  <button class="chip allow" data-filter="allow" aria-pressed="false"><i></i>Allow <span class="n">48</span></button>
  <button class="chip ask"   data-filter="ask"   aria-pressed="false"><i></i>Ask <span class="n">37</span></button>
  <button class="chip block" data-filter="block" aria-pressed="false"><i></i>Block <span class="n">0</span></button>
</div>

<div class="rule-card">
  <header>
    <h2>Allowed · inspection</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/runtimes.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/runtimes.toml#allow
    </a>
    <span class="count">48 patterns</span>
  </header>

<div class="rule-row" data-decision="allow" id="runtimes-deno-version">
  <div class="rule-cmd"><span class="prog">deno</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags. Always safe.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-deno-v">
  <div class="rule-cmd"><span class="prog">deno</span> -V</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags. Always safe.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-deno-help">
  <div class="rule-cmd"><span class="prog">deno</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags. Always safe.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-deno-h">
  <div class="rule-cmd"><span class="prog">deno</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags. Always safe.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-deno-check">
  <div class="rule-cmd"><span class="prog">deno</span> check</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Deno's read-only inspection subcommands. <code>fmt --check</code> and <code>test</code> also allow.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-deno-lint">
  <div class="rule-cmd"><span class="prog">deno</span> lint</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Deno's read-only inspection subcommands. <code>fmt --check</code> and <code>test</code> also allow.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-deno-doc">
  <div class="rule-cmd"><span class="prog">deno</span> doc</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Deno's read-only inspection subcommands. <code>fmt --check</code> and <code>test</code> also allow.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-deno-info">
  <div class="rule-cmd"><span class="prog">deno</span> info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Deno's read-only inspection subcommands. <code>fmt --check</code> and <code>test</code> also allow.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-deno-types">
  <div class="rule-cmd"><span class="prog">deno</span> types</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Deno's read-only inspection subcommands. <code>fmt --check</code> and <code>test</code> also allow.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-deno-completions">
  <div class="rule-cmd"><span class="prog">deno</span> completions</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints shell completion script for <code>deno</code> to stdout. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-deno-help-2">
  <div class="rule-cmd"><span class="prog">deno</span> help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints <code>deno</code> help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-deno-fmt-check">
  <div class="rule-cmd"><span class="prog">deno</span> fmt <span class="flag">--check</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Deno's read-only inspection subcommands. <code>fmt --check</code> and <code>test</code> also allow.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-deno-test">
  <div class="rule-cmd"><span class="prog">deno</span> test</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the Deno test suite. Executes test files in the default sandbox; no files written and no global installs.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-deno-bench">
  <div class="rule-cmd"><span class="prog">deno</span> bench</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs Deno benchmarks. Executes bench files in the default sandbox; no files written and no global installs.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-dotnet-version-info-list-sdks-list-runtimes">
  <div class="rule-cmd"><span class="prog">dotnet</span> <span class="flag">--version</span> <span class="flag">--info</span> <span class="flag">--list-sdks</span> <span class="flag">--list-runtimes</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags. Always safe.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-dotnet-help">
  <div class="rule-cmd"><span class="prog">dotnet</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags. Always safe.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-dotnet-h">
  <div class="rule-cmd"><span class="prog">dotnet</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags. Always safe.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-dotnet-help-2">
  <div class="rule-cmd"><span class="prog">dotnet</span> help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints <code>dotnet</code> help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-dotnet-build">
  <div class="rule-cmd"><span class="prog">dotnet</span> build</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Local build, test, and dependency restore. Outputs land under <code>bin/</code> and <code>obj/</code>.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-dotnet-test">
  <div class="rule-cmd"><span class="prog">dotnet</span> test</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Local build, test, and dependency restore. Outputs land under <code>bin/</code> and <code>obj/</code>.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-dotnet-run">
  <div class="rule-cmd"><span class="prog">dotnet</span> run</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Local build, test, and dependency restore. Outputs land under <code>bin/</code> and <code>obj/</code>.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-dotnet-clean">
  <div class="rule-cmd"><span class="prog">dotnet</span> clean</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Deletes build outputs under <code>bin/</code> and <code>obj/</code> for the project. Local cleanup only.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-dotnet-restore">
  <div class="rule-cmd"><span class="prog">dotnet</span> restore</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Local build, test, and dependency restore. Outputs land under <code>bin/</code> and <code>obj/</code>.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-dotnet-list">
  <div class="rule-cmd"><span class="prog">dotnet</span> list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists project references or installed packages. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-dotnet-sln">
  <div class="rule-cmd"><span class="prog">dotnet</span> sln</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspects or edits the solution file's project list. Reads with no args; <code>add</code>/<code>remove</code> rewrite the <code>.sln</code>.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-dotnet-format-check-verify-no-changes">
  <div class="rule-cmd"><span class="prog">dotnet</span> format <span class="flag">--check</span> <span class="flag">--verify-no-changes</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports formatting issues without writing. <code>--check</code> and <code>--verify-no-changes</code> make it read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-elixir-version-v">
  <div class="rule-cmd"><span class="prog">elixir</span> <span class="flag">--version</span> <span class="flag">-v</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags. Always safe.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-elixir-help-h">
  <div class="rule-cmd"><span class="prog">elixir</span> <span class="flag">--help</span> <span class="flag">-h</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags. Always safe.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-iex-version-v">
  <div class="rule-cmd"><span class="prog">iex</span> <span class="flag">--version</span> <span class="flag">-v</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags. Always safe.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-java-version-version-help-help-h">
  <div class="rule-cmd"><span class="prog">java</span> <span class="flag">--version</span> <span class="flag">-version</span> <span class="flag">--help</span> <span class="flag">-help</span> <span class="flag">-h</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags. Always safe.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-javac-version-version-help-help">
  <div class="rule-cmd"><span class="prog">javac</span> <span class="flag">--version</span> <span class="flag">-version</span> <span class="flag">--help</span> <span class="flag">-help</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags. Always safe.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-lua-v">
  <div class="rule-cmd"><span class="prog">lua</span> <span class="flag">-v</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags. Always safe.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-node-version-v">
  <div class="rule-cmd"><span class="prog">node</span> <span class="flag">--version</span> <span class="flag">-v</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags. Always safe.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-node-help-h">
  <div class="rule-cmd"><span class="prog">node</span> <span class="flag">--help</span> <span class="flag">-h</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags. Always safe.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-node-c-check">
  <div class="rule-cmd"><span class="prog">node</span> <span class="flag">-c</span> <span class="flag">--check</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Syntax check without execution.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-php-version-v">
  <div class="rule-cmd"><span class="prog">php</span> <span class="flag">--version</span> <span class="flag">-v</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags. Always safe.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-php-help-h">
  <div class="rule-cmd"><span class="prog">php</span> <span class="flag">--help</span> <span class="flag">-h</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags. Always safe.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-php-info-i">
  <div class="rule-cmd"><span class="prog">php</span> <span class="flag">--info</span> <span class="flag">-i</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints PHP configuration (<code>phpinfo</code>). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-php-l-syntax-check">
  <div class="rule-cmd"><span class="prog">php</span> <span class="flag">-l</span> <span class="flag">--syntax-check</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Per-language syntax checks. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-php-m">
  <div class="rule-cmd"><span class="prog">php</span> <span class="flag">-m</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists compiled-in PHP modules. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-python3-version-v-vv">
  <div class="rule-cmd"><span class="prog">python3</span> <span class="flag">--version</span> <span class="flag">-V</span> <span class="flag">-VV</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags. Always safe.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-python3-help-h">
  <div class="rule-cmd"><span class="prog">python3</span> <span class="flag">--help</span> <span class="flag">-h</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags. Always safe.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-ruby-version-v">
  <div class="rule-cmd"><span class="prog">ruby</span> <span class="flag">--version</span> <span class="flag">-v</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags. Always safe.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-ruby-help-h">
  <div class="rule-cmd"><span class="prog">ruby</span> <span class="flag">--help</span> <span class="flag">-h</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags. Always safe.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-ruby-c">
  <div class="rule-cmd"><span class="prog">ruby</span> <span class="flag">-c</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Per-language syntax checks. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-swift-version-help-h">
  <div class="rule-cmd"><span class="prog">swift</span> <span class="flag">--version</span> <span class="flag">--help</span> <span class="flag">-h</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Info flags. Always safe.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-swift-build">
  <div class="rule-cmd"><span class="prog">swift</span> build</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Compiles the Swift package. Outputs land under <code>.build/</code>; no code is executed.</div>
</div>
<div class="rule-row" data-decision="allow" id="runtimes-swift-test">
  <div class="rule-cmd"><span class="prog">swift</span> test</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the Swift package test suite. Builds and executes tests locally; outputs land under <code>.build/</code>.</div>
</div>
</div>

<div class="rule-card">
  <header>
    <h2>Asks first · code execution</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/runtimes.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/runtimes.toml#ask
    </a>
    <span class="count">37 patterns</span>
  </header>

<div class="rule-row" data-decision="ask" id="runtimes-deno-run">
  <div class="rule-cmd"><span class="prog">deno</span> run</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs a Deno script. Permissions are sandboxed by default; flags like <code>--allow-all</code> / <code>--allow-net</code> / <code>--allow-write</code> widen access.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-deno-serve">
  <div class="rule-cmd"><span class="prog">deno</span> serve</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Starts a Deno HTTP server. Binds a port (default 8000) and listens for incoming requests.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-deno-fmt">
  <div class="rule-cmd"><span class="prog">deno</span> fmt</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formats source files in place. Rewrites every matching file under the target paths.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-deno-compile">
  <div class="rule-cmd"><span class="prog">deno</span> compile</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Produces a standalone executable for the script. Writes a binary that embeds the Deno runtime and the script's modules.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-deno-install">
  <div class="rule-cmd"><span class="prog">deno</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installs a script as a global executable on PATH, or installs project dependencies. The global form writes to the Deno install root.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-deno-uninstall">
  <div class="rule-cmd"><span class="prog">deno</span> uninstall</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes a Deno-installed global executable from the Deno install root.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-deno-task">
  <div class="rule-cmd"><span class="prog">deno</span> task</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs a named task from <code>deno.json</code>. Executes the task's shell command line; treat as running that command.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-deno-upgrade">
  <div class="rule-cmd"><span class="prog">deno</span> upgrade</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Replaces the Deno binary with a newer release. Modifies the installed <code>deno</code> executable on PATH.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-deno-add">
  <div class="rule-cmd"><span class="prog">deno</span> add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adds a dependency to <code>deno.json</code> imports. Network fetch on next resolve.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-deno-remove">
  <div class="rule-cmd"><span class="prog">deno</span> remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes a dependency from <code>deno.json</code> imports.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-deno-publish">
  <div class="rule-cmd"><span class="prog">deno</span> publish</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Uploads the module to JSR. Public publish is irreversible: the version number cannot be reused.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-dotnet-publish">
  <div class="rule-cmd"><span class="prog">dotnet</span> publish</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Publishing application</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-dotnet-new">
  <div class="rule-cmd"><span class="prog">dotnet</span> new</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating project</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-dotnet-add">
  <div class="rule-cmd"><span class="prog">dotnet</span> add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adding reference/package</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-dotnet-remove">
  <div class="rule-cmd"><span class="prog">dotnet</span> remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removing reference/package</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-dotnet-nuget">
  <div class="rule-cmd"><span class="prog">dotnet</span> nuget</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">NuGet operation</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-dotnet-tool">
  <div class="rule-cmd"><span class="prog">dotnet</span> tool</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Tool management</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-dotnet-pack">
  <div class="rule-cmd"><span class="prog">dotnet</span> pack</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating NuGet package</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-dotnet-format">
  <div class="rule-cmd"><span class="prog">dotnet</span> format</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formatting code</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-elixir-e">
  <div class="rule-cmd"><span class="prog">elixir</span> <span class="flag">-e</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Executes inline Elixir via <code>-e</code>. Treat the code as an inline script.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-elixir">
  <div class="rule-cmd"><span class="prog">elixir</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs an Elixir script file (<code>.exs</code> / <code>.ex</code>). Full Elixir and Erlang stdlib access.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-iex">
  <div class="rule-cmd"><span class="prog">iex</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Starts the interactive Elixir REPL. Each input is evaluated with full Elixir and Erlang stdlib access.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-java">
  <div class="rule-cmd"><span class="prog">java</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs a Java class, JAR, or single source file. Full JVM access; classpath-loaded code runs unsandboxed.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-javac">
  <div class="rule-cmd"><span class="prog">javac</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compiles Java source files into <code>.class</code> bytecode. Writes output to the configured destination directory.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-lua-e">
  <div class="rule-cmd"><span class="prog">lua</span> <span class="flag">-e</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Executes inline Lua via <code>-e</code>. Treat the code as an inline script.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-lua">
  <div class="rule-cmd"><span class="prog">lua</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs a Lua script file. Full Lua stdlib access including <code>io</code>, <code>os</code>, and loaded C modules.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-node-e-eval-p-print">
  <div class="rule-cmd"><span class="prog">node</span> <span class="flag">-e</span> <span class="flag">--eval</span> <span class="flag">-p</span> <span class="flag">--print</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Executes inline JavaScript via <code>-e</code>. Treat the code as an inline script; full Node API access.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-node">
  <div class="rule-cmd"><span class="prog">node</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs a Node.js script file. Full Node API access including filesystem, network, and child processes.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-php-r">
  <div class="rule-cmd"><span class="prog">php</span> <span class="flag">-r</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Executes inline PHP via <code>-r</code>. Treat the code as an inline script.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-php">
  <div class="rule-cmd"><span class="prog">php</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs a PHP script file. Full PHP API access including filesystem, network, and shell execution.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-python3-c">
  <div class="rule-cmd"><span class="prog">python3</span> <span class="flag">-c</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Executes inline Python via <code>-c</code>. Treat the code as an inline script; can import any installed module.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-python3-m">
  <div class="rule-cmd"><span class="prog">python3</span> <span class="flag">-m</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs an installed Python module via <code>-m &lt;module&gt;</code>. Module code runs with the current interpreter; inherits the active venv if one is on PATH.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-python3">
  <div class="rule-cmd"><span class="prog">python3</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs a Python script file. The script runs with the current interpreter; inherits the active venv if one is on PATH.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-ruby-e">
  <div class="rule-cmd"><span class="prog">ruby</span> <span class="flag">-e</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Executes inline Ruby via <code>-e</code>. Treat the code as an inline script; full stdlib access.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-ruby">
  <div class="rule-cmd"><span class="prog">ruby</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs a Ruby script file. Full stdlib access including filesystem, network, and child processes.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-swift-run">
  <div class="rule-cmd"><span class="prog">swift</span> run</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Builds and runs the Swift executable target in the current package. Full Swift runtime access.</div>
</div>
<div class="rule-row" data-decision="ask" id="runtimes-swift-package">
  <div class="rule-cmd"><span class="prog">swift</span> package</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Manages the Swift package: init, update, resolve, generate-xcodeproj, clean. Mutates <code>Package.resolved</code> and the build cache.</div>
</div>
</div>

<nav class="breadcrumb" aria-label="Breadcrumb">
  <ol>
    <li><a href="index.html">tool-gates</a></li>
    <li>Reference</li>
    <li aria-current="page">Security floor</li>
  </ol>
</nav>
<h1>Security floor</h1>
<p class="page-lede">Every <code>block</code> rule and every <code>warn = true</code> rule across all 13 gates, on one page. The hard-deny floor fires regardless of <code>settings.json</code>; warn rules ask first but are marked dangerous-but-recoverable. The raw-string catalog runs against top-level commands and executable strings inside supported local shell wrappers, including shells invoked through <code>xargs</code>. Generated from <code>rules/*.toml</code>; authoritative for security review.</p>

<div class="rule-card">
  <header>
    <h2>Raw-string floor · matched before parsing</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/security.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/security.toml
    </a>
    <span class="count">34 patterns</span>
  </header>

<div class="rule-row" data-decision="ask" id="floor-pipe-bash">
  <div class="rule-cmd"><span class="prog">pipe-bash</span> <span class="flag">hard-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Piping to bash runs whatever upstream returns, with no chance to inspect. Save the output to a file first, review it, then run.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-pipe-sh">
  <div class="rule-cmd"><span class="prog">pipe-sh</span> <span class="flag">hard-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Piping to sh runs whatever upstream returns, with no chance to inspect. Save the output to a file first, review it, then run.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-pipe-zsh">
  <div class="rule-cmd"><span class="prog">pipe-zsh</span> <span class="flag">hard-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Piping to zsh runs whatever upstream returns, with no chance to inspect. Save the output to a file first, review it, then run.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-pipe-sudo">
  <div class="rule-cmd"><span class="prog">pipe-sudo</span> <span class="flag">hard-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Piping to sudo elevates upstream output. Same risk as <code>curl | bash</code> with full privileges; save and review the upstream content first.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-pipe-doas">
  <div class="rule-cmd"><span class="prog">pipe-doas</span> <span class="flag">hard-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Piping to doas elevates upstream output. Same risk as <code>curl | bash</code> with full privileges; save and review the upstream content first.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-pipe-python">
  <div class="rule-cmd"><span class="prog">pipe-python</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Piping to python runs upstream as a script. Save to a file first, review it, then run.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-pipe-perl">
  <div class="rule-cmd"><span class="prog">pipe-perl</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Piping to perl runs upstream as a script. Save to a file first, review it, then run.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-pipe-ruby">
  <div class="rule-cmd"><span class="prog">pipe-ruby</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Piping to ruby runs upstream as a script. Save to a file first, review it, then run.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-pipe-node">
  <div class="rule-cmd"><span class="prog">pipe-node</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Piping to node runs upstream as a script. Save to a file first, review it, then run.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-eval">
  <div class="rule-cmd"><span class="prog">eval</span> <span class="flag">hard-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason"><code>eval</code> runs arbitrary code constructed from variables. Prefer parameter expansion (<code>${var}</code>), array indexing, or <code>case</code> statements; if eval is truly needed, validate the input first.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-source">
  <div class="rule-cmd"><span class="prog">source</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason"><code>source</code> runs the file in the current shell and inherits its <code>export</code>s, aliases, and <code>cd</code>s. Verify the file's contents before approving.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-dot-source">
  <div class="rule-cmd"><span class="prog">dot-source</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason"><code>.</code> is equivalent to <code>source</code>: runs the file in the current shell and inherits its <code>export</code>s and aliases. Verify the file's contents before approving.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-xargs-rm">
  <div class="rule-cmd"><span class="prog">xargs-rm</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">xargs piping to <code>rm</code> runs it once per input line. Verify the upstream filter; mistakes cascade.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-xargs-mv">
  <div class="rule-cmd"><span class="prog">xargs-mv</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">xargs piping to <code>mv</code> runs it once per input line. Verify the upstream filter; mistakes cascade.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-xargs-cp">
  <div class="rule-cmd"><span class="prog">xargs-cp</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">xargs piping to <code>cp</code> runs it once per input line. Verify the upstream filter; mistakes cascade.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-xargs-chmod">
  <div class="rule-cmd"><span class="prog">xargs-chmod</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">xargs piping to <code>chmod</code> runs it once per input line. Verify the upstream filter; mistakes cascade.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-xargs-chown">
  <div class="rule-cmd"><span class="prog">xargs-chown</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">xargs piping to <code>chown</code> runs it once per input line. Verify the upstream filter; mistakes cascade.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-xargs-dd">
  <div class="rule-cmd"><span class="prog">xargs-dd</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">xargs piping to <code>dd</code> runs it once per input line. Verify the upstream filter; mistakes cascade.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-xargs-shred">
  <div class="rule-cmd"><span class="prog">xargs-shred</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">xargs piping to <code>shred</code> runs it once per input line. Verify the upstream filter; mistakes cascade.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-xargs-kubectl-delete">
  <div class="rule-cmd"><span class="prog">xargs-kubectl-delete</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">xargs piping to <code>kubectl delete</code> runs delete once per input line. Verify the upstream filter; mistakes cascade across many resources.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-find-delete">
  <div class="rule-cmd"><span class="prog">find-delete</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason"><code>find -delete</code> removes every match. Run without <code>-delete</code> first to preview which paths would be removed.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-find-exec">
  <div class="rule-cmd"><span class="prog">find-exec</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason"><code>find -exec</code> runs a command per match. Verify both the find filter and the command body; mistakes cascade across every match.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-find-fwrite">
  <div class="rule-cmd"><span class="prog">find-fwrite</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason"><code>find -fprintf</code>/<code>-fprint</code>/<code>-fls</code> writes matched output to a file, overwriting it. Verify the target path.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-fd-exec">
  <div class="rule-cmd"><span class="prog">fd-exec</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">fd executing <code>rm</code>/<code>mv</code>/<code>chmod</code>/<code>chown</code>/<code>dd</code>/<code>shred</code> per match via -x/--exec. Verify the fd filter first (run without -x); mistakes cascade across every match.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-rg-exec">
  <div class="rule-cmd"><span class="prog">rg-exec</span> <span class="flag">hard-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">ripgrep <code>--pre</code>/<code>--pre-glob</code>/<code>--hostname-bin</code> run an external program (a per-file preprocessor or a hostname helper), i.e. arbitrary code execution. Run that program directly and inspect it first.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-sort-output">
  <div class="rule-cmd"><span class="prog">sort-output</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason"><code>sort -o</code>/<code>--output</code> overwrites the target file without warning, and the target can be the input file itself. Verify the path.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-pg-dump-file">
  <div class="rule-cmd"><span class="prog">pg-dump-file</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason"><code>pg_dump -f</code>/<code>--file</code> writes the dump to a file and overwrites it. Omit <code>-f</code> to send the dump to stdout, or verify the path.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-gitleaks-report">
  <div class="rule-cmd"><span class="prog">gitleaks-report</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason"><code>gitleaks -r</code>/<code>--report-path</code> writes a report file to the given path, overwriting it. Verify the destination.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-unrar-extract">
  <div class="rule-cmd"><span class="prog">unrar-extract</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason"><code>unrar x</code>/<code>e</code> extracts archive contents to disk and can overwrite files. Use <code>unrar l</code> to list without extracting, or verify the destination.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-net-mutate">
  <div class="rule-cmd"><span class="prog">net-mutate</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Network configuration change (<code>ip/route ... add|del|set</code>, <code>ifconfig ... up|down</code>, <code>arp -d|-s</code>). Verify the interface and values; routing and interface changes can disrupt connectivity.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-dollar-subst">
  <div class="rule-cmd"><span class="prog">dollar-subst</span> <span class="flag">hard-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason"><code>$(...)</code> command substitution contains a dangerous inner command (<code>…</code>). It runs and injects its output into the outer command, so the destructive call executes even when nested. Run it separately first, then use the literal result.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-backtick-subst">
  <div class="rule-cmd"><span class="prog">backtick-subst</span> <span class="flag">hard-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Backtick substitution contains a dangerous inner command (<code>…</code>). It runs and injects its output into the outer command, so the destructive call executes even when nested. Run it separately first, then use the literal result. Prefer <code>$(...)</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-leading-semicolon">
  <div class="rule-cmd"><span class="prog">leading-semicolon</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Command starts with <code>;</code>. Usually a paste artifact or shell-injection attempt; review the full command before approving.</div>
</div>
<div class="rule-row" data-decision="ask" id="floor-redirect">
  <div class="rule-cmd"><span class="prog">redirect</span> <span class="flag">soft-ask</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Output redirection (<code>&gt;</code>, <code>&gt;&gt;</code>, <code>tee</code>) writes to a file. Verify the target path; <code>&gt;</code> overwrites without warning.</div>
</div>
</div>

<div class="rule-card">
  <header>
    <h2>Hard blocks · denied without prompting</h2>
    <a href="https://github.com/camjac251/tool-gates/tree/main/rules" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/*.toml#block
    </a>
    <span class="count">49 patterns</span>
  </header>

<div class="rule-row" data-decision="block" id="cloud-aws-iam-delete-user">
  <div class="rule-cmd"><span class="rule-gate">cloud</span><span class="prog">aws</span> iam delete-user</div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Blocked: <code>aws iam delete-user</code> removes an IAM identity. Detach policies and rotate access keys via individual commands instead.</div>
</div>
<div class="rule-row" data-decision="block" id="cloud-aws-organizations-delete">
  <div class="rule-cmd"><span class="rule-gate">cloud</span><span class="prog">aws</span> organizations delete</div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Blocked: <code>aws organizations delete-*</code> removes organization-level entities (accounts, OUs, policies). Effects span the whole org and are hard to reverse.</div>
</div>
<div class="rule-row" data-decision="block" id="cloud-kubectl-delete-namespace-kube-system">
  <div class="rule-cmd"><span class="rule-gate">cloud</span><span class="prog">kubectl</span> delete namespace kube-system</div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Refusing to delete the <code>kube-system</code> namespace. It hosts core cluster services; deleting it breaks the cluster.</div>
</div>
<div class="rule-row" data-decision="block" id="cloud-kubectl-delete-ns-kube-system">
  <div class="rule-cmd"><span class="rule-gate">cloud</span><span class="prog">kubectl</span> delete ns kube-system</div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Refusing to delete the <code>kube-system</code> namespace. It hosts core cluster services; deleting it breaks the cluster.</div>
</div>
<div class="rule-row" data-decision="block" id="filesystem-rm">
  <div class="rule-cmd"><span class="rule-gate">filesystem</span><span class="prog">rm</span> <span class="flag">/</span> <span class="flag">/*</span> <span class="flag">~/</span> <span class="flag">~/*</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason"><code>rm</code> against <code>/</code> or <code>~/</code> blocked: would recursively delete the system or home tree. No legitimate use in an agent workflow.</div>
</div>
<div class="rule-row" data-decision="block" id="filesystem-rm-rf">
  <div class="rule-cmd"><span class="rule-gate">filesystem</span><span class="prog">rm</span> -rf /</div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason"><code>rm -rf /</code> blocked: would recursively delete the entire root filesystem.</div>
</div>
<div class="rule-row" data-decision="block" id="filesystem-rm-rf-2">
  <div class="rule-cmd"><span class="rule-gate">filesystem</span><span class="prog">rm</span> -rf /*</div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason"><code>rm -rf /*</code> blocked: would recursively delete every top-level directory under root.</div>
</div>
<div class="rule-row" data-decision="block" id="filesystem-rm-rf-3">
  <div class="rule-cmd"><span class="rule-gate">filesystem</span><span class="prog">rm</span> -rf ~</div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason"><code>rm -rf ~</code> blocked: would recursively delete the user's home directory.</div>
</div>
<div class="rule-row" data-decision="block" id="filesystem-rm-fr">
  <div class="rule-cmd"><span class="rule-gate">filesystem</span><span class="prog">rm</span> -fr /</div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason"><code>rm -fr /</code> blocked: would recursively delete the entire root filesystem.</div>
</div>
<div class="rule-row" data-decision="block" id="filesystem-rm-fr-2">
  <div class="rule-cmd"><span class="rule-gate">filesystem</span><span class="prog">rm</span> -fr ~</div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason"><code>rm -fr ~</code> blocked: would recursively delete the user's home directory.</div>
</div>
<div class="rule-row" data-decision="block" id="gh-repo-delete">
  <div class="rule-cmd"><span class="rule-gate">gh</span><span class="prog">gh</span> repo delete</div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Deletes the repository on GitHub. Irreversible: history, issues, PRs, releases, and forks-from-this-repo are removed. Blocked unconditionally.</div>
</div>
<div class="rule-row" data-decision="block" id="gh-auth-logout">
  <div class="rule-cmd"><span class="rule-gate">gh</span><span class="prog">gh</span> auth logout</div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Logs out the gh CLI from GitHub. The agent has no way to re-authenticate without user interaction. Blocked unconditionally.</div>
</div>
<div class="rule-row" data-decision="block" id="network-nc-e">
  <div class="rule-cmd"><span class="rule-gate">network</span><span class="prog">nc</span> <span class="flag">-e</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">netcat <code>-e</code> blocked: connects a remote process to a shell on this host (classic reverse shell). No legitimate use in an agent workflow.</div>
</div>
<div class="rule-row" data-decision="block" id="system-chattr">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">chattr</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">File attribute change blocked: agent has no authority to change extended file attributes. Misconfigured attributes can render files unmodifiable. Ask the user to run chattr themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-chsh">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">chsh</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Shell change blocked: agent has no authority to change a user's login shell. Ask the user to run chsh themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-dd">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">dd</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Low-level disk operation blocked: agent has no authority to run raw block-device writes. The wrong destination overwrites a disk without warning. Ask the user to run dd themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-fdisk">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">fdisk</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Disk partitioning blocked: agent has no authority to repartition disks. Mistakes here destroy data permanently. Ask the user to run partitioning themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-firewall-cmd">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">firewall-cmd</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Firewall modification blocked: agent has no authority to modify firewall rules. Misconfigured rules can lock the user out of the system. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-gdisk">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">gdisk</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Disk partitioning blocked: agent has no authority to repartition disks. Mistakes here destroy data permanently. Ask the user to run partitioning themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-grub-install">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">grub-install</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Bootloader modification blocked: agent has no authority to modify the bootloader. A bad bootloader leaves the system unbootable. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-halt">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">halt</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">System power command blocked: agent has no authority to shut down or reboot the machine. If genuinely needed, ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-hdparm">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">hdparm</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Disk parameters blocked: agent has no authority to change disk-firmware parameters. Wrong values can brick drives. Ask the user to run hdparm themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-init">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">init</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">System power command blocked: agent has no authority to shut down or reboot the machine. If genuinely needed, ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-insmod">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">insmod</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Kernel module loading blocked: agent has no authority to load kernel modules. Module changes affect the entire running kernel. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-iptables">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">iptables</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Firewall modification blocked: agent has no authority to modify firewall rules. Misconfigured rules can lock the user out of the system. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-lvremove">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">lvremove</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">LVM management blocked: agent has no authority to remove physical volumes, volume groups, or logical volumes. Removal is irreversible and can destroy mounted filesystems on top of the LVM stack. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-mke2fs">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">mke2fs</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Filesystem creation blocked: agent has no authority to format filesystems. The wrong target erases data permanently. Ask the user to run mke2fs themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-mkfs">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">mkfs</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Disk partitioning blocked: agent has no authority to repartition disks. Mistakes here destroy data permanently. Ask the user to run partitioning themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-mkswap">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">mkswap</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Swap creation blocked: agent has no authority to create swap areas on devices. The wrong target overwrites a device. Ask the user to run mkswap themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-modprobe">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">modprobe</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Kernel module loading blocked: agent has no authority to load kernel modules. Module changes affect the entire running kernel. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-parted">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">parted</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Disk partitioning blocked: agent has no authority to repartition disks. Mistakes here destroy data permanently. Ask the user to run partitioning themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-passwd">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">passwd</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Password change blocked: agent has no authority to change account passwords. Ask the user to run passwd themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-poweroff">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">poweroff</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">System power command blocked: agent has no authority to shut down or reboot the machine. If genuinely needed, ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-pvremove">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">pvremove</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">LVM management blocked: agent has no authority to remove physical volumes, volume groups, or logical volumes. Removal is irreversible and can destroy mounted filesystems on top of the LVM stack. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-reboot">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">reboot</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">System power command blocked: agent has no authority to shut down or reboot the machine. If genuinely needed, ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-rmmod">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">rmmod</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Kernel module removal blocked: agent has no authority to unload kernel modules. Removal can destabilize the running kernel. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-shred">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">shred</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Secure delete blocked: agent has no authority to wipe files irreversibly. Ask the user to run shred themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-shutdown">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">shutdown</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">System power command blocked: agent has no authority to shut down or reboot the machine. If genuinely needed, ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-swapoff">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">swapoff</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Swap management blocked: agent has no authority to enable or disable swap. Changes affect virtual memory behavior system-wide and can trigger OOM kills if swap is removed under load. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-swapon">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">swapon</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Swap management blocked: agent has no authority to enable or disable swap. Changes affect virtual memory behavior system-wide and can trigger OOM kills if swap is removed under load. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-ufw">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">ufw</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Firewall modification blocked: agent has no authority to modify firewall rules. Misconfigured rules can lock the user out of the system. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-umount">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">umount</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Unmounting blocked: agent has no authority to unmount filesystems. Could disrupt running processes or system services depending on what's mounted. Ask the user to run umount themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-update-grub">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">update-grub</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Bootloader modification blocked: agent has no authority to modify the bootloader. A bad bootloader leaves the system unbootable. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-useradd">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">useradd</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">User management blocked: agent has no authority to create, delete, or modify user accounts. Account changes affect login and file ownership system-wide. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-userdel">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">userdel</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">User management blocked: agent has no authority to create, delete, or modify user accounts. Account changes affect login and file ownership system-wide. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-usermod">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">usermod</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">User management blocked: agent has no authority to create, delete, or modify user accounts. Account changes affect login and file ownership system-wide. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-vgremove">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">vgremove</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">LVM management blocked: agent has no authority to remove physical volumes, volume groups, or logical volumes. Removal is irreversible and can destroy mounted filesystems on top of the LVM stack. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-wipe">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">wipe</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Secure wipe blocked: agent has no authority to wipe devices irreversibly. Ask the user to run wipe themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-wipefs">
  <div class="rule-cmd"><span class="rule-gate">system</span><span class="prog">wipefs</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Filesystem wipe blocked: agent has no authority to wipe filesystem signatures. The wrong target destroys the partition table. Ask the user to run wipefs themselves.</div>
</div>
</div>

<div class="rule-card">
  <header>
    <h2>Warn rules · dangerous but recoverable</h2>
    <a href="https://github.com/camjac251/tool-gates/tree/main/rules" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      warn = true
    </a>
    <span class="count">5 patterns</span>
  </header>

<div class="rule-row" data-decision="ask" id="beads-bd-admin-reset">
  <div class="rule-cmd"><span class="rule-gate">beads</span><span class="prog">bd</span> admin reset</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span><span class="warn-tag" title="warn = true in source TOML">warn</span></div>
  <div class="rule-reason">Resets the beads database. Drops all issues, history, and local state. Cannot be undone without a backup or remote sync.</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-reset">
  <div class="rule-cmd"><span class="rule-gate">beads</span><span class="prog">bd</span> reset</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span><span class="warn-tag" title="warn = true in source TOML">warn</span></div>
  <div class="rule-reason">Resets the beads database. Drops all issues, history, and local state. Cannot be undone without a backup or remote sync.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-push-force-f">
  <div class="rule-cmd"><span class="rule-gate">git</span><span class="prog">git</span> push <span class="flag">--force</span> <span class="flag">-f</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span><span class="warn-tag" title="warn = true in source TOML">warn</span></div>
  <div class="rule-reason">Force push overwrites upstream history. Safer: <code>--force-with-lease</code> fails if the remote moved.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-reset-hard">
  <div class="rule-cmd"><span class="rule-gate">git</span><span class="prog">git</span> reset <span class="flag">--hard</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span><span class="warn-tag" title="warn = true in source TOML">warn</span></div>
  <div class="rule-reason">Hard reset discards uncommitted changes in the working tree and index. Safer: <code>git stash</code> first, or <code>git reset --soft</code> to keep changes staged.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-clean-fd-fdx-f">
  <div class="rule-cmd"><span class="rule-gate">git</span><span class="prog">git</span> clean <span class="flag">-fd</span> <span class="flag">-fdx</span> <span class="flag">-f</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span><span class="warn-tag" title="warn = true in source TOML">warn</span></div>
  <div class="rule-reason">Permanently deletes untracked files. Preview with <code>-n</code> (dry run) first; deletions cannot be undone.</div>
</div>
</div>

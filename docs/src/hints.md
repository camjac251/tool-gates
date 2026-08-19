<nav class="breadcrumb" aria-label="Breadcrumb">
  <ol>
    <li><a href="index.html">tool-gates</a></li>
    <li>Reference</li>
    <li aria-current="page">Modern CLI hints</li>
  </ol>
</nav>
<h1 id="hints-h1">Modern CLI hints</h1>
<p class="page-lede">When a command reaches for a legacy tool that has a sharper modern alternative, tool-gates may attach a one-line suggestion via <code>additionalContext</code>. Hints never determine the permission decision; applicable allow and ask responses can carry them. They fire only when the modern tool is installed on this machine. Repeated suggestions are deduplicated, and each response carries at most three unique hints. Code-search guidance names capabilities rather than project-scoped tools that may not be loaded. Generated from the hint catalog in <code>src/hints.rs</code>.</p>

<div class="hints">
  <header>
    <h2>Legacy &rarr; modern</h2>
    <span class="note">7-day cache · <code>tool-gates --tools-status</code> to inspect</span>
  </header>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>cat</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> bat</div>
  <div class="why"><b>Tip from tool-gates:</b> Line-numbered, syntax-highlighted output; precise follow-up edits.</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>less</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> bat</div>
  <div class="why"><b>Tip from tool-gates:</b> Paged, line-numbered viewing without a separate pager.</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>more</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> bat</div>
  <div class="why"><b>Tip from tool-gates:</b> Paged, line-numbered viewing without a separate pager.</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>head -n N &lt;file&gt;</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> bat -r :N</div>
  <div class="why"><b>Tip from tool-gates:</b> Arbitrary line ranges, not just first-N, with line numbers.</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>tail -n N &lt;file&gt;</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> bat -r -N:</div>
  <div class="why"><b>Tip from tool-gates:</b> Arbitrary line ranges, not just last-N, with line numbers.</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>grep</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> rg</div>
  <div class="why"><b>Tip from tool-gates:</b> Recursive by default, respects .gitignore, faster on large trees.</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>sg</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> ast-grep</div>
  <div class="why"><b>Tip from tool-gates:</b> Uses the supported executable name and avoids collision with the unrelated system `sg` group command.</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>ag / ack</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> rg</div>
  <div class="why"><b>Tip from tool-gates:</b> Faster with a similar interface.</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>find</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> fd</div>
  <div class="why"><b>Tip from tool-gates:</b> Shorter syntax, .gitignore-aware, faster.</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>rg/grep on PDFs, office docs, archives</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> rga</div>
  <div class="why"><b>Tip from tool-gates:</b> Searches inside PDF, docx, epub, and archives; plain rg/grep sees only bytes there.</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>sed s/.../.../</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> sd</div>
  <div class="why"><b>Tip from tool-gates:</b> Plain find/replace on non-code text, no s/.../.../g escaping.</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>awk '{print $N}'</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> choose</div>
  <div class="why"><b>Tip from tool-gates:</b> Field selection routes to choose; column sums to jq; line counts to rg -c; byte math to numbat; positional row/field to jc.</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>wc -l &lt;file&gt;</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> rg -c '.'</div>
  <div class="why"><b>Tip from tool-gates:</b> Counts non-blank lines without a separate utility (piped wc -l is fine).</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>curl &lt;github-url&gt;</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> gh api</div>
  <div class="why"><b>Tip from tool-gates:</b> Preserves auth, rate limits, and private-repo access.</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>wget &lt;github-url&gt;</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> gh api</div>
  <div class="why"><b>Tip from tool-gates:</b> Preserves auth, rate limits, and private-repo access.</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>xxd / hexdump</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> hexyl</div>
  <div class="why"><b>Tip from tool-gates:</b> Colored, readable hex output.</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>cloc</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> tokei</div>
  <div class="why"><b>Tip from tool-gates:</b> Faster with clearer formatting.</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>aspell / codespell</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> typos</div>
  <div class="why"><b>Tip from tool-gates:</b> Fast source-aware spell check with low false positives; read-only by default.</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>youtube-dl</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> yt-dlp</div>
  <div class="why"><b>Tip from tool-gates:</b> Maintained fork; youtube-dl is abandoned and breaks on current sites.</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>pip install</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> uv pip</div>
  <div class="why"><b>Tip from tool-gates:</b> Faster, lockfile-aware, cache-shared.</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>python -m venv</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> uv venv</div>
  <div class="why"><b>Tip from tool-gates:</b> Faster; picks up the project's Python pin.</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>dig / nslookup</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> doggo</div>
  <div class="why"><b>Tip from tool-gates:</b> Colored output, JSON with --json, modern defaults.</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>unzip</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> ouch decompress</div>
  <div class="why"><b>Tip from tool-gates:</b> Format-agnostic (zip/tar/gz/xz/7z), auto-detects.</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>zip</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> ouch compress</div>
  <div class="why"><b>Tip from tool-gates:</b> Format inferred from the output extension.</div>
</div>
<div class="hint-row">
  <div class="old"><span class="prog">$</span> <s>tar -x</s></div>
  <div class="arrow">→</div>
  <div class="new"><span class="prog">$</span> ouch decompress</div>
  <div class="why"><b>Tip from tool-gates:</b> Format-agnostic, auto-detects compression (create with tar -c).</div>
</div>
</div>

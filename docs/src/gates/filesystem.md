<div class="gate-head">
  <p class="breadcrumb"><a href="../index.html">Gates</a> / filesystem</p>
  <h1>filesystem gate</h1>
  <div class="gate-meta">
    <span class="tag">priority <b>30</b></span>
    <span class="tag">unknown <b>ask</b></span>
    <span class="tag">custom handler <b>check_rm</b></span>
    <span class="tag"><b>tar -t</b> / <b>unzip -l</b> are read-only</span>
  </div>

  <div class="summary" aria-label="Rule counts at a glance">
    <div class="seg-bar" role="img" aria-label="3 allow, 13 ask, 6 block">
      <div class="seg allow" style="flex: 3"></div>
      <div class="seg ask"   style="flex: 13"></div>
      <div class="seg block" style="flex: 6"></div>
    </div>
    <div class="counts">
      <span class="ca"><i></i><b>3</b> allow</span>
      <span class="cas"><i></i><b>13</b> ask</span>
      <span class="cb"><i></i><b>6</b> block</span>
    </div>
  </div>

  <p class="gate-lede">Everything that touches disk: <b>rm</b>, <b>mv</b>, <b>cp</b>, <b>mkdir</b>, <b>chmod</b>, <b>chown</b>, <b>ln</b>, <b>sed -i</b>, archives. This gate owns the destructive block floor. Patterns like <code>rm -rf /</code> are denied here so they can never reach the shell. Read-only archive listing is exempt.</p>
</div>

<div class="chips" role="group" aria-label="Filter rules by decision">
  <button class="chip all"   data-filter="all"   aria-pressed="true"><i></i>All <span class="n">22</span></button>
  <button class="chip allow" data-filter="allow" aria-pressed="false"><i></i>Allow <span class="n">3</span></button>
  <button class="chip ask"   data-filter="ask"   aria-pressed="false"><i></i>Ask <span class="n">13</span></button>
  <button class="chip block" data-filter="block" aria-pressed="false"><i></i>Block <span class="n">6</span></button>
</div>

<div class="rule-card">
  <header>
    <h2>Blocked · destructive paths</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/filesystem.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/filesystem.toml#block
    </a>
    <span class="count">6 patterns</span>
  </header>

<div class="rule-row" data-decision="block" id="filesystem-rm">
  <div class="rule-cmd"><span class="prog">rm</span> <span class="flag">/</span> <span class="flag">/*</span> <span class="flag">~/</span> <span class="flag">~/*</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason"><code>rm</code> against <code>/</code> or <code>~/</code> blocked: would recursively delete the system or home tree. No legitimate use in an agent workflow.</div>
</div>
<div class="rule-row" data-decision="block" id="filesystem-rm-rf">
  <div class="rule-cmd"><span class="prog">rm</span> -rf /</div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason"><code>rm -rf /</code> blocked: would recursively delete the entire root filesystem.</div>
</div>
<div class="rule-row" data-decision="block" id="filesystem-rm-rf-2">
  <div class="rule-cmd"><span class="prog">rm</span> -rf /*</div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason"><code>rm -rf /*</code> blocked: would recursively delete every top-level directory under root.</div>
</div>
<div class="rule-row" data-decision="block" id="filesystem-rm-rf-3">
  <div class="rule-cmd"><span class="prog">rm</span> -rf ~</div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason"><code>rm -rf ~</code> blocked: would recursively delete the user's home directory.</div>
</div>
<div class="rule-row" data-decision="block" id="filesystem-rm-fr">
  <div class="rule-cmd"><span class="prog">rm</span> -fr /</div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason"><code>rm -fr /</code> blocked: would recursively delete the entire root filesystem.</div>
</div>
<div class="rule-row" data-decision="block" id="filesystem-rm-fr-2">
  <div class="rule-cmd"><span class="prog">rm</span> -fr ~</div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason"><code>rm -fr ~</code> blocked: would recursively delete the user's home directory.</div>
</div>
</div>

<div class="rule-card">
  <header>
    <h2>Allowed · read-only</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/filesystem.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/filesystem.toml#allow
    </a>
    <span class="count">3 patterns</span>
  </header>

<div class="rule-row" data-decision="allow" id="filesystem-tar-t">
  <div class="rule-cmd"><span class="prog">tar</span> -t</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists archive contents without extracting. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="filesystem-tar-list">
  <div class="rule-cmd"><span class="prog">tar</span> --list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists archive contents without extracting. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="filesystem-unzip-l">
  <div class="rule-cmd"><span class="prog">unzip</span> <span class="flag">-l</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists zip archive contents. Read-only. <code>zip -l</code> is not a listing flag (it converts line endings). Use <code>zipinfo</code> from the basics gate.</div>
</div>
</div>

<div class="rule-card">
  <header>
    <h2>Asks first · mutations</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/filesystem.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/filesystem.toml#ask
    </a>
    <span class="count">13 patterns</span>
  </header>

<div class="rule-row" data-decision="ask" id="filesystem-chgrp">
  <div class="rule-cmd"><span class="prog">chgrp</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Changes file group. Verify the target group exists before running.</div>
</div>
<div class="rule-row" data-decision="ask" id="filesystem-chmod">
  <div class="rule-cmd"><span class="prog">chmod</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Changes file/dir mode bits. Use the minimum needed: 755 for dirs, 644 for files. Avoid 777 unless you know why.</div>
</div>
<div class="rule-row" data-decision="ask" id="filesystem-chown">
  <div class="rule-cmd"><span class="prog">chown</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Changes file ownership. Verify the target user/group exists before running.</div>
</div>
<div class="rule-row" data-decision="ask" id="filesystem-cp">
  <div class="rule-cmd"><span class="prog">cp</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Copies files or directories. Overwrites destination by default; <code>-n</code> to skip existing.</div>
</div>
<div class="rule-row" data-decision="ask" id="filesystem-ln">
  <div class="rule-cmd"><span class="prog">ln</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates a hard or symbolic link. <code>-s</code> for symlink, <code>-f</code> to overwrite an existing link target.</div>
</div>
<div class="rule-row" data-decision="ask" id="filesystem-mkdir">
  <div class="rule-cmd"><span class="prog">mkdir</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates a directory. <code>-p</code> also creates missing parent directories.</div>
</div>
<div class="rule-row" data-decision="ask" id="filesystem-mv">
  <div class="rule-cmd"><span class="prog">mv</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Moves or renames files. Overwrites destination if it exists unless <code>-n</code> is set.</div>
</div>
<div class="rule-row" data-decision="ask" id="filesystem-perl">
  <div class="rule-cmd"><span class="prog">perl</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">perl can execute arbitrary code via <code>-e</code>, <code>-E</code>, <code>system()</code>, or backticks. Treat like running an inline script.</div>
</div>
<div class="rule-row" data-decision="ask" id="filesystem-rmdir">
  <div class="rule-cmd"><span class="prog">rmdir</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes empty directories. Fails if the directory contains files; use <code>rm -r</code> for non-empty trees.</div>
</div>
<div class="rule-row" data-decision="ask" id="filesystem-touch">
  <div class="rule-cmd"><span class="prog">touch</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates an empty file or updates the mtime/atime of an existing one.</div>
</div>
<div class="rule-row" data-decision="ask" id="filesystem-unzip">
  <div class="rule-cmd"><span class="prog">unzip</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Extracts a zip archive. Verify trust; paths inside the archive can use <code>..</code> for directory traversal.</div>
</div>
<div class="rule-row" data-decision="ask" id="filesystem-zip">
  <div class="rule-cmd"><span class="prog">zip</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates or modifies a zip archive. Writes the destination path; existing archives are updated in place.</div>
</div>
<div class="rule-row" data-decision="ask" id="filesystem-sed-i-in-place">
  <div class="rule-cmd"><span class="prog">sed</span> <span class="flag">-i</span> <span class="flag">--in-place</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">sed is safe without -i flag (in-place edit)</div>
</div>
</div>

<p class="note">
  <svg class="alert" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
  <span><b>The block floor is path-aware, not pattern-matched.</b> The <code>check_rm</code> custom handler normalises paths (<code>//</code> → <code>/</code>, <code>/.</code> → <code>/</code>) before checking, and routes traversal patterns (<code>..</code>, <code>../</code>, bare <code>*</code>) to ask-with-warn instead of denying. Authoring this declaratively in TOML alone would miss cases.</span>
</p>

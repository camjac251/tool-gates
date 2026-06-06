<div class="gate-head">
  <p class="breadcrumb"><a href="../index.html">Gates</a> / Git</p>
  <h1>Git gate</h1>
  <div class="gate-meta">
    <span class="tag">priority <b>10</b></span>
    <span class="tag">unknown <b>ask</b></span>
    <span class="tag"><b>--dry-run</b> / <b>-n</b> always allows</span>
    <span class="tag">aliases resolved from <b>~/.gitconfig</b></span>
  </div>

  <div class="summary" aria-label="Rule counts at a glance">
    <div class="seg-bar" role="img" aria-label="45 allow, 60 ask, 0 block">
      <div class="seg allow" style="flex: 45"></div>
      <div class="seg ask"   style="flex: 60"></div>
      <div class="seg block" style="flex: 0"></div>
    </div>
    <div class="counts">
      <span class="ca"><i></i><b>45</b> allow</span>
      <span class="cas"><i></i><b>60</b> ask</span>
      <span class="cb"><i></i><b>0</b> block</span>
    </div>
  </div>

  <p class="gate-lede">Read-only history and inspection commands pass through. Anything that writes to the tree, the index, or a remote pauses for approval. <b>git</b> is never hard-blocked from this gate. The dangerous floor lives in the filesystem rules and the pre-AST raw-string pass.</p>
</div>

<div class="chips" role="group" aria-label="Filter rules by decision">
  <button class="chip all"   data-filter="all"   aria-pressed="true"><i></i>All <span class="n">105</span></button>
  <button class="chip allow" data-filter="allow" aria-pressed="false"><i></i>Allow <span class="n">45</span></button>
  <button class="chip ask"   data-filter="ask"   aria-pressed="false"><i></i>Ask <span class="n">60</span></button>
  <button class="chip block" data-filter="block" aria-pressed="false"><i></i>Block <span class="n">0</span></button>
</div>

<div class="rule-card">
  <header>
    <h2>Allowed · read-only</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/git.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/git.toml#allow
    </a>
    <span class="count">45 patterns</span>
  </header>

<div class="rule-row" data-decision="allow" id="git-status">
  <div class="rule-cmd"><span class="prog">git</span> status</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the working tree status: staged, unstaged, and untracked files. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-log">
  <div class="rule-cmd"><span class="prog">git</span> log</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows commit history. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-diff">
  <div class="rule-cmd"><span class="prog">git</span> diff</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows changes between commits, the working tree, and the index. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-show">
  <div class="rule-cmd"><span class="prog">git</span> show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows a commit, tag, or other object and its contents. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-tag">
  <div class="rule-cmd"><span class="prog">git</span> tag</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists tags when no mutating flag is given. Read-only in this form; creation and deletion flags are gated separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-describe">
  <div class="rule-cmd"><span class="prog">git</span> describe</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Names a commit using the nearest reachable tag. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-rev-parse">
  <div class="rule-cmd"><span class="prog">git</span> rev-parse</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Resolves refs and arguments to object names. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-ls-files">
  <div class="rule-cmd"><span class="prog">git</span> ls-files</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists files tracked in the index. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-blame">
  <div class="rule-cmd"><span class="prog">git</span> blame</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the commit and author that last touched each line of a file. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-reflog">
  <div class="rule-cmd"><span class="prog">git</span> reflog</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the history of ref updates such as HEAD movements. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-shortlog">
  <div class="rule-cmd"><span class="prog">git</span> shortlog</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Summarizes commit history grouped by author. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-whatchanged">
  <div class="rule-cmd"><span class="prog">git</span> whatchanged</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows commit history along with the files each commit changed. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-ls-tree">
  <div class="rule-cmd"><span class="prog">git</span> ls-tree</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the contents of a tree object. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-cat-file">
  <div class="rule-cmd"><span class="prog">git</span> cat-file</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the type, size, or contents of a repository object. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-rev-list">
  <div class="rule-cmd"><span class="prog">git</span> rev-list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists commit objects in reverse chronological order. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-name-rev">
  <div class="rule-cmd"><span class="prog">git</span> name-rev</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Names commits by their position relative to refs. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-for-each-ref">
  <div class="rule-cmd"><span class="prog">git</span> for-each-ref</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists refs matching a pattern, with a customizable format. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-symbolic-ref">
  <div class="rule-cmd"><span class="prog">git</span> symbolic-ref</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reads a symbolic ref such as HEAD. Read-only when no value is given; writes are gated separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-verify-commit">
  <div class="rule-cmd"><span class="prog">git</span> verify-commit</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Checks the GPG signature on a commit. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-verify-tag">
  <div class="rule-cmd"><span class="prog">git</span> verify-tag</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Checks the GPG signature on a tag. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-fsck">
  <div class="rule-cmd"><span class="prog">git</span> fsck</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Checks repository objects for connectivity and integrity. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-count-objects">
  <div class="rule-cmd"><span class="prog">git</span> count-objects</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports the count and on-disk size of repository objects. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-check-ignore">
  <div class="rule-cmd"><span class="prog">git</span> check-ignore</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports which paths are ignored and the matching gitignore rule. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-check-attr">
  <div class="rule-cmd"><span class="prog">git</span> check-attr</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports the gitattributes values applied to given paths. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-grep">
  <div class="rule-cmd"><span class="prog">git</span> grep</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Searches tracked file contents for a pattern. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-merge-base">
  <div class="rule-cmd"><span class="prog">git</span> merge-base</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Finds the common ancestor of two or more commits. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-show-ref">
  <div class="rule-cmd"><span class="prog">git</span> show-ref</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists refs and the object names they point to. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-help">
  <div class="rule-cmd"><span class="prog">git</span> help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows Git help text for a subcommand. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-version">
  <div class="rule-cmd"><span class="prog">git</span> version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the installed Git version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-version-2">
  <div class="rule-cmd"><span class="prog">git</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the installed Git version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-h">
  <div class="rule-cmd"><span class="prog">git</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows short usage help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-help-2">
  <div class="rule-cmd"><span class="prog">git</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows full help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-branch">
  <div class="rule-cmd"><span class="prog">git</span> branch</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists or creates branches. Read-only when listing; delete, move, and copy flags are gated separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-config-get">
  <div class="rule-cmd"><span class="prog">git</span> config get</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reads a Git configuration value. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-config-list">
  <div class="rule-cmd"><span class="prog">git</span> config list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists Git configuration values. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-config-get-2">
  <div class="rule-cmd"><span class="prog">git</span> config --get</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reads a Git configuration value. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-config-list-2">
  <div class="rule-cmd"><span class="prog">git</span> config --list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists Git configuration values. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-stash-list">
  <div class="rule-cmd"><span class="prog">git</span> stash list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists stash entries. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-stash-show">
  <div class="rule-cmd"><span class="prog">git</span> stash show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the diff recorded in a stash entry. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-worktree-list">
  <div class="rule-cmd"><span class="prog">git</span> worktree list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the linked worktrees of this repository. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-submodule-status">
  <div class="rule-cmd"><span class="prog">git</span> submodule status</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports the status and checked-out commit of each submodule. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-remote">
  <div class="rule-cmd"><span class="prog">git</span> remote</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists configured remotes. Read-only when listing; add, remove, rename, and set-url are gated separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-remote-show">
  <div class="rule-cmd"><span class="prog">git</span> remote show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows details about a remote, including its tracked branches. Read-only network query.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-remote-v">
  <div class="rule-cmd"><span class="prog">git</span> remote -v</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists remotes with their fetch and push URLs. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="git-remote-get-url">
  <div class="rule-cmd"><span class="prog">git</span> remote get-url</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the URL of a remote. Read-only.</div>
</div>
</div>

<div class="rule-card">
  <header>
    <h2>Asks first · writes</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/git.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/git.toml#ask
    </a>
    <span class="count">60 patterns</span>
  </header>

<div class="rule-row" data-decision="ask" id="git-gc">
  <div class="rule-cmd"><span class="prog">git</span> gc</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs garbage collection in <code>.git</code>. Repacks objects and may prune unreachable commits older than the gc grace window.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-prune">
  <div class="rule-cmd"><span class="prog">git</span> prune</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deletes unreachable objects from <code>.git</code>. Cannot be recovered without a backup or reflog entry still pointing at them.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-config-set">
  <div class="rule-cmd"><span class="prog">git</span> config set</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Sets a git config value. <code>--local</code> scopes to this repo; <code>--global</code> affects all repos for the user.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-config-add">
  <div class="rule-cmd"><span class="prog">git</span> config --add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adds a git config entry. <code>--local</code> for this repo, <code>--global</code> for user-wide.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-config-unset">
  <div class="rule-cmd"><span class="prog">git</span> config --unset</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes a git config entry. Permanent for the chosen scope.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-stash-drop">
  <div class="rule-cmd"><span class="prog">git</span> stash drop</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Drops a stash permanently. Run <code>git stash list</code> first to confirm the index; cannot be undone.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-stash-pop">
  <div class="rule-cmd"><span class="prog">git</span> stash pop</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Applies the top stash and removes it. Use <code>git stash apply</code> if you want to keep the stash entry.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-stash-clear">
  <div class="rule-cmd"><span class="prog">git</span> stash clear</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Clears ALL stashes permanently. List with <code>git stash list</code> first; cannot be undone.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-stash-push">
  <div class="rule-cmd"><span class="prog">git</span> stash push</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Saves working-tree changes to a new stash entry.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-stash-apply">
  <div class="rule-cmd"><span class="prog">git</span> stash apply</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Applies a stash entry without removing it from the stash list.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-worktree-add">
  <div class="rule-cmd"><span class="prog">git</span> worktree add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates a new linked worktree checkout. Writes a new directory and registers it in <code>.git/worktrees/</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-worktree-remove">
  <div class="rule-cmd"><span class="prog">git</span> worktree remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes a worktree directory. Refuses if it has uncommitted changes unless <code>--force</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-worktree-prune">
  <div class="rule-cmd"><span class="prog">git</span> worktree prune</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Prunes stale worktree references that no longer point to a real directory.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-submodule-foreach">
  <div class="rule-cmd"><span class="prog">git</span> submodule foreach</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason"><code>git submodule foreach</code> runs an arbitrary shell command per submodule. Treat the command as if invoked directly.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-submodule-init">
  <div class="rule-cmd"><span class="prog">git</span> submodule init</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Registers submodules from <code>.gitmodules</code> into the local repo config. Does not fetch content; pair with <code>submodule update</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-submodule-update">
  <div class="rule-cmd"><span class="prog">git</span> submodule update</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Fetches and checks out submodule commits recorded in the superproject. Can overwrite local submodule edits unless <code>--merge</code>/<code>--rebase</code> is set.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-submodule-add">
  <div class="rule-cmd"><span class="prog">git</span> submodule add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adds a new submodule entry to <code>.gitmodules</code> and clones the remote repo into the tree.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-submodule-deinit">
  <div class="rule-cmd"><span class="prog">git</span> submodule deinit</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Unregisters submodules and clears their working tree. Use <code>--force</code> to drop uncommitted submodule changes.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-remote-add">
  <div class="rule-cmd"><span class="prog">git</span> remote add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Registers a new remote URL under the given name. Subsequent fetches/pushes will trust this endpoint.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-remote-remove">
  <div class="rule-cmd"><span class="prog">git</span> remote remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes a remote and its tracking refs from this repo. Does not affect the remote server.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-remote-rename">
  <div class="rule-cmd"><span class="prog">git</span> remote rename</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Renames a remote and rewrites tracking-branch refs to use the new name.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-remote-set-url">
  <div class="rule-cmd"><span class="prog">git</span> remote set-url</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Changes the URL of an existing remote. Future fetches/pushes will hit the new endpoint.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-push-force-f">
  <div class="rule-cmd"><span class="prog">git</span> push <span class="flag">--force</span> <span class="flag">-f</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span><span class="warn-tag" title="warn = true in source TOML">warn</span></div>
  <div class="rule-reason">Force push overwrites upstream history. Safer: <code>--force-with-lease</code> fails if the remote moved.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-reset-hard">
  <div class="rule-cmd"><span class="prog">git</span> reset <span class="flag">--hard</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span><span class="warn-tag" title="warn = true in source TOML">warn</span></div>
  <div class="rule-reason">Hard reset discards uncommitted changes in the working tree and index. Safer: <code>git stash</code> first, or <code>git reset --soft</code> to keep changes staged.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-clean-fd-fdx-f">
  <div class="rule-cmd"><span class="prog">git</span> clean <span class="flag">-fd</span> <span class="flag">-fdx</span> <span class="flag">-f</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span><span class="warn-tag" title="warn = true in source TOML">warn</span></div>
  <div class="rule-reason">Permanently deletes untracked files. Preview with <code>-n</code> (dry run) first; deletions cannot be undone.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-commit">
  <div class="rule-cmd"><span class="prog">git</span> commit</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Records staged changes as a new commit on the current branch.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-push">
  <div class="rule-cmd"><span class="prog">git</span> push</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Publishes local commits to a remote. Inspect <code>git log @{u}..</code> first to see what would be sent.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-pull">
  <div class="rule-cmd"><span class="prog">git</span> pull</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Fetches and integrates remote changes into the current branch. Use <code>--rebase</code> to avoid merge commits.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-merge">
  <div class="rule-cmd"><span class="prog">git</span> merge</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Merges another branch into the current one. Can produce conflicts; abort with <code>git merge --abort</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-rebase">
  <div class="rule-cmd"><span class="prog">git</span> rebase</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Replays commits from the current branch onto another base, rewriting their SHAs. Interactive (<code>-i</code>) hangs the agent; abort a stuck rebase with <code>git rebase --abort</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-checkout-b-b">
  <div class="rule-cmd"><span class="prog">git</span> checkout <span class="flag">-b</span> <span class="flag">-B</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates a new branch and switches to it. <code>-B</code> resets an existing branch of the same name to the start point.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-checkout">
  <div class="rule-cmd"><span class="prog">git</span> checkout <span class="flag">--</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Discards uncommitted changes in the listed paths. Cannot be undone.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-checkout-2">
  <div class="rule-cmd"><span class="prog">git</span> checkout</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Switches branches or restores files in the working tree. Uncommitted edits in affected files may be lost.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-switch">
  <div class="rule-cmd"><span class="prog">git</span> switch</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Switches the working tree to another branch. Refuses if local edits would conflict unless <code>--discard-changes</code> is set.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-reset">
  <div class="rule-cmd"><span class="prog">git</span> reset</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Moves HEAD and optionally the index/working tree. <code>--soft</code> keeps changes staged, <code>--mixed</code> (default) unstages, <code>--hard</code> discards.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-restore">
  <div class="rule-cmd"><span class="prog">git</span> restore</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Restores files in the working tree from the index or a commit. Overwrites uncommitted edits in the targeted paths.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-clean">
  <div class="rule-cmd"><span class="prog">git</span> clean</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Cleans the working tree. Preview with <code>-n</code> first if unsure what would be deleted.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-cherry-pick">
  <div class="rule-cmd"><span class="prog">git</span> cherry-pick</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Replays the listed commits on the current branch. May produce conflicts; abort with <code>git cherry-pick --abort</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-revert">
  <div class="rule-cmd"><span class="prog">git</span> revert</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates a new commit that undoes the listed commits. Preserves history; does not rewrite it.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-am">
  <div class="rule-cmd"><span class="prog">git</span> am</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Applies a mailbox patch series as commits. Stops on conflict; resolve and <code>git am --continue</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-apply">
  <div class="rule-cmd"><span class="prog">git</span> apply</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Applies a patch to the working tree (no commit created). Use <code>--check</code> to preview without writing.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-format-patch">
  <div class="rule-cmd"><span class="prog">git</span> format-patch</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Writes one <code>.patch</code> file per commit in the specified range. Output goes to the working directory.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-init">
  <div class="rule-cmd"><span class="prog">git</span> init</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates a new git repository in the current directory. Writes a <code>.git/</code> directory.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-clone">
  <div class="rule-cmd"><span class="prog">git</span> clone</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Clones a remote repository into a new directory. Network operation; size depends on remote history.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-fetch">
  <div class="rule-cmd"><span class="prog">git</span> fetch</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Downloads refs and objects from a remote. Does not modify the working tree or current branch.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-mv">
  <div class="rule-cmd"><span class="prog">git</span> mv</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Moves or renames a tracked file and stages the rename in one step.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-rm">
  <div class="rule-cmd"><span class="prog">git</span> rm</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes a tracked file from the working tree and stages the deletion. <code>--cached</code> keeps the file on disk.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-tag-a-annotate-s-sign-u-local-user-m-message">
  <div class="rule-cmd"><span class="prog">git</span> tag <span class="flag">-a</span> <span class="flag">--annotate</span> <span class="flag">-s</span> <span class="flag">--sign</span> <span class="flag">-u</span> <span class="flag">--local-user</span> <span class="flag">-m</span> <span class="flag">--message</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates a tag pointing at the named commit (HEAD by default). Local only until <code>git push --tags</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-tag-d-delete">
  <div class="rule-cmd"><span class="prog">git</span> tag <span class="flag">-d</span> <span class="flag">--delete</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deletes a local tag. Use <code>git push --delete &lt;remote&gt; &lt;tag&gt;</code> separately to delete it on the remote.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-tag-f-force">
  <div class="rule-cmd"><span class="prog">git</span> tag <span class="flag">-f</span> <span class="flag">--force</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Force-replacing a tag breaks anyone who already pulled it. Confirm no downstream consumers.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-branch-d-d-delete">
  <div class="rule-cmd"><span class="prog">git</span> branch <span class="flag">-d</span> <span class="flag">-D</span> <span class="flag">--delete</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deletes a branch ref. <code>-d</code> refuses if the branch has unmerged commits; <code>-D</code> forces the delete regardless. Recover via <code>git reflog</code> if done by mistake.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-branch-m-m-move">
  <div class="rule-cmd"><span class="prog">git</span> branch <span class="flag">-m</span> <span class="flag">-M</span> <span class="flag">--move</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Renames a branch. <code>-M</code> forces the rename even if it would overwrite an existing branch name.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-bisect">
  <div class="rule-cmd"><span class="prog">git</span> bisect</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Starts a binary-search session over commit history. Mutates HEAD across iterations; end with <code>git bisect reset</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-filter-branch">
  <div class="rule-cmd"><span class="prog">git</span> filter-branch</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Rewrites commit history. Safer alternatives: <code>git revise --autosquash</code> for fixups, <code>git absorb</code> for auto-folding edits. <code>git-filter-repo</code> is the maintained replacement for filter-branch.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-filter-repo">
  <div class="rule-cmd"><span class="prog">git</span> filter-repo</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Rewrites commit history. Refuses to run on non-fresh clones; use <code>--force</code> only with intent.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-notes">
  <div class="rule-cmd"><span class="prog">git</span> notes</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adds, edits, or removes notes attached to commits. Stored in <code>refs/notes/*</code>; not shown in default <code>git log</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-bundle">
  <div class="rule-cmd"><span class="prog">git</span> bundle</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates or unpacks a git bundle file (offline-transportable pack of refs and objects).</div>
</div>
<div class="rule-row" data-decision="ask" id="git-maintenance">
  <div class="rule-cmd"><span class="prog">git</span> maintenance</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs repo maintenance tasks (gc, commit-graph, prefetch, loose-objects). Modifies <code>.git/</code> in the background.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-sparse-checkout">
  <div class="rule-cmd"><span class="prog">git</span> sparse-checkout</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Modifies sparse-checkout config. Changes which files are materialized in the working tree.</div>
</div>
<div class="rule-row" data-decision="ask" id="git-worktree">
  <div class="rule-cmd"><span class="prog">git</span> worktree</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Worktree operation. See <code>git worktree --help</code> for subcommand-specific risk.</div>
</div>
</div>

<p class="note">
  <svg class="alert" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
  <span><b>Hard blocks live in other gates.</b> The git gate never denies outright. A pattern like <code>curl … | bash</code> is caught by the pre-AST raw-string pass before any gate runs. Destructive filesystem patterns like <code>rm -rf /</code> are denied in <a href="filesystem.html">filesystem.toml</a>.</span>
</p>

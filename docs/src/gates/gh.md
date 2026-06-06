<div class="gate-head">
  <p class="breadcrumb"><a href="../index.html">Gates</a> / GitHub CLI</p>
  <h1>GitHub CLI gate</h1>
  <div class="gate-meta">
    <span class="tag">priority <b>10</b></span>
    <span class="tag">unknown <b>ask</b></span>
    <span class="tag"><b>api</b> method-aware via custom handler</span>
  </div>

  <div class="summary" aria-label="Rule counts at a glance">
    <div class="seg-bar" role="img" aria-label="44 allow, 88 ask, 2 block">
      <div class="seg allow" style="flex: 44"></div>
      <div class="seg ask"   style="flex: 88"></div>
      <div class="seg block" style="flex: 2"></div>
    </div>
    <div class="counts">
      <span class="ca"><i></i><b>44</b> allow</span>
      <span class="cas"><i></i><b>88</b> ask</span>
      <span class="cb"><i></i><b>2</b> block</span>
    </div>
  </div>

  <p class="gate-lede">GitHub CLI. Listing, viewing, searching, and read API are safe. Mutations ask. Two patterns are hard-blocked: deleting a repository (irreversible) and logging out (no way to re-authenticate without user interaction).</p>
</div>

<div class="chips" role="group" aria-label="Filter rules by decision">
  <button class="chip all"   data-filter="all"   aria-pressed="true"><i></i>All <span class="n">134</span></button>
  <button class="chip allow" data-filter="allow" aria-pressed="false"><i></i>Allow <span class="n">44</span></button>
  <button class="chip ask"   data-filter="ask"   aria-pressed="false"><i></i>Ask <span class="n">88</span></button>
  <button class="chip block" data-filter="block" aria-pressed="false"><i></i>Block <span class="n">2</span></button>
</div>

<div class="rule-card">
  <header>
    <h2>Blocked</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/gh.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/gh.toml#block
    </a>
    <span class="count">2 patterns</span>
  </header>

<div class="rule-row" data-decision="block" id="gh-repo-delete">
  <div class="rule-cmd"><span class="prog">gh</span> repo delete</div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Deletes the repository on GitHub. Irreversible: history, issues, PRs, releases, and forks-from-this-repo are removed. Blocked unconditionally.</div>
</div>
<div class="rule-row" data-decision="block" id="gh-auth-logout">
  <div class="rule-cmd"><span class="prog">gh</span> auth logout</div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Logs out the gh CLI from GitHub. The agent has no way to re-authenticate without user interaction. Blocked unconditionally.</div>
</div>
</div>

<div class="rule-card">
  <header>
    <h2>Allowed · read-only</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/gh.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/gh.toml#allow
    </a>
    <span class="count">44 patterns</span>
  </header>

<div class="rule-row" data-decision="allow" id="gh-issue-view">
  <div class="rule-cmd"><span class="prog">gh</span> issue view</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Issue inspection commands.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-issue-list">
  <div class="rule-cmd"><span class="prog">gh</span> issue list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Issue inspection commands.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-issue-status">
  <div class="rule-cmd"><span class="prog">gh</span> issue status</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Issue inspection commands.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-pr-view">
  <div class="rule-cmd"><span class="prog">gh</span> pr view</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">PR inspection commands. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-pr-list">
  <div class="rule-cmd"><span class="prog">gh</span> pr list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">PR inspection commands. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-pr-status">
  <div class="rule-cmd"><span class="prog">gh</span> pr status</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">PR inspection commands. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-pr-diff">
  <div class="rule-cmd"><span class="prog">gh</span> pr diff</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">PR inspection commands. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-pr-checks">
  <div class="rule-cmd"><span class="prog">gh</span> pr checks</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows CI check status for a pull request. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-pr-develop">
  <div class="rule-cmd"><span class="prog">gh</span> pr develop</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists linked branches for a pull request when run without flags. Read-only in this form; passing a branch name creates one (gated separately).</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-repo-view">
  <div class="rule-cmd"><span class="prog">gh</span> repo view</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Repo metadata.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-repo-list">
  <div class="rule-cmd"><span class="prog">gh</span> repo list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Repo metadata.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-search-issues">
  <div class="rule-cmd"><span class="prog">gh</span> search issues</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Search endpoints across GitHub. Always GET via the API.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-search-prs">
  <div class="rule-cmd"><span class="prog">gh</span> search prs</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Search endpoints across GitHub. Always GET via the API.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-search-repos">
  <div class="rule-cmd"><span class="prog">gh</span> search repos</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Search endpoints across GitHub. Always GET via the API.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-search-commits">
  <div class="rule-cmd"><span class="prog">gh</span> search commits</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Search endpoints across GitHub. Always GET via the API.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-search-code">
  <div class="rule-cmd"><span class="prog">gh</span> search code</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Search endpoints across GitHub. Always GET via the API.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-status">
  <div class="rule-cmd"><span class="prog">gh</span> status</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows a summary of your relevant issues, PRs, and review requests across repos. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-auth-status">
  <div class="rule-cmd"><span class="prog">gh</span> auth status</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the current authentication state, active account, and token scopes. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-auth-token">
  <div class="rule-cmd"><span class="prog">gh</span> auth token</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the stored OAuth token to stdout. Read-only but exposes a credential.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-config-get">
  <div class="rule-cmd"><span class="prog">gh</span> config get</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reads a single gh CLI configuration value. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-config-list">
  <div class="rule-cmd"><span class="prog">gh</span> config list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the gh CLI configuration values. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-run-list">
  <div class="rule-cmd"><span class="prog">gh</span> run list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists recent Actions workflow runs. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-run-view">
  <div class="rule-cmd"><span class="prog">gh</span> run view</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows details, jobs, and logs for an Actions workflow run. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-workflow-list">
  <div class="rule-cmd"><span class="prog">gh</span> workflow list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the Actions workflows defined in the repository. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-workflow-view">
  <div class="rule-cmd"><span class="prog">gh</span> workflow view</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows an Actions workflow definition and its recent runs. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-release-list">
  <div class="rule-cmd"><span class="prog">gh</span> release list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists releases for the repository. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-release-view">
  <div class="rule-cmd"><span class="prog">gh</span> release view</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows release notes and asset list for a release. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-gist-list">
  <div class="rule-cmd"><span class="prog">gh</span> gist list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists your gists. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-gist-view">
  <div class="rule-cmd"><span class="prog">gh</span> gist view</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the contents of a gist. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-label-list">
  <div class="rule-cmd"><span class="prog">gh</span> label list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists labels defined in the repository. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-codespace-list">
  <div class="rule-cmd"><span class="prog">gh</span> codespace list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists your codespaces and their state. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-cs-list">
  <div class="rule-cmd"><span class="prog">gh</span> cs list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists your codespaces and their state (<code>cs</code> alias). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-ssh-key-list">
  <div class="rule-cmd"><span class="prog">gh</span> ssh-key list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the SSH keys registered on the GitHub account. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-gpg-key-list">
  <div class="rule-cmd"><span class="prog">gh</span> gpg-key list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the GPG keys registered on the GitHub account. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-extension-list">
  <div class="rule-cmd"><span class="prog">gh</span> extension list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists installed gh CLI extensions. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-browse">
  <div class="rule-cmd"><span class="prog">gh</span> browse</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Opens the repository, issue, or PR in a browser, or prints the URL with <code>--no-browser</code>. Does not change anything on GitHub.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-alias-list">
  <div class="rule-cmd"><span class="prog">gh</span> alias list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the gh CLI command aliases. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-cache-list">
  <div class="rule-cmd"><span class="prog">gh</span> cache list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists Actions caches for the repository. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-variable-list">
  <div class="rule-cmd"><span class="prog">gh</span> variable list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists Actions variable names and values for the repo, environment, or org. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-secret-list">
  <div class="rule-cmd"><span class="prog">gh</span> secret list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists Actions secret names for the repo, environment, or org. Read-only and does not reveal secret values.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-ruleset-list">
  <div class="rule-cmd"><span class="prog">gh</span> ruleset list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists repository or organization rulesets. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-ruleset-view">
  <div class="rule-cmd"><span class="prog">gh</span> ruleset view</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the rules and configuration for a ruleset. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-project-list">
  <div class="rule-cmd"><span class="prog">gh</span> project list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists Projects for a user or organization. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="gh-project-view">
  <div class="rule-cmd"><span class="prog">gh</span> project view</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows a Project's fields and items. Read-only.</div>
</div>
</div>

<div class="rule-card">
  <header>
    <h2>Asks first · mutations</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/gh.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/gh.toml#ask
    </a>
    <span class="count">88 patterns</span>
  </header>

<div class="rule-row" data-decision="ask" id="gh-repo-clone">
  <div class="rule-cmd"><span class="prog">gh</span> repo clone</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Clones a repository into a new directory under the current path. Writes files locally; does not modify the remote.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-run-download">
  <div class="rule-cmd"><span class="prog">gh</span> run download</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Downloads workflow run artifacts into the current directory. Writes files locally; does not change anything on GitHub.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-release-download">
  <div class="rule-cmd"><span class="prog">gh</span> release download</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Downloads release asset files into the current directory. Writes files locally; does not change the release.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-gist-clone">
  <div class="rule-cmd"><span class="prog">gh</span> gist clone</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Clones a gist into a new local directory. Writes files locally; does not modify the gist.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-issue-create">
  <div class="rule-cmd"><span class="prog">gh</span> issue create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating issue</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-issue-close">
  <div class="rule-cmd"><span class="prog">gh</span> issue close</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Closing issue</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-issue-reopen">
  <div class="rule-cmd"><span class="prog">gh</span> issue reopen</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Reopening issue</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-issue-edit">
  <div class="rule-cmd"><span class="prog">gh</span> issue edit</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Editing issue</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-issue-comment">
  <div class="rule-cmd"><span class="prog">gh</span> issue comment</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Posts a comment to an issue on GitHub. Visible publicly and cannot be silently unsent.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-issue-delete">
  <div class="rule-cmd"><span class="prog">gh</span> issue delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deletes issue <code>&lt;issue&gt;</code> permanently. Irreversible; comments and reactions go with it. Prefer <code>close</code> for normal workflow.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-issue-transfer">
  <div class="rule-cmd"><span class="prog">gh</span> issue transfer</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Transferring issue</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-issue-pin">
  <div class="rule-cmd"><span class="prog">gh</span> issue pin</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Pinning issue</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-issue-unpin">
  <div class="rule-cmd"><span class="prog">gh</span> issue unpin</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Unpinning issue</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-issue-lock">
  <div class="rule-cmd"><span class="prog">gh</span> issue lock</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Locking issue</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-issue-unlock">
  <div class="rule-cmd"><span class="prog">gh</span> issue unlock</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Unlocking issue</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-pr-create">
  <div class="rule-cmd"><span class="prog">gh</span> pr create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating PR</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-pr-close">
  <div class="rule-cmd"><span class="prog">gh</span> pr close</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Closing PR</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-pr-reopen">
  <div class="rule-cmd"><span class="prog">gh</span> pr reopen</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Reopening PR</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-pr-edit">
  <div class="rule-cmd"><span class="prog">gh</span> pr edit</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Editing PR</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-pr-comment">
  <div class="rule-cmd"><span class="prog">gh</span> pr comment</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Posts a comment to a pull request on GitHub. Visible publicly and cannot be silently unsent.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-pr-merge">
  <div class="rule-cmd"><span class="prog">gh</span> pr merge</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Merges PR <code>&lt;pr&gt;</code> into the base branch. <code>--squash</code>/<code>--rebase</code> rewrite history; <code>--delete-branch</code> also deletes the source branch.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-pr-ready">
  <div class="rule-cmd"><span class="prog">gh</span> pr ready</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Marking PR ready</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-pr-review">
  <div class="rule-cmd"><span class="prog">gh</span> pr review</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Submits a pull request review (approve, request changes, or comment). Posted to GitHub and visible to the author and watchers.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-pr-checkout">
  <div class="rule-cmd"><span class="prog">gh</span> pr checkout</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Fetches a pull request branch and checks it out locally. Switches the working tree to the PR's HEAD.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-repo-create">
  <div class="rule-cmd"><span class="prog">gh</span> repo create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating repository</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-repo-rename">
  <div class="rule-cmd"><span class="prog">gh</span> repo rename</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Renaming repository</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-repo-edit">
  <div class="rule-cmd"><span class="prog">gh</span> repo edit</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Editing repository</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-repo-fork">
  <div class="rule-cmd"><span class="prog">gh</span> repo fork</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates a fork of the repository under your account and can add a local remote. Creates a new repo on GitHub.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-repo-archive">
  <div class="rule-cmd"><span class="prog">gh</span> repo archive</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Archives the repository on GitHub. Becomes read-only: no new issues, PRs, comments, or pushes. Reversible via <code>repo unarchive</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-repo-unarchive">
  <div class="rule-cmd"><span class="prog">gh</span> repo unarchive</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Unarchiving repository</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-repo-sync">
  <div class="rule-cmd"><span class="prog">gh</span> repo sync</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Syncing repository</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-repo-set-default">
  <div class="rule-cmd"><span class="prog">gh</span> repo set-default</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Setting default repo</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-release-create">
  <div class="rule-cmd"><span class="prog">gh</span> release create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating release</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-release-delete">
  <div class="rule-cmd"><span class="prog">gh</span> release delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deletes release <code>&lt;release&gt;</code> from GitHub. Removes release notes and uploaded assets; the underlying git tag stays unless <code>--cleanup-tag</code> is passed.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-release-edit">
  <div class="rule-cmd"><span class="prog">gh</span> release edit</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Editing release</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-release-upload">
  <div class="rule-cmd"><span class="prog">gh</span> release upload</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Uploads asset files to an existing release. Published assets become downloadable by anyone who can see the release.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-release-delete-asset">
  <div class="rule-cmd"><span class="prog">gh</span> release delete-asset</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deleting asset</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-gist-create">
  <div class="rule-cmd"><span class="prog">gh</span> gist create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating gist</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-gist-delete">
  <div class="rule-cmd"><span class="prog">gh</span> gist delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deletes gist <code>&lt;gist&gt;</code> permanently. Irreversible; comments and revision history go with it.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-gist-edit">
  <div class="rule-cmd"><span class="prog">gh</span> gist edit</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Editing gist</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-gist-rename">
  <div class="rule-cmd"><span class="prog">gh</span> gist rename</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Renaming gist</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-label-create">
  <div class="rule-cmd"><span class="prog">gh</span> label create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating label</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-label-delete">
  <div class="rule-cmd"><span class="prog">gh</span> label delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deleting label</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-label-edit">
  <div class="rule-cmd"><span class="prog">gh</span> label edit</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Editing label</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-label-clone">
  <div class="rule-cmd"><span class="prog">gh</span> label clone</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Cloning labels</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-workflow-run">
  <div class="rule-cmd"><span class="prog">gh</span> workflow run</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Triggers a GitHub Actions workflow run. Executes CI side effects such as deploys and consumes Actions minutes.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-workflow-enable">
  <div class="rule-cmd"><span class="prog">gh</span> workflow enable</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Enabling workflow</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-workflow-disable">
  <div class="rule-cmd"><span class="prog">gh</span> workflow disable</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Disabling workflow</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-run-cancel">
  <div class="rule-cmd"><span class="prog">gh</span> run cancel</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Canceling run</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-run-rerun">
  <div class="rule-cmd"><span class="prog">gh</span> run rerun</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Rerunning</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-run-delete">
  <div class="rule-cmd"><span class="prog">gh</span> run delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deleting run</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-run-watch">
  <div class="rule-cmd"><span class="prog">gh</span> run watch</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Watching run</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-codespace-create">
  <div class="rule-cmd"><span class="prog">gh</span> codespace create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating codespace</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-codespace-delete">
  <div class="rule-cmd"><span class="prog">gh</span> codespace delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deletes a codespace. Unsaved local changes inside the codespace are lost.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-codespace-edit">
  <div class="rule-cmd"><span class="prog">gh</span> codespace edit</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Editing codespace</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-codespace-stop">
  <div class="rule-cmd"><span class="prog">gh</span> codespace stop</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Stopping codespace</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-codespace-rebuild">
  <div class="rule-cmd"><span class="prog">gh</span> codespace rebuild</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Rebuilding codespace</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-cs-create">
  <div class="rule-cmd"><span class="prog">gh</span> cs create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating codespace</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-cs-delete">
  <div class="rule-cmd"><span class="prog">gh</span> cs delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deletes a codespace. Unsaved local changes inside the codespace are lost.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-ssh-key-add">
  <div class="rule-cmd"><span class="prog">gh</span> ssh-key add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adding SSH key</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-ssh-key-delete">
  <div class="rule-cmd"><span class="prog">gh</span> ssh-key delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes an SSH key from the GitHub account. SSH access from any machine using that key will stop working.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-gpg-key-add">
  <div class="rule-cmd"><span class="prog">gh</span> gpg-key add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adding GPG key</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-gpg-key-delete">
  <div class="rule-cmd"><span class="prog">gh</span> gpg-key delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes a GPG key from the GitHub account. Existing signed commits stay valid; future signatures with this key will not be marked verified.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-config-set">
  <div class="rule-cmd"><span class="prog">gh</span> config set</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Setting config</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-config-clear-cache">
  <div class="rule-cmd"><span class="prog">gh</span> config clear-cache</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Clearing cache</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-secret-set">
  <div class="rule-cmd"><span class="prog">gh</span> secret set</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Setting secret</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-secret-delete">
  <div class="rule-cmd"><span class="prog">gh</span> secret delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deletes an Actions/Codespaces/Dependabot secret. Future workflow runs that read this secret will fail until it is recreated.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-variable-set">
  <div class="rule-cmd"><span class="prog">gh</span> variable set</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Sets an Actions variable for the repo, environment, or organization. Visible to future workflow runs.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-variable-delete">
  <div class="rule-cmd"><span class="prog">gh</span> variable delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deletes an Actions variable. Future workflow runs that read this variable will see it as empty.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-cache-delete">
  <div class="rule-cmd"><span class="prog">gh</span> cache delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deletes one or more GitHub Actions caches. Next workflow run that expects this cache will rebuild it from scratch.</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-extension-install">
  <div class="rule-cmd"><span class="prog">gh</span> extension install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installing extension</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-extension-upgrade">
  <div class="rule-cmd"><span class="prog">gh</span> extension upgrade</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Upgrading extension</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-extension-remove">
  <div class="rule-cmd"><span class="prog">gh</span> extension remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removing extension</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-alias-set">
  <div class="rule-cmd"><span class="prog">gh</span> alias set</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Setting alias</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-alias-delete">
  <div class="rule-cmd"><span class="prog">gh</span> alias delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deleting alias</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-alias-import">
  <div class="rule-cmd"><span class="prog">gh</span> alias import</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Importing aliases</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-project-create">
  <div class="rule-cmd"><span class="prog">gh</span> project create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating project</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-project-delete">
  <div class="rule-cmd"><span class="prog">gh</span> project delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deleting project</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-project-edit">
  <div class="rule-cmd"><span class="prog">gh</span> project edit</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Editing project</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-project-close">
  <div class="rule-cmd"><span class="prog">gh</span> project close</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Closing project</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-project-copy">
  <div class="rule-cmd"><span class="prog">gh</span> project copy</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Copying project</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-project-item-add">
  <div class="rule-cmd"><span class="prog">gh</span> project item-add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adding project item</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-project-item-archive">
  <div class="rule-cmd"><span class="prog">gh</span> project item-archive</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Archiving item</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-project-item-create">
  <div class="rule-cmd"><span class="prog">gh</span> project item-create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating item</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-project-item-delete">
  <div class="rule-cmd"><span class="prog">gh</span> project item-delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deleting item</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-project-item-edit">
  <div class="rule-cmd"><span class="prog">gh</span> project item-edit</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Editing item</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-project-field-create">
  <div class="rule-cmd"><span class="prog">gh</span> project field-create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating field</div>
</div>
<div class="rule-row" data-decision="ask" id="gh-project-field-delete">
  <div class="rule-cmd"><span class="prog">gh</span> project field-delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deleting field</div>
</div>
</div>

<p class="note">
  <svg class="alert" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
  <span><b>Two-pattern block floor.</b> <code>gh repo delete</code> and <code>gh auth logout</code> are the only hard blocks: the first destroys repo history and metadata irreversibly; the second leaves the agent with no way to re-authenticate. Every other mutation asks.</span>
</p>

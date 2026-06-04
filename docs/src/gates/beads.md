<div class="gate-head">
  <p class="breadcrumb"><a href="../index.html">Gates</a> / beads</p>
  <h1>beads gate</h1>
  <div class="gate-meta">
    <span class="tag">priority <b>22</b></span>
    <span class="tag">unknown <b>ask</b></span>
    <span class="tag">aliases <b>beads</b> → <b>bd</b></span>
  </div>

  <div class="summary" aria-label="Rule counts at a glance">
    <div class="seg-bar" role="img" aria-label="106 allow, 114 ask, 0 block">
      <div class="seg allow" style="flex: 106"></div>
      <div class="seg ask"   style="flex: 114"></div>
      <div class="seg block" style="flex: 0"></div>
    </div>
    <div class="counts">
      <span class="ca"><i></i><b>106</b> allow</span>
      <span class="cas"><i></i><b>114</b> ask</span>
      <span class="cb"><i></i><b>0</b> block</span>
    </div>
  </div>

  <p class="gate-lede">Beads git-native issue tracker. Reads are safe; writes ask. Nothing is hard-blocked because every beads state mutation is recoverable through git or remote sync. Two <code>warn = true</code> rules: <code>bd admin reset</code> and <code>bd reset</code> drop the local database.</p>
</div>

<div class="chips" role="group" aria-label="Filter rules by decision">
  <button class="chip all"   data-filter="all"   aria-pressed="true"><i></i>All <span class="n">220</span></button>
  <button class="chip allow" data-filter="allow" aria-pressed="false"><i></i>Allow <span class="n">106</span></button>
  <button class="chip ask"   data-filter="ask"   aria-pressed="false"><i></i>Ask <span class="n">114</span></button>
  <button class="chip block" data-filter="block" aria-pressed="false"><i></i>Block <span class="n">0</span></button>
</div>

<div class="rule-card">
  <header>
    <h2>Allowed · queries</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/beads.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/beads.toml#allow
    </a>
    <span class="count">106 patterns</span>
  </header>

<div class="rule-row" data-decision="allow" id="beads-bd-list">
  <div class="rule-cmd"><span class="prog">bd</span> list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists issues, optionally filtered by status, priority, type, or assignee. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-show">
  <div class="rule-cmd"><span class="prog">bd</span> show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows full details of one issue: description, status, dependencies, and history. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-ready">
  <div class="rule-cmd"><span class="prog">bd</span> ready</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists issues ready to work on (all dependencies satisfied). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-blocked">
  <div class="rule-cmd"><span class="prog">bd</span> blocked</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists issues blocked by unmet dependencies. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-count">
  <div class="rule-cmd"><span class="prog">bd</span> count</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the number of issues matching a filter. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-search">
  <div class="rule-cmd"><span class="prog">bd</span> search</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Full-text search across issue titles and descriptions. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-where">
  <div class="rule-cmd"><span class="prog">bd</span> where</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the path to the active beads database and workspace. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-info">
  <div class="rule-cmd"><span class="prog">bd</span> info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows workspace metadata: database location, issue prefix, and counts. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-version">
  <div class="rule-cmd"><span class="prog">bd</span> version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the bd version string. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-help">
  <div class="rule-cmd"><span class="prog">bd</span> help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints command help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-status">
  <div class="rule-cmd"><span class="prog">bd</span> status</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows workspace status: pending sync, daemon state, and issue counts. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-doctor">
  <div class="rule-cmd"><span class="prog">bd</span> doctor</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs diagnostic checks on the workspace and reports problems. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-lint">
  <div class="rule-cmd"><span class="prog">bd</span> lint</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Checks issues for consistency problems and reports findings. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-human">
  <div class="rule-cmd"><span class="prog">bd</span> human</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints issues in a human-readable summary format. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-onboard">
  <div class="rule-cmd"><span class="prog">bd</span> onboard</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints onboarding guidance for getting started with beads. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-completion">
  <div class="rule-cmd"><span class="prog">bd</span> completion</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints a shell completion script to stdout. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-thanks">
  <div class="rule-cmd"><span class="prog">bd</span> thanks</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints project credits. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-detect-pollution">
  <div class="rule-cmd"><span class="prog">bd</span> detect-pollution</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Scans for cross-workspace data pollution and reports findings. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-dep">
  <div class="rule-cmd"><span class="prog">bd</span> dep</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspects issue dependencies. Read-only unless <code>add</code> or <code>remove</code> is given, which edit edges and ask separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-dep-tree">
  <div class="rule-cmd"><span class="prog">bd</span> dep tree</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Displays the dependency tree for an issue. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-dep-cycles">
  <div class="rule-cmd"><span class="prog">bd</span> dep cycles</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Detects and reports dependency cycles in the issue graph. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-graph">
  <div class="rule-cmd"><span class="prog">bd</span> graph</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Renders the issue dependency graph. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-label">
  <div class="rule-cmd"><span class="prog">bd</span> label</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspects issue labels. Read-only unless <code>add</code> or <code>remove</code> is given, which mutate labels and ask separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-label-list">
  <div class="rule-cmd"><span class="prog">bd</span> label list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists labels in use. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-label-list-all">
  <div class="rule-cmd"><span class="prog">bd</span> label list-all</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists all defined labels, including unused ones. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-comments">
  <div class="rule-cmd"><span class="prog">bd</span> comments</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows comments on an issue. Read-only unless <code>add</code> is given, which posts a comment and asks separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-comment">
  <div class="rule-cmd"><span class="prog">bd</span> comment</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows comments on an issue. Read-only unless <code>add</code> is given, which posts a comment and asks separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-daemons">
  <div class="rule-cmd"><span class="prog">bd</span> daemons</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports daemon status. Read-only unless a control verb (<code>start</code>, <code>stop</code>, <code>restart</code>, <code>killall</code>) is given, which asks separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-daemons-list">
  <div class="rule-cmd"><span class="prog">bd</span> daemons list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists running beads daemons. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-daemons-health">
  <div class="rule-cmd"><span class="prog">bd</span> daemons health</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports health of running daemons. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-daemons-logs">
  <div class="rule-cmd"><span class="prog">bd</span> daemons logs</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints daemon log output. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-daemon">
  <div class="rule-cmd"><span class="prog">bd</span> daemon</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports daemon status. Read-only unless a control verb (<code>start</code>, <code>stop</code>, <code>restart</code>, <code>kill</code>, <code>run</code>) is given, which asks separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-daemon-health">
  <div class="rule-cmd"><span class="prog">bd</span> daemon health</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports health of the daemon. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-daemon-logs">
  <div class="rule-cmd"><span class="prog">bd</span> daemon logs</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints daemon log output. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-config">
  <div class="rule-cmd"><span class="prog">bd</span> config</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reads configuration. Read-only unless <code>set</code> or <code>unset</code> is given, which write config and ask separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-config-get">
  <div class="rule-cmd"><span class="prog">bd</span> config get</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints a single configuration value. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-config-list">
  <div class="rule-cmd"><span class="prog">bd</span> config list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints all configuration values. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-stats">
  <div class="rule-cmd"><span class="prog">bd</span> stats</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows aggregate issue counts by status, priority, and type. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-activity">
  <div class="rule-cmd"><span class="prog">bd</span> activity</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows recent issue activity. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-stale">
  <div class="rule-cmd"><span class="prog">bd</span> stale</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists issues with no recent activity. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-orphans">
  <div class="rule-cmd"><span class="prog">bd</span> orphans</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists orphaned issues with no parent or links. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-preflight">
  <div class="rule-cmd"><span class="prog">bd</span> preflight</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs preflight checks and reports readiness. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-audit">
  <div class="rule-cmd"><span class="prog">bd</span> audit</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the audit log. Read-only unless <code>record</code> or <code>label</code> is given, which write audit entries and ask separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-epic">
  <div class="rule-cmd"><span class="prog">bd</span> epic</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspects epics. Read-only unless <code>create</code>, <code>close</code>, or <code>update</code> is given, which mutate epics and ask separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-epic-status">
  <div class="rule-cmd"><span class="prog">bd</span> epic status</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows epic progress and child-issue rollup. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-close-eligible">
  <div class="rule-cmd"><span class="prog">bd</span> close-eligible</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists issues eligible to be closed. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-swarm">
  <div class="rule-cmd"><span class="prog">bd</span> swarm</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspects swarms. Read-only unless a mutating verb (<code>create</code>, <code>close</code>, <code>update</code>, <code>add</code>, <code>remove</code>) is given, which asks separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-swarm-list">
  <div class="rule-cmd"><span class="prog">bd</span> swarm list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists swarms. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-gate">
  <div class="rule-cmd"><span class="prog">bd</span> gate</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspects gates. Read-only unless <code>resolve</code> or <code>add-waiter</code> is given, which mutate gate state and ask separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-gate-list">
  <div class="rule-cmd"><span class="prog">bd</span> gate list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists gates. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-gate-show">
  <div class="rule-cmd"><span class="prog">bd</span> gate show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows details of one gate. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-gate-check">
  <div class="rule-cmd"><span class="prog">bd</span> gate check</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Checks whether a gate's conditions are met. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-gate-discover">
  <div class="rule-cmd"><span class="prog">bd</span> gate discover</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Discovers gates from the workspace and reports them. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-template">
  <div class="rule-cmd"><span class="prog">bd</span> template</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspects templates. Read-only unless <code>instantiate</code> is given, which creates issues and asks separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-template-list">
  <div class="rule-cmd"><span class="prog">bd</span> template list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists available templates. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-template-show">
  <div class="rule-cmd"><span class="prog">bd</span> template show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the contents of one template. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-formula">
  <div class="rule-cmd"><span class="prog">bd</span> formula</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspects formulas. Read-only unless a mutating verb (<code>create</code>, <code>delete</code>, <code>update</code>, <code>edit</code>, <code>convert</code>) is given, which asks separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-formula-list">
  <div class="rule-cmd"><span class="prog">bd</span> formula list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists available formulas. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-formula-show">
  <div class="rule-cmd"><span class="prog">bd</span> formula show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the contents of one formula. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-mol">
  <div class="rule-cmd"><span class="prog">bd</span> mol</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspects molecules. Read-only unless a mutating verb (<code>burn</code>, <code>squash</code>, <code>bond</code>, <code>distill</code>, <code>create</code>) is given, which asks separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-mol-show">
  <div class="rule-cmd"><span class="prog">bd</span> mol show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows details of one molecule. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-mol-current">
  <div class="rule-cmd"><span class="prog">bd</span> mol current</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the currently active molecule. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-mol-stale">
  <div class="rule-cmd"><span class="prog">bd</span> mol stale</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists molecules with no recent activity. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-mol-progress">
  <div class="rule-cmd"><span class="prog">bd</span> mol progress</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows progress of a molecule's issues. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-mol-list">
  <div class="rule-cmd"><span class="prog">bd</span> mol list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists molecules. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-slot">
  <div class="rule-cmd"><span class="prog">bd</span> slot</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspects slots. Read-only unless a mutating verb (<code>set</code>, <code>clear</code>, <code>claim</code>, <code>release</code>) is given, which asks separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-slot-show">
  <div class="rule-cmd"><span class="prog">bd</span> slot show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows details of one slot. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-slot-list">
  <div class="rule-cmd"><span class="prog">bd</span> slot list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists slots. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-agent">
  <div class="rule-cmd"><span class="prog">bd</span> agent</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspects agents. Read-only unless a mutating verb (<code>set</code>, <code>clear</code>, <code>update</code>, <code>create</code>) is given, which asks separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-agent-show">
  <div class="rule-cmd"><span class="prog">bd</span> agent show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows details of one agent. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-agent-list">
  <div class="rule-cmd"><span class="prog">bd</span> agent list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists agents. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-state">
  <div class="rule-cmd"><span class="prog">bd</span> state</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspects workflow states. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-state-list">
  <div class="rule-cmd"><span class="prog">bd</span> state list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists configured workflow states. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-worktree">
  <div class="rule-cmd"><span class="prog">bd</span> worktree</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspects worktrees. Read-only unless <code>add</code>, <code>remove</code>, or <code>prune</code> is given, which mutate worktrees and ask separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-worktree-list">
  <div class="rule-cmd"><span class="prog">bd</span> worktree list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists worktrees. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-repo">
  <div class="rule-cmd"><span class="prog">bd</span> repo</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspects linked repositories. Read-only unless a mutating verb (<code>add</code>, <code>remove</code>, <code>set</code>, <code>sync</code>) is given, which asks separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-repo-list">
  <div class="rule-cmd"><span class="prog">bd</span> repo list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists linked repositories. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-repo-show">
  <div class="rule-cmd"><span class="prog">bd</span> repo show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows details of one linked repository. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-jira">
  <div class="rule-cmd"><span class="prog">bd</span> jira</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspects the Jira integration. Read-only unless a data-flow verb (<code>sync</code>, <code>push</code>, <code>import</code>, <code>create</code>) is given, which asks separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-jira-status">
  <div class="rule-cmd"><span class="prog">bd</span> jira status</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows Jira integration status. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-jira-list">
  <div class="rule-cmd"><span class="prog">bd</span> jira list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists Jira issues visible to the integration. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-jira-show">
  <div class="rule-cmd"><span class="prog">bd</span> jira show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows one Jira issue. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-linear">
  <div class="rule-cmd"><span class="prog">bd</span> linear</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspects the Linear integration. Read-only unless a data-flow verb (<code>sync</code>, <code>push</code>, <code>import</code>, <code>create</code>) is given, which asks separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-linear-status">
  <div class="rule-cmd"><span class="prog">bd</span> linear status</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows Linear integration status. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-linear-list">
  <div class="rule-cmd"><span class="prog">bd</span> linear list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists Linear issues visible to the integration. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-linear-show">
  <div class="rule-cmd"><span class="prog">bd</span> linear show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows one Linear issue. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-ship">
  <div class="rule-cmd"><span class="prog">bd</span> ship</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspects ships. Read-only unless <code>publish</code>, <code>create</code>, or <code>delete</code> is given, which mutate ships and ask separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-ship-list">
  <div class="rule-cmd"><span class="prog">bd</span> ship list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists ships. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-ship-show">
  <div class="rule-cmd"><span class="prog">bd</span> ship show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows details of one ship. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-upgrade">
  <div class="rule-cmd"><span class="prog">bd</span> upgrade</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports available upgrades. Read-only unless <code>--apply</code>, <code>--install</code>, or <code>ack</code> is given, which change state and ask separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-upgrade-status">
  <div class="rule-cmd"><span class="prog">bd</span> upgrade status</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows current upgrade status. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-upgrade-review">
  <div class="rule-cmd"><span class="prog">bd</span> upgrade review</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows what an upgrade would change before applying it. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-migrate">
  <div class="rule-cmd"><span class="prog">bd</span> migrate</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Previews a database migration. Read-only unless <code>--apply</code> or <code>--force</code> is given, which writes the migration and asks separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-duplicates">
  <div class="rule-cmd"><span class="prog">bd</span> duplicates</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists suspected duplicate issues. Read-only unless <code>--auto-merge</code> is given, which merges them and asks separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-cleanup-dry-run">
  <div class="rule-cmd"><span class="prog">bd</span> cleanup <span class="flag">--dry-run</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Previews cleanup of stale or orphaned issues. Read-only because <code>--dry-run</code> reports what would be removed without writing.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-compact-dry-run">
  <div class="rule-cmd"><span class="prog">bd</span> compact <span class="flag">--dry-run</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Previews database compaction. Read-only because <code>--dry-run</code> reports what would change without writing.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-delete-dry-run">
  <div class="rule-cmd"><span class="prog">bd</span> delete <span class="flag">--dry-run</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Previews an issue deletion. Read-only because <code>--dry-run</code> reports what would be deleted without writing.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-admin-cleanup-dry-run">
  <div class="rule-cmd"><span class="prog">bd</span> admin cleanup <span class="flag">--dry-run</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Previews admin-level cleanup. Read-only because <code>--dry-run</code> reports what would be removed without writing.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-admin-compact-dry-run">
  <div class="rule-cmd"><span class="prog">bd</span> admin compact <span class="flag">--dry-run</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Previews admin-level compaction. Read-only because <code>--dry-run</code> reports what would change without writing.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-prime">
  <div class="rule-cmd"><span class="prog">bd</span> prime</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints a context summary to prime an AI assistant. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-quickstart">
  <div class="rule-cmd"><span class="prog">bd</span> quickstart</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints quickstart guidance. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-workflow">
  <div class="rule-cmd"><span class="prog">bd</span> workflow</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the configured workflow description. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-tips">
  <div class="rule-cmd"><span class="prog">bd</span> tips</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints usage tips. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-deleted">
  <div class="rule-cmd"><span class="prog">bd</span> deleted</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists soft-deleted (tombstoned) issues. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-hook">
  <div class="rule-cmd"><span class="prog">bd</span> hook</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspects configured hooks. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="beads-bd-pin">
  <div class="rule-cmd"><span class="prog">bd</span> pin</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the pinned issue for an agent. Read-only unless <code>--set</code> or <code>--clear</code> is given, which change the pin and ask separately.</div>
</div>
</div>

<div class="rule-card">
  <header>
    <h2>Asks first · mutations</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/beads.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/beads.toml#ask
    </a>
    <span class="count">114 patterns</span>
  </header>

<div class="rule-row" data-decision="ask" id="beads-bd-create">
  <div class="rule-cmd"><span class="prog">bd</span> create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating new issue</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-create-form">
  <div class="rule-cmd"><span class="prog">bd</span> create-form</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating issue via form</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-q">
  <div class="rule-cmd"><span class="prog">bd</span> q</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Quick capturing issue</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-quick">
  <div class="rule-cmd"><span class="prog">bd</span> quick</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Quick capturing issue</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-update">
  <div class="rule-cmd"><span class="prog">bd</span> update</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Updating issue</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-edit">
  <div class="rule-cmd"><span class="prog">bd</span> edit</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Editing issue in editor</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-close">
  <div class="rule-cmd"><span class="prog">bd</span> close</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Closing issue</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-reopen">
  <div class="rule-cmd"><span class="prog">bd</span> reopen</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Reopening issue</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-delete">
  <div class="rule-cmd"><span class="prog">bd</span> delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deleting issue</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-move">
  <div class="rule-cmd"><span class="prog">bd</span> move</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Moves an issue to a different rig (workspace). Changes the issue's owning database; sync source and target to keep both consistent.</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-refile">
  <div class="rule-cmd"><span class="prog">bd</span> refile</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Refiling issue</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-set-state">
  <div class="rule-cmd"><span class="prog">bd</span> set-state</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Setting issue state</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-defer">
  <div class="rule-cmd"><span class="prog">bd</span> defer</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deferring issue</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-undefer">
  <div class="rule-cmd"><span class="prog">bd</span> undefer</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Undeferring issue</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-dep-add">
  <div class="rule-cmd"><span class="prog">bd</span> dep add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adding dependency</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-dep-remove">
  <div class="rule-cmd"><span class="prog">bd</span> dep remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removing dependency</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-relate">
  <div class="rule-cmd"><span class="prog">bd</span> relate</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Relating issues</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-unrelate">
  <div class="rule-cmd"><span class="prog">bd</span> unrelate</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Unrelating issues</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-duplicate">
  <div class="rule-cmd"><span class="prog">bd</span> duplicate</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Marking as duplicate</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-supersede">
  <div class="rule-cmd"><span class="prog">bd</span> supersede</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Marking as superseded</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-label-add">
  <div class="rule-cmd"><span class="prog">bd</span> label add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adding label</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-label-remove">
  <div class="rule-cmd"><span class="prog">bd</span> label remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removing label</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-comments-add">
  <div class="rule-cmd"><span class="prog">bd</span> comments add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adding comment</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-comment-add">
  <div class="rule-cmd"><span class="prog">bd</span> comment add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adding comment</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-sync">
  <div class="rule-cmd"><span class="prog">bd</span> sync</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Syncs local issues with the git-backed remote. Pulls and pushes issue changes; may merge or overwrite local edits if the remote diverged.</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-export">
  <div class="rule-cmd"><span class="prog">bd</span> export</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Exporting issues</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-import">
  <div class="rule-cmd"><span class="prog">bd</span> import</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Importing issues</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-init">
  <div class="rule-cmd"><span class="prog">bd</span> init</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Initializing beads in project</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-setup">
  <div class="rule-cmd"><span class="prog">bd</span> setup</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Setting up integration</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-config-set">
  <div class="rule-cmd"><span class="prog">bd</span> config set</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Changing configuration</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-config-unset">
  <div class="rule-cmd"><span class="prog">bd</span> config unset</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Unsetting configuration</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-daemons-start">
  <div class="rule-cmd"><span class="prog">bd</span> daemons start</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Starts a beads daemon process in the background. Daemons handle sync, hooks, and event delivery.</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-daemons-stop">
  <div class="rule-cmd"><span class="prog">bd</span> daemons stop</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Stops a running beads daemon process. Pauses background sync, hooks, and event delivery until restarted.</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-daemons-restart">
  <div class="rule-cmd"><span class="prog">bd</span> daemons restart</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Restarts a beads daemon process. Briefly pauses background sync, hooks, and event delivery.</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-daemons-killall">
  <div class="rule-cmd"><span class="prog">bd</span> daemons killall</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Kills every running beads daemon process on this machine. Stops background sync, hooks, and event delivery until restarted.</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-daemon-start">
  <div class="rule-cmd"><span class="prog">bd</span> daemon start</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Starts a beads daemon process in the background. Daemons handle sync, hooks, and event delivery.</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-daemon-stop">
  <div class="rule-cmd"><span class="prog">bd</span> daemon stop</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Stops a running beads daemon process. Pauses background sync, hooks, and event delivery until restarted.</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-daemon-restart">
  <div class="rule-cmd"><span class="prog">bd</span> daemon restart</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Restarts a beads daemon process. Briefly pauses background sync, hooks, and event delivery.</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-daemon-kill">
  <div class="rule-cmd"><span class="prog">bd</span> daemon kill</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Force-kills a beads daemon process. May leave temporary state if the daemon was mid-write.</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-daemon-run">
  <div class="rule-cmd"><span class="prog">bd</span> daemon run</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs a beads daemon in the foreground. Holds the terminal until interrupted.</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-hooks">
  <div class="rule-cmd"><span class="prog">bd</span> hooks</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Managing git hooks</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-migrate-apply-force">
  <div class="rule-cmd"><span class="prog">bd</span> migrate <span class="flag">--apply</span> <span class="flag">--force</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Migrating database</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-migrate-sync">
  <div class="rule-cmd"><span class="prog">bd</span> migrate sync</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Migrating sync</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-migrate-issues">
  <div class="rule-cmd"><span class="prog">bd</span> migrate issues</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Migrating issues</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-migrate-hash-ids">
  <div class="rule-cmd"><span class="prog">bd</span> migrate hash-ids</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Migrating hash IDs</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-migrate-tombstones">
  <div class="rule-cmd"><span class="prog">bd</span> migrate tombstones</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Migrating tombstones</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-admin">
  <div class="rule-cmd"><span class="prog">bd</span> admin</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs a beads admin operation (cleanup, compact, or reset depending on the subcommand). Scope varies; <code>admin reset</code> is destructive.</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-admin-cleanup">
  <div class="rule-cmd"><span class="prog">bd</span> admin cleanup</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Admin-level cleanup of stale or orphaned issues. Removes records matching cleanup rules; preview first with <code>--dry-run</code>. Recoverable via git.</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-admin-compact">
  <div class="rule-cmd"><span class="prog">bd</span> admin compact</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Admin-level compaction to shrink the database. Condenses resolved issue history; preview first with <code>--dry-run</code>. Recoverable via git.</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-admin-reset">
  <div class="rule-cmd"><span class="prog">bd</span> admin reset</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span><span class="warn-tag" title="warn = true in source TOML">warn</span></div>
  <div class="rule-reason">Resets the beads database. Drops all issues, history, and local state. Cannot be undone without a backup or remote sync.</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-compact">
  <div class="rule-cmd"><span class="prog">bd</span> compact</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compacts old issues to shrink the database. Condenses or removes resolved history; preview first with <code>--dry-run</code>. Recoverable via git.</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-cleanup">
  <div class="rule-cmd"><span class="prog">bd</span> cleanup</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Cleans up stale or orphaned issues. Removes records that match cleanup rules; preview first with <code>--dry-run</code>. Recoverable via git.</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-merge">
  <div class="rule-cmd"><span class="prog">bd</span> merge</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Merges two issues into one. Combines their fields and history and tombstones the merged-away issue. Recoverable via git history.</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-duplicates-auto-merge">
  <div class="rule-cmd"><span class="prog">bd</span> duplicates <span class="flag">--auto-merge</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Auto-merging duplicates</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-repair">
  <div class="rule-cmd"><span class="prog">bd</span> repair</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Repairs the beads database from local logs and remote state. Can modify or roll back issue records to resolve inconsistencies.</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-restore">
  <div class="rule-cmd"><span class="prog">bd</span> restore</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Restores a soft-deleted (tombstoned) issue back to active state.</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-upgrade-ack">
  <div class="rule-cmd"><span class="prog">bd</span> upgrade ack</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Acknowledging upgrade</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-upgrade-apply-install">
  <div class="rule-cmd"><span class="prog">bd</span> upgrade <span class="flag">--apply</span> <span class="flag">--install</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Applying upgrade</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-epic-create">
  <div class="rule-cmd"><span class="prog">bd</span> epic create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating epic</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-epic-close">
  <div class="rule-cmd"><span class="prog">bd</span> epic close</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Closing epic</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-epic-update">
  <div class="rule-cmd"><span class="prog">bd</span> epic update</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Updating epic</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-swarm-create">
  <div class="rule-cmd"><span class="prog">bd</span> swarm create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating swarm</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-swarm-close">
  <div class="rule-cmd"><span class="prog">bd</span> swarm close</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Closing swarm</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-swarm-update">
  <div class="rule-cmd"><span class="prog">bd</span> swarm update</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Updating swarm</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-swarm-add">
  <div class="rule-cmd"><span class="prog">bd</span> swarm add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adding to swarm</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-swarm-remove">
  <div class="rule-cmd"><span class="prog">bd</span> swarm remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removing from swarm</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-gate-resolve">
  <div class="rule-cmd"><span class="prog">bd</span> gate resolve</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Resolving gate</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-gate-add-waiter">
  <div class="rule-cmd"><span class="prog">bd</span> gate add-waiter</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adding gate waiter</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-template-instantiate">
  <div class="rule-cmd"><span class="prog">bd</span> template instantiate</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Instantiating template</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-mol-burn">
  <div class="rule-cmd"><span class="prog">bd</span> mol burn</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Burning molecule</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-mol-squash">
  <div class="rule-cmd"><span class="prog">bd</span> mol squash</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Squashing molecule</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-mol-bond">
  <div class="rule-cmd"><span class="prog">bd</span> mol bond</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Bonding molecules</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-mol-distill">
  <div class="rule-cmd"><span class="prog">bd</span> mol distill</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Distilling molecule</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-mol-create">
  <div class="rule-cmd"><span class="prog">bd</span> mol create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating molecule</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-pour">
  <div class="rule-cmd"><span class="prog">bd</span> pour</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating molecule from formula</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-wisp">
  <div class="rule-cmd"><span class="prog">bd</span> wisp</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating ephemeral wisp</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-cook">
  <div class="rule-cmd"><span class="prog">bd</span> cook</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compiling formula to proto</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-formula-create">
  <div class="rule-cmd"><span class="prog">bd</span> formula create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating formula</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-formula-delete">
  <div class="rule-cmd"><span class="prog">bd</span> formula delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deleting formula</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-formula-update">
  <div class="rule-cmd"><span class="prog">bd</span> formula update</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Updating formula</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-formula-edit">
  <div class="rule-cmd"><span class="prog">bd</span> formula edit</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Editing formula</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-formula-convert">
  <div class="rule-cmd"><span class="prog">bd</span> formula convert</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Converting formula</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-slot-set">
  <div class="rule-cmd"><span class="prog">bd</span> slot set</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Setting slot</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-slot-clear">
  <div class="rule-cmd"><span class="prog">bd</span> slot clear</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Clearing slot</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-slot-claim">
  <div class="rule-cmd"><span class="prog">bd</span> slot claim</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Claiming slot</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-slot-release">
  <div class="rule-cmd"><span class="prog">bd</span> slot release</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Releasing slot</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-agent-set">
  <div class="rule-cmd"><span class="prog">bd</span> agent set</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Setting agent state</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-agent-clear">
  <div class="rule-cmd"><span class="prog">bd</span> agent clear</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Clearing agent state</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-agent-update">
  <div class="rule-cmd"><span class="prog">bd</span> agent update</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Updating agent</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-agent-create">
  <div class="rule-cmd"><span class="prog">bd</span> agent create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating agent</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-audit-record">
  <div class="rule-cmd"><span class="prog">bd</span> audit record</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Recording audit entry</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-audit-label">
  <div class="rule-cmd"><span class="prog">bd</span> audit label</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Labeling audit entry</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-pin-set-clear">
  <div class="rule-cmd"><span class="prog">bd</span> pin <span class="flag">--set</span> <span class="flag">--clear</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Pinning work to agent</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-ship-publish">
  <div class="rule-cmd"><span class="prog">bd</span> ship publish</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Publishing capability</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-ship-create">
  <div class="rule-cmd"><span class="prog">bd</span> ship create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating ship</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-ship-delete">
  <div class="rule-cmd"><span class="prog">bd</span> ship delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deleting ship</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-rename-prefix">
  <div class="rule-cmd"><span class="prog">bd</span> rename-prefix</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Renames the workspace issue-ID prefix. Rewrites the ID of every issue; update any external references that pin the old prefix.</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-worktree-add">
  <div class="rule-cmd"><span class="prog">bd</span> worktree add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adding worktree</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-worktree-remove">
  <div class="rule-cmd"><span class="prog">bd</span> worktree remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removing worktree</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-worktree-prune">
  <div class="rule-cmd"><span class="prog">bd</span> worktree prune</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Pruning worktrees</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-repo-add">
  <div class="rule-cmd"><span class="prog">bd</span> repo add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adding repository</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-repo-remove">
  <div class="rule-cmd"><span class="prog">bd</span> repo remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removing repository</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-repo-set">
  <div class="rule-cmd"><span class="prog">bd</span> repo set</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Setting repository config</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-repo-sync">
  <div class="rule-cmd"><span class="prog">bd</span> repo sync</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Syncing repository</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-jira-sync">
  <div class="rule-cmd"><span class="prog">bd</span> jira sync</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Syncing with Jira</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-jira-push">
  <div class="rule-cmd"><span class="prog">bd</span> jira push</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Pushing to Jira</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-jira-import">
  <div class="rule-cmd"><span class="prog">bd</span> jira import</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Importing from Jira</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-jira-create">
  <div class="rule-cmd"><span class="prog">bd</span> jira create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating in Jira</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-linear-sync">
  <div class="rule-cmd"><span class="prog">bd</span> linear sync</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Syncing with Linear</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-linear-push">
  <div class="rule-cmd"><span class="prog">bd</span> linear push</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Pushing to Linear</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-linear-import">
  <div class="rule-cmd"><span class="prog">bd</span> linear import</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Importing from Linear</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-linear-create">
  <div class="rule-cmd"><span class="prog">bd</span> linear create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating in Linear</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-mail">
  <div class="rule-cmd"><span class="prog">bd</span> mail</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Delegating to mail provider</div>
</div>
<div class="rule-row" data-decision="ask" id="beads-bd-reset">
  <div class="rule-cmd"><span class="prog">bd</span> reset</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span><span class="warn-tag" title="warn = true in source TOML">warn</span></div>
  <div class="rule-reason">Resets the beads database. Drops all issues, history, and local state. Cannot be undone without a backup or remote sync.</div>
</div>
</div>

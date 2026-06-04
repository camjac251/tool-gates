<div class="gate-head">
  <p class="breadcrumb"><a href="../index.html">Gates</a> / shortcut</p>
  <h1>shortcut gate</h1>
  <div class="gate-meta">
    <span class="tag">priority <b>45</b></span>
    <span class="tag">unknown <b>ask</b></span>
    <span class="tag">covers the <b>short</b> CLI</span>
  </div>

  <div class="summary" aria-label="Rule counts at a glance">
    <div class="seg-bar" role="img" aria-label="9 allow, 21 ask, 0 block">
      <div class="seg allow" style="flex: 9"></div>
      <div class="seg ask"   style="flex: 21"></div>
      <div class="seg block" style="flex: 0"></div>
    </div>
    <div class="counts">
      <span class="ca"><i></i><b>9</b> allow</span>
      <span class="cas"><i></i><b>21</b> ask</span>
      <span class="cb"><i></i><b>0</b> block</span>
    </div>
  </div>

  <p class="gate-lede">Community <code>short</code> CLI for Shortcut.com. Searches and listings are safe. Story mutations, comments, attachments, and workflow-state changes ask. The custom handler routes <code>short api</code> by HTTP method.</p>
</div>

<div class="chips" role="group" aria-label="Filter rules by decision">
  <button class="chip all"   data-filter="all"   aria-pressed="true"><i></i>All <span class="n">30</span></button>
  <button class="chip allow" data-filter="allow" aria-pressed="false"><i></i>Allow <span class="n">9</span></button>
  <button class="chip ask"   data-filter="ask"   aria-pressed="false"><i></i>Ask <span class="n">21</span></button>
  <button class="chip block" data-filter="block" aria-pressed="false"><i></i>Block <span class="n">0</span></button>
</div>

<div class="rule-card">
  <header>
    <h2>Allowed · queries</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/shortcut.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/shortcut.toml#allow
    </a>
    <span class="count">9 patterns</span>
  </header>

<div class="rule-row" data-decision="allow" id="shortcut-short-search">
  <div class="rule-cmd"><span class="prog">short</span> search</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Searching stories</div>
</div>
<div class="rule-row" data-decision="allow" id="shortcut-short-find">
  <div class="rule-cmd"><span class="prog">short</span> find</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Searching stories</div>
</div>
<div class="rule-row" data-decision="allow" id="shortcut-short-story">
  <div class="rule-cmd"><span class="prog">short</span> story</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Viewing story</div>
</div>
<div class="rule-row" data-decision="allow" id="shortcut-short-members">
  <div class="rule-cmd"><span class="prog">short</span> members</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Listing members</div>
</div>
<div class="rule-row" data-decision="allow" id="shortcut-short-epics">
  <div class="rule-cmd"><span class="prog">short</span> epics</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Listing epics</div>
</div>
<div class="rule-row" data-decision="allow" id="shortcut-short-workflows">
  <div class="rule-cmd"><span class="prog">short</span> workflows</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Listing workflows</div>
</div>
<div class="rule-row" data-decision="allow" id="shortcut-short-projects">
  <div class="rule-cmd"><span class="prog">short</span> projects</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Listing projects</div>
</div>
<div class="rule-row" data-decision="allow" id="shortcut-short-workspace">
  <div class="rule-cmd"><span class="prog">short</span> workspace</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Listing workspaces</div>
</div>
<div class="rule-row" data-decision="allow" id="shortcut-short-help">
  <div class="rule-cmd"><span class="prog">short</span> help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Showing help</div>
</div>
</div>

<div class="rule-card">
  <header>
    <h2>Asks first · mutations</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/shortcut.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/shortcut.toml#ask
    </a>
    <span class="count">21 patterns</span>
  </header>

<div class="rule-row" data-decision="ask" id="shortcut-short-install">
  <div class="rule-cmd"><span class="prog">short</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Writes the Shortcut API token to the local <code>short</code> config. One-time auth setup.</div>
</div>
<div class="rule-row" data-decision="ask" id="shortcut-short-search-s-save">
  <div class="rule-cmd"><span class="prog">short</span> search <span class="flag">-S</span> <span class="flag">--save</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Saves the current search as a named workspace in the local <code>short</code> config. Writes to disk; does not change anything on shortcut.com.</div>
</div>
<div class="rule-row" data-decision="ask" id="shortcut-short-story-git-branch-git-branch-short">
  <div class="rule-cmd"><span class="prog">short</span> story <span class="flag">--git-branch</span> <span class="flag">--git-branch-short</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates and checks out a local git branch named for the story. Switches your working tree; commit or stash first.</div>
</div>
<div class="rule-row" data-decision="ask" id="shortcut-short-story-d-download">
  <div class="rule-cmd"><span class="prog">short</span> story <span class="flag">-D</span> <span class="flag">--download</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Downloads the story's attachments to the current directory. Writes files to disk.</div>
</div>
<div class="rule-row" data-decision="ask" id="shortcut-short-story-c-comment">
  <div class="rule-cmd"><span class="prog">short</span> story <span class="flag">-c</span> <span class="flag">--comment</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Posts a comment to the story on shortcut.com. Visible to all workspace members.</div>
</div>
<div class="rule-row" data-decision="ask" id="shortcut-short-story-d-description">
  <div class="rule-cmd"><span class="prog">short</span> story <span class="flag">-d</span> <span class="flag">--description</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Overwrites the story's description field. Replaces existing text; back up the current body if it matters.</div>
</div>
<div class="rule-row" data-decision="ask" id="shortcut-short-story-e-estimate">
  <div class="rule-cmd"><span class="prog">short</span> story <span class="flag">-e</span> <span class="flag">--estimate</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Sets the story's point estimate.</div>
</div>
<div class="rule-row" data-decision="ask" id="shortcut-short-story-epic">
  <div class="rule-cmd"><span class="prog">short</span> story <span class="flag">--epic</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Reassigns the story to a different epic.</div>
</div>
<div class="rule-row" data-decision="ask" id="shortcut-short-story-i-iteration">
  <div class="rule-cmd"><span class="prog">short</span> story <span class="flag">-i</span> <span class="flag">--iteration</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Moves the story into a different iteration (sprint).</div>
</div>
<div class="rule-row" data-decision="ask" id="shortcut-short-story-l-label">
  <div class="rule-cmd"><span class="prog">short</span> story <span class="flag">-l</span> <span class="flag">--label</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Sets the story's labels.</div>
</div>
<div class="rule-row" data-decision="ask" id="shortcut-short-story-move-after-move-before-move-down-move-up">
  <div class="rule-cmd"><span class="prog">short</span> story <span class="flag">--move-after</span> <span class="flag">--move-before</span> <span class="flag">--move-down</span> <span class="flag">--move-up</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Reorders the story within its workflow column.</div>
</div>
<div class="rule-row" data-decision="ask" id="shortcut-short-story-o-owners">
  <div class="rule-cmd"><span class="prog">short</span> story <span class="flag">-o</span> <span class="flag">--owners</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Sets the story's owners. Replaces the existing owner list.</div>
</div>
<div class="rule-row" data-decision="ask" id="shortcut-short-story-s-state">
  <div class="rule-cmd"><span class="prog">short</span> story <span class="flag">-s</span> <span class="flag">--state</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Updates the workflow state of story <code>&lt;story&gt;</code>. Moves it on the workflow board (e.g., To Do -&gt; In Progress -&gt; Done) and may trigger workflow automations.</div>
</div>
<div class="rule-row" data-decision="ask" id="shortcut-short-story-t-title">
  <div class="rule-cmd"><span class="prog">short</span> story <span class="flag">-t</span> <span class="flag">--title</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Renames the story's title.</div>
</div>
<div class="rule-row" data-decision="ask" id="shortcut-short-story-t-team">
  <div class="rule-cmd"><span class="prog">short</span> story <span class="flag">-T</span> <span class="flag">--team</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Reassigns the story to a different team.</div>
</div>
<div class="rule-row" data-decision="ask" id="shortcut-short-story-task">
  <div class="rule-cmd"><span class="prog">short</span> story <span class="flag">--task</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adds a subtask to the story.</div>
</div>
<div class="rule-row" data-decision="ask" id="shortcut-short-story-task-complete">
  <div class="rule-cmd"><span class="prog">short</span> story <span class="flag">--task-complete</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Toggles a subtask's done state on the story.</div>
</div>
<div class="rule-row" data-decision="ask" id="shortcut-short-story-y-type">
  <div class="rule-cmd"><span class="prog">short</span> story <span class="flag">-y</span> <span class="flag">--type</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Sets the story type (feature, bug, or chore).</div>
</div>
<div class="rule-row" data-decision="ask" id="shortcut-short-story-a-archived">
  <div class="rule-cmd"><span class="prog">short</span> story <span class="flag">-a</span> <span class="flag">--archived</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Archives story <code>&lt;story&gt;</code>. Hides it from default views but keeps history; reversible via <code>--archived=false</code> or the web UI.</div>
</div>
<div class="rule-row" data-decision="ask" id="shortcut-short-create">
  <div class="rule-cmd"><span class="prog">short</span> create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates a new story in the workspace.</div>
</div>
<div class="rule-row" data-decision="ask" id="shortcut-short-workspace-u-unset">
  <div class="rule-cmd"><span class="prog">short</span> workspace <span class="flag">-u</span> <span class="flag">--unset</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes a saved workspace (named search query) from the local <code>short</code> config. Does not delete anything on shortcut.com.</div>
</div>
</div>

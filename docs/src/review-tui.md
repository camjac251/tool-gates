  <p class="breadcrumb"><a href="index.html">Reference</a> / Review TUI</p>
  <h1 id="review-tui-h1">Review TUI</h1>
  <p class="page-lede"><code>tool-gates review</code> is where ask decisions become permanent rules. Every command you clicked through lands in a queue; the TUI lets you promote, deny, or dismiss each one, and manage the allow/deny rules already in your <code>settings.json</code>. It is keyboard-first, color-and-symbol coded, and biased toward the safe choice: the wider a rule reaches, the more friction it asks for.</p>

  <div class="sec-head" style="margin-top: var(--s-6)">
    <p class="lbl">Launch</p>
    <h2>One command, current project by default.</h2>
  </div>
  <pre class="code-block"><span class="prompt">$</span> tool-gates review          <span class="comment"># pending + rules for the current project</span>
<span class="prompt">$</span> tool-gates review --all    <span class="comment"># span every project on this machine</span></pre>
  <p class="step-prose">The header names the active project and the machine-wide pending total. Everything below is reachable without leaving the keyboard; the mouse can click rows and tabs too.</p>

  <div class="sec-head">
    <p class="lbl">Views</p>
    <h2>Three tabs: a queue and two rule managers.</h2>
    <p>Press <code>Tab</code> to cycle, or <code>1</code> / <code>2</code> / <code>3</code> to jump. The active tab is underlined.</p>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>View</th><th>Shows</th><th>Primary actions</th></tr>
    </thead>
    <tbody>
      <tr><td><b>Pending</b></td><td>Commands awaiting a decision, one row each, segments color-coded.</td><td><code>a</code> approve · <code>d</code> deny · <code>Del</code> dismiss</td></tr>
      <tr><td><b>Approved</b></td><td>Existing <code>allow</code> rules across scopes, grouped and filterable.</td><td><code>x</code> remove (with confirm)</td></tr>
      <tr><td><b>Denied</b></td><td>Existing <code>deny</code> rules across scopes.</td><td><code>x</code> remove (with confirm)</td></tr>
    </tbody>
  </table>

  <div class="sec-head">
    <p class="lbl">Pending</p>
    <h2>Make a decision.</h2>
    <p>The list stays quiet; the Decision panel below it is the focal surface and carries the accent border. Selecting a row fills the panel with the exact rule you are about to write.</p>
  </div>
<div class="terminal-window">
<div class="terminal-header">
<div class="terminal-dots"><span class="dot dot-close"></span><span class="dot dot-minimize"></span><span class="dot dot-maximize"></span></div>
<div class="terminal-title">tool-gates review</div>
</div>
<div class="terminal-body">
<pre class="tui-screen"> tool-gates · proj    1 pending across 1 project(s)
 Pending 1    Approved 0    Denied 0
┌ Pending · proj ──────────────────────────────────────────────────────────────────────────────────┐
│ › <span class="k">?</span> rm -rf target  &amp;&amp;  <span class="a">✓</span> cargo build   1×                                                        │
│                                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
┌ Decision ────────────────────────────────────────────────────────────────────────────────────────┐
│ ‹<span class="k">?</span> rm -rf target›  &amp;&amp;  <span class="a">✓</span> cargo build                                                             │
│   Recursively force-deletes &lt;path&gt;.                                                              │
│                                                                                                  │
│ Pattern   All "rm" commands   rm:*                                                               │
│ Scope     ‹ This project · shared ›                                                              │
│           → /home/u/proj/.claude/settings.json                                                   │
│ Blast radius  reach   ▰▰▱ everyone on this project                                               │
│               breadth ▰▰▰ every subcommand  <span class="danger">DANGER</span>                                               │
│ i Approving covers the whole command since "cargo" already allowed.                              │
│  a Approve (confirm)     d Deny     Del dismiss                                                  │
│                                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
 ↑↓ move  ←→ pattern  s scope  [ ] seg  a approve  d deny  Del dismiss  Tab view  p project  q quit</pre>
</div>
</div>
  <p class="step-prose">Each segment of a command is prefixed with a glyph and colored by its decision, so the encoding survives a no-color terminal or color blindness:</p>
  <table class="data-table">
    <thead><tr><th>Glyph</th><th>Decision</th><th>Meaning</th></tr></thead>
    <tbody>
      <tr><td><span class="gly gly-allow">&#10003;</span></td><td><b>allow</b></td><td>A gate already permits this segment. No rule needed.</td></tr>
      <tr><td><span class="gly gly-ask">?</span></td><td><b>ask</b></td><td>The segment that needs a decision. This is what a rule would cover.</td></tr>
      <tr><td><span class="gly gly-block">&#10007;</span></td><td><b>block</b></td><td>A hard safety-floor deny. Cannot be approved here.</td></tr>
    </tbody>
  </table>
  <p class="step-prose">For a compound command (<code>&amp;&amp;</code>, <code>||</code>, <code>|</code>, <code>;</code>) the panel shows every segment and underlines the one in focus; <code>[</code> and <code>]</code> step between the actionable ones. The rows beneath are the rule itself:</p>
  <ul class="prose-list">
    <li><b>Pattern</b>: the settings.json pattern that would be written. <code>&larr;</code> / <code>&rarr;</code> cycle from the narrowest form (this exact command) out to the broadest the gate considers safe to suggest. High-stakes programs deliberately offer only the narrow forms.</li>
    <li><b>Scope</b>: where the rule lives. <code>s</code> cycles local &rarr; project &rarr; global; <code>S</code> goes back. The resolved settings-file path is shown beneath, and the global choice is drawn in red because it touches every project on the machine.</li>
    <li><b>Blast radius</b>: the two-axis meter described below.</li>
  </ul>

  <div class="sec-head">
    <p class="lbl">Blast radius</p>
    <h2>The wider the rule, the louder the panel.</h2>
    <p>Two meters score the rule you are about to write. <b>Reach</b> is the scope (just you &rarr; the team &rarr; the whole machine); <b>breadth</b> is the pattern width (one command &rarr; a family &rarr; an entire program). Both fill and redden together, and their combination sets the risk level.</p>
  </div>
  <table class="data-table">
    <thead><tr><th>Risk</th><th>When</th><th>Approve</th></tr></thead>
    <tbody>
      <tr><td><span class="risk-chip risk-safe">safe</span></td><td>One exact command, local, low-stakes program.</td><td>Single keystroke.</td></tr>
      <tr><td><span class="risk-chip risk-caution">caution</span></td><td>Anything wider or farther-reaching, but not yet dangerous.</td><td>Single keystroke.</td></tr>
      <tr><td><span class="risk-chip risk-danger">DANGER</span></td><td>A wide rule applied to every project, a high-stakes tool reaching the whole team, or a whole-program glob over network / exec / destructive commands.</td><td>Requires an explicit <code>y</code> confirm.</td></tr>
    </tbody>
  </table>
  <p class="step-prose">Only <span class="risk-chip risk-danger">DANGER</span> writes demand confirmation. The approve button relabels itself to <code>a Approve (confirm)</code> and pressing <code>a</code> arms an inline prompt; <code>y</code> commits, any other key cancels. This is the anti-rubber-stamp guard: you cannot widen trust to the whole machine by leaning on one key.</p>

  <div class="sec-head">
    <p class="lbl">Approved &amp; Denied</p>
    <h2>Manage the rules you already have.</h2>
    <p>The two rule tabs read your settings files directly. Each row is a live <code>allow</code> or <code>deny</code> rule with its scope; the detail panel explains what removing it does.</p>
  </div>
<div class="terminal-window">
<div class="terminal-header">
<div class="terminal-dots"><span class="dot dot-close"></span><span class="dot dot-minimize"></span><span class="dot dot-maximize"></span></div>
<div class="terminal-title">tool-gates review · Approved</div>
</div>
<div class="terminal-body">
<pre class="tui-screen"> tool-gates · proj    1 pending across 1 project(s)
 Pending 1    Approved 2    Denied 0
┌ Approved · all scopes · 2 ───────────────────────────────────────────────────────────────────────┐
│ › <span class="a">✓</span> cargo:*   global                                                                             │
│   <span class="a">✓</span> git push:*   this project                                                                    │
│                                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
┌ Rule ────────────────────────────────────────────────────────────────────────────────────────────┐
│ <span class="a">✓</span> cargo:*                                                                                        │
│   Allows All "cargo" commands                                                                    │
│                                                                                                  │
│ Scope     global   → ~/.claude/settings.json                                                     │
│                                                                                                  │
│  x Remove    Removing makes these commands prompt again.                                         │
│                                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
 ↑↓ move  ↵/x remove  f scope: all scopes  Tab view  p project  q quit</pre>
</div>
</div>
  <p class="step-prose"><code>f</code> cycles the scope filter (all &rarr; global &rarr; project &rarr; local), so you can isolate, say, only the machine-wide rules. Removing a rule is gated behind the same confirm flow as a dangerous approval, so an accidental <code>x</code> while navigating never deletes anything:</p>
<div class="terminal-window">
<div class="terminal-header">
<div class="terminal-dots"><span class="dot dot-close"></span><span class="dot dot-minimize"></span><span class="dot dot-maximize"></span></div>
<div class="terminal-title">tool-gates review · confirm remove</div>
</div>
<div class="terminal-body">
<pre class="tui-screen"> tool-gates · proj    1 pending across 1 project(s)
 Pending 1    Approved 0    Denied 0
┌ Approved · all scopes · 1 ───────────────────────────────────────────────────────────────────────┐
│ › <span class="a">✓</span> cargo:*   global                                                                             │
│                                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
┌ Rule ────────────────────────────────────────────────────────────────────────────────────────────┐
│ <span class="a">✓</span> cargo:*                                                                                        │
│   Allows All "cargo" commands                                                                    │
│                                                                                                  │
│ Scope     global   → ~/.claude/settings.json                                                     │
│                                                                                                  │
│ ⚠ Remove approval cargo:* (global)    y confirm   any other key cancels                          │
│                                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
 y confirm    esc cancel</pre>
</div>
</div>
  <p class="note">
    <svg class="alert" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
    <span><b>Removal edits real settings files.</b> A global rule in the Approved or Denied view lives in <code>~/.claude/settings.json</code>; removing it there affects every project on the machine. The confirm prompt names the scope so you see the reach before committing.</span>
  </p>

  <div class="sec-head">
    <p class="lbl">Projects</p>
    <h2>Switch without leaving the queue.</h2>
    <p>Press <code>p</code> for an overlay of every project with pending commands, grouped by parent directory like a folder tree. Pick one to scope the views to it, or choose <b>All projects</b> to see everything at once.</p>
  </div>
<div class="terminal-window">
<div class="terminal-header">
<div class="terminal-dots"><span class="dot dot-close"></span><span class="dot dot-minimize"></span><span class="dot dot-maximize"></span></div>
<div class="terminal-title">tool-gates review · switch project</div>
</div>
<div class="terminal-body">
<pre class="tui-screen"> tool-gates · gamma    3 pending across 3 project(s)
 Pending 1    Approved 0    Denied 0
┌ Pending · gamma ─────────────────────────────────────────────────────────────────────────────────┐
│ › <span class="k">?</span> go test ./...   1×                                                                           │
│                                                                                                  │
│                      ┌ Switch project ────────────────────────────────────┐                      │
│                      │ /srv/projects/                                     │                      │
│                      │     alpha (1)                                      │                      │
└──────────────────────│     beta (1)                                       │──────────────────────┘
┌ Decision ────────────│ /srv/work/                                         │──────────────────────┐
│ <span class="k">?</span> go test ./...      │   › gamma (1)                                      │                      │
│   Recursively force-d│   ───────                                          │                      │
│                      │   All projects (3)                                 │                      │
│ Pattern   All "go tes└────────────────────────────────────────────────────┘                      │
│ Scope     ‹ This project · shared ›                                                              │
│           → /srv/work/gamma/.claude/settings.json                                                │
│ Blast radius  reach   ▰▰▱ everyone on this project                                               │
│               breadth ▰▰▱ a family of commands                                                   │
│  a Approve     d Deny     Del dismiss                                                            │
│                                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
 ↑↓ move  ←→ pattern  s scope  a approve  d deny  Del dismiss  Tab view  p project  q quit</pre>
</div>
</div>

  <div class="sec-head">
    <p class="lbl">Keys</p>
    <h2>One key, one meaning.</h2>
    <p>Arrows always move within the active list. There is no panel-focus mode to track; the same key does the same thing wherever you are.</p>
  </div>
  <table class="data-table">
    <thead><tr><th>Key</th><th>Action</th><th>Where</th></tr></thead>
    <tbody>
      <tr><td>&uarr; &darr; · j / k</td><td>Move within the active list</td><td>everywhere</td></tr>
      <tr><td>Tab · &#8679;Tab</td><td>Cycle views; <code>1</code> / <code>2</code> / <code>3</code> jump direct</td><td>everywhere</td></tr>
      <tr><td>p</td><td>Open the project switcher</td><td>everywhere</td></tr>
      <tr><td>&larr; &rarr; · h / l</td><td>Cycle the pattern (narrow &harr; broad)</td><td>Pending</td></tr>
      <tr><td>s · S</td><td>Cycle the scope forward / back</td><td>Pending</td></tr>
      <tr><td>[ · ]</td><td>Step between segments of a compound command</td><td>Pending</td></tr>
      <tr><td>a · Enter</td><td>Approve the selected command (arms a confirm if dangerous)</td><td>Pending</td></tr>
      <tr><td>d</td><td>Deny (writes a <code>deny</code> rule)</td><td>Pending</td></tr>
      <tr><td>Del · x</td><td>Dismiss the row from the queue (no rule written)</td><td>Pending</td></tr>
      <tr><td>f</td><td>Cycle the scope filter</td><td>Approved / Denied</td></tr>
      <tr><td>x · Enter</td><td>Remove the selected rule (with confirm)</td><td>Approved / Denied</td></tr>
      <tr><td>y</td><td>Confirm an armed action; any other key cancels</td><td>confirm prompt</td></tr>
      <tr><td>u</td><td>Undo the last write, dismiss, or removal</td><td>everywhere</td></tr>
      <tr><td>q · Esc</td><td>Quit</td><td>everywhere</td></tr>
    </tbody>
  </table>
  <p class="note">
    <svg class="alert" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
    <span><b>Only human approvals queue.</b> Under auto mode the classifier decides silently; nothing it approves reaches <code>pending.jsonl</code>. The queue stays focused on the patterns you explicitly clicked through. Prefer the command line? <code>tool-gates pending list</code>, <code>tool-gates approve</code>, and <code>tool-gates rules remove</code> do the same writes without the TUI. See the <a href="approval-learning.html">Approval Learning</a> and <a href="cli.html">CLI Reference</a> pages.</span>
  </p>

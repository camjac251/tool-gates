  <p class="breadcrumb"><a href="index.html">Core Concepts</a> / Auto Mode</p>
  <h1 id="auto-h1">Auto Mode</h1>
  <p class="page-lede">When Claude Code runs in <code>auto</code> permission mode, a server-side classifier decides <code>ask</code> calls instead of prompting. tool-gates layers in as a deterministic pre-filter and safety floor: hard denies stay hard, allows skip the classifier, and only genuinely ambiguous calls reach the classifier.</p>
  <div class="sec-head" style="margin-top: var(--s-6)">
    <p class="lbl">Decision matrix</p>
    <h2>What the classifier sees.</h2>
    <p>tool-gates decides first. Only asks pass through to the classifier; allows and denies short-circuit.</p>
  </div>
  <div class="triad">
    <article class="triad-card allow">
      <h3>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" width="14" height="14"><polyline points="20 6 9 17 4 12"></polyline></svg>
        Allow
      </h3>
      <p>Classifier skipped. The action executes immediately.</p>
      <span class="ex">git status, cargo check</span>
    </article>
    <article class="triad-card ask">
      <h3>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" width="14" height="14"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>
        Ask
      </h3>
      <p>Classifier runs and decides allow or deny silently.</p>
      <span class="ex">cargo install foo</span>
    </article>
    <article class="triad-card block">
      <h3>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" width="14" height="14"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>
        Deny
      </h3>
      <p>Hard floor. Classifier bypassed entirely.</p>
      <span class="ex">rm -rf /, curl | bash</span>
    </article>
  </div>
  <div class="sec-head">
    <p class="lbl">What changes</p>
    <h2>Auto mode strengthens the floor.</h2>
    <p>The deterministic rules tighten in four places, plus two ergonomic additions.</p>
  </div>
  <div class="hook-cards">
    <article class="hook-card">
      <h4>Pipe-to-shell escalates</h4>
      <p>Patterns like <code>curl … | bash</code> and <code>eval "…"</code> escalate from <code>ask</code> to <code>deny</code> under auto mode. No legitimate use case in autonomous operation; the classifier doesn't get a vote.</p>
    </article>
    <article class="hook-card">
      <h4>acceptEdits fast path is not trusted</h4>
      <p>Claude's hardcoded <code>acceptEdits</code> Bash allow list includes <code>rm</code>, <code>rmdir</code>, <code>mv</code>, <code>cp</code>, <code>touch</code>. Under auto mode tool-gates owns the decision instead. Path-aware allows like <code>mkdir -p src/components</code> and <code>sed -i … file</code> still succeed; unapproved hardcoded bases deny before Claude's fast path can approve them.</p>
    </article>
    <article class="hook-card">
      <h4>Pending queue stays human-only</h4>
      <p>The classifier decides silently; nothing it approves goes into <code>pending.jsonl</code>. The approval-learning review queue contains only patterns you explicitly clicked through.</p>
    </article>
    <article class="hook-card">
      <h4>Classifier denials get retry hints</h4>
      <p>If the classifier denies a call tool-gates would have allowed (e.g. <code>cargo check</code>), the <code>PermissionDenied</code> hook returns <code>retry: true</code> and the model takes another shot.</p>
    </article>
    <article class="hook-card">
      <h4>Skill auto-approval still fires</h4>
      <p><code>[[auto_approve_skills]]</code> rules are explicit trust declarations and aren't revoked by opting into the classifier.</p>
    </article>
    <article class="hook-card">
      <h4>Configure via settings.json</h4>
      <p>The classifier itself is configured via <code>autoMode.{allow, soft_deny, hard_deny, environment}</code> in <code>settings.json</code>. Inspect merged config with <code>claude auto-mode config</code> (also <code>defaults</code> and <code>critique</code>).</p>
    </article>
  </div>
  <p class="note">
    <svg class="alert" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
    <span><b>Requires Claude Code 2.1.88+</b> for the <code>PermissionDenied</code> retry hook. Earlier auto-mode-capable builds still get the deny promotion, pattern narrowing, and pending-queue guard. The retry hint is the only version-gated feature.</span>
  </p>

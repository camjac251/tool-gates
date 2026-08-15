<div class="gate-head">
  <nav class="breadcrumb" aria-label="Breadcrumb">
    <ol>
      <li><a href="../index.html">tool-gates</a></li>
      <li aria-current="page">Gates</li>
    </ol>
  </nav>
  <h1>All gates</h1>

  <section class="summary" aria-label="Rule counts across every gate">
    <div class="seg-bar" role="img" aria-label="1083 allow, 1047 ask, 49 block">
      <div class="seg allow" style="flex: 1083"></div>
      <div class="seg ask"   style="flex: 1047"></div>
      <div class="seg block" style="flex: 49"></div>
    </div>
    <div class="counts">
      <span class="ca"><i></i><b>1083</b> allow</span>
      <span class="cas"><i></i><b>1047</b> ask</span>
      <span class="cb"><i></i><b>49</b> block</span>
    </div>
  </section>

  <p class="gate-lede">Thirteen gates resolve every shell command tool-gates sees. Each page below is generated from its <code>rules/*.toml</code> source, so what you read here is the rule set the engine actually runs. Gates are listed alphabetically; the <b>priority</b> column is the order the engine tries them, and <code>basics</code> always runs last.</p>
</div>

<ul class="gate-index">

<li><a class="gate-card" href="basics.html">
  <span class="gc-name">Basic Utilities</span>
  <span class="gc-count gc-count-empty">catch&#8209;all<span class="sr-only">, no per-program rules</span></span>
  <span class="gc-prio">100<span class="sr-only"> priority</span></span>
  <span class="gc-desc">The default-safe list. No per-program rules: one allowlist of read-only utilities, and anything unrecognized falls through to the client.</span>
</a></li>

<li><a class="gate-card" href="beads.html">
  <span class="gc-name">Beads Tracker (bd)</span>
  <span class="gc-count">220<span class="sr-only"> rules</span></span>
  <span class="gc-prio">22<span class="sr-only"> priority</span></span>
  <span class="gc-desc">Git-native issue tracker. Reads are safe, writes ask. Nothing is hard-blocked, because every state mutation is recoverable through git.</span>
</a></li>

<li><a class="gate-card" href="cloud.html">
  <span class="gc-name">Cloud Providers</span>
  <span class="gc-count">419<span class="sr-only"> rules</span></span>
  <span class="gc-prio">15<span class="sr-only"> priority</span></span>
  <span class="gc-desc">Cloud CLIs and container orchestration: AWS, GCP, Azure, Kubernetes, Docker, Terraform.</span>
</a></li>

<li><a class="gate-card" href="devtools.html">
  <span class="gc-name">Development Tools</span>
  <span class="gc-count">165<span class="sr-only"> rules</span></span>
  <span class="gc-prio">25<span class="sr-only"> priority</span></span>
  <span class="gc-desc">Tools that can modify files. Linters and type checkers inspect by default and ask once a write flag appears.</span>
</a></li>

<li><a class="gate-card" href="filesystem.html">
  <span class="gc-name">Filesystem Operations</span>
  <span class="gc-count">22<span class="sr-only"> rules</span></span>
  <span class="gc-prio">30<span class="sr-only"> priority</span></span>
  <span class="gc-desc">Everything that touches disk. Small, and the densest block floor per rule of any gate.</span>
</a></li>

<li><a class="gate-card" href="git.html">
  <span class="gc-name">Git</span>
  <span class="gc-count">106<span class="sr-only"> rules</span></span>
  <span class="gc-prio">10<span class="sr-only"> priority</span></span>
  <span class="gc-desc">History and inspection pass through. Writes to the tree, the index, or a remote pause for approval. Never hard-blocked here.</span>
</a></li>

<li><a class="gate-card" href="gh.html">
  <span class="gc-name">GitHub CLI</span>
  <span class="gc-count">134<span class="sr-only"> rules</span></span>
  <span class="gc-prio">10<span class="sr-only"> priority</span></span>
  <span class="gc-desc">Listing, viewing, searching, and the read API are safe. Mutations ask. Repository deletion is hard-blocked.</span>
</a></li>

<li><a class="gate-card" href="runtimes.html">
  <span class="gc-name">Language Runtimes</span>
  <span class="gc-count">85<span class="sr-only"> rules</span></span>
  <span class="gc-prio">27<span class="sr-only"> priority</span></span>
  <span class="gc-desc">Version and syntax-check flags are safe. Anything that executes code asks first.</span>
</a></li>

<li><a class="gate-card" href="network.html">
  <span class="gc-name">Network &amp; HTTP</span>
  <span class="gc-count">39<span class="sr-only"> rules</span></span>
  <span class="gc-prio">35<span class="sr-only"> priority</span></span>
  <span class="gc-desc">GET requests and head checks pass through. Mutating, downloading, and interactive calls pause for approval.</span>
</a></li>

<li><a class="gate-card" href="package_managers.html">
  <span class="gc-name">Package Managers</span>
  <span class="gc-count">453<span class="sr-only"> rules</span></span>
  <span class="gc-prio">20<span class="sr-only"> priority</span></span>
  <span class="gc-desc">Listing, inspecting, and auditing are safe. Installing, removing, publishing, and running arbitrary scripts ask.</span>
</a></li>

<li><a class="gate-card" href="shortcut.html">
  <span class="gc-name">Shortcut CLI</span>
  <span class="gc-count">30<span class="sr-only"> rules</span></span>
  <span class="gc-prio">45<span class="sr-only"> priority</span></span>
  <span class="gc-desc">Community issue-tracker CLI. Reads are safe, story and epic mutations ask.</span>
</a></li>

<li><a class="gate-card" href="system.html">
  <span class="gc-name">System Commands</span>
  <span class="gc-count">497<span class="sr-only"> rules</span></span>
  <span class="gc-prio">40<span class="sr-only"> priority</span></span>
  <span class="gc-desc">OS-level operations: power, disk, kernel modules, firewall, users, database clients, crypto. The largest block floor of any gate.</span>
</a></li>

<li><a class="gate-card" href="tool_gates.html">
  <span class="gc-name">Tool Gates CLI</span>
  <span class="gc-count">17<span class="sr-only"> rules</span></span>
  <span class="gc-prio">23<span class="sr-only"> priority</span></span>
  <span class="gc-desc">tool-gates protects itself. Read-only queries skip prompting; writes to settings files ask.</span>
</a></li>

</ul>

<p class="gate-index-foot">Counts come from the generated pages and move with <code>rules/*.toml</code>. To change what a gate decides, edit the TOML and rebuild &mdash; see <a href="../contributing.html">Contributing</a>.</p>

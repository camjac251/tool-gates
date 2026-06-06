  <p class="breadcrumb"><a href="index.html">Development</a> / Custom Handlers</p>
  <h1 id="handlers-h1">Custom Handlers</h1>
  <p class="page-lede">Each handler is a Rust function called by the gate when declarative TOML can't express the rule. The TOML declares <code>[[custom_handlers]]</code> with a program and handler name; the gate's Rust file implements the handler. Listed by gate.</p>
  <div class="sec-head" style="margin-top: var(--s-6)">
    <p class="lbl">filesystem</p>
    <h2>Path-aware logic.</h2>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>Program</th><th>Handler</th><th>What it does</th></tr>
    </thead>
    <tbody>
      <tr><td><code>rm</code></td><td><code>check_rm</code></td><td>Normalises paths (<code>//</code> → <code>/</code>, <code>/.</code> → <code>/</code>); blocks destructive targets (<code>/</code>, <code>~/</code>); flags traversal patterns (<code>..</code>, <code>../</code>, bare <code>*</code>) with ask-and-warn.</td></tr>
      <tr><td><code>tar</code></td><td><code>check_tar</code></td><td>Decodes combined flags (<code>-tvf</code>, <code>-xf</code>, <code>-cf</code>); allows list mode, asks for extract/create.</td></tr>
    </tbody>
  </table>
  <div class="sec-head">
    <p class="lbl">network</p>
    <h2>Method and flag dispatch.</h2>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>Program</th><th>Handler</th><th>What it does</th></tr>
    </thead>
    <tbody>
      <tr><td><code>curl</code></td><td><code>check_curl</code></td><td>Detects HTTP method from <code>-X</code>/<code>--request</code>, presence of <code>-d</code>/<code>--data</code>, and download flags <code>-o</code>/<code>-O</code>. Routes GET to allow, mutations and downloads to ask. Also asks on GitHub content URLs (hint nudges toward <code>gh api</code>).</td></tr>
      <tr><td><code>nc</code></td><td><code>check_netcat</code></td><td>Hard-blocks <code>-e</code> (reverse shell); asks on <code>-l</code> (listen mode); applies the same rules to <code>ncat</code> and <code>netcat</code> aliases.</td></tr>
      <tr><td><code>wget</code></td><td><code>check_wget</code></td><td>Allows <code>--spider</code> (URL-resolves only); asks on downloads, recursive modes, post bodies.</td></tr>
      <tr><td><code>http</code> / <code>xh</code></td><td><code>check_httpie</code></td><td>Allows GET (URL-only or <code>GET</code> verb); asks on POST / PUT / DELETE / PATCH.</td></tr>
      <tr><td><code>rsync</code></td><td><code>check_rsync</code></td><td>Allows <code>--dry-run</code> / <code>-n</code>; asks on actual syncs (with <code>--delete</code> noted in the reason).</td></tr>
    </tbody>
  </table>
  <div class="sec-head">
    <p class="lbl">cloud</p>
    <h2>Multi-word subcommand patterns.</h2>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>Program</th><th>Handler</th><th>What it does</th></tr>
    </thead>
    <tbody>
      <tr><td><code>gcloud</code></td><td><code>check_gcloud</code></td><td>Three-word subcommand routing (<code>gcloud compute instances create</code>). Allows <code>list</code> / <code>describe</code> / <code>get</code> actions; asks on <code>create</code> / <code>delete</code> / <code>update</code> / <code>deploy</code>.</td></tr>
      <tr><td><code>docker</code></td><td><code>check_docker</code></td><td>Handles <code>docker compose</code> with flags between the subcommand (e.g. <code>docker compose -f x.yml config</code>).</td></tr>
    </tbody>
  </table>
  <div class="sec-head">
    <p class="lbl">system</p>
    <h2>SQL parsing, prefix matching.</h2>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>Program</th><th>Handler</th><th>What it does</th></tr>
    </thead>
    <tbody>
      <tr><td><code>sudo</code></td><td><code>check_sudo</code></td><td>Extracts the underlying command and asks with a descriptive reason naming the inner program. <code>-l</code> / <code>-v</code> / <code>-k</code> allow without execution.</td></tr>
      <tr><td><code>systemctl</code></td><td><code>check_systemctl</code></td><td>Checks for read-only ops (status, list-units, is-active, etc.) before falling back to declarative rules.</td></tr>
      <tr><td><code>apt</code> / <code>dnf</code> / <code>brew</code></td><td><code>check_apt</code>, <code>check_dnf</code>, <code>check_brew</code></td><td>Each package manager has its own handler that checks read-only subcommands (search, list, show, info) before falling back to declarative rules.</td></tr>
      <tr><td><code>pacman</code></td><td><code>check_pacman</code></td><td>Prefix matching on <code>-S</code> (sync), <code>-R</code> (remove), <code>-U</code> (upgrade), <code>-D</code> (database).</td></tr>
      <tr><td><code>make</code></td><td><code>check_make</code></td><td>Allows known-safe targets (test, check, lint, build, clean, format); asks for unknown targets with the target name in the reason.</td></tr>
      <tr><td><code>psql</code> / <code>mysql</code></td><td><code>check_psql</code>, <code>check_mysql</code></td><td>Parses <code>-c</code> / <code>-e</code> query strings; allows SELECT / SHOW / <code>\d</code>; asks on INSERT / UPDATE / DELETE. <code>-f</code> always asks (file content unknown).</td></tr>
      <tr><td><code>kill</code> / <code>pkill</code></td><td><code>check_kill</code>, <code>check_pkill</code></td><td>Allows <code>-0</code> (process-exists check) and <code>-l</code> / <code>-L</code> (list signals). Anything else asks.</td></tr>
      <tr><td><code>crontab</code></td><td><code>check_crontab</code></td><td>Allows <code>-l</code> (list scheduled tasks); asks on edit or write operations.</td></tr>
    </tbody>
  </table>
  <div class="sec-head">
    <p class="lbl">basics, package_managers, others</p>
    <h2>Inner-command checking, wrapper resolution.</h2>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>Program</th><th>Handler</th><th>What it does</th></tr>
    </thead>
    <tbody>
      <tr><td><code>xargs</code></td><td><code>check_xargs</code></td><td>Allows only when the target command is itself in <code>safe_commands</code>; otherwise asks. Also handles <code>xargs sh -c '…'</code> by parsing the inner script.</td></tr>
      <tr><td><code>bash</code> / <code>sh</code> / <code>zsh</code></td><td><code>check_shell_c</code></td><td>Parses <code>-c '…'</code> arguments and runs each inner command through the gate engine.</td></tr>
      <tr><td><code>command</code></td><td><code>check_command_builtin</code></td><td>Allows <code>command -v</code> / <code>-V</code> (lookup only). Evaluates other invocations through the gate engine as transparent wrappers.</td></tr>
      <tr><td><code>sd</code></td><td><code>check_sd</code></td><td>Without file args, sd is a stdin→stdout pipe (safe). With file args, it modifies in place (ask).</td></tr>
      <tr><td><code>npm</code> / <code>pnpm</code> / <code>yarn</code> / <code>bun</code></td><td><code>check_npm</code>, etc.</td><td>Handles devtool delegation (<code>npm eslint</code>, <code>pnpm biome</code>) by routing to the devtools gate. Bare <code>yarn</code> resolves to <code>yarn install</code>.</td></tr>
      <tr><td><code>uv</code> / <code>poetry</code> / <code>pipx</code> / <code>mise</code></td><td><code>check_uv</code>, etc.</td><td>Routes <code>uv run &lt;tool&gt;</code> / <code>poetry run &lt;tool&gt;</code> / <code>mise exec &lt;tool&gt;</code> through the devtools gate. Mise task expansion adds another layer.</td></tr>
      <tr><td><code>git</code></td><td><code>extract_subcommand</code>, <code>check_git_add</code></td><td>Strips global flags (<code>-C</code>, <code>--git-dir</code>, <code>-c</code>) to find the real subcommand. <code>check_git_add</code> handles <code>git add -A</code> / <code>--all</code> / <code>.</code> / wildcard with extra care.</td></tr>
      <tr><td><code>short</code></td><td><code>check_short_api</code></td><td>For <code>short api</code>: allows GET, asks POST / PUT / PATCH / DELETE.</td></tr>
    </tbody>
  </table>
  <p class="note">
    <svg class="alert" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
    <span><b>The generated gate function returns <code>Skip</code> for any program with a custom handler.</b> The Rust wrapper file then takes over. Without that wiring the handler never fires; see the <a href="contributing.html">Contributing</a> page for the pattern.</span>
  </p>

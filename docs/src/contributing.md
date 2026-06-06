  <p class="breadcrumb"><a href="index.html">Development</a> / Contributing</p>
  <h1 id="contrib-h1">Contributing</h1>
  <p class="page-lede">Adding a rule to an existing gate is usually a single TOML edit. Adding a new gate also needs a small Rust file. The build pipeline picks up TOML changes automatically; the generator in <code>build.rs</code> emits the Rust gate function from the TOML on every build.</p>
  <div class="sec-head" style="margin-top: var(--s-6)">
    <p class="lbl">Adding a tool to an existing gate</p>
    <h2>Edit the TOML. Done.</h2>
  </div>
  <p class="step-prose">Simplest case: add <code>shellcheck</code> to <code>devtools.toml</code> as always-safe.</p>
<pre class="code-block"><span class="comment"># rules/devtools.toml</span>
<span class="sec">[[programs]]</span>
<span class="k">name</span>           = <span class="s">"shellcheck"</span>
<span class="k">unknown_action</span> = <span class="s">"allow"</span>  <span class="comment"># always safe (read-only)</span></pre>
  <p class="step-prose">Then <code>cargo build --release</code>. Done. Flag-conditional behavior:</p>
<pre class="code-block"><span class="comment"># rules/devtools.toml</span>
<span class="sec">[[programs]]</span>
<span class="k">name</span>           = <span class="s">"prettier"</span>
<span class="k">unknown_action</span> = <span class="s">"allow"</span>
<span class="sec">[[programs.ask]]</span>
<span class="k">reason</span>        = <span class="s">"Writing formatted files"</span>
<span class="k">if_flags_any</span>  = [<span class="s">"--write"</span>, <span class="s">"-w"</span>]</pre>
  <div class="sec-head">
    <p class="lbl">TOML schema</p>
    <h2>Root-level fields.</h2>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>Field</th><th>Description</th></tr>
    </thead>
    <tbody>
      <tr><td><code>meta</code></td><td>Rule metadata (priority, lede, behavior tags, custom card titles).</td></tr>
      <tr><td><code>[[programs]]</code></td><td>An array of program-specific rules.</td></tr>
      <tr><td><code>safe_commands</code></td><td>An array of always-allowed command names (read-only command list).</td></tr>
      <tr><td><code>[[conditional_allow]]</code></td><td>Conditional rules that allow or gate a program based on flag presence.</td></tr>
      <tr><td><code>[[custom_handlers]]</code></td><td>Declares Rust function overrides for complex CLI logic.</td></tr>
      <tr><td><code>[[command_groups]]</code></td><td>Docs-only command groupings for Basics gate grid categorization.</td></tr>
    </tbody>
  </table>

  <div class="sec-head">
    <p class="lbl">TOML schema</p>
    <h2>Program-level fields (under <code>[[programs]]</code>).</h2>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>Field</th><th>Description</th></tr>
    </thead>
    <tbody>
      <tr><td><code>name</code></td><td>Program binary name as it appears on PATH.</td></tr>
      <tr><td><code>aliases</code></td><td>Alternative names. Example: <code>["podman"]</code> aliased to docker.</td></tr>
      <tr><td><code>unknown_action</code></td><td>What to do for unrecognised subcommands. One of <code>allow</code>, <code>ask</code>, <code>skip</code>, <code>block</code>.</td></tr>
      <tr><td><code>default_allow</code></td><td>Boolean indicating if the command is allowed by default.</td></tr>
      <tr><td><code>reason</code></td><td>Docs-only reason for <code>unknown_action = "allow"</code> programs.</td></tr>
      <tr><td><code>[[programs.allow]]</code></td><td>Rules that allow execution. Conditions are optional.</td></tr>
      <tr><td><code>[[programs.ask]]</code></td><td>Rules that ask the user for approval. <code>reason</code> is required.</td></tr>
      <tr><td><code>[[programs.block]]</code></td><td>Rules that block execution. <code>reason</code> is required.</td></tr>
      <tr><td><code>[[programs.allow_if_flags]]</code></td><td>List of flags that automatically allow execution.</td></tr>
      <tr><td><code>[programs.api_rules]</code></td><td>Custom HTTP API endpoint routing rules (e.g. safe methods, endpoint prefixes).</td></tr>
    </tbody>
  </table>

  <div class="sec-head">
    <p class="lbl">Rule conditions</p>
    <h2>How rules match (under allow/ask/block rules).</h2>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>Field</th><th>Description</th></tr>
    </thead>
    <tbody>
      <tr><td><code>subcommand</code></td><td>Match a specific subcommand string. Example: <code>"pr list"</code>.</td></tr>
      <tr><td><code>subcommands</code></td><td>Match any of the listed subcommands.</td></tr>
      <tr><td><code>subcommand_prefix</code></td><td>Match a subcommand prefix. Example: <code>"describe"</code> matches <code>describe-instances</code>, <code>describe-volumes</code>, etc.</td></tr>
      <tr><td><code>action_prefix</code></td><td>Match a prefix on <code>args[1]</code>. Used for AWS-style <code>describe-*</code> / <code>list-*</code> / <code>create-*</code> patterns.</td></tr>
      <tr><td><code>if_flags_any</code></td><td>Apply the rule only if any listed flag is present.</td></tr>
      <tr><td><code>unless_flags</code></td><td>Apply the rule unless any listed flag is present.</td></tr>
      <tr><td><code>if_args_contain</code></td><td>Apply the rule if args contain any listed string. Used for path-aware blocks.</td></tr>
      <tr><td><code>unless_args_contain</code></td><td>Apply the rule unless args contain any listed string.</td></tr>
      <tr><td><code>warn</code></td><td>On <code>[[programs.ask]]</code>: mark as dangerous-but-recoverable. Surfaces on the <a href="security-floor.html">Security floor</a> page.</td></tr>
      <tr><td><code>accept_edits_auto_allow</code></td><td>On <code>[[programs.ask]]</code>: auto-allow this program when the session is in <code>acceptEdits</code> mode.</td></tr>
    </tbody>
  </table>
  <div class="sec-head">
    <p class="lbl">Custom handlers</p>
    <h2>When TOML can't express it.</h2>
    <p>Some logic doesn't fit declarative TOML: path normalisation (rm against <code>/</code> or <code>~/</code>), method-aware HTTP routing (gh api), shell-script inner-command checking (bash -c). For those, write a Rust handler.</p>
  </div>
<pre class="code-block"><span class="comment"># rules/devtools.toml</span>
<span class="sec">[[custom_handlers]]</span>
<span class="k">program</span>     = <span class="s">"ruff"</span>
<span class="k">handler</span>     = <span class="s">"check_ruff"</span>
<span class="k">description</span> = <span class="s">"ruff format asks unless --check or --diff present"</span></pre>
  <p class="step-prose">Then implement <code>check_ruff</code> in the gate file. The generated gate returns <code>Skip</code> for this program, letting the custom handler take over.</p>
  <div class="sec-head">
    <p class="lbl">Adding a new gate</p>
    <h2>Three steps.</h2>
    <p>For a new category of tools that doesn't fit an existing gate.</p>
  </div>
  <p class="step-prose"><b>1. Create <code>rules/newgate.toml</code>.</b> Pick a priority that slots in correctly; lower runs first, basics at 100 is always last.</p>
<pre class="code-block"><span class="sec">[meta]</span>
<span class="k">name</span>        = <span class="s">"newgate"</span>
<span class="k">description</span> = <span class="s">"New category of tools"</span>
<span class="k">priority</span>    = <span class="s">50</span>
<span class="sec">[[programs]]</span>
<span class="k">name</span>           = <span class="s">"newtool"</span>
<span class="k">unknown_action</span> = <span class="s">"ask"</span>
<span class="sec">[[programs.allow]]</span>
<span class="k">subcommand</span> = <span class="s">"list"</span>
<span class="sec">[[programs.ask]]</span>
<span class="k">subcommand</span> = <span class="s">"create"</span>
<span class="k">reason</span>     = <span class="s">"Creating resource"</span></pre>
  <p class="step-prose"><b>2. Create <code>src/gates/newgate.rs</code>.</b> Thin wrapper around the generated function.</p>
<pre class="code-block"><span class="k">use</span> <span class="s">crate::generated::rules::check_newgate_gate</span>;
<span class="k">use</span> <span class="s">crate::models::{CommandInfo, GateResult}</span>;
<span class="k">pub fn</span> <span class="sec">check_newgate</span>(cmd: <span class="k">&amp;</span>CommandInfo) <span class="k">-&gt;</span> GateResult {
    check_newgate_gate(cmd)
}</pre>
  <p class="step-prose"><b>3. Register in <code>src/gates/mod.rs</code>.</b> Add to the <code>GATES</code> array in priority order.</p>
<pre class="code-block"><span class="k">mod</span> newgate;
<span class="k">pub use</span> newgate::check_newgate;
<span class="k">pub static</span> GATES: <span class="k">&amp;</span>[(<span class="k">&amp;</span><span class="s">str</span>, GateCheckFn)] = <span class="k">&amp;</span>[
    <span class="comment">// … other gates …</span>
    (<span class="s">"newgate"</span>, check_newgate),
    (<span class="s">"basics"</span>, check_basics), <span class="comment">// basics last</span>
];</pre>
  <div class="sec-head">
    <p class="lbl">Simulator</p>
    <h2>WebAssembly compilation.</h2>
    <p>The Try page runs a local simulator powered by a WebAssembly build of the gate engine. The compilation uses the <code>release-wasm</code> profile, the <code>wasm32-unknown-unknown</code> target, and compiles only the library target with the <code>wasm</code> feature enabled.</p>
  </div>
  <p class="step-prose"><b>1. Build via mise.</b> The project uses a mise task to build the WebAssembly module. It compiles the Rust codebase and uses Zig CC via a wrapper script to compile the C-based tree-sitter parser without requiring a manual clang/WASI-sdk installation. Run the following command:</p>
<pre class="code-block"><span class="prompt">$</span> mise run build-wasm</pre>
  <p class="step-prose">This compiles the target, runs <code>wasm-bindgen</code> to generate bindings in <code>docs/src/wasm/</code>, and runs <code>wasm-opt</code> with the bulk memory feature enabled to optimize the output size.</p>

  <div class="sec-head">
    <p class="lbl">Testing</p>
    <h2>Test rules.</h2>
  </div>
  <table class="data-table">
    <thead>
      <tr><th>Rule</th><th>Why</th></tr>
    </thead>
    <tbody>
      <tr><td>No real-world data in tests</td><td>Generic placeholders only (<code>mytool</code>, <code>$HOME/scripts/deploy/</code>, <code>my-service</code>). Tests are committed to a public repo; never leak usage patterns or personal workflows.</td></tr>
      <tr><td>CI portability</td><td>Don't assume specific modern CLI tools (rg, bat, fd) are installed. CI runners have minimal environments. Detect tool availability at runtime and skip gracefully.</td></tr>
      <tr><td>Serde output verification</td><td>Any struct serialized to JSON for Claude Code needs a test asserting exact field casing. The CLI expects camelCase. Use <code>serde_json::to_string</code> and assert key names.</td></tr>
    </tbody>
  </table>
  <p class="note">
    <svg class="alert" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
    <span><b>Read the <a href="reason-style.html">Reason style guide</a> before writing new <code>reason</code> strings.</b> The 250-char limit, no-em-dashes rule, and authorization-hedge ban are enforced by <code>build.rs</code> and by code review.</span>
  </p>

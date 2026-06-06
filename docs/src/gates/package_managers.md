<div class="gate-head">
  <p class="breadcrumb"><a href="../index.html">Gates</a> / Package Managers</p>
  <h1>Package Managers gate</h1>
  <div class="gate-meta">
    <span class="tag">priority <b>20</b></span>
    <span class="tag">unknown <b>ask</b></span>
    <span class="tag">covers <b>npm · pnpm · yarn · bun · pip · uv · cargo · go · poetry · pipx · conda · mise</b></span>
  </div>

  <div class="summary" aria-label="Rule counts at a glance">
    <div class="seg-bar" role="img" aria-label="228 allow, 205 ask, 0 block">
      <div class="seg allow" style="flex: 228"></div>
      <div class="seg ask"   style="flex: 205"></div>
      <div class="seg block" style="flex: 0"></div>
    </div>
    <div class="counts">
      <span class="ca"><i></i><b>228</b> allow</span>
      <span class="cas"><i></i><b>205</b> ask</span>
      <span class="cb"><i></i><b>0</b> block</span>
    </div>
  </div>

  <p class="gate-lede">Language package managers. Listing, inspecting, and auditing are safe. Installing, removing, publishing, and running arbitrary scripts ask. No hard blocks at this layer (the dangerous floor is filesystem-level).</p>
</div>

<div class="chips" role="group" aria-label="Filter rules by decision">
  <button class="chip all"   data-filter="all"   aria-pressed="true"><i></i>All <span class="n">433</span></button>
  <button class="chip allow" data-filter="allow" aria-pressed="false"><i></i>Allow <span class="n">228</span></button>
  <button class="chip ask"   data-filter="ask"   aria-pressed="false"><i></i>Ask <span class="n">205</span></button>
  <button class="chip block" data-filter="block" aria-pressed="false"><i></i>Block <span class="n">0</span></button>
</div>

<div class="rule-card">
  <header>
    <h2>Allowed · inspection</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/package_managers.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/package_managers.toml#allow
    </a>
    <span class="count">228 patterns</span>
  </header>

<div class="rule-row" data-decision="allow" id="package_managers-bun-pm">
  <div class="rule-cmd"><span class="prog">bun</span> pm</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspects bun's package manager state (ls, cache dir, bin path, hash). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-bun-v">
  <div class="rule-cmd"><span class="prog">bun</span> -v</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the bun version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-bun-version">
  <div class="rule-cmd"><span class="prog">bun</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the bun version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-bun-h">
  <div class="rule-cmd"><span class="prog">bun</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints bun help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-bun-help">
  <div class="rule-cmd"><span class="prog">bun</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints bun help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-bun-test">
  <div class="rule-cmd"><span class="prog">bun</span> test</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the project's test suite with Bun's test runner. Compiles and executes test code locally.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-bun-build">
  <div class="rule-cmd"><span class="prog">bun</span> build</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Bundles the project's entry points into output artifacts. Local build step.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-bun-dev">
  <div class="rule-cmd"><span class="prog">bun</span> dev</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>dev</code> script from <code>package.json</code>. Starts the local dev workflow.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-bun-lint">
  <div class="rule-cmd"><span class="prog">bun</span> lint</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>lint</code> script from <code>package.json</code>. Reports style and correctness issues.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-bun-check">
  <div class="rule-cmd"><span class="prog">bun</span> check</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>check</code> script from <code>package.json</code>. Local validation step.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-bun-typecheck">
  <div class="rule-cmd"><span class="prog">bun</span> typecheck</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>typecheck</code> script from <code>package.json</code>. Reports type errors.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-bun-format">
  <div class="rule-cmd"><span class="prog">bun</span> format</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>format</code> script from <code>package.json</code>. Rewrites local source to match style.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-check">
  <div class="rule-cmd"><span class="prog">cargo</span> check</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Type-checks the crate without producing a final binary. Writes only build artifacts under <code>target</code>.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-clippy">
  <div class="rule-cmd"><span class="prog">cargo</span> clippy</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the Clippy linter over the crate and reports warnings. Read-only unless <code>--fix</code> is present, which is gated separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-doc">
  <div class="rule-cmd"><span class="prog">cargo</span> doc</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Builds the crate's API documentation into <code>target/doc</code>. Writes only documentation artifacts.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-tree">
  <div class="rule-cmd"><span class="prog">cargo</span> tree</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Displays the crate dependency graph as a tree. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-metadata">
  <div class="rule-cmd"><span class="prog">cargo</span> metadata</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints resolved package and dependency metadata as JSON. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-pkgid">
  <div class="rule-cmd"><span class="prog">cargo</span> pkgid</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the fully qualified package ID for a dependency. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-verify-project">
  <div class="rule-cmd"><span class="prog">cargo</span> verify-project</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Checks that the <code>Cargo.toml</code> manifest is valid and reports the result. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-search">
  <div class="rule-cmd"><span class="prog">cargo</span> search</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Searches crates.io for packages matching the given terms. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-info">
  <div class="rule-cmd"><span class="prog">cargo</span> info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows registry metadata for a crate (versions, features, dependencies). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-locate-project">
  <div class="rule-cmd"><span class="prog">cargo</span> locate-project</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the path to the nearest <code>Cargo.toml</code>. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-read-manifest">
  <div class="rule-cmd"><span class="prog">cargo</span> read-manifest</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the resolved manifest of the current package as JSON. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-version">
  <div class="rule-cmd"><span class="prog">cargo</span> version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the cargo version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-v">
  <div class="rule-cmd"><span class="prog">cargo</span> -V</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the cargo version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-version-2">
  <div class="rule-cmd"><span class="prog">cargo</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the cargo version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-h">
  <div class="rule-cmd"><span class="prog">cargo</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints cargo help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-help">
  <div class="rule-cmd"><span class="prog">cargo</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints cargo help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-help-2">
  <div class="rule-cmd"><span class="prog">cargo</span> help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints help for cargo or a specific subcommand. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-build">
  <div class="rule-cmd"><span class="prog">cargo</span> build</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Compiles the local crate and its dependencies into the <code>target</code> directory. Local build; fetches declared dependencies as needed.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-run">
  <div class="rule-cmd"><span class="prog">cargo</span> run</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Builds and runs the crate's binary target locally. Executes the just-built local binary.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-test">
  <div class="rule-cmd"><span class="prog">cargo</span> test</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Builds and runs the crate's test suite. Compiles and executes test code locally.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-bench">
  <div class="rule-cmd"><span class="prog">cargo</span> bench</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Builds and runs the crate's benchmarks. Compiles and executes benchmark code locally.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-fmt">
  <div class="rule-cmd"><span class="prog">cargo</span> fmt</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Formats Rust source files in place using <code>rustfmt</code>. Rewrites local source to match style.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-clean">
  <div class="rule-cmd"><span class="prog">cargo</span> clean</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Removes the <code>target</code> build-output directory. Deletes only local build artifacts; next build recompiles.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-nextest">
  <div class="rule-cmd"><span class="prog">cargo</span> nextest</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Builds and runs the test suite with the nextest runner. Compiles and executes test code locally.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-audit">
  <div class="rule-cmd"><span class="prog">cargo</span> audit</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Scans <code>Cargo.lock</code> for dependencies with known security advisories. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-deny">
  <div class="rule-cmd"><span class="prog">cargo</span> deny</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Checks dependencies against license, advisory, and ban policies. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-expand">
  <div class="rule-cmd"><span class="prog">cargo</span> expand</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the crate source after macro expansion. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-semver-checks">
  <div class="rule-cmd"><span class="prog">cargo</span> semver-checks</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Compares the crate's public API against a baseline for semver violations. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-llvm-cov">
  <div class="rule-cmd"><span class="prog">cargo</span> llvm-cov</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the test suite and reports code coverage. Compiles and executes test code locally.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-outdated">
  <div class="rule-cmd"><span class="prog">cargo</span> outdated</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports dependencies that have newer versions available. Read-only; no updates.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-bloat">
  <div class="rule-cmd"><span class="prog">cargo</span> bloat</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Analyzes the built binary and reports what takes up space. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-machete">
  <div class="rule-cmd"><span class="prog">cargo</span> machete</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Scans for declared but unused dependencies and reports them. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-depgraph">
  <div class="rule-cmd"><span class="prog">cargo</span> depgraph</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Generates a dependency-graph description for the crate. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-cargo-insta">
  <div class="rule-cmd"><span class="prog">cargo</span> insta</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs insta snapshot tests and reports mismatches. Read-only unless <code>review</code>, <code>accept</code>, or <code>reject</code> is present, which is gated separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-conda-info">
  <div class="rule-cmd"><span class="prog">conda</span> info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints conda installation and environment configuration details. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-conda-list">
  <div class="rule-cmd"><span class="prog">conda</span> list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists packages installed in the active or named environment. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-conda-search">
  <div class="rule-cmd"><span class="prog">conda</span> search</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Searches configured channels for packages matching the given terms. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-conda-config">
  <div class="rule-cmd"><span class="prog">conda</span> config</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows conda config values. Read-only unless a write flag (<code>--add</code>, <code>--remove</code>, <code>--set</code>, <code>--append</code>, <code>--prepend</code>, <code>--remove-key</code>) is present, which is gated separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-conda-package">
  <div class="rule-cmd"><span class="prog">conda</span> package</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspects or queries package metadata (low-level package operations in read mode). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-conda-version">
  <div class="rule-cmd"><span class="prog">conda</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the conda version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-conda-v">
  <div class="rule-cmd"><span class="prog">conda</span> -V</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the conda version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-conda-help">
  <div class="rule-cmd"><span class="prog">conda</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints conda help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-conda-h">
  <div class="rule-cmd"><span class="prog">conda</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints conda help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-conda-doctor">
  <div class="rule-cmd"><span class="prog">conda</span> doctor</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs environment health checks and reports integrity findings. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-conda-notices">
  <div class="rule-cmd"><span class="prog">conda</span> notices</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Displays channel notices and announcements. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-conda-compare">
  <div class="rule-cmd"><span class="prog">conda</span> compare</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Compares the active environment against an environment spec file and reports differences. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-conda-env-list">
  <div class="rule-cmd"><span class="prog">conda</span> env list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists all conda environments on the machine. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-go-list">
  <div class="rule-cmd"><span class="prog">go</span> list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the packages or modules matching the given import paths. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-go-doc">
  <div class="rule-cmd"><span class="prog">go</span> doc</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints documentation for a package, symbol, or method. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-go-env">
  <div class="rule-cmd"><span class="prog">go</span> env</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints Go environment configuration. Read-only unless <code>-w</code> or <code>-u</code> is present, which is gated separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-go-version">
  <div class="rule-cmd"><span class="prog">go</span> version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Go version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-go-vet">
  <div class="rule-cmd"><span class="prog">go</span> vet</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs Go static analysis and reports suspicious constructs. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-go-help">
  <div class="rule-cmd"><span class="prog">go</span> help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints help for the go command or a topic. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-go-h">
  <div class="rule-cmd"><span class="prog">go</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints go command help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-go-help-2">
  <div class="rule-cmd"><span class="prog">go</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints go command help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-go-build">
  <div class="rule-cmd"><span class="prog">go</span> build</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Compiles the packages in the current module to verify they build. Local build; fetches declared dependencies as needed.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-go-test">
  <div class="rule-cmd"><span class="prog">go</span> test</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Builds and runs the module's test suite. Compiles and executes test code locally.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-go-clean">
  <div class="rule-cmd"><span class="prog">go</span> clean</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Removes object files and cached build artifacts for the current module. Deletes only generated artifacts.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-go-mod-graph">
  <div class="rule-cmd"><span class="prog">go</span> mod graph</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the module requirement graph. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-go-mod-verify">
  <div class="rule-cmd"><span class="prog">go</span> mod verify</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Checks that downloaded module dependencies match <code>go.sum</code> and reports the result. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-go-mod-why">
  <div class="rule-cmd"><span class="prog">go</span> mod why</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Explains why a package or module is needed by the build. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-ls">
  <div class="rule-cmd"><span class="prog">mise</span> ls</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists installed tool versions managed by mise. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-list">
  <div class="rule-cmd"><span class="prog">mise</span> list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists installed tool versions managed by mise (<code>mise list</code> aliases <code>mise ls</code>). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-ls-remote">
  <div class="rule-cmd"><span class="prog">mise</span> ls-remote</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists versions available to install for a tool from upstream. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-current">
  <div class="rule-cmd"><span class="prog">mise</span> current</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the tool versions active in the current directory. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-where">
  <div class="rule-cmd"><span class="prog">mise</span> where</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the install path of a given tool version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-which">
  <div class="rule-cmd"><span class="prog">mise</span> which</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the resolved path to a tool binary. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-env">
  <div class="rule-cmd"><span class="prog">mise</span> env</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the environment variables mise would export for the current directory. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-version">
  <div class="rule-cmd"><span class="prog">mise</span> version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the mise version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-version-2">
  <div class="rule-cmd"><span class="prog">mise</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the mise version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-v">
  <div class="rule-cmd"><span class="prog">mise</span> -V</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the mise version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-help">
  <div class="rule-cmd"><span class="prog">mise</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints mise help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-h">
  <div class="rule-cmd"><span class="prog">mise</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints mise help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-help-2">
  <div class="rule-cmd"><span class="prog">mise</span> help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints help for mise or a specific subcommand. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-doctor">
  <div class="rule-cmd"><span class="prog">mise</span> doctor</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs mise health checks and reports configuration problems. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-plugins">
  <div class="rule-cmd"><span class="prog">mise</span> plugins</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists installed mise plugins. Read-only unless an install/remove/update subcommand is given, which is gated separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-settings">
  <div class="rule-cmd"><span class="prog">mise</span> settings</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows mise settings values. Read-only in list form.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-alias">
  <div class="rule-cmd"><span class="prog">mise</span> alias</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows tool-version aliases configured in mise. Read-only in list form.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-bin-paths">
  <div class="rule-cmd"><span class="prog">mise</span> bin-paths</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the bin directories mise would add to PATH. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-completion">
  <div class="rule-cmd"><span class="prog">mise</span> completion</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints shell completion scripts for mise. Read-only; output is not installed automatically.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-direnv">
  <div class="rule-cmd"><span class="prog">mise</span> direnv</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints direnv integration helpers for mise. Read-only; output is not installed automatically.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-outdated">
  <div class="rule-cmd"><span class="prog">mise</span> outdated</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports installed tool versions that have newer releases available. Read-only; no updates.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-reshim">
  <div class="rule-cmd"><span class="prog">mise</span> reshim</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Regenerates mise shim scripts for installed tools. Rewrites only mise-managed shim files.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-trust">
  <div class="rule-cmd"><span class="prog">mise</span> trust</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Marks a project's mise config file as trusted so its tool versions and env load. Records trust for the local config path.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-exec">
  <div class="rule-cmd"><span class="prog">mise</span> exec</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs a command with mise-managed tool versions on PATH. Devtool delegation is handled by the mise handler.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-mise-registry">
  <div class="rule-cmd"><span class="prog">mise</span> registry</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists tools available in the mise registry. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-list">
  <div class="rule-cmd"><span class="prog">npm</span> list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists installed packages in the dependency tree. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-ls">
  <div class="rule-cmd"><span class="prog">npm</span> ls</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists installed packages in the dependency tree (<code>npm ls</code> aliases <code>npm list</code>). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-ll">
  <div class="rule-cmd"><span class="prog">npm</span> ll</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists installed packages in long format with extra detail. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-la">
  <div class="rule-cmd"><span class="prog">npm</span> la</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists installed packages in long format including transitive deps. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-view">
  <div class="rule-cmd"><span class="prog">npm</span> view</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows registry metadata for a package (versions, dependencies, dist-tags). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-show">
  <div class="rule-cmd"><span class="prog">npm</span> show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows registry metadata for a package (<code>npm show</code> aliases <code>npm view</code>). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-info">
  <div class="rule-cmd"><span class="prog">npm</span> info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows registry metadata for a package (<code>npm info</code> aliases <code>npm view</code>). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-search">
  <div class="rule-cmd"><span class="prog">npm</span> search</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Searches the registry for packages matching the given terms. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-help">
  <div class="rule-cmd"><span class="prog">npm</span> help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints help for npm or a specific subcommand. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-config">
  <div class="rule-cmd"><span class="prog">npm</span> config</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows npm config values. Read-only unless <code>set</code>, <code>delete</code>, or <code>edit</code> is present, which is gated separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-get">
  <div class="rule-cmd"><span class="prog">npm</span> get</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reads a single npm config value. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-prefix">
  <div class="rule-cmd"><span class="prog">npm</span> prefix</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the npm prefix (install root) path. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-root">
  <div class="rule-cmd"><span class="prog">npm</span> root</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the effective <code>node_modules</code> path. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-bin">
  <div class="rule-cmd"><span class="prog">npm</span> bin</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the directory where npm installs executables. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-whoami">
  <div class="rule-cmd"><span class="prog">npm</span> whoami</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the username of the logged-in registry account. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-token">
  <div class="rule-cmd"><span class="prog">npm</span> token</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists authentication tokens for the registry account. Read-only; does not create or revoke.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-team">
  <div class="rule-cmd"><span class="prog">npm</span> team</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists or inspects organization teams on the registry. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-outdated">
  <div class="rule-cmd"><span class="prog">npm</span> outdated</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports which installed packages are out of date versus the registry. Read-only; no installs.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-doctor">
  <div class="rule-cmd"><span class="prog">npm</span> doctor</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs environment and registry health checks and reports findings. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-explain">
  <div class="rule-cmd"><span class="prog">npm</span> explain</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Explains why a package is present in the dependency tree. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-why">
  <div class="rule-cmd"><span class="prog">npm</span> why</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Explains why a package is installed and what depends on it. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-fund">
  <div class="rule-cmd"><span class="prog">npm</span> fund</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists funding URLs declared by installed dependencies. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-audit">
  <div class="rule-cmd"><span class="prog">npm</span> audit</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports known vulnerabilities in the dependency tree. Read-only unless <code>fix</code> is present, which is gated separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-query">
  <div class="rule-cmd"><span class="prog">npm</span> query</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs a dependency-selector query against the installed tree. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-v">
  <div class="rule-cmd"><span class="prog">npm</span> -v</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the npm version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-version">
  <div class="rule-cmd"><span class="prog">npm</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the npm version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-h">
  <div class="rule-cmd"><span class="prog">npm</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints npm help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-help-2">
  <div class="rule-cmd"><span class="prog">npm</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints npm help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-test">
  <div class="rule-cmd"><span class="prog">npm</span> test</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>test</code> script from <code>package.json</code>. Compiles and executes test code locally.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-build">
  <div class="rule-cmd"><span class="prog">npm</span> build</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>build</code> script from <code>package.json</code>. Local build step.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-dev">
  <div class="rule-cmd"><span class="prog">npm</span> dev</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>dev</code> script from <code>package.json</code>. Starts the local dev workflow.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-lint">
  <div class="rule-cmd"><span class="prog">npm</span> lint</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>lint</code> script from <code>package.json</code>. Reports style and correctness issues.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-check">
  <div class="rule-cmd"><span class="prog">npm</span> check</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>check</code> script from <code>package.json</code>. Local validation step.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-typecheck">
  <div class="rule-cmd"><span class="prog">npm</span> typecheck</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>typecheck</code> script from <code>package.json</code>. Reports type errors.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-format">
  <div class="rule-cmd"><span class="prog">npm</span> format</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>format</code> script from <code>package.json</code>. Rewrites local source to match style.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-prettier">
  <div class="rule-cmd"><span class="prog">npm</span> prettier</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Delegates to the Prettier formatter via npm. Formatting is gated by the devtools handler.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-eslint">
  <div class="rule-cmd"><span class="prog">npm</span> eslint</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Delegates to the ESLint linter via npm. Linting is read-only unless <code>--fix</code> is passed.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-npm-tsc">
  <div class="rule-cmd"><span class="prog">npm</span> tsc</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Delegates to the TypeScript compiler via npm. Reports type errors and emits declared output.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pip-list">
  <div class="rule-cmd"><span class="prog">pip</span> list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists installed Python packages and their versions. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pip-show">
  <div class="rule-cmd"><span class="prog">pip</span> show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows metadata for an installed package (version, location, dependencies). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pip-freeze">
  <div class="rule-cmd"><span class="prog">pip</span> freeze</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints installed packages in <code>requirements.txt</code> format. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pip-check">
  <div class="rule-cmd"><span class="prog">pip</span> check</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Verifies that installed packages have compatible dependencies and reports conflicts. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pip-search">
  <div class="rule-cmd"><span class="prog">pip</span> search</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Searches the package index for matching packages. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pip-index">
  <div class="rule-cmd"><span class="prog">pip</span> index</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Queries package index information such as available versions. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pip-config">
  <div class="rule-cmd"><span class="prog">pip</span> config</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows pip config values. Read-only unless <code>set</code>, <code>edit</code>, or <code>unset</code> is present, which is gated separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pip-cache">
  <div class="rule-cmd"><span class="prog">pip</span> cache</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows pip cache info and location. Read-only unless <code>purge</code> or <code>remove</code> is present, which is gated separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pip-debug">
  <div class="rule-cmd"><span class="prog">pip</span> debug</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints pip and environment debug information. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pip-v">
  <div class="rule-cmd"><span class="prog">pip</span> -V</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the pip version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pip-version">
  <div class="rule-cmd"><span class="prog">pip</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the pip version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pip-h">
  <div class="rule-cmd"><span class="prog">pip</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints pip help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pip-help">
  <div class="rule-cmd"><span class="prog">pip</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints pip help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pipx-list">
  <div class="rule-cmd"><span class="prog">pipx</span> list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists applications installed by pipx and their entrypoints. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pipx-environment">
  <div class="rule-cmd"><span class="prog">pipx</span> environment</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints pipx environment paths and configuration. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pipx-version">
  <div class="rule-cmd"><span class="prog">pipx</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the pipx version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pipx-help">
  <div class="rule-cmd"><span class="prog">pipx</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints pipx help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pnpm-list">
  <div class="rule-cmd"><span class="prog">pnpm</span> list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists installed packages in the dependency tree. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pnpm-ls">
  <div class="rule-cmd"><span class="prog">pnpm</span> ls</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists installed packages in the dependency tree (<code>pnpm ls</code> aliases <code>pnpm list</code>). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pnpm-ll">
  <div class="rule-cmd"><span class="prog">pnpm</span> ll</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists installed packages in long format with extra detail. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pnpm-why">
  <div class="rule-cmd"><span class="prog">pnpm</span> why</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Explains why a package is installed and what depends on it. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pnpm-outdated">
  <div class="rule-cmd"><span class="prog">pnpm</span> outdated</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports which installed packages are out of date versus the registry. Read-only; no installs.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pnpm-audit">
  <div class="rule-cmd"><span class="prog">pnpm</span> audit</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports known vulnerabilities in the dependency tree. Read-only unless <code>--fix</code> is present, which is gated separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pnpm-v">
  <div class="rule-cmd"><span class="prog">pnpm</span> -v</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the pnpm version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pnpm-version">
  <div class="rule-cmd"><span class="prog">pnpm</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the pnpm version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pnpm-h">
  <div class="rule-cmd"><span class="prog">pnpm</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints pnpm help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pnpm-help">
  <div class="rule-cmd"><span class="prog">pnpm</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints pnpm help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pnpm-test">
  <div class="rule-cmd"><span class="prog">pnpm</span> test</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>test</code> script from <code>package.json</code>. Compiles and executes test code locally.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pnpm-build">
  <div class="rule-cmd"><span class="prog">pnpm</span> build</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>build</code> script from <code>package.json</code>. Local build step.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pnpm-dev">
  <div class="rule-cmd"><span class="prog">pnpm</span> dev</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>dev</code> script from <code>package.json</code>. Starts the local dev workflow.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pnpm-lint">
  <div class="rule-cmd"><span class="prog">pnpm</span> lint</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>lint</code> script from <code>package.json</code>. Reports style and correctness issues.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pnpm-check">
  <div class="rule-cmd"><span class="prog">pnpm</span> check</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>check</code> script from <code>package.json</code>. Local validation step.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pnpm-typecheck">
  <div class="rule-cmd"><span class="prog">pnpm</span> typecheck</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>typecheck</code> script from <code>package.json</code>. Reports type errors.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pnpm-format">
  <div class="rule-cmd"><span class="prog">pnpm</span> format</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>format</code> script from <code>package.json</code>. Rewrites local source to match style.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-pnpm-tsc">
  <div class="rule-cmd"><span class="prog">pnpm</span> tsc</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Delegates to the TypeScript compiler via pnpm. Reports type errors and emits declared output.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-poetry-show">
  <div class="rule-cmd"><span class="prog">poetry</span> show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists installed packages or shows details for one package. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-poetry-search">
  <div class="rule-cmd"><span class="prog">poetry</span> search</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Searches configured repositories for packages matching the given terms. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-poetry-check">
  <div class="rule-cmd"><span class="prog">poetry</span> check</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Validates the <code>pyproject.toml</code> and lockfile consistency and reports problems. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-poetry-config">
  <div class="rule-cmd"><span class="prog">poetry</span> config</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows poetry config values. Read-only unless <code>--unset</code> is present, which removes a key.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-poetry-config-list">
  <div class="rule-cmd"><span class="prog">poetry</span> config list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists all poetry config values. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-poetry-env-info">
  <div class="rule-cmd"><span class="prog">poetry</span> env info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows information about the active project virtualenv. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-poetry-env-list">
  <div class="rule-cmd"><span class="prog">poetry</span> env list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the virtualenvs associated with the project. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-poetry-env-activate">
  <div class="rule-cmd"><span class="prog">poetry</span> env activate</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the command to activate the project virtualenv. Read-only; does not modify the shell itself.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-poetry-version">
  <div class="rule-cmd"><span class="prog">poetry</span> version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the project version or the poetry version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-poetry-about">
  <div class="rule-cmd"><span class="prog">poetry</span> about</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints information about poetry itself. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-poetry-version-2">
  <div class="rule-cmd"><span class="prog">poetry</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the poetry version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-poetry-v">
  <div class="rule-cmd"><span class="prog">poetry</span> -V</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the poetry version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-poetry-help">
  <div class="rule-cmd"><span class="prog">poetry</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints poetry help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-poetry-h">
  <div class="rule-cmd"><span class="prog">poetry</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints poetry help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-poetry-build">
  <div class="rule-cmd"><span class="prog">poetry</span> build</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Builds source and wheel distributions into <code>dist/</code>. Writes artifacts; does not publish.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-poetry-lock">
  <div class="rule-cmd"><span class="prog">poetry</span> lock</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Resolves dependencies and writes <code>poetry.lock</code>. Network access; pinned versions may change.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-rustc-version-v-print-explain-help-h-vv">
  <div class="rule-cmd"><span class="prog">rustc</span> <span class="flag">--version</span> <span class="flag">-V</span> <span class="flag">--print</span> <span class="flag">--explain</span> <span class="flag">--help</span> <span class="flag">-h</span> <span class="flag">-vV</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Queries the Rust compiler for version, target, or diagnostic info without compiling. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-rustup-show">
  <div class="rule-cmd"><span class="prog">rustup</span> show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the active toolchain and installed targets and components. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-rustup-toolchain-list">
  <div class="rule-cmd"><span class="prog">rustup</span> toolchain list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists installed Rust toolchains. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-rustup-target-list">
  <div class="rule-cmd"><span class="prog">rustup</span> target list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists available and installed compilation targets. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-rustup-component-list">
  <div class="rule-cmd"><span class="prog">rustup</span> component list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists available and installed toolchain components. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-rustup-run">
  <div class="rule-cmd"><span class="prog">rustup</span> run</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs a command under a specific toolchain without changing the default. Executes the named command with that toolchain on PATH.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-rustup-which">
  <div class="rule-cmd"><span class="prog">rustup</span> which</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the resolved path to a binary for the active toolchain. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-rustup-doc">
  <div class="rule-cmd"><span class="prog">rustup</span> doc</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Opens or locates the offline Rust documentation for the active toolchain. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-rustup-version">
  <div class="rule-cmd"><span class="prog">rustup</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the rustup version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-rustup-v">
  <div class="rule-cmd"><span class="prog">rustup</span> -V</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the rustup version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-rustup-help">
  <div class="rule-cmd"><span class="prog">rustup</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints rustup help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-rustup-h">
  <div class="rule-cmd"><span class="prog">rustup</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints rustup help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-rustup-help-2">
  <div class="rule-cmd"><span class="prog">rustup</span> help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints help for rustup or a specific subcommand. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-uv-version">
  <div class="rule-cmd"><span class="prog">uv</span> version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the uv version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-uv-help">
  <div class="rule-cmd"><span class="prog">uv</span> help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints help for uv or a specific subcommand. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-uv-tree">
  <div class="rule-cmd"><span class="prog">uv</span> tree</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Displays the project dependency graph as a tree. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-uv-version-2">
  <div class="rule-cmd"><span class="prog">uv</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the uv version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-uv-v">
  <div class="rule-cmd"><span class="prog">uv</span> -V</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the uv version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-uv-h">
  <div class="rule-cmd"><span class="prog">uv</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints uv help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-uv-help-2">
  <div class="rule-cmd"><span class="prog">uv</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints uv help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-uv-pip-list">
  <div class="rule-cmd"><span class="prog">uv</span> pip list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists packages in the active venv via uv's pip-compatible frontend. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-uv-pip-show">
  <div class="rule-cmd"><span class="prog">uv</span> pip show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows metadata for a package in the active venv via uv's pip-compatible frontend. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-uv-pip-freeze">
  <div class="rule-cmd"><span class="prog">uv</span> pip freeze</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints active-venv packages in <code>requirements.txt</code> format via uv's pip-compatible frontend. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-uv-pip-check">
  <div class="rule-cmd"><span class="prog">uv</span> pip check</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Verifies active-venv dependencies are compatible via uv's pip-compatible frontend. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-yarn-list">
  <div class="rule-cmd"><span class="prog">yarn</span> list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists installed packages in the dependency tree. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-yarn-info">
  <div class="rule-cmd"><span class="prog">yarn</span> info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows registry metadata for a package (versions, dependencies). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-yarn-why">
  <div class="rule-cmd"><span class="prog">yarn</span> why</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Explains why a package is installed and what depends on it. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-yarn-outdated">
  <div class="rule-cmd"><span class="prog">yarn</span> outdated</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports which installed packages are out of date versus the registry. Read-only; no installs.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-yarn-audit">
  <div class="rule-cmd"><span class="prog">yarn</span> audit</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports known vulnerabilities in the dependency tree. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-yarn-config">
  <div class="rule-cmd"><span class="prog">yarn</span> config</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows yarn config values. Read-only unless <code>set</code> or <code>delete</code> is present, which is gated separately.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-yarn-v">
  <div class="rule-cmd"><span class="prog">yarn</span> -v</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the yarn version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-yarn-version">
  <div class="rule-cmd"><span class="prog">yarn</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the yarn version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-yarn-h">
  <div class="rule-cmd"><span class="prog">yarn</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints yarn help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-yarn-help">
  <div class="rule-cmd"><span class="prog">yarn</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints yarn help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-yarn-test">
  <div class="rule-cmd"><span class="prog">yarn</span> test</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>test</code> script from <code>package.json</code>. Compiles and executes test code locally.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-yarn-build">
  <div class="rule-cmd"><span class="prog">yarn</span> build</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>build</code> script from <code>package.json</code>. Local build step.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-yarn-dev">
  <div class="rule-cmd"><span class="prog">yarn</span> dev</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>dev</code> script from <code>package.json</code>. Starts the local dev workflow.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-yarn-lint">
  <div class="rule-cmd"><span class="prog">yarn</span> lint</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>lint</code> script from <code>package.json</code>. Reports style and correctness issues.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-yarn-check">
  <div class="rule-cmd"><span class="prog">yarn</span> check</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>check</code> script from <code>package.json</code>. Local validation step.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-yarn-typecheck">
  <div class="rule-cmd"><span class="prog">yarn</span> typecheck</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>typecheck</code> script from <code>package.json</code>. Reports type errors.</div>
</div>
<div class="rule-row" data-decision="allow" id="package_managers-yarn-format">
  <div class="rule-cmd"><span class="prog">yarn</span> format</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the package <code>format</code> script from <code>package.json</code>. Rewrites local source to match style.</div>
</div>
</div>

<div class="rule-card">
  <header>
    <h2>Asks first · mutations</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/package_managers.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/package_managers.toml#ask
    </a>
    <span class="count">205 patterns</span>
  </header>

<div class="rule-row" data-decision="ask" id="package_managers-bun-run">
  <div class="rule-cmd"><span class="prog">bun</span> run</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Running script from package.json</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-bun-start">
  <div class="rule-cmd"><span class="prog">bun</span> start</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Running start script</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-bun-install">
  <div class="rule-cmd"><span class="prog">bun</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installing packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-bun-i">
  <div class="rule-cmd"><span class="prog">bun</span> i</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installing packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-bun-add">
  <div class="rule-cmd"><span class="prog">bun</span> add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adding packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-bun-remove">
  <div class="rule-cmd"><span class="prog">bun</span> remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removing packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-bun-rm">
  <div class="rule-cmd"><span class="prog">bun</span> rm</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removing packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-bun-update">
  <div class="rule-cmd"><span class="prog">bun</span> update</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Updating packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-bun-link">
  <div class="rule-cmd"><span class="prog">bun</span> link</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates a global symlink and links the package into node_modules. Modifies bun's global link registry; can shadow real installs of <code>&lt;package&gt;</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-bun-unlink">
  <div class="rule-cmd"><span class="prog">bun</span> unlink</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes the global symlink created by <code>bun link</code>. Affects every project that consumed the linked package.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-bun-x">
  <div class="rule-cmd"><span class="prog">bun</span> x</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs an arbitrary command through bun (downloads the package if missing). Same trust boundary as <code>curl | bash</code> for untrusted packages.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-bun-init">
  <div class="rule-cmd"><span class="prog">bun</span> init</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Initializes a new bun project in the current directory by writing <code>package.json</code> and supporting files.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-bun-create">
  <div class="rule-cmd"><span class="prog">bun</span> create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Scaffolds a project from a <code>create-&lt;name&gt;</code> template, downloading it if missing. Same trust boundary as <code>curl | bash</code> for untrusted initializers.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-bun-publish">
  <div class="rule-cmd"><span class="prog">bun</span> publish</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Publishes the package to its registry. Public publish is irreversible: the version number cannot be reused.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-cargo-clippy-fix">
  <div class="rule-cmd"><span class="prog">cargo</span> clippy <span class="flag">--fix</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Auto-fixing lint suggestions</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-cargo-insta-review-accept-reject">
  <div class="rule-cmd"><span class="prog">cargo</span> insta <span class="flag">review</span> <span class="flag">accept</span> <span class="flag">reject</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Reviews or applies insta snapshot changes. <code>accept</code> overwrites <code>.snap</code> files with current output; <code>reject</code> discards pending snapshots.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-cargo-watch">
  <div class="rule-cmd"><span class="prog">cargo</span> watch</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Re-runs a given cargo command on every file change. Executes that command repeatedly; runs until interrupted.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-cargo-mutants">
  <div class="rule-cmd"><span class="prog">cargo</span> mutants</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Mutation testing rewrites source files to introduce synthetic bugs and checks test coverage. Files are restored on completion; interrupting mid-run can leave the tree mutated.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-cargo-install">
  <div class="rule-cmd"><span class="prog">cargo</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installs a binary crate into <code>~/.cargo/bin</code>. Compiles from source and puts the binary on PATH for the current user.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-cargo-uninstall">
  <div class="rule-cmd"><span class="prog">cargo</span> uninstall</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes a previously <code>cargo install</code>ed binary from <code>~/.cargo/bin</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-cargo-new">
  <div class="rule-cmd"><span class="prog">cargo</span> new</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Scaffolds a new Cargo package in a new directory, writing <code>Cargo.toml</code> and <code>src/</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-cargo-init">
  <div class="rule-cmd"><span class="prog">cargo</span> init</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Initializing project</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-cargo-add">
  <div class="rule-cmd"><span class="prog">cargo</span> add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adding dependency</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-cargo-remove">
  <div class="rule-cmd"><span class="prog">cargo</span> remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removing dependency</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-cargo-update">
  <div class="rule-cmd"><span class="prog">cargo</span> update</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Updates dependencies in <code>Cargo.lock</code> to newer compatible versions. Changes resolved versions; no manifest edits.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-cargo-publish">
  <div class="rule-cmd"><span class="prog">cargo</span> publish</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Publishing crate</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-cargo-yank">
  <div class="rule-cmd"><span class="prog">cargo</span> yank</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Yanks a published crate version on crates.io so new projects can't select it. Existing lockfiles keep resolving it; reversible with <code>--undo</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-cargo-fix">
  <div class="rule-cmd"><span class="prog">cargo</span> fix</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Applies compiler-suggested fixes to source files in place. Rewrites code; run on a clean tree so changes stay reviewable.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-cargo-generate-lockfile">
  <div class="rule-cmd"><span class="prog">cargo</span> generate-lockfile</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates or regenerates <code>Cargo.lock</code> by resolving dependencies. May change pinned versions.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-conda-config-add-remove-set-append-prepend-remove-key">
  <div class="rule-cmd"><span class="prog">conda</span> config <span class="flag">--add</span> <span class="flag">--remove</span> <span class="flag">--set</span> <span class="flag">--append</span> <span class="flag">--prepend</span> <span class="flag">--remove-key</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Modifying conda config</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-conda-install">
  <div class="rule-cmd"><span class="prog">conda</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installing packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-conda-remove">
  <div class="rule-cmd"><span class="prog">conda</span> remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removing packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-conda-uninstall">
  <div class="rule-cmd"><span class="prog">conda</span> uninstall</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Uninstalling packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-conda-update">
  <div class="rule-cmd"><span class="prog">conda</span> update</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Updating packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-conda-upgrade">
  <div class="rule-cmd"><span class="prog">conda</span> upgrade</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Upgrading packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-conda-create">
  <div class="rule-cmd"><span class="prog">conda</span> create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating environment</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-conda-activate">
  <div class="rule-cmd"><span class="prog">conda</span> activate</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Activating environment</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-conda-deactivate">
  <div class="rule-cmd"><span class="prog">conda</span> deactivate</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deactivating environment</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-conda-clean">
  <div class="rule-cmd"><span class="prog">conda</span> clean</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Mutates the conda cache (packages, tarballs, indexes). Frees disk; next install re-downloads.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-conda-build">
  <div class="rule-cmd"><span class="prog">conda</span> build</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Builds a conda package from a recipe. Writes artifacts under the conda-bld directory.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-conda-init">
  <div class="rule-cmd"><span class="prog">conda</span> init</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Modifies shell rc files (<code>.bashrc</code>, <code>.zshrc</code>, etc.) to initialize conda on shell startup.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-conda-run">
  <div class="rule-cmd"><span class="prog">conda</span> run</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs a command inside a named conda environment. Treat as executing that command with the env's interpreter on PATH.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-conda-env-create">
  <div class="rule-cmd"><span class="prog">conda</span> env create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates a new conda environment from a name or YAML spec. Downloads packages and writes under the conda envs dir.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-conda-env-remove">
  <div class="rule-cmd"><span class="prog">conda</span> env remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deletes a named conda environment and everything installed in it. Not reversible without re-creation.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-go-env-w-u">
  <div class="rule-cmd"><span class="prog">go</span> env <span class="flag">-w</span> <span class="flag">-u</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Modifying Go environment config</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-go-fmt">
  <div class="rule-cmd"><span class="prog">go</span> fmt</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Formatting files</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-go-run">
  <div class="rule-cmd"><span class="prog">go</span> run</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Executing Go code</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-go-mod-tidy">
  <div class="rule-cmd"><span class="prog">go</span> mod tidy</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Tidying go.mod/go.sum</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-go-mod-download">
  <div class="rule-cmd"><span class="prog">go</span> mod download</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Downloading modules</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-go-install">
  <div class="rule-cmd"><span class="prog">go</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installing</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-go-get">
  <div class="rule-cmd"><span class="prog">go</span> get</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adds or updates module dependencies in <code>go.mod</code>/<code>go.sum</code> and downloads them. Changes the dependency set.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-go-generate">
  <div class="rule-cmd"><span class="prog">go</span> generate</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs <code>//go:generate</code> directives found in source. Executes arbitrary commands those directives specify.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-go-fix">
  <div class="rule-cmd"><span class="prog">go</span> fix</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Rewrites packages to use newer Go APIs in place. Modifies source files.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-go-work">
  <div class="rule-cmd"><span class="prog">go</span> work</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Manages the Go workspace file <code>go.work</code> (init, use, edit, sync). Changes which modules resolve locally.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-go-mod-init">
  <div class="rule-cmd"><span class="prog">go</span> mod init</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Initializes a new module by writing <code>go.mod</code> in the current directory.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-go-mod-edit">
  <div class="rule-cmd"><span class="prog">go</span> mod edit</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Edits <code>go.mod</code> programmatically (require, replace, drop, go directive). Rewrites the manifest.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-mise-run">
  <div class="rule-cmd"><span class="prog">mise</span> run</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Running mise task</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-mise-task">
  <div class="rule-cmd"><span class="prog">mise</span> task</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Manages or runs mise tasks (run, ls, edit, add). <code>mise task run</code> executes shell from the task file; treat as running that script.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-mise-tasks">
  <div class="rule-cmd"><span class="prog">mise</span> tasks</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Manages or runs mise tasks (run, ls, edit, add). <code>mise tasks run</code> executes shell from the task file; treat as running that script.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-mise-install">
  <div class="rule-cmd"><span class="prog">mise</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installing tool versions</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-mise-i">
  <div class="rule-cmd"><span class="prog">mise</span> i</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installing tool versions</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-mise-use">
  <div class="rule-cmd"><span class="prog">mise</span> use</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Setting tool version</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-mise-u">
  <div class="rule-cmd"><span class="prog">mise</span> u</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Setting tool version</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-mise-upgrade">
  <div class="rule-cmd"><span class="prog">mise</span> upgrade</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Upgrading tools</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-mise-up">
  <div class="rule-cmd"><span class="prog">mise</span> up</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Upgrading tools</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-mise-uninstall">
  <div class="rule-cmd"><span class="prog">mise</span> uninstall</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Uninstalling tools</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-mise-prune">
  <div class="rule-cmd"><span class="prog">mise</span> prune</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Pruning unused versions</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-mise-sync">
  <div class="rule-cmd"><span class="prog">mise</span> sync</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Syncing tool versions</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-mise-activate">
  <div class="rule-cmd"><span class="prog">mise</span> activate</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Activating mise in shell</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-mise-deactivate">
  <div class="rule-cmd"><span class="prog">mise</span> deactivate</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deactivating mise</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-mise-implode">
  <div class="rule-cmd"><span class="prog">mise</span> implode</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removing mise installation</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-mise-self-update">
  <div class="rule-cmd"><span class="prog">mise</span> self-update</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Updating mise itself</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-mise-plugins-install">
  <div class="rule-cmd"><span class="prog">mise</span> plugins install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installing plugin</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-mise-plugins-add">
  <div class="rule-cmd"><span class="prog">mise</span> plugins add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installing plugin</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-mise-plugins-remove">
  <div class="rule-cmd"><span class="prog">mise</span> plugins remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removing plugin</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-mise-plugins-update">
  <div class="rule-cmd"><span class="prog">mise</span> plugins update</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Updating plugins</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-mise-cache">
  <div class="rule-cmd"><span class="prog">mise</span> cache</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Mutates the mise cache (clear). Deletes cached tool downloads; next install will re-download.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-mise-link">
  <div class="rule-cmd"><span class="prog">mise</span> link</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Symlinks an externally-installed tool version into mise's data dir so it can be selected like a managed version.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-config-set-delete-edit">
  <div class="rule-cmd"><span class="prog">npm</span> config <span class="flag">set</span> <span class="flag">delete</span> <span class="flag">edit</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Modifying npm config</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-audit-fix">
  <div class="rule-cmd"><span class="prog">npm</span> audit <span class="flag">fix</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Fixing vulnerabilities (modifies dependencies)</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-run">
  <div class="rule-cmd"><span class="prog">npm</span> run</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Running script from package.json</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-run-script">
  <div class="rule-cmd"><span class="prog">npm</span> run-script</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Running script from package.json</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-start">
  <div class="rule-cmd"><span class="prog">npm</span> start</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Running start script</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-install">
  <div class="rule-cmd"><span class="prog">npm</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installing packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-i">
  <div class="rule-cmd"><span class="prog">npm</span> i</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installing packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-add">
  <div class="rule-cmd"><span class="prog">npm</span> add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installing packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-ci">
  <div class="rule-cmd"><span class="prog">npm</span> ci</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Clean install</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-uninstall">
  <div class="rule-cmd"><span class="prog">npm</span> uninstall</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Uninstalling packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-remove">
  <div class="rule-cmd"><span class="prog">npm</span> remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Uninstalling packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-rm">
  <div class="rule-cmd"><span class="prog">npm</span> rm</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Uninstalling packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-un">
  <div class="rule-cmd"><span class="prog">npm</span> un</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Uninstalling packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-update">
  <div class="rule-cmd"><span class="prog">npm</span> update</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Updating packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-up">
  <div class="rule-cmd"><span class="prog">npm</span> up</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Updating packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-upgrade">
  <div class="rule-cmd"><span class="prog">npm</span> upgrade</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Updating packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-link">
  <div class="rule-cmd"><span class="prog">npm</span> link</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates a global symlink to this package and links it into node_modules. Modifies the global npm prefix; can shadow real installs of <code>&lt;package&gt;</code> system-wide.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-unlink">
  <div class="rule-cmd"><span class="prog">npm</span> unlink</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes the global symlink created by <code>npm link</code>. Affects every project that consumed the linked package.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-publish">
  <div class="rule-cmd"><span class="prog">npm</span> publish</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Publishes the package to its registry. Public publish is irreversible: the version number cannot be reused.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-unpublish">
  <div class="rule-cmd"><span class="prog">npm</span> unpublish</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes a published version from the registry. Public unpublish is restricted by npm policy and can break downstream consumers.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-deprecate">
  <div class="rule-cmd"><span class="prog">npm</span> deprecate</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Marks a published version as deprecated on the registry. Shows a warning to every future install of that version.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-init">
  <div class="rule-cmd"><span class="prog">npm</span> init</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Initializes a new package in the current directory by writing <code>package.json</code>. With <code>npm init &lt;initializer&gt;</code> it runs an arbitrary <code>create-&lt;initializer&gt;</code> package.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-create">
  <div class="rule-cmd"><span class="prog">npm</span> create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs a <code>create-&lt;name&gt;</code> package to scaffold a project, downloading it if missing. Same trust boundary as <code>curl | bash</code> for untrusted initializers.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-exec">
  <div class="rule-cmd"><span class="prog">npm</span> exec</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs an arbitrary command through the package manager (downloads the package if missing). Same trust boundary as <code>curl | bash</code> for untrusted packages.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-npx">
  <div class="rule-cmd"><span class="prog">npm</span> npx</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs an arbitrary command through <code>npx</code> (downloads the package if missing). Same trust boundary as <code>curl | bash</code> for untrusted packages.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-prune">
  <div class="rule-cmd"><span class="prog">npm</span> prune</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes packages from <code>node_modules</code> that are not listed in <code>package.json</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-dedupe">
  <div class="rule-cmd"><span class="prog">npm</span> dedupe</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Rewrites <code>node_modules</code> and <code>package-lock.json</code> to reduce duplication. Can change resolved versions.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-shrinkwrap">
  <div class="rule-cmd"><span class="prog">npm</span> shrinkwrap</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Writes <code>npm-shrinkwrap.json</code> to lock the dependency tree for publishing.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-cache">
  <div class="rule-cmd"><span class="prog">npm</span> cache</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Mutates the npm cache (verify, clean, add). <code>npm cache clean --force</code> wipes all cached tarballs and metadata.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-pack">
  <div class="rule-cmd"><span class="prog">npm</span> pack</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Builds a tarball of the package as it would be published. Writes a <code>.tgz</code> file to the cwd.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-npm-set">
  <div class="rule-cmd"><span class="prog">npm</span> set</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Sets an npm config key. Default scope is the user-level <code>.npmrc</code>; <code>--global</code> writes to the global prefix.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pip-config-set-edit-unset">
  <div class="rule-cmd"><span class="prog">pip</span> config <span class="flag">set</span> <span class="flag">edit</span> <span class="flag">unset</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Modifying pip config</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pip-cache-purge-remove">
  <div class="rule-cmd"><span class="prog">pip</span> cache <span class="flag">purge</span> <span class="flag">remove</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deleting pip cache</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pip-install">
  <div class="rule-cmd"><span class="prog">pip</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installing packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pip-uninstall">
  <div class="rule-cmd"><span class="prog">pip</span> uninstall</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Uninstalling packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pip-download">
  <div class="rule-cmd"><span class="prog">pip</span> download</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Downloading packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pip-wheel">
  <div class="rule-cmd"><span class="prog">pip</span> wheel</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Building wheel</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pipx-install">
  <div class="rule-cmd"><span class="prog">pipx</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installing application</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pipx-uninstall">
  <div class="rule-cmd"><span class="prog">pipx</span> uninstall</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Uninstalling application</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pipx-upgrade">
  <div class="rule-cmd"><span class="prog">pipx</span> upgrade</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Upgrading application</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pipx-upgrade-all">
  <div class="rule-cmd"><span class="prog">pipx</span> upgrade-all</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Upgrading all applications</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pipx-reinstall">
  <div class="rule-cmd"><span class="prog">pipx</span> reinstall</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Reinstalling application</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pipx-reinstall-all">
  <div class="rule-cmd"><span class="prog">pipx</span> reinstall-all</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Reinstalling all</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pipx-inject">
  <div class="rule-cmd"><span class="prog">pipx</span> inject</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Injecting package</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pipx-uninject">
  <div class="rule-cmd"><span class="prog">pipx</span> uninject</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Uninjecting package</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pipx-ensurepath">
  <div class="rule-cmd"><span class="prog">pipx</span> ensurepath</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Modifying PATH</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pipx-run">
  <div class="rule-cmd"><span class="prog">pipx</span> run</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Running application</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pnpm-audit-fix">
  <div class="rule-cmd"><span class="prog">pnpm</span> audit <span class="flag">--fix</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Fixing vulnerabilities (modifies dependencies)</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pnpm-run">
  <div class="rule-cmd"><span class="prog">pnpm</span> run</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Running script from package.json</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pnpm-start">
  <div class="rule-cmd"><span class="prog">pnpm</span> start</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Running start script</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pnpm-exec">
  <div class="rule-cmd"><span class="prog">pnpm</span> exec</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs an arbitrary command through the package manager (downloads the package if missing). Same trust boundary as <code>curl | bash</code> for untrusted packages.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pnpm-install">
  <div class="rule-cmd"><span class="prog">pnpm</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installing packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pnpm-i">
  <div class="rule-cmd"><span class="prog">pnpm</span> i</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installing packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pnpm-add">
  <div class="rule-cmd"><span class="prog">pnpm</span> add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adding packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pnpm-remove">
  <div class="rule-cmd"><span class="prog">pnpm</span> remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removing packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pnpm-rm">
  <div class="rule-cmd"><span class="prog">pnpm</span> rm</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removing packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pnpm-uninstall">
  <div class="rule-cmd"><span class="prog">pnpm</span> uninstall</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removing packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pnpm-update">
  <div class="rule-cmd"><span class="prog">pnpm</span> update</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Updating packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pnpm-up">
  <div class="rule-cmd"><span class="prog">pnpm</span> up</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Updating packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pnpm-link">
  <div class="rule-cmd"><span class="prog">pnpm</span> link</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates a global symlink and links the package into node_modules. Modifies the global pnpm store and can shadow real installs of <code>&lt;package&gt;</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pnpm-unlink">
  <div class="rule-cmd"><span class="prog">pnpm</span> unlink</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes the global symlink created by <code>pnpm link</code>. Affects every project that consumed the linked package.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pnpm-publish">
  <div class="rule-cmd"><span class="prog">pnpm</span> publish</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Publishes the package to its registry. Public publish is irreversible: the version number cannot be reused.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pnpm-init">
  <div class="rule-cmd"><span class="prog">pnpm</span> init</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Initializes a new package in the current directory by writing <code>package.json</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pnpm-create">
  <div class="rule-cmd"><span class="prog">pnpm</span> create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs a <code>create-&lt;name&gt;</code> package to scaffold a project, downloading it if missing. Same trust boundary as <code>curl | bash</code> for untrusted initializers.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pnpm-dlx">
  <div class="rule-cmd"><span class="prog">pnpm</span> dlx</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs an arbitrary command through the package manager (downloads the package if missing). Same trust boundary as <code>curl | bash</code> for untrusted packages.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pnpm-prune">
  <div class="rule-cmd"><span class="prog">pnpm</span> prune</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes packages from <code>node_modules</code> and the pnpm store that are not listed in <code>package.json</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pnpm-store">
  <div class="rule-cmd"><span class="prog">pnpm</span> store</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Mutates the shared pnpm content-addressable store (prune, add, status). <code>store prune</code> deletes orphaned packages used by no project on this machine.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-pnpm-patch">
  <div class="rule-cmd"><span class="prog">pnpm</span> patch</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates an editable copy of a dependency in a temp dir; <code>patch-commit</code> writes a persistent patch file consumed by future installs.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-poetry-env-use">
  <div class="rule-cmd"><span class="prog">poetry</span> env use</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating/activating Python environment</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-poetry-env-remove">
  <div class="rule-cmd"><span class="prog">poetry</span> env remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removing Python environment</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-poetry-run">
  <div class="rule-cmd"><span class="prog">poetry</span> run</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Running arbitrary command in environment</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-poetry-shell">
  <div class="rule-cmd"><span class="prog">poetry</span> shell</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Spawning interactive shell</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-poetry-install">
  <div class="rule-cmd"><span class="prog">poetry</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installing dependencies</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-poetry-add">
  <div class="rule-cmd"><span class="prog">poetry</span> add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adding dependency</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-poetry-remove">
  <div class="rule-cmd"><span class="prog">poetry</span> remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removing dependency</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-poetry-update">
  <div class="rule-cmd"><span class="prog">poetry</span> update</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Updating dependencies</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-poetry-init">
  <div class="rule-cmd"><span class="prog">poetry</span> init</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Initializing project</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-poetry-new">
  <div class="rule-cmd"><span class="prog">poetry</span> new</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creating project</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-poetry-publish">
  <div class="rule-cmd"><span class="prog">poetry</span> publish</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Publishes the package to its registry. Public publish is irreversible: the version number cannot be reused.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-poetry-cache">
  <div class="rule-cmd"><span class="prog">poetry</span> cache</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Mutates the poetry cache (clear, list). <code>poetry cache clear --all</code> deletes cached package tarballs and wheels.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-poetry-export">
  <div class="rule-cmd"><span class="prog">poetry</span> export</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Writes the locked dependencies to a <code>requirements.txt</code>-style file. Output path may overwrite existing files.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-poetry-self">
  <div class="rule-cmd"><span class="prog">poetry</span> self</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Manages the poetry installation itself: add, update, lock, sync of poetry plugins. Modifies the user-global poetry environment.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-poetry-source">
  <div class="rule-cmd"><span class="prog">poetry</span> source</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adds, removes, or shows package index sources in <code>pyproject.toml</code>. Changes where future installs resolve from.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-rustc">
  <div class="rule-cmd"><span class="prog">rustc</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compiles Rust source directly with rustc. Writes an output binary or library to the cwd or <code>-o</code> path.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-rustup-install">
  <div class="rule-cmd"><span class="prog">rustup</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installing toolchain</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-rustup-update">
  <div class="rule-cmd"><span class="prog">rustup</span> update</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Updating toolchains</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-rustup-default">
  <div class="rule-cmd"><span class="prog">rustup</span> default</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Changing default toolchain</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-rustup-toolchain-install">
  <div class="rule-cmd"><span class="prog">rustup</span> toolchain install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installing toolchain</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-rustup-toolchain-uninstall">
  <div class="rule-cmd"><span class="prog">rustup</span> toolchain uninstall</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Uninstalling toolchain</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-rustup-target-add">
  <div class="rule-cmd"><span class="prog">rustup</span> target add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adding compilation target</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-rustup-target-remove">
  <div class="rule-cmd"><span class="prog">rustup</span> target remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removing compilation target</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-rustup-component-add">
  <div class="rule-cmd"><span class="prog">rustup</span> component add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adding component</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-rustup-component-remove">
  <div class="rule-cmd"><span class="prog">rustup</span> component remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removing component</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-rustup-override">
  <div class="rule-cmd"><span class="prog">rustup</span> override</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Setting toolchain override</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-rustup-self">
  <div class="rule-cmd"><span class="prog">rustup</span> self</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Modifying rustup installation</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-uv-run">
  <div class="rule-cmd"><span class="prog">uv</span> run</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs a command inside the project venv. Will create the venv and download missing dependencies from the lockfile on first run.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-uv-sync">
  <div class="rule-cmd"><span class="prog">uv</span> sync</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Reconciles the project venv with the lockfile. Installs missing deps and removes extras; can mutate the active <code>.venv</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-uv-lock">
  <div class="rule-cmd"><span class="prog">uv</span> lock</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Resolves dependencies and writes <code>uv.lock</code>. Network access; pinned versions may change.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-uv-venv">
  <div class="rule-cmd"><span class="prog">uv</span> venv</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates a new virtual environment at <code>&lt;path&gt;</code> (default <code>.venv</code>). Overwrites an existing venv at the same path.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-uv-add">
  <div class="rule-cmd"><span class="prog">uv</span> add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adding dependency</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-uv-remove">
  <div class="rule-cmd"><span class="prog">uv</span> remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removing dependency</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-uv-tool">
  <div class="rule-cmd"><span class="prog">uv</span> tool</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Manages uv-installed standalone tools: install, uninstall, upgrade, run. Modifies the user-level uv tool directory and binaries on PATH.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-uv-python">
  <div class="rule-cmd"><span class="prog">uv</span> python</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Manages uv-managed Python interpreters: install, uninstall, pin, find. Downloads interpreter builds and writes to the user-level uv data dir.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-uv-cache">
  <div class="rule-cmd"><span class="prog">uv</span> cache</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Mutates the uv cache (clean, prune). <code>uv cache clean</code> deletes all cached wheels and source distributions.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-uv-init">
  <div class="rule-cmd"><span class="prog">uv</span> init</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Initializes a new uv project in the current directory by writing <code>pyproject.toml</code> and supporting files.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-uv-build">
  <div class="rule-cmd"><span class="prog">uv</span> build</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Builds source and wheel distributions into <code>dist/</code>. Writes artifacts; does not publish.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-uv-publish">
  <div class="rule-cmd"><span class="prog">uv</span> publish</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Publishes the package to its registry. Public publish is irreversible: the version number cannot be reused.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-uv-pip-install">
  <div class="rule-cmd"><span class="prog">uv</span> pip install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installs packages into the currently active venv via uv's pip-compatible frontend. Writes to site-packages of <code>&lt;venv&gt;</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-uv-pip-uninstall">
  <div class="rule-cmd"><span class="prog">uv</span> pip uninstall</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes packages from the currently active venv via uv's pip-compatible frontend.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-yarn-config-set-delete">
  <div class="rule-cmd"><span class="prog">yarn</span> config <span class="flag">set</span> <span class="flag">delete</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Modifying yarn config</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-yarn-run">
  <div class="rule-cmd"><span class="prog">yarn</span> run</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Running script from package.json</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-yarn-start">
  <div class="rule-cmd"><span class="prog">yarn</span> start</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Running start script</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-yarn-exec">
  <div class="rule-cmd"><span class="prog">yarn</span> exec</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs an arbitrary command through the package manager (downloads the package if missing). Same trust boundary as <code>curl | bash</code> for untrusted packages.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-yarn-install">
  <div class="rule-cmd"><span class="prog">yarn</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installing packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-yarn-add">
  <div class="rule-cmd"><span class="prog">yarn</span> add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adding packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-yarn-remove">
  <div class="rule-cmd"><span class="prog">yarn</span> remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removing packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-yarn-upgrade">
  <div class="rule-cmd"><span class="prog">yarn</span> upgrade</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Upgrading packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-yarn-upgrade-interactive">
  <div class="rule-cmd"><span class="prog">yarn</span> upgrade-interactive</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Upgrading packages</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-yarn-link">
  <div class="rule-cmd"><span class="prog">yarn</span> link</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates a global symlink and links the package into node_modules. Modifies the user-level yarn link registry; can shadow real installs of <code>&lt;package&gt;</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-yarn-unlink">
  <div class="rule-cmd"><span class="prog">yarn</span> unlink</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes the global symlink created by <code>yarn link</code>. Affects every project that consumed the linked package.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-yarn-publish">
  <div class="rule-cmd"><span class="prog">yarn</span> publish</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Publishes the package to its registry. Public publish is irreversible: the version number cannot be reused.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-yarn-init">
  <div class="rule-cmd"><span class="prog">yarn</span> init</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Initializes a new package in the current directory by writing <code>package.json</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-yarn-create">
  <div class="rule-cmd"><span class="prog">yarn</span> create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs a <code>create-&lt;name&gt;</code> package to scaffold a project, downloading it if missing. Same trust boundary as <code>curl | bash</code> for untrusted initializers.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-yarn-dlx">
  <div class="rule-cmd"><span class="prog">yarn</span> dlx</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs an arbitrary command through the package manager (downloads the package if missing). Same trust boundary as <code>curl | bash</code> for untrusted packages.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-yarn-cache">
  <div class="rule-cmd"><span class="prog">yarn</span> cache</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Mutates the yarn cache (clean, list). <code>yarn cache clean</code> deletes all cached package tarballs.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-yarn-global">
  <div class="rule-cmd"><span class="prog">yarn</span> global</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Operates on the user-global install location: add, remove, upgrade, bin, list. Modifies binaries on PATH for the current user.</div>
</div>
<div class="rule-row" data-decision="ask" id="package_managers-yarn-set">
  <div class="rule-cmd"><span class="prog">yarn</span> set</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Sets a yarn config key. Affects the project's <code>.yarnrc.yml</code> (Berry) or the user-level <code>.yarnrc</code> (Classic).</div>
</div>
</div>

<p class="note">
  <svg class="alert" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
  <span><b>Custom handlers per package manager.</b> Each program has a small Rust handler (<code>check_npm</code>, <code>check_pnpm</code>, <code>check_yarn</code>, <code>check_pip</code>, <code>check_uv</code>, <code>check_poetry</code>, <code>check_pipx</code>, <code>check_mise</code>) that recognises devtool delegation (e.g. <code>npm eslint</code> routes to the devtools gate), bare invocations (<code>yarn</code> = install), and per-package-manager idioms like <code>pip install --dry-run</code>.</span>
</p>

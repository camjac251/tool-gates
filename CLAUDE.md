# Tool Gates Maintainer Guide

Tool Gates is a Rust permission hook for Claude Code, Codex CLI, and Antigravity CLI, with deprecated Gemini CLI compatibility. It parses shell commands with tree-sitter, applies a deterministic safety floor and per-tool gates, then serializes the decision for the active client.

`AGENTS.md` is a symlink to this file, so keep the guidance client-neutral and repository-specific. General file-reading, code-search, editing, Git, research, and multi-agent rules belong in the machine-wide instructions, not here. Public product behavior belongs in `docs/src/`; this file should retain only the commands, invariants, and gotchas needed before changing the repository.

## Start Here

Documentation routing:

| Change area | Read first |
|---|---|
| Engine pipeline or module ownership | `docs/src/architecture.md` |
| Hook events and client wire formats | `docs/src/hook-model.md` |
| Codex behavior | `docs/src/codex.md` |
| Antigravity behavior | `docs/src/antigravity.md` |
| Permission modes and precedence | `docs/src/modes.md`, `docs/src/auto-mode.md`, `docs/src/settings-precedence.md` |
| Scratch auto-approval | `docs/src/scratch.md` |
| Raw command guardrails | `docs/src/security-floor.md` |
| Write/Edit scanning | `docs/src/security-reminders.md`, `docs/src/design-lint.md` |
| Declarative gates and custom handlers | `docs/src/contributing.md`, `docs/src/custom-handlers.md` |
| Permission reason copy | `docs/src/reason-style.md` |
| CLI or configuration | `docs/src/cli.md`, `docs/src/configuration.md` |
| Recent user-facing changes | `docs/src/whats-new.md` |

## Repository Map

- `rules/*.toml`: declarative gate source of truth.
- `build.rs`: validates the rule catalog and generates Rust gate functions.
- `src/generated/`: generated Rust. Never edit it by hand.
- `src/gates/`: thin wrappers plus custom logic that TOML cannot express.
- `src/raw_floor.rs`: shared pre-AST checks for top-level and nested shell strings.
- `src/security_floor.rs`: hard-block and hard-ask pattern catalog.
- `src/pipe_caps.rs`: output-cap hard denials and carve-outs.
- `src/task_expansion.rs`: mise and package-script expansion.
- `src/main.rs`: CLI, hook entrypoints, client normalization, and output shaping.
- `src/rules_export.rs`: generated Markdown reference pages.
- `docs/src/`: mdBook source and the authoritative product documentation.
- `tests/`: cross-module and wire-contract integration tests.

## Commands

CI uses these commands:

```bash
cargo build --locked
cargo fmt -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo test --locked --features wasm --lib
cargo build --locked --release --target x86_64-unknown-linux-musl
```

Useful targeted forms:

```bash
cargo test gates::git -- --nocapture
cargo test test_git_status_allows
echo '{"tool_name":"Bash","tool_input":{"command":"git status"}}' | tool-gates
```

Documentation commands:

```bash
cargo run --locked --release -- rules export --format md
mise run build-wasm
mise exec -- mdbook build docs
```

Run `mise run build-wasm` when a change affects the browser simulator or the WASM-compatible engine path. The project MSRV is Rust 1.86; do not introduce newer language or standard-library requirements.

## Source-of-Truth Invariants

- Edit `rules/*.toml` for declarative behavior. A normal Cargo build regenerates `src/generated/rules.rs`.
- `priority` in TOML controls generation order only. Runtime dispatch order is the hand-maintained `GATES` array in `src/gates/mod.rs`; `basics` must remain last.
- A program declared under `[[custom_handlers]]` must also be routed by the corresponding Rust gate wrapper. The generated function returns `Skip` for that program so the custom handler can take over.
- Every `[[programs.ask]]` and `[[programs.block]]` rule needs a `reason`. `build.rs` rejects reasons longer than 250 characters. Follow `docs/src/reason-style.md`.
- `build.rs` runs `rustfmt --edition 2024` on generated Rust. Keep that explicit edition because generated formatting otherwise drifts when the build cache is invalidated.
- Wire-format structs are external contracts. Any serialized field added or changed for a client needs a test that asserts its exact JSON key casing and allowed shape.
- `HookOutput::deny()` always carries a reason. On Claude, it omits the optional top-level `systemMessage` unless `.user_visible()` is called for a denial such as a Tier 1 secret block. Codex displays every deny reason as hook feedback regardless of `.user_visible()`.

## Client Integration Invariants

- Claude and deprecated Gemini payloads can be identified from their hook event. Codex emits the same hook event names as Claude, so installed Codex commands must include `--client codex`.
- Antigravity payloads have no `hook_event_name`, so installed commands must include `--client antigravity` or `--client agy`.
- Codex PreToolUse output is deny-only in practice. Allow and Ask produce empty stdout so Codex can apply its own approval policy. Do not emit fields its parser rejects.
- Antigravity keeps the strictest native or hook decision. A hook `allow` is inert, so Tool Gates emits only tightening decisions and otherwise leaves stdout empty. Only PreToolUse is installed because its post payload lacks the tool name and input, and it has no PermissionRequest event.
- Gemini is compatibility-only. New client work should target Antigravity unless the task explicitly concerns existing Gemini setups.

When any of these rules change, update the exact serialization tests plus `docs/src/hook-model.md` and the affected client page.

## Test Invariants

- Tests and examples are public. Use generic placeholders such as `mytool`, `$HOME/scripts/deploy/`, and `my-service`; never encode a real session command, private path, hostname, service, or workflow.
- CI runners have a minimal environment. Tests must not assume optional tools such as `rg`, `bat`, or `fd` are installed. Detect availability and skip gracefully when an external binary is not the behavior under test.
- Assert exact camelCase wire keys with `serde_json::to_string` whenever a struct or enum is serialized for a hook client.

## Generated Documentation

`cargo run --locked --release -- rules export --format md` regenerates:

- `docs/src/gates/*.md`
- `docs/src/security-floor.md`
- `docs/src/hints.md`
- `docs/src/security-reminders.md`
- `docs/src/design-lint.md`

Change their source catalogs or `src/rules_export.rs`, then regenerate. Do not hand-edit generated pages unless the generator itself is the subject of the change. Other pages under `docs/src/` are hand-maintained.

## Releases And Recent Releases

- `docs/src/whats-new.md` is the hand-curated Recent Releases page. Keep the newest version first and preserve the existing HTML entry shape.
- A released version's `src-tag` links to its `chore: release vX.Y.Z` commit, not a feature or merge commit. Find it with `git log --oneline --grep "chore: release vX.Y.Z" origin/main`.
- A version without a merged release PR uses `release pending` with no commit link. Replace it with the release commit after the release lands.
- Curated release prose describes changes in Tool Gates itself. Omit GitHub workflow-only plumbing unless it changes user-visible behavior or the delivered release.
- Documentation-only commits must use a `docs:`, `chore:`, or `ci:` prefix. A `feat:` or `fix:` prefix can make release-plz create an unnecessary version bump even though CI and release workflows ignore `docs/**` and Markdown-only changes.

# Changelog

## [1.5.6](https://github.com/camjac251/tool-gates/compare/v1.5.5...v1.5.6) - 2026-03-21

### Fixed

- *(hooks)* stage build-generated files in pre-commit

### Other

- add Homebrew as recommended install method

## [1.5.5](https://github.com/camjac251/tool-gates/compare/v1.5.4...v1.5.5) - 2026-03-20

### Fixed

- *(ci)* use actions/checkout for homebrew-tap push auth

### Other

- Merge pull request #36 from camjac251/renovate/actions-attest-build-provenance-4.x

## [1.5.4] - 2026-03-20

### Bug Fixes

- Use CARGO_MANIFEST_DIR to detect package verify context
- Remove publish=false from Cargo.toml
- Remove name field from skills so prefix shows in autocomplete

### Refactoring

- Move plugin to subdirectory to prevent skill leakage

## [1.5.2] - 2026-03-18

### Bug Fixes

- Require all sub-commands to match settings for compound allow
## [1.5.1] - 2026-03-14

### Bug Fixes

- Remove patch from acceptEdits auto-allow, add 20 security tests
## [1.5.0] - 2026-03-13

### Features

- Smarter secret handling for .env and doc files
## [1.4.0] - 2026-03-11

### Features

- Add skill auto-approval and doctor command
## [1.3.0] - 2026-03-10

### Features

- Add per-tier config toggles and Configuration docs
## [1.2.0] - 2026-03-10

### Bug Fixes

- Replace deprecated approve decision with proper allow/no-opinion

### Features

- Add MCP tool matcher for PreToolUse hooks
- Add security reminders for Write/Edit/MultiEdit content scanning
## [1.1.0] - 2026-03-10

### Bug Fixes

- Address clippy warnings in parser tests
- Exclude shell keywords from fuzz test
- Reduce false positives for pipe patterns and xargs
- Build before fmt to generate code
- Format generated code before clippy
- Update rust crate toml to 0.9
- Build before fmt to generate code
- Lefthook pre-commit builds before fmt
- Catch fd -x/--exec with dangerous commands
- Allow /dev/null redirections (not actual file writes)
- Detect implicit POST in gh api with -f/--field flags
- Exclude arrow operators (=>) from redirection detection
- Add sg as alias for ast-grep
- Exclude $ from redirection detection for ast-grep metavars
- Track cd commands when expanding mise tasks
- Go run should ask, not allow
- Deny rules should block directly, not defer
- Address multiple gate bypass vulnerabilities
- Allow lint/check/format commands through gate path
- Route exec/run commands through all gates
- Require approval for commands that write to local filesystem
- Detect xargs kubectl delete pattern
- Ignore > inside quoted strings when detecting redirections
- Make tests independent of installed tools
- Ignore | inside quoted strings when detecting pipe-to-shell
- Convert Skip to Ask before comparing in check_command_result
- Update rust crate ratatui to 0.30
- Add Backend::Error constraint for ratatui 0.30
- Update rust crate crossterm to 0.29
- Add word boundaries to xargs dangerous command detection
- Update rust crate toml to v1
- Strip comments before raw string security checks
- Capture numeric args for accurate hints
- Preserve gate hints on settings decisions
- Use camelCase for PermissionRequest decision fields
- Make hint-preservation tests CI-portable
- Default is_success to true for PostToolUse events
- Only treat backslash as escape in double quotes
- Use quote-stripped string for eval/xargs/find/fd checks
- Handle directory and root blocked paths
- Use word-boundary :* format instead of glob *
- Race-safe clear, exact project filter, per-project dedup
- Eliminate TOCTOU race with atomic take
- Store cwd alongside project_id for lossless display
- Gate state-changing flags on commands previously blanket-allowed
- Check settings and security patterns before mise/package.json task expansion
- Use manifest-based release-please config

### Features

- Initial commit - Rust bash permission gate for Claude Code
- Integrate settings.json to respect user permissions
- Add base64 to safe commands list
- Add declarative rules system with build-time codegen
- Add --version flag with git tag info
- Add shellcheck gate and generate unified gate functions
- Add hadolint to allowed devtools
- Add read-only system info commands and golangci-lint
- Parse xargs sh -c scripts to allow safe commands
- Expand mise tasks to underlying commands for permission checks
- Detect devtools invoked via npm/pnpm/yarn
- Expand npm/pnpm/yarn scripts to underlying commands
- Extract commands from Python run subcommands
- Parse bash/sh/zsh -c scripts for permission checks
- Add suggestions and acceptEdits mode support
- Add cwd boundary and additionalDirectories support
- Add mise, docker compose, go fmt, gofmt, golangci-lint support
- Add gci (Go import organizer) support
- Make file-editing detection declarative via TOML
- Add permission gate for bd CLI
- Add permission gate for Shortcut CLI
- Add mcp-cli permission gate
- Treat search/ endpoints as read-only for gh api
- Add modern CLI hints via additionalContext
- Add PermissionRequest hook support for subagent approval
- Add hooks subcommand for managing Claude Code hooks
- Add ty, gitleaks, lefthook and expand Python tool support
- Auto-allow mkdir within allowed directories
- Add command approval learning system
- Redesign review TUI with grouped commands and multi-project support
- Allow sd in pipe mode (no file args)
- Add choose to safe commands
- Prefer sg for code grep and add actionable find rewrites
- Add project skills for testing and hook reference
- Implement project list toggle with cursor navigation
- Handle `command` builtin as transparent wrapper
- Add Claude Code plugin, self-gate, and AST-aware settings matching
- Add missing read-only gates from doti session analysis
- Add gate-audit skill for mining sessions for edge cases
- Session-scoped hint dedup to reduce context tax
- Redesign review TUI with project-first dashboard layout
- Switch to release-please, improve CI pipeline
- Rename bash-gates to tool-gates
- Unified tool routing with configurable blocking and file guards

### Refactoring

- Standardize LazyLock and extract test helper
- Simplify CommandInfo and fix gate block priority
- Make more gate rules declarative via TOML
- Remove suggestions code (not supported by Claude Code hooks)
- Align PermissionRequest with PreToolUse policy path
- Harden optional metadata handling and remove dead gate path
- Simplify release workflow
- Reduce approval context to first-ask-only one-liner

# Changelog

## [1.11.0](https://github.com/camjac251/tool-gates/compare/v1.10.0...v1.11.0) - 2026-04-03

### Added

- *(gates)* acceptEdits wrapper resolution for package manager invocations

## [1.10.0](https://github.com/camjac251/tool-gates/compare/v1.9.2...v1.10.0) - 2026-04-03

### Added

- *(gates)* add runtimes gate, expand coverage across all gates

## [1.9.2](https://github.com/camjac251/tool-gates/compare/v1.9.1...v1.9.2) - 2026-03-31

### Fixed

- *(ci)* remove redundant workflow_dispatch that races with push

## [1.9.1](https://github.com/camjac251/tool-gates/compare/v1.9.0...v1.9.1) - 2026-03-31

### Fixed

- *(router)* remove approval context from additionalContext

## [1.9.0](https://github.com/camjac251/tool-gates/compare/v1.8.0...v1.9.0) - 2026-03-31

### Added

- *(hooks)* detect and update stale matchers on hooks add

## [1.8.0](https://github.com/camjac251/tool-gates/compare/v1.7.3...v1.8.0) - 2026-03-30

### Added

- *(permission_request)* auto-approve Edit/Write in agent worktrees

### Fixed

- *(router)* let gate-allowed commands participate in compound settings approval

### Other

- *(git)* clarify branch allow rule covers create too

## [1.7.3](https://github.com/camjac251/tool-gates/compare/v1.7.2...v1.7.3) - 2026-03-28

### Other

- remove MultiEdit tool and mcp-cli gate
- replace em-dash patterns in source code and config
- *(plugin)* bump to 1.5.8, add when_to_use to skills
- replace em-dash patterns with periods and commas
- Merge pull request #46 from camjac251/renovate/proptest-1.x-lockfile

## [1.7.2](https://github.com/camjac251/tool-gates/compare/v1.7.1...v1.7.2) - 2026-03-25

### Fixed

- *(hooks)* resolve binary path via argv[0] and PATH lookup

## [1.7.1](https://github.com/camjac251/tool-gates/compare/v1.7.0...v1.7.1) - 2026-03-25

### Fixed

- *(hooks)* use symlink path instead of canonicalized Cellar path

## [1.7.0](https://github.com/camjac251/tool-gates/compare/v1.6.0...v1.7.0) - 2026-03-25

### Added

- *(gemini)* native BeforeTool/AfterTool hook support

## [1.6.0](https://github.com/camjac251/tool-gates/compare/v1.5.10...v1.6.0) - 2026-03-22

### Added

- *(gates)* add gates for missing programs

## [1.5.10](https://github.com/camjac251/tool-gates/compare/v1.5.9...v1.5.10) - 2026-03-22

### Fixed

- *(build)* format generated code with rustfmt, prettyplease fallback
- *(build)* run rustfmt on generated files to prevent dirty worktree
- *(hooks)* use recursive globs so hooks trigger for all source files
- *(parser)* include expansion nodes in command argument extraction
- *(security)* detect github_pat_ fine-grained personal access tokens
- *(security)* detect Stripe sk_live_ and sk_test_ secret keys
- *(cache)* use atomic write-then-rename for hint tracker and tool cache
- *(parser)* split compound commands in fallback parser
- *(parser)* recover from poisoned mutex instead of panicking
- *(main)* log serialization errors instead of silently swallowing
- *(parser)* strip transparent command wrappers before gate evaluation
- *(router)* block entire .git/ directory in acceptEdits mode

### Other

- *(cache)* remove unused tools from detection cache
- *(cache)* remove unused lsd from tool detection
- *(router)* compile security regexes once via LazyLock

## [1.5.9](https://github.com/camjac251/tool-gates/compare/v1.5.8...v1.5.9) - 2026-03-21

### Fixed

- *(hints)* remove ALWAYS, fix pipe false positives, add new detections

### Other

- bump plugin versions to 1.5.7
- update skills and convert hook-reference to path-scoped rule

## [1.5.8](https://github.com/camjac251/tool-gates/compare/v1.5.7...v1.5.8) - 2026-03-21

### Fixed

- *(pending)* sync simulate_append test helper with new dedup logic
- *(pending)* per-subcommand gate evaluation for compound commands

### Other

- add Windows x64 and arm64 build targets

## [1.5.7](https://github.com/camjac251/tool-gates/compare/v1.5.6...v1.5.7) - 2026-03-21

### Fixed

- *(ci)* specify musl target for binary size check
- *(settings)* specificity-based ask/allow resolution and $HOME expansion

### Other

- use cam-release-bot app token for release automation
- auto-merge release-plz PRs and trigger release

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

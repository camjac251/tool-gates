<div align="center">

# Tool Gates

**Intelligent tool permission gate for AI coding assistants**

[![Documentation](https://img.shields.io/badge/docs-live-blue.svg)](https://camjac251.github.io/tool-gates/)
[![CI](https://github.com/camjac251/tool-gates/actions/workflows/ci.yml/badge.svg)](https://github.com/camjac251/tool-gates/actions/workflows/ci.yml)
[![Release](https://github.com/camjac251/tool-gates/actions/workflows/release.yml/badge.svg)](https://github.com/camjac251/tool-gates/actions/workflows/release.yml)
[![Rust](https://img.shields.io/badge/rust-1.86+-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A hook for [Claude Code](https://code.claude.com/docs/en/hooks), [Codex CLI](https://github.com/openai/codex), [Antigravity CLI](https://antigravity.google/docs/cli-overview), and the deprecated [Gemini CLI](https://github.com/google-gemini/gemini-cli) that gates Bash commands, file operations, and tool invocations using AST parsing. Determines whether to allow, ask, or block based on potential impact.

### 📚 [Read the Live Documentation](https://camjac251.github.io/tool-gates/)

[Installation](#installation) · [Quick Start](#quick-start) · [Features](#features) · [Architecture](#architecture)

</div>

---

## Quick Start

Tool Gates integrates into your AI assistant session by checking tool calls before they run.

### 1. Installation

#### Homebrew (macOS & Linux)

```bash
brew install camjac251/tap/tool-gates
```

For other installation methods, see the [Installation Guide](https://camjac251.github.io/tool-gates/install.html).

### 2. Configure Hooks

Install the hooks automatically for your preferred CLI tool:

```bash
# For Claude Code (recommended)
tool-gates hooks add -s user

# For Codex CLI
tool-gates hooks add --codex

# For Antigravity CLI (agy)
tool-gates hooks add --antigravity  # ~/.gemini/config/hooks.json
tool-gates hooks add --antigravity -s project  # .agents/hooks.json

# For Gemini CLI (deprecated; Google sunsets it 2026-06-18)
tool-gates hooks add --gemini
```

Verify your installation using the doctor command:

```bash
tool-gates doctor
```

---

## Features

- **AST Parsing**: Uses [tree-sitter-bash](https://github.com/tree-sitter/tree-sitter-bash) to parse shell commands, handling `&&`, `||`, `|`, and `;` chains correctly.
- **Approval Learning**: Tracks manually approved commands and uses the review TUI to save patterns to `settings.json`.
- **Security Floor**: Blocks dangerous shell patterns like pipe-to-shell, command injection, and `eval`. For details, see the [Security Floor documentation](https://camjac251.github.io/tool-gates/security-floor.html).
- **Security Reminders**: Scans file contents on writes and edits for 28 anti-patterns across three tiers. For details, see the [Security Reminders documentation](https://camjac251.github.io/tool-gates/security-reminders.html).
- **Design Lint**: Scans UI file writes and edits for generic, templated design patterns and missing UI-quality basics (overused gradients and palettes, the default sans font, placeholder content, em dashes in copy, hardcoded palette colors, missing focus styles). Opt-in. For details, see the [Design Lint documentation](https://camjac251.github.io/tool-gates/design-lint.html).
- **File Guards**: Protects sensitive AI configuration files (like `CLAUDE.md`, `.cursorrules`) from symlink-based read or write attacks.
- **Modern CLI Hints**: Recommends modern alternatives like `bat`, `rg`, or `fd` when legacy commands are run.
- **Auto Mode & Accept Edits**: Adapts behavior dynamically based on the current session permission mode.

> [!TIP]
> For a full list of features and details on how they work, read the [Introduction](https://camjac251.github.io/tool-gates/).

---

## Architecture

Tool Gates operates at the hook layer to analyze and intercept actions before execution:

```mermaid
flowchart TD
    CC[AI Assistant] --> TOOL{Tool Type}
    TOOL -->|Bash/Monitor| CMD[Shell Command]
    TOOL -->|Write/Edit| FILE[File Operation]

    subgraph PTU [PreToolUse Hook]
        direction TB
        PTU_CHECK[tool-gates check] --> PTU_DEC{Decision}
        PTU_DEC -->|dangerous| PTU_DENY[deny]
        PTU_DEC -->|risky| PTU_ASK[ask + track]
        PTU_DEC -->|safe| PTU_CTX{Context?}
        PTU_CTX -->|main session| PTU_ALLOW[allow ✓]
        PTU_CTX -->|subagent| PTU_IGNORED[ignored by Claude]
    end

    subgraph PTU_FILE [PreToolUse - File Tools]
        direction TB
        FG[Symlink guard] --> FG_DEC{Symlink?}
        FG_DEC -->|guarded symlink| FG_DENY[deny - use real path]
        FG_DEC -->|ok| SEC{Content scan}
        SEC -->|hardcoded secret| SEC_DENY[deny - Tier 1]
        SEC -->|safe| SEC_PASS[pass through]
    end

    CMD --> PTU
    FILE --> PTU_FILE

    PTU_IGNORED --> INTERNAL[Claude internal checks]
    INTERNAL -->|path outside cwd| PR_HOOK

    subgraph PR_HOOK [PermissionRequest Hook]
        direction TB
        PR_CHECK[tool-gates re-check] --> PR_DEC{Decision}
        PR_DEC -->|safe| PR_ALLOW[allow ✓]
        PR_DEC -->|dangerous| PR_DENY[deny]
        PR_DEC -->|risky| PR_PROMPT[show prompt]
    end

    PTU_ASK --> EXEC[Command Executes]
    PR_PROMPT --> USER_APPROVE[User Approves] --> EXEC
    SEC_PASS --> FILE_EXEC[Write Succeeds]

    subgraph POST [PostToolUse Hook]
        direction TB
        POST_CHECK[check tracking] --> POST_DEC{Tracked + Success?}
        POST_DEC -->|yes| PENDING[add to pending queue]
        POST_DEC -->|no| POST_SKIP[skip]
        POST_SEC[Security scan] --> POST_SEC_DEC{Anti-pattern?}
        POST_SEC_DEC -->|yes| NUDGE[inject reminder]
        POST_SEC_DEC -->|no| POST_SKIP
    end

    EXEC --> POST
    FILE_EXEC --> POST_SEC
    PENDING --> REVIEW[tool-gates review]
    REVIEW --> SETTINGS[settings.json]
```

> [!NOTE]
> To learn more about the lifecycle, read the [Hook Model documentation](https://camjac251.github.io/tool-gates/hook-model.html).

---

## Configuration

Tool Gates is highly customizable via `~/.config/tool-gates/config.toml`. Key configuration options include:

- **Feature Toggles**: Selectively enable or disable gates, file guards, hints, and security reminders.
- **Git Aliases**: Automatically resolve git aliases against your git configuration.
- **Tool Blocking**: Block specific tools or restrict them from accessing certain domains.
- **Skill Auto-Approval**: Define rules to automatically approve skills under trusted paths or project conditions.
- **Codex Project Edits**: Automatically approve patch applications inside the project directory.

> [!NOTE]
> Refer to the [Configuration Reference](https://camjac251.github.io/tool-gates/configuration.html) for detailed settings templates and examples.

---

## CLI & Approval Learning

You can manage learned patterns and configure permissions directly using the CLI:

```bash
# Start the interactive TUI to review pending approvals
tool-gates review

# List currently stored rules
tool-gates rules list

# Check hook and configuration health
tool-gates doctor
```

> [!NOTE]
> For more CLI commands, see the [CLI Command Reference](https://camjac251.github.io/tool-gates/cli.html) and [Approval Learning](https://camjac251.github.io/tool-gates/approval-learning.html).

## Credits

Security reminder patterns were built on and informed by:

- [Anthropic's security-guidance plugin](https://github.com/anthropics/claude-plugins-official/tree/main/plugins/security-guidance), the official Claude Code security hook (9 base patterns we expanded to 28)
- [Arcanum-Sec/sec-context](https://github.com/Arcanum-Sec/sec-context), curated security anti-pattern database synthesized from 150+ sources
- [SecureCodeWarrior/ai-security-rules](https://github.com/SecureCodeWarrior/ai-security-rules), security rule files for AI coding tools
- [OWASP Top 10](https://owasp.org/www-project-top-ten/), standard web application security risks
- [dwarvesf/claude-guardrails](https://github.com/dwarvesf/claude-guardrails), multi-layer defense hooks for Claude Code
- [GitHub Actions workflow injection research](https://github.blog/security/vulnerability-research/how-to-catch-github-actions-workflow-injections-before-attackers-do/), GHA injection patterns and remediation

---

## References

- [Live Documentation Website](https://camjac251.github.io/tool-gates/)
- [13 Gates Reference](https://camjac251.github.io/tool-gates/gates/git.html)
- [Claude Code Hooks Guide](https://code.claude.com/docs/en/hooks)
- [Antigravity CLI Hooks](https://antigravity.google/docs/hooks)
- [Gemini CLI Repository](https://github.com/google-gemini/gemini-cli)
- [tree-sitter-bash](https://github.com/tree-sitter/tree-sitter-bash)

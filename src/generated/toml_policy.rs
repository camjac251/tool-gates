//! Auto-generated TOML policy for Gemini CLI.
//! DO NOT EDIT - changes will be overwritten by build.rs

/// Generated TOML policy content
pub const TOML_POLICY: &str = r#"
# Bash Gates - Generated Policy for Gemini CLI
#
# This file was auto-generated from declarative TOML rules.
# Save to: ~/.gemini/policies/tool-gates.toml
#
# Only allow and deny rules are generated.
# Everything else inherits Gemini CLI's default: ask_user
#

# === MCP gate ===

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "mcp-cli servers",
    "mcp-cli tools",
    "mcp-cli info",
    "mcp-cli grep",
    "mcp-cli resources",
    "mcp-cli read",
    "mcp-cli help",
]
decision = "allow"
priority = 100

# === GH gate ===

# Block: Deleting repositories is blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "gh repo delete"
decision = "deny"
priority = 900

# Block: Logging out is blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "gh auth logout"
decision = "deny"
priority = 900

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "gh issue view",
    "gh issue list",
    "gh issue status",
    "gh pr view",
    "gh pr list",
    "gh pr status",
    "gh pr diff",
    "gh pr checks",
    "gh pr develop",
    "gh repo view",
    "gh repo list",
    "gh search issues",
    "gh search prs",
    "gh search repos",
    "gh search commits",
    "gh search code",
    "gh status",
    "gh auth status",
    "gh auth token",
    "gh config get",
    "gh config list",
    "gh run list",
    "gh run view",
    "gh workflow list",
    "gh workflow view",
    "gh release list",
    "gh release view",
    "gh gist list",
    "gh gist view",
    "gh label list",
    "gh codespace list",
    "gh cs list",
    "gh ssh-key list",
    "gh gpg-key list",
    "gh extension list",
    "gh browse",
    "gh alias list",
    "gh cache list",
    "gh variable list",
    "gh secret list",
    "gh ruleset list",
    "gh ruleset view",
    "gh project list",
    "gh project view",
]
decision = "allow"
priority = 100

# === GIT gate ===

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "git status",
    "git log",
    "git diff",
    "git show",
    "git describe",
    "git rev-parse",
    "git ls-files",
    "git blame",
    "git reflog",
    "git shortlog",
    "git whatchanged",
    "git ls-tree",
    "git cat-file",
    "git rev-list",
    "git name-rev",
    "git for-each-ref",
    "git symbolic-ref",
    "git verify-commit",
    "git verify-tag",
    "git fsck",
    "git count-objects",
    "git check-ignore",
    "git check-attr",
    "git grep",
    "git merge-base",
    "git show-ref",
    "git help",
    "git version",
    "git --version",
    "git -h",
    "git --help",
    "git config get",
    "git config list",
    "git config --get",
    "git config --list",
    "git stash list",
    "git stash show",
    "git worktree list",
    "git submodule status",
    "git remote show",
    "git remote -v",
    "git remote get-url",
]
decision = "allow"
priority = 100

# === CLOUD gate ===

# Block: Deleting IAM users is blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "aws iam delete-user"
decision = "deny"
priority = 900

# Block: Organization deletion blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "aws organizations delete"
decision = "deny"
priority = 900

# aws: allow when action starts with describe
[[rule]]
toolName = "run_shell_command"
commandRegex = "aws\\s+\\S+\\s+describe[^\\s]*"
decision = "allow"
priority = 100

# aws: allow when action starts with list
[[rule]]
toolName = "run_shell_command"
commandRegex = "aws\\s+\\S+\\s+list[^\\s]*"
decision = "allow"
priority = 100

# aws: allow when action starts with get
[[rule]]
toolName = "run_shell_command"
commandRegex = "aws\\s+\\S+\\s+get[^\\s]*"
decision = "allow"
priority = 100

# aws: allow when action starts with head
[[rule]]
toolName = "run_shell_command"
commandRegex = "aws\\s+\\S+\\s+head[^\\s]*"
decision = "allow"
priority = 100

# aws: allow when action starts with query
[[rule]]
toolName = "run_shell_command"
commandRegex = "aws\\s+\\S+\\s+query[^\\s]*"
decision = "allow"
priority = 100

# aws: allow when action starts with scan
[[rule]]
toolName = "run_shell_command"
commandRegex = "aws\\s+\\S+\\s+scan[^\\s]*"
decision = "allow"
priority = 100

# aws: allow when action starts with filter
[[rule]]
toolName = "run_shell_command"
commandRegex = "aws\\s+\\S+\\s+filter[^\\s]*"
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "aws --version",
    "aws help",
    "aws s3 ls",
    "aws sts get-caller-identity",
    "aws sts get-session-token",
    "aws configure list",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "gcloud config list",
    "gcloud config get-value",
    "gcloud auth list",
    "gcloud auth describe",
    "gcloud projects list",
    "gcloud projects describe",
    "gcloud compute instances list",
    "gcloud compute instances describe",
    "gcloud compute zones list",
    "gcloud compute regions list",
    "gcloud compute machine-types list",
    "gcloud container clusters list",
    "gcloud container clusters describe",
    "gcloud storage ls",
    "gcloud storage cat",
    "gcloud functions list",
    "gcloud functions describe",
    "gcloud functions logs",
    "gcloud run services list",
    "gcloud run services describe",
    "gcloud sql instances list",
    "gcloud sql instances describe",
    "gcloud logging read",
    "gcloud iam list",
    "gcloud iam describe",
    "gcloud secrets list",
    "gcloud secrets describe",
    "gcloud secrets versions",
    "gcloud --version",
    "gcloud help",
    "gcloud info",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "az --version",
    "az --help",
    "az -h",
]
decision = "allow"
priority = 100

# terraform fmt: allow when -check present
[[rule]]
toolName = "run_shell_command"
commandRegex = "terraform fmt\\s+.*\\-check"
decision = "allow"
priority = 110

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "terraform plan",
    "terraform show",
    "terraform output",
    "terraform validate",
    "terraform version",
    "terraform providers",
    "terraform graph",
    "terraform -version",
    "terraform --version",
    "terraform -help",
    "terraform --help",
    "terraform state list",
    "terraform state show",
    "terraform workspace list",
]
decision = "allow"
priority = 100

# Block: Cannot delete kube-system
[[rule]]
toolName = "run_shell_command"
commandPrefix = "kubectl delete namespace kube-system"
decision = "deny"
priority = 900

# Block: Cannot delete kube-system
[[rule]]
toolName = "run_shell_command"
commandPrefix = "kubectl delete ns kube-system"
decision = "deny"
priority = 900

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "kubectl get",
    "kubectl describe",
    "kubectl logs",
    "kubectl top",
    "kubectl explain",
    "kubectl api-resources",
    "kubectl api-versions",
    "kubectl cluster-info",
    "kubectl version",
    "kubectl -h",
    "kubectl --help",
    "kubectl config view",
    "kubectl config get-contexts",
    "kubectl config current-context",
    "kubectl config get-clusters",
    "kubectl auth can-i",
    "kubectl auth whoami",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "docker ps",
    "docker images",
    "docker inspect",
    "docker logs",
    "docker stats",
    "docker top",
    "docker port",
    "docker version",
    "docker info",
    "docker history",
    "docker -v",
    "docker --version",
    "docker -h",
    "docker --help",
    "docker network ls",
    "docker network list",
    "docker network inspect",
    "docker volume ls",
    "docker volume list",
    "docker volume inspect",
    "docker system df",
    "docker system info",
    "docker compose ps",
    "docker compose logs",
    "docker compose config",
    "docker compose images",
    "docker compose ls",
    "docker compose version",
    "docker compose top",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "podman ps",
    "podman images",
    "podman inspect",
    "podman logs",
    "podman stats",
    "podman top",
    "podman port",
    "podman version",
    "podman info",
    "podman history",
    "podman search",
    "podman healthcheck",
    "podman -v",
    "podman --version",
    "podman -h",
    "podman --help",
    "podman network ls",
    "podman network list",
    "podman network inspect",
    "podman volume ls",
    "podman volume list",
    "podman volume inspect",
    "podman system df",
    "podman system info",
    "podman machine info",
    "podman machine inspect",
    "podman machine list",
    "podman pod ps",
    "podman pod list",
    "podman pod inspect",
    "podman pod logs",
    "podman pod top",
    "podman pod stats",
    "podman secret ls",
    "podman secret list",
    "podman secret inspect",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "docker-compose ps",
    "docker-compose logs",
    "docker-compose config",
    "docker-compose images",
    "docker-compose ls",
    "docker-compose version",
    "docker-compose -h",
    "docker-compose --help",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "helm list",
    "helm ls",
    "helm get",
    "helm show",
    "helm search",
    "helm repo list",
    "helm status",
    "helm history",
    "helm version",
    "helm -h",
    "helm --help",
    "helm template",
    "helm lint",
    "helm verify",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "pulumi preview",
    "pulumi whoami",
    "pulumi version",
    "pulumi -h",
    "pulumi --help",
    "pulumi stack ls",
    "pulumi stack list",
    "pulumi stack output",
    "pulumi stack history",
    "pulumi stack export",
    "pulumi config get",
]
decision = "allow"
priority = 100

# === PACKAGE_MANAGERS gate ===

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "npm list",
    "npm ls",
    "npm ll",
    "npm la",
    "npm view",
    "npm show",
    "npm info",
    "npm search",
    "npm help",
    "npm get",
    "npm prefix",
    "npm root",
    "npm bin",
    "npm whoami",
    "npm token",
    "npm team",
    "npm outdated",
    "npm doctor",
    "npm explain",
    "npm why",
    "npm fund",
    "npm query",
    "npm -v",
    "npm --version",
    "npm -h",
    "npm --help",
    "npm test",
    "npm build",
    "npm dev",
    "npm lint",
    "npm check",
    "npm typecheck",
    "npm format",
    "npm prettier",
    "npm eslint",
    "npm tsc",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "pnpm list",
    "pnpm ls",
    "pnpm ll",
    "pnpm why",
    "pnpm outdated",
    "pnpm -v",
    "pnpm --version",
    "pnpm -h",
    "pnpm --help",
    "pnpm test",
    "pnpm build",
    "pnpm dev",
    "pnpm lint",
    "pnpm check",
    "pnpm typecheck",
    "pnpm format",
    "pnpm tsc",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "yarn list",
    "yarn info",
    "yarn why",
    "yarn outdated",
    "yarn audit",
    "yarn -v",
    "yarn --version",
    "yarn -h",
    "yarn --help",
    "yarn test",
    "yarn build",
    "yarn dev",
    "yarn lint",
    "yarn check",
    "yarn typecheck",
    "yarn format",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "pip list",
    "pip show",
    "pip freeze",
    "pip check",
    "pip search",
    "pip index",
    "pip debug",
    "pip -V",
    "pip --version",
    "pip -h",
    "pip --help",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "uv version",
    "uv help",
    "uv tree",
    "uv --version",
    "uv -V",
    "uv -h",
    "uv --help",
    "uv pip list",
    "uv pip show",
    "uv pip freeze",
    "uv pip check",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "cargo check",
    "cargo doc",
    "cargo tree",
    "cargo metadata",
    "cargo pkgid",
    "cargo verify-project",
    "cargo search",
    "cargo info",
    "cargo locate-project",
    "cargo read-manifest",
    "cargo version",
    "cargo -V",
    "cargo --version",
    "cargo -h",
    "cargo --help",
    "cargo help",
    "cargo build",
    "cargo run",
    "cargo test",
    "cargo bench",
    "cargo fmt",
    "cargo clean",
]
decision = "allow"
priority = 100

# rustc: allow when --version present
[[rule]]
toolName = "run_shell_command"
commandRegex = "rustc\\s+.*\\-\\-version"
decision = "allow"
priority = 110

# rustc: allow when -V present
[[rule]]
toolName = "run_shell_command"
commandRegex = "rustc\\s+.*\\-V"
decision = "allow"
priority = 110

# rustc: allow when --print present
[[rule]]
toolName = "run_shell_command"
commandRegex = "rustc\\s+.*\\-\\-print"
decision = "allow"
priority = 110

# rustc: allow when --explain present
[[rule]]
toolName = "run_shell_command"
commandRegex = "rustc\\s+.*\\-\\-explain"
decision = "allow"
priority = 110

# rustc: allow when --help present
[[rule]]
toolName = "run_shell_command"
commandRegex = "rustc\\s+.*\\-\\-help"
decision = "allow"
priority = 110

# rustc: allow when -h present
[[rule]]
toolName = "run_shell_command"
commandRegex = "rustc\\s+.*\\-h"
decision = "allow"
priority = 110

# rustc: allow when -vV present
[[rule]]
toolName = "run_shell_command"
commandRegex = "rustc\\s+.*\\-vV"
decision = "allow"
priority = 110

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "rustup show",
    "rustup toolchain list",
    "rustup target list",
    "rustup component list",
    "rustup run",
    "rustup which",
    "rustup doc",
    "rustup --version",
    "rustup -V",
    "rustup --help",
    "rustup -h",
    "rustup help",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "go list",
    "go doc",
    "go version",
    "go vet",
    "go help",
    "go -h",
    "go --help",
    "go build",
    "go test",
    "go clean",
    "go mod graph",
    "go mod verify",
    "go mod why",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "bun pm",
    "bun -v",
    "bun --version",
    "bun -h",
    "bun --help",
    "bun test",
    "bun build",
    "bun dev",
    "bun lint",
    "bun check",
    "bun typecheck",
    "bun format",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "conda info",
    "conda list",
    "conda search",
    "conda package",
    "conda --version",
    "conda -V",
    "conda --help",
    "conda -h",
    "conda doctor",
    "conda notices",
    "conda compare",
    "conda env list",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "poetry show",
    "poetry search",
    "poetry check",
    "poetry config list",
    "poetry env info",
    "poetry env list",
    "poetry env activate",
    "poetry version",
    "poetry about",
    "poetry --version",
    "poetry -V",
    "poetry --help",
    "poetry -h",
    "poetry build",
    "poetry lock",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "pipx list",
    "pipx environment",
    "pipx --version",
    "pipx --help",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "mise ls",
    "mise list",
    "mise current",
    "mise where",
    "mise which",
    "mise env",
    "mise version",
    "mise --version",
    "mise -V",
    "mise --help",
    "mise -h",
    "mise help",
    "mise doctor",
    "mise plugins",
    "mise settings",
    "mise alias",
    "mise bin-paths",
    "mise completion",
    "mise direnv",
    "mise outdated",
    "mise reshim",
    "mise trust",
    "mise exec",
    "mise registry",
]
decision = "allow"
priority = 100

# === BEADS gate ===

# bd cleanup: allow when --dry-run present
[[rule]]
toolName = "run_shell_command"
commandRegex = "bd cleanup\\s+.*\\-\\-dry\\-run"
decision = "allow"
priority = 110

# bd compact: allow when --dry-run present
[[rule]]
toolName = "run_shell_command"
commandRegex = "bd compact\\s+.*\\-\\-dry\\-run"
decision = "allow"
priority = 110

# bd delete: allow when --dry-run present
[[rule]]
toolName = "run_shell_command"
commandRegex = "bd delete\\s+.*\\-\\-dry\\-run"
decision = "allow"
priority = 110

# bd admin cleanup: allow when --dry-run present
[[rule]]
toolName = "run_shell_command"
commandRegex = "bd admin cleanup\\s+.*\\-\\-dry\\-run"
decision = "allow"
priority = 110

# bd admin compact: allow when --dry-run present
[[rule]]
toolName = "run_shell_command"
commandRegex = "bd admin compact\\s+.*\\-\\-dry\\-run"
decision = "allow"
priority = 110

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "bd list",
    "bd show",
    "bd ready",
    "bd blocked",
    "bd count",
    "bd search",
    "bd where",
    "bd info",
    "bd version",
    "bd help",
    "bd status",
    "bd doctor",
    "bd lint",
    "bd human",
    "bd onboard",
    "bd completion",
    "bd thanks",
    "bd detect-pollution",
    "bd dep tree",
    "bd dep cycles",
    "bd graph",
    "bd label list",
    "bd label list-all",
    "bd daemons list",
    "bd daemons health",
    "bd daemons logs",
    "bd daemon health",
    "bd daemon logs",
    "bd config get",
    "bd config list",
    "bd stats",
    "bd activity",
    "bd stale",
    "bd orphans",
    "bd preflight",
    "bd epic status",
    "bd close-eligible",
    "bd swarm list",
    "bd gate list",
    "bd gate show",
    "bd gate check",
    "bd gate discover",
    "bd template list",
    "bd template show",
    "bd formula list",
    "bd formula show",
    "bd mol show",
    "bd mol current",
    "bd mol stale",
    "bd mol progress",
    "bd mol list",
    "bd slot show",
    "bd slot list",
    "bd agent show",
    "bd agent list",
    "bd state",
    "bd state list",
    "bd worktree list",
    "bd repo list",
    "bd repo show",
    "bd jira status",
    "bd jira list",
    "bd jira show",
    "bd linear status",
    "bd linear list",
    "bd linear show",
    "bd ship list",
    "bd ship show",
    "bd upgrade status",
    "bd upgrade review",
    "bd prime",
    "bd quickstart",
    "bd workflow",
    "bd tips",
    "bd deleted",
    "bd hook",
]
decision = "allow"
priority = 100

# === TOOL_GATES gate ===

# tool-gates: allow when --help present
[[rule]]
toolName = "run_shell_command"
commandRegex = "tool\\-gates\\s+.*\\-\\-help"
decision = "allow"
priority = 110

# tool-gates: allow when -h present
[[rule]]
toolName = "run_shell_command"
commandRegex = "tool\\-gates\\s+.*\\-h"
decision = "allow"
priority = 110

# tool-gates: allow when --version present
[[rule]]
toolName = "run_shell_command"
commandRegex = "tool\\-gates\\s+.*\\-\\-version"
decision = "allow"
priority = 110

# tool-gates: allow when -V present
[[rule]]
toolName = "run_shell_command"
commandRegex = "tool\\-gates\\s+.*\\-V"
decision = "allow"
priority = 110

# tool-gates: allow when --tools-status present
[[rule]]
toolName = "run_shell_command"
commandRegex = "tool\\-gates\\s+.*\\-\\-tools\\-status"
decision = "allow"
priority = 110

# tool-gates: allow when --export-toml present
[[rule]]
toolName = "run_shell_command"
commandRegex = "tool\\-gates\\s+.*\\-\\-export\\-toml"
decision = "allow"
priority = 110

# tool-gates: allow when --gemini-policy present
[[rule]]
toolName = "run_shell_command"
commandRegex = "tool\\-gates\\s+.*\\-\\-gemini\\-policy"
decision = "allow"
priority = 110

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "tool-gates pending list",
    "tool-gates pending count",
    "tool-gates rules list",
    "tool-gates hooks status",
]
decision = "allow"
priority = 100

# === DEVTOOLS gate ===

# sad: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "sad "
decision = "allow"
priority = 11

# ast-grep: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "ast-grep "
decision = "allow"
priority = 11

# yq: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "yq "
decision = "allow"
priority = 11

# jq: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "jq "
decision = "allow"
priority = 11

# semgrep: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "semgrep "
decision = "allow"
priority = 11

# comby: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "comby "
decision = "allow"
priority = 11

# grit: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "grit "
decision = "allow"
priority = 11

[[rule]]
toolName = "run_shell_command"
commandPrefix = "biome lint"
decision = "allow"
priority = 100

# biome: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "biome "
decision = "allow"
priority = 11

# prettier: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "prettier "
decision = "allow"
priority = 11

# eslint: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "eslint "
decision = "allow"
priority = 11

# ruff format: allow when --check present
[[rule]]
toolName = "run_shell_command"
commandRegex = "ruff format\\s+.*\\-\\-check"
decision = "allow"
priority = 110

# ruff format: allow when --diff present
[[rule]]
toolName = "run_shell_command"
commandRegex = "ruff format\\s+.*\\-\\-diff"
decision = "allow"
priority = 110

# ruff: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "ruff "
decision = "allow"
priority = 11

# black: allow when --check present
[[rule]]
toolName = "run_shell_command"
commandRegex = "black\\s+.*\\-\\-check"
decision = "allow"
priority = 110

# black: allow when --diff present
[[rule]]
toolName = "run_shell_command"
commandRegex = "black\\s+.*\\-\\-diff"
decision = "allow"
priority = 110

# isort: allow when --check present
[[rule]]
toolName = "run_shell_command"
commandRegex = "isort\\s+.*\\-\\-check"
decision = "allow"
priority = 110

# isort: allow when --check-only present
[[rule]]
toolName = "run_shell_command"
commandRegex = "isort\\s+.*\\-\\-check\\-only"
decision = "allow"
priority = 110

# isort: allow when --diff present
[[rule]]
toolName = "run_shell_command"
commandRegex = "isort\\s+.*\\-\\-diff"
decision = "allow"
priority = 110

# shellcheck: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "shellcheck "
decision = "allow"
priority = 11

# hadolint: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "hadolint "
decision = "allow"
priority = 11

# golangci-lint: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "golangci-lint "
decision = "allow"
priority = 11

# gci: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "gci "
decision = "allow"
priority = 11

# air: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "air "
decision = "allow"
priority = 11

# actionlint: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "actionlint "
decision = "allow"
priority = 11

# gitleaks: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "gitleaks "
decision = "allow"
priority = 11

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "lefthook run",
    "lefthook version",
    "lefthook dump",
]
decision = "allow"
priority = 100

# vite: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "vite "
decision = "allow"
priority = 11

# vitest: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "vitest "
decision = "allow"
priority = 11

# jest: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "jest "
decision = "allow"
priority = 11

# mocha: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "mocha "
decision = "allow"
priority = 11

# tsc: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "tsc "
decision = "allow"
priority = 11

# tsup: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "tsup "
decision = "allow"
priority = 11

# esbuild: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "esbuild "
decision = "allow"
priority = 11

# turbo: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "turbo "
decision = "allow"
priority = 11

# nx: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "nx "
decision = "allow"
priority = 11

# knip: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "knip "
decision = "allow"
priority = 11

# oxlint: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "oxlint "
decision = "allow"
priority = 11

# gofmt: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "gofmt "
decision = "allow"
priority = 11

# goimports: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "goimports "
decision = "allow"
priority = 11

# shfmt: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "shfmt "
decision = "allow"
priority = 11

# rustfmt: allow when --check present
[[rule]]
toolName = "run_shell_command"
commandRegex = "rustfmt\\s+.*\\-\\-check"
decision = "allow"
priority = 110

# stylua: allow when --check present
[[rule]]
toolName = "run_shell_command"
commandRegex = "stylua\\s+.*\\-\\-check"
decision = "allow"
priority = 110

# clang-format: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "clang-format "
decision = "allow"
priority = 11

# autopep8: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "autopep8 "
decision = "allow"
priority = 11

# rubocop: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "rubocop "
decision = "allow"
priority = 11

# standardrb: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "standardrb "
decision = "allow"
priority = 11

# patch: allow when --dry-run present
[[rule]]
toolName = "run_shell_command"
commandRegex = "patch\\s+.*\\-\\-dry\\-run"
decision = "allow"
priority = 110

# stylelint: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "stylelint "
decision = "allow"
priority = 11

# perltidy: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "perltidy "
decision = "allow"
priority = 11

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "dart analyze",
    "dart info",
    "dart --version",
]
decision = "allow"
priority = 100

# scalafmt: allow when --check present
[[rule]]
toolName = "run_shell_command"
commandRegex = "scalafmt\\s+.*\\-\\-check"
decision = "allow"
priority = 110

# ktlint: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "ktlint "
decision = "allow"
priority = 11

# swiftformat: allow when --lint present
[[rule]]
toolName = "run_shell_command"
commandRegex = "swiftformat\\s+.*\\-\\-lint"
decision = "allow"
priority = 110

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "buf lint",
    "buf breaking",
    "buf ls-files",
    "buf --version",
]
decision = "allow"
priority = 100

# === FILESYSTEM gate ===

# Block: Catastrophic rm blocked (root or home)
[[rule]]
toolName = "run_shell_command"
commandRegex = "rm\\s+(\\s+.*)?( /| /\\*| ~/| ~/\\*)(\\s|$)"
decision = "deny"
priority = 900

# Block: rm -rf / blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "rm -rf /"
decision = "deny"
priority = 900

# Block: rm -rf /* blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "rm -rf /*"
decision = "deny"
priority = 900

# Block: rm -rf ~ blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "rm -rf ~"
decision = "deny"
priority = 900

# Block: rm -fr / blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "rm -fr /"
decision = "deny"
priority = 900

# Block: rm -fr ~ blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "rm -fr ~"
decision = "deny"
priority = 900

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "tar -t",
    "tar --list",
]
decision = "allow"
priority = 100

# unzip: allow when -l present
[[rule]]
toolName = "run_shell_command"
commandRegex = "unzip\\s+.*\\-l"
decision = "allow"
priority = 110

# === NETWORK gate ===

# curl: allow when -I present
[[rule]]
toolName = "run_shell_command"
commandRegex = "curl\\s+.*\\-I"
decision = "allow"
priority = 110

# curl: allow when --head present
[[rule]]
toolName = "run_shell_command"
commandRegex = "curl\\s+.*\\-\\-head"
decision = "allow"
priority = 110

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "curl --version",
    "curl -h",
    "curl --help",
]
decision = "allow"
priority = 100

# curl: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "curl "
decision = "allow"
priority = 11

# wget: allow when --spider present
[[rule]]
toolName = "run_shell_command"
commandRegex = "wget\\s+.*\\-\\-spider"
decision = "allow"
priority = 110

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "wget --version",
    "wget -h",
    "wget --help",
]
decision = "allow"
priority = 100

# Block: Netcat -e blocked (reverse shell risk)
[[rule]]
toolName = "run_shell_command"
commandRegex = "nc\\s+(\\s+.*)?(\\-e)(\\s|$)"
decision = "deny"
priority = 900

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "http --version",
    "http --help",
    "http GET",
]
decision = "allow"
priority = 100

# === SYSTEM gate ===

# Block: System power command blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "shutdown "
decision = "deny"
priority = 900

# shutdown: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "shutdown "
decision = "deny"
priority = 11

# Block: System power command blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "reboot "
decision = "deny"
priority = 900

# reboot: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "reboot "
decision = "deny"
priority = 11

# Block: System power command blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "poweroff "
decision = "deny"
priority = 900

# poweroff: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "poweroff "
decision = "deny"
priority = 11

# Block: System power command blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "halt "
decision = "deny"
priority = 900

# halt: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "halt "
decision = "deny"
priority = 11

# Block: System power command blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "init "
decision = "deny"
priority = 900

# init: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "init "
decision = "deny"
priority = 11

# Block: Disk partitioning blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "mkfs "
decision = "deny"
priority = 900

# mkfs: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "mkfs "
decision = "deny"
priority = 11

# Block: Disk partitioning blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "fdisk "
decision = "deny"
priority = 900

# fdisk: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "fdisk "
decision = "deny"
priority = 11

# Block: Disk partitioning blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "parted "
decision = "deny"
priority = 900

# parted: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "parted "
decision = "deny"
priority = 11

# Block: Disk partitioning blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "gdisk "
decision = "deny"
priority = 900

# gdisk: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "gdisk "
decision = "deny"
priority = 11

# Block: Low-level disk operation blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "dd "
decision = "deny"
priority = 900

# dd: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "dd "
decision = "deny"
priority = 11

# Block: Secure delete blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "shred "
decision = "deny"
priority = 900

# shred: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "shred "
decision = "deny"
priority = 11

# Block: Secure wipe blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "wipe "
decision = "deny"
priority = 900

# wipe: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "wipe "
decision = "deny"
priority = 11

# Block: Filesystem creation blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "mke2fs "
decision = "deny"
priority = 900

# mke2fs: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "mke2fs "
decision = "deny"
priority = 11

# Block: Swap creation blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "mkswap "
decision = "deny"
priority = 900

# mkswap: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "mkswap "
decision = "deny"
priority = 11

# Block: Filesystem wipe blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "wipefs "
decision = "deny"
priority = 900

# wipefs: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "wipefs "
decision = "deny"
priority = 11

# Block: Disk parameters blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "hdparm "
decision = "deny"
priority = 900

# hdparm: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "hdparm "
decision = "deny"
priority = 11

# Block: Kernel module loading blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "insmod "
decision = "deny"
priority = 900

# insmod: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "insmod "
decision = "deny"
priority = 11

# Block: Kernel module removal blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "rmmod "
decision = "deny"
priority = 900

# rmmod: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "rmmod "
decision = "deny"
priority = 11

# Block: Kernel module loading blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "modprobe "
decision = "deny"
priority = 900

# modprobe: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "modprobe "
decision = "deny"
priority = 11

# Block: Bootloader modification blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "grub-install "
decision = "deny"
priority = 900

# grub-install: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "grub-install "
decision = "deny"
priority = 11

# Block: Bootloader modification blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "update-grub "
decision = "deny"
priority = 900

# update-grub: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "update-grub "
decision = "deny"
priority = 11

# Block: User management blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "useradd "
decision = "deny"
priority = 900

# useradd: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "useradd "
decision = "deny"
priority = 11

# Block: User management blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "userdel "
decision = "deny"
priority = 900

# userdel: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "userdel "
decision = "deny"
priority = 11

# Block: User management blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "usermod "
decision = "deny"
priority = 900

# usermod: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "usermod "
decision = "deny"
priority = 11

# Block: Password change blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "passwd "
decision = "deny"
priority = 900

# passwd: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "passwd "
decision = "deny"
priority = 11

# Block: Shell change blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "chsh "
decision = "deny"
priority = 900

# chsh: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "chsh "
decision = "deny"
priority = 11

# Block: Firewall modification blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "iptables "
decision = "deny"
priority = 900

# iptables: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "iptables "
decision = "deny"
priority = 11

# Block: Firewall modification blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "ufw "
decision = "deny"
priority = 900

# ufw: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "ufw "
decision = "deny"
priority = 11

# Block: Firewall modification blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "firewall-cmd "
decision = "deny"
priority = 900

# firewall-cmd: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "firewall-cmd "
decision = "deny"
priority = 11

# Block: File attribute change blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "chattr "
decision = "deny"
priority = 900

# chattr: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "chattr "
decision = "deny"
priority = 11

# mount: allow when --version present
[[rule]]
toolName = "run_shell_command"
commandRegex = "mount\\s+.*\\-\\-version"
decision = "allow"
priority = 110

# mount: allow when --help present
[[rule]]
toolName = "run_shell_command"
commandRegex = "mount\\s+.*\\-\\-help"
decision = "allow"
priority = 110

# mount: allow when -h present
[[rule]]
toolName = "run_shell_command"
commandRegex = "mount\\s+.*\\-h"
decision = "allow"
priority = 110

# mount: allow when -V present
[[rule]]
toolName = "run_shell_command"
commandRegex = "mount\\s+.*\\-V"
decision = "allow"
priority = 110

# Block: Unmounting blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "umount "
decision = "deny"
priority = 900

# umount: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "umount "
decision = "deny"
priority = 11

# Block: Swap management blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "swapoff "
decision = "deny"
priority = 900

# swapoff: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "swapoff "
decision = "deny"
priority = 11

# Block: Swap management blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "swapon "
decision = "deny"
priority = 900

# swapon: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "swapon "
decision = "deny"
priority = 11

# Block: LVM management blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "lvremove "
decision = "deny"
priority = 900

# lvremove: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "lvremove "
decision = "deny"
priority = 11

# Block: LVM management blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "vgremove "
decision = "deny"
priority = 900

# vgremove: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "vgremove "
decision = "deny"
priority = 11

# Block: LVM management blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "pvremove "
decision = "deny"
priority = 900

# pvremove: unknown subcommands blocked
[[rule]]
toolName = "run_shell_command"
commandPrefix = "pvremove "
decision = "deny"
priority = 11

# psql: allow when -l present
[[rule]]
toolName = "run_shell_command"
commandRegex = "psql\\s+.*\\-l"
decision = "allow"
priority = 110

# psql: allow when --list present
[[rule]]
toolName = "run_shell_command"
commandRegex = "psql\\s+.*\\-\\-list"
decision = "allow"
priority = 110

# pg_dump: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "pg_dump "
decision = "allow"
priority = 11

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "alembic history",
    "alembic current",
    "alembic heads",
    "alembic branches",
    "alembic show",
]
decision = "allow"
priority = 100

# sqlite3: allow when -readonly present
[[rule]]
toolName = "run_shell_command"
commandRegex = "sqlite3\\s+.*\\-readonly"
decision = "allow"
priority = 110

# kill: allow when -0 present
[[rule]]
toolName = "run_shell_command"
commandRegex = "kill\\s+.*\\-0"
decision = "allow"
priority = 110

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "make test",
    "make tests",
    "make check",
    "make lint",
    "make build",
    "make all",
    "make clean",
    "make format",
    "make fmt",
    "make typecheck",
    "make dev",
    "make run",
    "make help",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "cmake --version",
    "cmake --help",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = "ninja -t"
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "just --list",
    "just --summary",
    "just --dump",
    "just --evaluate",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "task --list",
    "task --list-all",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "gradle tasks",
    "gradle help",
    "gradle dependencies",
    "gradle properties",
    "gradle build",
    "gradle test",
    "gradle check",
    "gradle clean",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "mvn help",
    "mvn validate",
    "mvn compile",
    "mvn test",
    "mvn package",
    "mvn verify",
    "mvn clean",
    "mvn dependency:tree",
    "mvn dependency:analyze",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "bazel info",
    "bazel query",
    "bazel cquery",
    "bazel aquery",
    "bazel build",
    "bazel test",
    "bazel coverage",
    "bazel version",
    "bazel help",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "meson introspect",
    "meson configure",
    "meson --version",
    "meson --help",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "ansible --version",
    "ansible --help",
    "ansible --list-hosts",
    "ansible --list-tasks",
    "ansible --syntax-check",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "vagrant status",
    "vagrant global-status",
    "vagrant ssh-config",
    "vagrant port",
    "vagrant version",
    "vagrant --help",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "hyperfine --version",
    "hyperfine --help",
]
decision = "allow"
priority = 100

# sudo: allow when -l present
[[rule]]
toolName = "run_shell_command"
commandRegex = "sudo\\s+.*\\-l"
decision = "allow"
priority = 110

# sudo: allow when --list present
[[rule]]
toolName = "run_shell_command"
commandRegex = "sudo\\s+.*\\-\\-list"
decision = "allow"
priority = 110

# sudo: allow when -v present
[[rule]]
toolName = "run_shell_command"
commandRegex = "sudo\\s+.*\\-v"
decision = "allow"
priority = 110

# sudo: allow when --validate present
[[rule]]
toolName = "run_shell_command"
commandRegex = "sudo\\s+.*\\-\\-validate"
decision = "allow"
priority = 110

# sudo: allow when -k present
[[rule]]
toolName = "run_shell_command"
commandRegex = "sudo\\s+.*\\-k"
decision = "allow"
priority = 110

# sudo: allow when --reset-timestamp present
[[rule]]
toolName = "run_shell_command"
commandRegex = "sudo\\s+.*\\-\\-reset\\-timestamp"
decision = "allow"
priority = 110

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "systemctl status",
    "systemctl show",
    "systemctl list-units",
    "systemctl list-unit-files",
    "systemctl list-sockets",
    "systemctl list-timers",
    "systemctl list-jobs",
    "systemctl list-dependencies",
    "systemctl is-active",
    "systemctl is-enabled",
    "systemctl is-failed",
    "systemctl is-system-running",
    "systemctl cat",
    "systemctl help",
    "systemctl --version",
    "systemctl -h",
    "systemctl --help",
]
decision = "allow"
priority = 100

# service: allow when --status-all present
[[rule]]
toolName = "run_shell_command"
commandRegex = "service\\s+.*\\-\\-status\\-all"
decision = "allow"
priority = 110

# crontab: allow when -l present
[[rule]]
toolName = "run_shell_command"
commandRegex = "crontab\\s+.*\\-l"
decision = "allow"
priority = 110

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "apt list",
    "apt search",
    "apt show",
    "apt showpkg",
    "apt depends",
    "apt rdepends",
    "apt policy",
    "apt madison",
    "apt pkgnames",
    "apt dotty",
    "apt xvcg",
    "apt stats",
    "apt dump",
    "apt dumpavail",
    "apt showsrc",
    "apt changelog",
    "apt --version",
    "apt -v",
    "apt --help",
    "apt -h",
]
decision = "allow"
priority = 100

# apt-cache: unknown subcommands allow
[[rule]]
toolName = "run_shell_command"
commandPrefix = "apt-cache "
decision = "allow"
priority = 11

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "dnf list",
    "dnf info",
    "dnf search",
    "dnf provides",
    "dnf whatprovides",
    "dnf repolist",
    "dnf repoinfo",
    "dnf repoquery",
    "dnf deplist",
    "dnf check",
    "dnf check-update",
    "dnf history",
    "dnf alias",
    "dnf --version",
    "dnf -v",
    "dnf --help",
    "dnf -h",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "pacman -Q",
    "pacman --query",
    "pacman -Qs",
    "pacman -Qi",
    "pacman -Ql",
    "pacman -Qo",
    "pacman -Ss",
    "pacman -Si",
    "pacman -Sl",
    "pacman -Sg",
    "pacman -F",
    "pacman --files",
    "pacman -V",
    "pacman --version",
    "pacman -h",
    "pacman --help",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "brew list",
    "brew ls",
    "brew search",
    "brew info",
    "brew home",
    "brew homepage",
    "brew deps",
    "brew uses",
    "brew leaves",
    "brew outdated",
    "brew config",
    "brew doctor",
    "brew commands",
    "brew desc",
    "brew --version",
    "brew -v",
    "brew --help",
    "brew -h",
    "brew cat",
    "brew formula",
    "brew cask",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "zypper search",
    "zypper se",
    "zypper info",
    "zypper if",
    "zypper list-updates",
    "zypper lu",
    "zypper packages",
    "zypper pa",
    "zypper patterns",
    "zypper pt",
    "zypper products",
    "zypper pd",
    "zypper repos",
    "zypper lr",
    "zypper services",
    "zypper ls",
    "zypper --version",
    "zypper -V",
    "zypper --help",
    "zypper -h",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "apk info",
    "apk list",
    "apk search",
    "apk dot",
    "apk policy",
    "apk stats",
    "apk audit",
    "apk --version",
    "apk -V",
    "apk --help",
    "apk -h",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "nix search",
    "nix show",
    "nix eval",
    "nix repl",
    "nix flake",
    "nix path-info",
    "nix derivation",
    "nix store",
    "nix log",
    "nix why-depends",
    "nix --version",
    "nix --help",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "nix-env -q",
    "nix-env --query",
]
decision = "allow"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "flatpak list",
    "flatpak info",
    "flatpak search",
    "flatpak remote-ls",
    "flatpak remotes",
    "flatpak history",
    "flatpak --version",
    "flatpak --help",
]
decision = "allow"
priority = 100

# === SHORTCUT gate ===

[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "short search",
    "short find",
    "short story",
    "short members",
    "short epics",
    "short workflows",
    "short projects",
    "short workspace",
    "short help",
]
decision = "allow"
priority = 100

# === BASICS gate ===

# Safe commands (with args)
[[rule]]
toolName = "run_shell_command"
commandPrefix = [
    "echo ",
    "printf ",
    "cat ",
    "head ",
    "tail ",
    "less ",
    "more ",
    "bat ",
    "batcat ",
    "ls ",
    "eza ",
    "lsd ",
    "tree ",
    "find ",
    "fd ",
    "locate ",
    "which ",
    "whereis ",
    "type ",
    "grep ",
    "rg ",
    "ripgrep ",
    "choose ",
    "cut ",
    "sort ",
    "uniq ",
    "wc ",
    "tr ",
    "column ",
    "paste ",
    "join ",
    "comm ",
    "diff ",
    "cmp ",
    "fold ",
    "fmt ",
    "nl ",
    "rev ",
    "tac ",
    "expand ",
    "unexpand ",
    "pr ",
    "file ",
    "stat ",
    "du ",
    "df ",
    "lsof ",
    "readlink ",
    "realpath ",
    "basename ",
    "dirname ",
    "lsattr ",
    "getfacl ",
    "ps ",
    "top ",
    "htop ",
    "btop ",
    "procs ",
    "pgrep ",
    "pidof ",
    "uptime ",
    "w ",
    "who ",
    "whoami ",
    "id ",
    "groups ",
    "uname ",
    "hostname ",
    "hostnamectl ",
    "date ",
    "cal ",
    "free ",
    "vmstat ",
    "iostat ",
    "nproc ",
    "lscpu ",
    "lsmem ",
    "lsblk ",
    "lspci ",
    "lsusb ",
    "locale ",
    "getconf ",
    "vainfo ",
    "vdpauinfo ",
    "glxinfo ",
    "clinfo ",
    "xdpyinfo ",
    "xwininfo ",
    "ping ",
    "traceroute ",
    "tracepath ",
    "mtr ",
    "dig ",
    "nslookup ",
    "host ",
    "whois ",
    "ss ",
    "netstat ",
    "ip ",
    "ifconfig ",
    "route ",
    "arp ",
    "zipinfo ",
    "unrar ",
    "tokei ",
    "cloc ",
    "scc ",
    "loc ",
    "jq ",
    "yq ",
    "gron ",
    "fx ",
    "hexdump ",
    "xxd ",
    "base64 ",
    "od ",
    "hexyl ",
    "strings ",
    "delta ",
    "difft ",
    "dust ",
    "fselect ",
    "pastel ",
    "numbat ",
    "fzf ",
    "tig ",
    "z ",
    "zi ",
    "zoxide ",
    "sha256sum ",
    "md5sum ",
    "sha1sum ",
    "sha512sum ",
    "b2sum ",
    "cksum ",
    "man ",
    "info ",
    "help ",
    "tldr ",
    "tealdeer ",
    "cheat ",
    "true ",
    "false ",
    "yes ",
    "seq ",
    "expr ",
    "bc ",
    "dc ",
    "factor ",
    "sleep ",
    "wait ",
    "printenv ",
    "export ",
    "set ",
    "pwd ",
    "cd ",
    "pushd ",
    "popd ",
    "dirs ",
    "unalias ",
    "hash ",
    "test ",
    "[ ",
    "[[ ",
    "read ",
]
decision = "allow"
priority = 100

# Safe commands (bare, no args)
[[rule]]
toolName = "run_shell_command"
commandRegex = "^(echo|printf|cat|head|tail|less|more|bat|batcat|ls|eza|lsd|tree|find|fd|locate|which|whereis|type|grep|rg|ripgrep|choose|cut|sort|uniq|wc|tr|column|paste|join|comm|diff|cmp|fold|fmt|nl|rev|tac|expand|unexpand|pr|file|stat|du|df|lsof|readlink|realpath|basename|dirname|lsattr|getfacl|ps|top|htop|btop|procs|pgrep|pidof|uptime|w|who|whoami|id|groups|uname|hostname|hostnamectl|date|cal|free|vmstat|iostat|nproc|lscpu|lsmem|lsblk|lspci|lsusb|locale|getconf|vainfo|vdpauinfo|glxinfo|clinfo|xdpyinfo|xwininfo|ping|traceroute|tracepath|mtr|dig|nslookup|host|whois|ss|netstat|ip|ifconfig|route|arp|zipinfo|unrar|tokei|cloc|scc|loc|jq|yq|gron|fx|hexdump|xxd|base64|od|hexyl|strings|delta|difft|dust|fselect|pastel|numbat|fzf|tig|z|zi|zoxide|sha256sum|md5sum|sha1sum|sha512sum|b2sum|cksum|man|info|help|tldr|tealdeer|cheat|true|false|yes|seq|expr|bc|dc|factor|sleep|wait|printenv|export|set|pwd|cd|pushd|popd|dirs|unalias|hash|test|\\[|\\[\\[|read)$"
decision = "allow"
priority = 100

"#;
